"""Verifier — enforces that every Finding cites code that actually exists.

The promise on the box: "every finding cites file:line and quotes the offending
code." If we ship a Finding whose quoted_code doesn't appear at the cited
location, the promise is broken and the brand is dead.

This module re-reads the source to validate. Drops anything that fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from closeread.schema import ArtifactReport, AuditPacket, Finding


@dataclass(frozen=True)
class VerificationResult:
    finding: Finding
    passed: bool
    reason: str  # "ok", "file_missing", "line_out_of_range", "quote_mismatch"


def _verify_finding(finding: Finding, repo_root: Path) -> VerificationResult:
    """Check that the finding's citation matches the source."""
    cit = finding.citation
    file_path = repo_root / cit.file
    if not file_path.is_file():
        return VerificationResult(finding, False, "file_missing")
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return VerificationResult(finding, False, "file_unreadable")

    lines = text.splitlines()
    if cit.line_start < 1 or cit.line_end > len(lines):
        return VerificationResult(finding, False, "line_out_of_range")

    # Extract the cited region and check the quote appears in it.
    region = "\n".join(lines[cit.line_start - 1 : cit.line_end])
    # Normalize whitespace for comparison — quoted code can drift on trailing whitespace.
    quote_normalized = _normalize(cit.quoted_code)
    region_normalized = _normalize(region)

    if quote_normalized not in region_normalized:
        # Fall back: check if normalized quote appears anywhere in the file
        # (useful when the citation has the wrong line but the right code).
        file_normalized = _normalize(text)
        if quote_normalized in file_normalized:
            return VerificationResult(finding, False, "quote_at_wrong_line")
        return VerificationResult(finding, False, "quote_mismatch")

    return VerificationResult(finding, True, "ok")


def _normalize(s: str) -> str:
    """Normalize whitespace for forgiving quote comparison."""
    return " ".join(s.split())


def verify_artifact(
    artifact: ArtifactReport, repo_root: Path
) -> tuple[ArtifactReport, list[VerificationResult]]:
    """Return a new ArtifactReport with only verified findings, plus rejection log."""
    results = [_verify_finding(f, repo_root) for f in artifact.findings]
    verified = [r.finding for r in results if r.passed]
    rejected = [r for r in results if not r.passed]

    new_report = artifact.model_copy(update={"findings": verified})
    return new_report, rejected


def verify_packet(
    packet: AuditPacket, repo_root: Path
) -> tuple[AuditPacket, list[VerificationResult]]:
    """Verify all findings in a packet. Returns (cleaned_packet, all_rejections)."""
    new_artifacts: list[ArtifactReport] = []
    all_rejections: list[VerificationResult] = []
    for artifact in packet.artifacts:
        cleaned, rejections = verify_artifact(artifact, repo_root)
        new_artifacts.append(cleaned)
        all_rejections.extend(rejections)
    new_packet = packet.model_copy(update={"artifacts": new_artifacts})
    return new_packet, all_rejections
