"""Credential Inventory scanner -- finds hardcoded secrets in source.

Maps to ArtifactKind.CREDENTIALS. Answers buyer DD question #7:
"Show me every credential -- AWS, Stripe, Jenkins -- and confirm I'll get
access at close."

Detection: pure-Python regex first (no external tool required); optionally
shells out to gitleaks if installed for richer coverage.

Pattern sources (per research swarm-15):
  1. AWS access key: AKIA[A-Z2-7]{16}
  2. Stripe secret: sk_(live|test)_[A-Za-z0-9]{24,}
  3. SSH private key PEM: -----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----
  4. Committed .env file (by path)
  5. Generic high-entropy in (key|secret|token|pass|pwd) variable
  6. GitHub PAT: gh[pousr]_[A-Za-z0-9_]{36}
  7. Anthropic API key: sk-ant-(admin01|api03)-[A-Za-z0-9_-]{40,}
  8. OpenAI API key: sk-(proj-)?[A-Za-z0-9_-]{40,}
  9. Slack token: xox[baprs]-[0-9A-Za-z-]{10,}
 10. Generic Bearer token in code: Bearer\\s+[A-Za-z0-9._-]{20,}
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from closeread.ingest import IngestResult
from closeread.schema import (
    ArtifactKind,
    ArtifactReport,
    Citation,
    Effort,
    Finding,
    Severity,
    make_finding_id,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Files larger than this are skipped (likely minified/binary).
MAX_FILE_BYTES = 500 * 1024  # 500 KB

# Extensions that are high false-positive noise for secrets; skip for regex.
# Exception: .env files are explicitly included below.
# Bug 4 fix (Day 7 10-OSS batch): .html / .htm added because the Mealie
# packet was 872KB of Bon Appetit recipe HTML matched by the generic
# entropy pattern. Documents and markup files do not legitimately contain
# secrets in the way source code does; if a real .env-like secret lives
# in an .html template (rare), tools like gitleaks running on the raw git
# tree will still surface it via the gitleaks fallback below.
SKIP_EXTENSIONS = {".md", ".txt", ".csv", ".json", ".html", ".htm"}
# Day 16 D2 fix (pmxt give-first audit): documentation formats carry example /
# placeholder API keys in usage snippets, not live credentials. pmxt's
# docs/api-reference/*.mdx produced ~9 false "High-Entropy Secret" / "OpenAI
# API Key" findings. .md was already skipped; its siblings were not.
SKIP_EXTENSIONS |= {".mdx", ".markdown", ".rst", ".adoc"}

# Bug 4 fix: cap quoted_code length so a credential finding can never
# embed an entire page of recipe HTML or other large surrounding context
# into the packet. The OWASP recommendation for secret display is the
# minimal context needed to confirm the location; 500 chars is plenty.
MAX_QUOTED_LINE_CHARS = 500

# Path fragments that signal a test/fixture file. Findings here get LOW severity.
TEST_PATH_FRAGMENTS = {
    "test",
    "tests",
    "__tests__",
    "fixtures",
    "examples",
    "spec",
    "specs",
    "mock",
    "mocks",
    "fake",
    "fakes",
    "seed",
    "seeds",
    "sample",
    "samples",
    "stub",
    "stubs",
}

# If a single file produces more than this many findings of the same category,
# collapse them into one summary finding (it's almost certainly a fixture/seed).
MAX_FINDINGS_PER_CATEGORY_PER_FILE = 10

# Entropy threshold for "high-entropy" generic variable scan.
# Shannon entropy of a random 32-char base64 string ~ 5.5 bits/char.
ENTROPY_THRESHOLD = 3.5

# ---------------------------------------------------------------------------
# False-positive suppression (Day 19 give-first batch QA)
# Free Guy/findings/2026-06-02-give-first-batch-qa-10-of-10-dropped.md
# Six of ten give-first drafts died on credential false positives. These are
# the deterministic patterns behind them, nailed to the wall.
# ---------------------------------------------------------------------------

# Canonical documentation example credentials. AWS docs always use keys ending
# in EXAMPLE; posthog and tooljet both shipped AKIAIOSFODNN7EXAMPLE in UI
# placeholders and got flagged CRITICAL.
_EXAMPLE_CRED_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
}

# Line markers that signal a documented example or UI placeholder, not a live
# credential. High-precision: a real secret rarely shares a line with these.
_PLACEHOLDER_LINE_MARKERS = (
    "placeholder",
    "e.g.",
    "for example",
    "example only",
    "<your",
    "your-key",
    "your_key",
    "changeme",
    "change-me",
    "replace-me",
    "redacted",
)

# Comment-line prefixes. A commented-out PEM header is documentation (appsmith
# shipped one in a helm values.yaml example block).
_COMMENT_PREFIXES = ("#", "//", ";", "*", "<!--", "/*", "--", "%")

# Filename tokens + content markers that mark an intentionally-bundled
# self-signed / development certificate. mockoon ships one in ssl.constants.ts
# (comment "Default self signed certificates", exports DefaultTLSOptions).
_CERT_FILE_TOKENS = (
    "ssl",
    "tls",
    "cert",
    "selfsign",
    "self-sign",
    "self_sign",
    "snakeoil",
    "devcert",
    "dev-cert",
)
_CERT_CONTENT_MARKERS = (
    "self-signed",
    "self signed",
    "selfsigned",
    "defaulttls",
    "default cert",
    "default certificate",
    "development",
    "for local",
    "localhost",
    "do not use in production",
    "snakeoil",
)

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredPattern:
    """A single detection rule."""

    name: str  # Human-readable category label
    regex: re.Pattern[str]
    # Severity when found in a NON-test file.
    severity_live: Severity
    # Severity when found in a test/fixture file.
    severity_test: Severity
    confidence: float
    # Short label used in Finding summary (does NOT include the matched value).
    summary_label: str
    recommendation: str


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


PATTERNS: list[CredPattern] = [
    # --- Cloud provider keys (CRITICAL outside tests) ---
    CredPattern(
        name="aws_access_key",
        regex=_compile(r"AKIA[A-Z2-7]{16}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="AWS Access Key ID",
        recommendation=(
            "Rotate the AWS access key immediately via IAM. Remove from source,"
            " add to a secrets manager (e.g. AWS Secrets Manager, Vault),"
            " and audit CloudTrail for unauthorized use."
        ),
    ),
    CredPattern(
        name="stripe_live_key",
        regex=_compile(r"sk_live_[A-Za-z0-9]{24,}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="Stripe Live Secret Key",
        recommendation=(
            "Roll the Stripe secret key in the Stripe dashboard immediately."
            " Move to environment variable injection and audit recent API calls"
            " for unauthorized charges."
        ),
    ),
    CredPattern(
        name="stripe_test_key",
        regex=_compile(r"sk_test_[A-Za-z0-9]{24,}"),
        severity_live=Severity.MEDIUM,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="Stripe Test Secret Key",
        recommendation=(
            "Remove from source and load via environment variable."
            " Test keys cannot charge real cards but should not be committed."
        ),
    ),
    CredPattern(
        name="github_pat",
        regex=_compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="GitHub Personal Access Token",
        recommendation=(
            "Revoke the token in GitHub Settings > Developer Settings."
            " Audit the token's recent API activity."
            " Use environment variables or GitHub Actions secrets instead."
        ),
    ),
    CredPattern(
        name="anthropic_api_key",
        regex=_compile(r"sk-ant-(?:admin01|api03)-[A-Za-z0-9_\-]{40,}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="Anthropic API Key",
        recommendation=(
            "Revoke via console.anthropic.com and regenerate."
            " Store in an environment variable or secrets manager."
        ),
    ),
    CredPattern(
        name="openai_api_key",
        regex=_compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{40,}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.90,
        summary_label="OpenAI API Key",
        recommendation=(
            "Revoke via platform.openai.com and rotate."
            " Use secrets injection rather than hardcoding."
        ),
    ),
    CredPattern(
        name="slack_token",
        regex=_compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        severity_live=Severity.CRITICAL,
        severity_test=Severity.LOW,
        confidence=0.95,
        summary_label="Slack Token",
        recommendation=(
            "Revoke via api.slack.com/apps. Rotate bot/user tokens"
            " and use environment variables or Slack secret management."
        ),
    ),
    CredPattern(
        name="bearer_token",
        regex=_compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"),
        severity_live=Severity.HIGH,
        severity_test=Severity.LOW,
        confidence=0.75,
        summary_label="Hardcoded Bearer Token",
        recommendation=(
            "Remove hardcoded token. Fetch at runtime from a secrets manager"
            " or environment variable."
        ),
    ),
    # --- SSH private key (HIGH regardless, found in source = real risk) ---
    CredPattern(
        name="ssh_private_key",
        regex=_compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        severity_live=Severity.HIGH,
        severity_test=Severity.HIGH,
        confidence=0.95,
        summary_label="SSH/PEM Private Key",
        recommendation=(
            "Remove the private key from source immediately."
            " Revoke or regenerate the key pair."
            " Use a secrets manager and provision keys at deploy time."
        ),
    ),
]

# The .env committed file pattern is handled separately (path-based).

# High-entropy generic variable pattern: matches assignment to key/secret/token/pass/pwd.
# Groups: (1) variable name, (2) candidate value.
_GENERIC_ENTROPY_RE = re.compile(
    r"""(?xi)
    (?:^|\s)                                    # start of line or whitespace
    (?P<varname>
        [A-Za-z_][A-Za-z0-9_]*                 # variable name
        (?:key|secret|token|pass|pwd|password)  # must end with sensitive word
        [A-Za-z0-9_]*
    )
    \s*
    (?:[=:]\s*|:\s*["']?)                       # assignment-like separator
    (?P<value>
        [A-Za-z0-9+/=_\-]{16,}                 # candidate secret value
    )
    """,
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_test_path(relative_path: str) -> bool:
    """Return True if any path segment looks like a test/fixture directory."""
    parts = set(Path(relative_path).parts)
    return bool(parts & TEST_PATH_FRAGMENTS)


def _should_skip_extension(path: Path) -> bool:
    """Skip high-noise extensions, but ALWAYS scan .env files."""
    suffix = path.suffix.lower()
    name = path.name.lower()
    # .env and .env.* files are always scanned.
    if name == ".env" or name.startswith(".env."):
        return False
    return suffix in SKIP_EXTENSIONS


# .env templates ship placeholder values on purpose, so they are NOT committed
# secrets. Flagging them produced pmxt's false "1 committed .env file" headline
# (Day 16 D2): the old code matched any name.startswith(".env."), which catches
# .env.example. The marker is the trailing token after the last dot.
_ENV_TEMPLATE_SUFFIXES = {"example", "sample", "template", "dist", "defaults", "tpl", "tmpl"}


def _is_real_committed_env(name_lower: str) -> bool:
    """True for a real committed env file (.env, .env.local, .env.production);
    False for a template (.env.example, .env.sample, .env.template, .env.dist)."""
    if not (name_lower == ".env" or name_lower.startswith(".env.")):
        return False
    if "." in name_lower:
        last = name_lower.rsplit(".", 1)[1]
        if last in _ENV_TEMPLATE_SUFFIXES:
            return False
    return True


def _safe_read_lines(path: Path) -> list[str] | None:
    """Read file lines, respecting size limit. Returns None on error/too-large."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None


def _redact(line: str, match_value: str) -> str:
    """Replace the matched secret value with [REDACTED] in the quoted line."""
    # Only redact if the value is long enough to be meaningful (avoid blanking tiny substrings).
    if len(match_value) < 8:
        return line
    return line.replace(match_value, "[REDACTED]", 1)


def _is_example_value(value: str) -> bool:
    """True for canonical documentation example credentials (never live)."""
    if value in _EXAMPLE_CRED_VALUES:
        return True
    # AWS docs example keys always end in EXAMPLE; real AKIA keys do not.
    if value.startswith("AKIA") and value.endswith("EXAMPLE"):
        return True
    if value.endswith("EXAMPLEKEY"):
        return True
    return False


def _is_placeholder_context(line: str, start: int, end: int) -> bool:
    """True if a placeholder/example marker sits NEAR the match.

    Proximity-scoped (a 50-char window each side) so a distant word elsewhere on
    a long line cannot suppress a real secret, and a long run of filler can never
    look like a placeholder.
    """
    window = line[max(0, start - 50) : end + 50].lower()
    return any(marker in window for marker in _PLACEHOLDER_LINE_MARKERS)


def _is_comment_line(line: str) -> bool:
    """True if the (left-stripped) line begins with a comment marker."""
    return line.lstrip().startswith(_COMMENT_PREFIXES)


def _looks_like_bundled_cert_file(relative_path: str, content_lower: str) -> bool:
    """True for an intentionally-bundled self-signed / development certificate.

    Requires BOTH a filename/path signal (ssl/tls/cert/...) AND a content marker
    (self-signed / default / development / localhost). A real production key in
    such a file is still possible, so PEM hits here are DEMOTED, not dropped.
    """
    path_l = relative_path.lower()
    if not any(tok in path_l for tok in _CERT_FILE_TOKENS):
        return False
    return any(marker in content_lower for marker in _CERT_CONTENT_MARKERS)


# A leaked PEM private key has a base64 body between its BEGIN and END markers.
# A lone header/footer string constant used to PARSE keys has none (appsmith
# RSAKeyUtil.java: `PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"`, with
# the matching FOOTER constant on the next line and no key material between).
# Requiring real key material kills that false positive without dropping a key.
_PEM_END_RE = re.compile(r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
# A base64 run long enough to be a key body line. Length alone is not enough:
# a long camelCase/PascalCase identifier is also all base64-alphabet chars, so
# _is_key_material() additionally requires real entropy (see below).
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _is_key_material(run: str) -> bool:
    """True if a base64 run looks like key material, not a code identifier.

    Base64 of random key bytes carries entropy: a digit or a base64-special
    char (+ / =) almost always appears. A source identifier, however long, is
    letters-only. Requiring that entropy stops a long identifier sitting near a
    PEM header constant from being mistaken for a leaked key body.
    """
    return any(c.isdigit() for c in run) or any(c in "+/=" for c in run)


def _has_pem_key_body(
    lines: list[str], begin_idx: int, marker_end: int, lookahead: int = 60
) -> bool:
    """True if base64 key material follows the BEGIN marker before any END marker.

    Distinguishes a real leaked private key (a base64 body sits between BEGIN and
    END) from a bare PEM header/footer literal used for key parsing, which has no
    body. Scans the remainder of the BEGIN line plus the next `lookahead` lines;
    stops at the END marker and requires the body to precede it.
    """
    first = lines[begin_idx][marker_end:]
    segments = [first]
    segments.extend(lines[begin_idx + 1 : begin_idx + 1 + lookahead])
    for seg in segments:
        end_m = _PEM_END_RE.search(seg)
        search_space = seg[: end_m.start()] if end_m else seg
        for m in _PEM_BODY_RE.finditer(search_space):
            if _is_key_material(m.group(0)):
                return True
        if end_m:
            return False
    return False


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


@dataclass
class RawHit:
    """A single regex/entropy match before de-duplication."""

    pattern_name: str
    relative_path: str
    line_no: int
    quoted_line: str  # REDACTED version
    severity: Severity
    confidence: float
    summary_label: str
    recommendation: str


def _scan_file_for_patterns(
    lines: list[str],
    relative_path: str,
    is_test: bool,
) -> list[RawHit]:
    """Run all PATTERNS against a list of lines. Returns raw hits."""
    hits: list[RawHit] = []
    content_lower = "\n".join(lines).lower()
    is_devcert_file = _looks_like_bundled_cert_file(relative_path, content_lower)
    for pattern in PATTERNS:
        for line_no, raw_line in enumerate(lines, start=1):
            m = pattern.regex.search(raw_line)
            if not m:
                continue
            matched_value = m.group(0)
            # FP suppression: documentation example values + placeholder context.
            if _is_example_value(matched_value) or _is_placeholder_context(
                raw_line, m.start(), m.end()
            ):
                continue
            severity = pattern.severity_test if is_test else pattern.severity_live
            summary_label = pattern.summary_label
            recommendation = pattern.recommendation
            confidence = pattern.confidence
            if pattern.name == "ssh_private_key":
                # A commented-out PEM header is a docs/example placeholder. Check
                # only the text BEFORE the match, so the PEM's own leading dashes
                # ("-----BEGIN") are never mistaken for a "--" comment marker.
                if _is_comment_line(raw_line[: m.start()]):
                    continue
                # A bare PEM header/footer literal with no base64 key body is a
                # parsing constant (appsmith RSAKeyUtil.java), not a leaked key.
                if not _has_pem_key_body(lines, line_no - 1, m.end()):
                    continue
                # An intentionally-bundled self-signed/dev cert is not a leak.
                # Demote out of the headline but keep it for manual confirmation.
                if is_devcert_file:
                    severity = Severity.LOW
                    summary_label = "Bundled Self-Signed / Dev Certificate"
                    confidence = 0.5
                    recommendation = (
                        "This PEM block sits in a file that looks like an"
                        " intentionally-bundled self-signed or development"
                        " certificate (filename plus self-signed/default markers)."
                        " Confirm it is not a production key; if it is, rotate it."
                    )
            hits.append(
                RawHit(
                    pattern_name=pattern.name,
                    relative_path=relative_path,
                    line_no=line_no,
                    quoted_line=raw_line.rstrip()[:MAX_QUOTED_LINE_CHARS],
                    severity=severity,
                    confidence=confidence,
                    summary_label=summary_label,
                    recommendation=recommendation,
                )
            )
    return hits


def _scan_file_for_entropy(
    lines: list[str],
    relative_path: str,
    is_test: bool,
) -> list[RawHit]:
    """High-entropy generic variable scan."""
    hits: list[RawHit] = []
    for line_no, raw_line in enumerate(lines, start=1):
        for m in _GENERIC_ENTROPY_RE.finditer(raw_line):
            value = m.group("value")
            if _shannon_entropy(value) < ENTROPY_THRESHOLD:
                continue
            # FP suppression: documentation example values + placeholder context.
            if _is_example_value(value) or _is_placeholder_context(
                raw_line, m.start("value"), m.end("value")
            ):
                continue
            severity = Severity.LOW if is_test else Severity.MEDIUM
            hits.append(
                RawHit(
                    pattern_name="generic_entropy",
                    relative_path=relative_path,
                    line_no=line_no,
                    quoted_line=raw_line.rstrip()[:MAX_QUOTED_LINE_CHARS],
                    severity=severity,
                    confidence=0.70,
                    summary_label="High-Entropy Secret Variable",
                    recommendation=(
                        "Review this variable assignment."
                        " If it is a real credential, move it to a secrets manager"
                        " or environment variable and rotate the value."
                    ),
                )
            )
    return hits


def _scan_env_file(relative_path: str) -> RawHit:
    """Produce a single HIGH finding for a committed .env file."""
    return RawHit(
        pattern_name="committed_env_file",
        relative_path=relative_path,
        line_no=1,
        quoted_line=f"# .env file committed to source: {relative_path}",
        severity=Severity.HIGH,
        confidence=0.95,
        summary_label="Committed .env File",
        recommendation=(
            "Remove the .env file from version control (git rm --cached)."
            " Add .env to .gitignore."
            " Rotate every credential it contains."
            " Use a secrets manager or CI/CD secret injection going forward."
        ),
    )


# ---------------------------------------------------------------------------
# De-duplication and collapsing
# ---------------------------------------------------------------------------


def _collapse_hits(hits: list[RawHit]) -> list[RawHit]:
    """If a file has >MAX hits of the same category, collapse to one summary hit."""
    # Group by (relative_path, pattern_name).
    groups: dict[tuple[str, str], list[RawHit]] = defaultdict(list)
    for h in hits:
        groups[(h.relative_path, h.pattern_name)].append(h)

    result: list[RawHit] = []
    for (rel_path, pattern_name), group_hits in groups.items():
        if len(group_hits) > MAX_FINDINGS_PER_CATEGORY_PER_FILE:
            # Emit single collapsed hit pointing at line 1.
            first = group_hits[0]
            collapsed = RawHit(
                pattern_name=first.pattern_name,
                relative_path=first.relative_path,
                line_no=1,
                quoted_line=(
                    f"# {len(group_hits)} occurrences of {first.summary_label}"
                    f" in {first.relative_path} -- likely a fixture/seed file"
                ),
                severity=Severity.LOW,
                confidence=0.60,
                summary_label=first.summary_label,
                recommendation=(
                    "This file contains an unusually large number of credential-like"
                    " patterns. Confirm it is a test fixture and not production data."
                    " If real credentials exist, rotate them."
                ),
            )
            result.append(collapsed)
        else:
            result.extend(group_hits)
    return result


# ---------------------------------------------------------------------------
# Optional gitleaks fallback
# ---------------------------------------------------------------------------


def _run_gitleaks(repo_root: Path, next_id: int) -> list[Finding]:
    """Run gitleaks if available. Returns supplemental findings."""
    if not shutil.which("gitleaks"):
        return []
    try:
        proc = subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source", str(repo_root),
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--no-git",
                "--exit-code", "0",  # always exit 0, we parse JSON
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        import json

        raw = proc.stdout.strip()
        if not raw or raw == "null":
            return []
        leaks = json.loads(raw)
        if not isinstance(leaks, list):
            return []
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError, KeyError):
        return []

    findings: list[Finding] = []
    for leak in leaks:
        try:
            rel_file = leak.get("File", "unknown")
            line_no = int(leak.get("StartLine", 1))
            rule = leak.get("RuleID", "unknown")
            # Keep raw line for verifier; render layer redacts at display.
            # Bug 4 fix: cap the gitleaks Match length too — gitleaks can
            # emit long Match strings for things like JWT bodies.
            line_text = leak.get("Match", "")[:MAX_QUOTED_LINE_CHARS]

            findings.append(
                Finding(
                    finding_id=make_finding_id(next_id),
                    artifact=ArtifactKind.CREDENTIALS,
                    severity=Severity.HIGH,
                    summary=f"[gitleaks] {rule} detected in {rel_file}",
                    details=(
                        f"gitleaks rule '{rule}' matched in {rel_file}:{line_no}.\n"
                        f"Secret value not shown in this summary."
                    ),
                    citation=Citation(
                        file=rel_file,
                        line_start=line_no,
                        line_end=line_no,
                        quoted_code=line_text or f"# gitleaks match in {rel_file}",
                    ),
                    is_sensitive=True,
                    recommendation=(
                        "Review the matched pattern, rotate the credential, and remove"
                        " from source control history."
                    ),
                    effort=Effort.S,
                    confidence=0.85,
                )
            )
            next_id += 1
        except (KeyError, TypeError, ValueError):
            continue
    return findings


# ---------------------------------------------------------------------------
# Health score
# ---------------------------------------------------------------------------


def _health_score(findings: list[Finding]) -> int:
    """Subtract from 100 per finding. Floor at 0.

    Critical: -25, High: -15, Medium: -5, Low: -1, Info: -0.
    """
    weight = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 5,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    score = 100.0 - sum(weight[f.severity] for f in findings)
    return max(0, int(round(score)))


# ---------------------------------------------------------------------------
# Public scan() entry point
# ---------------------------------------------------------------------------


def scan(ingest: IngestResult, *, finding_start: int = 1) -> ArtifactReport:
    """Scan all text-source files in the repo for credential patterns.

    Returns an ArtifactReport with artifact=ArtifactKind.CREDENTIALS.
    """
    all_hits: list[RawHit] = []
    env_files_found: list[str] = []

    for f in ingest.files:
        rel = f.relative_path
        p = f.path
        name_lower = p.name.lower()

        # Check for .env-family files first (path-based).
        if name_lower == ".env" or name_lower.startswith(".env."):
            # A real committed .env is a HIGH structural finding. A TEMPLATE
            # (.env.example / .sample / .template / .dist) is NOT a committed
            # secret -- flagging it produced pmxt's false "1 committed .env"
            # (Day 16 D2).
            if _is_real_committed_env(name_lower):
                env_files_found.append(rel)
                all_hits.append(_scan_env_file(rel))
            # Either way, still scan the content: a real key pasted into a
            # template is still a real leak we want to surface.
            lines = _safe_read_lines(p)
            if lines:
                is_test = _is_test_path(rel)
                all_hits.extend(_scan_file_for_patterns(lines, rel, is_test))
                all_hits.extend(_scan_file_for_entropy(lines, rel, is_test))
            continue

        # Skip high-noise extensions.
        if _should_skip_extension(p):
            continue

        lines = _safe_read_lines(p)
        if lines is None:
            continue  # too large or unreadable

        is_test = _is_test_path(rel)
        all_hits.extend(_scan_file_for_patterns(lines, rel, is_test))
        all_hits.extend(_scan_file_for_entropy(lines, rel, is_test))

    # Collapse high-volume per-file groups (likely fixtures).
    all_hits = _collapse_hits(all_hits)

    # Build Findings from hits.
    findings: list[Finding] = []
    next_id = finding_start
    seen_locations: set[tuple[str, int, str]] = set()

    for hit in all_hits:
        # Deduplicate exact same (file, line, pattern) triples.
        loc_key = (hit.relative_path, hit.line_no, hit.pattern_name)
        if loc_key in seen_locations:
            continue
        seen_locations.add(loc_key)

        summary = (
            f"{hit.summary_label} found in {hit.relative_path}:{hit.line_no}"
        )
        # Truncate if over schema limit.
        summary = summary[:200]

        details = (
            f"Category: {hit.summary_label}\n"
            f"File: {hit.relative_path}\n"
            f"Line: {hit.line_no}\n"
            f"Pattern: {hit.pattern_name}\n"
            f"Severity rationale: {'test/fixture file -- downgraded' if _is_test_path(hit.relative_path) else 'production file'}\n"
            f"Quoted (redacted): {hit.quoted_line}"
        )

        # Effort: CRITICAL/HIGH findings need rotation (M); others lighter.
        effort = Effort.M if hit.severity in {Severity.CRITICAL, Severity.HIGH} else Effort.S

        findings.append(
            Finding(
                finding_id=make_finding_id(next_id),
                artifact=ArtifactKind.CREDENTIALS,
                severity=hit.severity,
                summary=summary,
                details=details,
                citation=Citation(
                    file=hit.relative_path,
                    line_start=hit.line_no,
                    line_end=hit.line_no,
                    quoted_code=hit.quoted_line,
                ),
                recommendation=hit.recommendation,
                effort=effort,
                confidence=hit.confidence,
                is_sensitive=True,
            )
        )
        next_id += 1

    # Optional gitleaks supplement.
    gitleaks_findings = _run_gitleaks(ingest.repo_root, next_id)
    findings.extend(gitleaks_findings)

    # Build narrative.
    n_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in findings if f.severity == Severity.HIGH)
    n_medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    n_low = sum(1 for f in findings if f.severity == Severity.LOW)

    if not findings:
        narrative = (
            "No hardcoded credentials or committed secret files were detected in this"
            " repository. Patterns checked include AWS keys, Stripe keys, SSH private"
            " keys, GitHub PATs, Anthropic/OpenAI API keys, Slack tokens, and"
            " high-entropy variable assignments. This does not guarantee the absence"
            " of secrets -- a manual review of environment variable injection points"
            " and CI/CD pipelines is still recommended."
        )
    else:
        env_note = (
            f" {len(env_files_found)} committed .env file(s) detected."
            if env_files_found
            else ""
        )
        narrative = (
            f"Found {len(findings)} credential finding(s) across the codebase:"
            f" {n_critical} CRITICAL, {n_high} HIGH, {n_medium} MEDIUM, {n_low} LOW."
            f"{env_note}"
            f" Each finding must be rotated before close, and access credentials"
            f" should be transferred to the buyer via a secrets manager handoff"
            f" (not raw values in email). Low-severity findings in test files"
            f" are likely fixture data but should be confirmed."
        )

    return ArtifactReport(
        artifact=ArtifactKind.CREDENTIALS,
        summary_narrative=narrative,
        findings=findings,
        health_score=_health_score(findings),
    )
