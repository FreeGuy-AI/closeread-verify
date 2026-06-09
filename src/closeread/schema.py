"""Pydantic schemas for Closeread audit packets.

These are the contract for every finding and every artifact. The verifier
agent rejects any finding that does not conform to this schema. The render
layer assumes this shape.

Lesson 004 from Free Guy's brain: the vault is the brain. This file is the
canonical schema. Don't duplicate it elsewhere.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from closeread.source_role import SourceRole, classify_source_role


class Severity(StrEnum):
    """How loud should the buyer's alarm be."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Effort(StrEnum):
    """T-shirt sizing for remediation effort."""

    XS = "XS"  # <1 hour
    S = "S"  # <1 day
    M = "M"  # 1-3 days
    L = "L"  # 1-2 weeks
    XL = "XL"  # >2 weeks


class ArtifactKind(StrEnum):
    """The artifacts in a Closeread packet, mapped to buyer DD questions."""

    RELIABILITY = "reliability"  # Q1: error log, downtime risk
    SCA = "sca"  # Q2: software composition analysis (deps + CVEs)
    STACK = "stack"  # Q3: tech stack + hireability
    IP_OWNERSHIP = "ip_ownership"  # Q4: IP ownership, contributor assignment
    ARCHITECTURE = "architecture"  # Q5: architecture walkthrough
    THIRD_PARTY = "third_party"  # Q6: third-party API dependencies + costs
    CREDENTIALS = "credentials"  # Q7: credential inventory
    SECURITY = "security"  # Q8: security posture (pre-pentest signal)
    TEST_COVERAGE = "test_coverage"  # Q9: test coverage reality check
    KEY_PERSON = "key_person"  # Q10: bus factor, undocumented decisions
    # DECISION: DB_MIGRATION is an 11th artifact beyond the original 10.
    # It answers the buyer DD question "how does the seller manage schema change?"
    # which M&A reviewers rank in the top 3 post-close risk signals. Adding it
    # as a separate kind keeps the packet renderer and verifier extensible without
    # mutating any existing artifact's ID space.
    DB_MIGRATION = "db_migration"  # Q11: database migration risk
    # DECISION: LICENSE_COMPLIANCE is a 12th artifact. It is distinct from
    # SCA (CVE/dep inventory) and IP_OWNERSHIP (repo's own license file). This
    # artifact answers "what license-conflict liability does the buyer inherit from
    # the dependency tree?" -- a separate buyer DD question that colliding with
    # ArtifactKind.SCA was masking. Day 11 bug fix: unwired specialist.
    LICENSE_COMPLIANCE = "license_compliance"  # Q12: dependency tree license risk
    # DECISION: API_VERSIONING is a 13th artifact. It was previously mapped to
    # RELIABILITY (closest buyer DD question) but that caused finding-level
    # collision: api_versioning findings were merged into the reliability section
    # in the packet, hiding them from the renderer and from buyers looking for
    # API-surface risk specifically. Day 11 bug fix: unwired specialist.
    API_VERSIONING = "api_versioning"  # Q13: API versioning hygiene


class Citation(BaseModel):
    """Pointer back into the source code. Required on every finding.

    The verifier confirms `quoted_code` appears verbatim at the cited location
    before letting the finding into the packet.
    """

    file: str = Field(..., description="Path relative to repo root")
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    quoted_code: str = Field(
        ...,
        min_length=1,
        description="Verbatim code at file:line_start..line_end. Verifier re-reads.",
    )

    @field_validator("quoted_code", mode="before")
    @classmethod
    def _coerce_empty_quote(cls, v: object) -> object:
        # A scanner can legitimately surface an absence-type finding with no single
        # line to quote (e.g. missing-api-versioning-strategy). Rather than crash
        # schema validation (min_length=1) and abort the entire audit, coerce an
        # empty/whitespace quote to a non-matching sentinel. The verifier then drops
        # the finding at the citation gate. Honest behavior preserved: a finding that
        # cannot quote real code never ships in a packet.
        if v is None or (isinstance(v, str) and not v.strip()):
            return "[no-verbatim-excerpt-available]"
        return v

    @field_validator("line_end")
    @classmethod
    def end_must_be_after_or_equal_to_start(cls, v: int, info) -> int:
        start = info.data.get("line_start")
        if start is not None and v < start:
            raise ValueError(f"line_end ({v}) must be >= line_start ({start})")
        return v

    def location_str(self) -> str:
        if self.line_start == self.line_end:
            return f"{self.file}:{self.line_start}"
        return f"{self.file}:{self.line_start}-{self.line_end}"


class Finding(BaseModel):
    """One atomic finding in an artifact. Must cite source."""

    finding_id: str = Field(..., pattern=r"^FREE-\d{4}$")
    artifact: ArtifactKind
    severity: Severity
    summary: str = Field(..., min_length=1, max_length=200)
    details: str = Field(..., min_length=1)
    citation: Citation
    recommendation: str = Field(..., min_length=1)
    effort: Effort
    confidence: float = Field(..., ge=0.0, le=1.0)
    is_sensitive: bool = Field(
        default=False,
        description=(
            "If true, the citation contains sensitive content (e.g. credential). "
            "Verifier still confirms verbatim match against source; render layer "
            "redacts before display."
        ),
    )
    dependency_kind: str | None = Field(
        default=None,
        description=(
            "For SCA findings: 'prod' (direct production dep), 'dev', 'peer', "
            "'optional', or 'transitive'. None for non-dependency findings "
            "(credentials, structural), which are treated as headline-worthy. "
            "Used to keep a dev/transitive CVE from leading a buyer's headline "
            "when a real production finding exists (Gap C)."
        ),
    )

    def is_critical(self) -> bool:
        return self.severity in {Severity.CRITICAL, Severity.HIGH}

    @property
    def source_role(self) -> SourceRole:
        """Where this finding lives: PRODUCT tree vs EXAMPLE / TEST / DOCS.

        Computed from ``citation.file`` on access -- the path is the source of
        truth, so this is a property, not a stored field. It never appears in
        ``model_dump()`` (no schema change, no double-write); existing packets
        and tests round-trip unchanged.
        """
        return classify_source_role(self.citation.file)


class ArtifactReport(BaseModel):
    """One of the 10 artifacts. Findings + narrative summary.

    The canonical enum field is `artifact` (since 0.1). Bug 8 from the
    Day 7 OSS batch noted that external integrations sometimes look for
    `artifact_type` instead; the alias property below makes both names
    work so consumers don't have to track which spelling the in-tree
    code uses.
    """

    artifact: ArtifactKind
    summary_narrative: str = Field(
        ...,
        description="Plain-English overview of this artifact's findings, for the seller to read first.",
    )
    findings: list[Finding] = Field(default_factory=list)
    health_score: int = Field(..., ge=0, le=100, description="0-100 score for this artifact")

    @property
    def artifact_type(self) -> ArtifactKind:
        """Alias for `artifact`. Kept for external integrations (Bug 8 fix).

        Prefer `.artifact` in new code. This property exists so a
        consumer that reaches for `report.artifact_type` doesn't crash;
        it does not appear in the Pydantic field schema (no JSON-Schema
        leak, no double-serialization).
        """
        return self.artifact

    def severity_breakdown(self) -> dict[Severity, int]:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out


class RepoMetadata(BaseModel):
    """What we know about the repo being audited."""

    name: str
    source: str = Field(..., description="URL or local path")
    commit_sha: str | None = None
    total_files: int
    total_lines: int
    primary_language: str
    languages: dict[str, int] = Field(
        default_factory=dict,
        description="Language -> line count breakdown.",
    )


class CostBreakdown(BaseModel):
    """Per-audit-run cost data, exposed for the ADR-0016 cost-aware pricing
    promise (publish $/audit alongside every shipped sample packet).

    Phase 1 (Day 8) only captures adversarial-reviewer cost; other lines
    (specialist Claude calls, narrative agent, render, ingest) are
    aggregated as those code paths get instrumented in subsequent phases.

    ADR-0018 Phase 1 (Day 11) adds per-backend cost fields. The legacy
    `adversarial_review_*` fields stay populated for backwards
    compatibility (existing renderer + tests + published sample packets
    continue to read them); the new `gpt5_codex_*` / `gemini_direct_*`
    / `deepseek_direct_*` / `openrouter_fallback_*` fields decompose
    the same number across the multi-backend rotation.

    Subscription-covered backends (Codex sub, Gemini sub) report
    `*_cost_usd = 0.0` but a non-zero `*_call_count` — the breakdown
    surfaces the free-rider economics promised in ADR-0018.
    """

    adversarial_review_cost_usd: float = Field(default=0.0, ge=0.0)
    adversarial_review_call_count: int = Field(default=0, ge=0)
    adversarial_review_tokens_in: int = Field(default=0, ge=0)
    adversarial_review_tokens_out: int = Field(default=0, ge=0)
    # Bug 9 fix (Day 8 batch-2): when every OpenRouter call fails (HTTP
    # 402 credits-empty, persistent timeout, etc.) we still record a
    # call_count but cost and tokens are zero across the board. Without
    # this flag the renderer would show "$0.0000 (N calls)" which is
    # structurally misleading: looks like a free run, actually a
    # degraded run. The flag makes the renderer + downstream pricing
    # consumer distinguish "free" from "broken".
    adversarial_review_degraded: bool = Field(default=False)

    # ADR-0018 Phase 1: per-backend decomposition. Every value defaults
    # to 0 so old packets (no per-backend instrumentation) round-trip
    # through Pydantic unchanged.
    gpt5_codex_cost_usd: float = Field(default=0.0, ge=0.0)
    gpt5_codex_call_count: int = Field(default=0, ge=0)
    gpt5_codex_tokens_in: int = Field(default=0, ge=0)
    gpt5_codex_tokens_out: int = Field(default=0, ge=0)

    gemini_direct_cost_usd: float = Field(default=0.0, ge=0.0)
    gemini_direct_call_count: int = Field(default=0, ge=0)
    gemini_direct_tokens_in: int = Field(default=0, ge=0)
    gemini_direct_tokens_out: int = Field(default=0, ge=0)

    deepseek_direct_cost_usd: float = Field(default=0.0, ge=0.0)
    deepseek_direct_call_count: int = Field(default=0, ge=0)
    deepseek_direct_tokens_in: int = Field(default=0, ge=0)
    deepseek_direct_tokens_out: int = Field(default=0, ge=0)

    openrouter_fallback_cost_usd: float = Field(default=0.0, ge=0.0)
    openrouter_fallback_call_count: int = Field(default=0, ge=0)
    openrouter_fallback_tokens_in: int = Field(default=0, ge=0)
    openrouter_fallback_tokens_out: int = Field(default=0, ge=0)

    # Aggregate field. Currently equal to adversarial_review_cost_usd; the
    # contract is "sum of every cost line in the packet" so when other
    # lines are wired this field gets the full sum without breaking any
    # downstream packet-renderer / pricing-page consumer.
    total_cost_usd: float = Field(default=0.0, ge=0.0)


class AuditPacket(BaseModel):
    """A complete Closeread DD packet. The customer's deliverable."""

    packet_id: str = Field(..., description="Unique ID for this audit run")
    customer_name: str | None = None
    repo: RepoMetadata
    started_at: datetime
    completed_at: datetime | None = None
    artifacts: list[ArtifactReport] = Field(default_factory=list)
    overall_health_score: int | None = Field(default=None, ge=0, le=100)
    cost_breakdown: CostBreakdown | None = Field(
        default=None,
        description=(
            "Per-audit cost data (ADR-0016 Phase 1). None when no cost "
            "lines were captured (e.g. adversarial reviewer skipped due "
            "to missing OPENROUTER_API_KEY)."
        ),
    )

    def total_findings(self) -> int:
        return sum(len(a.findings) for a in self.artifacts)

    def critical_findings(self) -> list[Finding]:
        return [f for a in self.artifacts for f in a.findings if f.is_critical()]

    def product_findings(self) -> list[Finding]:
        """Findings in the shippable product tree (the buyer's headline)."""
        return [
            f
            for a in self.artifacts
            for f in a.findings
            if f.source_role == SourceRole.PRODUCT
        ]

    def non_product_findings(self) -> list[Finding]:
        """Findings in example / test / docs code: real, but lower priority."""
        return [
            f
            for a in self.artifacts
            for f in a.findings
            if f.source_role != SourceRole.PRODUCT
        ]

    def product_critical_findings(self) -> list[Finding]:
        """Critical/high findings in the product tree only. The 'read first'
        list leads with these so example/test/docs findings never inflate the
        buyer's deal-killer count (Day 16 product bug D1)."""
        return [f for f in self.product_findings() if f.is_critical()]

    def give_first_lead(self) -> Finding | None:
        """The single product-critical finding to lead give-first outreach with.

        Leads ONLY with a DIRECT finding: a production-runtime dependency
        (dependency_kind 'prod') or a non-dependency headline issue (credential /
        structural, dependency_kind None). A founder can act on a direct dep they
        declared; a transitive/dev-only CVE they merely inherited is not a worthy
        headline, and leading with one (e.g. a build tool like @babel/traverse)
        reads like scanner noise. If the product tree has only transitive/dev
        findings, returns None so the give-first is DROPPED rather than sent with a
        weak lead (Day 24: monitoro had 52 transitive findings and zero direct, so
        there is nothing honest to lead with). Within the direct set: highest
        severity, then highest confidence. The full packet still reports the
        transitive findings; this only governs the single headline.
        """
        direct = [
            f for f in self.product_critical_findings()
            if f.dependency_kind in {None, "prod"}
        ]
        if not direct:
            return None
        sev_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        direct.sort(key=lambda f: (sev_rank[f.severity], -f.confidence))
        return direct[0]

    def grouped_product_findings(self) -> list[dict]:
        """Judgment-ordered, deduped deliverable view of the product-critical findings.

        The raw finding list is one row per (package, version, advisory): a single
        aged dependency can produce a dozen near-identical rows, which reads like a
        scanner dump rather than the judgment Closeread sells. This collapses SCA
        findings to one entry per package (with its affected versions + advisory ids),
        tags each as direct (the founder's to bump) vs transitive (inherited), keeps
        non-dependency findings (credentials, structural) as standalone headline
        issues, and orders by actionability: headline issues first, then direct deps,
        then transitive, severity-first within each tier.

        Returns pre-sorted dicts so every consumer (give-first email, reply packet,
        customer report) renders the same view top-to-bottom.
        """
        import re

        # OSV returns ids under many prefixes, not just GHSA/CVE: PyPI advisories
        # are often PYSEC-, Go is GO-, Rust is RUSTSEC-, plus OSV-/GSD-/DSA-/etc.
        # Matching only GHSA/CVE dropped a real Python/Go DIRECT CVE into the
        # standalone `else` branch, leaking the raw scanner summary as the package
        # name with no version/advisory collapse (Gap 4, Day 24).
        sca_re = re.compile(
            r"^(?P<pkg>.+)@(?P<ver>\d\S*?)\s+affected by\s+"
            r"(?P<adv>(?:GHSA|CVE|PYSEC|GO|RUSTSEC|OSV|GSD|DSA|RHSA|DLA)-\S+)",
            re.IGNORECASE,
        )
        sev_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        direct_kinds = {None, "prod"}
        deps: dict[str, dict] = {}
        standalone: list[dict] = []

        for f in self.product_critical_findings():
            m = sca_re.match(f.summary)
            loc = f.citation.location_str() if f.citation else ""
            if m:
                pkg = m.group("pkg").strip()
                ver = m.group("ver").strip().rstrip(".")
                adv = m.group("adv").strip().rstrip(".")
                g = deps.get(pkg)
                if g is None:
                    g = deps[pkg] = {
                        "kind": "dependency",
                        "package": pkg,
                        "_sev": f.severity,
                        "is_direct": False,
                        "versions": set(),
                        "advisories": set(),
                        "locations": set(),
                        "recommendation": f.recommendation,
                    }
                g["versions"].add(ver)
                g["advisories"].add(adv)
                if loc:
                    g["locations"].add(loc)
                if f.dependency_kind in direct_kinds:
                    g["is_direct"] = True
                if sev_rank[f.severity] < sev_rank[g["_sev"]]:
                    g["_sev"] = f.severity
            else:
                standalone.append({
                    "kind": "issue",
                    "package": f.summary,
                    "_sev": f.severity,
                    "is_direct": True,
                    "versions": [],
                    "advisories": [],
                    "locations": [loc] if loc else [],
                    "recommendation": f.recommendation,
                })

        groups = list(deps.values()) + standalone

        def tier(g: dict) -> int:
            if g["kind"] == "issue":
                return 0
            return 1 if g["is_direct"] else 2

        groups.sort(key=lambda g: (tier(g), sev_rank[g["_sev"]], -len(g["advisories"])))

        out = []
        for g in groups:
            versions = g["versions"]
            advisories = g["advisories"]
            locations = g["locations"]
            out.append({
                "kind": g["kind"],
                "package": g["package"],
                "severity": g["_sev"].value,
                "is_direct": g["is_direct"],
                "versions": sorted(versions) if isinstance(versions, set) else versions,
                "advisories": sorted(advisories) if isinstance(advisories, set) else advisories,
                "advisory_count": len(advisories),
                "locations": sorted(locations) if isinstance(locations, set) else locations,
                "recommendation": g["recommendation"],
            })
        return out

    def get_artifact(self, kind: ArtifactKind) -> ArtifactReport | None:
        for a in self.artifacts:
            if a.artifact == kind:
                return a
        return None


def make_finding_id(index: int) -> str:
    """FREE-0001, FREE-0002, ..."""
    return f"FREE-{index:04d}"
