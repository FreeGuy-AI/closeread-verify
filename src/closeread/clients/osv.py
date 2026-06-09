"""Minimal client for OSV.dev — Google's open-source vulnerability database.

Free, no API key required. Documented at https://google.github.io/osv.dev/api/.

Why OSV: it's the most aggregated free CVE/advisory source. Better signal
than NVD alone for npm/pip/etc. ecosystems.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 20.0

# Bug 1 fix (Day 7 10-OSS batch): OSV.dev returned IncompleteRead /
# transient 5xx on monorepos (cal.com + ghost both died mid-scan with
# 20-30 manifests). Wrap each query in a bounded exponential backoff so
# one bad chunk no longer kills the whole audit.
_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF_S = (0.5, 1.0, 2.0)  # one entry per attempt-after-first


@dataclass
class Vulnerability:
    id: str  # e.g. GHSA-xxxx, CVE-2023-xxxxx
    summary: str
    severity_score: float | None  # CVSS 0-10 if available
    severity_label: str | None  # "CRITICAL" / "HIGH" / ...
    aliases: list[str] = field(default_factory=list)
    affected_ranges: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class OSVResult:
    """Vulnerabilities found for a specific package@version."""

    ecosystem: str
    package: str
    version: str | None
    vulnerabilities: list[Vulnerability]
    error: str | None = None  # set if the API call failed

    def is_clean(self) -> bool:
        return self.error is None and not self.vulnerabilities

    def worst_severity_label(self) -> str | None:
        order = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"]
        labels = {v.severity_label for v in self.vulnerabilities if v.severity_label}
        for level in order:
            if level in labels:
                return level
        return None


# ---------------------------------------------------------------------------
# Open-range false-positive guard (Day 21 Gap B)
# Free Guy/findings/2026-06-04-seal-proof-and-batch-2-gaps.md
#
# OSV matches a version server-side. When an advisory's SEMVER range is the
# known-incomplete OPEN shape (an `introduced` event with no `fixed` /
# `last_affected`), OSV treats EVERY version as affected -- even versions the
# advisory's own `database_specific.last_known_affected_version_range` clears.
# That shipped a false positive: xlsx@0.20.3 flagged for GHSA-4r6h-8v6p-xvw6
# (CVE-2023-30533, fixed in 0.19.3 but delisted from npm so OSV's npm range
# never got a `fixed` event). We override OSV ONLY in that exact shape, and
# ONLY when the queried version is CONFIDENTLY outside the boundary. Any parse
# uncertainty keeps the finding (never trade a false positive for a false
# negative).
# ---------------------------------------------------------------------------

_CONSTRAINT_RE = re.compile(r"(<=|>=|<|>|==|=)\s*v?([0-9][0-9A-Za-z.+\-]*)")


def _release_tuple(version: str) -> tuple[int, ...] | None:
    """Numeric release components of a clean version, else None (uncertain).

    '0.20.3' -> (0, 20, 3). A prerelease/build suffix ('1.2.3-rc1', '1.2.3+x')
    or any non-numeric segment returns None, so prerelease edge cases are never
    risked into a wrong drop.
    """
    s = version.strip().lstrip("vV=")
    if not s or "-" in s or "+" in s:
        return None
    out: list[int] = []
    for part in s.split("."):
        if not part.isdigit():
            return None
        out.append(int(part))
    return tuple(out) or None


def _cmp_release(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _satisfies(vt: tuple[int, ...], op: str, bt: tuple[int, ...]) -> bool:
    c = _cmp_release(vt, bt)
    return {
        "<": c < 0,
        "<=": c <= 0,
        ">": c > 0,
        ">=": c >= 0,
        "=": c == 0,
        "==": c == 0,
    }.get(op, True)


def _confidently_outside(version: str, boundary: str) -> bool:
    """True only if `version` can be cleanly placed OUTSIDE `boundary`.

    `boundary` is a last_known_affected_version_range like '< 0.19.3' or
    '>= 1.0.0, < 2.0.0'. The version is WITHIN the affected set if it satisfies
    every clause; OUTSIDE if it fails at least one. Returns False on any parse
    uncertainty (keep the finding).
    """
    vt = _release_tuple(version)
    if vt is None:
        return False
    clauses = _CONSTRAINT_RE.findall(boundary)
    if not clauses:
        return False
    for op, bound in clauses:
        bt = _release_tuple(bound)
        if bt is None:
            return False
        if not _satisfies(vt, op, bt):
            return True
    return False


def _open_range_match_is_spurious(
    advisory: dict[str, Any], ecosystem: str, package: str, version: str | None
) -> bool:
    """True if this OSV match exists ONLY because of an unbounded open range.

    Narrow + conservative: drops a match ONLY when, for the matched
    package+ecosystem, EVERY affected entry is open-ended (no `fixed` /
    `last_affected` event, no explicit `versions` list) AND each carries a
    `last_known_affected_version_range` that confidently places the queried
    version outside it. Any concrete boundary, missing boundary, or parse
    uncertainty returns False (trust OSV, keep the finding).
    """
    if not version:
        return False
    relevant = [
        a
        for a in advisory.get("affected", [])
        if a.get("package", {}).get("ecosystem") == ecosystem
        and str(a.get("package", {}).get("name", "")).lower() == package.lower()
    ]
    if not relevant:
        return False
    for a in relevant:
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev or "last_affected" in ev:
                    return False  # a concrete boundary -> trust OSV
        if a.get("versions"):
            return False  # explicit affected versions -> trust OSV
        lkav = a.get("database_specific", {}).get("last_known_affected_version_range")
        if not lkav or not _confidently_outside(version, lkav):
            return False  # unrefutable open range -> keep the finding
    return True


def _parse_severity(advisory: dict[str, Any]) -> tuple[float | None, str | None]:
    """Try to extract a CVSS score + label from an OSV advisory."""
    score: float | None = None
    label: str | None = None
    severities = advisory.get("severity", [])
    for s in severities:
        s_type = s.get("type", "")
        s_score = s.get("score", "")
        if s_type.startswith("CVSS_V") and s_score:
            # CVSS vector strings — we want the numeric base score
            # Easier proxy: look at the database_specific.severity if present
            pass
    db_specific = advisory.get("database_specific", {})
    if "severity" in db_specific:
        label = str(db_specific["severity"]).upper()
    if "cvss_score" in db_specific:
        try:
            score = float(db_specific["cvss_score"])
        except (TypeError, ValueError):
            pass
    return score, label


def _parse_vuln(advisory: dict[str, Any]) -> Vulnerability:
    score, label = _parse_severity(advisory)
    aliases = list(advisory.get("aliases", []))
    refs = [r.get("url", "") for r in advisory.get("references", []) if r.get("url")]
    affected_ranges: list[str] = []
    for a in advisory.get("affected", []):
        for r in a.get("ranges", []):
            events = r.get("events", [])
            events_str = ", ".join(
                f"{k}={v}" for ev in events for k, v in ev.items() if v
            )
            if events_str:
                affected_ranges.append(events_str)
    return Vulnerability(
        id=advisory.get("id", "unknown"),
        summary=advisory.get("summary") or advisory.get("details", "")[:300],
        severity_score=score,
        severity_label=label,
        aliases=aliases,
        affected_ranges=affected_ranges,
        references=refs,
    )


def _is_retryable(exc: Exception) -> bool:
    """Transient network / server errors that justify a retry.

    Includes timeouts, connection drops, IncompleteRead-style protocol
    errors, and 5xx responses. Excludes 4xx (caller's payload is wrong;
    retry would just burn budget).
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return 500 <= exc.response.status_code < 600
    return isinstance(
        exc,
        (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.ReadError,
            httpx.WriteError,
            httpx.RemoteProtocolError,  # IncompleteRead, server hangup mid-body
            httpx.NetworkError,
        ),
    )


async def query_one(
    client: httpx.AsyncClient,
    *,
    ecosystem: str,
    package: str,
    version: str | None,
) -> OSVResult:
    """Query OSV for one package@version with bounded retry."""
    payload: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    last_exc: Exception | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
            # Drop matches that exist only because OSV's SEMVER range is the
            # known-incomplete open shape while the advisory's last_known_affected
            # boundary clears this version (Day 21 Gap B).
            kept = [
                a
                for a in data.get("vulns", [])
                if not _open_range_match_is_spurious(a, ecosystem, package, version)
            ]
            vulns = [_parse_vuln(a) for a in kept]
            return OSVResult(
                ecosystem=ecosystem,
                package=package,
                version=version,
                vulnerabilities=vulns,
            )
        except httpx.HTTPError as e:
            last_exc = e
            if attempt + 1 >= _RETRY_ATTEMPTS or not _is_retryable(e):
                break
            await asyncio.sleep(_RETRY_BACKOFF_S[attempt])

    return OSVResult(
        ecosystem=ecosystem,
        package=package,
        version=version,
        vulnerabilities=[],
        error=str(last_exc) if last_exc else "unknown error",
    )


async def query_many(
    deps: list[tuple[str, str, str | None]],
    *,
    concurrency: int = 8,
) -> list[OSVResult]:
    """Query OSV for many (ecosystem, package, version) tuples in parallel."""
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:

        async def _bounded(eco: str, pkg: str, ver: str | None) -> OSVResult:
            async with sem:
                return await query_one(
                    client, ecosystem=eco, package=pkg, version=ver
                )

        tasks = [_bounded(eco, pkg, ver) for eco, pkg, ver in deps]
        return await asyncio.gather(*tasks)
