"""SCA — Software Composition Analysis scanner.

Reads package manifests, extracts (name, version) tuples, queries OSV.dev for
known vulnerabilities, emits Findings with citations back to the manifest line.

v1 scope: package.json, requirements.txt, pyproject.toml.
v2+: pnpm-lock.yaml, poetry.lock, Gemfile, go.mod, etc. (richer ecosystems).

No Claude API in this scanner. The narrative summary is added separately by
the narrative agent — this scanner does deterministic fact-finding only.
"""

from __future__ import annotations

import asyncio
import json
import re
import tomllib
from dataclasses import dataclass, replace

from closeread.clients.osv import OSVResult, query_many
from closeread.ingest import IngestedFile, IngestResult
from closeread.schema import (
    ArtifactKind,
    ArtifactReport,
    Citation,
    Effort,
    Finding,
    Severity,
    make_finding_id,
)


@dataclass(frozen=True)
class Dependency:
    """A single dependency, with where in the manifest it lives."""

    name: str
    version: str | None
    ecosystem: str  # "npm", "PyPI", etc. (OSV ecosystem keys)
    manifest_path: str  # relative
    line_start: int
    line_end: int
    quoted: str  # exact line text
    # True if this came from a LOCKFILE (the installed/resolved version); False if
    # from a manifest declaration (a range like "^1.2.7", resolved to its floor).
    # The installed version is the truth; a declared floor can sit below a fix the
    # lockfile already pulled. See extract_dependencies (Gap D, Day 21).
    resolved: bool = False
    # "prod" (direct production dep), "dev", "peer", "optional", "transitive", or
    # "unknown" (a lockfile entry before extract_dependencies resolves its kind).
    # Used to keep dev/transitive CVEs from leading a buyer headline (Gap C).
    dependency_kind: str = "unknown"


SEVERITY_FROM_OSV: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


# OSV ecosystem names. See https://google.github.io/osv.dev/data/.
ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "rubygems": "RubyGems",
    "go": "Go",
    "cargo": "crates.io",
    "composer": "Packagist",
    "maven": "Maven",
    "gradle": "Maven",
}


# --- Parsers --------------------------------------------------------------


def _find_line_for_substring(
    lines: list[str], needle: str, start_from: int = 0
) -> tuple[int, str] | None:
    """Find the 1-indexed line number containing `needle`. Returns (line_no, line_text) or None."""
    for i in range(start_from, len(lines)):
        if needle in lines[i]:
            return i + 1, lines[i].rstrip("\n")
    return None


# Non-registry npm version specifiers: the version cannot be read from the
# manifest (it points at a tarball, a workspace, a git ref, or a URL).
_NPM_NONREGISTRY_PREFIXES = (
    "file:",
    "link:",
    "workspace:",
    "git+",
    "git:",
    "github:",
    "http://",
    "https://",
    "npm:",
    "portal:",
    "patch:",
)
# A vendored tarball name like xlsx-0.20.3.tgz still carries a concrete version.
_TARBALL_VERSION_RE = re.compile(
    r"-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)\.(?:tgz|tar\.gz)$"
)


def _resolve_npm_version(spec: object) -> str | None:
    """Resolve a package.json version spec to a concrete version, or None.

    package.json declares ranges, not installed versions. We OSV-match only when
    the spec pins a sound proxy for the installed version (exact, ^, ~, =). Open
    lower bounds (>=, >), upper bounds (<), wildcards (*, latest), and
    non-registry specs (file:, link:, workspace:, git, http) are UNRESOLVABLE
    from the manifest alone and produce false positives if matched (Day 19:
    cal-com `next: ">=14.0.0"` matched a CVE the installed 16.x never saw). For a
    vendored tarball we recover the version from the filename so a genuinely
    pinned vulnerable dep is still caught (formbricks xlsx-0.20.3.tgz -> 0.20.3).
    """
    if not spec:
        return None
    s = str(spec).strip()
    if not s:
        return None
    low = s.lower()
    if low.startswith(_NPM_NONREGISTRY_PREFIXES):
        m = _TARBALL_VERSION_RE.search(s)
        return m.group(1) if m else None
    if s.startswith((">=", ">", "<")):
        return None
    if low in ("*", "x", "latest"):
        return None
    cleaned = s.lstrip("^~=v").split(",")[0].split(" ")[0].strip()
    return cleaned or None


# A resolvable version is at least major.minor of digits (plus optional
# patch/prerelease). Rejects malformed fragments like "2." or "1.8." (which the
# requirements regex produces from `==2.*` / `==1.8.*` wildcard pins) and anything
# with a wildcard. The prerelease/build suffix must have a real char after its
# separator, so a trailing "." can never slip through.
_PYPI_VALID_VERSION = re.compile(
    r"^\d+\.\d+(?:\.\d+)*(?:[.\-+][0-9A-Za-z][0-9A-Za-z.\-+]*)?$"
)


def _resolve_pypi_version(spec: object) -> str | None:
    """Resolve a PyPI version spec to a concrete version, or None.

    OSV-match only a version we can actually pin: an exact ``==`` pin or a bare
    version. Range operators (``>=``, ``>``, ``<``, ``<=``, ``~=``, ``!=``, ``^``,
    ``*``) are unresolvable from the manifest alone and produce false positives if
    matched to their floor (Day 21 sweep: fireshare ``Pillow>=10.0.0`` floored to
    10.0.0 matched a CVE the real install may have cleared). The installed version
    comes from the lockfile (poetry.lock / Pipfile.lock); without one, a range
    stays None. This is the PyPI analogue of _resolve_npm_version.
    """
    if not spec:
        return None
    s = str(spec).strip()
    if not s:
        return None
    if s.startswith("=="):
        v = s[2:].strip().split(",")[0].strip()
        return v if _PYPI_VALID_VERSION.match(v) else None
    # Any range / wildcard operator -> unresolvable (use the lockfile instead).
    if s[0] in "><~!^*" or "*" in s:
        return None
    # Bare version with no operator, e.g. "1.2.3".
    if s[0].isdigit():
        v = s.split(",")[0].split(";")[0].strip()
        return v if _PYPI_VALID_VERSION.match(v) else None
    return None


def parse_package_json(manifest: IngestedFile) -> list[Dependency]:
    """Extract npm dependencies from package.json."""
    text = manifest.path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=False)
    data = json.loads(text)

    section_kind = {
        "dependencies": "prod",
        "devDependencies": "dev",
        "peerDependencies": "peer",
        "optionalDependencies": "optional",
    }
    deps: list[Dependency] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = data.get(key) or {}
        if not isinstance(section, dict):
            continue
        kind = section_kind[key]
        for name, version in section.items():
            # Find the line containing this dep (best-effort).
            needle = f'"{name}"'
            found = _find_line_for_substring(lines, needle)
            if found is None:
                line_no, line_text = 1, f'"{name}": "{version}"'
            else:
                line_no, line_text = found
            # Resolve to a concrete version, or None if unresolvable (open
            # floor, non-registry, wildcard). See _resolve_npm_version.
            clean_version = _resolve_npm_version(version)
            deps.append(
                Dependency(
                    name=name,
                    version=clean_version,
                    ecosystem="npm",
                    manifest_path=manifest.relative_path,
                    line_start=line_no,
                    line_end=line_no,
                    quoted=line_text,
                    dependency_kind=kind,
                )
            )
    return deps


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]+\])?\s*([=<>~!]=?\s*[A-Za-z0-9_.\-]+)?"
)


def _requirements_kind(name: str) -> str:
    """A requirements-*dev*/*test* file holds dev deps; a dev-only CVE must not
    headline a buyer's give-first (consistent with Gap C). Everything else (the
    main requirements.txt, requirements/base.txt, requirements.in) is prod."""
    low = name.lower()
    return "dev" if ("dev" in low or "test" in low) else "prod"


def parse_requirements_txt(
    manifest: IngestedFile, *, kind: str = "prod"
) -> list[Dependency]:
    """Extract PyPI dependencies from a requirements file (txt or .in)."""
    text = manifest.path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=False)
    deps: list[Dependency] = []
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        version_spec = (m.group(2) or "").strip()
        # Resolve only exact pins; a range floor is unresolvable without a
        # lockfile (Gap D, Python extension). See _resolve_pypi_version.
        clean_version = _resolve_pypi_version(version_spec)
        deps.append(
            Dependency(
                name=name,
                version=clean_version,
                ecosystem="PyPI",
                manifest_path=manifest.relative_path,
                line_start=i,
                line_end=i,
                quoted=raw,
                dependency_kind=kind,
            )
        )
    return deps


def parse_pyproject_toml(manifest: IngestedFile) -> list[Dependency]:
    """Extract PyPI dependencies from pyproject.toml (PEP 621 + Poetry)."""
    text = manifest.path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=False)
    data = tomllib.loads(text)

    deps: list[Dependency] = []

    # PEP 621 style: [project] dependencies = ["foo>=1.0", ...]
    project = data.get("project", {})
    pep621_deps = project.get("dependencies", []) or []
    for spec in pep621_deps:
        m = _REQ_LINE_RE.match(spec)
        if not m:
            continue
        name = m.group(1)
        version_spec = (m.group(2) or "").strip()
        # Resolve only exact pins; a range floor is unresolvable without a
        # lockfile (Gap D, Python extension). See _resolve_pypi_version.
        clean_version = _resolve_pypi_version(version_spec)
        # Find the line in the source containing this dependency name
        found = _find_line_for_substring(lines, name)
        line_no, line_text = found if found else (1, spec)
        deps.append(
            Dependency(
                name=name,
                version=clean_version,
                ecosystem="PyPI",
                manifest_path=manifest.relative_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                dependency_kind="prod",
            )
        )

    # Poetry style: [tool.poetry.dependencies]
    poetry_deps = (data.get("tool", {}).get("poetry", {}).get("dependencies", {})) or {}
    for name, version in poetry_deps.items():
        if name.lower() == "python":
            continue
        clean_version = (
            _resolve_pypi_version(version) if isinstance(version, str) else None
        )
        found = _find_line_for_substring(lines, name)
        line_no, line_text = found if found else (1, f"{name} = {version}")
        deps.append(
            Dependency(
                name=name,
                version=clean_version,
                ecosystem="PyPI",
                manifest_path=manifest.relative_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                dependency_kind="prod",
            )
        )

    return deps


def parse_poetry_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse poetry.lock. Returns resolved PyPI deps from the [[package]] list."""
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, OSError, ValueError):
        return []
    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version or (name, version) in seen:
            continue
        seen.add((name, version))
        found = _find_line_for_substring(
            lines, f'name = "{name}"'
        ) or _find_line_for_substring(lines, str(name))
        line_no, line_text = found if found else (1, f"{name} {version}")
        out.append(
            Dependency(
                name=str(name),
                version=str(version),
                ecosystem="PyPI",
                manifest_path=manifest.relative_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                resolved=True,
            )
        )
    return out


def parse_pipfile_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse Pipfile.lock (JSON). Resolved PyPI deps from default + develop."""
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    for section, kind in (("default", "prod"), ("develop", "dev")):
        deps_obj = data.get(section, {})
        if not isinstance(deps_obj, dict):
            continue
        for name, info in deps_obj.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version", "")
            version = ver.lstrip("=").strip() if isinstance(ver, str) else None
            if not version or (name, version) in seen:
                continue
            seen.add((name, version))
            found = _find_line_for_substring(lines, f'"{name}"')
            line_no, line_text = found if found else (1, f"{name} {ver}")
            out.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="PyPI",
                    manifest_path=manifest.relative_path,
                    line_start=line_no,
                    line_end=line_no,
                    quoted=line_text,
                    resolved=True,
                    dependency_kind=kind,
                )
            )
    return out


# A requirements file is not just the literal "requirements.txt": the split
# layout uses requirements-dev.txt, requirements/base.txt, requirements*.txt and
# requirements.in (pip-tools). Mirror ingest.manifest_ecosystem's detection so the
# dispatch routes every variant through parse_requirements_txt (Gap 3, Day 24).
_REQUIREMENTS_NAME_RE = re.compile(r"^requirements.*\.(?:txt|in)$", re.IGNORECASE)


def _is_requirements_manifest(manifest: IngestedFile) -> bool:
    name = manifest.path.name
    if _REQUIREMENTS_NAME_RE.match(name):
        return True
    return manifest.path.parent.name == "requirements" and (
        manifest.path.suffix.lower() in (".txt", ".in")
    )


def parse_manifest(manifest: IngestedFile) -> list[Dependency]:
    """Dispatch to the right parser based on the manifest filename."""
    name = manifest.path.name
    try:
        if name == "package.json":
            return parse_package_json(manifest)
        if name == "package-lock.json":
            # Lazy import to avoid circular reference (lockfile_npm imports from sca)
            from closeread.scanners.lockfile_npm import parse_package_lock
            return parse_package_lock(manifest)
        if name == "pnpm-lock.yaml":
            from closeread.scanners.lockfile_npm import parse_pnpm_lock
            return parse_pnpm_lock(manifest)
        if name == "yarn.lock":
            from closeread.scanners.lockfile_npm import parse_yarn_lock
            return parse_yarn_lock(manifest)
        if _is_requirements_manifest(manifest):
            return parse_requirements_txt(manifest, kind=_requirements_kind(name))
        if name == "pyproject.toml":
            return parse_pyproject_toml(manifest)
        if name == "poetry.lock":
            return parse_poetry_lock(manifest)
        if name == "Pipfile.lock":
            return parse_pipfile_lock(manifest)
        if name == "Gemfile.lock":
            # Lazy import to avoid a circular reference (lockfile_polyglot imports
            # Dependency + _find_line_for_substring from this module).
            from closeread.scanners.lockfile_polyglot import parse_gemfile_lock
            return parse_gemfile_lock(manifest)
        if name == "composer.lock":
            from closeread.scanners.lockfile_polyglot import parse_composer_lock
            return parse_composer_lock(manifest)
        if name == "Cargo.lock":
            from closeread.scanners.lockfile_polyglot import parse_cargo_lock
            return parse_cargo_lock(manifest)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError, ValueError):
        # Don't let a bad manifest kill the whole scan.
        return []
    return []


# Manifest basenames parse_manifest actually has a parser for. Kept in lockstep
# with the dispatch above so the honesty caveat below cannot drift. (Requirements
# variants are matched by _is_requirements_manifest, not by exact name.)
_SUPPORTED_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "composer.lock",
        "Cargo.lock",
    }
)
# Human-readable label for the supported set, surfaced in the narrative so we
# never again under-report capability with a stale "npm, pip, poetry" string.
SUPPORTED_ECOSYSTEMS_LABEL = (
    "npm (incl. package-lock/pnpm/yarn), Python "
    "(requirements, pyproject, poetry.lock, Pipfile.lock), Ruby (Gemfile.lock), "
    "PHP (composer.lock), and Rust (Cargo.lock)"
)


def _manifest_is_supported(manifest: IngestedFile) -> bool:
    """True if parse_manifest has a real parser for this manifest."""
    return (
        manifest.path.name in _SUPPORTED_MANIFEST_NAMES
        or _is_requirements_manifest(manifest)
    )


def _unsupported_manifests(ingest: IngestResult) -> list[IngestedFile]:
    """Manifests ingest detected (Gemfile.lock, go.sum, Cargo.lock, composer.lock,
    pom.xml, mix.exs, ...) for which no parser exists yet. Their dependencies are
    NOT analyzed, so the report must say so rather than imply a clean result
    (Gap 1, Day 24: honesty about what was skipped)."""
    return [m for m in ingest.manifests if not _manifest_is_supported(m)]


def _unsupported_caveat(unsupported: list[IngestedFile]) -> str:
    """One explicit sentence naming the detected-but-skipped manifests, so a
    polyglot (Ruby/Go/Rust/PHP/Java/Elixir) repo never reads as a clean pass."""
    names = sorted({m.path.name for m in unsupported})
    shown = ", ".join(names[:6]) + (f", +{len(names) - 6} more" if len(names) > 6 else "")
    return (
        f"NOTE: {len(unsupported)} manifest(s) in ecosystems not yet supported in "
        f"v1 ({shown}) were detected but NOT analyzed. Their dependencies are not "
        f"covered by this scan, so this is not a clean bill of health for them."
    )


# --- Scanner --------------------------------------------------------------


def extract_dependencies(ingest: IngestResult) -> list[Dependency]:
    """Across all manifests, extract dependencies, preferring lockfile-resolved
    versions over manifest-declared ranges.

    A lockfile records the INSTALLED version; a manifest records a range (e.g.
    "^1.2.7") that we can only resolve to its floor. A caret/tilde range often
    resolves in the lockfile to a version ABOVE the floor that has already patched
    the advisory the floor matched. So when a lockfile resolves a package, we drop
    the manifest-declared (floor) entry for that package and OSV-match only the
    installed version. (Gap D, Day 21: sanitize-html ^2.17.3 floor matched a CVE
    the lockfile-installed 2.17.4 had already fixed.)
    """
    raw: list[Dependency] = []
    for manifest in ingest.manifests:
        raw.extend(parse_manifest(manifest))

    # Packages for which a lockfile gave us a real installed version.
    resolved_packages = {(dep.ecosystem, dep.name) for dep in raw if dep.resolved}
    # The declared kind (prod/dev/peer/optional) lives in the manifest, not the
    # lockfile. Map it so a lockfile-resolved entry can inherit it (Gap C).
    declared_kind: dict[tuple[str, str], str] = {}
    for dep in raw:
        if not dep.resolved and dep.dependency_kind != "unknown":
            declared_kind.setdefault((dep.ecosystem, dep.name), dep.dependency_kind)

    all_deps: list[Dependency] = []
    seen: set[tuple[str, str, str | None]] = set()
    for dep in raw:
        # Drop a declared-range (floor) entry when a lockfile resolved that same
        # package: the installed version is the truth, not the manifest floor.
        if not dep.resolved and (dep.ecosystem, dep.name) in resolved_packages:
            continue
        # A lockfile entry inherits its declared kind; a package in no manifest is
        # transitive (pulled in by another dependency), never a headline lead.
        if dep.dependency_kind == "unknown":
            kind = declared_kind.get((dep.ecosystem, dep.name), "transitive")
            dep = replace(dep, dependency_kind=kind)
        key = (dep.ecosystem, dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)
        all_deps.append(dep)
    return all_deps


async def _scan_async(
    deps: list[Dependency], *, finding_start: int = 1
) -> list[Finding]:
    """Query OSV in parallel and build findings."""
    # Only query deps with a resolvable version. A None version (open floor,
    # non-registry spec, unpinned) cannot be soundly matched to a CVE and was a
    # false-positive source (Day 19: cal-com, formbricks).
    queryable = [dep for dep in deps if dep.version]
    queries = [(dep.ecosystem, dep.name, dep.version) for dep in queryable]
    results: list[OSVResult] = await query_many(queries)

    findings: list[Finding] = []
    next_id = finding_start
    for dep, result in zip(queryable, results, strict=True):
        if result.error or not result.vulnerabilities:
            continue
        for vuln in result.vulnerabilities:
            label = (vuln.severity_label or "MEDIUM").upper()
            severity = SEVERITY_FROM_OSV.get(label, Severity.MEDIUM)
            summary = f"{dep.name}@{dep.version or '?'} affected by {vuln.id}"
            details = (
                f"{vuln.summary}\n\n"
                f"Affected: {dep.name} version {dep.version or '(version not pinned)'}\n"
                f"OSV ID: {vuln.id}\n"
                f"Aliases: {', '.join(vuln.aliases) if vuln.aliases else 'none'}\n"
                f"References:\n"
                + "\n".join(f"  - {r}" for r in vuln.references[:5])
            )
            rec = f"Update {dep.name} to a patched version (see references)."
            citation = Citation(
                file=dep.manifest_path,
                line_start=dep.line_start,
                line_end=dep.line_end,
                quoted_code=dep.quoted,
            )
            findings.append(
                Finding(
                    finding_id=make_finding_id(next_id),
                    artifact=ArtifactKind.SCA,
                    severity=severity,
                    summary=summary[:200],
                    details=details,
                    citation=citation,
                    recommendation=rec,
                    effort=Effort.S,
                    confidence=0.9,  # OSV is high-confidence; we don't add Claude here
                    dependency_kind=dep.dependency_kind,
                )
            )
            next_id += 1
    return findings


def _health_score(findings: list[Finding]) -> int:
    """Crude heuristic. Subtract from 100 per finding severity.

    Critical: -20, High: -10, Medium: -5, Low: -2, Info: -0.5.
    Floor at 0.
    """
    weight = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0.5,
    }
    score = 100.0 - sum(weight[f.severity] for f in findings)
    return max(0, int(round(score)))


def scan(ingest: IngestResult, *, finding_start: int = 1) -> ArtifactReport:
    """Run the full SCA scan. Synchronous wrapper around async OSV queries."""
    deps = extract_dependencies(ingest)
    unsupported = _unsupported_manifests(ingest)
    if not deps:
        if unsupported:
            # Manifests WERE found, just in ecosystems we cannot parse yet. Saying
            # "no manifests found" or letting this read as clean would be a lie by
            # omission, the exact failure the cite-everything moat forbids.
            narrative = (
                f"No supported package manifests were analyzed. {_unsupported_caveat(unsupported)} "
                f"v1 supports {SUPPORTED_ECOSYSTEMS_LABEL}."
            )
        else:
            narrative = (
                "No package manifests found. Either this repo doesn't declare "
                "dependencies in a standard manifest, or the manifests use an "
                f"ecosystem we don't yet support (v1 supports {SUPPORTED_ECOSYSTEMS_LABEL})."
            )
        return ArtifactReport(
            artifact=ArtifactKind.SCA,
            summary_narrative=narrative,
            findings=[],
            health_score=50,  # unknown is not good and not bad
        )

    findings = asyncio.run(_scan_async(deps, finding_start=finding_start))

    n_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    n_high = sum(1 for f in findings if f.severity == Severity.HIGH)
    ecosystems = sorted({d.ecosystem for d in deps})
    # Count only the manifests we actually parsed, not the unsupported ones ingest
    # also detected, so "across N manifest(s)" never overstates coverage.
    n_analyzed = sum(1 for m in ingest.manifests if _manifest_is_supported(m))

    narrative = (
        f"Scanned {len(deps)} declared dependencies across "
        f"{n_analyzed} manifest(s) in {', '.join(ecosystems)}. "
        f"Found {len(findings)} known-vulnerability advisories: "
        f"{n_critical} CRITICAL, {n_high} HIGH, "
        f"{sum(1 for f in findings if f.severity == Severity.MEDIUM)} MEDIUM, "
        f"{sum(1 for f in findings if f.severity == Severity.LOW)} LOW."
    )
    if unsupported:
        narrative += " " + _unsupported_caveat(unsupported)

    return ArtifactReport(
        artifact=ArtifactKind.SCA,
        summary_narrative=narrative,
        findings=findings,
        health_score=_health_score(findings),
    )
