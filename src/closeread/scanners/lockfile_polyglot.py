"""Polyglot lockfile parsers: Gemfile.lock (Ruby), composer.lock (PHP),
Cargo.lock (Rust).

These ecosystems were detected by ingest.PACKAGE_MANIFESTS but never parsed, so
Ruby/PHP/Rust repos silently shipped a clean SCA bill of health (Gap 1, Day 24).
Each parser mirrors the existing lockfile parsers in lockfile_npm.py: it reads the
INSTALLED/resolved version (never a declared floor), hardcodes the OSV-correct
ecosystem string inline, sets resolved=True, and cites back to the lockfile line.

OSV ecosystem keys (https://google.github.io/osv.dev/data/):
  Gemfile.lock -> "RubyGems"
  composer.lock -> "Packagist"
  Cargo.lock   -> "crates.io"

Correctness note: these feed give-first emails to real maintainers. Be
conservative. Mark a dep "transitive" when directness cannot be proven from the
lockfile alone, never wrongly claim "prod". Do not guess version strings.

No Claude API; deterministic only.
"""

from __future__ import annotations

import json
import re
import tomllib

from closeread.ingest import IngestedFile
from closeread.scanners.sca import Dependency, _find_line_for_substring

# ---------------------------------------------------------------------------
# Gemfile.lock (Ruby -> RubyGems)
#
# Shape:
#   GEM
#     remote: https://rubygems.org/
#     specs:
#       nokogiri (1.13.0)            <- installed gem (4-space indent)
#         mini_portile2 (~> 2.7.0)   <- a gem's sub-dependency (6-space, SKIP)
#       mini_portile2 (2.7.0)
#
#   PLATFORMS
#     ruby
#
#   DEPENDENCIES
#     nokogiri (~> 1.13)             <- a DIRECT dep (2-space indent)
#     rails!                         <- a `!` suffix marks a pinned git/path gem
#
# The `specs:` lines under GEM (and GIT/PATH) give the installed version. The
# DEPENDENCIES section names the top-level (direct) gems; everything in specs
# but NOT in DEPENDENCIES is transitive.
# ---------------------------------------------------------------------------

# A spec line: exactly 4 leading spaces, "name (version)". 6-space lines are a
# gem's own sub-dependencies (a constraint, not an install) and are skipped by
# the strict 4-space anchor. The version must start with a digit so a constraint
# like "(>= 1.0)" can never be read as an installed version.
_GEM_SPEC_RE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \((\d[^()]*?)\)\s*$")


def _strip_gem_platform(version: str) -> str:
    """A platform-specific gem pins its version as "1.13.0-x86_64-linux" or
    "1.4.2-java". OSV/RubyGems indexes the BARE version (1.13.0); querying the
    platform-suffixed string would miss the advisory (the floor-vs-install moat).
    Ruby gem versions use DOTS for prereleases (1.0.0.beta1), so the platform is
    always the suffix after the FIRST dash, and stripping it is unambiguous."""
    return version.split("-", 1)[0]
# A DEPENDENCIES entry: exactly 2 leading spaces, the gem name, an optional
# version constraint in parens, and an optional `!` (git/path) suffix. We only
# need the NAME here (the install version comes from the specs section).
_GEM_DEP_RE = re.compile(r"^ {2}([A-Za-z0-9_.\-]+)!?(?: \([^)]*\))?\s*$")


def parse_gemfile_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse Gemfile.lock. Returns resolved RubyGems deps.

    Installed versions come from the GEM/GIT/PATH `specs:` blocks; gems also named
    in the DEPENDENCIES section are marked prod (direct), the rest transitive.
    """
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines(keepends=False)

    # Pass 1: collect the names listed under DEPENDENCIES (the direct gems).
    direct: set[str] = set()
    in_deps = False
    for raw in lines:
        if not raw.startswith(" "):  # a top-level section header (or blank-ish)
            in_deps = raw.strip() == "DEPENDENCIES"
            continue
        if in_deps:
            m = _GEM_DEP_RE.match(raw)
            if m:
                direct.add(m.group(1))

    # Pass 2: read the installed gems from every `specs:` block. A spec line is
    # 4-space-indented "name (version)". We accept spec lines regardless of which
    # section we're in (GEM/GIT/PATH all use the same 4-space spec shape); the
    # 4-space anchor plus digit-leading version is specific enough to avoid the
    # 6-space sub-dependency lines and the 2-space DEPENDENCIES lines.
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for i, raw in enumerate(lines, start=1):
        m = _GEM_SPEC_RE.match(raw)
        if not m:
            continue
        name = m.group(1)
        version = _strip_gem_platform(m.group(2).strip())
        if (name, version) in seen:
            continue
        seen.add((name, version))
        kind = "prod" if name in direct else "transitive"
        out.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="RubyGems",
                manifest_path=manifest.relative_path,
                line_start=i,
                line_end=i,
                quoted=raw,
                resolved=True,
                dependency_kind=kind,
            )
        )
    return out


# ---------------------------------------------------------------------------
# composer.lock (PHP -> Packagist)
#
# JSON. "packages" (production) and "packages-dev" (dev) are arrays of objects
# each with "name" (vendor/package) and "version" (e.g. "4.4.0" or "v4.4.0").
# ---------------------------------------------------------------------------


def _strip_composer_version(ver: object) -> str | None:
    """Normalize a composer version. Composer commonly prefixes a leading 'v'
    (e.g. "v4.4.0"); OSV/Packagist versions are bare. Reject dev/branch refs
    ("dev-main", "9999999-dev") which are not OSV-matchable release versions."""
    if not isinstance(ver, str):
        return None
    v = ver.strip()
    if not v:
        return None
    low = v.lower()
    if low.startswith("dev-") or "-dev" in low or low.endswith("-dev"):
        return None
    if v[0] in ("v", "V") and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    # An installed composer version starts with a digit (a real release).
    return v if v[0].isdigit() else None


def parse_composer_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse composer.lock (JSON). Resolved Packagist deps from packages (prod)
    and packages-dev (dev)."""
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for section, kind in (("packages", "prod"), ("packages-dev", "dev")):
        pkgs = data.get(section)
        if not isinstance(pkgs, list):
            continue
        for pkg in pkgs:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = _strip_composer_version(pkg.get("version"))
            if not name or not isinstance(name, str) or not version:
                continue
            if (name, version) in seen:
                continue
            seen.add((name, version))
            found = _find_line_for_substring(lines, f'"{name}"')
            line_no, line_text = found if found else (1, f"{name} {version}")
            out.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="Packagist",
                    manifest_path=manifest.relative_path,
                    line_start=line_no,
                    line_end=line_no,
                    quoted=line_text,
                    resolved=True,
                    dependency_kind=kind,
                )
            )
    return out


# ---------------------------------------------------------------------------
# Cargo.lock (Rust -> crates.io)
#
# TOML. A list of [[package]] tables each with name + version. Direct-vs-transitive
# is NOT in Cargo.lock alone, so we read the sibling Cargo.toml (if present) to
# mark direct deps; absent that, every dep is conservatively "transitive".
# ---------------------------------------------------------------------------


def _cargo_direct_names(manifest: IngestedFile) -> set[str]:
    """Read direct crate names from the sibling Cargo.toml, if present.

    Cargo.toml [dependencies], [dev-dependencies], [build-dependencies] and the
    target-specific [target.*.dependencies] tables name the DIRECT deps. We only
    use this to mark directness; we never read a version from Cargo.toml (it
    declares a range/floor, and the moat is to use the installed version from the
    lockfile). Returns an empty set if Cargo.toml is missing or unreadable, in
    which case every dep stays conservatively transitive.
    """
    cargo_toml = manifest.path.parent / "Cargo.toml"
    if not cargo_toml.is_file():
        return set()
    try:
        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError, ValueError):
        return set()
    names: set[str] = set()

    def _collect(table: object) -> None:
        if isinstance(table, dict):
            names.update(k for k in table if isinstance(k, str))

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        _collect(data.get(section))
    # target.<cfg>.dependencies (and dev-/build-) live nested under [target].
    target = data.get("target")
    if isinstance(target, dict):
        for cfg in target.values():
            if isinstance(cfg, dict):
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    _collect(cfg.get(section))
    # A workspace root may declare shared deps under [workspace.dependencies].
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        _collect(workspace.get("dependencies"))
    return names


def parse_cargo_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse Cargo.lock (TOML). Resolved crates.io deps from [[package]] tables.

    If a sibling Cargo.toml is present, crates it lists as dependencies are marked
    prod (direct); all others are transitive. Without a Cargo.toml every crate is
    conservatively transitive (directness is not in Cargo.lock alone)."""
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, OSError, ValueError):
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    direct = _cargo_direct_names(manifest)
    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if (
            not name
            or not isinstance(name, str)
            or not version
            or not isinstance(version, str)
        ):
            continue
        version = version.strip()
        if not version or (name, version) in seen:
            continue
        seen.add((name, version))
        found = _find_line_for_substring(
            lines, f'name = "{name}"'
        ) or _find_line_for_substring(lines, str(name))
        line_no, line_text = found if found else (1, f"{name} {version}")
        kind = "prod" if name in direct else "transitive"
        out.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="crates.io",
                manifest_path=manifest.relative_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                resolved=True,
                dependency_kind=kind,
            )
        )
    return out
