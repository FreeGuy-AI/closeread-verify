"""npm lockfile parser: package-lock.json (v1, v2, v3).

Parses all lockfile formats and returns a flat, deduplicated list of
`Dependency` objects for SCA consumption. No Claude API; deterministic only.
"""

from __future__ import annotations

import json
import re

import yaml

from closeread.ingest import IngestedFile
from closeread.scanners.sca import Dependency, _find_line_for_substring


def _extract_name_from_package_key(key: str) -> str:
    """Extract the package name from a v2/v3 'packages' key.

    Keys look like:
      "node_modules/foo"
      "node_modules/@scope/bar"
      "node_modules/foo/node_modules/baz"

    Returns the last segment after the final "node_modules/" delimiter.
    """
    marker = "node_modules/"
    idx = key.rfind(marker)
    if idx == -1:
        return key
    return key[idx + len(marker):]


def _parse_v1_dependencies(
    deps_obj: dict,
    lines: list[str],
    manifest_path: str,
    seen: set[tuple[str, str | None]],
    out: list[Dependency],
) -> None:
    """Recursively walk the v1 'dependencies' tree."""
    for name, info in deps_obj.items():
        if not isinstance(info, dict):
            continue
        version: str | None = info.get("version") or None
        key = (name, version)
        if key not in seen:
            seen.add(key)
            found = _find_line_for_substring(lines, f'"{name}"')
            if found is None:
                line_no, line_text = 1, f'"{name}": "{version}"'
            else:
                line_no, line_text = found
            out.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    manifest_path=manifest_path,
                    line_start=line_no,
                    line_end=line_no,
                    quoted=line_text,
                    resolved=True,
                )
            )
        # Nested (hoisted) deps live under info["dependencies"]
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _parse_v1_dependencies(nested, lines, manifest_path, seen, out)


def _parse_v2v3_packages(
    packages_obj: dict,
    lines: list[str],
    manifest_path: str,
    seen: set[tuple[str, str | None]],
    out: list[Dependency],
) -> None:
    """Walk the flat v2/v3 'packages' object."""
    for pkg_key, info in packages_obj.items():
        # Skip the root entry ("") and any entry without a version (workspace links)
        if not pkg_key:
            continue
        if not isinstance(info, dict):
            continue
        if "workspaces" in info and "version" not in info:
            continue
        version: str | None = info.get("version") or None
        if version is None:
            continue

        name = _extract_name_from_package_key(pkg_key)
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)

        # Prefer a line containing the exact package key path for precision,
        # fall back to just the name.
        found = _find_line_for_substring(lines, f'"{pkg_key}"')
        if found is None:
            found = _find_line_for_substring(lines, f'"{name}"')
        if found is None:
            line_no, line_text = 1, f"{name}@{version}"
        else:
            line_no, line_text = found

        out.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                manifest_path=manifest_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                resolved=True,
            )
        )


def parse_package_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse package-lock.json (v1, v2, v3). Returns flat list of all
    dependencies (direct + transitive), deduplicated by (name, version).

    Lockfile version detection:
      - v1: data.get('lockfileVersion') == 1 (or absent). Walk 'dependencies' recursively.
      - v2: data['lockfileVersion'] == 2. Walk 'packages' object (flat). Also has
        'dependencies' for backwards compat -- we prefer 'packages' when present.
      - v3: data['lockfileVersion'] == 3. Walk 'packages' only (no 'dependencies').

    For v2/v3 'packages':
      - Keys are paths like "" (root), "node_modules/foo", "node_modules/foo/node_modules/bar"
      - Skip the root entry (key == "")
      - Extract package name from the last segment after "node_modules/"
      - Skip workspace entries (they don't have a 'version' field but have 'workspaces')

    For each dep, emit one Dependency with:
      - ecosystem="npm"
      - manifest_path=manifest.relative_path
      - line_start, line_end: best-effort via _find_line_for_substring
      - quoted: the line text found, or a synthesized "{name}@{version}" if not found
    """
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, dict):
        return []

    lines = text.splitlines(keepends=False)
    lockfile_version: int = data.get("lockfileVersion", 1)

    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()

    packages_obj = data.get("packages")
    dependencies_obj = data.get("dependencies")

    if lockfile_version >= 2 and isinstance(packages_obj, dict):
        # v2 and v3: authoritative source is 'packages'
        _parse_v2v3_packages(packages_obj, lines, manifest.relative_path, seen, out)
    elif isinstance(dependencies_obj, dict):
        # v1 (or v2 fallback if 'packages' is absent)
        _parse_v1_dependencies(dependencies_obj, lines, manifest.relative_path, seen, out)

    return out


# ---------------------------------------------------------------------------
# pnpm-lock.yaml and yarn.lock (Gap D, Day 21). Same npm ecosystem, different
# package managers. These lockfiles were never parsed, so the give-first machine
# fell back to package.json caret floors and shipped false positives. Their
# resolved versions are the real install, so every Dependency here is resolved=True.
# ---------------------------------------------------------------------------


def _parse_pnpm_package_key(key: str) -> tuple[str | None, str | None]:
    """Parse a pnpm-lock `packages:` key into (name, version).

    Handles:
      "better-auth@1.2.9"                -> (better-auth, 1.2.9)
      "@scope/name@1.2.3"                -> (@scope/name, 1.2.3)
      "foo@1.0.0(react@18.0.0)"          -> (foo, 1.0.0)   (peer suffix stripped)
      "/foo@1.0.0"                       -> (foo, 1.0.0)   (pnpm v6 slash)
      "/foo/1.0.0"                       -> (foo, 1.0.0)   (pnpm v5 slash)
    Returns (None, None) if it cannot be parsed.
    """
    k = str(key).split("(", 1)[0].strip().strip("'\"")
    if k.startswith("/"):
        k = k[1:]
    # Modern format: version follows the LAST '@' (a scope '@' is leading).
    if "@" in k.lstrip("@"):
        name, _, version = k.rpartition("@")
        name, version = name.strip(), version.strip()
        if name and version and version[0].isdigit():
            return name, version
    # pnpm v5 slash format: "name/1.0.0" or "@scope/name/1.0.0"
    if "/" in k:
        name, _, version = k.rpartition("/")
        if name and version and version[0].isdigit():
            return name.strip(), version.strip()
    return None, None


def parse_pnpm_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse pnpm-lock.yaml. Returns resolved deps from the `packages:` section."""
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(text)
    except (yaml.YAMLError, OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    for key in packages:
        name, version = _parse_pnpm_package_key(str(key))
        if not name or not version or (name, version) in seen:
            continue
        seen.add((name, version))
        found = _find_line_for_substring(lines, str(key)) or _find_line_for_substring(
            lines, name
        )
        line_no, line_text = found if found else (1, f"{name}@{version}")
        out.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                manifest_path=manifest.relative_path,
                line_start=line_no,
                line_end=line_no,
                quoted=line_text,
                resolved=True,
            )
        )
    return out


_YARN_VERSION_RE = re.compile(r'version\s+"?([0-9][^"\s]*)"?')


def _yarn_name_from_spec(spec: str) -> str | None:
    """Extract the package name from a yarn.lock spec like 'better-auth@^1.2.7'
    or '@scope/name@^1.0.0' (the name is everything before the LAST '@')."""
    s = spec.strip().strip('"')
    if "@" in s.lstrip("@"):
        return (s.rpartition("@")[0]).strip() or None
    return s or None


def parse_yarn_lock(manifest: IngestedFile) -> list[Dependency]:
    """Parse a yarn v1 lockfile. Entry shape:

        "better-auth@^1.2.7", "better-auth@^1.2.0":
          version "1.2.9"

    Yarn berry (v2+) uses a YAML format with __metadata; not handled here.
    """
    try:
        text = manifest.path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if "__metadata:" in text:  # yarn berry (YAML) -- different format, skip
        return []
    lines = text.splitlines(keepends=False)
    out: list[Dependency] = []
    seen: set[tuple[str, str | None]] = set()
    current_names: list[str] = []
    header_line, header_text = 1, ""
    for i, raw in enumerate(lines):
        if not raw or raw.startswith("#"):
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            current_names = [
                nm
                for spec in raw.rstrip()[:-1].split(",")
                if (nm := _yarn_name_from_spec(spec))
            ]
            header_line, header_text = i + 1, raw.rstrip()
            continue
        if current_names and raw.strip().startswith("version"):
            m = _YARN_VERSION_RE.search(raw)
            if not m:
                continue
            version = m.group(1)
            for nm in current_names:
                if (nm, version) in seen:
                    continue
                seen.add((nm, version))
                out.append(
                    Dependency(
                        name=nm,
                        version=version,
                        ecosystem="npm",
                        manifest_path=manifest.relative_path,
                        line_start=header_line,
                        line_end=header_line,
                        quoted=header_text,
                        resolved=True,
                    )
                )
            current_names = []
    return out
