"""Repo ingest: walk the file tree, classify languages, find package manifests.

No Claude API here. Deterministic. The output feeds every downstream scanner.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from closeread.schema import RepoMetadata

# Directories we never want to scan.
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "out",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "coverage",
    ".coverage",
    ".idea",
    ".vscode",
    ".cache",
    "tmp",
    "temp",
}

# Extension -> language name. Lowercase keys.
LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rb": "Ruby",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".cc": "C++",
    ".c": "C",
    ".h": "C/C++ header",
    ".hpp": "C++ header",
    ".scala": "Scala",
    ".clj": "Clojure",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".md": "Markdown",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
}

# Filenames that signal a package manifest. (filename, ecosystem).
PACKAGE_MANIFESTS: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "pyproject.toml": "pip",  # could also be poetry
    "poetry.lock": "poetry",
    "Gemfile": "rubygems",
    "Gemfile.lock": "rubygems",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "composer.json": "composer",
    "composer.lock": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "mix.exs": "mix",
}

# The standard split-requirements layout uses more than the literal
# "requirements.txt": requirements-dev.txt, requirements/base.txt (a requirements/
# directory), requirements*.txt, and requirements.in (pip-tools). Matching only the
# exact name silently dropped every dep in those files. Detect the variants by
# pattern and treat them all as the pip ecosystem (Gap 3, Day 24).
_REQUIREMENTS_RE = re.compile(r"^requirements.*\.(?:txt|in)$", re.IGNORECASE)


def manifest_ecosystem(path: Path) -> str | None:
    """Ecosystem for a manifest path, or None if it is not a manifest.

    Checks the exact-name table first, then the requirements-variant pattern
    (incl. any file directly under a requirements/ directory)."""
    eco = PACKAGE_MANIFESTS.get(path.name)
    if eco is not None:
        return eco
    if _REQUIREMENTS_RE.match(path.name):
        return "pip"
    if path.parent.name == "requirements" and path.suffix.lower() in (".txt", ".in"):
        return "pip"
    return None


@dataclass(frozen=True)
class IngestedFile:
    path: Path  # absolute path on disk
    relative_path: str  # relative to repo root, posix-style
    language: str | None
    line_count: int
    is_manifest: bool
    ecosystem: str | None  # only set if is_manifest


@dataclass
class IngestResult:
    repo_root: Path
    files: list[IngestedFile]
    metadata: RepoMetadata
    manifests: list[IngestedFile]


def clone_repo(url: str, dest: Path) -> Path:
    """Shallow clone a git repo to dest. Returns the path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise FileExistsError(f"{dest} already exists; refusing to overwrite")
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def get_commit_sha(repo_root: Path) -> str | None:
    """Best-effort: return the HEAD SHA, or None."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _count_lines(path: Path) -> int:
    """Cheap line count. Returns 0 on read errors (binary, encoding, etc.)."""
    try:
        with path.open("rb") as f:
            return sum(1 for _ in f)
    except (OSError, ValueError):
        return 0


def _walk_files(repo_root: Path) -> Iterable[Path]:
    """Yield every file path, skipping EXCLUDED_DIRS."""
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        # skip if any parent dir is excluded
        rel_parts = p.relative_to(repo_root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts[:-1]):
            continue
        yield p


def ingest(repo_root: Path | str, name: str | None = None) -> IngestResult:
    """Walk a local repo and produce IngestResult."""
    repo_root = Path(repo_root).resolve()
    if not repo_root.is_dir():
        raise FileNotFoundError(f"Not a directory: {repo_root}")

    files: list[IngestedFile] = []
    manifests: list[IngestedFile] = []
    languages: dict[str, int] = {}

    for path in _walk_files(repo_root):
        ext = path.suffix.lower()
        language = LANGUAGE_EXTENSIONS.get(ext)
        line_count = _count_lines(path) if language else 0
        ecosystem = manifest_ecosystem(path)
        is_manifest = ecosystem is not None
        relative = path.relative_to(repo_root).as_posix()

        f = IngestedFile(
            path=path,
            relative_path=relative,
            language=language,
            line_count=line_count,
            is_manifest=is_manifest,
            ecosystem=ecosystem,
        )
        files.append(f)
        if is_manifest:
            manifests.append(f)
        if language and line_count > 0:
            languages[language] = languages.get(language, 0) + line_count

    # "Primary language" should mean the dominant source code, not config or markup.
    # Filter out data / config / markup formats for the primary-language pick.
    NON_SOURCE_LANGUAGES = {
        "JSON",
        "YAML",
        "TOML",
        "Markdown",
        "HTML",
        "CSS",
        "SCSS",
        "SQL",
    }
    source_only = {
        lang: count for lang, count in languages.items() if lang not in NON_SOURCE_LANGUAGES
    }
    if source_only:
        primary_language = max(source_only.items(), key=lambda kv: kv[1])[0]
    elif languages:
        primary_language = max(languages.items(), key=lambda kv: kv[1])[0]
    else:
        primary_language = "Unknown"

    metadata = RepoMetadata(
        name=name or repo_root.name,
        source=str(repo_root),
        commit_sha=get_commit_sha(repo_root),
        total_files=len(files),
        total_lines=sum(languages.values()),
        primary_language=primary_language,
        languages=languages,
    )

    return IngestResult(
        repo_root=repo_root,
        files=files,
        metadata=metadata,
        manifests=manifests,
    )
