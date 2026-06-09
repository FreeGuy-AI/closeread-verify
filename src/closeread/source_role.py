"""Source-role classification for findings.

One question, asked of every cited path: is this finding in the PRODUCT tree
(the code a buyer actually acquires) or in EXAMPLE / TEST / DOCS code (real, but
lower-priority noise that must not inflate the buyer's headline numbers)?

No Claude. Deterministic. Pure path heuristics. The output feeds the headline
split in schema.AuditPacket and the "read first" list in the renderer.

Surfaced by the first two real give-first audits (Day 16):
  - lost-pixel: 499 of 564 SCA findings were in examples/ demo-app lockfiles.
  - pmxt: docs/api-reference/*.mdx placeholder keys counted as headline secrets.

Both share one root cause: every finding was weighted equally regardless of
whether its file is part of the shippable product. This module is the fix.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath


class SourceRole(StrEnum):
    """Where in the tree a finding lives, for headline-priority purposes."""

    PRODUCT = "product"  # the shippable product tree (default)
    VENDORED = "vendored"  # node_modules/, vendor/, patches/, *.patch, *.min.js
    EXAMPLE = "example"  # examples/, demo/, sample/, sandbox/, playground/
    TEST = "test"  # tests/, __tests__/, *.test.*, *_test.go, fixtures/
    DOCS = "docs"  # docs/, *.md, *.mdx, *.rst, *.adoc


# Directory segments (matched exactly against any path part, case-insensitive)
# that mark a non-product tree.
# NOTE: "spec"/"specs" are deliberately NOT here. In Ruby they mean tests, but
# in API projects `spec/openapi.yaml` is a product API surface. For a DD tool,
# wrongly demoting a real finding out of the buyer's headline (false negative) is
# worse than a little test noise, so we bias against demotion: test-ness from a
# `spec` context is detected by the FILENAME pattern (`*.spec.*`, `*_spec.rb`)
# below, not by a bare directory segment. (Codex review, Day 17.)
_TEST_SEGMENTS = {
    "test",
    "tests",
    "__tests__",
    "e2e",
    "__mocks__",
    "fixtures",
    "fixture",
    "__fixtures__",
    "testdata",
}
_EXAMPLE_SEGMENTS = {
    "example",
    "examples",
    "demo",
    "demos",
    "sample",
    "samples",
    "sandbox",
    "playground",
}
_DOCS_SEGMENTS = {"docs", "doc", "documentation"}

# Extensions that are documentation, not product source. NOTE: .txt is NOT here
# -- `requirements.txt` is a Python product manifest, and classifying it as DOCS
# dropped its real CVE findings out of the buyer's headline (Codex review, Day 17).
_DOCS_EXTENSIONS = {".md", ".mdx", ".markdown", ".rst", ".adoc"}

# Third-party code that ships in the repo but the team did not author. A finding
# here is dependency/vendored noise, not the product the buyer's team built, so
# it must not inflate the headline. Surfaced Day 19 (give-first batch QA):
#   - documenso: a PEM string literal inside patches/@ai-sdk+...patch
#   - vendored tarballs and minified dist bundles produced phantom secrets/CVEs.
_VENDORED_SEGMENTS = {
    "node_modules",
    "vendor",
    "vendored",
    "third_party",
    "third-party",
    "thirdparty",
    "bower_components",
    "patches",
    ".yarn",
}


def _is_minified_or_generated(name: str) -> bool:
    """Minified or generated bundles are vendored/generated, not authored source."""
    n = name.lower()
    return n.endswith((".min.js", ".min.css", ".bundle.js")) or ".min." in n


def _is_test_filename(name: str) -> bool:
    """Filename patterns that mark a test file regardless of directory."""
    n = name.lower()
    return (
        n.startswith("test_")
        or n.endswith("_test.go")
        or n.endswith("_test.py")
        or ".test." in n
        or ".spec." in n
        or "_spec." in n  # Ruby/RSpec: user_spec.rb (we dropped bare `spec/` dir)
        or n == "conftest.py"
    )


_SEGMENT_SPLIT_RE = re.compile(r"[._\-]")


def _has_example_subtoken(dir_segs: set[str]) -> bool:
    """True if a directory segment contains an EXAMPLE word as a sub-token.

    Catches sample-config directories like ``sample_conf`` / ``example-config`` /
    ``conf.sample`` that exact-segment matching misses (cronicle ships a demo
    self-signed cert PAIR in ``sample_conf/``). A word that merely starts with the
    letters (``sampler``, ``resample``) does NOT match: we split on ``. _ -`` and
    compare whole sub-tokens, so only a real ``sample``/``example``/``demo`` word
    triggers it.
    """
    return any(
        tok in _EXAMPLE_SEGMENTS
        for seg in dir_segs
        for tok in _SEGMENT_SPLIT_RE.split(seg)
    )


def classify_source_role(relative_path: str) -> SourceRole:
    """Classify a repo-relative path into a SourceRole.

    Precedence: VENDORED > TEST > EXAMPLE > DOCS > PRODUCT. Any non-product signal beats
    PRODUCT; the ordering only disambiguates among non-product roles so the
    result is deterministic for paths that match more than one.

    Note: a ROOT lockfile (e.g. ``package-lock.json`` with no example/test
    parent dir) classifies as PRODUCT -- it is the real dependency tree a buyer
    inherits. Only lockfiles UNDER examples/ or tests/ are demoted.
    """
    p = PurePosixPath(str(relative_path).replace("\\", "/"))
    dir_segs = {seg.lower() for seg in p.parts[:-1]}
    name = p.name

    if (
        dir_segs & _VENDORED_SEGMENTS
        or p.suffix.lower() == ".patch"
        or _is_minified_or_generated(name)
    ):
        return SourceRole.VENDORED
    if dir_segs & _TEST_SEGMENTS or _is_test_filename(name):
        return SourceRole.TEST
    if dir_segs & _EXAMPLE_SEGMENTS or _has_example_subtoken(dir_segs):
        return SourceRole.EXAMPLE
    if dir_segs & _DOCS_SEGMENTS or p.suffix.lower() in _DOCS_EXTENSIONS:
        return SourceRole.DOCS
    return SourceRole.PRODUCT
