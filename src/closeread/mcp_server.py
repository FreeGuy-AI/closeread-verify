"""closeread-verify -- an MCP server that gives any AI agent a VERIFIED finding.

The strategic point (Day 25): a free scanner (npm audit, OSV-Scanner) and the
agent itself can already produce a raw scan. What they cannot manufacture is
closeread's *verified verdict*: each version checked against the INSTALLED
lockfile version (not the declared floor), the direct-vs-transitive split, the
one finding that actually matters, and the exact fix. That verified artifact is
the product. This server is the cheapest possible test of whether agents pull.

It exposes the existing deterministic SCA path (ingest -> sca.scan ->
credential_inventory.scan -> AuditPacket -> verify_packet) over MCP stdio. No
LLM/anthropic call, no tree-sitter full audit: SCA-only, fast, re-checkable.

Tools:
  - audit_project(files)                             [PRIMARY]
  - audit_dependencies(lockfile_content, filename)   [convenience: one file]
  - audit_repo(github_url)                            [SECONDARY]

``audit_project`` takes a {filename: content} map so an agent working locally can
pass the manifest AND its lockfile together (e.g. package.json + package-lock.json).
That pairing is what restores npm's direct-vs-transitive split: a bare
package-lock.json has no way to mark top-level deps, so every entry collapses to
transitive and the give-first lead is lost. With the sibling package.json present,
the declared production dep is recovered as DIRECT (the founder's to bump).
``audit_dependencies`` is the single-file convenience wrapper that delegates here.

Run it:
    closeread-verify                       # console entry point (stdio)
    python -m closeread.mcp_server          # module form
    .venv/bin/python -m closeread.mcp_server

Library/core functions accept an optional ``as_of`` timestamp so they never call
``datetime.now`` themselves (the suite forbids non-deterministic library code);
the MCP tool layer stamps the real UTC time before delegating.
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from closeread.ingest import clone_repo, ingest
from closeread.scanners import credential_inventory, sca
from closeread.schema import AuditPacket
from closeread.verifier import verify_packet

# The one sentence that IS the product: what "verified" means, in plain English.
VERIFICATION_BASIS = (
    "each version is the INSTALLED version resolved from the lockfile, not the "
    "declared floor; advisories confirmed via OSV; result is deterministic and "
    "re-checkable"
)


def _build_packet(repo_path: Path, name: str, *, as_of: datetime) -> AuditPacket:
    """Deterministic, scanner-only audit of a local directory ($0, no LLM).

    Replicates the documented assembly used by the CLI ``audit`` command and the
    give-first machine's ``run_scanners``: ingest the tree, run the SCA scan and
    the credential inventory, assemble an :class:`AuditPacket`, then run the
    citation gate so no finding ships whose quote does not match the real file.
    """
    ingest_result = ingest(repo_path, name=name)
    sca_artifact = sca.scan(ingest_result)
    cred_artifact = credential_inventory.scan(
        ingest_result, finding_start=len(sca_artifact.findings) + 1
    )
    packet = AuditPacket(
        packet_id=str(uuid.uuid4())[:8],
        repo=ingest_result.metadata,
        started_at=as_of,
        completed_at=as_of,
        artifacts=[sca_artifact, cred_artifact],
        overall_health_score=min(
            sca_artifact.health_score, cred_artifact.health_score
        ),
    )
    # Citation gate: drop any finding whose quote does not match the real file.
    verified, _rejections = verify_packet(packet, ingest_result.repo_root)
    return verified


def _lead_dict(packet: AuditPacket) -> dict | None:
    """The single DIRECT finding to lead with, flattened to a clean dict.

    Returns None when the product tree has only transitive/dev findings -- there
    is then nothing honest to headline, and the give-first DROPS (Day 24). The
    full grouped view still reports those transitive findings.
    """
    lead = packet.give_first_lead()
    if lead is None:
        return None
    return {
        "summary": lead.summary,
        "severity": lead.severity.value,
        "is_direct": True,  # give_first_lead only ever returns a direct finding
        "dependency_kind": lead.dependency_kind,
        "location": lead.citation.location_str() if lead.citation else None,
        "fix": lead.recommendation,
        "confidence": lead.confidence,
    }


def _packet_to_result(
    packet: AuditPacket, *, source: str, as_of: datetime
) -> dict:
    """Shape the verified packet into the structured dict both tools return.

    The grouped view (``grouped_product_findings``) is already judgment-ordered
    and deduped: one row per package, direct (yours to bump) split from
    transitive (inherited). We surface that split explicitly plus the single
    lead finding and the verification basis -- the part a raw scan cannot fake.
    """
    groups = packet.grouped_product_findings()
    direct = [g for g in groups if g["kind"] == "dependency" and g["is_direct"]]
    transitive = [
        g for g in groups if g["kind"] == "dependency" and not g["is_direct"]
    ]
    issues = [g for g in groups if g["kind"] == "issue"]

    return {
        "source": source,
        "repo": {
            "name": packet.repo.name,
            "total_files": packet.repo.total_files,
            "total_lines": packet.repo.total_lines,
            "primary_language": packet.repo.primary_language,
        },
        "lead": _lead_dict(packet),
        "findings": {
            # Non-dependency headline issues (e.g. an exposed credential).
            "issues": issues,
            # Direct production deps: the founder's to bump.
            "direct": direct,
            # Inherited from the dependency tree: real, but not the founder's
            # to fix directly.
            "transitive": transitive,
        },
        "counts": {
            "product_critical": len(packet.product_critical_findings()),
            "issues": len(issues),
            "direct": len(direct),
            "transitive": len(transitive),
            "total_findings": packet.total_findings(),
        },
        "verification": {
            "basis": VERIFICATION_BASIS,
            "scanner": "closeread SCA (deterministic, no LLM)",
            "advisory_source": "OSV.dev",
            "as_of": as_of.isoformat(),
        },
    }


def _safe_relpath(filename: str) -> str | None:
    """Normalise a caller-supplied filename to a tree-relative posix path.

    Accepts a subdir prefix (``server/package.json``) so a monorepo layout is
    expressible, but refuses anything that would escape the temp dir: absolute
    paths, ``..`` traversal, or an empty/normalised-away name. Returns None when
    the filename is not safe to write.
    """
    if not filename:
        return None
    rel = PurePosixPath(filename.replace("\\", "/"))
    if rel.is_absolute() or any(part == ".." for part in rel.parts):
        return None
    cleaned = rel.as_posix().strip("/")
    if not cleaned or cleaned == ".":
        return None
    return cleaned


def audit_project(
    files: dict[str, str],
    *,
    as_of: datetime | None = None,
) -> dict:
    """Audit one OR MORE manifest/lockfiles together and return a verified result.

    This is the tool an agent working in a real checkout should reach for: it can
    pass both the manifest and the lockfile (the common local case), e.g.
    ``{"package.json": ..., "package-lock.json": ...}``. Writing both into one
    tree is what lets closeread recover npm's direct-vs-transitive split -- a bare
    package-lock.json cannot mark top-level deps, so a declared production dep
    would otherwise collapse to transitive and the give-first lead would be lost.
    A single-file map (e.g. ``{"requirements.txt": ...}``) works too.

    Args:
        files: a mapping of {filename: content}. Each filename is its name
            (``package.json``, ``package-lock.json``, ``yarn.lock``,
            ``pnpm-lock.yaml``, ``requirements.txt``, ``poetry.lock``,
            ``Pipfile.lock``, ``Gemfile.lock``, ``composer.lock``,
            ``Cargo.lock``, ...) so each parser picks the right ecosystem. A
            subdir prefix is allowed (``server/package.json``) and is created
            under the temp tree; absolute paths and ``..`` traversal are rejected.
        as_of: UTC timestamp to stamp into the verification block. The MCP tool
            layer passes the real time.

    Returns:
        The same structured dict every tool here returns: the lead finding, the
        grouped findings split into issues / direct / transitive, counts, and the
        verification basis. Identical shape to ``audit_dependencies``.

    Deterministic and SCA-only -- no LLM call, no full tree-sitter audit.
    """
    if as_of is None:
        as_of = datetime.now(UTC)
    if not files:
        return {
            "error": "files is required: pass at least one {filename: content}",
            "source": "audit_project",
        }
    safe_files: dict[str, str] = {}
    for filename, content in files.items():
        rel = _safe_relpath(filename)
        if rel is None:
            return {
                "error": f"unsafe filename rejected: {filename!r}",
                "source": "audit_project",
            }
        safe_files[rel] = content

    with tempfile.TemporaryDirectory(prefix="closeread-verify-") as tmp:
        root = Path(tmp)
        for rel, content in safe_files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        # Name the audit after the project root, not any one file -- there may be
        # several. The basenames provided are echoed in the source field.
        packet = _build_packet(root, name="project", as_of=as_of)
        provided = ", ".join(sorted(safe_files))
        return _packet_to_result(
            packet, source=f"project:{provided}", as_of=as_of
        )


def audit_dependencies(
    lockfile_content: str,
    filename: str,
    *,
    as_of: datetime | None = None,
) -> dict:
    """Audit one manifest/lockfile and return a verified, judgment-applied result.

    Convenience wrapper over :func:`audit_project` for the single-file case. When
    you have both a manifest and its lockfile, prefer ``audit_project`` so the
    direct-vs-transitive split survives (a bare lockfile cannot express it).

    Args:
        lockfile_content: the raw text of the manifest or lockfile.
        filename: its name (e.g. ``package-lock.json``, ``yarn.lock``,
            ``pnpm-lock.yaml``, ``requirements.txt``, ``poetry.lock``,
            ``Pipfile.lock``, ``Gemfile.lock``, ``composer.lock``,
            ``Cargo.lock``) so the parser picks the right ecosystem.
        as_of: UTC timestamp to stamp into the verification block. The MCP tool
            layer passes the real time; defaults to epoch-free omission only in
            direct unit calls (callers that care should pass it).

    Returns:
        A structured dict: the lead finding, the grouped findings split into
        issues / direct / transitive, counts, and the verification basis.

    Deterministic and SCA-only -- no LLM call, no full tree-sitter audit.
    """
    if as_of is None:
        as_of = datetime.now(UTC)
    safe_name = Path(filename).name  # never let a path escape the temp dir
    if not safe_name:
        return {
            "error": "filename is required so the parser can pick the ecosystem",
            "source": "audit_dependencies",
        }
    result = audit_project({safe_name: lockfile_content}, as_of=as_of)
    # Preserve the single-file source label the prior tool contract used.
    if "error" not in result:
        result["source"] = f"lockfile:{safe_name}"
    return result


def audit_repo(
    github_url: str,
    *,
    as_of: datetime | None = None,
) -> dict:
    """Shallow-clone a public repo, run the same verified audit, same shape.

    The clone gate is the verification firewall: if the repo 404s, is private,
    or yields an empty tree, we return an error rather than a fabricated result
    (a result you did not see returned is not a result).
    """
    if as_of is None:
        as_of = datetime.now(UTC)
    name = github_url.rstrip("/").split("/")[-1].removesuffix(".git") or "repo"
    with tempfile.TemporaryDirectory(prefix="closeread-verify-repo-") as tmp:
        dest = Path(tmp) / name
        try:
            clone_repo(github_url, dest)
        except Exception as exc:  # any clone failure = no result, never a fake one
            return {
                "error": f"clone_failed: {type(exc).__name__}",
                "repo": github_url,
                "source": "audit_repo",
            }
        if not (dest.is_dir() and any(dest.rglob("*"))):
            return {
                "error": "clone_failed: empty tree",
                "repo": github_url,
                "source": "audit_repo",
            }
        packet = _build_packet(dest, name=name, as_of=as_of)
        return _packet_to_result(packet, source=github_url, as_of=as_of)


def build_server():
    """Construct the FastMCP server with both tools registered.

    Kept as a factory so tests can import and inspect it without starting stdio.
    The tool wrappers are the *only* place ``datetime.now`` is called for the
    audit timestamp, keeping the core functions deterministic.
    """
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("closeread-verify")

    @server.tool()
    def audit_project_tool(files: dict[str, str]) -> dict:
        """Audit one or more manifest/lockfiles TOGETHER and return a VERIFIED result.

        Pass a {filename: content} map. When you have both a manifest and its
        lockfile (e.g. package.json AND package-lock.json), send both: that pairing
        is what recovers npm's direct-vs-transitive split, so the production
        dependency you actually own surfaces as the DIRECT lead instead of
        collapsing to transitive. A single-file map works too (e.g. just
        requirements.txt). A subdir prefix like server/package.json is allowed.
        Versions are the INSTALLED lockfile versions, not the declared floor;
        advisories are confirmed via OSV. Deterministic, no LLM.
        """
        return audit_project(files, as_of=datetime.now(UTC))

    @server.tool()
    def audit_dependencies_tool(lockfile_content: str, filename: str) -> dict:
        """Audit a single manifest/lockfile and return a VERIFIED finding.

        Pass the raw lockfile text and its filename (package-lock.json,
        yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock, Pipfile.lock,
        Gemfile.lock, composer.lock, Cargo.lock). Returns the one finding that
        actually matters (the lead), the full direct-vs-transitive split, and the
        basis of the verdict. Versions are the INSTALLED lockfile versions, not
        the declared floor; advisories are confirmed via OSV. Deterministic.
        """
        return audit_dependencies(
            lockfile_content, filename, as_of=datetime.now(UTC)
        )

    @server.tool()
    def audit_repo_tool(github_url: str) -> dict:
        """Shallow-clone a public GitHub repo and return the same VERIFIED result.

        Use when you have a repo URL rather than a raw lockfile. Same output
        shape as audit_dependencies. Returns an error (never a fabricated
        result) if the repo cannot be cloned.
        """
        return audit_repo(github_url, as_of=datetime.now(UTC))

    return server


def main() -> None:
    """Console entry point: run the MCP server over stdio."""
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
