# closeread-verify

[![PyPI](https://img.shields.io/pypi/v/closeread-verify.svg)](https://pypi.org/project/closeread-verify/) [![Python](https://img.shields.io/pypi/pyversions/closeread-verify.svg)](https://pypi.org/project/closeread-verify/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![MCP](https://img.shields.io/badge/MCP-server-1f6feb.svg)](https://modelcontextprotocol.io)

**A verified dependency-audit verdict any AI agent can call.**

<!-- mcp-name: io.github.FreeGuy-AI/closeread-verify -->

A free scanner gives you raw CVEs. `closeread-verify` gives you the judgment: the
verdict checked against the version you actually installed, the one finding that
matters, and the exact fix. It runs as an [MCP](https://modelcontextprotocol.io)
server, so any agent (Claude Code, Cursor, your own) can call it before it ships
code and get back a checked answer, not a wall of noise.

## Why this and not `npm audit`

A raw scanner and the agent itself can already produce a list of CVEs. What they
cannot manufacture is the *verdict*. `closeread-verify` is built around the one
discipline that separates a real audit from a scan:

- **It reports the INSTALLED version, not the declared floor.** `^4.17.0` in a
  manifest is not what you shipped. The tool resolves the real pinned version
  from your lockfile and checks *that*, so it does not cry wolf over a caret
  range you already patched, and does not miss a vulnerable pin a manifest-only
  scan would wave through.
- **It splits direct vs transitive.** The dependency you declared and own (yours
  to bump) is separated from the one you inherited five levels down. Most scanners
  flatten these into one undifferentiated list. This one tells you which is which.
- **It surfaces the one finding that matters.** Instead of 200 rows, you get a
  single `lead`: the highest-severity *direct production* issue, with the exact
  fix. If the only findings are transitive or dev-only, the lead is honestly
  `null` rather than a manufactured headline.
- **It is deterministic and re-checkable.** No LLM in the path. Same lockfile in,
  same verdict out. Advisories are confirmed against [OSV.dev](https://osv.dev).
  The verdict carries its own basis so a reviewer can re-run it.

That verified artifact, not the raw scan, is the product.

## Install

```bash
pip install closeread-verify
```

Python 3.11+. No API key, no account, no source access. Lockfile in, verdict out.

## See it in an agent loop

[`examples/agent_loop.py`](examples/agent_loop.py) is a runnable agent that uses
closeread-verify as a pre-ship gate: it blocks on a real Flask CVE, applies the
named fix, re-checks, and ships. Real MCP over stdio, real OSV advisories, no API
key.

```bash
python examples/agent_loop.py
```

## Use it as an MCP server

`closeread-verify` is the stdio command that starts the server:

```bash
closeread-verify
```

### Client config

Add it to your MCP client. Claude Code / Cursor style (`mcp.json` /
`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "closeread-verify": {
      "command": "closeread-verify"
    }
  }
}
```

If you installed into a specific environment, point at that interpreter instead:

```json
{
  "mcpServers": {
    "closeread-verify": {
      "command": "python",
      "args": ["-m", "closeread.mcp_server"]
    }
  }
}
```

## The three tools

| Tool | Input | Use it when |
|------|-------|-------------|
| `audit_project` | `files`: a `{filename: content}` map | You have a real checkout. Pass the manifest **and** its lockfile together (e.g. `package.json` + `package-lock.json`) so the direct-vs-transitive split is recovered. Subdir prefixes like `server/package.json` are allowed. |
| `audit_dependencies` | `lockfile_content`: str, `filename`: str | You have a single manifest or lockfile and want a one-shot verdict. |
| `audit_repo` | `github_url`: str | You have a public repo URL. It shallow-clones and runs the same audit. Returns an error, never a fabricated result, if the clone fails. |

The filename is load-bearing: it routes the content to the right ecosystem
parser. Supported lockfiles include `package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`,
`Gemfile.lock`, `composer.lock`, and `Cargo.lock`.

### Example

Calling `audit_dependencies` on a `requirements.txt` that pins `flask==0.12.0`:

```json
{
  "source": "lockfile:requirements.txt",
  "lead": {
    "summary": "flask@0.12.0 affected by GHSA-562c-5r94-xh97",
    "severity": "high",
    "is_direct": true,
    "dependency_kind": "prod",
    "location": "requirements.txt:1",
    "fix": "Update flask to a patched version (see references).",
    "confidence": 0.9
  },
  "findings": {
    "issues": [],
    "direct": [
      {
        "kind": "dependency",
        "package": "flask",
        "severity": "high",
        "is_direct": true,
        "versions": ["0.12.0"],
        "advisories": ["GHSA-562c-5r94-xh97", "GHSA-5wv5-4vpf-pj6m", "GHSA-m2qf-hxjv-5gpq"],
        "locations": ["requirements.txt:1"],
        "recommendation": "Update flask to a patched version (see references)."
      }
    ],
    "transitive": []
  },
  "counts": { "product_critical": 3, "issues": 0, "direct": 1, "transitive": 0 },
  "verification": {
    "basis": "each version is the INSTALLED version resolved from the lockfile, not the declared floor; advisories confirmed via OSV; result is deterministic and re-checkable",
    "scanner": "closeread SCA (deterministic, no LLM)",
    "advisory_source": "OSV.dev",
    "as_of": "2026-06-08T12:00:00+00:00"
  }
}
```

The agent does not get a scan to interpret. It gets a verdict to act on: bump
`flask`, here is the line, here is why.

## The verified-audit primitive for the agent era

Agents are starting to write, review, and ship code on their own. Before an agent
opens a PR or green-lights a deploy, it needs an answer to a simple question with
a checkable answer: *is anything I depend on known-vulnerable, in the version I
actually pinned, and is it mine to fix?* `closeread-verify` is that primitive. One
MCP call, a deterministic verdict, no LLM in the loop to hallucinate a CVE that
does not exist or miss one that does.

## Scope, honestly

- **Ecosystems:** npm/yarn/pnpm, pip/poetry/pipenv, RubyGems, Packagist
  (Composer), crates.io (Cargo).
- **Deterministic:** no LLM, no network beyond OSV.dev advisory lookups.
- **Lockfile-only:** it reads manifests and lockfiles. It does not need, request,
  or transmit your source code.
- **What it is not:** this is the free, deterministic dependency-audit tier. It is
  not a full code review, not a SAST engine, not a license or architecture audit.
  It does one thing: a verified verdict on your dependencies.

## License

MIT. Built by Free Guy.
