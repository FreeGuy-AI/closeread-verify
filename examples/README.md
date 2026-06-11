# Examples

## `agent_loop.py` - the pre-ship gate

The case for closeread-verify in one runnable file: an AI coding agent that
refuses to ship until its dependencies pass a checked audit. No human is going to
run `npm audit` for an agent, so the agent calls the audit itself, over MCP, and
reads the verdict before it ships.

```bash
pip install closeread-verify
python agent_loop.py
```

Expected output:

```text
AGENT: about to ship. Running the pre-ship dependency gate.

  closeread-verify (before):
    LEAD [HIGH] flask@0.12.0 affected by GHSA-562c-5r94-xh97
         at requirements.txt:1
         fix: Update flask to a patched version (see references).
    counts: 1 direct, 0 transitive

AGENT: BLOCKED. A HIGH finding I can act on.
AGENT: applying the named fix and re-running the gate.

  closeread-verify (after):
    clean: lead is null (nothing actionable to block on)
    counts: 0 direct, 0 transitive

AGENT: verdict is clean. SHIPPING.
```

### What is real and what is not

The agent's decision logic is scripted, so the demo is deterministic and needs no
API key. Everything closeread-verify does is real: the script launches the
published MCP server over stdio, the audit runs against live [OSV.dev](https://osv.dev)
advisories, and the finding is a genuine CVE in Flask 0.12.0. Swap in your own
`requirements.txt` (or `package.json` + `package-lock.json`) and the verdict
changes with it.

### The point

The agent never sees a wall of CVEs. It gets a single `lead`: the one direct,
production, actionable finding, with the version to bump to. When the project is
clean, `lead` is `null` and the agent ships. That binary, checked-against-the-
installed-version signal is the thing an agent can gate on, and the thing a raw
scan cannot hand it.
