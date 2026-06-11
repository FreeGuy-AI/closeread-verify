#!/usr/bin/env python3
"""agent_loop.py - a shipping agent that calls closeread-verify before it ships.

This is the whole pitch in one file: an AI coding agent should not ship code
without a checked answer about its dependencies, and no human is going to run
`npm audit` for it. So the agent calls closeread-verify over MCP as a pre-ship
gate, reads the verdict, and refuses to ship on a real, actionable finding.

The agent's decision logic here is scripted so the demo is deterministic and
needs no API key. Everything closeread-verify returns is REAL: the demo spins up
the published MCP server over stdio, audits against live OSV.dev advisories, and
the finding below is a genuine CVE in Flask 0.12.0.

Run:
    pip install closeread-verify
    python agent_loop.py
"""
import asyncio
import json
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# The "project" our agent is about to ship. It pins an old Flask with a known CVE.
VULNERABLE = {"requirements.txt": "flask==0.12.0\n"}
# The fix the agent applies once closeread-verify names a patched version.
PATCHED = {"requirements.txt": "flask==3.1.0\n"}


async def gate(session, files):
    """Call the real MCP tool and return the parsed verdict dict."""
    res = await session.call_tool("audit_project", {"files": files})
    data = getattr(res, "structuredContent", None)
    if not data:
        data = json.loads(res.content[0].text)
    if isinstance(data, dict) and set(data) == {"result"}:  # some SDKs wrap it
        data = data["result"]
    return data


def show(label, verdict):
    lead = verdict.get("lead")
    print(f"  closeread-verify ({label}):")
    if lead:
        print(f"    LEAD [{lead['severity'].upper()}] {lead['summary']}")
        print(f"         at {lead['location']}")
        print(f"         fix: {lead['fix']}")
    else:
        print("    clean: lead is null (nothing actionable to block on)")
    c = verdict.get("counts", {})
    print(f"    counts: {c.get('direct', 0)} direct, {c.get('transitive', 0)} transitive")


async def main():
    params = StdioServerParameters(command="closeread-verify")
    # Silence the server subprocess's own logging so the demo output is just the
    # agent and the verdict. The audit itself is unchanged.
    devnull = open(os.devnull, "w")
    async with stdio_client(params, errlog=devnull) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("AGENT: about to ship. Running the pre-ship dependency gate.\n")
            before = await gate(session, VULNERABLE)
            show("before", before)

            lead = before.get("lead")
            if not lead:
                print("\nAGENT: clean, shipping. (unexpected for this demo)")
                return

            print(f"\nAGENT: BLOCKED. A {lead['severity'].upper()} finding I can act on.")
            print("AGENT: applying the named fix and re-running the gate.\n")

            after = await gate(session, PATCHED)
            show("after", after)

            if after.get("lead"):
                print("\nAGENT: still blocked. Not shipping.")
            else:
                print("\nAGENT: verdict is clean. SHIPPING.")


if __name__ == "__main__":
    asyncio.run(main())
