# ADR-0001: CLI wrapper over an MCP server

**Status:** Accepted
**Date:** 2026-07-31
**Deciders:** Ross

## Context

Bitwarden ships an official MCP server that gives an AI assistant structured tool calls against a
password vault — retrieve/create/edit items, generate passwords, manage organization settings.
It's a reasonable design for what it's for: letting an assistant *manage a vault* on a human's
behalf.

That's not this project's problem. The agent here (Claude Code, or anything like it) already has
unrestricted shell access via a Bash tool. It doesn't need a structured tool-call surface to reach
Bitwarden — it can already run `curl`, `git`, `psql`, anything. What it needs is a gate in front of
*secret-using commands specifically*: an allowlist, an audit trail, and a human approval step for
anything not pre-approved. An MCP server that hands the agent broader interactive vault access
(read arbitrary items, write new ones) adds a second, differently-shaped credential surface without
removing the first — the agent still has the Bash tool, now also has vault tool calls. It's more
surface area, not less.

Options considered:

1. **Adopt the Bitwarden MCP server as-is.** Gives an assistant direct read/write vault access via
   `bw unlock`. Rejected — this is explicitly the access model this whole project exists to avoid;
   granting an agent that's already got an unrestricted Bash tool full interactive vault access on
   top of it was judged "overly paranoid" territory to adopt.
2. **Build our own MCP server**, exposing a narrower tool (e.g. `run_with_secrets`) instead of full
   vault access. Would work, and is more "agent-native" — but it's a second interface (CLI +
   MCP protocol) to build and maintain for zero gain over a CLI, since the agent already has a
   shell and doesn't need a structured schema to invoke one more binary.
3. **CLI wrapper**, invoked like any other shell command. The agent already runs commands via Bash;
   this is just one more command, with the same allowlist/audit/approval gate applying uniformly to
   it as to everything else the agent might try to do with secrets.

## Decision

CLI wrapper only. Not "CLI now, MCP later" — permanently. If an MCP-compatible surface is ever
wanted, it would wrap this same binary/broker rather than duplicate its logic, but that's not
planned.

## Consequences

**Positive**
- One trust surface, one interface, one place the allowlist/audit/approval gate is enforced.
- Works with any shell-capable agent harness, not just MCP clients.
- No protocol/schema work — cobra flag parsing is the entire interface.

**Negative**
- No structured tool-call schema for an agent harness to introspect ahead of time (an MCP client
  could otherwise show a human "this tool wants to run X" before the agent even attempts it). This
  project's approval gate happens at invocation time instead, via `kdialog`.
- Doesn't help non-shell-capable agent architectures (e.g. an agent that only ever gets a fixed
  tool-call API, never a raw shell) — not a target for v1.
