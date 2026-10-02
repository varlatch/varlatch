# The MCP server: `varlatch mcp`

`varlatch mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio, for MCP hosts that give their model no shell. A coding
agent with a shell uses the CLI directly, in
[assisted mode](assisted-mode.md). The server ships inside the CLI, so its
version is always the CLI's.

```
varlatch mcp [--server <url>] [--org <slug>] [--project <slug>] [-e <env>] [--allow-writes]
```

Register it with an MCP host, for example:

```
claude mcp add varlatch -- varlatch mcp --org acme --project api -e development
```

Or let the CLI add it to the project's MCP files (`.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
`opencode.json`, `.codex/config.toml`) with
`varlatch agents install --mcp`; see
[coding agents](coding-agents.md#mcp-opt-in).

## Tools

- **Always:** server and context information, organizations, projects,
  environments, the effective configuration (with non-secret values on
  request), the active Contract, validation, and audit events.
- **With `--allow-writes`** (or `VARLATCH_MCP_ALLOW_WRITES=1`):
  `varlatch_set_value` and `varlatch_delete_value`.
- Tools that are off are not registered, so the host never sees them.

## What it never does

No MCP host can keep a tool result out of the model's context, and every
tool argument comes from the model. So:

- **No tool returns a Secret's value.** There is no disclosure tool.
  `--allow-disclose` and `VARLATCH_MCP_ALLOW_DISCLOSE` are refused with
  status 64, not ignored.
- **No tool writes a Secret's value.** `varlatch_set_value` refuses an item
  the active Contract marks sensitive, an item outside the Contract, any
  item of a project without a Contract, and any item when the Contract
  cannot be read, and writes nothing. Secrets enter through
  `varlatch import`, `varlatch values set --generate`, `--from-file`,
  `--stdin`, or the human. `varlatch_delete_value` writes no value and stays
  available with `--allow-writes`.
- **No tool replaces a value without the item named again.**
  `varlatch_set_value` writes a new plain value directly, but replaces one
  the environment already has, or inherits from its parent environment,
  only when its `replace` argument repeats the item's name; otherwise it
  returns an error and writes nothing. Existence comes from metadata only
  (no values are read), and when the server cannot say whether the item
  has a value, it counts as existing. `replace` naming another item is
  refused before any request. `replace` never makes a Secret writable, and
  `expectedVersionId` guards against a concurrent change: it is no
  substitute for `replace`. Like `confirm`, `replace` records intent, not
  proof that a human approved.
- **No tool deletes without the item named again.** `varlatch_delete_value`
  deletes only when its `confirm` argument repeats the item's name, for a
  plain value and a Secret alike; otherwise it returns an error and makes
  no request. `--allow-writes` enables the tool; it does not record the
  intent to delete. The confirmation records that intent, not proof that
  a human approved: a coding agent passes it only after the human approved
  deleting that item in that environment.

## The credential

- It uses `VARLATCH_TOKEN`, or the credential `varlatch login` stored for the
  server.
- Inside an agent-safe run it uses only the run's agent-run credential (from
  `--agent-metadata`), and never your stored credential, even when
  `VARLATCH_CONFIG_DIR` is unset. Without an agent-run credential it does
  not start (status 77). `--allow-writes` is refused there (64): the
  agent-run credential is read-only.
- Organization, project, and environment default to the repository context
  of the working directory; flags override them, and every tool also
  accepts them as arguments.

## Exit status

The server runs until the host closes its stdin. It does not start, and
exits, with 64 for a wrong command line (including `--allow-disclose`) and 77
when there is no credential.

## Migrating from `varlatch-mcp`

The separate `varlatch-mcp` entry point still starts, but prints a
deprecation notice and runs exactly what `varlatch mcp` runs, with the same
refusals. Replace `varlatch-mcp` with `varlatch mcp` in your host's
configuration, and remove any `--allow-disclose`.
