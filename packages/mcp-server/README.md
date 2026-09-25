# @varlatch/mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
varlatch to MCP hosts (Claude Code, Claude Desktop, other agents) over stdio.

## Security model

Read-only by default, aligned with Varlatch's agent-safety posture:

- Always available: metadata, org/project/environment listings, effective
  configuration (secrets stay redacted), contract, validation, audit events.
- `--allow-writes` (or `VARLATCH_MCP_ALLOW_WRITES=1`): `varlatch_set_value`,
  `varlatch_delete_value`.
- `--allow-disclose` (or `VARLATCH_MCP_ALLOW_DISCLOSE=1`):
  `varlatch_disclose_secrets`, the only path to plaintext secrets, audited
  server-side.

Disabled tools are not registered at all, so hosts never see them.

## Configuration

Authentication reuses the CLI's credentials: `VARLATCH_TOKEN`, or the token
stored by `varlatch login` for the target server. When launched inside a
varlatch repo, the default organization/project/environment resolve from
`varlatch.toml` / `.varlatch/local.json`; otherwise pass `--org`, `--project`,
`--environment` (every tool also accepts them as arguments per call).

Example Claude Code registration:

```sh
claude mcp add varlatch -- varlatch-mcp --org acme --project api --environment dev
```

## Development

```sh
pnpm --filter @varlatch/mcp-server build
pnpm --filter @varlatch/mcp-server test
```
