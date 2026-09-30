# @varlatch/mcp-server

The [Model Context Protocol](https://modelcontextprotocol.io) server behind
`varlatch mcp`, which ships inside the CLI. See
[the MCP server](../../docs/reference/mcp.md) for tools, refusals, and
configuration:

```sh
claude mcp add varlatch -- varlatch mcp --org acme --project api -e development
```

No tool returns or writes a Secret's value; writes of non-secret values need
`--allow-writes`. `run.ts` holds the one start path that both `varlatch mcp`
and the deprecated `varlatch-mcp` entry point use, so neither can start the
server with fewer protections.

## Development

```sh
pnpm --filter @varlatch/mcp-server build
pnpm --filter @varlatch/mcp-server test
```
