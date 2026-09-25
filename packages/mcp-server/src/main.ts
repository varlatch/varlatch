#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ContextError, loadToken, resolveContext } from "@varlatch/context";
import { VarlatchClient } from "@varlatch/sdk";
import { createVarlatchMcpServer, type McpDefaults } from "./server.js";

function fail(message: string): never {
  process.stderr.write(`varlatch-mcp: ${message}\n`);
  process.exit(1);
}

interface CliArgs {
  server?: string;
  organization?: string;
  project?: string;
  environment?: string;
  allowWrites: boolean;
  allowDisclose: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    allowWrites: process.env["VARLATCH_MCP_ALLOW_WRITES"] === "1",
    allowDisclose: process.env["VARLATCH_MCP_ALLOW_DISCLOSE"] === "1",
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) fail(`${arg} requires a value`);
      return v;
    };
    switch (arg) {
      case "--server":
        args.server = next();
        break;
      case "--org":
      case "--organization":
        args.organization = next();
        break;
      case "--project":
        args.project = next();
        break;
      case "--environment":
      case "--env":
        args.environment = next();
        break;
      case "--allow-writes":
        args.allowWrites = true;
        break;
      case "--allow-disclose":
        args.allowDisclose = true;
        break;
      case "--help":
      case "-h":
        process.stdout.write(
          `Usage: varlatch-mcp [--server URL] [--org SLUG] [--project SLUG] [--environment NAME] [--allow-writes] [--allow-disclose]

Runs a Model Context Protocol server over stdio. Defaults for org/project/
environment come from the varlatch repo context of the working directory
(varlatch.toml, .varlatch/local.json) when available; flags override.
Authentication uses VARLATCH_TOKEN or the stored credentials for the server.
Write and secret-disclosure tools are disabled unless explicitly enabled via
flags or VARLATCH_MCP_ALLOW_WRITES=1 / VARLATCH_MCP_ALLOW_DISCLOSE=1.
`,
        );
        process.exit(0);
        break;
      default:
        fail(`unknown argument ${arg}`);
    }
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  const defaults: McpDefaults = {};
  let server = args.server ?? process.env["VARLATCH_SERVER"];
  try {
    const resolveOptions = {
      cwd: process.cwd(),
      ...(args.environment !== undefined ? { environment: args.environment } : {}),
      ...(args.server !== undefined ? { server: args.server } : {}),
    };
    const ctx = resolveContext(resolveOptions);
    server ??= ctx.server;
    defaults.organization = args.organization ?? ctx.organization;
    defaults.project = args.project ?? ctx.project;
    defaults.environment = args.environment ?? ctx.environment;
  } catch (err) {
    if (!(err instanceof ContextError)) throw err;
    // Not inside a varlatch repo: fall back to flags/env only.
    if (args.organization !== undefined) defaults.organization = args.organization;
    if (args.project !== undefined) defaults.project = args.project;
    if (args.environment !== undefined) defaults.environment = args.environment;
  }

  if (!server) {
    fail(
      "no server configured; pass --server, set VARLATCH_SERVER, or run inside a varlatch repo",
    );
  }
  const token = loadToken(server);
  if (!token) {
    fail(`not authenticated to ${server}; run \`varlatch login\` or set VARLATCH_TOKEN`);
  }

  const client = new VarlatchClient({ server, token });
  const mcp = createVarlatchMcpServer({
    client,
    defaults,
    allowWrites: args.allowWrites,
    allowDisclose: args.allowDisclose,
  });
  await mcp.connect(new StdioServerTransport());
}

main().catch((err: unknown) => fail(err instanceof Error ? err.message : String(err)));
