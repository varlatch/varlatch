#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { createRequire } from "node:module";
import { runMcpServer } from "./run.js";

/**
 * The old `varlatch-mcp` entry point, kept for configurations that name it.
 * It runs exactly what `varlatch mcp` runs (runMcpServer), so it cannot
 * start a server with fewer protections, and says which command replaces it.
 */
const version = (createRequire(import.meta.url)("../package.json") as { version: string }).version;
process.stderr.write("varlatch-mcp: this entry point is deprecated; configure your MCP host with `varlatch mcp` instead\n");
runMcpServer(process.argv.slice(2), {
  env: process.env,
  cwd: process.cwd(),
  version,
  name: "varlatch-mcp",
  err: (line) => process.stderr.write(`${line}\n`),
  out: (text) => process.stdout.write(text),
}).then(
  (code) => {
    if (code !== null) process.exit(code);
  },
  (err: unknown) => {
    process.stderr.write(`varlatch-mcp: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
