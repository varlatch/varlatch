#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Smoke test of `varlatch mcp` in a built CLI bundle (ADR-0043 Decision 9):
 * the release asset must carry a working MCP server with no disclosure tool.
 * It speaks MCP's stdio JSON-RPC directly (initialize, then tools/list), so
 * it needs nothing but Node; tools/list contacts no Varlatch server.
 *
 * Checks: the server starts and reports the bundle's version; the read tools
 * are listed and nothing that discloses; --allow-writes adds exactly the two
 * write tools; --allow-disclose is refused with status 64.
 *
 * Usage: smoke-mcp.mjs <path/to/varlatch.cjs>
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const bundle = process.argv[2] ? resolve(process.argv[2]) : null;
if (!bundle) {
  console.error("usage: smoke-mcp.mjs <path/to/varlatch.cjs>");
  process.exit(64);
}

const READ_TOOLS = [
  "varlatch_effective_configuration",
  "varlatch_get_active_contract",
  "varlatch_list_audit_events",
  "varlatch_list_environments",
  "varlatch_list_organizations",
  "varlatch_list_projects",
  "varlatch_validate_environment",
  "varlatch_whoami",
];
const WRITE_TOOLS = ["varlatch_delete_value", "varlatch_set_value"];

const home = mkdtempSync(join(tmpdir(), "varlatch-mcp-smoke-"));
const env = {
  PATH: process.env.PATH,
  HOME: home,
  VARLATCH_CONFIG_DIR: join(home, "config"),
  VARLATCH_TOKEN: "vlt_smoke_not_a_credential",
  VARLATCH_ASSISTED: "0",
};
const args = ["mcp", "--server", "http://127.0.0.1:9", "--org", "smoke", "--project", "smoke", "--environment", "smoke"];

function fail(message) {
  console.error(`smoke-mcp: ${message}`);
  rmSync(home, { recursive: true, force: true });
  process.exit(1);
}

/** Start the server with `extra` flags, list its tools, and stop it. */
function listTools(extra) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bundle, ...args, ...extra], { env, cwd: home, stdio: ["pipe", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`no tools/list answer within 20 seconds; stderr: ${stderr}`));
    }, 20_000);
    let buffer = "";
    let stderr = "";
    let serverInfo = null;
    child.stderr.on("data", (d) => (stderr += d));
    child.stdout.on("data", (d) => {
      buffer += d;
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        const message = JSON.parse(line);
        if (message.id === 1) {
          serverInfo = message.result?.serverInfo ?? null;
          child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
          child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
        } else if (message.id === 2) {
          clearTimeout(timer);
          child.kill();
          resolve({ serverInfo, tools: (message.result?.tools ?? []).map((t) => t.name).sort() });
        }
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (serverInfo === null) reject(new Error(`exited ${code} before answering initialize; stderr: ${stderr}`));
    });
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "smoke-mcp", version: "0" } } })}\n`,
    );
  });
}

const version = spawnSync(process.execPath, [bundle, "--version"], { env, encoding: "utf8" }).stdout.trim().split(" ")[1];
try {
  const plain = await listTools([]);
  if (plain.serverInfo?.name !== "varlatch") fail(`serverInfo.name is ${JSON.stringify(plain.serverInfo?.name)}, expected "varlatch"`);
  if (plain.serverInfo?.version !== version) fail(`serverInfo.version is ${plain.serverInfo?.version}, the bundle is ${version}`);
  if (JSON.stringify(plain.tools) !== JSON.stringify(READ_TOOLS)) fail(`read-only tools are ${plain.tools.join(", ")}`);
  const writes = await listTools(["--allow-writes"]);
  const expected = [...READ_TOOLS, ...WRITE_TOOLS].sort();
  if (JSON.stringify(writes.tools) !== JSON.stringify(expected)) fail(`with --allow-writes the tools are ${writes.tools.join(", ")}`);
  for (const list of [plain.tools, writes.tools]) {
    if (list.some((name) => /disclose|reveal/i.test(name))) fail(`a disclosure tool is listed: ${list.join(", ")}`);
  }
} catch (err) {
  fail(err.message);
}
const refused = spawnSync(process.execPath, [bundle, ...args, "--allow-disclose"], { env, cwd: home, encoding: "utf8", timeout: 20_000 });
if (refused.status !== 64 || !/secret disclosure through MCP has been removed/.test(refused.stderr)) {
  fail(`--allow-disclose was not refused with status 64 (status ${refused.status}; stderr: ${refused.stderr.trim()})`);
}
rmSync(home, { recursive: true, force: true });
console.log(`smoke-mcp: varlatch mcp ${version} starts, lists ${READ_TOOLS.length} read tools (${READ_TOOLS.length + WRITE_TOOLS.length} with --allow-writes), no disclosure tool, --allow-disclose refused`);
