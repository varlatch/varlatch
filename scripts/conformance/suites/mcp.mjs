#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * `varlatch mcp`, the MCP server inside the CLI under test, over stdio
 * against the target: it starts, lists its read tools (and no write or
 * disclosure tool without --allow-writes), and answers one read with the
 * target's own data, never a Secret's value. The client side is plain
 * JSON-RPC, one message per line, as MCP's stdio transport defines it.
 *
 *   mcp.mjs <origin> <api token> <seeded secret>   (run by scripts/conformance/run.mjs)
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cliPath, reporter } from "../suite-kit.mjs";

const [origin, token, seeded] = process.argv.slice(2);
if (!origin || !token || !seeded) {
  console.error("Usage: mcp.mjs <origin> <api token> <seeded secret>");
  process.exit(64);
}
const kit = reporter({ detailOnFailure: true });
const { check, error, finish } = kit;
const repo = mkdtempSync(join(tmpdir(), "mcp-repo-"));
const config = mkdtempSync(join(tmpdir(), "mcp-cfg-"));
const env = { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, VARLATCH_ASSISTED: "0" };

/** An MCP session with `varlatch mcp`: request(method, params) resolves with the response. */
function session(args) {
  const child = spawn(process.execPath, [cliPath(), "mcp", ...args], { cwd: repo, env, stdio: ["pipe", "pipe", "pipe"] });
  const pending = new Map();
  let buffer = "";
  let stderr = "";
  let next = 1;
  const exited = new Promise((resolve) => child.on("close", (code, signal) => resolve({ code, signal })));
  child.stderr.on("data", (d) => (stderr += d));
  child.stdout.on("data", (d) => {
    buffer += d;
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        error(`varlatch mcp wrote a line that is not JSON-RPC: ${line.slice(0, 200)}`);
        continue;
      }
      const waiter = pending.get(message.id);
      if (waiter) {
        pending.delete(message.id);
        waiter(message);
      }
    }
  });
  const send = (message) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
  const request = (method, params) =>
    new Promise((resolve, reject) => {
      const id = next++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`no answer to ${method} within 60 s; stderr: ${stderr.trim().slice(-300)}`));
      }, 60_000);
      pending.set(id, (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      send({ id, method, params });
    });
  return { request, notify: (method, params) => send({ method, params }), close: () => child.stdin.end(), exited, stderr: () => stderr, kill: () => child.kill("SIGKILL") };
}

let mcp = null;
try {
  if (kit.supports("mcp")) {
    const cli = (args) => spawnSync(process.execPath, [cliPath(), ...args], { cwd: repo, env, encoding: "utf8", timeout: 90_000 });
    const init = cli(["init", "--org", "acme", "--project", "api", "--server", origin]);
    if (init.status !== 0) throw new Error(`init exited ${init.status}: ${(init.stdout + init.stderr).trim().slice(-300)}`);
    const login = cli(["login", "--server", origin, "--token", token]);
    if (login.status !== 0) throw new Error(`login exited ${login.status}: ${(login.stdout + login.stderr).trim().slice(-300)}`);

    mcp = session(["-e", "development"]);
    const hello = await mcp.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "varlatch-conformance", version: "1" },
    });
    mcp.notify("notifications/initialized", {});
    check(
      "mcp.initializes-over-stdio",
      "varlatch mcp answers initialize over stdio and offers tools",
      !hello.error && typeof hello.result?.protocolVersion === "string" && hello.result?.capabilities?.tools !== undefined,
      JSON.stringify(hello).slice(0, 400),
    );

    const listed = await mcp.request("tools/list", {});
    const names = (listed.result?.tools ?? []).map((t) => t.name);
    const reads = ["varlatch_whoami", "varlatch_list_projects", "varlatch_list_environments", "varlatch_effective_configuration", "varlatch_get_active_contract"];
    check(
      "mcp.lists-read-tools-only",
      "tools/list names the read tools, and no write or disclosure tool without --allow-writes",
      reads.every((n) => names.includes(n)) && !names.some((n) => /set_value|delete_value|disclose/.test(n)),
      JSON.stringify(names),
    );

    // What the target itself says, to compare the tool's answer with.
    const direct = await fetch(`${origin}/v1/organizations/acme/projects/api/environments/development/effective-configuration`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((r) => r.json());
    const items = (direct.items ?? []).map((i) => i.name);
    const read = await mcp.request("tools/call", { name: "varlatch_effective_configuration", arguments: {} });
    const text = (read.result?.content ?? []).map((c) => c.text ?? "").join("\n");
    check(
      "mcp.reads-effective-configuration",
      "a read tool answers with the target's own data: every item of acme/api development's effective configuration",
      !read.error && read.result?.isError !== true && items.includes("DATABASE_URL") && items.every((n) => text.includes(n)),
      `${JSON.stringify(items)} ${JSON.stringify(read).slice(0, 400)}`,
    );
    check(
      "mcp.read-holds-no-secret",
      "no message from varlatch mcp carries the Secret's value or the credential",
      !JSON.stringify(read).includes(seeded) && !JSON.stringify(listed).includes(seeded) && !mcp.stderr().includes(seeded) && !mcp.stderr().includes(token),
    );

    mcp.close();
    const exit = await Promise.race([mcp.exited, new Promise((resolve) => setTimeout(() => resolve(null), 15_000))]);
    check("mcp.exits-when-stdin-closes", "varlatch mcp exits 0 when the host closes its input", exit?.code === 0, JSON.stringify(exit));
    mcp = null;
  }
} catch (err) {
  error(`mcp: ${err.message}`);
} finally {
  mcp?.kill();
  rmSync(repo, { recursive: true, force: true });
  rmSync(config, { recursive: true, force: true });
}
finish("MCP check(s)");
