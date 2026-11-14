// SPDX-License-Identifier: Apache-2.0
/**
 * The mcp suite's secrecy check, against a stand-in `varlatch mcp`: it
 * fails when the Secret's value or the credential shows anywhere in what
 * the process writes, from initialize to exit, and passes when neither does.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseSuiteOutput } from "../lib/results.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const suitePath = join(here, "..", "suites", "mcp.mjs");
const SEEDED = "postgres://seeded-secret-value";
const TOKEN = "credential-under-test-0123456789";

// A stand-in CLI: `init` and `login` succeed; `mcp` answers JSON-RPC on
// stdio and leaks what LEAK names. The suite runs the CLI with a clean
// environment, so each leak gets its own copy with LEAK filled in.
const FAKE_CLI = (leak) => `
const [cmd] = process.argv.slice(2);
if (cmd !== "mcp") process.exit(0);
const leak = ${JSON.stringify(leak)};
const seeded = ${JSON.stringify(SEEDED)};
const token = ${JSON.stringify(TOKEN)};
const out = (m) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...m }) + "\\n");
let buffer = "";
process.stdin.on("data", (d) => {
  buffer += d;
  let i;
  while ((i = buffer.indexOf("\\n")) >= 0) {
    const m = JSON.parse(buffer.slice(0, i));
    buffer = buffer.slice(i + 1);
    if (m.method === "initialize") {
      out({ id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: leak === "initialize" ? seeded : "varlatch" } } });
    } else if (m.method === "tools/list") {
      out({ id: m.id, result: { tools: ["varlatch_whoami", "varlatch_list_projects", "varlatch_list_environments", "varlatch_effective_configuration", "varlatch_get_active_contract"].map((name) => ({ name })) } });
    } else if (m.method === "tools/call") {
      out({ id: m.id, result: { content: [{ type: "text", text: "DATABASE_URL PORT" + (leak === "read-token" ? " " + token : "") }] } });
      if (leak === "notification") out({ method: "notifications/message", params: { data: seeded } });
      if (leak === "escaped") process.stdout.write('{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"' + [...seeded].map((c) => "\\\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("") + '"}}\\n');
    }
  }
});
process.stdin.on("end", () => {
  if (leak === "stderr-at-exit") process.stderr.write("closing with " + token + "\\n");
  process.exit(0);
});
`;

let dir;
let server;
let origin;
before(async () => {
  dir = mkdtempSync(join(tmpdir(), "mcp-suite-test-"));
  server = createServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ items: [{ name: "DATABASE_URL" }, { name: "PORT" }] }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

function runSuite(leak) {
  const cli = join(dir, `fake-cli-${leak || "none"}.cjs`);
  writeFileSync(cli, FAKE_CLI(leak));
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [suitePath, origin, TOKEN, SEEDED], {
      env: { PATH: process.env.PATH ?? "", CONFORMANCE_SUITE: "mcp", VARLATCH_CLI: cli, VARLATCH_CLI_VERSION: "" },
    });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.on("close", (code) => resolve({ code, stdout, results: parseSuiteOutput(stdout).results }));
  });
}

const outcome = (r, id) => r.results.find((x) => x.id === id)?.status;

test("no leak: every MCP check passes", async () => {
  const r = await runSuite("");
  assert.equal(r.code, 0, r.stdout);
  assert.equal(outcome(r, "mcp.read-holds-no-secret"), "PASS");
});

for (const leak of ["initialize", "read-token", "notification", "escaped", "stderr-at-exit"]) {
  test(`a leak in ${leak} fails the secrecy check`, async () => {
    const r = await runSuite(leak);
    assert.equal(outcome(r, "mcp.read-holds-no-secret"), "FAIL", r.stdout);
    assert.equal(r.code, 1);
  });
}
