// SPDX-License-Identifier: Apache-2.0
// The go-binary target and the stale-`lacks` probe. The tests that need a
// real varlatchd run when VARLATCH_GO_BINARY names one (go.yml builds it);
// with VARLATCH_REQUIRE_GO_BINARY set, a missing binary fails instead.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { probeLacks } from "../lacks-probe.mjs";
import { lacksFor } from "../lib/expect.mjs";
import { NOT_IMPLEMENTED_YET, openapiOperations } from "../lib/operations.mjs";
import { assess } from "../lib/request-log.mjs";
import * as goBinary from "../targets/go-binary.mjs";
import { loadTarget } from "../targets/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const inventory = JSON.parse(readFileSync(join(here, "..", "inventory.json"), "utf8"));
const openapi = openapiOperations(readFileSync(join(repoRoot, "packages/protocol/openapi.yaml"), "utf8"));
const binary = process.env.VARLATCH_GO_BINARY;
const needBinary = { skip: binary ? false : process.env.VARLATCH_REQUIRE_GO_BINARY ? false : "VARLATCH_GO_BINARY is not set (go.yml builds varlatchd and sets it)" };

test("go-binary refuses a path that is no executable, before creating anything", async () => {
  const { target, expectKey } = await loadTarget("go-binary:/nonexistent/varlatchd");
  assert.equal(expectKey, "go-binary");
  await assert.rejects(target.up({ argument: "/nonexistent/varlatchd", onState: () => assert.fail("created state") }), /is not an executable file/);
  await target.down({});
});

test("go-binary's request log: the requests the window counted, with millisecond times and the forwarded header", () => {
  const log = [
    { arrived: "2026-11-14T12:00:00.100Z", completed: "2026-11-14T12:00:00.150Z", client: "127.0.0.1", method: "GET", path: "/v1/meta", status: 200, bytes: 9, window: true, requestId: "req_1" },
    { arrived: "2026-11-14T12:00:00.200Z", completed: "2026-11-14T12:00:00.201Z", client: "127.0.0.1", method: "GET", path: "/assets/a.js", status: 200, bytes: 9, window: false, requestId: "req_2" },
    "not json",
    { arrived: "2026-11-14T12:00:01.000Z", completed: "2026-11-14T12:00:01.002Z", client: "198.18.0.4", method: "POST", path: "/v1/auth/device", status: 429, bytes: 9, window: true, forwardedFor: "198.18.0.4", requestId: "req_3" },
  ].map((r) => (typeof r === "string" ? r : JSON.stringify(r))).join("\n");
  const records = goBinary.requestsFromAccessLog(log);
  assert.deepEqual(records, [
    { client: "127.0.0.1", method: "GET", path: "/v1/meta", status: 200, arrivedAt: Date.parse("2026-11-14T12:00:00.100Z"), completedAt: Date.parse("2026-11-14T12:00:00.150Z"), resolutionMs: 1 },
    { client: "198.18.0.4", method: "POST", path: "/v1/auth/device", status: 429, arrivedAt: Date.parse("2026-11-14T12:00:01.000Z"), completedAt: Date.parse("2026-11-14T12:00:01.002Z"), resolutionMs: 1, forwardedFor: "198.18.0.4" },
  ]);
  // The proxy probe's pending-cap answer is recognized from these records.
  const windows = { "proxy-probe": [{ start: Date.parse("2026-11-14T12:00:00Z"), end: Date.parse("2026-11-14T12:00:02Z") }] };
  assert.equal(assess(records, { windows }).refusals.length, 0);
});

test("a real varlatchd: up, the operations, restart with its data, the request log, down", needBinary, async () => {
  let state;
  try {
    state = await goBinary.up({ argument: binary, onState: (s) => (state = s) });
    const meta = await fetch(`${state.origin}/v1/meta`).then((r) => r.json());
    assert.match(meta.installationId, /^inst_[a-z2-7]{26}$/);
    assert.ok(!meta.capabilities.includes("cli.download"));
    for (const op of ["bootstrap", "recover"]) {
      await assert.rejects(goBinary[op](state, "idn_x", {}), (err) => err.code === NOT_IMPLEMENTED_YET && /not built yet/.test(err.message));
    }
    await assert.rejects(goBinary.serveCli(state, true), (err) => err.code === NOT_IMPLEMENTED_YET);
    assert.equal((await fetch(`${state.origin}/readyz`)).status, 200, "varlatchd runs again after the serve_cli probe");
    await goBinary.restart(state);
    const again = await fetch(`${state.origin}/v1/meta`).then((r) => r.json());
    assert.equal(again.installationId, meta.installationId);
    const records = await goBinary.requestLog(state);
    assert.ok(records.filter((r) => r.path === "/v1/meta" && r.status === 200 && r.client === "127.0.0.1").length >= 2);
    assert.ok(!records.some((r) => r.path === "/readyz"), "/readyz is outside the window");
    assert.match(await goBinary.logs(state), /varlatchd is serving/);
    assert.equal(goBinary.fingerprint(state).sha256.length, 64);
  } finally {
    if (state) await goBinary.down(state);
  }
});

// The probe against a real varlatchd: every operation expect/go-binary.json
// lists answers the stub, so nothing is stale; an operation with a handler
// (here /v1/meta, which this varlatchd serves) listed as lacking is stale,
// named, and fails the run.
test("the stale-lacks probe against a real varlatchd", needBinary, async () => {
  const lacks = [...lacksFor(JSON.parse(readFileSync(join(here, "..", "expect", "go-binary.json"), "utf8")), "go-binary").keys()];
  let state;
  try {
    state = await goBinary.up({ argument: binary, onState: (s) => (state = s) });
    const ask = (list) => probeLacks({ inventory, openapi, lacks: list, origin: state.origin, target: goBinary, state });
    assert.deepEqual(await ask(lacks), []);
    const stale = await ask(["listOrganizations", "getMeta", "enroll-page"]);
    assert.deepEqual(stale.map((s) => s.operation), ["getMeta"]);
    assert.match(stale[0].why, /answered 200, not 501 NOT_IMPLEMENTED_YET/);
    // The runner turns a stale entry into a problem: the run fails.
    const { evaluate } = await import("../lib/inventory.mjs");
    const judged = evaluate({ inventory: { ...inventory, checks: {} }, reports: [], errors: stale.map((s) => ({ suite: "runner", message: `expect/go-binary.json lacks ${s.operation}, but ${s.why}` })) });
    assert.equal(judged.ok, false);
    assert.match(judged.problems[0], /lacks getMeta, but the target answered 200/);
    // A target operation that succeeds is stale too.
    const fake = { bootstrap: async () => "http://localhost/enroll#x\n" };
    assert.match((await probeLacks({ inventory, openapi, lacks: ["admin-bootstrap"], origin: state.origin, target: fake, state }))[0].why, /bootstrap operation succeeded/);
  } finally {
    if (state) await goBinary.down(state);
  }
});

// A stand-in varlatchd for the adapter's process handling: `serve --config
// <file>` listens where the file says and answers /readyz; with
// FAKE_HANG_FIRST set it never answers the first /readyz; with
// FAKE_STOP_DELAY_MS set it takes that long to stop after SIGTERM.
const FAKE = `#!/usr/bin/env node
const fs = require("node:fs");
const http = require("node:http");
const conf = fs.readFileSync(process.argv[process.argv.indexOf("--config") + 1], "utf8");
const [, host, port] = /^listen = (.+):(\\d+)$/m.exec(conf);
let first = true;
http.createServer((req, res) => {
  if (req.url === "/readyz" && first && process.env.FAKE_HANG_FIRST) { first = false; return; }
  res.statusCode = req.url === "/readyz" ? 200 : 404;
  res.end("ok");
}).listen(Number(port), host, () => console.log("varlatchd is serving"));
process.on("SIGTERM", () => setTimeout(() => process.exit(0), Number(process.env.FAKE_STOP_DELAY_MS ?? 0)));
`;

function fakeBinary() {
  const dir = mkdtempSync(join(tmpdir(), "go-binary-fake-"));
  const path = join(dir, "varlatchd");
  writeFileSync(path, FAKE);
  chmodSync(path, 0o755);
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const parentOf = (pid) => Number(readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\) /s, "").split(" ")[1]);
const runsConf = (pid, conf) => {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").includes(conf);
  } catch {
    return false;
  }
};

// The runner killed outright (SIGKILL: no finally, no down): the
// supervisor stops varlatchd and removes the installation directory. Only
// the PIDs and the directory this test's runner created are looked at.
// With duringStop, the runner first starts a restart, so the supervisor
// has its `stop` and varlatchd is still shutting down (it takes
// FAKE_STOP_DELAY_MS) when the runner is killed.
async function killedRunnerLeavesNothing(binaryPath, env = {}, { duringStop = false } = {}) {
  const adapter = pathToFileURL(join(here, "..", "targets", "go-binary.mjs")).href;
  const code = `
    const goBinary = await import(${JSON.stringify(adapter)});
    const state = await goBinary.up({ argument: ${JSON.stringify(binaryPath)} });
    if (${duringStop}) {
      goBinary.restart(state).catch(() => {});
      await new Promise((r) => setTimeout(r, 300));
    }
    console.log(JSON.stringify(state));
    setInterval(() => {}, 1 << 30);
  `;
  const runner = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "inherit"], env: { ...process.env, ...env } });
  let state;
  const pids = [];
  try {
    state = await new Promise((resolveState, reject) => {
      let out = "";
      runner.stdout.on("data", (d) => {
        out += d;
        const line = out.split("\n")[0];
        if (out.includes("\n")) resolveState(JSON.parse(line));
      });
      runner.once("exit", (c) => reject(new Error(`the runner exited ${c} before varlatchd was up`)));
    });
    const server = Number(readFileSync(state.pidFile, "utf8"));
    const supervisor = parentOf(server);
    pids.push(server, supervisor);
    assert.ok(alive(server) && runsConf(server, state.conf), "varlatchd runs");
    assert.ok(runsConf(supervisor, state.conf) && supervisor !== runner.pid, "under its supervisor");
    if (duringStop) {
      assert.ok(alive(server) && alive(supervisor), "varlatchd is still shutting down when the runner dies");
    } else {
      assert.equal((await fetch(`${state.origin}/readyz`)).status, 200);
    }
    runner.kill("SIGKILL");
    const deadline = Date.now() + 30_000;
    while ((alive(server) || alive(supervisor) || existsSync(state.dir)) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    assert.ok(!alive(server), "varlatchd stopped");
    assert.ok(!alive(supervisor), "the supervisor ended");
    assert.ok(!existsSync(state.dir), "the installation directory is removed");
  } finally {
    if (runner.exitCode === null && runner.signalCode === null) runner.kill("SIGKILL");
    for (const pid of pids) if (state && alive(pid) && runsConf(pid, state.conf)) process.kill(pid, "SIGKILL");
    if (state?.dir?.startsWith(join(tmpdir(), "conformance-go-"))) rmSync(state.dir, { recursive: true, force: true });
  }
}

const linuxOnly = { skip: process.platform === "linux" ? false : "reads /proc" };

test("a runner killed outright leaves no varlatchd and no directory behind", linuxOnly, async () => {
  const fake = fakeBinary();
  try {
    await killedRunnerLeavesNothing(fake.path);
  } finally {
    fake.cleanup();
  }
});

test("a runner killed outright leaves nothing behind, with a real varlatchd", { ...needBinary, ...(process.platform === "linux" ? {} : linuxOnly) }, async () => {
  await killedRunnerLeavesNothing(binary);
});

test("a runner killed while a restart's stop is under way leaves nothing behind", linuxOnly, async () => {
  const fake = fakeBinary();
  try {
    await killedRunnerLeavesNothing(fake.path, { FAKE_STOP_DELAY_MS: "3000" }, { duringStop: true });
  } finally {
    fake.cleanup();
  }
});

test("up, restart and down keep the directory until down, then leave nothing", linuxOnly, async () => {
  const fake = fakeBinary();
  let state;
  try {
    state = await goBinary.up({ argument: fake.path, onState: (s) => (state = s) });
    const first = Number(readFileSync(state.pidFile, "utf8"));
    await goBinary.restart(state);
    const second = Number(readFileSync(state.pidFile, "utf8"));
    assert.ok(!alive(first) && alive(second) && existsSync(state.dir), "restarted on the same directory");
    await goBinary.down(state);
    assert.ok(!alive(second) && !existsSync(state.dir));
  } finally {
    if (state) await goBinary.down(state);
    fake.cleanup();
  }
});

test("a /readyz that never answers is abandoned and asked again", linuxOnly, async () => {
  const fake = fakeBinary();
  const saved = process.env.FAKE_HANG_FIRST;
  process.env.FAKE_HANG_FIRST = "1";
  let state;
  try {
    const t0 = Date.now();
    state = await goBinary.up({ argument: fake.path, onState: (s) => (state = s) });
    assert.ok(Date.now() - t0 < 15_000, "ready after the first probe timed out");
  } finally {
    if (saved === undefined) delete process.env.FAKE_HANG_FIRST;
    else process.env.FAKE_HANG_FIRST = saved;
    if (state) await goBinary.down(state);
    fake.cleanup();
  }
});
