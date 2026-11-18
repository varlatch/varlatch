// SPDX-License-Identifier: Apache-2.0
/**
 * A target operation's deadline (lib/deadline.mjs) ends the operation's own
 * child processes with everything they started, so a bounded call leaves no
 * orphan: a wrapper (target-op.mjs) whose child (docker compose) started a
 * child of its own (the Compose plugin) all end by the deadline, a process
 * that ignores SIGTERM included, and a child that exits early takes what it
 * left behind with it.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { DEADLINE_ENV, deadlineSpawnSync, GRACE_MS, remainingMs } from "../lib/deadline.mjs";

const DEADLINE = fileURLToPath(new URL("../lib/deadline.mjs", import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** A sleep length no other process uses, to find this test's processes. */
const marker = () => `${31 + Math.random()}`.slice(0, 9);
/** The PIDs of processes whose command line holds `pattern`. */
const running = (pattern) => spawnSync("pgrep", ["-f", pattern], { encoding: "utf8" }).stdout.split("\n").filter(Boolean).map(Number).filter((p) => p !== process.pid);

/** Runs `script` (shell) through deadlineSpawnSync in a wrapper process, as target-op.mjs runs docker compose; its answer and how long it took. */
function throughWrapper(script, deadlineInMs) {
  const dir = mkdtempSync(join(tmpdir(), "deadline-test-"));
  try {
    const wrapper = join(dir, "wrapper.mjs");
    writeFileSync(wrapper, `import { deadlineSpawnSync } from ${JSON.stringify(DEADLINE)};
const r = deadlineSpawnSync("sh", ["-c", ${JSON.stringify(script)}], { encoding: "utf8" });
process.stdout.write(JSON.stringify({ timedOut: r.timedOut, status: r.status, signal: r.signal, stdout: r.stdout }));
`);
    const started = Date.now();
    const r = spawnSync(process.execPath, [wrapper], {
      encoding: "utf8", timeout: 20_000, killSignal: "SIGKILL",
      env: { ...process.env, [DEADLINE_ENV]: String(Date.now() + deadlineInMs) },
    });
    assert.equal(r.status, 0, r.stderr);
    return { ...JSON.parse(r.stdout), took: Date.now() - started };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("without a deadline the command runs as plain spawnSync", () => {
  assert.equal(remainingMs({}), undefined);
  const r = deadlineSpawnSync("sh", ["-c", "read x; echo got $x"], { encoding: "utf8", input: "in\n" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), "got in");
  assert.equal(r.timedOut, undefined);
});

test("under a deadline output, input and status pass through", () => {
  const before = process.env[DEADLINE_ENV];
  process.env[DEADLINE_ENV] = String(Date.now() + 10_000);
  try {
    const r = deadlineSpawnSync("sh", ["-c", "read x; echo got $x; echo err >&2; exit 3"], { encoding: "utf8", input: "in\n" });
    assert.deepEqual({ status: r.status, stdout: r.stdout.trim(), stderr: r.stderr.trim(), timedOut: r.timedOut }, { status: 3, stdout: "got in", stderr: "err", timedOut: false });
  } finally {
    if (before === undefined) delete process.env[DEADLINE_ENV];
    else process.env[DEADLINE_ENV] = before;
  }
});

test("a deadline already past runs nothing", () => {
  const before = process.env[DEADLINE_ENV];
  const m = marker();
  process.env[DEADLINE_ENV] = String(Date.now() - 1);
  try {
    const r = deadlineSpawnSync("sh", ["-c", `sleep ${m}`], { encoding: "utf8" });
    assert.equal(r.timedOut, true);
    assert.equal(r.status, null);
    assert.deepEqual(running(`sleep ${m}`), []);
  } finally {
    if (before === undefined) delete process.env[DEADLINE_ENV];
    else process.env[DEADLINE_ENV] = before;
  }
});

test("at the deadline the whole group ends, a grandchild that ignores SIGTERM included", async () => {
  const m = marker();
  try {
    // The parent honours SIGTERM; its child ignores it.
    const r = throughWrapper(`(trap "" TERM; exec sleep ${m}) & sleep ${m}; wait`, 800);
    assert.equal(r.timedOut, true);
    assert.ok(r.took < 800 + GRACE_MS + 3000, `returned after ${r.took} ms`);
    await sleep(200);
    assert.deepEqual(running(`sleep ${m}`), [], "a process outlived the deadline");
  } finally {
    for (const pid of running(`sleep ${m}`)) process.kill(pid, "SIGKILL");
  }
});

test("a command that exits early takes what it left behind with it, and did not time out", async () => {
  const m = marker();
  try {
    const r = throughWrapper(`sleep ${m} & echo done`, 10_000);
    assert.equal(r.timedOut, false);
    assert.equal(r.status, 0);
    assert.equal(r.stdout.trim(), "done");
    assert.ok(r.took < 5000, `returned after ${r.took} ms`);
    await sleep(200);
    assert.deepEqual(running(`sleep ${m}`), [], "a process outlived the call");
  } finally {
    for (const pid of running(`sleep ${m}`)) process.kill(pid, "SIGKILL");
  }
});
