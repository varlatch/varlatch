// SPDX-License-Identifier: Apache-2.0
/**
 * A target operation's deadline (lib/deadline.mjs) stops the operation's
 * own child processes with theirs, so a bounded call leaves no orphan: a
 * wrapper (target-op.mjs) whose child (docker compose) started a child of
 * its own (the Compose plugin) all end by the deadline.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { DEADLINE_ENV, deadlineSpawnSync, remainingMs } from "../lib/deadline.mjs";

const DEADLINE = fileURLToPath(new URL("../lib/deadline.mjs", import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** The PIDs of processes whose command line holds `marker` (never this test's own). */
const running = (marker) => spawnSync("pgrep", ["-f", marker], { encoding: "utf8" }).stdout.split("\n").filter(Boolean).map(Number).filter((p) => p !== process.pid);

test("without a deadline the command runs as plain spawnSync", () => {
  assert.equal(remainingMs({}), undefined);
  const r = deadlineSpawnSync("sh", ["-c", "echo ok"], { encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), "ok");
  assert.equal(r.timedOut, undefined);
});

test("a wrapper's child and its grandchild end by the operation's deadline, leaving no orphan", async () => {
  const marker = `${31 + Math.random()}`.slice(0, 9); // a sleep length no other process uses
  const dir = mkdtempSync(join(tmpdir(), "deadline-test-"));
  try {
    // The wrapper, as target-op.mjs: its child (sh) starts a grandchild
    // (sleep, in the background) and waits, as the docker CLI waits for its
    // Compose plugin.
    const wrapper = join(dir, "wrapper.mjs");
    writeFileSync(wrapper, `import { deadlineSpawnSync } from ${JSON.stringify(DEADLINE)};
const r = deadlineSpawnSync("sh", ["-c", "sleep ${marker} & sleep ${marker}; wait"], { encoding: "utf8" });
process.stdout.write(JSON.stringify({ timedOut: r.timedOut, status: r.status }));
`);
    const started = Date.now();
    const r = spawnSync(process.execPath, [wrapper], {
      encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL",
      env: { ...process.env, [DEADLINE_ENV]: String(Date.now() + 800) },
    });
    const took = Date.now() - started;
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), { timedOut: true, status: 124 });
    assert.ok(took < 5000, `the wrapper returned after ${took} ms`);
    await sleep(200);
    assert.deepEqual(running(`sleep ${marker}`), [], "a child or grandchild outlived the deadline");
  } finally {
    for (const pid of running(`sleep ${marker}`)) process.kill(pid, "SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});
