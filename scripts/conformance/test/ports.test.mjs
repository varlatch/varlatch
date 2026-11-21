// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fixtureStatus } from "../lib/fixture-status.mjs";
import { ephemeralRange, FALLBACK_RANGE, pickRange, reservePort, reservePorts } from "../lib/ports.mjs";

test("the ephemeral range is read from the kernel, with Linux's default when it cannot be", () => {
  assert.deepEqual(ephemeralRange(() => "32768\t60999\n"), [32768, 60999]);
  assert.deepEqual(ephemeralRange(() => "1024 65535"), [1024, 65535]);
  assert.deepEqual(ephemeralRange(() => "nonsense"), [32768, 60999]);
  assert.deepEqual(
    ephemeralRange(() => {
      throw new Error("ENOENT");
    }),
    [32768, 60999],
  );
});

test("ports are picked below the ephemeral range, above the well-known services", () => {
  assert.deepEqual(pickRange([32768, 60999]), [20000, 32767]);
  // A range that starts low still leaves a band of ports above 1023.
  const [low, high] = pickRange([3000, 60999]);
  assert.ok(low >= 1024 && high === 2999 && low <= high);
  // No room below (an ephemeral range from 1025, or lower): the room above
  // it when there is some, else the fixed range; never low > high.
  assert.deepEqual(pickRange([1025, 60999]), [61000, 62999]);
  assert.deepEqual(pickRange([1024, 64000]), [64001, 65535]);
  assert.deepEqual(pickRange([1025, 65535]), FALLBACK_RANGE);
  assert.deepEqual(pickRange([600, 65000]), [65001, 65535]);
  assert.deepEqual(pickRange([600, 65535]), FALLBACK_RANGE);
  for (const range of [[1, 65535], [1025, 1025], [1200, 65535], [32768, 60999], [49152, 65535]]) {
    const [l, h] = pickRange(range);
    assert.ok(l >= 1024 && l <= h && h <= 65535, `${range}: [${l}, ${h}]`);
  }
});

test("reserved ports are free, below the ephemeral range and never the same twice", async () => {
  const [ephemeralLow] = ephemeralRange();
  const ports = await reservePorts(8);
  assert.equal(new Set(ports).size, 8);
  for (const port of ports) {
    assert.ok(port < ephemeralLow, `${port} is in the ephemeral range`);
    const server = createServer();
    await new Promise((ok, fail) => {
      server.once("error", fail);
      server.listen(port, "127.0.0.1", ok);
    });
    await new Promise((ok) => server.close(ok));
  }
});

test("a taken port is skipped", async () => {
  const held = createServer();
  await new Promise((ok) => held.listen(0, "127.0.0.1", ok));
  const taken = held.address().port;
  // Every candidate the first time is the held port; then a free one.
  let calls = 0;
  const free = await reservePort({ range: [taken, taken], tries: 3, random: () => (calls++, 0) });
  assert.notEqual(free, taken);
  await new Promise((ok) => held.close(ok));
});

test("a fixture that cannot listen says why in its log", async () => {
  const held = createServer();
  await new Promise((ok) => held.listen(0, "127.0.0.1", ok));
  const port = held.address().port;
  const dir = mkdtempSync(join(tmpdir(), "conformance-ports-"));
  const receiver = join(import.meta.dirname, "..", "lib", "webhook-receiver.cjs");
  const out = await new Promise((resolve) => {
    const child = spawn(process.execPath, [receiver, dir, String(port)], { stdio: ["ignore", "pipe", "pipe"] });
    let text = "";
    child.stdout.on("data", (d) => (text += d));
    child.stderr.on("data", (d) => (text += d));
    child.on("exit", (code) => resolve({ code, text }));
  });
  await new Promise((ok) => held.close(ok));
  assert.equal(out.code, 1);
  assert.match(out.text, new RegExp(`webhook-receiver: cannot listen on 127\\.0\\.0\\.1:${port}: EADDRINUSE`));
});

test("a fixture that did not start is said running only when it is", () => {
  assert.equal(fixtureStatus("exited 1", false, 30_000), "exited 1");
  assert.equal(fixtureStatus("killed by SIGKILL", true, 30_000), "killed by SIGKILL");
  assert.equal(fixtureStatus(null, true, 30_000), "still running after 30 s, its last probe not answered");
  assert.equal(fixtureStatus(null, false, 30_000), "no longer running, its exit not seen");
});
