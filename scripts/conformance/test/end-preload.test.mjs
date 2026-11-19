// SPDX-License-Identifier: Apache-2.0
/**
 * The end-of-suite preload (lib/end-preload.mjs) outside and inside the
 * runner's arrangement: it reads and closes fd 4 only when the runner says
 * it opened it (CONFORMANCE_NONCE_FD=4) and fd 4 is a socket; anywhere else
 * it leaves fd 4 alone and the nonce empty. Run by hand, it used to close
 * one of Node's own fds and abort.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const PRELOAD = new URL("../lib/end-preload.mjs", import.meta.url).href;
const CHANNEL = new URL("../lib/end-channel.mjs", import.meta.url).href;
// Prints the nonce the preload left, and whether fd 4 is still open.
const SHOW = `const fs = require("fs");
let open = true; try { fs.fstatSync(4); } catch { open = false; }
import(${JSON.stringify(CHANNEL)}).then((m) => console.log(JSON.stringify({ nonce: m.endNonce(), fd4: open, flag: process.env.CONFORMANCE_NONCE_FD ?? null })));`;

const env = () => {
  const out = { ...process.env };
  delete out.CONFORMANCE_NONCE_FD;
  return out;
};

test("run by hand, the preload leaves Node's own fd 4 alone and the nonce empty", () => {
  const r = spawnSync(process.execPath, ["--import", PRELOAD, "-e", SHOW], { encoding: "utf8", env: env() });
  assert.equal(r.signal, null, r.stderr);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), { nonce: "", fd4: true, flag: null });
});

test("with the runner's flag but fd 4 not a socket, the preload leaves it alone", () => {
  const dir = mkdtempSync(join(tmpdir(), "end-preload-"));
  try {
    const file = join(dir, "not-a-socket");
    writeFileSync(file, "0123456789abcdef0123456789abcdef");
    const fd = openSync(file, "r");
    try {
      const r = spawnSync(process.execPath, ["--import", PRELOAD, "-e", SHOW], {
        encoding: "utf8",
        env: { ...env(), CONFORMANCE_NONCE_FD: "4" },
        stdio: ["ignore", "pipe", "pipe", "ignore", fd],
      });
      assert.equal(r.status, 0, r.stderr);
      // The flag is gone, the file was neither read as a nonce nor closed.
      assert.deepEqual(JSON.parse(r.stdout), { nonce: "", fd4: true, flag: null });
    } finally {
      closeSync(fd);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("as the runner starts it (the flag, fd 4 a socket), the preload reads the nonce", async () => {
  const nonce = "0123456789abcdef0123456789abcdef";
  const child = spawn(process.execPath, ["--import", PRELOAD, "-e", SHOW], {
    env: { ...env(), CONFORMANCE_NONCE_FD: "4" },
    stdio: ["ignore", "pipe", "pipe", "ignore", "pipe"],
  });
  child.stdio[4].end(nonce);
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const code = await new Promise((ok) => child.on("close", ok));
  assert.equal(code, 0, err);
  const shown = JSON.parse(out);
  assert.equal(shown.nonce, nonce);
  assert.equal(shown.flag, null);
});
