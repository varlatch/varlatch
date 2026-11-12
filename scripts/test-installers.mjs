#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// The install scripts an installation serves (ADR-0058 Decision 3), checked
// where they run:
//
//   node scripts/test-installers.mjs shellcheck   install.sh through shellcheck (POSIX sh)
//   node scripts/test-installers.mjs windows      install.ps1 in PowerShell, on Windows
//
// The Windows run serves a stand-in CLI on 127.0.0.1 (loopback http:, as a
// local trial does), with LOCALAPPDATA in a temporary directory, and checks
// what each case leaves behind: a fresh install, a rerun, the user PATH (its
// other entries kept, the directory added once), a different copy it may not
// replace without an answer, and a download that does not match its SHA-256.
// It changes the runner user's PATH in the registry: run it on a CI runner.
// Node 22.18 or newer: it imports the TypeScript source directly.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installPs1, installSh } from "../services/varlatchd/src/http/cliDownload.ts";

const VERSION = "0.99.0";
const CLI = Buffer.from(`console.log(${JSON.stringify(`varlatch ${VERSION} (migration 1)`)})\n`);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failures.push(what);
};

const mode = process.argv[2];
const work = mkdtempSync(join(tmpdir(), "varlatch-installers-"));

if (mode === "shellcheck") {
  for (const loopbackHttp of [false, true]) {
    const origin = loopbackHttp ? "http://localhost:8787" : "https://vault.example.com";
    const file = join(work, `install-${loopbackHttp ? "local" : "https"}.sh`);
    writeFileSync(file, installSh({ file: CLI, sha256: sha(CLI), version: VERSION, origin, loopbackHttp }));
    const r = spawnSync("shellcheck", ["--shell=sh", "--severity=style", file], { encoding: "utf8" });
    if (r.error) throw r.error;
    process.stdout.write(r.stdout);
    check(r.status === 0, `shellcheck ${origin}`);
  }
} else if (mode === "windows") {
  if (process.platform !== "win32") throw new Error("the windows check runs on Windows");
  let body = CLI;
  const server = createServer((req, res) => {
    if (req.url === "/cli/varlatch.cjs") {
      res.writeHead(200);
      res.end(body);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const script = join(work, "install.ps1");
  writeFileSync(script, installPs1({ file: CLI, sha256: sha(CLI), version: VERSION, origin, loopbackHttp: true }));
  const appData = join(work, "LocalAppData");
  mkdirSync(appData);
  const dir = join(appData, "Programs", "Varlatch");
  const target = join(dir, "varlatch.cjs");

  const pwsh = (code) =>
    new Promise((resolve) => {
      // Async: the server above answers from this process.
      import("node:child_process").then(({ spawn }) => {
        const child = spawn("pwsh", ["-NoProfile", "-NonInteractive", "-Command", code], { env: { ...process.env, LOCALAPPDATA: appData } });
        let out = "";
        child.stdout.on("data", (d) => (out += d));
        child.stderr.on("data", (d) => (out += d));
        child.on("close", (status) => resolve({ status, out }));
      });
    });
  const userPath = async () => (await pwsh("[Environment]::GetEnvironmentVariable('Path', 'User')")).out.trim();
  // As a person runs it: irm <address>/install.ps1 | iex.
  const run = () => pwsh(`Get-Content -Raw '${script}' | Invoke-Expression`);

  const before = await userPath();
  const seeded = `${before};C:\\varlatch-test\\keep-me`;
  await pwsh(`[Environment]::SetEnvironmentVariable('Path', '${seeded.replace(/'/g, "''")}', 'User')`);
  try {
    const first = await run();
    console.log(first.out);
    check(first.status === 0, "a fresh install succeeds");
    check(existsSync(target) && readFileSync(target).equals(CLI), "the checked file is installed");
    check(readFileSync(join(dir, "varlatch.cmd"), "utf8").trim() === '@node "%~dp0varlatch.cjs" %*', "the varlatch.cmd shim is written");
    const afterFirst = (await userPath()).split(";");
    check(afterFirst.filter((e) => e.toLowerCase() === dir.toLowerCase()).length === 1, "the user PATH gains the directory once");
    check(afterFirst.includes("C:\\varlatch-test\\keep-me"), "the user PATH keeps its other entries");
    check(first.out.includes(`Next: varlatch login --server ${origin}`), "it names the next step");

    const second = await run();
    check(second.status === 0 && second.out.includes(`varlatch ${VERSION} is already installed`), "a rerun changes nothing");
    check((await userPath()).split(";").filter((e) => e.toLowerCase() === dir.toLowerCase()).length === 1, "a rerun adds no second PATH entry");

    writeFileSync(target, "console.log('varlatch 0.1.0 (migration 1)')\n");
    const refused = await run();
    check(refused.status !== 0 && refused.out.includes("replacing it needs your answer in an interactive window"), "a different copy is not replaced without an answer");
    check(readFileSync(target, "utf8").includes("0.1.0"), "the different copy is left as it was");

    rmSync(target);
    body = Buffer.from("console.log('something else')\n");
    const mismatch = await run();
    check(mismatch.status !== 0 && mismatch.out.includes("does not match its SHA-256"), "a mismatching download fails");
    check(!existsSync(target), "nothing is installed after a mismatch");
  } finally {
    await pwsh(`[Environment]::SetEnvironmentVariable('Path', '${before.replace(/'/g, "''")}', 'User')`);
    server.close();
  }
} else {
  console.error("Usage: node scripts/test-installers.mjs shellcheck|windows");
  process.exit(64);
}

rmSync(work, { recursive: true, force: true });
if (failures.length > 0) {
  console.error(`${failures.length} check(s) failed`);
  process.exit(1);
}
