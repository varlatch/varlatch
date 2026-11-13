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
// other entries kept, %VARIABLE% entries unexpanded, its registry kind kept,
// the directory added once, nothing left from the change notice), a different
// copy it may not replace without an answer, and a download that does not
// match its SHA-256. It changes the runner user's PATH in the registry
// (restored, value and kind, afterwards): run it on a CI runner.
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

/** One PowerShell run, async (the stub server answers from this process); `stdin` answers Read-Host. */
function shell(exe, appData, code, { stdin = "", interactive = false, env: extra = {} } = {}) {
  return new Promise((resolve) => {
    import("node:child_process").then(({ spawn }) => {
      const args = ["-NoProfile", ...(interactive ? [] : ["-NonInteractive"]), "-Command", code];
      // Each PowerShell with its own module path: one started from the other
      // (CI steps run under pwsh) would otherwise inherit the wrong one.
      const env = { ...process.env, ...extra, LOCALAPPDATA: appData };
      delete env.PSModulePath;
      const child = spawn(exe, args, { env });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (out += d));
      child.on("close", (status) => resolve({ status, out }));
      child.stdin.end(stdin);
    });
  });
}

// The user PATH as the registry stores it: "<kind>|<value>", %VARIABLES%
// unexpanded ("None|" when there is none), and written back the same way.
const READ_PATH =
  "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment'); " +
  "if ($k.GetValueNames() -contains 'Path') { '{0}|{1}' -f $k.GetValueKind('Path'), $k.GetValue('Path', '', 'DoNotExpandEnvironmentNames') } else { 'None|' }";
const WRITE_PATH =
  "$k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); " +
  "if ($env:VARLATCH_PATH_KIND -eq 'None') { $k.DeleteValue('Path', $false) } else { $k.SetValue('Path', $env:VARLATCH_PATH_VALUE, $env:VARLATCH_PATH_KIND) }";
// The user variables named like the installer's change notice, listed and
// removed.
const REFRESH_VARS =
  "$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment'); " +
  "($k.GetValueNames() | Where-Object { $_ -like 'VARLATCH_INSTALL_REFRESH*' } | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $k.GetValue($_) }) -join ';'";
const DELETE_REFRESH_VARS =
  "$k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment'); " +
  "$k.GetValueNames() | Where-Object { $_ -like 'VARLATCH_INSTALL_REFRESH*' } | ForEach-Object { $k.DeleteValue($_) }";
const rawPath = async (exe, appData) => {
  const [kind, ...rest] = (await shell(exe, appData, READ_PATH)).out.trim().split("|");
  return { kind, value: rest.join("|") };
};
const writePath = (exe, appData, { kind, value }) =>
  shell(exe, appData, WRITE_PATH, { env: { VARLATCH_PATH_KIND: kind, VARLATCH_PATH_VALUE: value } });

async function windowsCases(exe, origin, script, serveBody, kind) {
  const appData = join(work, `LocalAppData-${exe}`);
  mkdirSync(appData);
  const dir = join(appData, "Programs", "Varlatch");
  const target = join(dir, "varlatch.cjs");
  const shim = join(dir, "varlatch.cmd");
  const userPath = async () => (await rawPath(exe, appData)).value;
  // As a person runs it: irm <address>/install.ps1 | iex.
  const iex = `Get-Content -Raw '${script}' | Invoke-Expression`;
  const run = (opts) => shell(exe, appData, iex, opts);
  const named = (what) => `${exe}: ${what}`;
  serveBody(CLI);

  // A %VARIABLE% entry (which must stay unexpanded) and a plain one, stored
  // as the given kind; and a user variable named like the change notice.
  // The variable is one Windows always defines: an undefined one stays as
  // written when expanded, so its loss would not show. Expanding when read
  // only happens to REG_EXPAND_SZ, so the 5.1 round is the one that would
  // catch the old expand-and-write-back; the 7 round checks REG_SZ is kept.
  const varEntry = "%SystemRoot%\\varlatch-test\\bin";
  const before = await userPath();
  await writePath(exe, appData, { kind, value: [before, "C:\\varlatch-test\\keep-me", varEntry].filter(Boolean).join(";") });
  await shell(exe, appData, "[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment').SetValue('VARLATCH_INSTALL_REFRESH', 'the user''s own')");

  const first = await run();
  console.log(first.out);
  check(first.status === 0, named("a fresh install succeeds"));
  check(existsSync(target) && readFileSync(target).equals(CLI), named("the checked file is installed"));
  check(readFileSync(shim, "utf8").trim() === '@node "%~dp0varlatch.cjs" %*', named("the varlatch.cmd shim is written"));
  const raw = await rawPath(exe, appData);
  const afterFirst = raw.value.split(";");
  check(afterFirst.filter((e) => e.toLowerCase() === dir.toLowerCase()).length === 1, named("the user PATH gains the directory once"));
  check(afterFirst.includes("C:\\varlatch-test\\keep-me"), named("the user PATH keeps its other entries"));
  check(afterFirst.includes(varEntry), named("the user PATH keeps a %VARIABLE% entry unexpanded"));
  check(raw.kind === kind, named(`the user PATH stays ${kind} (it is ${raw.kind})`));
  const refresh = (await shell(exe, appData, REFRESH_VARS)).out.trim();
  check(refresh === "VARLATCH_INSTALL_REFRESH=the user's own", named(`the change notice leaves no variable and keeps the user's (${refresh})`));
  await shell(exe, appData, DELETE_REFRESH_VARS);
  check(first.out.includes(`Next: varlatch login --server ${origin}`), named("it names the next step"));

  const second = await run();
  check(second.status === 0 && second.out.includes(`varlatch ${VERSION} is already installed`), named("a rerun changes nothing"));
  check((await userPath()).split(";").filter((e) => e.toLowerCase() === dir.toLowerCase()).length === 1, named("a rerun adds no second PATH entry"));

  if (kind === "ExpandString") {
    // Entries are compared expanded: the directory written with a variable
    // is already on the PATH, and nothing is added.
    const asVariable = afterFirst.map((e) => (e.toLowerCase() === dir.toLowerCase() ? "%LOCALAPPDATA%\\Programs\\Varlatch" : e)).join(";");
    await writePath(exe, appData, { kind, value: asVariable });
    const third = await run();
    const now = await rawPath(exe, appData);
    check(third.status === 0 && !third.out.includes("Added ") && now.value === asVariable && now.kind === kind, named("an entry written as %LOCALAPPDATA%\\Programs\\Varlatch counts: nothing is added"));
  }

  writeFileSync(shim, "@echo my own launcher\r\n");
  const shimRefused = await run();
  check(shimRefused.status !== 0 && shimRefused.out.includes("needs your answer in an interactive window"), named("a customized varlatch.cmd is not replaced without an answer"));
  check(readFileSync(shim, "utf8").includes("my own launcher"), named("the customized varlatch.cmd is left as it was"));
  writeFileSync(shim, '@node "%~dp0varlatch.cjs" %*\r\n');

  writeFileSync(target, "console.log('varlatch 0.1.0 (migration 1)')\n");
  const refused = await run();
  check(refused.status !== 0 && refused.out.includes("replacing it needs your answer in an interactive window"), named("a different copy is not replaced without an answer"));
  check(readFileSync(target, "utf8").includes("0.1.0"), named("the different copy is left as it was"));

  // Approved: the atomic replace ([IO.File]::Replace) runs and succeeds.
  const approved = await run({ interactive: true, stdin: "y\r\n" });
  console.log(approved.out);
  check(approved.status === 0 && approved.out.includes(`Installed varlatch ${VERSION}`), named("an approved replacement succeeds"));
  check(readFileSync(target).equals(CLI), named("the approved replacement installs the checked file"));
  check(!existsSync(join(dir, "varlatch.cjs.new")) && !existsSync(join(dir, "varlatch.cmd.new")), named("no staged file is left after a replacement"));

  rmSync(target);
  serveBody(Buffer.from("console.log('something else')\n"));
  const mismatch = await run();
  check(mismatch.status !== 0 && mismatch.out.includes("does not match its SHA-256"), named("a mismatching download fails"));
  check(!existsSync(target), named("nothing is installed after a mismatch"));
  check(!existsSync(join(dir, "varlatch.cjs.new")) && !existsSync(join(dir, "varlatch.cmd.new")), named("no staged file is left behind"));
  serveBody(CLI);
}

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
  const userPathBefore = await rawPath("pwsh", join(work, "unused"));
  if (!["ExpandString", "String", "None"].includes(userPathBefore.kind)) throw new Error(`reading the user PATH: ${userPathBefore.kind}`);
  if ((await shell("pwsh", join(work, "unused"), REFRESH_VARS)).out.trim() !== "") throw new Error("this machine already has VARLATCH_INSTALL_REFRESH variables");
  try {
    // Windows PowerShell 5.1 and PowerShell 7: the script must work in both;
    // the user PATH stored as REG_EXPAND_SZ (the usual kind) and as REG_SZ,
    // each round from the runner's own PATH.
    await windowsCases("powershell", origin, script, (b) => (body = b), "ExpandString");
    await writePath("pwsh", join(work, "unused"), userPathBefore);
    await windowsCases("pwsh", origin, script, (b) => (body = b), "String");
  } finally {
    await writePath("pwsh", join(work, "unused"), userPathBefore);
    await shell("pwsh", join(work, "unused"), DELETE_REFRESH_VARS);
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
