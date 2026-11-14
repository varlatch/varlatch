#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * CLI serving on (ADR-0058 Decision 3): with the server's serve-cli setting
 * on, /v1/meta lists cli.download, the install scripts name the server's
 * origin, and install.sh installs the CLI the server reports as its own
 * version, as a person would run it. Serving is turned off again at the end.
 *
 *   cli-download-on.mjs <origin>      (run by scripts/conformance/run.mjs)
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin] = process.argv.slice(2);
if (!origin) {
  console.error("Usage: cli-download-on.mjs <origin>");
  process.exit(64);
}
const { check, error, finish } = reporter();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const meta = () => fetch(`${origin}/v1/meta`).then((r) => (r.ok ? r.json() : null), () => null);
const listsDownload = (m) => Array.isArray(m?.capabilities) && m.capabilities.includes("cli.download");
const home = mkdtempSync(join(tmpdir(), "conformance-install-"));

try {
  targetOp("serve-cli", ["on"]);
  let served = null;
  for (let i = 0; i < 60; i++) {
    served = await meta();
    if (listsDownload(served)) break;
    await sleep(2000);
  }
  check("cli-download-on.meta-lists-cli-download", "/v1/meta lists cli.download with serving on", listsDownload(served));

  const fetchText = (path) => fetch(`${origin}${path}`).then(async (r) => (r.ok ? r.text() : null), () => null);
  const sh = await fetchText("/install.sh");
  check("cli-download-on.install-sh-names-origin", `install.sh names ${origin}`, sh !== null && sh.split("\n").includes(`ORIGIN='${origin}'`));
  const ps1 = await fetchText("/install.ps1");
  check("cli-download-on.install-ps1-names-origin", `install.ps1 names ${origin}`, ps1 !== null && ps1.includes(`$Origin = '${origin}'`));

  writeFileSync(join(home, "install.sh"), sh ?? "");
  const install = spawnSync("sh", [join(home, "install.sh")], { env: { ...process.env, HOME: home }, input: "", encoding: "utf8" });
  const output = `${install.stdout}${install.stderr}`;
  check("cli-download-on.install-sh-installs", "install.sh through the server installs the CLI", install.status === 0, output.trim().slice(-500));
  const version = spawnSync(join(home, ".local", "bin", "varlatch"), ["--version"], { encoding: "utf8" });
  const installed = (version.stdout ?? "").trim();
  check(
    "cli-download-on.installed-version-matches-server",
    "the installed CLI reports the server's own version",
    version.status === 0 && typeof served?.serverVersion === "string" && installed.startsWith(`varlatch ${served.serverVersion} `),
    `installed '${installed}', server ${served?.serverVersion ?? "unknown"}`,
  );
  check("cli-download-on.install-names-next-step", "install.sh names the next step", output.includes(`Next: varlatch login --server ${origin}`));
} catch (err) {
  error(`cli download on: ${err.message}`);
} finally {
  rmSync(home, { recursive: true, force: true });
  try {
    targetOp("serve-cli", ["off"]);
    let back = false;
    for (let i = 0; i < 60 && !(back = (await meta()) !== null); i++) await sleep(2000);
    if (!back) error("the server did not answer /v1/meta after serving was turned off");
  } catch (err) {
    error(`turning serving off: ${err.message}`);
  }
}
finish();
