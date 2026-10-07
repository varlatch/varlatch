#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Live E2E for the CLI browser-handoff login (ADR-0017): enrolls a passkey
 * via a recovery grant, then drives `varlatch login` end to end — CLI opens
 * a loopback callback, browser signs in with the passkey, CLI receives the
 * bearer. Usage: node scripts/e2e-cli-login.mjs <recovery-enroll-url>
 */
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const enrollUrl = process.argv[2];
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-cli-login.mjs <http://.../enroll#vlt_setup_...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
const cliPath = new URL("../../../apps/cli/dist/main.js", import.meta.url).pathname;

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

// 1. Enroll the passkey (recovery re-enrollment).
await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
if (!/API credential/.test(await page.textContent("#status"))) {
  console.error("FAIL  enrollment: " + (await page.textContent("#status")));
  process.exit(1);
}
console.log("PASS  recovery passkey enrolled");

// 2. Run `varlatch login` (no --token) and capture its callback URL.
const home = mkdtempSync(join(tmpdir(), "varlatch-login-e2e-"));
const cli = spawn("node", [cliPath, "login", "--server", base], {
  env: { ...process.env, VARLATCH_CONFIG_DIR: home, DISPLAY: "" },
});
let out = "";
cli.stdout.on("data", (d) => (out += d.toString()));
cli.stderr.on("data", (d) => (out += d.toString()));
const loginUrl = await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error("no login URL printed")), 10000);
  const check = () => {
    const m = out.match(/http:\/\/[^\s]+\/enroll\?callback=[^\s]+/);
    if (m) {
      clearTimeout(t);
      resolve(m[0]);
    } else setTimeout(check, 100);
  };
  check();
});
console.log("PASS  CLI printed handoff URL");

// 3. Complete sign-in in the browser; the page posts the bearer to the CLI.
await page.goto(loginUrl);
await page.click("#signin");
await page.waitForFunction(
  () => /terminal|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
const status = await page.textContent("#status");
if (!/terminal/.test(status)) {
  console.error("FAIL  browser handoff: " + status);
  process.exit(1);
}
console.log("PASS  browser delivered the credential to the CLI callback");

const code = await new Promise((resolve) => cli.on("exit", resolve));
if (code !== 0 || !/Logged in to/.test(out)) {
  console.error(`FAIL  CLI exit ${code}: ${out}`);
  process.exit(1);
}
console.log("PASS  varlatch login completed: " + out.trim().split("\n").pop());

await browser.close();
