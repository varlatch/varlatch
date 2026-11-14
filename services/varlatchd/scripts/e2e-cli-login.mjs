#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
import { cliPath as cliUnderTest, reporter } from "../../../scripts/conformance/suite-kit.mjs";
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
// The CLI under test (VARLATCH_CLI), set by scripts/conformance/run.mjs.
const cliPath = cliUnderTest();
const { check, finish } = reporter();

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
{
  const status = await page.textContent("#status");
  if (!check("cli-login.recovery-passkey-enrolled", "recovery passkey enrolled", /API credential/.test(status), /API credential/.test(status) ? "" : status)) finish();
}

// 2. Run `varlatch login` (no --token) and capture its callback URL.
const home = mkdtempSync(join(tmpdir(), "varlatch-login-e2e-"));
// The human's browser handoff: VARLATCH_ASSISTED=0, as in the strict-run
// E2E, so a coding agent's marker in the host shell does not switch on
// assisted mode, where login starts a device sign-in instead (ADR-0043).
const cli = spawn("node", [cliPath, "login", "--server", base], {
  env: { ...process.env, VARLATCH_ASSISTED: "0", VARLATCH_CONFIG_DIR: home, DISPLAY: "" },
});
let out = "";
cli.stdout.on("data", (d) => (out += d.toString()));
cli.stderr.on("data", (d) => (out += d.toString()));
const loginUrl = await new Promise((resolve) => {
  const deadline = Date.now() + 10000;
  const poll = () => {
    const m = out.match(/http:\/\/[^\s]+\/enroll\?callback=[^\s]+/);
    if (m) resolve(m[0]);
    else if (Date.now() > deadline) resolve(null);
    else setTimeout(poll, 100);
  };
  poll();
});
if (!check("cli-login.cli-printed-handoff-url", "CLI printed handoff URL", loginUrl !== null, loginUrl ? "" : out)) {
  cli.kill();
  await browser.close();
  finish();
}

// 3. Complete sign-in in the browser; the page posts the bearer to the CLI.
await page.goto(loginUrl);
await page.click("#signin");
await page.waitForFunction(
  () => /terminal|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
const status = await page.textContent("#status");
if (!check("cli-login.browser-delivered-credential-cli-callback", "browser delivered the credential to the CLI callback", /terminal/.test(status), /terminal/.test(status) ? "" : `browser handoff: ${status}`)) {
  cli.kill();
  await browser.close();
  finish();
}

const code = await new Promise((resolve) => cli.on("exit", resolve));
const completed = code === 0 && /Logged in to/.test(out);
check("cli-login.login-completed", "varlatch login completed", completed, completed ? out.trim().split("\n").pop() : `CLI exit ${code}: ${out}`);

await browser.close();
finish();
