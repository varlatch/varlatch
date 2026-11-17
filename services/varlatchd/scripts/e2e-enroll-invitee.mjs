#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Enrolls an invited person on the server's own enroll page, in a real
 * browser with a CDP virtual authenticator (as e2e-passkey.mjs does), and
 * writes the short-lived API credential the page shows, for a suite that
 * needs a second person (scripts/conformance/suites/deletion.mjs: a second
 * admin approves an Organization's deletion). Usage:
 *
 *   node services/varlatchd/scripts/e2e-enroll-invitee.mjs <origin>/enroll#<invitation token> <name> <file>
 *
 * Writes the credential to <file> (mode 0600), never to the output, which
 * masks tokens; exits 1 with the page's status when the enrollment fails.
 */
import { writeFileSync } from "node:fs";
import { chromium } from "playwright";

const [enrollUrl, name, out] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !name || !out) {
  console.error("Usage: e2e-enroll-invitee.mjs <http://.../enroll#vlt_invite_...> <name> <file>");
  process.exit(64);
}

const browser = await chromium.launch();
try {
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
  await page.goto(enrollUrl);
  await page.fill("#name", name);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
  const status = await page.textContent("#status");
  const token = status.match(/vlt_web_[A-Za-z0-9_-]+/)?.[0];
  if (!token) {
    console.error(`the enrollment did not complete: ${status.split("\n")[0]}`);
    process.exitCode = 1;
  } else {
    writeFileSync(out, token, { mode: 0o600 });
  }
} finally {
  await browser.close();
}
