#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live passkey E2E (ADR-0006/0008): drives the real enrollment page against
 * the running canonical stack with a CDP virtual authenticator. Usage:
 *   node scripts/e2e-passkey.mjs <enroll-url-with-#token>
 * Prints VERDICT lines; exits nonzero on failure.
 */
import { chromium } from "playwright";

const enrollUrl = process.argv[2];
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-passkey.mjs <http://.../enroll#vlt_setup_...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;

const browser = await chromium.launch();
let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};

async function newPageWithAuthenticator(context) {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { page, cdp, authenticatorId };
}

// ---- 0. An abandoned ceremony does not burn the token (issue #23). Starting
// registration (what a cancelled prompt or closed tab leaves behind) must not
// consume the grant; the same link must still enroll in step 1.
const setupToken = decodeURIComponent(new URL(enrollUrl).hash.slice(1));
const abandoned = await fetch(
  `${base}/auth/passkey/generate-register-options?context=${encodeURIComponent(setupToken)}`,
  { headers: { Origin: base } },
);
check("abandoned ceremony start is accepted", abandoned.status === 200, `status ${abandoned.status}`);

// ---- 1. Enrollment consumes the setup token and yields a working credential.
const context = await browser.newContext();
const { page, cdp, authenticatorId } = await newPageWithAuthenticator(context);
page.on("console", (m) => {
  if (m.type() === "error") console.log(`  [browser] ${m.text()}`);
});
await page.goto(enrollUrl);
await page.fill("#name", "Jeremy (e2e)");
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
const enrollStatus = await page.textContent("#status");
check("passkey enrollment completes", /API credential/.test(enrollStatus), enrollStatus.split("\n")[0]);

const enrollToken = enrollStatus.match(/vlt_web_[A-Za-z0-9_-]+/)?.[0];
check("exchange yields a browser bearer", Boolean(enrollToken));

const orgs = await fetch(`${base}/v1/organizations`, {
  headers: { Authorization: `Bearer ${enrollToken}` },
});
check("browser bearer authenticates /v1", orgs.status === 200, `status ${orgs.status}`);

// ---- 2. The setup token is single-use.
const replayContext = await browser.newContext();
const replay = await newPageWithAuthenticator(replayContext);
await replay.page.goto(enrollUrl);
await replay.page.click("#enroll");
await replay.page.waitForFunction(
  () => /failed|API credential/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
const replayStatus = await replay.page.textContent("#status");
check("setup token replay is rejected", /failed/i.test(replayStatus), replayStatus.split("\n")[0]);
await replayContext.close();

// ---- 3. Sign-in with the discoverable credential in a fresh session.
// Reuse the same authenticator (holds the resident key) but clear cookies.
await context.clearCookies();
await page.goto(`${base}/enroll`);
await page.click("#signin");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
const signinStatus = await page.textContent("#status");
check("passkey sign-in works with a discoverable credential", /API credential/.test(signinStatus), signinStatus.split("\n")[0]);
const signinToken = signinStatus.match(/vlt_web_[A-Za-z0-9_-]+/)?.[0];
if (signinToken) {
  const res = await fetch(`${base}/v1/organizations`, {
    headers: { Authorization: `Bearer ${signinToken}` },
  });
  check("sign-in bearer authenticates /v1", res.status === 200, `status ${res.status}`);
}

// ---- 4. Without the authenticator, sign-in cannot succeed silently.
const noAuthContext = await browser.newContext();
const bare = await noAuthContext.newPage();
await bare.goto(`${base}/enroll`);
await bare.click("#signin");
await bare.waitForFunction(
  () => /failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
).catch(() => {});
const bareStatus = await bare.textContent("#status");
check("sign-in without an authenticator fails", /failed/i.test(bareStatus), bareStatus.split("\n")[0]);
await noAuthContext.close();

void cdp;
void authenticatorId;
await browser.close();
process.exit(failed ? 1 : 0);
