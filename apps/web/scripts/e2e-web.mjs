#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live dashboard E2E: enroll a passkey through the dashboard origin, then
 * verify the two-backend client — /v1 views (orgs, projects, environments,
 * validation) and the reactive Convex audit mirror. Usage:
 *   node scripts/e2e-web.mjs <enroll-url-on-dashboard-origin>
 */
import { chromium } from "playwright";

const enrollUrl = process.argv[2];
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-web.mjs <http://localhost:5173/enroll#vlt_...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;

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
let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};
page.on("console", (m) => {
  if (m.type() === "error") console.log(`  [browser] ${m.text().slice(0, 160)}`);
});

// 1. Enroll on the dashboard origin (session cookie lands first-party).
await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
check("enrollment on dashboard origin", /API credential/.test(await page.textContent("#status")));

// 2. The app resumes the session and redirects into the org shell.
await page.goto(`${base}/`);
await page.waitForSelector('[data-testid="whoami"]', { timeout: 20000 });
// The footer shows the profile display name; the identity id lives in `title`.
check("session resume + whoami", /Signed in as idn_/.test(await page.getAttribute('[data-testid="whoami"]', "title")));
check("org deep link route", /\/o\/.+\/projects/.test(page.url()), page.url());
await page.waitForSelector('[data-testid="org-switcher"]', { timeout: 10000 });
const orgName = await page.textContent('[data-testid="org-switcher"] option');
check("org switcher renders", Boolean(orgName), orgName ?? "");
await page.waitForSelector("table td", { timeout: 10000 });

// 3. Validation button drives POST /v1 :validate (wait out the env fetch).
const validateButton = page.locator("button", { hasText: "validate" }).first();
try {
  await validateButton.waitFor({ timeout: 15000 });
  await validateButton.click();
  await page.waitForSelector(".allow, .deny", { timeout: 10000 });
  check("environment validation renders a verdict", true);
} catch (err) {
  check("environment validation renders a verdict", false, String(err).slice(0, 80));
}

// 4. The reactive audit feed populates from the Convex mirror (Audit route).
await page.click('a[href$="/audit"]');
await page.waitForSelector('[data-testid="audit-feed"] tbody tr', { timeout: 30000 });
const rows = await page.locator('[data-testid="audit-feed"] tbody tr').count();
check("reactive audit mirror shows events", rows > 0, `${rows} rows`);

await browser.close();
process.exit(failed ? 1 : 0);
