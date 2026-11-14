#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Live dashboard E2E: enroll a passkey through the dashboard origin, then
 * verify the two-backend client — /v1 views (orgs, projects, environments,
 * environment health) and the reactive Convex audit mirror. Usage:
 *   node scripts/e2e-web.mjs <enroll-url-on-dashboard-origin>
 * Run by scripts/conformance/run.mjs; each check's ID is in
 * scripts/conformance/inventory.json.
 */
import { chromium } from "playwright";
import { reporter } from "../../../scripts/conformance/suite-kit.mjs";
import { watchCsp } from "./e2e-csp.mjs";

const enrollUrl = process.argv[2];
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-web.mjs <http://localhost:5173/enroll#vlt_...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;

const browser = await chromium.launch();
const context = await browser.newContext();
const cspViolations = watchCsp(context);
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
const { check, finish } = reporter();
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
check("dashboard.enrollment-dashboard-origin", "enrollment on dashboard origin", /API credential/.test(await page.textContent("#status")));
// ADR-0058 Decision 4: an invitation's next steps. This stack does not serve
// the CLI, so the verified route is offered and no install line is shown.
{
  const steps = await page.textContent("#status");
  check(
    "dashboard.invitation-shows-next-steps-install-sign", "invitation shows the next steps: install, sign in, run",
    /1\. Install the CLI/.test(steps) && /2\. Sign in from your terminal/.test(steps) && /varlatch run -- <your command>/.test(steps),
  );
  check("dashboard.without-cli-download-verified-route-no-install-sh", "without cli.download, the verified route and no install.sh", /Install it from its signed release/.test(steps) && !/install\.sh/.test(steps));
  check("dashboard.short-lived-credential-folded-away", "the short-lived credential is folded away", await page.$eval("#status details", (d) => !d.open && /API credential/.test(d.textContent)));
  // The target's own enroll page against its own /v1/meta: the install line
  // only when the server lists cli.download, the verified route otherwise.
  // (The page's handling of a failing or stalled /v1/meta is a component
  // check against a stub server: e2e-enroll-steps.mjs.)
  const meta = await fetch(`${base}/v1/meta`).then((r) => r.json(), () => null);
  const serving = Array.isArray(meta?.capabilities) && meta.capabilities.includes("cli.download");
  // The page shows the install line once its own /v1/meta request answers.
  if (serving) {
    await page.waitForFunction(() => /install\.sh/.test(document.getElementById("status").textContent), null, { timeout: 5000 }).catch(() => {});
  } else {
    await page.waitForTimeout(500);
  }
  const shown = await page.textContent("#status");
  const routeShown = serving
    ? shown.includes(`curl -fsSL ${base}/install.sh | sh`)
    : /Install it from its signed release/.test(shown) && !/install\.sh/.test(shown);
  check(
    "dashboard.enroll-steps-match-meta",
    "the enroll page's next steps match the server's /v1/meta",
    meta !== null && routeShown && shown.includes(`varlatch login --server ${base}`),
    `cli.download ${meta === null ? "unknown (no /v1/meta)" : serving ? "listed" : "not listed"}`,
  );
}

// 2. The app resumes the session and redirects into the org shell, under a
// strict Content-Security-Policy (ADR-0046 rollout step 4).
const shell = await page.goto(`${base}/`);
const csp = (await shell?.allHeaders())?.["content-security-policy"] ?? "";
// Judged once the session, the /v1 views and the audit feed (the realtime
// connection) have loaded, below.
const strictDirectives =
  ["default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"].every((d) => csp.includes(d)) &&
  !csp.includes("unsafe-inline") &&
  !csp.includes("unsafe-eval");
// The TypeScript stack's realtime backend (Convex) behind the dashboard's
// origin; the Go server has none, and dashboard.csp-strict covers its
// realtime connection.
check("dashboard.csp-connect-src-convex", "its connect-src names the Convex origin the dashboard uses", csp.includes(`connect-src 'self' ${base}`), csp);
await page.waitForSelector('[data-testid="whoami"]', { timeout: 20000 });
// The footer shows the profile display name; the identity id lives in `title`.
const resumed = check("dashboard.session-resume-whoami", "session resume + whoami", /Signed in as idn_/.test(await page.getAttribute('[data-testid="whoami"]', "title")));
check("dashboard.org-deep-link-route", "org deep link route", /\/o\/.+\/projects/.test(page.url()), page.url());
await page.waitForSelector('[data-testid="org-switcher-name"]', { timeout: 10000 });
// The menu button names the current organization once /v1 has answered.
const orgName = await page
  .waitForFunction(() => {
    const t = document.querySelector('[data-testid="org-switcher-name"]')?.textContent?.trim();
    return t && t !== "…" ? t : null;
  }, null, { timeout: 10000 })
  .then((h) => h.jsonValue(), () => null);
const v1Answered = check("dashboard.org-switcher-renders", "org switcher renders", Boolean(orgName), orgName ?? "");
await page.waitForSelector('[data-testid="project-row"]', { timeout: 10000 });

// 3. Each project row shows environment health from /v1 metadata (active
//    contract + effective configuration), without a click.
try {
  await page.waitForSelector('[data-testid="project-row"] [data-health="ok"], [data-testid="project-row"] [data-health="missing"]', {
    timeout: 15000,
  });
  check("dashboard.environment-health-renders-verdict", "environment health renders a verdict", true);
} catch (err) {
  check("dashboard.environment-health-renders-verdict", "environment health renders a verdict", false, String(err).slice(0, 80));
}

// 4. The reactive audit feed populates from the Convex mirror (Audit route).
await page.click('a[href$="/audit"]');
await page.waitForSelector('[data-testid="audit-feed"] [data-audit-row]', { timeout: 30000 });
const rows = await page.locator('[data-testid="audit-feed"] [data-audit-row]').count();
check("dashboard.audit-feed-shows-events", "reactive audit mirror shows events", rows > 0, `${rows} rows`);
check(
  "dashboard.csp-strict",
  "the dashboard is served with a strict Content-Security-Policy, and the session, the /v1 views and the audit feed load under it",
  strictDirectives && resumed && v1Answered && rows > 0 && cspViolations.length === 0,
  `${csp}${cspViolations.length > 0 ? ` | violations: ${cspViolations.slice(0, 3).join(" | ")}` : ""}`,
);

check("dashboard.no-content-security-policy-violations", "no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
await browser.close();
finish();
