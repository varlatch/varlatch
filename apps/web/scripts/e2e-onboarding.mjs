#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Onboarding E2E: the getting-started checklist derives every checkmark from
 * authoritative /v1 state (design R2 §Onboarding) — steps check off as the
 * project/contract/environments/values appear, git-vs-managed branches the
 * instructions, and the card disappears on its own once the required loop is
 * complete (solo org = complete; recommended steps never keep it alive).
 * Usage: e2e-onboarding.mjs <enroll-url> <api-token>
 */
import { chromium } from "playwright";
import { watchCsp } from "./e2e-csp.mjs";

const [enrollUrl, apiToken] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !apiToken) {
  console.error("Usage: e2e-onboarding.mjs <enroll-url> <api-token>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;

const api = (method, path, body) =>
  fetch(`${base}/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

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
let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};
page.on("console", (m) => {
  if (m.type() === "error") console.log(`  [browser] ${m.text().slice(0, 140)}`);
});

// A fresh org so the checklist starts from zero (acme is fully onboarded).
const mkOrg = await api("POST", "/organizations", { name: "Onboard Co", slug: "onboard-co" });
check("fresh org seeded", mkOrg.status === 201, `status ${mkOrg.status}`);

await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);

// 1. Fresh org: the getting-started steps replace the empty list, all four
//    required steps pending.
await page.goto(`${base}/o/onboard-co/projects`);
await page.waitForSelector('[data-testid="onboarding"]', { timeout: 20000 });
const pending = await page
  .locator('[data-testid^="onboarding-"][data-done="false"]')
  .evaluateAll((els) => els.map((e) => e.dataset.testid));
check(
  "fresh org shows all required steps pending",
  ["project", "contract", "environments", "values"].every((s) =>
    pending.includes(`onboarding-${s}`),
  ),
  pending.join(","),
);
check(
  "progress derives 0 of 4",
  (await page.textContent('[data-testid="onboarding-progress"]')) === "0 of 4",
);
check(
  "workload + invite are recommended, not required",
  (await page.locator('[data-testid="onboarding-recommended"] [data-testid="onboarding-workload"]').count()) === 1 &&
    (await page.locator('[data-testid="onboarding-recommended"] [data-testid="onboarding-invite"]').count()) === 1,
);
check("no empty project list", (await page.locator('[data-testid="project-row"]').count()) === 0);

// 2. Create a git-authority project through the New project dialog, with no
//    environments yet: the project step checks off live, the page stays.
await page.click('[data-testid="onboarding-new-project"]');
await page.waitForSelector('[data-testid="new-project-dialog"]', { timeout: 5000 });
await page.fill('[data-testid="new-project-slug"]', "web");
check(
  "git is the default contract location",
  (await page.getAttribute('[data-testid="contract-authority-git"]', "aria-checked")) === "true",
);
for (const tier of ["development", "staging", "production"]) {
  await page.click(`[data-testid="new-project-env-${tier}"]`);
}
await page.click('[data-testid="create-project"]');
await page.waitForSelector('[data-testid="onboarding-project"][data-done="true"]', {
  timeout: 15000,
});
check("project step checks off from authoritative state", true);
check(
  "environments step still pending (all environment toggles were off)",
  (await page.getAttribute('[data-testid="onboarding-environments"]', "data-done")) === "false",
);
const contractStep = await page.textContent('[data-testid="onboarding-contract"]');
check(
  "git authority branches to CLI contract push snippet",
  contractStep.includes("contract push --schema"),
  contractStep.slice(0, 80),
);

// 3. "Create all three" on the environments step: it checks off live.
await page.click('[data-testid="onboarding-create-environments"]');
await page.waitForSelector('[data-testid="onboarding-environments"][data-done="true"]', {
  timeout: 15000,
});
check("environments step checks off from authoritative state", true);
await page.waitForSelector('[data-testid="project-row"][data-slug="web"] [data-env="production"]', { timeout: 15000 });
check("the project row lists the new environments", true);

// 3b. Another environment from the row's "…" menu.
await page.click('[data-testid="project-row"][data-slug="web"] [data-testid="project-menu"]');
await page.click('[data-testid="menu-new-environment"]');
await page.fill('[data-testid="new-environment-name"]', "qa");
await page.click('[data-testid="create-environment"]');
await page.waitForSelector('[data-testid="project-row"][data-slug="web"] [data-env="qa"]', { timeout: 15000 });
check("new environment from the project menu", true);

// 3c. Rename the display name through the same menu; the slug stays.
await page.click('[data-testid="project-row"][data-slug="web"] [data-testid="project-menu"]');
await page.click('[data-testid="menu-rename-project"]');
await page.fill('[data-testid="prompt-input"]', "Web storefront");
await page.click('[data-testid="prompt-ok"]');
await page.waitForSelector('[data-testid="project-row"][data-slug="web"] >> text=Web storefront', {
  timeout: 15000,
});
check("rename from the project menu shows the new display name", true);

// 4. Contract push + activate via /v1 (the CLI path the snippet teaches).
const rev = await (
  await api("POST", "/organizations/onboard-co/projects/web/contract/revisions", {
    contract: {
      schemaVersion: 1,
      items: [{ name: "DATABASE_URL", required: { kind: "always" }, sensitive: true, type: "url" }],
    },
  })
).json();
await api(
  "POST",
  `/organizations/onboard-co/projects/web/contract/revisions/${rev.id}/activate`,
  {},
);
await page.reload();
await page.waitForSelector('[data-testid="onboarding-contract"][data-done="true"]', {
  timeout: 15000,
});
check(
  "contract step checks off after push+activate",
  (await page.textContent('[data-testid="onboarding-progress"]')) === "3 of 4",
);

// 5. First value completes the required loop — the card removes itself
//    (solo org, no machine identity: recommended steps never block).
await api("PUT", "/organizations/onboard-co/projects/web/environments/development/values/DATABASE_URL", {
  value: "postgres://onboard-db",
});
await page.reload();
await page.waitForSelector('[data-testid="project-row"]', { timeout: 15000 });
await page
  .waitForSelector('[data-testid="onboarding"]', { state: "detached", timeout: 15000 })
  .catch(() => {});
check(
  "completed solo org hides the checklist",
  (await page.locator('[data-testid="onboarding"]').count()) === 0,
);
check(
  "projects page still renders normally",
  (await page.locator('[data-testid="project-row"][data-slug="web"]').count()) === 1 &&
    (await page.locator('[data-testid="project-filter"]').count()) === 1,
);

check("no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
await browser.close();
process.exit(failed ? 1 : 0);
