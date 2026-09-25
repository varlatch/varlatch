#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * P2 values/matrix E2E (design R2 critical cases): matrix states, masked
 * Secrets, per-item audited reveal without over-disclosure, reveal-all,
 * blind overwrite, draft -> review -> production checkbox, and atomic
 * change-set conflict rejection.
 * Usage: e2e-values.mjs <enroll-url> <api-bearer-for-conflict-writes>
 */
import { chromium } from "playwright";

const [enrollUrl, apiToken] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !apiToken) {
  console.error("Usage: e2e-values.mjs <enroll-url> <api-token>");
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
  if (m.type() === "error") console.log(`  [browser] ${m.text().slice(0, 140)}`);
});

// Watch disclosure responses to prove no over-disclosure. The push must be
// synchronous with the response event: fetching the body first (res.json())
// costs an extra CDP round-trip, so the page can render the revealed value
// while the counter still lags — a race that flakes on slow CI runners.
const disclosures = [];
page.on("response", (res) => {
  if (res.url().includes("/disclosures") && res.status() === 200) {
    disclosures.push(res.json().catch(() => null));
  }
});
// Bounded wait for an expected count; event delivery is still asynchronous.
const untilDisclosures = async (n, ms = 5000) => {
  const t0 = Date.now();
  while (disclosures.length < n && Date.now() - t0 < ms) {
    await new Promise((r) => setTimeout(r, 50));
  }
};

// Enroll + land in the shell.
await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
await page.goto(`${base}/o/acme/p/api`);

// 1. Matrix states from contract + presence metadata.
await page.waitForSelector('[data-testid="matrix"]', { timeout: 20000 });
const cell = (sel) => page.locator(`[data-cell="${sel}"]`).count();
check("matrix: set cell", (await cell("DATABASE_URL:development:set")) === 1);
check("matrix: missing-required in production", (await cell("DATABASE_URL:production:missing_required")) === 1);
check("matrix: covered-by-default", (await cell("PORT:production:covered_by_default")) === 1);
check("matrix: unset-optional", (await cell("API_KEY:development:unset_optional")) === 1);

// 2. Editor: non-sensitive visible, Secret masked.
await page.goto(`${base}/o/acme/p/api/e/development`);
await page.waitForSelector('[data-testid="values-table"]', { timeout: 20000 });
await page.waitForSelector('[data-row="PORT"]');
check("non-sensitive value visible", (await page.textContent('[data-row="PORT"]')).includes("3000"));
check("secret masked by default", (await page.textContent('[data-row="DATABASE_URL"]')).includes("••••"));

// 3. Per-item reveal is audited and does not over-disclose.
await page.click('[data-testid="eye-DATABASE_URL"]');
await page.waitForFunction(
  () => document.querySelector('[data-row="DATABASE_URL"]')?.textContent.includes("postgres://"),
  null,
  { timeout: 10000 },
);
check("per-item reveal shows plaintext", true);
await untilDisclosures(1);
const firstDisclosure = await disclosures[0];
check(
  "reveal of one Secret discloses only that Secret",
  disclosures.length === 1 && firstDisclosure.items.length === 1 && firstDisclosure.items[0].name === "DATABASE_URL",
  JSON.stringify(firstDisclosure?.items.map((i) => i.name)),
);
check("disclosure notice shown", (await page.locator('[data-testid="disclosure-notice"]').count()) === 1);

// 4. Draft add + edit -> review -> atomic save.
await page.fill('[data-testid="add-name"]', "NEW_FLAG");
await page.fill('[data-testid="add-value"]', "on");
await page.click('[data-testid="add-item"]');
await page.click('[data-testid="edit-PORT"]');
await page.fill('[data-row="PORT"] textarea', "4000");
check("dirty bar counts drafts", (await page.textContent('[data-testid="dirty-count"]')).includes("2"));
await page.click('[data-testid="review-save"]');
await page.click('[data-testid="commit-changes"]');
await page.waitForFunction(
  () => document.querySelector('[data-row="PORT"]')?.textContent.includes("4000"),
  null,
  { timeout: 10000 },
);
check("change set committed (dev, no confirmation needed)", true);

// 5. Conflict: stale draft is rejected atomically.
await page.click('[data-testid="edit-PORT"]');
await page.fill('[data-row="PORT"] textarea', "5000");
// Concurrent writer bumps PORT via the API while the draft is open.
const bump = await fetch(`${base}/v1/organizations/acme/projects/api/environments/development/values/PORT`, {
  method: "PUT",
  headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
  body: JSON.stringify({ value: "9999" }),
});
check("concurrent writer succeeded", bump.ok);
await page.click('[data-testid="review-save"]');
await page.click('[data-testid="commit-changes"]');
await page.waitForSelector('[data-testid="editor-error"]', { timeout: 10000 });
const conflictText = await page.textContent('[data-testid="editor-error"]');
check("stale change set rejected with preserved draft", /Changed since review.*PORT/.test(conflictText), conflictText.slice(0, 60));
await page.waitForFunction(
  () => document.querySelector('[data-row="PORT"]')?.textContent.includes("edited"),
  null,
  { timeout: 5000 },
);
check("draft preserved after conflict", true);
await page.click('[data-row="PORT"] button[title="Revert draft"]');

// 5b. ${NAME} references: expanded display, ref chip, literal text on edit.
// PUBLIC_URL is contract-marked non-sensitive; uncontracted items default to
// sensitive and would be masked (never expanded) on this path.
const refPut = await fetch(
  `${base}/v1/organizations/acme/projects/api/environments/development/values/PUBLIC_URL`,
  {
    method: "PUT",
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ value: "http://localhost:${PORT}" }),
  },
);
check("reference value written", refPut.ok, `status ${refPut.status}`);
await page.reload();
await page.waitForSelector('[data-row="PUBLIC_URL"]', { timeout: 20000 });
check(
  "reference displays expanded with ref chip",
  (await page.textContent('[data-row="PUBLIC_URL"]')).includes("http://localhost:9999") &&
    (await page.locator('[data-testid="ref-PUBLIC_URL"]').count()) === 1,
);
await page.click('[data-testid="edit-PUBLIC_URL"]');
check(
  "editing shows the literal stored ${NAME}, not the expansion",
  (await page.inputValue('[data-row="PUBLIC_URL"] textarea')) === "http://localhost:${PORT}",
);
await page.keyboard.press("Escape");

// 5c. Dual-phase rotation (ADR-0027): overlap the old value with the new one.
const DEV_VALUES = "/v1/organizations/acme/projects/api/environments/development/values";
const apiJson = (path, method, body) =>
  fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
// API_KEY is a contract Secret; seed it in development so it renders.
await apiJson(`${DEV_VALUES}/API_KEY`, "PUT", { value: "key-v1" });
await page.reload();
await page.waitForSelector('[data-row="API_KEY"]', { timeout: 20000 });
await page.click('[data-testid="rotate-API_KEY"]');
await page.fill('[data-testid="rotate-value"]', "key-v2");
await page.click('[data-testid="confirm-rotate"]');
await page.waitForSelector('[data-testid="rotating-API_KEY"]', { timeout: 10000 });
check("rotating badge shown after begin", true);

const rotDisc = await (
  await apiJson(`/v1/organizations/acme/projects/api/environments/development/disclosures`, "POST", {
    items: ["API_KEY"],
  })
).json();
check(
  "disclosure returns the new primary and the retiring value",
  rotDisc.items[0].value === "key-v2" && rotDisc.items[0].retiring?.value === "key-v1",
  JSON.stringify(rotDisc.items[0]),
);

await page.click('[data-testid="complete-rotation-API_KEY"]');
await page.waitForFunction(
  () => !document.querySelector('[data-testid="rotating-API_KEY"]'),
  null,
  { timeout: 10000 },
);
const afterComplete = await (
  await apiJson(`/v1/organizations/acme/projects/api/environments/development/disclosures`, "POST", {
    items: ["API_KEY"],
  })
).json();
check("retiring value dropped after finishing rotation", afterComplete.items[0].retiring === undefined);
await apiJson(`${DEV_VALUES}/API_KEY`, "DELETE"); // cleanup

// 6. Blind overwrite of a Secret (no reveal) + production confirmation.
await page.goto(`${base}/o/acme/p/api/e/production`);
await page.waitForSelector('[data-testid="values-table"]', { timeout: 20000 });
await page.fill('[data-testid="add-name"]', "DATABASE_URL");
await page.fill('[data-testid="add-value"]', "postgres://prod-rotated");
await page.click('[data-testid="add-item"]');
await page.click('[data-testid="review-save"]');
const commitButton = page.locator('[data-testid="commit-changes"]');
check("production commit gated on checkbox", await commitButton.isDisabled());
await page.check('[data-testid="production-confirm"]');
await commitButton.click();
await page.waitForFunction(
  () => !document.querySelector('[data-testid="dirty-count"]'),
  null,
  { timeout: 10000 },
);
check("production save with explicit confirmation", true);
check("blind overwrite required no disclosure", disclosures.length === 1, `${disclosures.length} disclosures total`);

// 7. Reveal all (production) is a deliberate scope.
await page.click('[data-testid="reveal-all"]');
await page.waitForFunction(
  () => document.querySelector('[data-row="DATABASE_URL"]')?.textContent.includes("prod-rotated"),
  null,
  { timeout: 10000 },
);
await untilDisclosures(2);
check("reveal-all disclosed authorized secrets", disclosures.length === 2, `${disclosures.length} disclosure responses`);

await browser.close();
process.exit(failed ? 1 : 0);
