#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Values E2E (design R2 critical cases) on the project values grid and the
 * environment page: cell states, non-secret values shown and Secrets masked,
 * audited reveals with requested sets (per column, per item, reveal-all and
 * the ?reveal=1 deep link) without over-disclosure, inline edits and the
 * add row -> review -> atomic save, production checkbox, blind overwrite,
 * change-set conflict rejection with drafts kept, references, dual-phase
 * rotation, non-secret .env export, and deleting an environment.
 * Usage: e2e-values.mjs <enroll-url> <api-bearer-for-conflict-writes>
 */
import { readFileSync } from "node:fs";
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
const disclosureRequests = [];
page.on("response", (res) => {
  if (res.url().includes("/disclosures") && res.status() === 200) {
    disclosures.push(res.json().catch(() => null));
  }
});
page.on("request", (req) => {
  if (req.url().includes("/disclosures") && req.method() === "POST") {
    disclosureRequests.push(JSON.parse(req.postData() ?? "{}"));
  }
});
// Bounded wait for an expected count; event delivery is still asynchronous.
const untilDisclosures = async (n, ms = 5000) => {
  const t0 = Date.now();
  while (disclosures.length < n && Date.now() - t0 < ms) {
    await new Promise((r) => setTimeout(r, 50));
  }
};


const apiJson = (path, method, body) =>
  fetch(`${base}${path}`, {
    method,
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
const API = "/v1/organizations/acme/projects/api";
const cellSel = (name, env, state) => `[data-cell="${name}:${env}:${state}"]`;
const cellText = async (name, env, state = "set") => (await page.textContent(cellSel(name, env, state))) ?? "";
const rowText = async (name) => (await page.textContent(`[data-row="${name}"]`)) ?? "";
const waitText = (selector, text, timeout = 10000) =>
  page.waitForFunction(
    ([s, t]) => document.querySelector(s)?.textContent.includes(t),
    [selector, text],
    { timeout },
  );

// Enroll + land in the shell.
await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
await page.goto(`${base}/o/acme/p/api`);

// 1. Grid states from contract + presence metadata; non-secret values shown, Secrets masked.
await page.waitForSelector('[data-testid="matrix"]', { timeout: 20000 });
await page.waitForSelector(cellSel("DATABASE_URL", "development", "set"), { timeout: 20000 });
const cell = (sel) => page.locator(`[data-cell="${sel}"]`).count();
check("grid: set cell", (await cell("DATABASE_URL:development:set")) === 1);
check("grid: missing-required in production", (await cell("DATABASE_URL:production:missing_required")) === 1);
check("grid: covered-by-default", (await cell("PORT:production:covered_by_default")) === 1);
check("grid: unset-optional", (await cell("API_KEY:development:unset_optional")) === 1);
check("grid shows the non-secret value", (await cellText("PORT", "development")).includes("3000"));
const maskedCell = await cellText("DATABASE_URL", "development");
check("grid masks the secret", maskedCell.includes("••••") && !maskedCell.includes("postgres://"), maskedCell);
check(
  "column status counts what is missing",
  ((await page.textContent('[data-testid="column-status-production"]')) ?? "").includes("missing"),
);

// 2. Per-column reveal is audited and requests exactly that column's set Secrets.
await page.click('[data-testid="reveal-column-development"]');
await waitText(cellSel("DATABASE_URL", "development", "set"), "postgres://");
await untilDisclosures(1);
const columnDisclosure = await disclosures[0];
check(
  "column reveal requests and discloses only that column's secrets",
  disclosures.length === 1 &&
    JSON.stringify(disclosureRequests[0]?.items) === JSON.stringify(["DATABASE_URL"]) &&
    columnDisclosure.items.map((i) => i.name).join(",") === "DATABASE_URL",
  JSON.stringify({ request: disclosureRequests[0], items: columnDisclosure?.items.map((i) => i.name) }),
);
check("disclosure notice shown", (await page.locator('[data-testid="disclosure-notice"]').count()) === 1);
await page.click('[data-testid="mask-all"]');
check("mask all hides the plaintext again", (await cellText("DATABASE_URL", "development")).includes("••••"));

// 3. Inline cell edit + add row -> review -> atomic save (dev: no confirmation).
await page.click(cellSel("PORT", "development", "set"));
await page.fill('[data-testid="cell-editor"]', "4000");
await page.keyboard.press("Enter");
await page.fill('[data-testid="add-name"]', "NEW_FLAG");
await page.selectOption('[data-testid="add-env"]', "development");
// At least 8 bytes: later suites `varlatch run` this environment, and in an
// assisted (coding agent) session the CLI refuses Secrets too short to mask.
await page.fill('[data-testid="add-value"]', "flag-enabled");
await page.click('[data-testid="add-item"]');
check("save bar counts drafts", ((await page.textContent('[data-testid="dirty-count"]')) ?? "").includes("2 unsaved changes"));
check("edited cell is marked", (await cellText("PORT", "development")).includes("edited"));
await page.click('[data-testid="review-save"]');
await page.waitForSelector('[data-testid="review-dialog"]');
const reviewPort = (await page.textContent('[data-review-item="PORT"]')) ?? "";
const reviewFlag = (await page.textContent('[data-review-item="NEW_FLAG"]')) ?? "";
check("review shows old -> new for a non-secret", reviewPort.includes("3000") && reviewPort.includes("4000"), reviewPort);
check("review hides a new secret's value", reviewFlag.includes("hidden") && !reviewFlag.includes("flag-enabled"), reviewFlag);
await page.click('[data-testid="commit-changes"]');
await waitText(cellSel("PORT", "development", "set"), "4000");
await page.waitForSelector('[data-testid="dirty-count"]', { state: "detached", timeout: 10000 });
check("change set committed from the grid", !(await cellText("PORT", "development")).includes("edited"));

// 4. Environment page: non-sensitive visible, Secret masked.
await page.goto(`${base}/o/acme/p/api/e/development`);
await page.waitForSelector('[data-testid="values-table"]', { timeout: 20000 });
await page.waitForSelector('[data-row="PORT"]');
check("non-sensitive value visible", (await rowText("PORT")).includes("4000"));
check("secret masked by default", (await rowText("DATABASE_URL")).includes("••••"));
const changedShown = await page
  .waitForFunction(() => document.querySelector('[data-row="PORT"]')?.textContent.includes("changed"), null, { timeout: 10000 })
  .then(() => true, () => false);
check("row says when the value last changed (filtered audit log)", changedShown, await rowText("PORT"));

// 5. Per-item reveal is audited and does not over-disclose.
await page.click('[data-testid="eye-DATABASE_URL"]');
await waitText('[data-row="DATABASE_URL"]', "postgres://");
await untilDisclosures(2);
const itemDisclosure = await disclosures[1];
check(
  "reveal of one Secret discloses only that Secret",
  disclosures.length === 2 && itemDisclosure.items.length === 1 && itemDisclosure.items[0].name === "DATABASE_URL",
  JSON.stringify(itemDisclosure?.items.map((i) => i.name)),
);

// 6. Conflict: a change made after review is rejected atomically, even once
// the dashboard's live update has refreshed the data behind the dialog.
await page.click('[data-testid="edit-PORT"]');
await page.fill('[data-row="PORT"] [data-testid="cell-editor"]', "5000");
await page.keyboard.press("Enter");
await page.click('[data-testid="review-save"]');
const refreshed = page
  .waitForResponse((r) => r.url().includes("/effective-configuration"), { timeout: 30000 })
  .catch(() => null);
// Concurrent writer bumps PORT via the API while the review is open.
const bump = await apiJson(`${API}/environments/development/values/PORT`, "PUT", { value: "9999" });
check("concurrent writer succeeded", bump.ok);
check("the live update reached the open review", (await refreshed) !== null);
await page.click('[data-testid="commit-changes"]');
await page.waitForSelector('[data-testid="editor-error"]', { timeout: 10000 });
const conflictText = (await page.textContent('[data-testid="editor-error"]')) ?? "";
check("stale change set rejected, nothing written", /Changed since review.*PORT.*Nothing was written/.test(conflictText), conflictText.slice(0, 120));
await page.waitForFunction(() => document.querySelector('[data-row="PORT"]')?.textContent.includes("edited"), null, {
  timeout: 5000,
});
check("draft preserved after conflict", (await rowText("PORT")).includes("5000"));
await page.click('[data-testid="discard-drafts"]');
await page.waitForSelector('[data-testid="dirty-count"]', { state: "detached", timeout: 5000 });

// 6b. ${NAME} references: expanded on the environment page with a ref chip,
// stored text in the grid, literal text in the editor. PUBLIC_URL is
// contract-marked non-sensitive; uncontracted items default to sensitive.
const refPut = await apiJson(`${API}/environments/development/values/PUBLIC_URL`, "PUT", {
  value: "http://localhost:${PORT}",
});
check("reference value written", refPut.ok, `status ${refPut.status}`);
await page.reload();
await page.waitForSelector('[data-row="PUBLIC_URL"]', { timeout: 20000 });
check(
  "reference displays expanded with ref chip",
  (await rowText("PUBLIC_URL")).includes("http://localhost:9999") &&
    (await page.locator('[data-testid="ref-PUBLIC_URL"]').count()) === 1,
);
await page.click('[data-testid="edit-PUBLIC_URL"]');
check(
  "editing shows the literal stored ${NAME}, not the expansion",
  (await page.inputValue('[data-row="PUBLIC_URL"] [data-testid="cell-editor"]')) === "http://localhost:${PORT}",
);
await page.keyboard.press("Escape");
check("Esc leaves no draft", (await page.locator('[data-testid="dirty-count"]').count()) === 0);

// 6c. Dual-phase rotation from the item panel: overlap the old value with the new one.
await apiJson(`${API}/environments/development/values/API_KEY`, "PUT", { value: "key-v1" });
await page.reload();
await page.waitForSelector('[data-row="API_KEY"]', { timeout: 20000 });
await page.click('[data-row="API_KEY"]');
await page.waitForSelector('[data-testid="item-panel"]');
await page.click('[data-testid="rotate-API_KEY"]');
await page.fill('[data-testid="rotate-value"]', "key-v2");
await page.click('[data-testid="confirm-rotate"]');
await page.waitForSelector('[data-testid="rotating-API_KEY"]', { timeout: 10000 });
check("rotating badge shown after begin", true);
const rotDisc = await (
  await apiJson(`${API}/environments/development/disclosures`, "POST", { items: ["API_KEY"] })
).json();
check(
  "disclosure returns the new primary and the retiring value",
  rotDisc.items[0].value === "key-v2" && rotDisc.items[0].retiring?.value === "key-v1",
  JSON.stringify(rotDisc.items[0]),
);
await page.click('[data-testid="complete-rotation-API_KEY"]');
await page.waitForFunction(() => !document.querySelector('[data-testid="rotating-API_KEY"]'), null, { timeout: 10000 });
const afterComplete = await (
  await apiJson(`${API}/environments/development/disclosures`, "POST", { items: ["API_KEY"] })
).json();
check("retiring value dropped after finishing rotation", afterComplete.items[0].retiring === undefined);
await apiJson(`${API}/environments/development/values/API_KEY`, "DELETE"); // cleanup

// 6d. The grid shows a reference as its stored text with a ref hint.
await page.goto(`${base}/o/acme/p/api`);
await page.waitForSelector(cellSel("PUBLIC_URL", "development", "set"), { timeout: 20000 });
check(
  "grid shows the stored reference text with a ref hint",
  (await cellText("PUBLIC_URL", "development")).includes("${PORT}") &&
    (await page.locator('[data-testid="ref-development-PUBLIC_URL"]').count()) === 1,
);

// 7. Blind overwrite of a Secret from the grid's "+ Set" (no reveal) + production confirmation.
await page.click('[data-testid="set-production-DATABASE_URL"]');
await page.fill('[data-testid="cell-editor"]', "postgres://prod-rotated");
await page.keyboard.press("Enter");
check("drafted secret stays masked in the grid", !(await cellText("DATABASE_URL", "production", "missing_required")).includes("prod-rotated"));
await page.click('[data-testid="review-save"]');
const commitButton = page.locator('[data-testid="commit-changes"]');
check("production commit gated on checkbox", await commitButton.isDisabled());
await page.check('[data-testid="production-confirm"]');
await commitButton.click();
await page.waitForSelector('[data-testid="dirty-count"]', { state: "detached", timeout: 10000 });
await page.waitForSelector(cellSel("DATABASE_URL", "production", "set"), { timeout: 10000 });
check("production save with explicit confirmation", true);
check("blind overwrite required no disclosure", disclosures.length === 2, `${disclosures.length} disclosures total`);

// 8. Reveal all (production) is a deliberate scope; so is the palette's ?reveal=1.
await page.goto(`${base}/o/acme/p/api/e/production`);
await page.waitForSelector('[data-row="DATABASE_URL"]', { timeout: 20000 });
await page.click('[data-testid="reveal-all"]');
await waitText('[data-row="DATABASE_URL"]', "prod-rotated");
await untilDisclosures(3);
check(
  "reveal-all requests the all-authorized scope",
  disclosures.length === 3 && disclosureRequests[2]?.scope === "all-authorized-secrets",
  `${disclosures.length} disclosure responses`,
);
await page.goto(`${base}/o/acme/p/api/e/production?reveal=1`);
await waitText('[data-row="DATABASE_URL"]', "prod-rotated", 20000);
await untilDisclosures(4);
check("?reveal=1 reveals once, audited", disclosures.length === 4 && disclosureRequests[3]?.scope === "all-authorized-secrets");
check("?reveal=1 leaves the URL", !page.url().includes("reveal=1"), page.url());

// 9. ?item= deep link (palette) selects the item; its panel shows the item history.
await page.goto(`${base}/o/acme/p/api/e/production?item=DATABASE_URL`);
await page.waitForSelector('[data-testid="item-panel"]', { timeout: 20000 });
check("?item= opens the item panel", ((await page.textContent('[data-testid="item-panel"]')) ?? "").includes("DATABASE_URL"));
const history = await page
  .waitForSelector('[data-testid="panel-history"]', { timeout: 10000 })
  .then((el) => el.textContent(), () => "");
check("item history lists this item's changes (filtered audit log)", (history ?? "").includes("set the value"), history?.slice(0, 120));

// 10. Export .env: non-secret values only unless secrets are explicitly included.
await page.goto(`${base}/o/acme/p/api`);
await page.waitForSelector(cellSel("PORT", "development", "set"), { timeout: 20000 });
await page.click('[data-testid="export-menu"]');
await page.click('[data-testid="export-development"]');
await page.waitForSelector('[data-testid="export-download"]:not([disabled])', { timeout: 10000 });
const [download] = await Promise.all([page.waitForEvent("download"), page.click('[data-testid="export-download"]')]);
const exported = readFileSync(await download.path(), "utf8");
check(
  "export holds non-secret values and leaves secrets out",
  exported.includes("PORT=9999") && !exported.includes("postgres://") && exported.includes("# DATABASE_URL: secret"),
  exported.split("\n").slice(0, 6).join(" | "),
);
check("export made no disclosure", disclosures.length === 4);

// 11. Deleting an environment: plain confirm for development tier, typed name for production.
const scratch = await apiJson(`${API}/environments`, "POST", { name: "scratch", tier: "development" });
check("scratch environment created", scratch.ok, `status ${scratch.status}`);
await page.goto(`${base}/o/acme/p/api/e/scratch`);
await page.waitForSelector('[data-testid="environment-menu"]', { timeout: 20000 });
await page.click('[data-testid="environment-menu"]');
await page.click('[data-testid="menu-delete-environment"]');
await page.waitForSelector('[data-testid="confirm-dialog"]');
check("non-production delete needs no typed name", (await page.locator('[data-testid="confirm-type"]').count()) === 0);
await page.click('[data-testid="confirm-ok"]');
await page.waitForURL("**/o/acme/p/api", { timeout: 10000 });
const remaining = await (await apiJson(`${API}/environments`, "GET")).json();
check("environment deleted", !remaining.items.some((e) => e.name === "scratch"));
await page.goto(`${base}/o/acme/p/api/e/production`);
await page.waitForSelector('[data-testid="environment-menu"]', { timeout: 20000 });
await page.click('[data-testid="environment-menu"]');
await page.click('[data-testid="menu-delete-environment"]');
await page.waitForSelector('[data-testid="confirm-type"]');
check("production delete waits for the typed name", await page.locator('[data-testid="confirm-ok"]').isDisabled());
await page.click('[data-testid="confirm-cancel"]');

await browser.close();
process.exit(failed ? 1 : 0);
