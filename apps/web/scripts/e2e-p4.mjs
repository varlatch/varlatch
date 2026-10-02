#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * P4 E2E: audit timeline (authoritative /v1 history, filters, provenance
 * drawer), contract tab (git read-only vs managed editor, moving to the
 * newest semantics rules, the integer type), command palette, settings.
 * Usage: e2e-p4.mjs <enroll-url> <api-token>
 */
import { chromium } from "playwright";

const [enrollUrl, apiToken, disposableToken] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !apiToken || !disposableToken) {
  console.error("Usage: e2e-p4.mjs <enroll-url> <api-token> <disposable-token>");
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

// Seed a managed project before loading the UI.
const mkProject = await api("POST", "/organizations/acme/projects", {
  slug: "managed-app",
  name: "managed-app",
  contractAuthority: "managed",
});
check("managed project seeded", mkProject.status === 201, `status ${mkProject.status}`);
await api("POST", "/organizations/acme/projects/managed-app/environments", {
  name: "development",
  tier: "development",
});

// Contracts at older semantics versions, pinned explicitly (a push without a
// pin to a project with no active revision gets the newest version).
const { semanticsVersions } = await (await fetch(`${base}/v1/meta`)).json();
const newestVersion = Math.max(...semanticsVersions);
check("server supports semantics version 3", newestVersion >= 3, `versions ${semanticsVersions}`);
const seedContract = async (slug, semanticsVersion, items) => {
  const pushed = await api("POST", `/organizations/acme/projects/${slug}/contract/revisions`, {
    contract: { schemaVersion: 1, semanticsVersion, items },
  });
  const revision = await pushed.json();
  const activated = await api(
    "POST",
    `/organizations/acme/projects/${slug}/contract/revisions/${revision.id}/activate`,
    {},
  );
  check(
    `${slug} seeded at semantics version ${semanticsVersion}`,
    pushed.status === 201 && activated.status === 200 && revision.semanticsVersion === semanticsVersion,
    `push ${pushed.status} activate ${activated.status} version ${revision.semanticsVersion}`,
  );
};
const activeContract = async (slug) =>
  (await api("GET", `/organizations/acme/projects/${slug}/contract`)).json();
await seedContract("managed-app", 1, [
  {
    name: "PORT",
    required: { kind: "always" },
    sensitive: false,
    type: "number",
    defaultValue: "3000",
    description: "HTTP port",
    example: "8080",
  },
]);
const legacyGit = await api("POST", "/organizations/acme/projects", {
  slug: "legacy-git",
  name: "legacy-git",
  contractAuthority: "git",
});
check("legacy git project seeded", legacyGit.status === 201, `status ${legacyGit.status}`);
await seedContract("legacy-git", 2, [
  { name: "LOG_LEVEL", required: { kind: "never" }, sensitive: false, type: "enum", enumValues: ["debug", "info"] },
  { name: "SESSION_KEY", required: { kind: "always" }, sensitive: true, type: "string", rotationGraceSeconds: 3600 },
]);

await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);

// 1. Audit timeline from the authoritative store.
await page.goto(`${base}/o/acme/audit`);
await page.waitForSelector('[data-audit-row]', { timeout: 20000 });
const totalRows = await page.locator("[data-audit-row]").count();
check("authoritative audit history renders", totalRows > 5, `${totalRows} rows`);
await page.fill('[data-testid="audit-filter"]', "identity.created");
const narrowed = await page.locator("[data-audit-row]").count();
check("text filter narrows the timeline", narrowed > 0 && narrowed < totalRows, `${narrowed} rows`);
const allTypes = await page.locator("[data-audit-row]").evaluateAll((rows) =>
  rows.map((r) => r.getAttribute("data-audit-row")),
);
check("filter keeps only matching events", allTypes.every((t) => t === "identity.created"));
await page.click('[data-audit-row="identity.created"]');
await page.waitForSelector('[data-testid="audit-drawer"]', { timeout: 10000 });
const drawer = await page.textContent('[data-testid="audit-drawer"]');
check("provenance drawer shows event + request ids", drawer.includes("evt_") || drawer.includes("Request"));
check(
  "timeline reads as sentences with names, not raw IDs",
  !(await page.textContent('[data-testid="audit-feed"]')).match(/idn_[a-z0-9]{6,}/),
);
await page.fill('[data-testid="audit-filter"]', "");
// The decision facet queries the server when it supports audit filters (and
// filters the loaded pages otherwise): wait for the rows to settle.
await page.selectOption('[data-testid="audit-decision"]', "info");
const onlyInfo = await page
  .waitForFunction(
    () => {
      const rows = [...document.querySelectorAll("[data-audit-row]")];
      return rows.length > 0 && rows.every((r) => r.querySelector("[data-decision]")?.getAttribute("data-decision") === "info");
    },
    null,
    { timeout: 10000 },
  )
  .then(() => true, () => false);
const infoRows = await page.locator("[data-audit-row]").count();
check("decision filter applies", onlyInfo && infoRows > 0, `${infoRows} rows`);
await page.selectOption('[data-testid="audit-decision"]', "");

// 1b. Audit webhooks: register (secret shown once), list, revoke.
const whUrl = "https://ops.example.invalid/varlatch-audit";
await page.fill('[data-testid="webhook-url"]', whUrl);
await page.fill('[data-testid="webhook-event-types"]', "value.disclosed, authentication.failed");
await page.click('[data-testid="create-webhook"]');
await page.waitForSelector('[data-testid="webhook-secret"]', { timeout: 10000 });
const whSecret = (await page.textContent('[data-testid="webhook-secret-value"]')).trim();
check("webhook signing secret shown once", whSecret.length >= 32, `${whSecret.length} chars`);
await page.click('[data-testid="dismiss-webhook-secret"]');
check(
  "webhook secret dismissed, not re-shown",
  (await page.locator('[data-testid="webhook-secret"]').count()) === 0,
);
await page.waitForSelector(`[data-webhook="${whUrl}"]`, { timeout: 10000 });
const whRow = await page.textContent(`[data-webhook="${whUrl}"]`);
check("webhook row lists its event-type filter", whRow.includes("value.disclosed"));

// 1c. Webhook edit (ADR-0029 §8): URL and filter change in place; the
// signing secret and delivery cursor are preserved (no new secret shown).
const whUrl2 = "https://ops.example.invalid/varlatch-audit-v2";
await page.locator(`[data-webhook="${whUrl}"] [data-testid^="edit-webhook-"]`).click();
await page.waitForSelector('[data-testid^="webhook-editor-"]', { timeout: 10000 });
await page.locator('[data-testid^="webhook-editor-"] input').nth(0).fill(whUrl2);
await page.locator('[data-testid^="webhook-editor-"] input').nth(1).fill(""); // clear -> all events
await page.locator('[data-testid^="save-webhook-"]').click();
await page.waitForSelector(`[data-webhook="${whUrl2}"]`, { timeout: 10000 });
check(
  "webhook edited in place: new URL, filter cleared to all events",
  (await page.textContent(`[data-webhook="${whUrl2}"]`)).includes("all events"),
);
check(
  "no new signing secret shown on edit",
  (await page.locator('[data-testid="webhook-secret"]').count()) === 0,
);
await page.locator(`[data-webhook="${whUrl2}"] [data-testid^="revoke-webhook-"]`).click();
// Revoking goes through the confirmation dialog.
await page.waitForSelector('[data-testid="confirm-dialog"]', { timeout: 10000 });
await page.click('[data-testid="confirm-ok"]');
await page.waitForFunction(
  (url) => !document.querySelector(`[data-webhook="${url}"]`),
  whUrl2,
  { timeout: 10000 },
);
check("webhook revoked from dashboard", true);

// 2. Git-authority contract tab: read-only.
await page.goto(`${base}/o/acme/p/api/contract`);
await page.waitForSelector('[data-testid="contract-items"]', { timeout: 20000 });
check("git contract items render", (await page.locator('[data-contract-item="DATABASE_URL"]').count()) === 1);
check(
  "git authority shown",
  (await page.getAttribute('[data-testid="contract-authority"]', "data-authority")) === "git" &&
    (await page.textContent('[data-testid="contract-authority"]')).includes("varlatch contract push"),
);
check("no managed editor for git projects", (await page.locator('[data-testid="managed-editor"]').count()) === 0);

// 2b. Git project at an older semantics version: move to the newest rules.
// The push and the activation are separate steps; cancel activates nothing.
await page.goto(`${base}/o/acme/p/legacy-git/contract`);
await page.waitForSelector('[data-testid="move-rules"]', { timeout: 20000 });
check(
  "git project offers moving to the newest rules",
  (await page.textContent('[data-testid="move-rules"]')).includes(`version ${newestVersion}`),
);
check("git project still has no managed editor", (await page.locator('[data-testid="managed-editor"]').count()) === 0);
const gitBefore = await activeContract("legacy-git");
await page.click('[data-testid="move-rules"]');
await page.waitForSelector('[data-testid="move-rules-review"]', { timeout: 10000 });
let review = await page.textContent('[data-testid="move-rules-review"]');
const gitDiff = await page.locator('[data-testid="move-rules-diff"] li').allTextContents();
check(
  "review diff shows only the semantics version change",
  gitDiff.length === 1 && gitDiff[0].includes(`Semantics version 2 → ${newestVersion}`),
  JSON.stringify(gitDiff),
);
check(
  "review explains the version 3 step only",
  review.includes("Adds the integer type") && !review.includes("Version 2:"),
);
check(
  "review tells git projects later pushes keep the version",
  review.includes(`Later pushes from your repository keep version ${newestVersion}`),
);
check("pushed revision is not active before confirmation", (await activeContract("legacy-git")).id === gitBefore.id);
await page.click('[data-testid="move-rules-review"] button:has-text("Cancel")');
await page.waitForSelector('[data-testid="move-rules"]', { timeout: 10000 });
check(
  "cancel leaves the active revision in place",
  (await activeContract("legacy-git")).id === gitBefore.id &&
    (await page.getAttribute('[data-testid="semantics-version"]', "data-version")) === "2",
);
await page.click('[data-testid="move-rules"]');
await page.waitForSelector('[data-testid="move-rules-activate"]:enabled', { timeout: 10000 });
await page.click('[data-testid="move-rules-activate"]');
await page.waitForSelector(`[data-testid="semantics-version"][data-version="${newestVersion}"]`, {
  timeout: 10000,
});
check("git project moved to the newest version", (await page.locator('[data-testid="move-rules"]').count()) === 0);
const gitAfter = await activeContract("legacy-git");
check(
  "the move changed the version and nothing else (git)",
  gitAfter.semanticsVersion === newestVersion &&
    JSON.stringify(gitAfter.contract.items) === JSON.stringify(gitBefore.contract.items),
);

// 3. Managed contract editor: add a row, publish through the review (adding
// an item is security-relevant, so it needs the acknowledgement), see it active.
await page.goto(`${base}/o/acme/p/managed-app/contract`);
await page.waitForSelector('[data-testid="managed-editor"]', { timeout: 20000 });
// Edits start from the active Contract: wait for it before adding an item.
await page.waitForSelector('[data-contract-item="PORT"]', { timeout: 20000 });
const publishDraft = async () => {
  await page.click('[data-testid="contract-publish"]');
  await page.waitForSelector('[data-testid="contract-diff"]', { timeout: 10000 });
  check(
    "publishing a security-relevant change asks for the acknowledgement",
    await page.locator('[data-testid="contract-publish-confirm"]').isDisabled(),
  );
  await page.check('[data-testid="contract-publish-ack"]');
  await page.click('[data-testid="contract-publish-confirm"]');
};
await page.fill('[data-testid="contract-item-name"]', "FEATURE_FLAG");
await page.selectOption('[data-testid="contract-item-required"]', "never");
await page.click('[data-testid="contract-add-item"]');
check(
  "the new row shows in the draft before publishing",
  (await page.getAttribute('[data-contract-item="FEATURE_FLAG"]', "data-row-state")) === "new",
);
await publishDraft();
await page.waitForSelector('[data-contract-item="FEATURE_FLAG"][data-row-state="unchanged"]', { timeout: 10000 });
check(
  "managed publish activates a revision with the new item",
  (await activeContract("managed-app")).contract.items.some((i) => i.name === "FEATURE_FLAG" && i.required.kind === "never"),
);
check(
  "an edit keeps the semantics version",
  (await page.getAttribute('[data-testid="semantics-version"]', "data-version")) === "1",
);
const integerOption = '[data-testid="contract-item-type"] option[value="integer"]';
check("integer is not offered at version 1", await page.locator(integerOption).isDisabled());
check(
  "the editor says integer needs version 3",
  (await page.textContent('[data-testid="integer-unavailable"]')).includes("Needs semantics version 3"),
);

// 3b. Managed project: move from version 1 to the newest rules, then use integer.
const managedBefore = await activeContract("managed-app");
await page.click('[data-testid="move-rules"]');
await page.waitForSelector('[data-testid="move-rules-review"]', { timeout: 10000 });
review = await page.textContent('[data-testid="move-rules-review"]');
const managedDiff = await page.locator('[data-testid="move-rules-diff"] li').allTextContents();
check(
  "managed review diff shows only the semantics version change",
  managedDiff.length === 1 && managedDiff[0].includes(`Semantics version 1 → ${newestVersion}`),
  JSON.stringify(managedDiff),
);
check(
  "managed review explains every step and the consequences",
  review.includes("Version 2:") &&
    review.includes("Adds the integer type") &&
    review.includes("varlatch run --strict") &&
    review.includes("larger than 2^53 - 1") &&
    !review.includes("Later pushes from your repository"),
);
await page.click('[data-testid="move-rules-activate"]');
await page.waitForSelector(`[data-testid="semantics-version"][data-version="${newestVersion}"]`, {
  timeout: 10000,
});
check("managed project moved to the newest version", (await page.locator('[data-testid="move-rules"]').count()) === 0);
const managedAfter = await activeContract("managed-app");
check(
  "the move changed the version and nothing else (managed)",
  managedAfter.semanticsVersion === newestVersion &&
    JSON.stringify(managedAfter.contract.items) === JSON.stringify(managedBefore.contract.items),
);
check("integer is offered at version 3", !(await page.locator(integerOption).isDisabled()));
await page.fill('[data-testid="contract-item-name"]', "WORKERS");
await page.selectOption('[data-testid="contract-item-type"]', "integer");
await page.click('[data-testid="contract-add-item"]');
await publishDraft();
await page.waitForSelector('[data-contract-item="WORKERS"][data-row-state="unchanged"]', { timeout: 10000 });
const managedFinal = await activeContract("managed-app");
check(
  "an integer item publishes at version 3",
  managedFinal.contract.items.some((i) => i.name === "WORKERS" && i.type === "integer") &&
    managedFinal.semanticsVersion === newestVersion,
);

// 3c. Inline edit: a non-security change (description) publishes without the
// acknowledgement and marks the row edited until then.
await page.fill('[aria-label="Description of WORKERS"]', "Background worker processes");
check(
  "an edited row is marked in the draft",
  (await page.getAttribute('[data-contract-item="WORKERS"]', "data-row-state")) === "edited",
);
await page.click('[data-testid="contract-publish"]');
await page.waitForSelector('[data-contract-item="WORKERS"][data-row-state="unchanged"]', { timeout: 10000 });
check(
  "a description-only change publishes directly",
  (await activeContract("managed-app")).contract.items.find((i) => i.name === "WORKERS")?.description ===
    "Background worker processes",
);

// 4. The environment-name mapping was removed: no card on the contract tab.
check("contract tab has no environment-name mapping card", (await page.$('[data-testid="varlock-mapping"]')) === null);

// 5. Command palette.
await page.keyboard.press("ControlOrMeta+k");
await page.waitForSelector('[data-testid="command-palette"]', { timeout: 5000 });
await page.fill('[data-testid="palette-input"]', "api");
await page.waitForSelector('[data-palette-entry="api"]', { timeout: 10000 });
await page.click('[data-palette-entry="api"]');
await page.waitForURL("**/o/acme/p/api", { timeout: 10000 });
check("palette navigates to a project", true);

// 5b. Server-side Config Item name search (ADR-0030): metadata-only hits
// that land on the environment page with the item selected via ?item=.
await page.keyboard.press("ControlOrMeta+k");
await page.waitForSelector('[data-testid="command-palette"]', { timeout: 5000 });
await page.fill('[data-testid="palette-input"]', "database");
await page.waitForSelector('[data-palette-entry="api:DATABASE_URL"]', { timeout: 10000 });
await page.click('[data-palette-entry="api:DATABASE_URL"]');
await page.waitForURL("**/o/acme/p/api/e/**", { timeout: 10000 });
check("palette item hit deep-links with the item name", page.url().includes("item=DATABASE_URL"));
await page.waitForSelector('[data-testid="item-panel"]', { timeout: 20000 });
check(
  "deep link selects the item",
  ((await page.textContent('[data-testid="item-panel"]')) ?? "").includes("DATABASE_URL") &&
    (await page.getAttribute('[data-row="DATABASE_URL"]', "aria-selected")) === "true",
);

// 5c. Palette actions: the theme switch and the shortcuts sheet.
const theme = () => page.evaluate(() => document.documentElement.dataset.theme);
const themeBefore = await theme();
await page.keyboard.press("ControlOrMeta+k");
await page.waitForSelector('[data-testid="command-palette"]', { timeout: 5000 });
await page.fill('[data-testid="palette-input"]', "theme");
await page.waitForSelector('[data-palette-entry="action:theme"][aria-selected="true"]', { timeout: 5000 });
await page.keyboard.press("Enter");
check("palette action switches the theme", (await theme()) !== themeBefore, `${themeBefore} -> ${await theme()}`);
await page.keyboard.press("ControlOrMeta+k");
await page.fill('[data-testid="palette-input"]', "theme");
await page.waitForSelector('[data-palette-entry="action:theme"][aria-selected="true"]', { timeout: 5000 });
await page.keyboard.press("Enter");
await page.keyboard.press("ControlOrMeta+k");
await page.fill('[data-testid="palette-input"]', "shortcuts");
await page.waitForSelector('[data-palette-entry="action:shortcuts"][aria-selected="true"]', { timeout: 5000 });
await page.keyboard.press("Enter");
check(
  "palette opens the keyboard shortcuts",
  await page.waitForSelector('[data-testid="shortcuts-dialog"]', { timeout: 5000 }).then(() => true, () => false),
);
await page.keyboard.press("Escape");
check("theme restored", (await theme()) === themeBefore);

// 6. Settings.
await page.goto(`${base}/o/acme/settings`);
await page.waitForSelector('[data-testid="settings-server"]', { timeout: 20000 });
// Compare against what the server actually reports, so the assertion
// survives version bumps instead of pinning a released number.
const { serverVersion } = await (await fetch(`${base}/v1/meta`)).json();
// The card renders before its own meta query returns: wait for the version
// instead of reading the first paint.
const versionShown = await page
  .locator('[data-testid="settings-server"]', { hasText: serverVersion })
  .waitFor({ timeout: 20000 })
  .then(() => true, () => false);
const settingsText = await page.textContent('[data-testid="settings-server"]');
check(
  "settings shows the server's reported version",
  versionShown,
  `ui="${settingsText.trim().slice(0, 120)}" meta=${serverVersion}`,
);

// 7. Me-scoped realtime: /credentials refreshes on the identitySignal when
// a credential of this identity is revoked from another surface (no reload).
await page.goto(`${base}/credentials`);
await page.waitForSelector('[data-testid="credentials-list"]', { timeout: 20000 });
const meCreds = await (
  await fetch(`${base}/v1/me/credentials`, {
    headers: { Authorization: `Bearer ${disposableToken}` },
  })
).json();
const disposable = meCreds.items.find((c) => c.current);
check("disposable credential identified", Boolean(disposable), JSON.stringify(meCreds.items?.map((c) => c.id)));
await page.waitForSelector(`[data-credential="${disposable.id}"]`, { timeout: 10000 });
check(
  "disposable credential listed as active",
  !(await page.textContent(`[data-credential="${disposable.id}"]`)).includes("revoked"),
);
const revokeRes = await fetch(`${base}/v1/me/credentials/${disposable.id}`, {
  method: "DELETE",
  headers: { Authorization: `Bearer ${disposableToken}` },
});
check("credential revoked via the API", revokeRes.status === 204, `status ${revokeRes.status}`);
await page.waitForFunction(
  (id) => document.querySelector(`[data-credential="${id}"]`)?.textContent.includes("revoked"),
  disposable.id,
  { timeout: 20000 },
);
check("credentials page refreshed reactively on the identity signal", true);

await browser.close();
process.exit(failed ? 1 : 0);
