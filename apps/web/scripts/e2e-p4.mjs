#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * P4 E2E: audit timeline (authoritative /v1 history, filters, provenance
 * drawer), contract tab (git read-only vs managed editor),
 * command palette, settings.
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
await page.fill('[data-testid="audit-filter"]', "");
await page.selectOption('[data-testid="audit-decision"]', "info");
const infoRows = await page.locator("[data-audit-row]").count();
check("decision filter applies", infoRows > 0 && infoRows <= totalRows, `${infoRows} rows`);

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
check("git authority shown", (await page.textContent('[data-testid="contract-authority"]')).includes("git"));
check("no managed editor for git projects", (await page.locator('[data-testid="managed-editor"]').count()) === 0);

// 3. Managed contract editor: add item, publish, see it active.
await page.goto(`${base}/o/acme/p/managed-app/contract`);
await page.waitForSelector('[data-testid="managed-editor"]', { timeout: 20000 });
await page.fill('[data-testid="contract-item-name"]', "FEATURE_FLAG");
await page.selectOption('[data-testid="managed-editor"] select >> nth=1', "never");
await page.click('[data-testid="contract-add-item"]');
await page.click('[data-testid="contract-publish"]');
await page.waitForSelector('[data-contract-item="FEATURE_FLAG"]', { timeout: 10000 });
check("managed publish activates a revision with the new item", true);

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
// that land in the editor with the filter prefilled via the ?item= link.
await page.keyboard.press("ControlOrMeta+k");
await page.waitForSelector('[data-testid="command-palette"]', { timeout: 5000 });
await page.fill('[data-testid="palette-input"]', "database");
await page.waitForSelector('[data-palette-entry="api:DATABASE_URL"]', { timeout: 10000 });
await page.click('[data-palette-entry="api:DATABASE_URL"]');
await page.waitForURL("**/o/acme/p/api/e/**", { timeout: 10000 });
check("palette item hit deep-links with the item name", page.url().includes("item=DATABASE_URL"));
await page.waitForSelector('input[placeholder="Filter items…"]', { timeout: 20000 });
check(
  "editor filter prefilled from the deep link",
  (await page.inputValue('input[placeholder="Filter items…"]')) === "DATABASE_URL",
);

// 6. Settings.
await page.goto(`${base}/o/acme/settings`);
await page.waitForSelector('[data-testid="settings-server"]', { timeout: 20000 });
// Compare against what the server actually reports, so the assertion
// survives version bumps instead of pinning a released number.
const { serverVersion } = await (await fetch(`${base}/v1/meta`)).json();
const settingsText = await page.textContent('[data-testid="settings-server"]');
check(
  "settings shows the server's reported version",
  settingsText.includes(serverVersion),
  `ui="${settingsText.trim().slice(0, 40)}" meta=${serverVersion}`,
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
