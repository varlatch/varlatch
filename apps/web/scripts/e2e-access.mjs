#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * P3 access E2E: machine identity with one-time credential, default-deny
 * before any Grant, preset Grants compiling to real access, revocation
 * taking effect, invite links, tailnet requirements, My Credentials.
 * Usage: e2e-access.mjs <enroll-url>
 */
import { chromium } from "playwright";

const [enrollUrl] = process.argv.slice(2);
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-access.mjs <enroll-url>");
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

const asMachine = (token, path) =>
  fetch(`${base}/v1${path}`, { headers: { Authorization: `Bearer ${token}` } });
// Destructive actions go through an in-app confirmation dialog.
const confirmDialog = async () => {
  await page.waitForSelector('[data-testid="confirm-ok"]', { timeout: 10000 });
  await page.click('[data-testid="confirm-ok"]');
};
const createMachine = async (name, kind, extra = async () => {}) => {
  await page.click('[data-testid="new-machine"]');
  await page.waitForSelector('[data-testid="machine-name"]', { timeout: 10000 });
  await page.fill('[data-testid="machine-name"]', name);
  if (kind) await page.selectOption('[data-testid="machine-kind"]', kind);
  await extra();
  await page.click('[data-testid="create-machine"]');
};

await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(
  () => /API credential|failed/.test(document.getElementById("status").textContent),
  null,
  { timeout: 20000 },
);
await page.goto(`${base}/o/acme/access`);
// The Access page is tabbed (?tab=…); Members is the default tab.
await page.waitForSelector('[data-testid="access-tab-machines"]', { timeout: 20000 });
await page.click('[data-testid="access-tab-machines"]');
await page.waitForSelector('[data-testid="machines-section"]', { timeout: 20000 });

// 1. Machine identity: credential shown exactly once.
await createMachine("ci-deployer");
await page.waitForSelector('[data-testid="one-time-credential"]', { timeout: 10000 });
const machineToken = (await page.textContent('[data-testid="one-time-credential-token"]')).trim();
check("one-time machine credential displayed", /^vlt_svc_/.test(machineToken));
await page.click('[data-testid="dismiss-credential"]');
check("credential dismissed, not re-shown", (await page.locator('[data-testid="one-time-credential"]').count()) === 0);
await page.waitForSelector('[data-identity="ci-deployer"]');

// 1b. Credential TTL + use budget flow through creation and are echoed once.
await createMachine("budget-runner", null, async () => {
  await page.fill('[data-testid="machine-ttl"]', "3600");
  await page.fill('[data-testid="machine-max-uses"]', "5");
});
await page.waitForSelector('[data-testid="one-time-credential-limits"]', { timeout: 10000 });
const limitsText = await page.textContent('[data-testid="one-time-credential-limits"]');
check(
  "credential expiry and use budget echoed at creation",
  /Expires /.test(limitsText) && /5 requests/.test(limitsText),
  limitsText.trim().slice(0, 80),
);
await page.click('[data-testid="dismiss-credential"]');
await page.waitForSelector('[data-identity="budget-runner"]');

// 1c. Another credential for an existing machine (identity.credentials.issue):
// named, shown once, listed, authenticating as the machine, revocable alone.
const deployerId = await page.getAttribute('[data-identity="ci-deployer"]', "data-identity-id");
await page.click('[data-identity="ci-deployer"]');
await page.waitForSelector(`[data-testid="issue-credential-${deployerId}"]`, { timeout: 10000 });
await page.click(`[data-testid="issue-credential-${deployerId}"]`);
await page.waitForSelector('[data-testid="issue-credential-name"]', { timeout: 10000 });
await page.fill('[data-testid="issue-credential-name"]', "nightly backup");
await page.fill('[data-testid="issue-credential-ttl"]', "3600");
await page.click('[data-testid="issue-credential-submit"]');
await page.waitForSelector('[data-testid="issued-credential"]', { timeout: 10000 });
const issuedToken = (await page.textContent('[data-testid="issued-credential-token"]')).trim();
check("issued credential shown once, a new service token", /^vlt_svc_/.test(issuedToken) && issuedToken !== machineToken);
check("issued credential's expiry echoed", /Expires /.test(await page.textContent('[data-testid="issued-credential-limits"]')));
await page.click('[data-testid="dismiss-issued-credential"]');
check("issued credential dismissed, not re-shown", (await page.locator('[data-testid="issued-credential"]').count()) === 0);
const issuedRow = page.locator(`[data-testid="credentials-panel-${deployerId}"] [data-credential]`, { hasText: "nightly backup" });
await issuedRow.waitFor({ timeout: 10000 });
check("issued credential listed under its name", true);
const asIssued = await asMachine(issuedToken, "/organizations/acme/projects");
check("issued credential authenticates as the machine (denied, not unauthenticated)", asIssued.status === 403, `status ${asIssued.status}`);
await issuedRow.locator('[data-testid^="revoke-credential-"]').click();
await confirmDialog();
await issuedRow.locator("text=revoked").waitFor({ timeout: 10000 });
const afterIssuedRevoke = await asMachine(issuedToken, "/organizations/acme/projects");
const firstStillWorks = await asMachine(machineToken, "/organizations/acme/projects");
check(
  "revoking the issued credential leaves the first one working",
  afterIssuedRevoke.status === 401 && firstStillWorks.status === 403,
  `issued ${afterIssuedRevoke.status}, first ${firstStillWorks.status}`,
);
await page.click('[data-identity="ci-deployer"]');

// 2. Default-deny: zero grants means the machine sees nothing.
const before = await asMachine(machineToken, "/organizations/acme/projects");
check("machine denied before any grant", !before.ok, `status ${before.status}`);

// 3. Preset grant compiles to real access.
await page.click('[data-testid="access-tab-grants"]');
await page.waitForSelector('[data-testid="grants-section"]', { timeout: 10000 });
await page.selectOption('[data-testid="grant-subject"]', { label: "ci-deployer" });
await page.selectOption('[data-testid="grant-permission"]', "preset:read-config");
await page.click('[data-testid="create-grant"]');
await page.waitForSelector('[data-grant-subject="ci-deployer"]', { timeout: 10000 });
const grantRow = await page.textContent('[data-grant-subject="ci-deployer"]');
check("grant row reads as a sentence and keeps its actions", grantRow.includes("Read configuration") && grantRow.includes("project.read"));
const after = await asMachine(machineToken, "/organizations/acme/projects");
check("machine can read configuration after grant", after.ok, `status ${after.status}`);
const secrets = await fetch(
  `${base}/v1/organizations/acme/projects/api/environments/development/disclosures`,
  { method: "POST", headers: { Authorization: `Bearer ${machineToken}`, "Content-Type": "application/json" }, body: JSON.stringify({ scope: "all-authorized-secrets" }) },
);
check("read-config grant does NOT allow secret disclosure", !secrets.ok, `status ${secrets.status}`);

// 4. Revocation takes effect immediately.
const revokeBtn = page.locator('[data-grant-subject="ci-deployer"] [data-testid^="revoke-grant-"]');
await revokeBtn.click();
await confirmDialog();
await page.waitForFunction(
  () => !document.querySelector('[data-grant-subject="ci-deployer"]'),
  null,
  { timeout: 10000 },
);
const revoked = await asMachine(machineToken, "/organizations/acme/projects");
check("machine denied after grant revocation", !revoked.ok, `status ${revoked.status}`);

// 4b. Environment-scoped grant: access stops at the environment boundary.
await page.selectOption('[data-testid="grant-subject"]', { label: "ci-deployer" });
await page.selectOption('[data-testid="grant-scope"]', { label: "api" });
await page.selectOption('[data-testid="grant-env-scope"]', "pick");
await page.waitForSelector('[data-testid="grant-environments"] [data-env="development"]', {
  timeout: 10000,
});
await page.click('[data-testid="grant-environments"] [data-env="development"]');
await page.click('[data-testid="create-grant"]');
await page.waitForSelector('[data-grant-subject="ci-deployer"]', { timeout: 10000 });
check(
  "environment-scoped grant row lists its selector",
  (await page.textContent('[data-grant-subject="ci-deployer"]')).includes("development"),
);
const devCfg = await asMachine(
  machineToken,
  "/organizations/acme/projects/api/environments/development/effective-configuration",
);
check("granted environment readable", devCfg.ok, `status ${devCfg.status}`);
const prodCfg = await asMachine(
  machineToken,
  "/organizations/acme/projects/api/environments/production/effective-configuration",
);
check("sibling environment still denied", !prodCfg.ok, `status ${prodCfg.status}`);
await page.locator('[data-grant-subject="ci-deployer"] [data-testid^="revoke-grant-"]').click();
await confirmDialog();
await page.waitForFunction(
  () => !document.querySelector('[data-grant-subject="ci-deployer"]'),
  null,
  { timeout: 10000 },
);

// 5. Invite link (Members tab).
await page.click('[data-testid="access-tab-members"]');
await page.waitForSelector('[data-testid="people-section"]', { timeout: 10000 });
await page.click('[data-testid="open-invite"]');
await page.fill('[data-testid="invite-name"]', "Sam");
await page.click('[data-testid="create-invite"]');
await page.waitForSelector('[data-testid="invite-url"]', { timeout: 10000 });
const inviteText = await page.textContent('[data-testid="invite-url"]');
check("invite link minted on dashboard origin", inviteText.includes(`${base}/enroll#`));

// 5b. OIDC federation: bind, list, revoke (Machines tab).
await page.click('[data-testid="access-tab-machines"]');
await page.waitForSelector('[data-identity="ci-deployer"]', { timeout: 10000 });
await page.click('[data-identity="ci-deployer"]'); // expand: OIDC bindings and credentials
await page.waitForSelector('[data-testid="oidc-section"]', { timeout: 10000 });
await page.click('[data-testid="add-oidc-binding"]');
await page.fill('[data-testid="oidc-issuer"]', "https://token.actions.githubusercontent.com");
await page.fill('[data-testid="oidc-audience"]', "varlatch");
await page.fill('[data-testid="oidc-subject"]', "repo:acme/api:*");
await page.click('[data-testid="create-oidc-binding"]');
await page.waitForSelector('[data-oidc-binding="repo:acme/api:*"]', { timeout: 10000 });
check(
  "oidc binding listed with issuer",
  (await page.textContent('[data-oidc-binding="repo:acme/api:*"]')).includes(
    "token.actions.githubusercontent.com",
  ),
);
await page.locator('[data-oidc-binding="repo:acme/api:*"] [data-testid^="revoke-oidc-"]').click();
await confirmDialog();
await page.waitForFunction(
  () => document.querySelectorAll('[data-oidc-binding="repo:acme/api:*"]').length === 0,
  null,
  { timeout: 10000 },
);
check("oidc binding revoked from dashboard", true);

// 5c. Roles, Groups, Teams (ADR-0028): reuse compiles to real access.
// ci-deployer is back to default-deny here (prior grants were revoked).
const denyBefore = await asMachine(machineToken, "/organizations/acme/projects");
check("machine denied before role/group grant", !denyBefore.ok);

await page.click('[data-testid="access-tab-roles"]');
await page.waitForSelector('[data-testid="roles-section"]', { timeout: 10000 });
await page.click('[data-testid="new-role"]');
await page.fill('[data-testid="role-name"]', "reader-role");
await page.click('[data-role-action="organization.read"]');
await page.click('[data-role-action="project.read"]');
await page.click('[data-testid="create-role"]');
await page.waitForSelector('[data-role="reader-role"]', { timeout: 10000 });
check("custom role created", true);

await page.click('[data-testid="new-group"]');
await page.fill('[data-testid="group-name"]', "readers");
await page.click('[data-testid="create-group"]');
await page.waitForSelector('[data-group="readers"]', { timeout: 10000 });
await page.click('[data-group="readers"] [data-testid^="expand-group-"]'); // membership editor
await page.locator('[data-group="readers"] select[data-testid^="member-select-"]').selectOption({ label: "ci-deployer" });
await page.locator('[data-group="readers"] [data-testid^="add-member-"]').click();
await page.waitForSelector('[data-group="readers"] [data-member="ci-deployer"]', { timeout: 10000 });
check("identity added to group", true);

// Grant the group the custom role, org-wide (Grants tab). Reset the scope
// explicitly — the form may retain state from the earlier grant.
await page.click('[data-testid="access-tab-grants"]');
await page.waitForSelector('[data-testid="grants-section"]', { timeout: 10000 });
await page.selectOption('[data-testid="grant-scope"]', "org");
await page.selectOption('[data-testid="grant-subject"]', { label: "readers" });
await page.selectOption('[data-testid="grant-permission"]', { label: "reader-role" });
await page.click('[data-testid="create-grant"]');
await page.waitForSelector('[data-grant-subject="readers"]', { timeout: 10000 });
const groupGrantRow = await page.textContent('[data-grant-subject="readers"]');
check("group+role grant lists the role", groupGrantRow.includes("reader-role"));

const allowAfter = await asMachine(machineToken, "/organizations/acme/projects");
check("group member inherits role-granted access", allowAfter.ok, `status ${allowAfter.status}`);

// 5c-bis. Role edit (ADR-0029): editing the role re-points the untouched
// grant on the next authorization decision — no revoke window, no churn.
await page.click('[data-testid="access-tab-roles"]');
await page.waitForSelector('[data-role="reader-role"]', { timeout: 10000 });
await page.locator('[data-role="reader-role"] [data-testid^="open-role-"]').click();
await page.locator('[data-testid="role-drawer"] [data-edit-action="project.read"]').click(); // toggle off
await page.locator('[data-testid="role-drawer"] [data-testid^="save-role-"]').click();
await page.waitForFunction(
  () => {
    const row = document.querySelector('[data-role="reader-role"]');
    // The editor closes on save; the row then lists only the current actions.
    return row && !row.querySelector('[data-edit-action]') && !row.textContent.includes("project.read");
  },
  null,
  { timeout: 10000 },
);
const narrowed = await asMachine(machineToken, "/organizations/acme/projects");
check("removing an action from the role narrows the member immediately", !narrowed.ok, `status ${narrowed.status}`);
await page.locator('[data-role="reader-role"] [data-testid^="open-role-"]').click();
await page.locator('[data-testid="role-drawer"] [data-edit-action="project.read"]').click(); // toggle back on
await page.locator('[data-testid="role-drawer"] [data-testid^="save-role-"]').click();
await page.waitForFunction(
  () => {
    const row = document.querySelector('[data-role="reader-role"]');
    return row && !row.querySelector('[data-edit-action]') && row.textContent.includes("project.read");
  },
  null,
  { timeout: 10000 },
);
const widened = await asMachine(machineToken, "/organizations/acme/projects");
check("adding the action back widens without touching the grant", widened.ok, `status ${widened.status}`);

// Team CRUD: create, own a project.
await page.click('[data-testid="new-team"]');
await page.fill('[data-testid="team-name"]', "backend");
await page.click('[data-testid="create-team"]');
await page.waitForSelector('[data-team="backend"]', { timeout: 10000 });
await page.click('[data-team="backend"] [data-testid^="expand-team-"]'); // members and projects
await page.locator('[data-team="backend"] select[data-testid^="project-select-"]').selectOption({ label: "api" });
await page.locator('[data-team="backend"] [data-testid^="add-project-"]').click();
await page.waitForSelector('[data-team="backend"] [data-owned-project="api"]', { timeout: 10000 });
check("team owns a project", true);

// Restore default-deny for the sections that follow (Grants tab).
await page.click('[data-testid="access-tab-grants"]');
await page.waitForSelector('[data-grant-subject="readers"]', { timeout: 10000 });
await page.locator('[data-grant-subject="readers"] [data-testid^="revoke-grant-"]').click();
await confirmDialog();
await page.waitForFunction(
  () => !document.querySelector('[data-grant-subject="readers"]'),
  null,
  { timeout: 10000 },
);
const denyAfterRevoke = await asMachine(machineToken, "/organizations/acme/projects");
check("revoking the group grant denies the member again", !denyAfterRevoke.ok);

// 5d. Grant replace (ADR-0029): "editing" a grant keeps subject and scope
// and atomically swaps the permission — one operation, linked audit events.
await page.selectOption('[data-testid="grant-subject"]', { label: "ci-deployer" });
await page.selectOption('[data-testid="grant-permission"]', "preset:read-config");
await page.click('[data-testid="create-grant"]');
await page.waitForSelector('[data-grant-subject="ci-deployer"]', { timeout: 10000 });
await page.locator('[data-grant-subject="ci-deployer"] [data-testid^="edit-grant-"]').click();
await page.waitForSelector('[data-testid^="grant-editor-"]', { timeout: 10000 });
await page
  .locator('select[data-testid^="edit-grant-role-"]')
  .selectOption({ label: "reader-role" });
await page.locator('[data-testid^="save-grant-"]').click();
await page.waitForFunction(
  () => document.querySelector('[data-grant-subject="ci-deployer"]')?.textContent.includes("reader-role"),
  null,
  { timeout: 10000 },
);
check("replaced grant row now cites the role", true);
const replacedAccess = await asMachine(machineToken, "/organizations/acme/projects");
check("successor grant authorizes via the role", replacedAccess.ok, `status ${replacedAccess.status}`);
await page.locator('[data-grant-subject="ci-deployer"] [data-testid^="revoke-grant-"]').click();
await confirmDialog();
await page.waitForFunction(
  () => !document.querySelector('[data-grant-subject="ci-deployer"]'),
  null,
  { timeout: 10000 },
);

// 5e. Group and team renames happen in place (ADR-0029) — same id, members
// and owned projects intact. (Roles & teams tab; expansion state was reset
// by tab switches, so the team is re-expanded before asserting ownership.)
await page.click('[data-testid="access-tab-roles"]');
await page.waitForSelector('[data-group="readers"]', { timeout: 10000 });
await page.locator('[data-group="readers"] button[aria-label="Actions for readers"]').click();
await page.locator('[data-testid^="rename-group-"]').click();
await page.fill('[data-testid="prompt-input"]', "viewers");
await page.click('[data-testid="prompt-ok"]');
await page.waitForSelector('[data-group="viewers"]', { timeout: 10000 });
check("group renamed in place", true);
await page.locator('[data-team="backend"] button[aria-label="Actions for backend"]').click();
await page.locator('[data-testid^="rename-team-"]').click();
await page.fill('[data-testid="prompt-input"]', "platform");
await page.click('[data-testid="prompt-ok"]');
await page.waitForSelector('[data-team="platform"]', { timeout: 10000 });
if ((await page.locator('[data-team="platform"] [data-owned-project]').count()) === 0) {
  await page.click('[data-team="platform"] [data-testid^="expand-team-"]'); // list owned projects
}
await page.waitForSelector('[data-team="platform"] [data-owned-project="api"]', { timeout: 10000 });
check(
  "team renamed in place, still owning its project",
  (await page.locator('[data-team="platform"] [data-owned-project="api"]').count()) === 1,
);

// 6. Tailnet requirement (Advanced tab).
await page.click('[data-testid="access-tab-advanced"]');
await page.waitForSelector('[data-testid="requirements-section"]', { timeout: 10000 });
await page.click('[data-testid="add-requirement"]');
await page.fill('[data-testid="req-tailnet"]', "example.ts.net");
await page.fill('[data-testid="req-tags"]', "tag:prod");
await page.click('[data-testid="create-requirement"]');
await page.waitForSelector('[data-requirement]', { timeout: 10000 });
check("tailnet requirement listed", (await page.textContent('[data-requirement]')).includes("example.ts.net"));

// 6b. Requirement edit (ADR-0029): selector widened in place; loosening is
// exactly as audited as tightening.
await page.locator('[data-requirement] [data-testid^="edit-requirement-"]').click();
await page.locator('[data-requirement] input').nth(1).fill("tag:prod,tag:ci");
await page.locator('[data-requirement] [data-testid^="save-requirement-"]').click();
await page.waitForFunction(
  () => document.querySelector('[data-requirement]')?.textContent.includes("tag:ci"),
  null,
  { timeout: 10000 },
);
check("requirement selector edited in place", true);

// 6c. A requirement the form cannot represent (one Environment, devices
// pinned by node ID, as the API allows) is shown in full and cannot be
// edited: saving the tier/tag form over it would let more devices in.
const asHuman = (method, path, body) =>
  page.evaluate(
    async ({ method, path, body }) => {
      const { token } = await (await fetch("/auth/varlatch-token", { method: "POST", credentials: "include" })).json();
      const res = await fetch(`/v1${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      return { status: res.status, json: res.status === 204 ? null : await res.json() };
    },
    { method, path, body },
  );
const prodEnv = await asHuman("GET", "/organizations/acme/projects/api/environments/production");
const pinned = await asHuman("POST", "/organizations/acme/requirements", {
  kind: "tailnet",
  target: { kind: "environments", environmentIds: [prodEnv.json.id] },
  selector: { tailnet: "example.ts.net", nodes: ["nE2eDevice1CNTRL"] },
});
check("device-pinned requirement created through the API", pinned.status === 201, `status ${pinned.status}`);
await page.reload();
await page.waitForSelector('[data-testid="access-tab-advanced"]', { timeout: 20000 });
await page.click('[data-testid="access-tab-advanced"]');
const pinnedRow = `[data-requirement="${pinned.json.id}"]`;
await page.waitForSelector(`${pinnedRow} [data-target-environment]`, { timeout: 10000 });
const pinnedText = await page.textContent(pinnedRow);
check(
  "device-pinned requirement names its environment and device",
  pinnedText.includes("api / production") && pinnedText.includes("nE2eDevice1CNTRL"),
  pinnedText,
);
check(
  "device-pinned requirement cannot be edited in the form",
  await page.isDisabled(`${pinnedRow} [data-testid="edit-requirement-${pinned.json.id}"]`),
);
const removed = await asHuman("DELETE", `/organizations/acme/requirements/${pinned.json.id}`);
check("device-pinned requirement removed", removed.status === 204, `status ${removed.status}`);

// 7. Broker capabilities (ADR-0022): oversight list + revoke-from-dashboard.
// Broker/agent identities are created on the Machines tab first.
await page.click('[data-testid="access-tab-machines"]');
await page.waitForSelector('[data-testid="machines-section"]', { timeout: 10000 });
await createMachine("ui-broker", "broker");
await page.waitForSelector('[data-testid="one-time-credential"]', { timeout: 10000 });
const brokerToken = (await page.textContent('[data-testid="one-time-credential-token"]')).trim();
await page.click('[data-testid="dismiss-credential"]');
await createMachine("ui-agent", "agent");
await page.waitForSelector('[data-identity="ui-agent"]', { timeout: 10000 });
const agentId = await page.getAttribute('[data-identity="ui-agent"]', "data-identity-id");

const capRes = await fetch(
  `${base}/v1/organizations/acme/projects/api/environments/development/capabilities`,
  {
    method: "POST",
    headers: { Authorization: `Bearer ${brokerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      agentIdentityId: agentId,
      items: ["DATABASE_URL"],
      destinations: ["api.example.com"],
      targets: { DATABASE_URL: ["header:authorization"] },
      ttlSeconds: 600,
      runId: "run_ui_e2e",
    }),
  },
);
const cap = await capRes.json();
check("broker issued a capability for the UI test", capRes.status === 201, `status ${capRes.status}`);

await page.reload();
await page.waitForSelector('[data-testid="access-tab-advanced"]', { timeout: 20000 });
await page.click('[data-testid="access-tab-advanced"]');
await page.waitForSelector('[data-testid="capabilities-section"]', { timeout: 20000 });
await page.selectOption('[data-testid="capability-project"]', "api");
await page.selectOption('[data-testid="capability-environment"]', "development");
await page.waitForSelector(`[data-capability="${cap.id}"]`, { timeout: 10000 });
const capRow = await page.textContent(`[data-capability="${cap.id}"]`);
check(
  "capability row shows agent, broker, items, destination, run",
  capRow.includes("ui-agent") &&
    capRow.includes("ui-broker") &&
    capRow.includes("DATABASE_URL") &&
    capRow.includes("api.example.com:443") &&
    capRow.includes("run_ui_e2e"),
);
await page.click(`[data-testid="revoke-capability-${cap.id}"]`);
await confirmDialog();
await page.waitForFunction(
  (id) => document.querySelector(`[data-capability="${id}"]`)?.textContent.includes("revoked"),
  cap.id,
  { timeout: 10000 },
);
check("capability revoked from the dashboard", true);
const postRevoke = await fetch(
  `${base}/v1/organizations/acme/projects/api/environments/development/capabilities/${cap.id}/exercises`,
  {
    method: "POST",
    headers: { Authorization: `Bearer ${brokerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      capabilitySecret: cap.secret,
      destination: { host: "api.example.com", port: 443 },
      placements: [{ item: "DATABASE_URL", target: "header:authorization" }],
    }),
  },
);
check("dashboard revocation denies the next exercise", postRevoke.status === 403, `status ${postRevoke.status}`);

// 8. My credentials: current session visible and marked.
await page.goto(`${base}/credentials`);
await page.waitForSelector('[data-testid="credentials-list"]', { timeout: 20000 });
// The list renders before its rows load; wait for the marker, not the box.
const marked = await page
  .waitForFunction(() => document.querySelector('[data-testid="credentials-list"]')?.textContent?.includes("this session"), null, { timeout: 20000 })
  .then(() => true, () => false);
check("own credential listed with session marker", marked);

await browser.close();
process.exit(failed ? 1 : 0);
