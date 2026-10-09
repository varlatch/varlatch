#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Live E2E for device sign-in (design notes "Device-authorization
 * sign-in"): the built CLI starts a sign-in, a person approves it on the
 * dashboard's /device page with a passkey (a virtual authenticator), and
 * the CLI collects and stores the credential; then a denial, a wrong code,
 * and an approval without a passkey that therefore does not happen.
 * Usage: node scripts/e2e-device.mjs <recovery-enroll-url-on-dashboard-origin>
 */
import { spawn } from "node:child_process";
import { watchCsp } from "./e2e-csp.mjs";
import { existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const enrollUrl = process.argv[2];
if (!enrollUrl?.includes("#")) {
  console.error("Usage: e2e-device.mjs <http://localhost:8787/enroll#vlt_setup_...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
const cliPath = new URL("../../cli/dist/main.js", import.meta.url).pathname;
const config = mkdtempSync(join(tmpdir(), "varlatch-device-e2e-"));

let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};

function cli(args, env = {}) {
  return new Promise((resolve, reject) => {
    // A clean environment: no coding-agent markers, so only --assisted turns assisted mode on.
    const child = spawn(process.execPath, [cliPath, ...args], {
      env: { PATH: process.env.PATH ?? "", HOME: config, VARLATCH_CONFIG_DIR: config, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
const pendingFile = join(config, "pending-sign-ins.json");
const pendingEntry = () => (existsSync(pendingFile) ? Object.values(JSON.parse(readFileSync(pendingFile, "utf8")).servers)[0] : undefined);

const browser = await chromium.launch();
const context = await browser.newContext();
const cspViolations = watchCsp(context);
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
const authenticator = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});
page.on("console", (m) => {
  if (m.type() === "error") console.log(`  [browser] ${m.text().slice(0, 160)}`);
});

// 1. Enroll a passkey on the dashboard origin: the session cookie is first-party.
await page.goto(enrollUrl);
await page.click("#enroll");
await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
check("passkey enrolled", /API credential/.test(await page.textContent("#status")));

// 2. The CLI starts a sign-in: address and code printed, the device code only in the 0600 file.
const started = await cli(["login", "--server", base, "--start", "--json"]);
const doc = started.code === 0 ? JSON.parse(started.stdout) : {};
const entry = pendingEntry();
check("login --start exits 0 with the address and code", started.code === 0 && doc.verificationUri === `${base}/device` && /^[A-Z]{4}-[A-Z]{4}$/.test(doc.userCode ?? ""), `${started.code} ${started.stderr.trim()}`);
check("the device code is only in the pending file", Boolean(entry?.deviceCode) && !started.stdout.includes(entry.deviceCode) && !started.stderr.includes(entry.deviceCode));
check("the pending file is 0600 in a 0700 directory", (statSync(pendingFile).mode & 0o777) === 0o600 && (statSync(config).mode & 0o777) === 0o700);

// 3. Before approval, --wait reaches its deadline with the sign-in pending: 75.
const early = await cli(["login", "--server", base, "--wait", "--timeout", "3"]);
check("login --wait before approval exits 75 and keeps the entry", early.code === 75 && Boolean(pendingEntry()), `${early.code} ${early.stderr.trim().split("\n").pop()}`);

// 4. The verification page: never cached, never prefilled from the URL.
const response = await page.goto(`${base}/device?code=${doc.userCode}&user_code=${doc.userCode}`);
check("GET /device is served with Cache-Control: no-store", response?.headers()["cache-control"] === "no-store", response?.headers()["cache-control"]);
await page.waitForSelector('[data-testid="device-code-input"]', { timeout: 20000 });
check("the code is never prefilled from the URL", (await page.inputValue('[data-testid="device-code-input"]')) === "");

// 5. A wrong code is refused.
await page.fill('[data-testid="device-code-input"]', "BBBB-BBBB");
await page.click('[data-testid="device-continue"]');
await page.waitForSelector("text=No pending sign-in has this code", { timeout: 10000 });
check("a wrong code is refused", true);

// 6. The right code, typed lower-case without the dash: the confirmation names who asks.
await page.fill('[data-testid="device-code-input"]', doc.userCode.replace("-", "").toLowerCase());
await page.click('[data-testid="device-continue"]');
await page.waitForSelector('[data-testid="device-confirm"]', { timeout: 10000 });
const confirmText = await page.textContent('[data-testid="device-confirm"]');
check("the confirmation says the CLI signs in as you, for how long", /A Varlatch CLI asks to sign in as you/.test(confirmText) && /for 12 hours/.test(confirmText) && /Approve only a sign-in you started yourself/.test(confirmText));
check("the confirmation names the requester's address and user agent", (await page.textContent('[data-testid="device-detail-agent"]'))?.startsWith("varlatch-cli/") && Boolean((await page.textContent('[data-testid="device-detail-ip"]'))?.trim()));

// 7. Approve with the passkey; the CLI collects and stores the credential.
await page.click('[data-testid="device-approve"]');
await page.waitForSelector('[data-testid="device-result"]', { timeout: 20000 });
check("approval with a fresh passkey assertion", (await page.getAttribute('[data-testid="device-result"]', "data-decision")) === "approved");
const waited = await cli(["login", "--server", base, "--wait"]);
const stored = existsSync(join(config, "credentials.json")) ? JSON.parse(readFileSync(join(config, "credentials.json"), "utf8")).servers[base] : undefined;
check("login --wait exits 0 and stores the credential", waited.code === 0 && /Logged in to/.test(waited.stdout) && stored?.token?.startsWith("vlt_cli_"), `${waited.code} ${waited.stderr.trim()}`);
check("the credential never appears in the CLI's output", Boolean(stored) && !waited.stdout.includes(stored.token) && !waited.stderr.includes(stored.token));
check("the pending entry is removed", !pendingEntry());
const orgs = await fetch(`${base}/v1/organizations`, { headers: { Authorization: `Bearer ${stored?.token}` } });
check("the stored credential works", orgs.status === 200, String(orgs.status));
const again = await cli(["login", "--server", base, "--wait"]);
check("a second --wait finds nothing to collect (64)", again.code === 64, String(again.code));

// 8. A denial: the CLI is told, nothing is stored, the existing credential stays.
const second = JSON.parse((await cli(["--assisted", "login", "--server", base, "--json"])).stdout);
check("assisted login with no method starts a device sign-in", /^[A-Z]{4}-[A-Z]{4}$/.test(second.userCode ?? ""));
await page.goto(`${base}/device`);
await page.fill('[data-testid="device-code-input"]', second.userCode);
await page.click('[data-testid="device-continue"]');
await page.waitForSelector('[data-testid="device-confirm"]', { timeout: 10000 });
await page.click('[data-testid="device-deny"]');
await page.waitForSelector('[data-testid="device-result"]', { timeout: 10000 });
check("denial recorded", (await page.getAttribute('[data-testid="device-result"]', "data-decision")) === "denied");
const denied = await cli(["login", "--server", base, "--wait"]);
const after = JSON.parse(readFileSync(join(config, "credentials.json"), "utf8")).servers[base];
check("login --wait after a denial exits 77 and keeps the existing credential", denied.code === 77 && /denied/.test(denied.stderr) && after?.token === stored?.token, `${denied.code}`);

// 9. Without the passkey the signed-in session cannot approve: the sign-in stays pending.
const third = JSON.parse((await cli(["login", "--server", base, "--start", "--json"])).stdout);
await page.goto(`${base}/device`);
await page.fill('[data-testid="device-code-input"]', third.userCode);
await page.click('[data-testid="device-continue"]');
await page.waitForSelector('[data-testid="device-confirm"]', { timeout: 10000 });
// The authenticator forgets its passkey: the browser can produce no assertion.
await cdp.send("WebAuthn.clearCredentials", { authenticatorId: authenticator.authenticatorId });
await page.click('[data-testid="device-approve"]');
await page.waitForSelector('[data-testid="device-error"]', { timeout: 90000 });
check("no passkey, no approval", /did not complete/.test(await page.textContent('[data-testid="device-error"]')));
const stillPending = await cli(["login", "--server", base, "--wait", "--timeout", "2"]);
check("the sign-in is still pending (75)", stillPending.code === 75, String(stillPending.code));

check("no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
await browser.close();
if (failed) process.exit(1);
