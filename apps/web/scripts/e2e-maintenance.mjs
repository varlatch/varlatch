#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
import { cliPath as cliUnderTest, reporter, targetOp } from "../../../scripts/conformance/suite-kit.mjs";
/**
 * Isolating maintenance E2E (ADR-0036 D6). The installation is put into the
 * same `503 MAINTENANCE` admission a restore uses, for a short lease:
 * - a signed-in dashboard shows the maintenance banner, not the sign-in
 *   screen, and recovers without a reload;
 * - a dashboard opened during the window shows the maintenance screen, then
 *   continues into the app by itself;
 * - the CLI says once, on stderr, that it is waiting, and succeeds after.
 *
 * Usage: e2e-maintenance.mjs <enroll-url> <api-token>
 * Run by scripts/conformance/run.mjs against a target with the maintenance
 * capability, which opens the window.
 */
import { spawn, spawnSync } from "node:child_process";
import { watchCsp } from "./e2e-csp.mjs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const [enrollUrl, apiToken] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !apiToken) {
  console.error("Usage: e2e-maintenance.mjs <enroll-url> <api-token>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
// The CLI under test (VARLATCH_CLI), set by scripts/conformance/run.mjs.
const cliPath = cliUnderTest();
const LEASE_MS = 20_000;

const { check, error, finish, supports } = reporter();
const since = (t) => `${Math.round((Date.now() - t) / 100) / 10} s`;
// The target's maintenance operation: the admission a restore uses, for a lease.
const gate = () => {
  try {
    targetOp("maintenance", [String(LEASE_MS)]);
  } catch (err) {
    throw new Error(`could not open a maintenance window: ${err.message}`);
  }
};

const browser = await chromium.launch();
const context = await browser.newContext();
const cspViolations = watchCsp(context);
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
try {
  await page.goto(enrollUrl);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
  await page.goto(`${base}/o/acme/projects`);
  await page.waitForSelector('[data-testid="project-row"]', { timeout: 20000 });
  await page.evaluate(() => { window.__varlatchNoReload = true; });

  const cfg = mkdtempSync(join(tmpdir(), "maint-e2e-cfg-"));
  const repo = mkdtempSync(join(tmpdir(), "maint-e2e-repo-"));
  const cliEnv = { ...process.env, VARLATCH_CONFIG_DIR: cfg };
  spawnSync("node", [cliPath, "init", "--org", "acme", "--project", "api", "--server", base], { cwd: repo, env: cliEnv });
  spawnSync("node", [cliPath, "login", "--server", base, "--token", apiToken], { cwd: repo, env: cliEnv });

  // ---- The window opens.
  const opened = Date.now();
  gate();

  // A signed-in page: the next request meets MAINTENANCE.
  await page.click('nav a[href="/o/acme/audit"]');
  await page.waitForSelector('[data-testid="maintenance-status"]', { timeout: 15000 });
  check("maintenance.signed-in-dashboard-shows-maintenance-banner", "a signed-in dashboard shows the maintenance banner", true, since(opened));
  check("maintenance.not-sign-in-screen", "…and not the sign-in screen", (await page.getByText("Sign in with passkey").count()) === 0);

  // A page opened during the window: its session exchange meets MAINTENANCE.
  const fresh = await context.newPage();
  await fresh.goto(`${base}/o/acme/projects`);
  await fresh.waitForSelector('[data-testid="maintenance-screen"]', { timeout: 15000 });
  check("maintenance.dashboard-opened-during-maintenance-shows", "a dashboard opened during maintenance shows the maintenance screen, not sign-in",
    (await fresh.getByText("Sign in with passkey").count()) === 0);
  await fresh.evaluate(() => { window.__varlatchNoReload = true; });

  // The CLI waits, says so once on stderr, and succeeds after the window.
  // Its own feature group: a CLI that predates waiting skips only this.
  if (supports("maintenance-wait")) {
    const run = await new Promise((resolve) => {
      const child = spawn("node", [cliPath, "env", "list"], { cwd: repo, env: cliEnv });
      let stdout = "", stderr = "";
      child.stdout.on("data", (d) => { stdout += d; });
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("exit", (code) => resolve({ code, stdout, stderr }));
    });
    const notices = (run.stderr.match(/in maintenance/g) ?? []).length;
    check("maintenance.cli-waits-out-maintenance-succeeds", "the CLI waits out maintenance and succeeds", run.code === 0 && /development/.test(run.stdout), `exit ${run.code}, ${since(opened)}`);
    check("maintenance.saying-once-stderr-only", "…saying so once, on stderr only", notices === 1 && !/maintenance/.test(run.stdout), run.stderr.trim().slice(0, 160));
  }

  // ---- The window has closed: both pages continue without a reload.
  await fresh.waitForSelector('[data-testid="project-row"]', { timeout: LEASE_MS + 30000 });
  check("maintenance.page-opened-during-maintenance-continues-app", "the page opened during maintenance continues into the app by itself", await fresh.evaluate(() => window.__varlatchNoReload === true), since(opened));
  await page.waitForSelector('[data-testid="maintenance-status"]', { state: "detached", timeout: 30000 });
  check("maintenance.banner-clears-once-installation-answers-again", "the banner clears once the installation answers again", await page.evaluate(() => window.__varlatchNoReload === true), since(opened));
} catch (err) {
  error(`maintenance E2E: ${String(err).slice(0, 300)}`);
} finally {
  check("maintenance.no-content-security-policy-violations", "no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
  await browser.close();
}
finish();
