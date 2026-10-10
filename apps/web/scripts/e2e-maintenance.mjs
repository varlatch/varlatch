#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Isolating maintenance E2E (ADR-0036 D6). The installation is put into the
 * same `503 MAINTENANCE` admission a restore uses, for a short lease:
 * - a signed-in dashboard shows the maintenance banner, not the sign-in
 *   screen, and recovers without a reload;
 * - a dashboard opened during the window shows the maintenance screen, then
 *   continues into the app by itself;
 * - the CLI says once, on stderr, that it is waiting, and succeeds after.
 *
 * Usage: e2e-maintenance.mjs <enroll-url> <api-token> -- <docker compose command...>
 */
import { spawn, spawnSync } from "node:child_process";
import { watchCsp } from "./e2e-csp.mjs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const sep = process.argv.indexOf("--");
const [enrollUrl, apiToken] = process.argv.slice(2, sep < 0 ? undefined : sep);
const compose = sep < 0 ? [] : process.argv.slice(sep + 1);
if (!enrollUrl?.includes("#") || !apiToken || compose.length < 2) {
  console.error("Usage: e2e-maintenance.mjs <enroll-url> <api-token> -- <docker compose command...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
const cliPath = new URL("../../cli/dist/varlatch.cjs", import.meta.url).pathname;
const LEASE_MS = 20_000;

let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};
const since = (t) => `${Math.round((Date.now() - t) / 100) / 10} s`;
const gate = () => {
  const r = spawnSync(compose[0], [...compose.slice(1), "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "backup-control", "capture-begin"],
    { input: JSON.stringify({ ttlMs: LEASE_MS }), encoding: "utf8" });
  if (r.status !== 0) throw new Error(`could not open a maintenance window: ${r.stdout}${r.stderr}`);
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
  check("a signed-in dashboard shows the maintenance banner", true, since(opened));
  check("…and not the sign-in screen", (await page.getByText("Sign in with passkey").count()) === 0);

  // A page opened during the window: its session exchange meets MAINTENANCE.
  const fresh = await context.newPage();
  await fresh.goto(`${base}/o/acme/projects`);
  await fresh.waitForSelector('[data-testid="maintenance-screen"]', { timeout: 15000 });
  check("a dashboard opened during maintenance shows the maintenance screen, not sign-in",
    (await fresh.getByText("Sign in with passkey").count()) === 0);
  await fresh.evaluate(() => { window.__varlatchNoReload = true; });

  // The CLI waits, says so once on stderr, and succeeds after the window.
  const run = await new Promise((resolve) => {
    const child = spawn("node", [cliPath, "env", "list"], { cwd: repo, env: cliEnv });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
  const notices = (run.stderr.match(/in maintenance/g) ?? []).length;
  check("the CLI waits out maintenance and succeeds", run.code === 0 && /development/.test(run.stdout), `exit ${run.code}, ${since(opened)}`);
  check("…saying so once, on stderr only", notices === 1 && !/maintenance/.test(run.stdout), run.stderr.trim().slice(0, 160));

  // ---- The window has closed: both pages continue without a reload.
  await fresh.waitForSelector('[data-testid="project-row"]', { timeout: LEASE_MS + 30000 });
  check("the page opened during maintenance continues into the app by itself", await fresh.evaluate(() => window.__varlatchNoReload === true), since(opened));
  await page.waitForSelector('[data-testid="maintenance-status"]', { state: "detached", timeout: 30000 });
  check("the banner clears once the installation answers again", await page.evaluate(() => window.__varlatchNoReload === true), since(opened));
} catch (err) {
  check("maintenance E2E", false, String(err).slice(0, 300));
} finally {
  check("no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
  await browser.close();
}
process.exit(failed ? 1 : 0);
