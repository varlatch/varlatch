#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
import { cliPath as cliUnderTest, reporter, targetOp } from "../../../scripts/conformance/suite-kit.mjs";
/**
 * Degraded realtime E2E (ADR-0035 D10). With convex-backend stopped, the
 * dashboard says live updates are reconnecting, keeps showing changes made
 * elsewhere by polling /v1, and still writes; CLI `env list` and `run`
 * work. With it started again, the indicator clears and live signals drive
 * updates again. No page reload. (The credential broker E2E, which used to
 * run from here, is its own suite; on the TypeScript stack the runner keeps
 * Convex stopped while it runs.)
 *
 * Usage: e2e-realtime.mjs <enroll-url> <api-token>
 * Run by scripts/conformance/run.mjs against a target with the ts-stack
 * capability (it stops and starts the TypeScript stack's Convex backend).
 */
import { spawnSync } from "node:child_process";
import { watchCsp } from "./e2e-csp.mjs";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const [enrollUrl, apiToken] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || !apiToken) {
  console.error("Usage: e2e-realtime.mjs <enroll-url> <api-token>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
// The CLI under test (VARLATCH_CLI), set by scripts/conformance/run.mjs.
const cliPath = cliUnderTest();
const suffix = randomBytes(3).toString("hex");

const { check, error, finish } = reporter();
// docker compose, through the target's ts-stack capability.
const dc = (...args) => targetOp("ts-stack", ["compose", ...args]);
const createProject = (slug) =>
  fetch(`${base}/v1/organizations/acme/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ slug, name: slug, contractAuthority: "git" }),
  }).then((r) => r.status);
const card = (slug) => `[data-testid="project-row"][data-slug="${slug}"]`;
const indicator = '[data-testid="live-updates-status"]';
const since = (t) => `${Math.round((Date.now() - t) / 100) / 10} s`;

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
let convexStopped = false;
try {
  await page.goto(enrollUrl);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
  await page.goto(`${base}/o/acme/projects`);
  await page.waitForSelector('[data-testid="project-row"]', { timeout: 20000 });
  await page.evaluate(() => { window.__varlatchNoReload = true; });
  await page.waitForTimeout(6000); // past the grace period
  check("realtime.no-indicator-live-updates-work", "no indicator while live updates work", (await page.locator(indicator).count()) === 0);

  // ---- Convex down.
  dc("stop", "convex-backend");
  convexStopped = true;
  let t = Date.now();
  await page.waitForSelector(indicator, { timeout: 30000 });
  check("realtime.dashboard-says-live-updates-reconnecting", "the dashboard says live updates are reconnecting", /Live updates reconnecting/.test(await page.textContent(indicator)), `${since(t)}: ${await page.textContent(indicator)}`);

  const byApi = `rt-down-${suffix}`;
  check("realtime.api-accepts-change-convex-down", "the API accepts a change while Convex is down", (await createProject(byApi)) === 201);
  t = Date.now();
  await page.waitForSelector(card(byApi), { timeout: 30000 });
  check("realtime.change-made-elsewhere-shows-up-polling", "a change made elsewhere shows up by polling /v1", true, since(t));

  const byUi = `rt-ui-${suffix}`;
  await page.click('[data-testid="new-project"]');
  await page.fill('[data-testid="new-project-slug"]', byUi);
  await page.click('[data-testid="create-project"]');
  // Creating opens the new project; come back in-app (no reload).
  await page.waitForURL(`**/o/acme/p/${byUi}`, { timeout: 15000 });
  await page.click('nav a[href="/o/acme/projects"]');
  await page.waitForSelector(card(byUi), { timeout: 15000 });
  check("realtime.dashboard-writes-convex-down", "the dashboard writes while Convex is down", true);

  const cfg = mkdtempSync(join(tmpdir(), "realtime-e2e-cfg-"));
  const repo = mkdtempSync(join(tmpdir(), "realtime-e2e-repo-"));
  const cli = (...args) => spawnSync("node", [cliPath, ...args], { cwd: repo, env: { ...process.env, VARLATCH_CONFIG_DIR: cfg }, encoding: "utf8", timeout: 60000 });
  cli("init", "--org", "acme", "--project", "api", "--server", base);
  cli("login", "--server", base, "--token", apiToken);
  const list = cli("env", "list");
  check("realtime.cli-env-list-works-convex-down", "CLI env list works while Convex is down", list.status === 0 && /development/.test(list.stdout), (list.stdout + list.stderr).trim().slice(0, 160));
  const port = () => cli("run", "-e", "development", "--", "node", "-e", "process.stdout.write('PORT=' + (process.env.PORT ?? ''))");
  const setPort = (value) => fetch(`${base}/v1/organizations/acme/projects/api/environments/development/values/PORT`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  }).then((r) => r.status);
  const before = port().stdout.match(/PORT=(\S*)/)?.[1];
  const changed = String(40000 + Math.floor(Math.random() * 10000));
  const written = await setPort(changed);
  const run = port();
  check("realtime.cli-run-injects-current-value-convex", "CLI run injects the current value while Convex is down", written < 300 && run.status === 0 && run.stdout.includes(`PORT=${changed}`), (run.stdout + run.stderr).trim().slice(0, 160));
  if (before) await setPort(before);

  // ---- Convex back.
  dc("start", "convex-backend");
  convexStopped = false;
  t = Date.now();
  await page.waitForSelector(indicator, { state: "detached", timeout: 120000 });
  check("realtime.indicator-clears-convex-returns", "the indicator clears when Convex returns", true, since(t));
  const live = `rt-live-${suffix}`;
  await createProject(live);
  t = Date.now();
  // Polling stopped with the reconnect: only a live signal brings this in.
  await page.waitForSelector(card(live), { timeout: 45000 });
  check("realtime.live-signals-drive-updates-again", "live signals drive updates again", true, since(t));
  check("realtime.no-page-reload-throughout", "no page reload throughout", await page.evaluate(() => window.__varlatchNoReload === true));
} catch (err) {
  error(`degraded realtime E2E: ${String(err).slice(0, 300)}`);
} finally {
  if (convexStopped) { try { dc("start", "convex-backend"); } catch { /* reported above */ } }
  check("realtime.no-content-security-policy-violations", "no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
  await browser.close();
}
finish();
