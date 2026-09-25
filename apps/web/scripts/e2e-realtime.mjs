#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Degraded realtime E2E (ADR-0035 D10). With convex-backend stopped, the
 * dashboard says live updates are reconnecting, keeps showing changes made
 * elsewhere by polling /v1, and still writes; CLI `env list` and `run` and
 * the whole credential broker E2E (ADR-0022) work. With it started again,
 * the indicator clears and live signals drive updates again. No page reload.
 *
 * Usage: e2e-realtime.mjs <enroll-url> <api-token> -- <docker compose command...>
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";

const sep = process.argv.indexOf("--");
const [enrollUrl, apiToken] = process.argv.slice(2, sep < 0 ? undefined : sep);
const compose = sep < 0 ? [] : process.argv.slice(sep + 1);
if (!enrollUrl?.includes("#") || !apiToken || compose.length < 2) {
  console.error("Usage: e2e-realtime.mjs <enroll-url> <api-token> -- <docker compose command...>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
const cliPath = new URL("../../cli/dist/varlatch.cjs", import.meta.url).pathname;
const brokerE2e = new URL("../../../services/varlatchd/scripts/e2e-broker.mjs", import.meta.url).pathname;
const suffix = randomBytes(3).toString("hex");

let failed = false;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failed = true;
};
const dc = (...args) => {
  const r = spawnSync(compose[0], [...compose.slice(1), ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`docker compose ${args.join(" ")} failed: ${r.stderr}`);
};
const createProject = (slug) =>
  fetch(`${base}/v1/organizations/acme/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ slug, name: slug, contractAuthority: "git" }),
  }).then((r) => r.status);
const card = (slug) => `[data-testid="project-card"][data-slug="${slug}"]`;
const indicator = '[data-testid="live-updates-status"]';
const since = (t) => `${Math.round((Date.now() - t) / 100) / 10} s`;

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
let convexStopped = false;
try {
  await page.goto(enrollUrl);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
  await page.goto(`${base}/o/acme/projects`);
  await page.waitForSelector('[data-testid="project-card"]', { timeout: 20000 });
  await page.evaluate(() => { window.__varlatchNoReload = true; });
  await page.waitForTimeout(6000); // past the grace period
  check("no indicator while live updates work", (await page.locator(indicator).count()) === 0);

  // ---- Convex down.
  dc("stop", "convex-backend");
  convexStopped = true;
  let t = Date.now();
  await page.waitForSelector(indicator, { timeout: 30000 });
  check("the dashboard says live updates are reconnecting", /Live updates reconnecting/.test(await page.textContent(indicator)), `${since(t)}: ${await page.textContent(indicator)}`);

  const byApi = `rt-down-${suffix}`;
  check("the API accepts a change while Convex is down", (await createProject(byApi)) === 201);
  t = Date.now();
  await page.waitForSelector(card(byApi), { timeout: 30000 });
  check("a change made elsewhere shows up by polling /v1", true, since(t));

  const byUi = `rt-ui-${suffix}`;
  await page.fill('[data-testid="new-project-slug"]', byUi);
  await page.click('[data-testid="create-project"]');
  await page.waitForSelector(card(byUi), { timeout: 15000 });
  check("the dashboard writes while Convex is down", true);

  const cfg = mkdtempSync(join(tmpdir(), "realtime-e2e-cfg-"));
  const repo = mkdtempSync(join(tmpdir(), "realtime-e2e-repo-"));
  const cli = (...args) => spawnSync("node", [cliPath, ...args], { cwd: repo, env: { ...process.env, VARLATCH_CONFIG_DIR: cfg }, encoding: "utf8", timeout: 60000 });
  cli("init", "--org", "acme", "--project", "api", "--server", base);
  cli("login", "--server", base, "--token", apiToken);
  const list = cli("env", "list");
  check("CLI env list works while Convex is down", list.status === 0 && /development/.test(list.stdout), (list.stdout + list.stderr).trim().slice(0, 160));
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
  check("CLI run injects the current value while Convex is down", written < 300 && run.status === 0 && run.stdout.includes(`PORT=${changed}`), (run.stdout + run.stderr).trim().slice(0, 160));
  if (before) await setPort(before);

  console.log("--- credential broker E2E (ADR-0022), with Convex down");
  const broker = spawnSync("node", [brokerE2e, base, apiToken], { encoding: "utf8", timeout: 300000 });
  process.stdout.write(broker.stdout.split("\n").map((l) => (l ? `  ${l}` : l)).join("\n"));
  check("the credential broker E2E passes while Convex is down", broker.status === 0, broker.status === 0 ? "" : broker.stderr.slice(-300));

  // ---- Convex back.
  dc("start", "convex-backend");
  convexStopped = false;
  t = Date.now();
  await page.waitForSelector(indicator, { state: "detached", timeout: 120000 });
  check("the indicator clears when Convex returns", true, since(t));
  const live = `rt-live-${suffix}`;
  await createProject(live);
  t = Date.now();
  // Polling stopped with the reconnect: only a live signal brings this in.
  await page.waitForSelector(card(live), { timeout: 45000 });
  check("live signals drive updates again", true, since(t));
  check("no page reload throughout", await page.evaluate(() => window.__varlatchNoReload === true));
} catch (err) {
  check("degraded realtime E2E", false, String(err).slice(0, 300));
} finally {
  if (convexStopped) { try { dc("start", "convex-backend"); } catch { /* reported above */ } }
  await browser.close();
}
process.exit(failed ? 1 : 0);
