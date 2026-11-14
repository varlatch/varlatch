#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The enroll page's next steps after an invitation (ADR-0058 Decision 4),
 * in a real browser against a stub server: varlatchd's own ENROLL_HTML,
 * a stand-in enroll.js that "creates" a passkey, and /v1/meta answering
 * per case. The verified route shows at once; the install line appears
 * only when /v1/meta lists cli.download; a failing or stalled /v1/meta
 * never holds the page; the CLI hand-off never asks /v1/meta.
 *
 *   node apps/web/scripts/e2e-enroll-steps.mjs [chromium executable]
 *
 * Node 22.18 or newer: it imports the TypeScript page source directly.
 * A component check: it tests this checkout's page, not the server under
 * test (scripts/conformance/inventory.json); the target's own enroll page is
 * checked by dashboard.enroll-steps-match-meta in e2e-web.mjs.
 */
import { createServer } from "node:http";
import { chromium } from "playwright";
import { ENROLL_HTML } from "../../../services/varlatchd/src/enroll/page.ts";
import { reporter } from "../../../scripts/conformance/suite-kit.mjs";

const kit = reporter();
const { check } = kit;

let meta = "on";
let metaRequests = 0;
const stalled = [];
const credential = { token: "vlt_ses_stub", identityId: "idn_stub" };
const server = createServer((req, res) => {
  if (req.url.startsWith("/enroll.js")) {
    res.writeHead(200, { "Content-Type": "text/javascript" });
    res.end(`const r = () => ({ token: ${JSON.stringify(credential.token)}, identityId: ${JSON.stringify(credential.identityId)}, expiresAt: new Date(Date.now() + 600000).toISOString() });
window.varlatch = { enroll: async () => r(), signIn: async () => r() };`);
  } else if (req.url === "/v1/meta") {
    metaRequests++;
    if (meta === "stalled") { stalled.push(res); return; }
    if (meta === "error") { res.writeHead(500); res.end(); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ capabilities: meta === "on" ? ["cli.download"] : [] }));
  } else if (req.url.startsWith("/enroll")) {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(ENROLL_HTML);
  } else if (req.url === "/cb") {
    res.writeHead(200, { "Access-Control-Allow-Origin": "*" });
    res.end();
  } else {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch(process.argv[2] ? { executablePath: process.argv[2] } : {});

async function enroll(mode) {
  meta = mode;
  metaRequests = 0;
  const page = await browser.newPage();
  await page.goto(`${base}/enroll#invite-token`);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 2000 });
  return page;
}
const text = (page) => page.textContent("#status");

try {
  {
    const page = await enroll("on");
    await page.waitForFunction(() => /install\.sh/.test(document.getElementById("status").textContent), null, { timeout: 5000 });
    const steps = await text(page);
    check("enroll-steps.cli-download-install-sh-line", "with cli.download: the install.sh line", steps.includes(`curl -fsSL ${base}/install.sh | sh`));
    await page.click('button[data-os="windows"]');
    check("enroll-steps.windows-tab-shows-install-ps1-line", "the Windows tab shows the install.ps1 line", (await text(page)).includes(`irm ${base}/install.ps1 | iex`));
    check("enroll-steps.sign-in-run-steps", "the sign-in and run steps", /2\. Sign in from your terminal/.test(steps) && /varlatch run -- <your command>/.test(steps));
    await page.close();
  }
  const verifiedOnly = { off: "enroll-steps.meta-off-verified-route-only", error: "enroll-steps.meta-error-verified-route-only" };
  for (const mode of ["off", "error"]) {
    const page = await enroll(mode);
    await page.waitForTimeout(500);
    const steps = await text(page);
    check(verifiedOnly[mode], `/v1/meta ${mode}: the verified route only`, /Install it from its signed release/.test(steps) && !/install\.sh/.test(steps));
    await page.close();
  }
  {
    // The steps render while /v1/meta never answers.
    const page = await enroll("stalled");
    const steps = await text(page);
    check("enroll-steps.stalled-meta-never-holds-steps", "a stalled /v1/meta never holds the steps", /1\. Install the CLI/.test(steps) && /Install it from its signed release/.test(steps) && /varlatch login --server/.test(steps));
    check("enroll-steps.credential-shown-while-meta-stalls", "the credential is on the page while /v1/meta stalls", /API credential/.test(steps));
    await page.close();
  }
  {
    meta = "on";
    metaRequests = 0;
    const page = await browser.newPage();
    await page.goto(`${base}/enroll?callback=${encodeURIComponent(`${base}/cb`)}`);
    await page.click("#signin");
    await page.waitForFunction(() => /terminal|failed/.test(document.getElementById("status").textContent), null, { timeout: 5000 });
    check("enroll-steps.cli-hand-off-completes", "the CLI hand-off still completes", /terminal/.test(await text(page)));
    await page.waitForTimeout(500);
    check("enroll-steps.cli-hand-off-never-asks-meta", "the CLI hand-off never asks /v1/meta", metaRequests === 0);
    await page.close();
  }
} finally {
  for (const res of stalled) res.destroy();
  await browser.close();
  server.close();
}
if (kit.failures === 0) console.log("enroll page next steps: all checks passed");
kit.finish("check(s)");
