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
 */
import { createServer } from "node:http";
import { chromium } from "playwright";
import { ENROLL_HTML } from "../../../services/varlatchd/src/enroll/page.ts";

const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failures.push(what);
};

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
    check(steps.includes(`curl -fsSL ${base}/install.sh | sh`), "with cli.download: the install.sh line");
    await page.click('button[data-os="windows"]');
    check((await text(page)).includes(`irm ${base}/install.ps1 | iex`), "the Windows tab shows the install.ps1 line");
    check(/2\. Sign in from your terminal/.test(steps) && /varlatch run -- <your command>/.test(steps), "the sign-in and run steps");
    await page.close();
  }
  for (const mode of ["off", "error"]) {
    const page = await enroll(mode);
    await page.waitForTimeout(500);
    const steps = await text(page);
    check(/Install it from its signed release/.test(steps) && !/install\.sh/.test(steps), `/v1/meta ${mode}: the verified route only`);
    await page.close();
  }
  {
    // The steps render while /v1/meta never answers.
    const page = await enroll("stalled");
    const steps = await text(page);
    check(/1\. Install the CLI/.test(steps) && /Install it from its signed release/.test(steps) && /varlatch login --server/.test(steps), "a stalled /v1/meta never holds the steps");
    check(/API credential/.test(steps), "the credential is on the page while /v1/meta stalls");
    await page.close();
  }
  {
    meta = "on";
    metaRequests = 0;
    const page = await browser.newPage();
    await page.goto(`${base}/enroll?callback=${encodeURIComponent(`${base}/cb`)}`);
    await page.click("#signin");
    await page.waitForFunction(() => /terminal|failed/.test(document.getElementById("status").textContent), null, { timeout: 5000 });
    check(/terminal/.test(await text(page)), "the CLI hand-off still completes");
    await page.waitForTimeout(500);
    check(metaRequests === 0, "the CLI hand-off never asks /v1/meta");
    await page.close();
  }
} finally {
  for (const res of stalled) res.destroy();
  await browser.close();
  server.close();
}
if (failures.length > 0) {
  console.error(`${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("enroll page next steps: all checks passed");
