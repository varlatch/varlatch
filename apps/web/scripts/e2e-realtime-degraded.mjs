#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
import { reporter } from "../../../scripts/conformance/suite-kit.mjs";
/**
 * Degraded live updates on any server (ADR-0035 Decision 10, ADR-0059
 * Decision 4; gate G11's reconnect check). The dashboard's live-update
 * connection is cut in the page itself, whatever carries it (the Go
 * server's server-sent events, or the TypeScript server's Convex
 * WebSocket): while it is down the dashboard says so, keeps what is on
 * screen fresh by polling /v1 with a bound, and when it returns it
 * refreshes, so a signal missed while it was down is covered. No page
 * reload throughout.
 *
 * The page is the account's sessions page, whose credential list follows
 * the person's identitySignal; the changes are revocations of the same
 * person's CLI credentials through /v1, from outside the page.
 *
 * Usage: e2e-realtime-degraded.mjs <enroll-url> <credential> <credential> <credential>
 * (three disposable CLI credentials of the enrolled identity; run by
 * scripts/conformance/run.mjs)
 */
import { chromium } from "playwright";
import { watchCsp } from "./e2e-csp.mjs";

const [enrollUrl, ...tokens] = process.argv.slice(2);
if (!enrollUrl?.includes("#") || tokens.length !== 3) {
  console.error("Usage: e2e-realtime-degraded.mjs <enroll-url> <credential> <credential> <credential>");
  process.exit(1);
}
const base = new URL(enrollUrl).origin;
const { check, error, finish } = reporter();
const indicator = '[data-testid="live-updates-status"]';
const since = (t) => `${Math.round((Date.now() - t) / 100) / 10} s`;

/**
 * Lets the test cut the page's live-update connections and keep new ones
 * from opening, without touching the server: EventSource (the Go server)
 * and WebSocket (Convex) are wrapped before the dashboard loads.
 */
function realtimeSwitch() {
  const state = { blocked: false, live: new Set() };
  const fail = (target) =>
    setTimeout(() => {
      const e = new Event("error");
      target.dispatchEvent(e);
    }, 50);
  const NativeES = window.EventSource;
  if (NativeES) {
    window.EventSource = function EventSource(url, init) {
      if (state.blocked) {
        const fake = new EventTarget();
        Object.defineProperty(fake, "onerror", {
          set(fn) {
            if (this._onerror) fake.removeEventListener("error", this._onerror);
            this._onerror = fn;
            if (fn) fake.addEventListener("error", fn);
          },
          get() {
            return this._onerror ?? null;
          },
        });
        fake.close = () => {};
        fake.readyState = 2;
        fail(fake);
        return fake;
      }
      const es = new NativeES(url, init);
      state.live.add(es);
      return es;
    };
    window.EventSource.prototype = NativeES.prototype;
  }
  const NativeWS = window.WebSocket;
  window.WebSocket = function WebSocket(url, protocols) {
    const ws = new NativeWS(url, protocols);
    if (state.blocked) setTimeout(() => ws.close(), 0);
    else state.live.add(ws);
    return ws;
  };
  window.WebSocket.prototype = NativeWS.prototype;
  for (const k of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) window.WebSocket[k] = NativeWS[k];
  window.__varlatchRealtime = (blocked) => {
    state.blocked = blocked;
    if (!blocked) return state.live.size;
    const cut = state.live.size;
    for (const c of state.live) {
      if (typeof c.send === "function") c.close();
      else {
        c.close();
        c.dispatchEvent(new Event("error"));
      }
    }
    state.live.clear();
    return cut;
  };
}

const browser = await chromium.launch();
const context = await browser.newContext();
const cspViolations = watchCsp(context);
await context.addInitScript(realtimeSwitch);
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
const credentialRequests = [];
page.on("request", (r) => {
  if (new URL(r.url()).pathname === "/v1/me/credentials" && r.method() === "GET") credentialRequests.push(Date.now());
});
const cut = (blocked) => page.evaluate((b) => window.__varlatchRealtime(b), blocked);

/** A credential's id (its own /v1/me/credentials entry), and its revocation from outside the page. */
async function credentialOf(token) {
  const r = await fetch(`${base}/v1/me/credentials`, { headers: { Authorization: `Bearer ${token}` } });
  const items = (await r.json()).items ?? [];
  const id = items.find((c) => c.current)?.id;
  if (!id) throw new Error(`no current credential in /v1/me/credentials (${r.status})`);
  return {
    id,
    revoke: () => fetch(`${base}/v1/me/credentials/${id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } }).then((x) => x.status),
  };
}
const revokedOnPage = (id, timeout) =>
  page
    .waitForFunction((x) => document.querySelector(`[data-credential="${x}"]`)?.textContent.includes("revoked"), id, { timeout })
    .then(
      () => true,
      () => false,
    );

try {
  const [first, second, third] = await Promise.all(tokens.map(credentialOf));
  await page.goto(enrollUrl);
  await page.click("#enroll");
  await page.waitForFunction(() => /API credential|failed/.test(document.getElementById("status").textContent), null, { timeout: 20000 });
  await page.goto(`${base}/account/sessions`);
  await page.waitForSelector(`[data-credential="${first.id}"]`, { timeout: 20000 });
  await page.evaluate(() => {
    window.__varlatchNoReload = true;
  });
  await page.waitForTimeout(6000); // past the grace period
  check("realtime-degraded.no-indicator-while-live", "no indicator while live updates work", (await page.locator(indicator).count()) === 0);

  // ---- Cut: the indicator, polling with a bound.
  const cutCount = await cut(true);
  let t = Date.now();
  await page.waitForSelector(indicator, { timeout: 30000 });
  const text = (await page.textContent(indicator)) ?? "";
  check(
    "realtime-degraded.says-reconnecting",
    "the dashboard says live updates are reconnecting, and that it refreshes what is on screen",
    cutCount > 0 && /Live updates reconnecting/.test(text) && /refreshing every 15 s/.test(text),
    `${cutCount} connection(s) cut; after ${since(t)}: ${text}`,
  );
  const degradedAt = Date.now();
  const before = credentialRequests.length;
  const firstStatus = await first.revoke();
  t = Date.now();
  const polled = firstStatus === 204 && (await revokedOnPage(first.id, 30000));
  check("realtime-degraded.change-shows-up-by-polling", "a change made elsewhere shows up by polling /v1 while live updates are down", polled, `revoke ${firstStatus}, shown after ${since(t)}`);
  // Longer: the refreshes stay at least 12 s apart (15 s less the jitter,
  // backing off to 60 s), never faster.
  await page.waitForTimeout(32000);
  const polls = credentialRequests.slice(before).filter((at) => at >= degradedAt);
  const gaps = polls.slice(1).map((at, i) => at - polls[i]);
  const span = Date.now() - degradedAt;
  check(
    "realtime-degraded.polling-is-bounded",
    "polling while disconnected is bounded: at least 12 s between refreshes of what is on screen",
    polls.length >= 1 && polls.length <= Math.ceil(span / 12000) && gaps.every((g) => g >= 11500),
    `${polls.length} refreshes in ${Math.round(span / 1000)} s, gaps ${gaps.map((g) => Math.round(g / 100) / 10).join(", ") || "none"} s`,
  );

  // ---- Back.
  await cut(false);
  t = Date.now();
  const cleared = await page.waitForSelector(indicator, { state: "detached", timeout: 120000 }).then(
    () => true,
    () => false,
  );
  check("realtime-degraded.indicator-clears-on-reconnect", "the indicator clears when live updates return", cleared, since(t));

  // ---- A short drop (within the grace period): a signal sent while the
  // connection was down is missed, and the refresh on reconnect covers it.
  await page.waitForTimeout(3000);
  const beforeDrop = credentialRequests.length;
  await cut(true);
  const dropAt = Date.now();
  const secondStatus = await second.revoke();
  await page.waitForTimeout(500);
  await cut(false);
  const covered = secondStatus === 204 && (await revokedOnPage(second.id, 15000));
  const shownAfter = since(dropAt);
  const noIndicator = (await page.locator(indicator).count()) === 0;
  check(
    "realtime-degraded.reconnect-refresh-covers-missed-signal",
    "a signal missed while live updates were down is covered by the refresh on reconnect",
    covered && Date.now() - dropAt < 12000 && credentialRequests.length > beforeDrop,
    `revoke ${secondStatus}, shown ${covered} after ${shownAfter}, indicator ${noIndicator ? "not shown" : "shown"}, ${credentialRequests.length - beforeDrop} refresh(es)`,
  );

  // ---- Live again: only a live signal brings this in quickly (no polling).
  await page.waitForTimeout(6000);
  const thirdStatus = await third.revoke();
  t = Date.now();
  const live = thirdStatus === 204 && (await revokedOnPage(third.id, 10000));
  check("realtime-degraded.live-signals-drive-updates-again", "live signals drive updates again", live, `revoke ${thirdStatus}, shown after ${since(t)}`);
  check("realtime-degraded.no-page-reload", "no page reload throughout", await page.evaluate(() => window.__varlatchNoReload === true));
} catch (err) {
  error(`degraded live updates: ${String(err).slice(0, 300)}`);
} finally {
  check("realtime-degraded.no-content-security-policy-violations", "no Content-Security-Policy violations", cspViolations.length === 0, cspViolations.slice(0, 3).join(" | "));
  await browser.close();
}
finish();
