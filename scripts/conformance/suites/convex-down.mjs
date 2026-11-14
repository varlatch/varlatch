#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The dashboard keeps serving while Convex is down (ADR-0035 D5/D10): with
 * convex-backend stopped, the dashboard and /v1 answer, /convex fails fast
 * with a gateway error, the dashboard's nginx restarts without it, and
 * /convex recovers when it returns. ts-stack checks: the Go server has no
 * Convex.
 *
 *   convex-down.mjs <origin> <api token>      (run by scripts/conformance/run.mjs)
 */
import { reporter, tryTargetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: convex-down.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const compose = (...args) => tryTargetOp("ts-stack", ["compose", ...args]);
/** The status code, or 0 when there was no answer (curl's 000). */
const code = (path, headers = {}) =>
  fetch(`${origin}${path}`, { headers, signal: AbortSignal.timeout(60_000) }).then(
    async (r) => {
      await r.arrayBuffer();
      return r.status;
    },
    () => 0,
  );

let stopped = false;
try {
  if (compose("stop", "convex-backend").status !== 0) throw new Error("could not stop convex-backend");
  stopped = true;
  const web = await code("/");
  const api = await code("/v1/organizations", { Authorization: `Bearer ${token}` });
  const started = Date.now();
  const convex = await code("/convex/version");
  const seconds = Math.round((Date.now() - started) / 1000);
  if (compose("restart", "varlatch-web").status !== 0) throw new Error("could not restart varlatch-web");
  for (let i = 0; i < 30 && (await code("/")) !== 200; i++) await sleep(1000);
  const restarted = await code("/");
  if (compose("start", "convex-backend").status !== 0) throw new Error("could not start convex-backend");
  stopped = false;
  for (let i = 0; i < 60 && (await code("/convex/version")) !== 200; i++) await sleep(2000);
  const back = await code("/convex/version");
  console.log(`web=${web} api=${api} convex=${convex} (${seconds}s) web-after-restart=${restarted} convex-after-start=${back}`);
  check("convex-down.dashboard-serves", "the dashboard serves while Convex is down", web === 200, String(web));
  check("convex-down.api-serves", "/v1 serves while Convex is down", api === 200, String(api));
  // /convex answers a gateway error: 502 once Docker DNS has dropped the
  // stopped backend, 504 while nginx still holds its cached address.
  check("convex-down.convex-gateway-error", "/convex answers a gateway error while the backend is down", convex === 502 || convex === 504, String(convex));
  check("convex-down.convex-fails-fast", "/convex fails fast while the backend is down", seconds <= 10, `${seconds}s`);
  check("convex-down.web-restarts-without-convex", "the dashboard restarts while Convex is down", restarted === 200, String(restarted));
  check("convex-down.convex-recovers", "/convex recovers when the backend returns", back === 200, String(back));
} catch (err) {
  error(`convex down: ${err.message}`);
} finally {
  if (stopped) compose("start", "convex-backend");
}
finish();
