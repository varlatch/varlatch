#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Device sign-in behind the dashboard's nginx (ci-e2e.sh): each request
 * claims a different forged client address in X-Forwarded-For; varlatchd
 * must ignore it and count every request as the one real caller. The
 * harness first makes sure no sign-in is pending, so exactly ten requests
 * succeed and the rest meet the per-client pending cap itself (never the
 * general request window, a server error, or anything else). Rows are read
 * back by the probe's own name, so earlier suites' rows prove nothing.
 *
 *   e2e-proxy-probe.mjs send <origin> <name> <count>      responses as JSON on stdout
 *   e2e-proxy-probe.mjs check <responses.json> <rows.json> <nginx address>...
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const PENDING_PER_CLIENT = 10;
const FORGED = (i) => `198.18.0.${i + 1}`;

/** The problems with a probe's outcome; empty only when it proves the behaviour. */
export function checkProbe({ responses, rows, nginxIps, expected = 12 }) {
  const problems = [];
  if (responses.length !== expected) problems.push(`expected ${expected} responses, got ${responses.length}`);
  responses.forEach((r, i) => {
    if (i < PENDING_PER_CLIENT) {
      if (r.status !== 201) problems.push(`request ${i + 1}: expected 201 (a new pending sign-in), got ${r.status} ${r.code ?? ""}`.trim());
    } else if (!(r.status === 429 && r.code === "RATE_LIMITED" && r.cap === "pending-per-client")) {
      problems.push(`request ${i + 1}: expected the per-client pending cap (429 RATE_LIMITED pending-per-client), got ${r.status} ${r.code ?? ""} ${r.cap ?? ""}`.trim());
    }
  });
  if (rows.length !== PENDING_PER_CLIENT) problems.push(`expected ${PENDING_PER_CLIENT} sign-ins under the probe's name, found ${rows.length}`);
  const requesters = [...new Set(rows.map((r) => r.requesterIp))];
  if (requesters.length !== 1) problems.push(`expected one requester address for every probe request, found ${requesters.join(", ") || "none"}`);
  for (const requester of requesters) {
    if (!requester || !/^[0-9a-f.:]+$/i.test(requester)) problems.push(`requester ${requester} is not an address`);
    else if (requester.startsWith("198.18.")) problems.push(`a forged address was recorded: ${requester}`);
    else if (nginxIps.includes(requester)) problems.push(`the dashboard's nginx was recorded as the requester: ${requester}`);
  }
  return problems;
}

async function send(origin, name, count) {
  const responses = [];
  for (let i = 0; i < count; i++) {
    const res = await fetch(`${origin}/v1/auth/device`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": FORGED(i) },
      body: JSON.stringify({ name }),
    });
    const body = await res.json().catch(() => null);
    // The device code is a bearer: keep only what the check needs.
    responses.push({ status: res.status, code: body?.error?.code ?? null, cap: body?.error?.details?.cap ?? null });
  }
  return responses;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "send") {
    const [origin, name, count] = args;
    console.log(JSON.stringify(await send(origin, name, Number(count))));
  } else if (mode === "check") {
    const [responsesFile, rowsFile, ...nginxIps] = args;
    const responses = JSON.parse(readFileSync(responsesFile, "utf8"));
    const rows = JSON.parse(readFileSync(rowsFile, "utf8"));
    const problems = checkProbe({ responses, rows, nginxIps });
    const statuses = responses.map((r) => r.status).join(" ");
    if (problems.length > 0) {
      for (const p of problems) console.log(`FAIL  proxy probe: ${p}`);
      process.exit(1);
    }
    console.log(`PASS  ${PENDING_PER_CLIENT} requests with different forged addresses created sign-ins, then the per-client pending cap refused (${statuses})`);
    console.log(`PASS  every probe sign-in records one requester, the caller (${rows[0].requesterIp}), never a forged address or nginx (${nginxIps.join(", ")})`);
  } else {
    console.error("Usage: e2e-proxy-probe.mjs send <origin> <name> <count> | check <responses.json> <rows.json> <nginx address>...");
    process.exit(64);
  }
}
