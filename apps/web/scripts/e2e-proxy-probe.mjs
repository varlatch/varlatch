#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
import "../../../scripts/redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * Device sign-in behind a proxy: each request claims a different forged
 * client address in X-Forwarded-For; the server must ignore it and count
 * every request as the one real caller. On the TypeScript stack the
 * requests pass through the dashboard's nginx; on a server with no proxy in
 * front they reach it directly. The suite first makes sure no sign-in is
 * pending, so exactly ten requests succeed and the rest meet the per-client
 * pending cap itself (never the general request window, a server error, or
 * anything else). Rows are read back by the probe's own name, so earlier
 * suites' rows prove nothing.
 *
 *   e2e-proxy-probe.mjs <origin>
 *
 * Run by scripts/conformance/run.mjs. Server state is read through the
 * target's probes (expire-pending-device-sign-ins, device-sign-in-addresses,
 * proxy-addresses), never with SQL. The pending-cap 429s this suite causes
 * are the only ones the run's request-log check allows, and only from this
 * suite, on POST /v1/auth/device.
 */
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { reporter, targetOp } from "../../../scripts/conformance/suite-kit.mjs";

export const PENDING_PER_CLIENT = 10;
const FORGED = (i) => `198.18.0.${i + 1}`;
const COUNT = 12;

/** What is wrong with the probe's responses; empty when they show ten sign-ins, then the pending cap. */
export function responseProblems(responses, expected = COUNT) {
  const problems = [];
  if (responses.length !== expected) problems.push(`expected ${expected} responses, got ${responses.length}`);
  responses.forEach((r, i) => {
    if (i < PENDING_PER_CLIENT) {
      if (r.status !== 201) problems.push(`request ${i + 1}: expected 201 (a new pending sign-in), got ${r.status} ${r.code ?? ""}`.trim());
    } else if (!(r.status === 429 && r.code === "RATE_LIMITED" && r.cap === "pending-per-client")) {
      problems.push(`request ${i + 1}: expected the per-client pending cap (429 RATE_LIMITED pending-per-client), got ${r.status} ${r.code ?? ""} ${r.cap ?? ""}`.trim());
    }
  });
  return problems;
}

/** What is wrong with the recorded sign-ins; empty when all ten record the one real caller. */
export function rowProblems(rows, proxyIps) {
  const problems = [];
  if (rows.length !== PENDING_PER_CLIENT) problems.push(`expected ${PENDING_PER_CLIENT} sign-ins under the probe's name, found ${rows.length}`);
  const requesters = [...new Set(rows.map((r) => r.requesterIp))];
  if (requesters.length !== 1) problems.push(`expected one requester address for every probe request, found ${requesters.join(", ") || "none"}`);
  for (const requester of requesters) {
    if (!requester || !/^[0-9a-f.:]+$/i.test(requester)) problems.push(`requester ${requester} is not an address`);
    else if (requester.startsWith("198.18.")) problems.push(`a forged address was recorded: ${requester}`);
    else if (proxyIps.includes(requester)) problems.push(`the dashboard's nginx was recorded as the requester: ${requester}`);
  }
  return problems;
}

/** The problems with a probe's outcome; empty only when it proves the behaviour. */
export function checkProbe({ responses, rows, nginxIps, expected = COUNT }) {
  return [...responseProblems(responses, expected), ...rowProblems(rows, nginxIps)];
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
  const [origin] = process.argv.slice(2);
  if (!origin) {
    console.error("Usage: e2e-proxy-probe.mjs <origin>");
    process.exit(64);
  }
  const { check, error, finish } = reporter();
  try {
    const name = `proxy-probe-${randomBytes(6).toString("hex")}`;
    // A known start: no sign-in pending from anyone, so exactly ten probe requests can succeed.
    targetOp("probe", ["expire-pending-device-sign-ins"]);
    const responses = await send(origin, name, COUNT);
    const rows = JSON.parse(targetOp("probe", ["device-sign-in-addresses", name]));
    const proxyIps = JSON.parse(targetOp("probe", ["proxy-addresses"]));
    const statuses = responses.map((r) => r.status).join(" ");
    const fromResponses = responseProblems(responses);
    check(
      "proxy-probe.forged-addresses-meet-pending-cap",
      `${PENDING_PER_CLIENT} requests with different forged addresses created sign-ins, then the per-client pending cap refused (${statuses})`,
      fromResponses.length === 0,
      fromResponses.join("; "),
    );
    const fromRows = rowProblems(rows, proxyIps);
    check(
      "proxy-probe.records-caller-address",
      `every probe sign-in records one requester, the caller (${rows[0]?.requesterIp ?? "none"}), never a forged address or a proxy (${proxyIps.join(", ") || "none in front"})`,
      fromRows.length === 0,
      fromRows.join("; "),
    );
  } catch (err) {
    error(`proxy probe: ${err.message}`);
  }
  finish();
}
