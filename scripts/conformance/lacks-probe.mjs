// SPDX-License-Identifier: Apache-2.0
/**
 * The stale-`lacks` probe (ADR-0059 step 3, varlatchd-core decision 5): the
 * runner does not trust a target's declared gaps, it asks the target. Before
 * the suites, each operation expect/<target>.json lists under `lacks` gets
 * one request:
 *
 *   - a /v1 operation: its method and path, path parameters filled with
 *     placeholders, a JSON body {} for methods that take one;
 *   - a named HTTP operation (the enrollment page, the browser session): its
 *     method and path;
 *   - a named target operation (bootstrap, recover, serveCli): the target
 *     adapter's operation, which asks the server.
 *
 * Each must answer exactly as the Go server's shared stub does: 501 with the
 * code NOT_IMPLEMENTED_YET (a target operation: an error with that code). Any
 * other answer means the target provides the operation, and the entry is
 * stale: the run fails, naming it. The seed has no probe: it lacks exactly
 * when an operation it uses does.
 */
import { NOT_IMPLEMENTED_YET, probeFor, staleBecause } from "./lib/operations.mjs";

/** Asks the target about every lacking operation: [{ operation, why }] for each stale entry. */
export async function probeLacks({ inventory, openapi, lacks, origin, target, state }) {
  const stale = [];
  for (const op of lacks) {
    const probe = probeFor(inventory, openapi, op);
    let why = null;
    if (!probe) why = "the runner has no way to ask the target about it";
    else if (probe.kind === "http") why = await probeHttp(origin, probe);
    else why = await probeTargetOperation(target, state, probe.operation);
    if (why) stale.push({ operation: op, why });
  }
  return stale;
}

async function probeHttp(origin, { method, path }) {
  const body = ["POST", "PUT", "PATCH"].includes(method) ? "{}" : undefined;
  try {
    const res = await fetch(`${origin}${path}`, { method, headers: body ? { "Content-Type": "application/json" } : {}, body, redirect: "manual" });
    return staleBecause(res.status, await res.text());
  } catch (err) {
    return `the request failed: ${err.message}`;
  }
}

/**
 * A target operation must fail with the stub's code. An adapter without the
 * operation cannot run it at all, which is a gap too.
 */
async function probeTargetOperation(target, state, operation) {
  if (typeof target[operation] !== "function") return null;
  try {
    const args = operation === "recover" ? ["idn_lacksprobe", {}] : operation === "serveCli" ? [true] : [];
    const out = await target[operation](state, ...args);
    return `the target's ${operation} operation succeeded${typeof out === "string" && out ? ` (${out.trim().split("\n").length} lines of output)` : ""}: it provides the operation, so remove the entry`;
  } catch (err) {
    return err?.code === NOT_IMPLEMENTED_YET ? null : `the target's ${operation} operation failed otherwise: ${String(err?.message ?? err).slice(0, 300)}`;
  }
}
