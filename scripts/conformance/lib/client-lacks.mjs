// SPDX-License-Identifier: Apache-2.0
/**
 * What the Go CLI does not do yet (internal docs/design/go-cli.md, decision
 * 3), the client's counterpart of a target's `lacks`, kept in
 * scripts/conformance/client-go.json:
 *
 *   {
 *     "schema": 1,
 *     "lacksFeatures": {
 *       "<feature>": { "reason": "<why>", "slice": "<the slice that builds it>" }
 *     }
 *   }
 *
 * The lacks are the client's, the same on every target, so they have one
 * file next to clients.json rather than an entry in each target's
 * expect/<target>.json.
 *
 * A check lacks when its feature, or a feature its suite's setup uses
 * (inventory `suites.<name>.cliNeeds`), is listed. The runner reports it
 * `client-lacks` itself; no suite can. A suite runs as long as one of its
 * checks does not lack, and a result a suite still prints for a lacking
 * check is replaced, except a PASS: that means the entry is stale, and the
 * run fails until the pull request that built the feature removes it.
 * Only the `go` client has lacks; a TypeScript CLI has every feature its
 * version introduced.
 */
import { readFileSync } from "node:fs";

export const CLIENT_LACKS_FILE = new URL("../client-go.json", import.meta.url);

/** The Go CLI's lacking features: Map(feature → { reason, slice }). */
export function loadClientLacks(path = CLIENT_LACKS_FILE) {
  const file = JSON.parse(readFileSync(path, "utf8"));
  return new Map(Object.entries(file.lacksFeatures ?? {}));
}

/** Problems with client-go.json's shape; empty when it is valid. */
export function validateClientLacks(file, inventory) {
  const where = "client-go.json";
  if (file?.schema !== 1) return [`${where}: schema: expected 1`];
  const problems = [];
  for (const [feature, entry] of Object.entries(file.lacksFeatures ?? {})) {
    if (!(feature in (inventory.features ?? {}))) problems.push(`${where}: ${feature} is not a feature in the inventory`);
    const keys = Object.keys(entry ?? {}).sort().join(",");
    if (keys !== "reason,slice" || !String(entry.reason).trim() || !/^5\.[1-9][a-z]?$|^step [0-9]$/.test(String(entry.slice))) {
      problems.push(`${where}: ${feature} must be { "reason": "<why>", "slice": "<5.xy or step N>" }`);
    }
  }
  return problems;
}

/**
 * The CLI features check `id` needs: its suite's setup's, its own feature,
 * and those its `cliNeeds` lists (beside its feature, or instead of one).
 */
export function featuresNeeded(inventory, id) {
  const check = inventory.checks[id];
  const needs = new Set([...(inventory.suites?.[check?.suite]?.cliNeeds ?? []), ...(check?.cliNeeds ?? [])]);
  if (check?.feature) needs.add(check.feature);
  return [...needs].sort();
}

/**
 * The checks that report client-lacks for the client's lacking features:
 * Map(check id → the lacking features it needs). Empty for every client
 * but the Go CLI.
 */
export function clientLackingChecks(inventory, lacksFeatures) {
  const out = new Map();
  if (lacksFeatures.size === 0) return out;
  for (const id of Object.keys(inventory.checks)) {
    const missing = featuresNeeded(inventory, id).filter((f) => lacksFeatures.has(f));
    if (missing.length > 0) out.set(id, missing);
  }
  return out;
}

/**
 * A suite's results with the lacking checks' taken out, and every stale
 * entry they reveal: a lacking check that passed shows that the client has
 * what the entry says it lacks.
 */
export function withoutLacking(results, lacked, clientLacking) {
  const kept = [];
  const stale = [];
  for (const r of results) {
    if (!lacked.has(r.id)) {
      kept.push(r);
      continue;
    }
    if (r.status === "PASS" && clientLacking.has(r.id)) stale.push({ id: r.id, features: clientLacking.get(r.id) });
  }
  return { kept, stale };
}
