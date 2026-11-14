// SPDX-License-Identifier: Apache-2.0
/**
 * Operations and declared gaps (ADR-0059 step 3, varlatchd-core decision 5).
 *
 * An operation is what a check needs the target to provide:
 *
 *   - a /v1 operation, by its OpenAPI operationId
 *     (packages/protocol/openapi.yaml);
 *   - a named operation outside /v1, listed in inventory.json `operations`:
 *       { "title", "method", "path" }   an HTTP route outside /v1 (the
 *                                       enrollment page, the browser session);
 *       { "title", "target" }           a target operation (targets/*.mjs):
 *                                       bootstrap, recover, serveCli;
 *       { "title", "uses": [ops] }      the seed: the runner's own writes,
 *                                       lacking exactly when an operation it
 *                                       uses is.
 *
 * Each suite in the inventory lists the operations it needs
 * (`suites.<name>.operations`), and a check may add its own
 * (`checks.<id>.operations`, for a feature group that needs more than the
 * rest of its suite).
 *
 * A target declares what it lacks in its expectations file
 * (expect/<target>.json `lacks`, keyed by target, each with a reason and the
 * step that adds it). A check whose operations include a lacking one is
 * reported `target-lacks <operation>` by the runner; no suite can give that
 * result. `--gate` refuses it. A listed operation the target does provide
 * fails the run: before the suites the runner asks the target (`probe`
 * below), and requires exactly the stub's answer.
 */

/** The code of the Go server's shared stub (go/server/httpserver NotImplementedYet). */
export const NOT_IMPLEMENTED_YET = "NOT_IMPLEMENTED_YET";

const OPERATION_NAME = /^[a-z][a-z0-9-]*$/;
const OPERATION_ID = /^[a-z][A-Za-z0-9]*$/;
const METHODS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"];
/** The target operations a named operation may stand for. */
export const TARGET_OPERATIONS = ["bootstrap", "recover", "serveCli"];

/**
 * The operations of the OpenAPI document: Map(operationId → { method, path }),
 * the path with the document's server URL (/v1) in front. The document is
 * read line by line, as it is written (two-space indentation: paths at 2,
 * methods at 4, operationId at 6), so that this module needs nothing but
 * Node; test/operations.test.mjs checks the result against the routes the Go
 * server is generated with.
 */
export function openapiOperations(text) {
  const lines = text.split("\n");
  const server = /^servers:\s*\n\s*-\s*url:\s*(\S+)/m.exec(text)?.[1] ?? "";
  const ops = new Map();
  let inPaths = false;
  let path = null;
  let method = null;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      inPaths = line.startsWith("paths:");
      path = method = null;
      continue;
    }
    if (!inPaths) continue;
    let m;
    if ((m = /^ {2}(\/\S*):\s*$/.exec(line))) {
      path = m[1];
      method = null;
    } else if ((m = /^ {4}([a-z]+):\s*$/.exec(line))) {
      method = METHODS.includes(m[1]) ? m[1].toUpperCase() : null;
    } else if ((m = /^ {6}operationId:\s*(\S+)\s*$/.exec(line)) && path && method) {
      if (ops.has(m[1])) throw new Error(`openapi: operationId ${m[1]} appears twice`);
      ops.set(m[1], { method, path: `${server}${path}` });
      method = null;
    }
  }
  return ops;
}

/** A request path for an operation's route, every path parameter filled with a placeholder. */
export function placeholderPath(path) {
  return path.replace(/\{[^}]+\}/g, "placeholder");
}

/** Problems with the inventory's `operations` and every operation the suites and checks name; empty when valid. */
export function operationProblems(inventory, openapi) {
  const problems = [];
  const named = inventory.operations ?? {};
  const known = (op) => openapi.has(op) || Object.hasOwn(named, op);
  for (const [name, op] of Object.entries(named)) {
    const where = `operation ${name}`;
    if (!OPERATION_NAME.test(name)) problems.push(`${where}: a named operation is lowercase with dashes`);
    if (openapi.has(name)) problems.push(`${where}: is also an OpenAPI operationId`);
    if (typeof op?.title !== "string" || op.title === "") problems.push(`${where}: no title`);
    const kinds = ["path", "target", "uses"].filter((k) => k in (op ?? {}));
    if (kinds.length !== 1) {
      problems.push(`${where}: names exactly one of method and path, target, or uses`);
      continue;
    }
    if (kinds[0] === "path") {
      if (!METHODS.includes(String(op.method).toLowerCase()) || op.method !== String(op.method).toUpperCase()) problems.push(`${where}: method must be an HTTP method in capitals`);
      if (typeof op.path !== "string" || !op.path.startsWith("/") || op.path.startsWith("/v1/")) problems.push(`${where}: path must be a route outside /v1`);
    } else if (kinds[0] === "target") {
      if (!TARGET_OPERATIONS.includes(op.target)) problems.push(`${where}: target must be one of ${TARGET_OPERATIONS.join(", ")}`);
    } else {
      if (!Array.isArray(op.uses) || op.uses.length === 0) problems.push(`${where}: uses must list operations`);
      for (const used of op.uses ?? []) {
        if (!known(used)) problems.push(`${where}: uses ${used}, which is neither an OpenAPI operationId nor a named operation`);
        else if (named[used]?.uses) problems.push(`${where}: uses ${used}, which uses others in turn`);
      }
    }
  }
  const listed = (where, list) => {
    if (list === undefined) return;
    if (!Array.isArray(list)) {
      problems.push(`${where}: operations must be a list`);
      return;
    }
    const seen = new Set();
    for (const op of list) {
      if (!known(op)) problems.push(`${where}: ${op} is neither an OpenAPI operationId nor a named operation`);
      if (seen.has(op)) problems.push(`${where}: ${op} is listed twice`);
      seen.add(op);
    }
  };
  for (const [name, suite] of Object.entries(inventory.suites ?? {})) listed(`suite ${name}`, suite.operations);
  for (const [id, check] of Object.entries(inventory.checks ?? {})) {
    listed(`check ${id}`, check.operations);
    if (check.operations && check.reportedBy === "runner") problems.push(`check ${id}: a check the runner reports needs no operation`);
  }
  return problems;
}

/** The operations a check needs: its suite's and its own. */
export function operationsOf(inventory, id) {
  const check = inventory.checks?.[id];
  if (!check) return [];
  return [...new Set([...(inventory.suites?.[check.suite]?.operations ?? []), ...(check.operations ?? [])])].sort();
}

/** A set of operation names from a Set, a Map (its keys) or any iterable. */
const asSet = (lacks) => (lacks instanceof Set ? lacks : lacks instanceof Map ? new Set(lacks.keys()) : new Set(lacks));

/**
 * Whether an operation is lacking, given the lacking set: a listed operation,
 * or a named one that uses a listed one.
 */
function lacking(inventory, op, lacks) {
  if (lacks.has(op)) return true;
  const uses = inventory.operations?.[op]?.uses;
  return Array.isArray(uses) && uses.some((u) => lacks.has(u));
}

/**
 * The checks that report target-lacks for a set of lacking operations:
 * Map(check id → [the lacking operations it needs, sorted]).
 */
export function lackingChecks(inventory, lacks) {
  const set = asSet(lacks);
  const out = new Map();
  for (const id of Object.keys(inventory.checks ?? {})) {
    const missing = operationsOf(inventory, id).filter((op) => lacking(inventory, op, set));
    if (missing.length > 0) out.set(id, missing);
  }
  return out;
}

/** Whether a named setup operation (the seed, bootstrap) cannot run on a target lacking `lacks`. */
export function setupLacks(inventory, op, lacks) {
  return lacking(inventory, op, asSet(lacks));
}

/** Problems with one target key's `lacks` entries; empty when valid. */
export function lacksProblems(where, entries, { inventory, openapi }) {
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) return [`${where}: must map operations to { "reason", "step" }`];
  const problems = [];
  for (const [op, entry] of Object.entries(entries)) {
    const named = inventory?.operations?.[op];
    if (!(openapi?.has(op) || named)) problems.push(`${where}: ${op} is neither an OpenAPI operationId nor a named operation`);
    else if (named?.uses) problems.push(`${where}: ${op} is never listed: it lacks exactly when an operation it uses does`);
    if (!OPERATION_ID.test(op) && !OPERATION_NAME.test(op)) problems.push(`${where}: ${op} is not an operation name`);
    const keys = Object.keys(entry ?? {}).sort().join(",");
    if (keys !== "reason,step" || !String(entry.reason).trim() || !String(entry.step).trim()) {
      problems.push(`${where}: ${op} must be { "reason": "<why the target lacks it>", "step": "<the step that adds it>" }`);
    }
  }
  return problems;
}

/**
 * How the runner asks the target whether a listed operation is really
 * missing: { kind: "http", method, path } for a /v1 or named HTTP operation,
 * { kind: "target", operation } for a target operation. A named operation
 * that uses others has no probe of its own.
 */
export function probeFor(inventory, openapi, op) {
  const http = openapi.get(op);
  if (http) return { kind: "http", method: http.method, path: placeholderPath(http.path) };
  const named = inventory.operations?.[op];
  if (named?.path) return { kind: "http", method: named.method, path: named.path };
  if (named?.target) return { kind: "target", operation: named.target };
  return null;
}

/**
 * Judges one probe answer: null when it is exactly the stub's (501 with the
 * code NOT_IMPLEMENTED_YET), else why the entry is stale.
 */
export function staleBecause(status, body) {
  let code = null;
  try {
    code = JSON.parse(body)?.error?.code ?? null;
  } catch {
    // Not JSON: not the stub.
  }
  if (status === 501 && code === NOT_IMPLEMENTED_YET) return null;
  return `the target answered ${status}${code ? ` ${code}` : ""}, not 501 ${NOT_IMPLEMENTED_YET}: it provides the operation, so remove the entry`;
}
