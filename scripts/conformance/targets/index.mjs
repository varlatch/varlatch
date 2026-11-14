// SPDX-License-Identifier: Apache-2.0
/**
 * The targets a run can choose (`--target <name>[:<argument>]`). Each is a
 * module implementing the contract in scripts/conformance/README.md:
 * required operations up, down, origin, bootstrap, recover, restart, logs
 * and requestLog, and the optional capabilities it lists.
 */
const TARGETS = {
  "ts-source": () => import("./ts-source.mjs"),
};

const REQUIRED = ["up", "down", "origin", "bootstrap", "recover", "restart", "logs", "requestLog"];

/** Loads a target by its specification; fails on an unknown one or an incomplete module. */
export async function loadTarget(spec) {
  const [targetName, argument] = String(spec).split(/:(.*)/s);
  const load = TARGETS[targetName];
  if (!load) throw new Error(`unknown target ${spec}; known: ${Object.keys(TARGETS).join(", ")}`);
  const target = await load();
  const missing = REQUIRED.filter((op) => typeof target[op] !== "function");
  if (missing.length > 0) throw new Error(`target ${targetName} lacks required operations: ${missing.join(", ")}`);
  return { spec, name: targetName, argument: argument || null, target, capabilities: target.capabilities ?? [] };
}
