// SPDX-License-Identifier: Apache-2.0
/**
 * The targets a run can choose (`--target <name>[:<argument>]`). Each is a
 * module implementing the contract in scripts/conformance/README.md:
 * required operations up, down, origin, bootstrap, recover, restart, logs
 * and requestLog, and the optional capabilities it lists.
 *
 *   ts-source            the TypeScript stack built from this checkout
 *   ts-release:<x.y.z>   a signed TypeScript release, verified, pulled by digest
 *   go-binary:<path>     the Go server (a stub until ADR-0059 step 3)
 */
const TARGETS = {
  "ts-source": { load: () => import("./ts-source.mjs"), argument: "none" },
  "ts-release": { load: () => import("./ts-release.mjs"), argument: "required" },
  "go-binary": { load: () => import("./go-binary.mjs"), argument: "required" },
};

const REQUIRED = ["up", "down", "origin", "bootstrap", "recover", "restart", "logs", "requestLog"];

export const TARGET_NAMES = Object.keys(TARGETS);

/** Loads a target by its specification; fails on an unknown one, a missing or extra argument, or an incomplete module. */
export async function loadTarget(spec) {
  const [targetName, argument] = String(spec).split(/:(.*)/s);
  const entry = Object.hasOwn(TARGETS, targetName) ? TARGETS[targetName] : undefined;
  if (!entry) throw new Error(`unknown target ${spec}; known: ts-source, ts-release:<version>, go-binary:<path>`);
  if (entry.argument === "none" && argument !== undefined) throw new Error(`target ${targetName} takes no argument (got ${spec})`);
  if (entry.argument === "required" && !argument) throw new Error(`target ${targetName} needs an argument: ${targetName}:<${targetName === "ts-release" ? "version" : "path"}>`);
  const target = await entry.load();
  const missing = REQUIRED.filter((op) => typeof target[op] !== "function");
  if (missing.length > 0) throw new Error(`target ${targetName} lacks required operations: ${missing.join(", ")}`);
  return {
    spec,
    name: targetName,
    argument: argument || null,
    target,
    capabilities: target.capabilities ?? [],
    // The key its expected failures are kept under (expect/<name>.json).
    expectKey: target.expectKey ? target.expectKey(argument || null) : targetName,
  };
}
