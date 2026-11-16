// SPDX-License-Identifier: Apache-2.0
/**
 * The targets a run can choose (`--target <name>[:<argument>]`). Each is a
 * module implementing the contract in scripts/conformance/README.md:
 * required operations up, down, origin, bootstrap, recover, restart, logs
 * and requestLog, and the operations of the optional capabilities
 * capabilities.json gives it (its only source).
 *
 *   ts-source            the TypeScript stack built from this checkout
 *   ts-release:<x.y.z>   a signed TypeScript release, verified, pulled by digest
 *   go-binary:<path>     the Go varlatchd at <path>, run as a process
 */
import { CAPABILITIES } from "../lib/inventory.mjs";
import { CAPABILITIES_FILE, targetCapabilities } from "./capabilities.mjs";

const TARGETS = {
  "ts-source": { load: () => import("./ts-source.mjs"), argument: "none" },
  "ts-release": { load: () => import("./ts-release.mjs"), argument: "required" },
  "go-binary": { load: () => import("./go-binary.mjs"), argument: "required" },
};

const REQUIRED = ["up", "down", "origin", "bootstrap", "recover", "restart", "logs", "requestLog"];

/**
 * The operation each optional capability promises (scripts/conformance
 * README.md, The target contract): `probe:<name>` is the probe operation.
 */
const CAPABILITY_OPERATIONS = { maintenance: "maintenance", "serve-cli": "serveCli", "ts-stack": "tsStack", "go-server": "goServer", "webhook-receiver": "webhookReceiver", "object-store": "objectStore", "host-admin": "hostAdmin", "oidc-issuer": "oidcIssuer" };

export function capabilityOperation(capability) {
  return String(capability).startsWith("probe:") ? "probe" : CAPABILITY_OPERATIONS[capability];
}

/**
 * Why an adapter module cannot be loaded as target `name` with the
 * capabilities capabilities.json gives it; empty when it can. The data
 * file is the only source of a target's capabilities (the merge-base
 * check judges coverage from it): an adapter that declares its own list is
 * refused, and so is one without the operation a listed capability
 * promises.
 */
export function adapterProblems(name, target, capabilities) {
  const problems = [];
  const missing = REQUIRED.filter((op) => typeof target[op] !== "function");
  if (missing.length > 0) problems.push(`target ${name} lacks required operations: ${missing.join(", ")}`);
  if (target.capabilities !== undefined) {
    problems.push(`target ${name} declares its own capabilities (${[].concat(target.capabilities).join(", ")}); a target's capabilities are only those ${CAPABILITIES_FILE} lists`);
  }
  for (const capability of capabilities) {
    const op = CAPABILITIES.includes(capability) ? capabilityOperation(capability) : undefined;
    if (!op) problems.push(`${CAPABILITIES_FILE} gives target ${name} the unknown capability ${capability}`);
    else if (typeof target[op] !== "function") problems.push(`${CAPABILITIES_FILE} gives target ${name} ${capability}, but its adapter has no ${op} operation`);
  }
  return problems;
}

export const TARGET_NAMES = Object.keys(TARGETS);

/** Loads a target by its specification; fails on an unknown one, a missing or extra argument, or an incomplete module. */
export async function loadTarget(spec) {
  const [targetName, argument] = String(spec).split(/:(.*)/s);
  const entry = Object.hasOwn(TARGETS, targetName) ? TARGETS[targetName] : undefined;
  if (!entry) throw new Error(`unknown target ${spec}; known: ts-source, ts-release:<version>, go-binary:<path>`);
  if (entry.argument === "none" && argument !== undefined) throw new Error(`target ${targetName} takes no argument (got ${spec})`);
  if (entry.argument === "required" && !argument) throw new Error(`target ${targetName} needs an argument: ${targetName}:<${targetName === "ts-release" ? "version" : "path"}>`);
  const target = await entry.load();
  const capabilities = targetCapabilities(targetName);
  const problems = adapterProblems(targetName, target, capabilities);
  if (problems.length > 0) throw new Error(problems.join("; "));
  return {
    spec,
    name: targetName,
    argument: argument || null,
    target,
    capabilities,
    // The key its expected failures are kept under (expect/<name>.json).
    expectKey: target.expectKey ? target.expectKey(argument || null) : targetName,
  };
}
