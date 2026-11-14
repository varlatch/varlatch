// SPDX-License-Identifier: Apache-2.0
/**
 * Each target's optional capabilities, kept as data in capabilities.json so
 * that the merge-base check can read them at both commits without running
 * either side's code.
 */
import { readFileSync } from "node:fs";

export const CAPABILITIES_FILE = "scripts/conformance/targets/capabilities.json";

const all = JSON.parse(readFileSync(new URL("./capabilities.json", import.meta.url), "utf8"));

/** A target's capabilities, by target name. */
export function targetCapabilities(name) {
  const caps = all[name];
  if (!Array.isArray(caps)) throw new Error(`capabilities.json names no capabilities for target ${name}`);
  return [...caps];
}
