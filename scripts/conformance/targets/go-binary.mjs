// SPDX-License-Identifier: Apache-2.0
/**
 * Target `go-binary:<path>`: the Go `varlatchd` (ADR-0059) at <path>. A
 * stub: ADR-0059 step 3 writes the server and this adapter (the contract in
 * scripts/conformance/README.md: `varlatchd` itself is the origin, its
 * access log the request log, `varlatchd admin bootstrap|recover` print what
 * the TypeScript admin CLI prints). Until then every operation fails, so a
 * run against it fails clearly instead of passing anything.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const name = "go-binary";
export const capabilities = [];

const NOT_BUILT = "target go-binary: not built yet (ADR-0059 step 3 writes the Go server and this adapter)";
const notBuilt = async () => {
  throw new Error(NOT_BUILT);
};

/** Fails before anything is created. */
export async function up() {
  throw new Error(NOT_BUILT);
}

/** Nothing to remove: up creates nothing. */
export async function down() {}

export const origin = () => {
  throw new Error(NOT_BUILT);
};
export const bootstrap = notBuilt;
export const recover = notBuilt;
export const restart = notBuilt;
export const logs = notBuilt;
export const requestLog = notBuilt;

/**
 * The implementation fingerprint step 3 records: the binary's sha256, not
 * its path, so the same build compares equal wherever it is and another
 * build at the same path does not.
 */
export function fingerprintBinary(path) {
  return { target: name, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") };
}
export const fingerprint = (state) => (state?.binary ? fingerprintBinary(state.binary) : null);

/** Expectations are kept for the Go server whatever its path. */
export const expectKey = () => name;
