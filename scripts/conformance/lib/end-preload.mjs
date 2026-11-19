// SPDX-License-Identifier: Apache-2.0
/**
 * Loaded by the runner with `node --import` before any module of a suite
 * (run.mjs runSuite): reads the end-of-suite nonce the runner wrote to fd 4,
 * closes fd 4 so no process the suite starts can read it, and keeps it in
 * end-channel.mjs for suite-kit's finish(). The nonce is never in the
 * environment. Without fd 4 (EBADF), the suite has no nonce and cannot end
 * as finished, which fails the run.
 */
import { closeSync, readFileSync } from "node:fs";
import { setEndNonce } from "./end-channel.mjs";

export const NONCE_FD = 4;

let value = "";
try {
  value = readFileSync(NONCE_FD, "utf8");
} catch {
  // No fd 4: no nonce.
}
try {
  closeSync(NONCE_FD);
} catch {
  // Already closed, or never open.
}
setEndNonce(value.trim());
