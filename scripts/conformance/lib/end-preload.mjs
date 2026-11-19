// SPDX-License-Identifier: Apache-2.0
/**
 * Loaded by the runner with `node --import` before any module of a suite
 * (run.mjs runSuite): reads the end-of-suite nonce the runner wrote to fd 4,
 * closes fd 4 so no process the suite starts can read it, and keeps it in
 * end-channel.mjs for suite-kit's finish(). The nonce is never in the
 * environment.
 *
 * It touches fd 4 only when the runner says it opened it
 * (CONFORMANCE_NONCE_FD=4, not a secret, removed here) and fd 4 is a socket,
 * as the runner's stdio pipes are. Anywhere else (`node --import` run by
 * hand), fd 4 is one of Node's own (its event loop's, or a pipe it reads
 * forever), so it is left alone and the nonce stays empty: such a suite
 * cannot end as finished, which the runner would fail.
 */
import { closeSync, fstatSync, readFileSync } from "node:fs";
import { setEndNonce } from "./end-channel.mjs";

export const NONCE_FD = 4;

const opened = process.env.CONFORMANCE_NONCE_FD === String(NONCE_FD);
delete process.env.CONFORMANCE_NONCE_FD;

/** Whether fd is a socket (the runner's pipe); false when it is not open. */
function isSocket(fd) {
  try {
    return fstatSync(fd).isSocket();
  } catch {
    return false;
  }
}

let value = "";
if (opened && isSocket(NONCE_FD)) {
  try {
    value = readFileSync(NONCE_FD, "utf8");
  } catch {
    // Unreadable: no nonce.
  }
  try {
    closeSync(NONCE_FD);
  } catch {
    // Already closed.
  }
}
setEndNonce(value.trim());
