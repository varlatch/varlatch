// SPDX-License-Identifier: Apache-2.0
/**
 * The end-of-suite nonce, held for suite-kit's finish() (suite-kit.mjs).
 * The runner never puts it in the environment: it writes it to fd 4 of the
 * suite's process, and the preload (end-preload.mjs, `node --import`, run
 * before any module of the suite) reads it, closes fd 4 and sets it here.
 * Nothing else reads fd 4, so loading this module outside the runner does
 * nothing.
 */
let nonce = "";

/** Sets the nonce, once (end-preload.mjs). */
export function setEndNonce(value) {
  if (nonce === "" && typeof value === "string") nonce = value;
}

/** The nonce the runner gave this suite, or "" outside the runner. */
export function endNonce() {
  return nonce;
}
