// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomBytes } from "node:crypto";
import { decrypt, encrypt, type Envelope } from "./aead.js";

/**
 * Installation KEK canary (ADR-0019): a random installation-specific value
 * encrypted under the root KEK. Startup and `varlatch admin kek verify` prove
 * possession of a working KEK by authenticated decryption — never by touching
 * user secret Values, never printing key material.
 */

function canaryContext(installationId: string) {
  return { purpose: "kek-canary", installationId };
}

export function createCanary(rootKek: Buffer, installationId: string): Envelope {
  return encrypt(rootKek, randomBytes(32), canaryContext(installationId));
}

export function verifyKekAgainstCanary(
  candidateKek: Buffer,
  canary: Envelope,
  installationId: string,
): boolean {
  try {
    decrypt(candidateKek, canary, canaryContext(installationId));
    return true;
  } catch {
    return false;
  }
}
