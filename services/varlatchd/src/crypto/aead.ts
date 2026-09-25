// SPDX-License-Identifier: AGPL-3.0-or-later
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { canonicalJson } from "@varlatch/contract";

/**
 * AEAD primitives per ADR-0011: AES-256-GCM via Node's built-in crypto, random
 * 96-bit nonces, 128-bit tags, strict tag verification, and AAD bound through
 * the canonical JSON encoding (never ambiguous string concatenation).
 *
 * Envelopes are versioned so algorithms/formats can evolve. This module never
 * logs and never includes plaintext or key material in errors.
 */

export const ENVELOPE_FORMAT_VERSION = 1;
export const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
export const KEY_BYTES = 32;

/** Versioned ciphertext envelope. Safe to persist; contains no key material. */
export interface Envelope {
  formatVersion: typeof ENVELOPE_FORMAT_VERSION;
  algorithm: typeof ALGORITHM;
  /** base64 */
  nonce: string;
  /** base64 */
  ciphertext: string;
  /** base64 */
  authTag: string;
}

/** AAD context objects are canonically encoded; key order never matters. */
export type AadContext = Record<string, string | number>;

export class CryptoError extends Error {
  override name = "CryptoError";
  constructor(message: string) {
    // Deliberately terse: no plaintext, key material, or AAD echo.
    super(message);
  }
}

export function generateKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

function encodeAad(context: AadContext): Buffer {
  return Buffer.from(canonicalJson(context), "utf8");
}

export function encrypt(
  key: Buffer,
  plaintext: Buffer,
  context: AadContext,
): Envelope {
  if (key.length !== KEY_BYTES) throw new CryptoError("Invalid key length");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(encodeAad(context));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    formatVersion: ENVELOPE_FORMAT_VERSION,
    algorithm: ALGORITHM,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
  };
}

export function decrypt(
  key: Buffer,
  envelope: Envelope,
  context: AadContext,
): Buffer {
  if (key.length !== KEY_BYTES) throw new CryptoError("Invalid key length");
  if (envelope.formatVersion !== ENVELOPE_FORMAT_VERSION) {
    throw new CryptoError(`Unsupported envelope format ${envelope.formatVersion}`);
  }
  if (envelope.algorithm !== ALGORITHM) {
    throw new CryptoError("Unsupported envelope algorithm");
  }
  const nonce = Buffer.from(envelope.nonce, "base64");
  const authTag = Buffer.from(envelope.authTag, "base64");
  if (nonce.length !== NONCE_BYTES || authTag.length !== TAG_BYTES) {
    throw new CryptoError("Malformed envelope");
  }
  const decipher = createDecipheriv(ALGORITHM, key, nonce, {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(encodeAad(context));
  decipher.setAuthTag(authTag);
  try {
    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new CryptoError("Decryption failed: authentication error");
  }
}
