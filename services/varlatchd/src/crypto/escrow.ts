// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomBytes, scryptSync } from "node:crypto";
import { CryptoError, decrypt, encrypt, KEY_BYTES, type Envelope } from "./aead.js";

/**
 * Root-KEK backup escrow (companion to ADR-0011's hierarchy):
 *
 * 1. Passphrase escrow: the raw KEK wrapped by a scrypt-derived key. The
 *    resulting blob is safe to store anywhere — including next to database
 *    backups — because possession of the blob alone yields nothing. KDF
 *    parameters are bound into the AEAD AAD so they cannot be weakened
 *    after the fact.
 *
 * 2. Shamir secret sharing over GF(2^8): split the KEK into n shares of
 *    which any k reconstruct it and any k-1 reveal nothing. Each share
 *    embeds the scheme parameters plus a 32-bit fingerprint of the KEK so
 *    a mistyped or mismatched share set is detected offline (32 bits of a
 *    random 256-bit key is a negligible confirmation oracle).
 *
 * This module never logs and never includes key material in errors.
 */

export const ESCROW_FORMAT_VERSION = 1;

/** scrypt cost parameters; interactive-use hardened (~128 MiB, ~0.5s). */
const SCRYPT = { N: 1 << 17, r: 8, p: 1 } as const;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;
const SALT_BYTES = 16;
export const MIN_PASSPHRASE_LENGTH = 12;

export interface EscrowBlob {
  formatVersion: typeof ESCROW_FORMAT_VERSION;
  kind: "varlatch-kek-escrow";
  kdf: {
    algorithm: "scrypt";
    N: number;
    r: number;
    p: number;
    /** base64 */
    salt: string;
  };
  envelope: Envelope;
}

function escrowContext(kdf: EscrowBlob["kdf"]) {
  return {
    purpose: "kek-escrow",
    kdfAlgorithm: kdf.algorithm,
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    salt: kdf.salt,
  };
}

function deriveKey(passphrase: string, kdf: EscrowBlob["kdf"]): Buffer {
  return scryptSync(Buffer.from(passphrase, "utf8"), Buffer.from(kdf.salt, "base64"), KEY_BYTES, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: SCRYPT_MAXMEM,
  });
}

export function exportKekEscrow(rootKek: Buffer, passphrase: string): EscrowBlob {
  if (rootKek.length !== KEY_BYTES) throw new CryptoError("Invalid KEK length");
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new CryptoError(
      `Escrow passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
    );
  }
  const kdf: EscrowBlob["kdf"] = {
    algorithm: "scrypt",
    ...SCRYPT,
    salt: randomBytes(SALT_BYTES).toString("base64"),
  };
  return {
    formatVersion: ESCROW_FORMAT_VERSION,
    kind: "varlatch-kek-escrow",
    kdf,
    envelope: encrypt(deriveKey(passphrase, kdf), rootKek, escrowContext(kdf)),
  };
}

export function restoreKekEscrow(blob: EscrowBlob, passphrase: string): Buffer {
  if (blob.kind !== "varlatch-kek-escrow" || blob.formatVersion !== ESCROW_FORMAT_VERSION) {
    throw new CryptoError("Not a supported varlatch KEK escrow blob");
  }
  if (blob.kdf.algorithm !== "scrypt") throw new CryptoError("Unsupported escrow KDF");
  // Refuse maliciously weakened parameters even though AAD binding would
  // already fail decryption for a legitimately produced blob.
  if (blob.kdf.N < 1 << 14 || blob.kdf.r < 8 || blob.kdf.p < 1) {
    throw new CryptoError("Escrow KDF parameters below the accepted minimum");
  }
  const kek = decrypt(deriveKey(passphrase, blob.kdf), blob.envelope, escrowContext(blob.kdf));
  if (kek.length !== KEY_BYTES) throw new CryptoError("Escrowed key has invalid length");
  return kek;
}

// ---------------------------------------------------------------------------
// Shamir secret sharing over GF(2^8), reduction polynomial x^8+x^4+x^3+x+1.

function gfMul(a: number, b: number): number {
  let product = 0;
  while (b > 0) {
    if (b & 1) product ^= a;
    a <<= 1;
    if (a & 0x100) a ^= 0x11b;
    b >>= 1;
  }
  return product;
}

function gfInv(a: number): number {
  if (a === 0) throw new CryptoError("Division by zero in GF(256)");
  // a^254 = a^-1 in GF(2^8).
  let result = 1;
  for (let i = 0; i < 254; i++) result = gfMul(result, a);
  return result;
}

const SHARE_PREFIX = "vlks1";

function kekFingerprint(rootKek: Buffer): string {
  return createHash("sha256").update(rootKek).digest("hex").slice(0, 8);
}

export function splitKek(
  rootKek: Buffer,
  opts: { shares: number; threshold: number },
): { shares: string[]; fingerprint: string } {
  const { shares: n, threshold: k } = opts;
  if (rootKek.length !== KEY_BYTES) throw new CryptoError("Invalid KEK length");
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > 255) {
    throw new CryptoError("Require 2 <= threshold <= shares <= 255");
  }
  // One random polynomial of degree k-1 per secret byte; constant term is
  // the secret byte, share x-coordinates are 1..n.
  const coefficients = rootKek.length;
  const polys: Buffer[] = [];
  for (let byte = 0; byte < coefficients; byte++) {
    const poly = Buffer.concat([rootKek.subarray(byte, byte + 1), randomBytes(k - 1)]);
    polys.push(poly);
  }
  const fingerprint = kekFingerprint(rootKek);
  const out: string[] = [];
  for (let x = 1; x <= n; x++) {
    const y = Buffer.alloc(coefficients);
    for (let byte = 0; byte < coefficients; byte++) {
      const poly = polys[byte] as Buffer;
      let acc = 0;
      // Horner evaluation at x.
      for (let c = k - 1; c >= 0; c--) acc = gfMul(acc, x) ^ (poly[c] as number);
      y[byte] = acc;
    }
    out.push(`${SHARE_PREFIX}.${x}.${k}.${y.toString("base64url")}.${fingerprint}`);
  }
  return { shares: out, fingerprint };
}

interface ParsedShare {
  x: number;
  threshold: number;
  y: Buffer;
  fingerprint: string;
}

function parseShare(share: string): ParsedShare {
  const parts = share.trim().split(".");
  if (parts.length !== 5 || parts[0] !== SHARE_PREFIX) {
    throw new CryptoError("Malformed share (expected vlks1.<x>.<k>.<data>.<fingerprint>)");
  }
  const x = Number(parts[1]);
  const threshold = Number(parts[2]);
  const y = Buffer.from(parts[3] as string, "base64url");
  const fingerprint = parts[4] as string;
  if (!Number.isInteger(x) || x < 1 || x > 255 || !Number.isInteger(threshold) || threshold < 2) {
    throw new CryptoError("Malformed share coordinates");
  }
  if (y.length !== KEY_BYTES || !/^[0-9a-f]{8}$/.test(fingerprint)) {
    throw new CryptoError("Malformed share payload");
  }
  return { x, threshold, y, fingerprint };
}

export function combineKek(shareStrings: string[]): Buffer {
  const shares = shareStrings.map(parseShare);
  if (shares.length === 0) throw new CryptoError("No shares provided");
  const { threshold, fingerprint } = shares[0] as ParsedShare;
  if (shares.some((s) => s.threshold !== threshold || s.fingerprint !== fingerprint)) {
    throw new CryptoError("Shares are from different splits (threshold/fingerprint mismatch)");
  }
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) throw new CryptoError("Duplicate shares provided");
  if (shares.length < threshold) {
    throw new CryptoError(`Need ${threshold} distinct shares, got ${shares.length}`);
  }
  const used = shares.slice(0, threshold);
  const secret = Buffer.alloc(KEY_BYTES);
  for (let byte = 0; byte < KEY_BYTES; byte++) {
    let acc = 0;
    for (const si of used) {
      // Lagrange basis at x=0: prod_{j != i} x_j / (x_j ^ x_i).
      let basis = 1;
      for (const sj of used) {
        if (sj.x === si.x) continue;
        basis = gfMul(basis, gfMul(sj.x, gfInv(sj.x ^ si.x)));
      }
      acc ^= gfMul(si.y[byte] as number, basis);
    }
    secret[byte] = acc;
  }
  if (kekFingerprint(secret) !== fingerprint) {
    throw new CryptoError(
      "Combined key does not match the split's fingerprint (wrong or corrupted share)",
    );
  }
  return secret;
}
