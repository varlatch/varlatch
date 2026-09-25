// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { CryptoError, generateKey } from "../src/crypto/aead.js";
import {
  combineKek,
  exportKekEscrow,
  restoreKekEscrow,
  splitKek,
  type EscrowBlob,
} from "../src/crypto/escrow.js";

const PASSPHRASE = "correct horse battery staple";

describe("kek passphrase escrow", () => {
  it("round-trips the KEK through an escrow blob", () => {
    const kek = generateKey();
    const blob = exportKekEscrow(kek, PASSPHRASE);
    expect(restoreKekEscrow(blob, PASSPHRASE).equals(kek)).toBe(true);
  });

  it("rejects the wrong passphrase", () => {
    const blob = exportKekEscrow(generateKey(), PASSPHRASE);
    expect(() => restoreKekEscrow(blob, "wrong horse battery staple")).toThrow(CryptoError);
  });

  it("rejects short passphrases at export time", () => {
    expect(() => exportKekEscrow(generateKey(), "short")).toThrow(CryptoError);
  });

  it("rejects tampered KDF parameters (AAD binding)", () => {
    const blob = exportKekEscrow(generateKey(), PASSPHRASE);
    const weakened: EscrowBlob = { ...blob, kdf: { ...blob.kdf, N: 1 << 14 } };
    expect(() => restoreKekEscrow(weakened, PASSPHRASE)).toThrow(CryptoError);
  });

  it("rejects KDF parameters below the accepted minimum outright", () => {
    const blob = exportKekEscrow(generateKey(), PASSPHRASE);
    const weakened: EscrowBlob = { ...blob, kdf: { ...blob.kdf, N: 1024 } };
    expect(() => restoreKekEscrow(weakened, PASSPHRASE)).toThrow(CryptoError);
  });

  it("blob contains no key material and serializes through JSON", () => {
    const kek = generateKey();
    const blob = exportKekEscrow(kek, PASSPHRASE);
    const json = JSON.stringify(blob);
    expect(json).not.toContain(kek.toString("hex"));
    expect(json).not.toContain(kek.toString("base64"));
    expect(restoreKekEscrow(JSON.parse(json) as EscrowBlob, PASSPHRASE).equals(kek)).toBe(true);
  });
});

describe("kek shamir sharing", () => {
  it("reconstructs from exactly the threshold, any subset", () => {
    const kek = generateKey();
    const { shares } = splitKek(kek, { shares: 5, threshold: 3 });
    expect(combineKek([shares[0]!, shares[2]!, shares[4]!]).equals(kek)).toBe(true);
    expect(combineKek([shares[3]!, shares[1]!, shares[2]!]).equals(kek)).toBe(true);
    expect(combineKek(shares).equals(kek)).toBe(true);
  });

  it("supports 2-of-2", () => {
    const kek = generateKey();
    const { shares } = splitKek(kek, { shares: 2, threshold: 2 });
    expect(combineKek(shares).equals(kek)).toBe(true);
  });

  it("refuses fewer shares than the threshold", () => {
    const { shares } = splitKek(generateKey(), { shares: 5, threshold: 3 });
    expect(() => combineKek(shares.slice(0, 2))).toThrow(CryptoError);
  });

  it("refuses duplicate shares", () => {
    const { shares } = splitKek(generateKey(), { shares: 3, threshold: 2 });
    expect(() => combineKek([shares[0]!, shares[0]!])).toThrow(CryptoError);
  });

  it("detects a share from a different split via the fingerprint", () => {
    const a = splitKek(generateKey(), { shares: 3, threshold: 2 }).shares;
    const b = splitKek(generateKey(), { shares: 3, threshold: 2 }).shares;
    expect(() => combineKek([a[0]!, b[1]!])).toThrow(CryptoError);
  });

  it("detects a corrupted share payload", () => {
    const { shares } = splitKek(generateKey(), { shares: 3, threshold: 2 });
    const parts = shares[0]!.split(".");
    const data = Buffer.from(parts[3]!, "base64url");
    data[0]! ^= 0xff;
    parts[3] = data.toString("base64url");
    expect(() => combineKek([parts.join("."), shares[1]!])).toThrow(CryptoError);
  });

  it("rejects invalid split parameters", () => {
    const kek = generateKey();
    expect(() => splitKek(kek, { shares: 2, threshold: 3 })).toThrow(CryptoError);
    expect(() => splitKek(kek, { shares: 3, threshold: 1 })).toThrow(CryptoError);
    expect(() => splitKek(kek, { shares: 256, threshold: 3 })).toThrow(CryptoError);
  });
});
