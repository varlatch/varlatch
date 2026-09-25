// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { CryptoError, decrypt, encrypt, generateKey } from "../src/crypto/aead.js";
import {
  createWrappedOrgKek,
  decryptValue,
  encryptValue,
  rewrapOrgKek,
  unwrapOrgKek,
} from "../src/crypto/hierarchy.js";
import { createCanary, verifyKekAgainstCanary } from "../src/crypto/canary.js";

describe("aead", () => {
  it("round-trips with matching AAD context", () => {
    const key = generateKey();
    const env = encrypt(key, Buffer.from("hello"), { purpose: "t", id: "1" });
    expect(decrypt(key, env, { id: "1", purpose: "t" }).toString()).toBe("hello");
  });

  it("fails on AAD context mismatch (ciphertext transplant)", () => {
    const key = generateKey();
    const env = encrypt(key, Buffer.from("hello"), { purpose: "t", id: "1" });
    expect(() => decrypt(key, env, { purpose: "t", id: "2" })).toThrow(CryptoError);
  });

  it("fails on ciphertext or tag tampering", () => {
    const key = generateKey();
    const env = encrypt(key, Buffer.from("hello"), { purpose: "t", id: "1" });
    const flipped = Buffer.from(env.ciphertext, "base64");
    flipped[0] = (flipped[0] ?? 0) ^ 0xff;
    expect(() =>
      decrypt(key, { ...env, ciphertext: flipped.toString("base64") }, { purpose: "t", id: "1" }),
    ).toThrow(CryptoError);
  });

  it("fails with the wrong key", () => {
    const env = encrypt(generateKey(), Buffer.from("x"), { purpose: "t", id: "1" });
    expect(() => decrypt(generateKey(), env, { purpose: "t", id: "1" })).toThrow(
      CryptoError,
    );
  });

  it("rejects unsupported envelope versions", () => {
    const key = generateKey();
    const env = encrypt(key, Buffer.from("x"), { purpose: "t", id: "1" });
    expect(() =>
      decrypt(key, { ...env, formatVersion: 2 as 1 }, { purpose: "t", id: "1" }),
    ).toThrow(CryptoError);
  });
});

describe("key hierarchy", () => {
  const root = generateKey();

  it("wraps and unwraps org KEKs bound to the organization", () => {
    const { orgKek, wrapped } = createWrappedOrgKek(root, "org_1");
    expect(unwrapOrgKek(root, wrapped, "org_1").equals(orgKek)).toBe(true);
    expect(() => unwrapOrgKek(root, wrapped, "org_2")).toThrow(CryptoError);
  });

  it("value encryption round-trips and is identity-bound", () => {
    const { orgKek } = createWrappedOrgKek(root, "org_1");
    const enc = encryptValue(orgKek, "org_1", "sec_1", "v_1", Buffer.from("s3cret"));
    expect(
      decryptValue(orgKek, "org_1", "sec_1", "v_1", enc).toString(),
    ).toBe("s3cret");
    // Transplanting to another version/secret/org fails authentication.
    expect(() => decryptValue(orgKek, "org_1", "sec_1", "v_2", enc)).toThrow(CryptoError);
    expect(() => decryptValue(orgKek, "org_1", "sec_2", "v_1", enc)).toThrow(CryptoError);
    expect(() => decryptValue(orgKek, "org_2", "sec_1", "v_1", enc)).toThrow(CryptoError);
  });

  it("org KEK envelopes cannot be abused as DEK envelopes (purpose separation)", () => {
    const { wrapped } = createWrappedOrgKek(root, "org_1");
    expect(() =>
      decrypt(root, wrapped, { purpose: "dek", organizationId: "org_1", secretId: "s", versionId: "v" }),
    ).toThrow(CryptoError);
  });

  it("root KEK rotation rewraps without touching value ciphertext", () => {
    const newRoot = generateKey();
    const { orgKek, wrapped } = createWrappedOrgKek(root, "org_1");
    const enc = encryptValue(orgKek, "org_1", "sec_1", "v_1", Buffer.from("payload"));
    const rewrapped = rewrapOrgKek(root, newRoot, wrapped, "org_1");
    const recovered = unwrapOrgKek(newRoot, rewrapped, "org_1");
    expect(recovered.equals(orgKek)).toBe(true);
    expect(
      decryptValue(recovered, "org_1", "sec_1", "v_1", enc).toString(),
    ).toBe("payload");
    // Old root no longer unwraps the rewrapped envelope.
    expect(() => unwrapOrgKek(root, rewrapped, "org_1")).toThrow(CryptoError);
  });
});

describe("KEK canary", () => {
  it("verifies the right KEK and rejects a wrong one", () => {
    const root = generateKey();
    const canary = createCanary(root, "inst_1");
    expect(verifyKekAgainstCanary(root, canary, "inst_1")).toBe(true);
    expect(verifyKekAgainstCanary(generateKey(), canary, "inst_1")).toBe(false);
    // Bound to the installation identity.
    expect(verifyKekAgainstCanary(root, canary, "inst_2")).toBe(false);
  });
});
