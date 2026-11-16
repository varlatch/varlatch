// SPDX-License-Identifier: Apache-2.0
import nacl from "tweetnacl";

/**
 * The recipients' secret keys of the Go vectors' extra GitHub public keys
 * (SEAL_PUBLIC_KEYS): a value sealed to one of them is recorded opened, so
 * the replays (TypeScript and Go) compare the plaintext each language sent.
 */
export const SEAL_SECRETS = ["5a".repeat(32), "c3".repeat(32)];

export const SEAL_PUBLIC_KEYS = SEAL_SECRETS.map((hex) =>
  Buffer.from(nacl.box.keyPair.fromSecretKey(new Uint8Array(Buffer.from(hex, "hex"))).publicKey).toString("base64"),
);
