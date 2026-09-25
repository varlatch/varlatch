// SPDX-License-Identifier: Apache-2.0
import nacl from "tweetnacl";
import blake from "blakejs";

/**
 * libsodium crypto_box_seal, as GitHub's secret encryption requires:
 * ephemeral X25519 keypair, nonce = BLAKE2b-24(epk || recipient_pk),
 * output = epk || box(msg). tweetnacl provides crypto_box
 * (x25519-xsalsa20-poly1305); blakejs provides the parameterized-length
 * BLAKE2b that node:crypto lacks.
 */
export function sealedBox(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const ephemeral = nacl.box.keyPair();
  const nonce = blake.blake2b(
    concat(ephemeral.publicKey, recipientPublicKey),
    undefined,
    nacl.box.nonceLength,
  );
  const boxed = nacl.box(message, nonce, recipientPublicKey, ephemeral.secretKey);
  return concat(ephemeral.publicKey, boxed);
}

/** Test-only counterpart proving seal round-trips against a known keypair. */
export function sealedBoxOpen(
  sealed: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientSecretKey: Uint8Array,
): Uint8Array | null {
  const epk = sealed.slice(0, nacl.box.publicKeyLength);
  const boxed = sealed.slice(nacl.box.publicKeyLength);
  const nonce = blake.blake2b(concat(epk, recipientPublicKey), undefined, nacl.box.nonceLength);
  return nacl.box.open(boxed, nonce, epk, recipientSecretKey);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
