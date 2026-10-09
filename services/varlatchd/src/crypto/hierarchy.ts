// SPDX-License-Identifier: AGPL-3.0-or-later
import { hkdfSync } from "node:crypto";
import {
  decrypt,
  encrypt,
  generateKey,
  type AadContext,
  type Envelope,
} from "./aead.js";

/**
 * The ADR-0011 key hierarchy: Root KEK wraps per-organization KEKs; an
 * Organization KEK wraps per-secret-version DEKs; a DEK encrypts exactly one
 * secret version's payload. Every wrap/encrypt binds canonical identity via
 * AAD so ciphertext cannot be transplanted across rows.
 *
 * AAD `purpose` discriminators prevent cross-purpose envelope reuse (an org
 * KEK envelope can never decrypt as a DEK envelope, etc.).
 */

function orgKekContext(organizationId: string): AadContext {
  return { purpose: "org-kek", organizationId };
}

function dekContext(
  organizationId: string,
  secretId: string,
  versionId: string,
): AadContext {
  return { purpose: "dek", organizationId, secretId, versionId };
}

function payloadContext(
  organizationId: string,
  secretId: string,
  versionId: string,
): AadContext {
  return { purpose: "value", organizationId, secretId, versionId };
}

function webhookSecretContext(organizationId: string, webhookId: string): AadContext {
  return { purpose: "webhook-secret", organizationId, webhookId };
}

function platformCredentialContext(organizationId: string, connectionId: string): AadContext {
  return { purpose: "platform-credential", organizationId, connectionId };
}

function githubAppKeyContext(organizationId: string, githubAppId: string): AadContext {
  return { purpose: "github-app-key", organizationId, githubAppId };
}

/**
 * Platform Credentials (ADR-0031 §1) rest encrypted under the org KEK,
 * exactly like webhook secrets: recoverable (pushes must present them),
 * never displayed after entry.
 */
export function encryptPlatformCredential(
  orgKek: Buffer,
  organizationId: string,
  connectionId: string,
  credential: string,
): Envelope {
  return encrypt(
    orgKek,
    Buffer.from(credential, "utf8"),
    platformCredentialContext(organizationId, connectionId),
  );
}

export function decryptPlatformCredential(
  orgKek: Buffer,
  organizationId: string,
  connectionId: string,
  envelope: Envelope,
): string {
  return decrypt(
    orgKek,
    envelope,
    platformCredentialContext(organizationId, connectionId),
  ).toString("utf8");
}

/**
 * A GitHub App's private key (ADR-0047 Decision 1) rests under the org KEK,
 * bound to its github_apps row, like a Platform Credential: recoverable
 * (minting needs it), never displayed or returned.
 */
export function encryptGitHubAppKey(
  orgKek: Buffer,
  organizationId: string,
  githubAppId: string,
  privateKeyPem: string,
): Envelope {
  return encrypt(orgKek, Buffer.from(privateKeyPem, "utf8"), githubAppKeyContext(organizationId, githubAppId));
}

export function decryptGitHubAppKey(
  orgKek: Buffer,
  organizationId: string,
  githubAppId: string,
  envelope: Envelope,
): string {
  return decrypt(orgKek, envelope, githubAppKeyContext(organizationId, githubAppId)).toString("utf8");
}

/**
 * Sync-ledger content identity (ADR-0031 §3): a keyed fingerprint under a
 * domain-separated key derived from the Organization KEK, per Target — never
 * a bare hash, so database access alone cannot support offline guessing of
 * low-entropy Values. Fingerprints appear in no audit event or log.
 */
export function syncFingerprintKey(orgKek: Buffer, targetId: string): Buffer {
  return Buffer.from(
    hkdfSync("sha256", orgKek, Buffer.alloc(0), `varlatch-sync-fingerprint:${targetId}`, 32),
  );
}

/** Webhook HMAC signing secrets rest encrypted under the org KEK. */
export function encryptWebhookSecret(
  orgKek: Buffer,
  organizationId: string,
  webhookId: string,
  secret: string,
): Envelope {
  return encrypt(
    orgKek,
    Buffer.from(secret, "utf8"),
    webhookSecretContext(organizationId, webhookId),
  );
}

export function decryptWebhookSecret(
  orgKek: Buffer,
  organizationId: string,
  webhookId: string,
  envelope: Envelope,
): string {
  return decrypt(orgKek, envelope, webhookSecretContext(organizationId, webhookId)).toString(
    "utf8",
  );
}

export function createWrappedOrgKek(
  rootKek: Buffer,
  organizationId: string,
): { orgKek: Buffer; wrapped: Envelope } {
  const orgKek = generateKey();
  return { orgKek, wrapped: encrypt(rootKek, orgKek, orgKekContext(organizationId)) };
}

export function unwrapOrgKek(
  rootKek: Buffer,
  wrapped: Envelope,
  organizationId: string,
): Buffer {
  return decrypt(rootKek, wrapped, orgKekContext(organizationId));
}

export function rewrapOrgKek(
  oldRootKek: Buffer,
  newRootKek: Buffer,
  wrapped: Envelope,
  organizationId: string,
): Envelope {
  const orgKek = unwrapOrgKek(oldRootKek, wrapped, organizationId);
  return encrypt(newRootKek, orgKek, orgKekContext(organizationId));
}

export interface EncryptedValue {
  payload: Envelope;
  wrappedDek: Envelope;
}

/** Encrypt one secret-version payload with a fresh DEK (never reused). */
export function encryptValue(
  orgKek: Buffer,
  organizationId: string,
  secretId: string,
  versionId: string,
  plaintext: Buffer,
): EncryptedValue {
  const dek = generateKey();
  return {
    payload: encrypt(dek, plaintext, payloadContext(organizationId, secretId, versionId)),
    wrappedDek: encrypt(orgKek, dek, dekContext(organizationId, secretId, versionId)),
  };
}

export function decryptValue(
  orgKek: Buffer,
  organizationId: string,
  secretId: string,
  versionId: string,
  encrypted: EncryptedValue,
): Buffer {
  const dek = decrypt(
    orgKek,
    encrypted.wrappedDek,
    dekContext(organizationId, secretId, versionId),
  );
  return decrypt(
    dek,
    encrypted.payload,
    payloadContext(organizationId, secretId, versionId),
  );
}
