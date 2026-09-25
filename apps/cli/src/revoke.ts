// SPDX-License-Identifier: Apache-2.0
import type { StoredCredential } from "@varlatch/context";
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * Server-side revocation of a stored credential (ADR-0032), shared by
 * `logout` and by `login` replacing an existing entry. The credential
 * revokes itself via DELETE /v1/me/credentials/:id, which works whichever
 * identity it belongs to. Returns null on success, else the failure reason
 * for verbatim disclosure — callers never abort on it.
 */
export async function revokeStoredCredential(
  credential: StoredCredential,
  revoke: (credentialId: string) => Promise<unknown>,
): Promise<string | null> {
  if (!credential.credentialId) return "no credential id recorded by this login";
  try {
    await revoke(credential.credentialId);
    return null;
  } catch (err) {
    if (err instanceof VarlatchApiError) return err.code;
    return err instanceof Error ? err.message : String(err);
  }
}

/**
 * The entry a fresh `login` is about to overwrite, if it may still be live
 * server-side. Without this, every re-login (the renew path — there is no
 * auto-renewal, ADR-0032) orphans a working token until its expiry, with
 * nothing left on disk pointing at it.
 */
export function replacedCredential(
  previous: StoredCredential | null,
  nextToken: string,
  now: number = Date.now(),
): StoredCredential | null {
  if (!previous || previous.token === nextToken) return null;
  if (previous.expiresAt && Date.parse(previous.expiresAt) <= now) return null;
  return previous;
}
