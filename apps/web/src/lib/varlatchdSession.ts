// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

/**
 * The browser session of the Go server (ADR-0059 Decision 6), used when
 * /v1/meta lists auth.session (lib/backend.ts): /auth/session gives the
 * signed-in identity and the CSRF token every POST under /auth carries in
 * Varlatch-CSRF; the session itself is an HttpOnly cookie this code never
 * sees. The same calls as Better Auth's client gives the TypeScript server:
 * sign in with a passkey, add a passkey, sign out, and the bearer exchange.
 */

export class SessionRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | null,
    readonly response: Response,
  ) {
    super(message);
  }
}

let csrf: Promise<{ csrfToken: string; identityId: string | null }> | null = null;

/** The session state and CSRF token; fetched again when `fresh`. */
export function browserSession(fresh = false): Promise<{ csrfToken: string; identityId: string | null }> {
  if (!csrf || fresh) {
    const pending = fetch("/auth/session", { credentials: "include", headers: { Accept: "application/json" } }).then(async (res) => {
      if (!res.ok) throw new SessionRequestError(`session check failed: ${res.status}`, res.status, null, res);
      return (await res.json()) as { csrfToken: string; identityId: string | null };
    });
    csrf = pending;
    pending.catch(() => {
      if (csrf === pending) csrf = null;
    });
  }
  return csrf;
}

/** A POST under /auth, with the CSRF token; the response, whatever its status. */
export async function authPost(path: string, body?: unknown): Promise<Response> {
  const { csrfToken } = await browserSession();
  return fetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json", Accept: "application/json", "Varlatch-CSRF": csrfToken },
    body: JSON.stringify(body ?? {}),
  });
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await authPost(path, body);
  const json = (await res.json().catch(() => null)) as { error?: { code?: string; message?: string } } | null;
  if (!res.ok) {
    throw new SessionRequestError(json?.error?.message ?? `${path} failed: ${res.status}`, res.status, json?.error?.code ?? null, res);
  }
  return json as T;
}

/**
 * Sign in with a discoverable passkey. A passkey this server no longer
 * holds (the database was reset, say) is signalled to the browser to
 * forget, where supported, and explained.
 */
export async function signInWithPasskey(): Promise<void> {
  const { publicKey } = await postJson<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>("/auth/passkey/sign-in/options");
  const response = await startAuthentication({ optionsJSON: publicKey });
  try {
    await postJson("/auth/passkey/sign-in", { response });
  } catch (err) {
    if (err instanceof SessionRequestError && err.code === "PASSKEY_NOT_FOUND") {
      try {
        await (
          PublicKeyCredential as unknown as {
            signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
          }
        ).signalUnknownCredential?.({ rpId: location.hostname, credentialId: response.id });
      } catch {
        // Best-effort: older browsers simply keep offering the stale passkey.
      }
      throw new Error(
        "this passkey is no longer registered with the server (it may have been reset). " +
          "It was removed from your authenticator where supported; use another passkey or re-enroll.",
      );
    }
    throw err;
  }
}

/** Add a passkey to the signed-in person; it starts unconfirmed (ADR-0054 Decision 4). */
export async function addPasskey(name: string): Promise<void> {
  const { publicKey } = await postJson<{ publicKey: PublicKeyCredentialCreationOptionsJSON }>("/auth/passkey/registration/options", {});
  const response = await startRegistration({ optionsJSON: publicKey });
  await postJson("/auth/passkey/registration", { response, ...(name ? { name } : {}) });
}

/** End the session: its browser bearers are revoked with it. */
export async function signOut(): Promise<void> {
  await authPost("/auth/sign-out");
}
