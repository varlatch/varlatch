// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference lib="dom" />
/**
 * Browser glue for the interim enrollment page: the real Better Auth client
 * (bundled at build time — no CDN in the Secret Plane), exposing the minimal
 * ceremony surface. Replaced by apps/web.
 */
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

const authClient = createAuthClient({
  baseURL: `${location.origin}/auth`,
  plugins: [passkeyClient()],
});

async function enroll(token: string, name: string) {
  const result = await authClient.passkey.addPasskey({
    name,
    context: token,
    createSession: true,
  });
  if (result?.error) throw new Error(result.error.message ?? "enrollment failed");
  const exchange = await fetch("/auth/varlatch-token", {
    method: "POST",
    credentials: "include",
  });
  if (!exchange.ok) throw new Error(`token exchange failed: ${exchange.status}`);
  return exchange.json();
}

async function signIn() {
  const result = await authClient.signIn.passkey({ returnWebAuthnResponse: true });
  if (result?.error) {
    // A "Passkey not found" verify failure means the authenticator holds a
    // credential whose server row is gone (e.g. the database was reset).
    // Signal the browser to forget it (WebAuthn Signal API, where supported).
    const stale =
      ("code" in result.error && result.error.code === "PASSKEY_NOT_FOUND") ||
      result.error.message === "Passkey not found";
    const credentialId = (result as { webauthn?: { response?: { id?: string } } }).webauthn
      ?.response?.id;
    if (stale && credentialId) {
      try {
        await (
          PublicKeyCredential as unknown as {
            signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
          }
        ).signalUnknownCredential?.({ rpId: location.hostname, credentialId });
      } catch {
        // Best-effort: older browsers simply keep offering the stale passkey.
      }
      throw new Error(
        "this passkey is no longer registered with the server (it may have been reset). " +
          "It was removed from your authenticator where supported — use another passkey or re-enroll.",
      );
    }
    throw new Error(result.error.message ?? "sign-in failed");
  }
  const exchange = await fetch("/auth/varlatch-token", {
    method: "POST",
    credentials: "include",
  });
  if (!exchange.ok) throw new Error(`token exchange failed: ${exchange.status}`);
  return exchange.json();
}

declare global {
  interface Window {
    varlatch: { enroll: typeof enroll; signIn: typeof signIn };
  }
}
window.varlatch = { enroll, signIn };
