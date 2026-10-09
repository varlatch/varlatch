// SPDX-License-Identifier: AGPL-3.0-or-later
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useQueryClient } from "@tanstack/react-query";
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { VarlatchClient } from "@varlatch/sdk";

/**
 * Session lifecycle (design R2 §Q4): the /v1 bearer lives in memory only.
 * A 401 silently re-exchanges once through the httpOnly Better Auth session;
 * if that fails, `needsAuth` flips and the shell renders a route-preserving
 * sign-in interstitial. Server-disclosed plaintext never survives the auth
 * boundary (owners of disclosed state subscribe to `authEpoch`).
 *
 * Isolating maintenance (restore, schema migration; ADR-0036 D6) answers
 * 503 MAINTENANCE — including to the session exchange. That is never shown
 * as being signed out: `maintenance` flips instead, the exchange retries on
 * its own, and any normal answer clears it.
 */

const authClient = createAuthClient({
  baseURL: `${location.origin}/auth`,
  plugins: [passkeyClient()],
});

interface SessionState {
  identityId: string | null;
  needsAuth: boolean;
  /** The installation answered MAINTENANCE and has not answered normally since. */
  maintenance: boolean;
  /** Increments on every (re-)authentication: disclosed state must reset. */
  authEpoch: number;
  api: VarlatchClient;
  /** fetch with this session's bearer and its one silent re-exchange on 401, for another origin of this installation. */
  fetch: typeof fetch;
  mintConvexToken: () => Promise<string | null>;
  signInWithPasskey: () => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionState | null>(null);

/** Enrolled passkeys for the signed-in Better Auth user (My Credentials). */
export interface PasskeyInfo {
  id: string;
  name: string | null;
  deviceType: string;
  backedUp: boolean;
  createdAt: string;
}

export async function listPasskeys(): Promise<PasskeyInfo[]> {
  const res = await authClient.$fetch("/passkey/list-user-passkeys", { method: "GET" });
  if (res.error) throw new Error(res.error.message ?? "could not list passkeys");
  return res.data as PasskeyInfo[];
}

export async function addPasskey(name: string): Promise<void> {
  const result = await authClient.passkey.addPasskey({ name });
  if (result?.error) throw new Error(result.error.message ?? "passkey enrollment failed");
}

export async function deletePasskey(id: string): Promise<void> {
  const res = await authClient.$fetch("/passkey/delete-passkey", {
    method: "POST",
    body: { id },
  });
  if (res.error) throw new Error(res.error.message ?? "could not remove passkey");
}

/**
 * A "Passkey not found" verify failure means the authenticator holds a
 * credential whose server row is gone (e.g. the database was reset). Signal
 * the browser to forget it (WebAuthn Signal API, where supported) so the
 * stale passkey stops being offered, and explain what happened.
 */
async function signInPasskeyWithStaleCleanup(client: typeof authClient): Promise<void> {
  const result = await client.signIn.passkey({ returnWebAuthnResponse: true });
  if (!result?.error) return;
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

type Exchange =
  | { kind: "ok"; token: string; identityId: string }
  | { kind: "signed-out" }
  | { kind: "maintenance"; retryAfterMs: number };

async function isMaintenance(res: Response): Promise<boolean> {
  if (res.status !== 503) return false;
  const body = (await res.clone().json().catch(() => null)) as { error?: { code?: string } } | null;
  return body?.error?.code === "MAINTENANCE";
}

/**
 * Wait for `promise`, but stop at once when `signal` aborts, with its
 * reason. What it waits for goes on (others may share it); this caller
 * does not.
 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal | null | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (err: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(err);
      },
    );
  });
}

async function exchange(): Promise<Exchange> {
  const res = await fetch("/auth/varlatch-token", { method: "POST", credentials: "include" });
  if (res.ok) return { kind: "ok", ...((await res.json()) as { token: string; identityId: string }) };
  if (await isMaintenance(res)) {
    const after = Number(res.headers.get("Retry-After"));
    return { kind: "maintenance", retryAfterMs: (Number.isFinite(after) && after > 0 ? after : 5) * 1000 };
  }
  return { kind: "signed-out" };
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const bearer = useRef<string | null>(null);
  const currentIdentity = useRef<string | null>(null);
  const generation = useRef(0);
  const refreshing = useRef<ReturnType<typeof exchange> | null>(null);
  const clearSession = useCallback(() => {
    generation.current++;
    refreshing.current = null;
    bearer.current = null;
    currentIdentity.current = null;
    void queryClient.cancelQueries();
    queryClient.clear();
    setIdentityId(null);
    setNeedsAuth(true);
    setAuthEpoch(n => n + 1);
  }, [queryClient]);
  const [identityId, setIdentityId] = useState<string | null>(null);
  const [needsAuth, setNeedsAuth] = useState(false);
  const [maintenance, setMaintenance] = useState(false);
  const [checked, setChecked] = useState(false);
  const [authEpoch, setAuthEpoch] = useState(0);

  const adopt = useCallback((token: string, id: string) => {
    if (currentIdentity.current !== id) {
      generation.current++;
      void queryClient.cancelQueries();
      queryClient.clear();
    }
    currentIdentity.current = id;
    bearer.current = token;
    setIdentityId(id);
    setNeedsAuth(false);
    setAuthEpoch((n) => n + 1);
  }, [queryClient]);

  useEffect(() => {
    const started = generation.current;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = () => {
      void exchange().then((r) => {
        if (started !== generation.current) return;
        if (r.kind === "maintenance") {
          setMaintenance(true);
          // Never "signed out" during maintenance: try again on its own.
          timer = setTimeout(attempt, r.retryAfterMs * (0.8 + 0.4 * Math.random()));
        } else {
          setMaintenance(false);
          if (r.kind === "ok") adopt(r.token, r.identityId);
          else setNeedsAuth(true);
        }
        setChecked(true);
      });
    };
    attempt();
    return () => clearTimeout(timer);
  }, [adopt]);

  /** Fetch with bearer injection and one silent re-exchange on 401. */
  const sessionFetch = useCallback<typeof fetch>(
    async (input, init) => {
      const started = generation.current;
      const assertCurrent = () => {
        if (started !== generation.current) throw new DOMException("Session changed", "AbortError");
      };
      const doFetch = () =>
        globalThis.fetch(input, {
          ...init,
          headers: {
            ...(init?.headers as Record<string, string>),
            ...(bearer.current ? { Authorization: `Bearer ${bearer.current}` } : {}),
          },
        });
      let res = await doFetch();
      assertCurrent();
      if (res.status === 401) {
        const pending = refreshing.current ??= exchange();
        pending
          .finally(() => {
            if (refreshing.current === pending) refreshing.current = null;
          })
          .catch(() => {});
        // A caller's deadline covers the re-exchange too, and a request
        // given up on is never sent again once it lands.
        const refreshed = await untilAborted(pending, init?.signal);
        assertCurrent();
        if (refreshed.kind === "ok") {
          adopt(refreshed.token, refreshed.identityId);
          assertCurrent();
          if (init?.signal?.aborted) throw init.signal.reason;
          res = await doFetch();
          assertCurrent();
        } else if (refreshed.kind === "signed-out") {
          clearSession();
        }
        // Maintenance: keep the session; the SDK retries the request.
      }
      // Observed on every response the dashboard makes; the SDK rides out
      // the window itself (ADR-0036 D6).
      if (await isMaintenance(res)) setMaintenance(true);
      else if (res.ok) setMaintenance(false);
      return res;
    },
    [adopt, clearSession],
  );

  const api = useMemo(
    () => new VarlatchClient({ server: location.origin, fetch: sessionFetch }),
    [sessionFetch],
  );

  const signInWithPasskey = useCallback(async () => {
    const started = generation.current;
    await signInPasskeyWithStaleCleanup(authClient);
    const r = await exchange();
    if (started !== generation.current) throw new DOMException("Session changed", "AbortError");
    if (r.kind === "maintenance") throw new Error("Varlatch is in maintenance; try again in a moment");
    if (r.kind !== "ok") throw new Error("session exchange failed");
    adopt(r.token, r.identityId);
  }, [adopt]);

  const mintConvexToken = useCallback(async () => {
    const res = await sessionFetch("/v1/tokens/convex", { method: "POST" });
    if (!res.ok) return null;
    const body = (await res.json()) as { token: string };
    return body.token;
  }, [sessionFetch]);

  const signOut = useCallback(async () => {
    clearSession();
    await authClient.signOut().catch(() => undefined);
  }, [clearSession]);

  const value = useMemo(
    () => ({ identityId, needsAuth, maintenance, authEpoch, api, fetch: sessionFetch, mintConvexToken, signInWithPasskey, signOut }),
    [identityId, needsAuth, maintenance, authEpoch, api, sessionFetch, mintConvexToken, signInWithPasskey, signOut],
  );

  if (!checked) return <p className="p-8 text-muted">Loading…</p>;
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}
