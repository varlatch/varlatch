// SPDX-License-Identifier: AGPL-3.0-or-later
import type { EntryLinkView } from "@varlatch/protocol";
import * as varlatchd from "../../lib/varlatchdSession";

/**
 * What the entry page (ADR-0063) asks of varlatchd: the link's view, the one
 * submission, and a person's sign-in where the link needs one. It imports
 * nothing of the dashboard; the link's secret, the bearer and the value are
 * in this page's memory only, and go in request bodies and one header.
 */

/** The link's secret, taken out of the address before anything else happens. */
export function takeToken(): string {
  const token = decodeHash(window.location.hash);
  // No history entry keeps it, and nothing that reads the address sees it.
  if (window.location.hash !== "") window.history.replaceState(null, "", window.location.pathname);
  return token;
}

function decodeHash(hash: string): string {
  const raw = hash.replace(/^#/, "");
  return /^vlt_entry_[A-Za-z0-9_-]{10,100}$/.test(raw) ? raw : "";
}

/** A refusal, in the words the person reads. */
export class EntryRefusal extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly reason: string | null,
  ) {
    super(message);
  }
}

async function post<T>(path: string, body: unknown, bearer: string | null): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: "POST",
      // Cookies authenticate nothing here.
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "error",
      headers: { "Content-Type": "application/json", Accept: "application/json", ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) },
      body: JSON.stringify(body),
    });
  } catch {
    throw new EntryRefusal("Varlatch could not be reached. Nothing was entered as far as this page knows: try again.", "UNREACHABLE", null);
  }
  const json = (await res.json().catch(() => null)) as { error?: { code?: string; message?: string; details?: { reason?: string } } } | null;
  if (!res.ok) {
    const code = json?.error?.code ?? `HTTP_${res.status}`;
    throw new EntryRefusal(json?.error?.message ?? "Varlatch did not answer as expected. Try again.", code, json?.error?.details?.reason ?? null);
  }
  return json as T;
}

export const lookup = (token: string, bearer: string | null) => post<EntryLinkView>("/v1/entry-links/lookup", { token }, bearer);

export const submit = (token: string, bearer: string | null, value: { value: string } | { otpauth: string }) =>
  post<{ status: "entered" }>("/v1/entry-links/submit", { token, ...value }, bearer);

/** The bearer of whoever is signed in in this browser, null for nobody. */
export async function signedIn(): Promise<string | null> {
  const state = await varlatchd.browserSession(true);
  if (!state.identityId) return null;
  const res = await varlatchd.authPost("/auth/varlatch-token");
  if (!res.ok) return null;
  return ((await res.json()) as { token: string }).token;
}

/** Sign in with a passkey, as somebody else when somebody is. */
export async function signIn(asSomebodyElse: boolean): Promise<string> {
  if (asSomebodyElse) {
    await varlatchd.signOut();
    await varlatchd.browserSession(true);
  }
  await varlatchd.signInWithPasskey();
  const bearer = await signedIn();
  if (!bearer) throw new Error("the sign-in did not last; try again");
  return bearer;
}

/** What is odd about a value's ends, which a paste adds and nobody sees. */
export function strayEnds(value: string): boolean {
  return value !== "" && value !== value.trim();
}
