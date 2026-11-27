// SPDX-License-Identifier: AGPL-3.0-or-later

/** What a provider sent the browser back with (ADR-0062). */
export interface Arrival {
  state: string | undefined;
  code: string | undefined;
  error: string | undefined;
  iss: string | undefined;
  redirectUri: string;
}

let arrived: Arrival | null = null;

/**
 * Takes the answer out of the page's address, before anything is asked or
 * loaded from it: main.tsx imports this first. The server says of this path
 * that no request names its address and nothing keeps it.
 */
export function takeFromAddress(): void {
  const { origin, pathname, search } = window.location;
  if (!pathname.startsWith("/oauth/callback/") || search === "") return;
  const v = new URLSearchParams(search);
  window.history.replaceState(null, "", pathname);
  const one = (k: string) => v.get(k) ?? undefined;
  arrived = { state: one("state"), code: one("code"), error: one("error"), iss: one("iss"), redirectUri: origin + pathname };
}

/** Once. */
export function takeArrival(): Arrival | null {
  const a = arrived;
  arrived = null;
  return a;
}
