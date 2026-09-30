// SPDX-License-Identifier: Apache-2.0
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * The CLI's exit statuses (ADR-0043 Decision 10). Meanings scripts already
 * rely on are frozen: `validate` 1 (invalid) and 2 (incomplete), `scan` 1
 * (findings) and 2 (not everything scanned), `types --check` 1 (stale),
 * strict startup 78, and `varlatch run` passing the command's own status
 * through once the command has started. New distinctions follow sysexits.h,
 * as 78 (EX_CONFIG) already does. Any other failure is 1.
 */
export const EXIT = {
  ok: 0,
  failure: 1,
  /** EX_USAGE: the command line is wrong (a missing argument, an unknown command, flags that conflict). */
  usage: 64,
  /** EX_UNAVAILABLE: the server cannot be reached, or is in maintenance or overloaded. */
  unavailable: 69,
  /** EX_NOPERM: not authenticated, or the server denied the request. */
  denied: 77,
  /** EX_CONFIG: strict startup found a violation, or assisted mode cannot mask a Secret. */
  config: 78,
} as const;

/** The status for an error response from the server. */
export function apiErrorExit(err: VarlatchApiError): number {
  if (err.status === 401 || err.status === 403) return EXIT.denied;
  if (err.code === "MAINTENANCE" || err.status === 502 || err.status === 503 || err.status === 504) return EXIT.unavailable;
  return EXIT.failure;
}

const NETWORK_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
]);

/**
 * The network error code when `err` is a request that never reached the
 * server (fetch rejects with a TypeError whose cause carries the code), or
 * null for anything else.
 */
export function networkFailure(err: unknown): string | null {
  if (!(err instanceof TypeError) || err.message !== "fetch failed") return null;
  let cause: unknown = err.cause;
  for (let depth = 0; cause && depth < 3; depth++) {
    const code = (cause as { code?: unknown }).code;
    if (typeof code === "string" && NETWORK_CODES.has(code)) return code;
    cause = (cause as { cause?: unknown }).cause;
  }
  return "network error";
}
