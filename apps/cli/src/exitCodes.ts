// SPDX-License-Identifier: Apache-2.0
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * The CLI's exit statuses (ADR-0043 Decision 10). Meanings scripts already
 * rely on are frozen: `validate` 1 (invalid) and 2 (incomplete), `scan` 1
 * (findings) and 2 (not everything scanned), `types --check` 1 (stale),
 * `sync check` 1 (drift) and 2 (not everything checked),
 * strict startup 78, `varlatch run` passing the command's own status
 * through once the command has started, and `login --wait` 75 for a
 * sign-in still pending at its deadline. New distinctions follow
 * sysexits.h, as 78 (EX_CONFIG) already does. Any other failure is 1.
 *
 * Step-up approvals (ADR-0054 Decision 3, approvals.ts): 75 when the
 * approval is still pending and the CLI does not wait for it (assisted
 * mode: run the command again with --approval <id> once the person
 * approved), or it expired before anyone approved it; 77 when it was
 * cancelled or closed, was used already, does not fit the request
 * (APPROVAL_INVALID), or STEP_UP_REQUIRED surfaces without a wait; 130
 * when Ctrl-C stopped the wait.
 *
 * An Organization frozen for an incident (ADR-0055): 77, final for the
 * invocation. The CLI never retries it; runners and CI should back off.
 *
 * An Organization that needs a verified passkey sign-in
 * (PASSKEY_VERIFICATION_REQUIRED, ADR-0054 Decision 7): 77. The same
 * credential will keep being refused; `varlatch login` gets a new one.
 */
export const EXIT = {
  ok: 0,
  failure: 1,
  /** EX_USAGE: the command line is wrong (a missing argument, an unknown command, flags that conflict). */
  usage: 64,
  /** EX_UNAVAILABLE: the server cannot be reached, or is in maintenance or overloaded. */
  unavailable: 69,
  /** EX_TEMPFAIL: `login --wait` reached its deadline with the sign-in still pending; run it again. */
  tempfail: 75,
  /** EX_NOPERM: not authenticated, or the server denied the request. */
  denied: 77,
  /** EX_CONFIG: strict startup found a violation, or assisted mode cannot mask a Secret. */
  config: 78,
  /** Ctrl-C stopped a wait for a step-up approval (128 + SIGINT, as shells report it). */
  interrupted: 130,
} as const;

/** The status for an error response from the server. */
export function apiErrorExit(err: VarlatchApiError): number {
  // An approval that does not fit, or one the CLI did not wait for (ADR-0054 Decision 3).
  if (err.code === "APPROVAL_INVALID" || err.code === "STEP_UP_REQUIRED") return EXIT.denied;
  // Frozen for an incident: the server refused, and asking again will not help until it is lifted.
  if (err.code === "ORGANIZATION_FROZEN") return EXIT.denied;
  // An Organization that needs a verified passkey sign-in (ADR-0054 Decision 7): sign in again.
  if (err.code === "PASSKEY_VERIFICATION_REQUIRED") return EXIT.denied;
  // A mode this server does not offer yet: an ordinary failure, not a denial.
  if (err.code === "CONTROL_MODE_UNAVAILABLE") return EXIT.failure;
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
