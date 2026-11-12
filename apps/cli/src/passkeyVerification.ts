// SPDX-License-Identifier: Apache-2.0
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * An Organization that enforces passkey-verification (ADR-0054 Decision 7)
 * refused this credential: it was not made by a sign-in with a trusted
 * passkey that verified the person. Asking again with the same credential
 * will not help; a new sign-in will. Returns the lines to print, or null
 * for any other error.
 */
export function passkeyVerificationLines(err: unknown): string[] | null {
  if (!(err instanceof VarlatchApiError) || err.code !== "PASSKEY_VERIFICATION_REQUIRED") return null;
  return [
    `Error PASSKEY_VERIFICATION_REQUIRED: ${err.message} (request ${err.requestId})`,
    "To get a CLI credential this Organization accepts:",
    "  varlatch login --server <url>",
    "and approve the sign-in in the browser with a trusted passkey that asks for your PIN, fingerprint or face.",
    "A credential given with --token or --token-stdin carries no passkey sign-in, so it is always refused here.",
  ];
}
