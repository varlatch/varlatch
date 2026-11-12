// SPDX-License-Identifier: Apache-2.0
import { ERROR_CODES } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * Output that comes from a server, made safe to print (ADR-0058 Decision 2):
 * an error code only when it is one the protocol defines (a server could put
 * anything in that field, the request's own credential included), and text
 * with every control character escaped, so a name cannot add lines, move
 * the cursor or reach the terminal's clipboard.
 */

const KNOWN = new Set<string>(ERROR_CODES);

/** The API error's code when the protocol defines it; a fixed word otherwise. */
export function safeApiCode(err: VarlatchApiError): string {
  return KNOWN.has(err.code) ? err.code : "UNRECOGNIZED_ERROR";
}

/** C0, DEL and C1 controls, and the bidirectional overrides and isolates, as visible escapes. */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
