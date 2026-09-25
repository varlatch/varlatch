// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ErrorCode } from "@varlatch/protocol";

/** Domain errors carry a stable protocol code; the HTTP layer maps them. */
export class DomainError extends Error {
  override name = "DomainError";
  readonly code: ErrorCode;
  readonly details: Record<string, unknown> | undefined;
  constructor(code: ErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export function notFound(what: string): DomainError {
  return new DomainError("RESOURCE_NOT_FOUND", `${what} not found`);
}
