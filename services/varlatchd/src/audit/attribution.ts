// SPDX-License-Identifier: AGPL-3.0-or-later
import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Who is acting in this request (ADR-0016 §9: an event carries its actor's
 * session/credential reference). The /v1 bearer middleware runs the rest
 * of the request inside it once a principal is resolved, so the audit
 * writer can name the credential and client of every event the request
 * records without each call site threading them through. Background work
 * (sync delivery, webhooks, the mirror) and unauthenticated requests run
 * outside any request and are never attributed.
 */
export interface Attribution {
  identityId: string;
  credentialId: string;
  /**
   * clientLabel() of the request's User-Agent: what the client says it is
   * ("varlatch CLI 0.16.0 on Linux, assisted"), never verified and never an
   * authorization input. Null when not recognized.
   */
  client: string | null;
}

const storage = new AsyncLocalStorage<Attribution>();

/** Run `fn`, and everything it awaits, attributed to `attribution`. */
export function withAttribution<T>(attribution: Attribution, fn: () => T): T {
  return storage.run(attribution, fn);
}

/** The attribution of the request being served, if any. */
export function currentAttribution(): Attribution | undefined {
  return storage.getStore();
}
