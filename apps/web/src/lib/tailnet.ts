// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Environment } from "@varlatch/protocol";

/**
 * Tailnet-only values (ADR-0014). A Tailnet Requirement constrains every
 * value read, non-sensitive values included, to requests with verified
 * Tailnet Context. The dashboard reaches varlatchd's ordinary listener,
 * where that context never exists, so it can show these environments'
 * items and states but never their values.
 */

export const TAILNET_ONLY_LABEL = "Values: tailnet only";

/** For viewers who cannot see the policy itself. */
export const TAILNET_ONLY_GUIDANCE =
  "Values here require an approved device on the tailnet. Use the CLI configured for the Tailscale endpoint.";

/** The server's own word (capability environments.tailnet-required); older servers never set it. */
export function isTailnetOnly(env: Pick<Environment, "tailnetRequired"> | undefined): boolean {
  return env?.tailnetRequired === true;
}

/** A denial because a Tailnet Requirement was not met (policy can change while a page is open). */
export function isTailnetDenial(err: unknown): boolean {
  const code = err && typeof err === "object" && "code" in err ? (err as { code: unknown }).code : undefined;
  return typeof code === "string" && code.startsWith("TAILNET_");
}

/** A reveal refused, or a disclosure discarded, because the environment became tailnet-only. */
export class TailnetOnlyError extends Error {
  readonly code = "TAILNET_ONLY";
  constructor() {
    super(TAILNET_ONLY_GUIDANCE);
    this.name = "TailnetOnlyError";
  }
}

/** A disclosure discarded on arrival: the environment's plaintext was cleaned up while it was in flight. */
export class DisclosureDiscardedError extends Error {
  readonly code = "DISCLOSURE_DISCARDED";
  constructor() {
    super("Access to this environment changed while revealing, so nothing was shown. Reveal again.");
    this.name = "DisclosureDiscardedError";
  }
}
