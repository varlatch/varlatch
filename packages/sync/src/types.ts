// SPDX-License-Identifier: Apache-2.0
import type { AccessCheck } from "./access.js";

/**
 * Platform Adapters (ADR-0031 §8): the closed allowlist of platforms Sync
 * Targets can push Values to. Each adapter owns its platform's API shape,
 * auth, and encoding. There is deliberately no generic "POST values to a URL
 * template" adapter — that would be a first-class exfiltration primitive.
 * The allowlist constrains HOW we talk, not WHOM the admin trusts: for
 * adapters with a user-supplied base URL the admin's choice of host is the
 * trust decision, made explicit by the disclosure gate and audit.
 */

export const PLATFORMS = ["github-actions", "coolify", "convex"] as const;
export type Platform = (typeof PLATFORMS)[number];

export class AdapterError extends Error {
  override name = "AdapterError";
  constructor(
    message: string,
    /** True when retrying without operator intervention may succeed. */
    readonly retryable: boolean = true,
    /** The transport error, for an access check to read; never in the message. */
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/** One destination name with its fully rendered value. */
export interface SyncItem {
  name: string;
  value: string;
}

/** Per-name outcome; never throws for a single name's failure. */
export interface NameOutcome {
  name: string;
  ok: boolean;
  /** Status/short cause only — never the value or credential material. */
  error?: string;
}

export interface AdapterRequest {
  /** Canonical base identity (GitHub owner, Coolify instance origin). */
  baseIdentity: string;
  /** Canonicalized adapter-specific destination. */
  destination: Record<string, string>;
  /** The Platform Credential, plaintext, in memory only. Never log. */
  credential: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /**
   * Checked before each write/delete request in a batch and before a
   * redeploy trigger — preparatory reads (public-key fetch, env listing)
   * are NOT gated: true means the caller lost its authority to send (e.g.
   * a reconciliation lease was fenced) and the adapter must stop,
   * returning the outcomes it has. Narrows the stale-send window to the
   * final check-to-send race per gated request; it cannot eliminate it.
   */
  shouldAbort?: () => Promise<boolean>;
}

export interface PlatformAdapter {
  readonly platform: Platform;
  /**
   * Where per-destination credentials honestly exist (GitHub fine-grained
   * PATs) the UI encourages one Connection per destination; where tokens are
   * inherently instance-wide (Coolify) the Connection is the truthful unit.
   */
  readonly credentialScopeUnit: "destination" | "instance";
  /** Whether the platform can read values back (verify-and-fix repair). */
  readonly supportsReadBack: boolean;
  readonly supportsRedeploy: boolean;
  /** Validate + canonicalize a user-supplied base identity. Throws AdapterError. */
  canonicalizeBaseIdentity(raw: string): string;
  /**
   * Validate + canonicalize an adapter-specific destination against a
   * canonical base identity. `key` is the stable per-base destination
   * discriminator used in the canonical destination identity (Decision 1).
   */
  canonicalizeDestination(raw: Record<string, unknown>): {
    destination: Record<string, string>;
    key: string;
  };
  /** Reject names the platform cannot store before anything is sent. */
  validateName(name: string): string | null;
  /**
   * The destination-name form the platform stores (GitHub uppercases secret
   * names). The ledger is keyed by this canonical form so two mapped names
   * the platform would collapse into one are a conflict, not silent drift.
   */
  canonicalizeName(name: string): string;
  writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]>;
  deleteNames(req: AdapterRequest, names: string[]): Promise<NameOutcome[]>;
  /** Read back current names/values where supported (supportsReadBack). */
  readValues?(req: AdapterRequest): Promise<Map<string, string>>;
  /** Best-effort redeploy trigger (supportsRedeploy). */
  triggerRedeploy?(req: AdapterRequest): Promise<void>;
  /**
   * Read-only access check: does the credential reach the base identity,
   * and, when `req.destination` names one, that destination? Sends the
   * credential only to the base identity, writes nothing, and never
   * throws. Platforms cannot show write permission without a write, so
   * `ok` means "reachable and readable"; the first push confirms the rest.
   */
  checkAccess(req: AdapterRequest): Promise<AccessCheck>;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * The Connection-independent canonical destination identity (ADR-0031 §1):
 * platform + canonical base identity + destination key — never the
 * Connection id — so two Connections aimed at the same external application
 * conflict, while identical ids on different instances stay distinct.
 */
export function canonicalDestinationIdentity(
  platform: Platform,
  baseIdentity: string,
  destinationKey: string,
): string {
  return JSON.stringify([platform, baseIdentity, destinationKey]);
}
