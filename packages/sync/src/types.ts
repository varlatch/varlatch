// SPDX-License-Identifier: Apache-2.0
import type { AccessCheck, DestinationListing } from "./access.js";

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
  /**
   * What the credential is (GitHub only): a stored personal access token
   * (`token`, the default), or a one-hour installation token Varlatch
   * minted for this use from a GitHub App (`github-app`, ADR-0047). For an
   * App, the connection-only check and the listing read the installation,
   * and a minted token's expiry is never reported: it is not the
   * Connection's.
   */
  credentialKind?: "token" | "github-app";
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
  /**
   * Called when the platform says when the credential expires (GitHub, for
   * personal access tokens), as an ISO 8601 instant. Not called when it
   * says nothing, which does not mean the credential never expires.
   */
  onCredentialExpiry?: (expiresAt: string) => void;
  /**
   * What `inspectUsage` reported for this run, when the caller ran it:
   * lets a write refuse a value the destination would change.
   */
  usage?: UsageReport | null;
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
  /**
   * Reject names the platform cannot store before anything is sent. With a
   * canonical destination, also names that destination's platform sets
   * itself (a Coolify service's `SERVICE_URL_*`); without one, only the
   * platform-wide rules apply.
   */
  validateName(name: string, destination?: Record<string, string>): string | null;
  /**
   * The destination-name form the platform stores (GitHub uppercases secret
   * names). The ledger is keyed by this canonical form so two mapped names
   * the platform would collapse into one are a conflict, not silent drift.
   */
  canonicalizeName(name: string): string;
  writeValues(req: AdapterRequest, items: SyncItem[]): Promise<NameOutcome[]>;
  deleteNames(req: AdapterRequest, names: string[]): Promise<NameOutcome[]>;
  /**
   * Read back current names/values where supported (supportsReadBack). A
   * name the platform holds but whose value it withholds from this
   * credential maps to `null`: present, unreadable, never an empty string.
   */
  readValues?(req: AdapterRequest): Promise<Map<string, string | null>>;
  /**
   * Read-only: how the destination uses the given names, where the
   * platform lets a credential see that (a Coolify service's compose
   * files). `null` when the destination has no such notion (a Coolify
   * application). Only names, container names and verdicts leave the
   * adapter. Never throws for an unreadable answer: it reports
   * `checked: false` with a reason instead.
   */
  inspectUsage?(req: AdapterRequest, names: string[]): Promise<UsageReport | null>;
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
  /**
   * Read-only: the destinations the credential can see on the base
   * identity, for a picker. Absent where the base identity is the
   * destination (Convex). Never throws.
   */
  listDestinations?(req: AdapterRequest): Promise<DestinationListing>;
}

/**
 * How a destination uses one name (Coolify services, ADR-0031 amendment
 * 2026-10-21). Every field is a hint read from the platform's own
 * configuration, never a guarantee that a workload reads the value.
 */
export interface NameUsage {
  /** The platform sets this name itself: writing it would be overwritten. */
  owned?: boolean;
  /** The configuration references it, so the platform re-creates it after a delete. */
  referenced?: boolean;
  /** Containers whose configuration sets the name to another value, which wins. */
  shadowedIn?: string[];
  /** Containers that receive the name by no route the rules know. */
  notDeliveredTo?: string[];
  /** The platform generated it once (a password, a user name): a database may read it only on first start. */
  generatedOnce?: boolean;
  /** Containers whose configuration uses the name in a form outside the rules. */
  unknownIn?: string[];
  /**
   * The platform copies the stored value into the configuration it runs,
   * where `$` is expanded (a Compose default, `${NAME:-x}`): a value with
   * `$` would arrive changed.
   */
  copiedIntoCompose?: boolean;
}

export interface UsageReport {
  /** False when usage could not be checked at all; `reason` says why, in Varlatch's words. */
  checked: boolean;
  reason?: string;
  /** Verdicts for the names asked about; a name with no hint maps to `{}`. */
  names: Map<string, NameUsage>;
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
