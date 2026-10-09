// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  canonicalDestinationIdentity,
  getAdapter,
  AdapterError,
  type AccessCheck,
  type DestinationListing,
  type PlatformAdapter,
} from "@varlatch/sync";
import { recordAuditEvent } from "../audit/events.js";
import type { Envelope } from "../crypto/aead.js";
import { decryptPlatformCredential, encryptPlatformCredential } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { orgKekOf, type OrgRow } from "./orgs.js";

/**
 * Platform Connections and Sync Targets (ADR-0031 §1-2): a Connection
 * authenticates once per platform account/instance; a Target binds one
 * Environment to one destination on it and is standing disclosure authority.
 * The disclosure gate itself (secret.reveal / config.value.read at decision
 * time) runs in the HTTP layer, which holds the caller's evaluator context;
 * this module receives the recorded authz snapshot and enforces everything
 * structural: immutable base identity, destination exclusivity, atomic
 * credential replacement, lifecycle audit.
 */

export interface PlatformConnectionRow {
  id: string;
  organization_id: string;
  platform: string;
  base_identity: string;
  name: string;
  created_at: string;
  revoked_at: string | null;
  version: number;
  updated_at: string | null;
}

export type SyncMappingItem = {
  name: string;
  rename?: string;
  /**
   * True when disclosure of this item as a Secret has been authorized
   * (it was sensitive at decision time, or was re-affirmed after becoming
   * one). A mapped item that later becomes a Secret leaves the disclosure
   * set until an actor holding secret.reveal re-affirms it (ADR-0031 §2).
   */
  secretAffirmed: boolean;
};

export type SyncMapping =
  | { kind: "wildcard"; exclude?: string[] }
  | { kind: "explicit"; items: SyncMappingItem[] };

/**
 * Wildcard exclusion entry: an exact source-item name, or a prefix ending
 * in `*` (e.g. `CONVEX_*`). Exclusions match SOURCE names before any
 * rename (wildcard mappings have no renames). A bare `*` is rejected —
 * excluding everything is not a mapping.
 */
const EXCLUSION_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*\*?$/;
const MAX_EXCLUSIONS = 200;

export function matchesExclusion(exclude: string[] | undefined, name: string): boolean {
  if (!exclude) return false;
  return exclude.some((e) =>
    e.endsWith("*") ? name.startsWith(e.slice(0, -1)) : name === e,
  );
}

export interface SyncTargetRow {
  id: string;
  organization_id: string;
  project_id: string;
  environment_id: string;
  connection_id: string;
  destination: Record<string, string>;
  canonical_destination: string;
  mapping: SyncMapping;
  remove_orphans: boolean;
  redeploy: boolean;
  state: "active" | "paused" | "disabled";
  disabled_reason: string | null;
  failure_count: number;
  needs_sync: boolean;
  next_attempt_at: string | null;
  last_attempt_at: string | null;
  last_result: string | null;
  last_repair_at: string | null;
  created_at: string;
  revoked_at: string | null;
  version: number;
  updated_at: string | null;
}

export const TARGET_COLUMNS = `id, organization_id, project_id, environment_id, connection_id,
  destination, canonical_destination, mapping, remove_orphans, redeploy, state,
  disabled_reason, failure_count, needs_sync, next_attempt_at, last_attempt_at,
  last_result, last_repair_at, created_at, revoked_at, version, updated_at`;

const CONNECTION_COLUMNS = `id, organization_id, platform, base_identity, name,
  created_at, revoked_at, version, updated_at`;

function parseJson<T>(v: unknown): T {
  return (typeof v === "string" ? JSON.parse(v) : v) as T;
}

export function targetRow(raw: Record<string, unknown>): SyncTargetRow {
  return {
    ...(raw as unknown as SyncTargetRow),
    destination: parseJson<Record<string, string>>(raw.destination),
    mapping: parseJson<SyncMapping>(raw.mapping),
  };
}

/** Audit form of a destination: identifiers only, redacted like webhook URLs. */
export function describeDestination(platform: string, destinationKey: string): string {
  return `${platform}:${destinationKey}`;
}

/**
 * Which disclosure actions a mapping requires on the Environment's scope
 * (ADR-0031 §2): secret.reveal covers mapped Secrets, config.value.read
 * covers mapped non-sensitive items; a wildcard discloses both classes —
 * every current AND future item — so it always requires both. Exclusions
 * do not weaken that: the non-excluded remainder still covers unknown
 * future items, so a wildcard with exclusions gates exactly like `*`.
 */
export function requiredDisclosureActions(
  mapping: SyncMapping,
  sensitivityOfName: (name: string) => boolean,
): ("secret.reveal" | "config.value.read")[] {
  if (mapping.kind === "wildcard") return ["secret.reveal", "config.value.read"];
  const actions = new Set<"secret.reveal" | "config.value.read">();
  for (const item of mapping.items) {
    actions.add(sensitivityOfName(item.name) ? "secret.reveal" : "config.value.read");
  }
  return [...actions];
}

/** Validate a raw mapping's shape and destination names against the adapter. */
export function normalizeMapping(
  platform: string,
  raw:
    | { kind: "wildcard"; exclude?: string[] | undefined }
    | { kind: "explicit"; items: { name: string; rename?: string | undefined }[] },
  sensitivityOfName: (name: string) => boolean,
  previous?: SyncMapping,
): SyncMapping {
  if (raw.kind === "wildcard") {
    const exclude = [...new Set(raw.exclude ?? [])];
    if (exclude.length === 0) return { kind: "wildcard" };
    if (exclude.length > MAX_EXCLUSIONS) {
      throw new DomainError("VALIDATION_FAILED", `At most ${MAX_EXCLUSIONS} exclusions`);
    }
    for (const e of exclude) {
      if (!EXCLUSION_PATTERN.test(e)) {
        throw new DomainError(
          "VALIDATION_FAILED",
          `Invalid exclusion "${e}": an exact item name or a prefix ending in *`,
        );
      }
    }
    return { kind: "wildcard", exclude: exclude.sort() };
  }
  if (raw.items.length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Explicit mapping must list at least one item");
  }
  const adapter = getAdapter(platform);
  const prevByName = new Map(
    previous?.kind === "explicit" ? previous.items.map((i) => [i.name, i]) : [],
  );
  const seenSources = new Set<string>();
  const seenDests = new Set<string>();
  const items: SyncMappingItem[] = [];
  for (const item of raw.items) {
    if (seenSources.has(item.name)) {
      throw new DomainError("VALIDATION_FAILED", `Duplicate mapped item: ${item.name}`);
    }
    seenSources.add(item.name);
    const destName = adapter.canonicalizeName(item.rename ?? item.name);
    const problem = adapter.validateName(destName);
    if (problem) {
      throw new DomainError("VALIDATION_FAILED", `${item.name}: ${problem}`);
    }
    if (seenDests.has(destName)) {
      throw new DomainError(
        "VALIDATION_FAILED",
        `Two mapped items resolve to the same destination name ${destName}`,
      );
    }
    seenDests.add(destName);
    // The gate the caller just passed covers the item's CURRENT class; a
    // pre-existing affirmation survives edits that do not touch the item.
    const secretAffirmed = sensitivityOfName(item.name)
      ? true
      : (prevByName.get(item.name)?.secretAffirmed ?? false);
    items.push({
      name: item.name,
      ...(item.rename !== undefined ? { rename: item.rename } : {}),
      secretAffirmed,
    });
  }
  return { kind: "explicit", items };
}

/**
 * True when `next` widens the disclosure set over `prev` — which re-runs the
 * write-time gate; narrowing needs only config.sync.manage.
 */
export function mappingWidens(prev: SyncMapping, next: SyncMapping): boolean {
  if (next.kind === "wildcard") {
    if (prev.kind !== "wildcard") return true;
    // Removing (or rewriting) an exclusion entry can only expand coverage;
    // adding one can only shrink it. Entry-set comparison is a sound
    // over-approximation: a modified entry counts as removed + added.
    const nextEntries = new Set(next.exclude ?? []);
    return (prev.exclude ?? []).some((e) => !nextEntries.has(e));
  }
  if (prev.kind === "wildcard") return false;
  const prevByName = new Map(prev.items.map((i) => [i.name, i]));
  return next.items.some((i) => {
    const before = prevByName.get(i.name);
    return !before || (i.secretAffirmed && !before.secretAffirmed);
  });
}

// ---------------------------------------------------------------------------
// Platform Connections

export async function createConnection(
  ctx: AppCtx,
  org: OrgRow,
  input: { platform: string; baseIdentity: string; name: string; credential: string },
  actorIdentityId: string,
): Promise<PlatformConnectionRow> {
  const adapter = canonicalizeOrValidationError(() => getAdapter(input.platform));
  const baseIdentity = canonicalizeOrValidationError(() =>
    adapter.canonicalizeBaseIdentity(input.baseIdentity),
  );
  if (input.credential.trim().length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Platform Credential must not be empty");
  }
  const id = newId("platformConnection");
  const envelope = encryptPlatformCredential(orgKekOf(ctx, org), org.id, id, input.credential);
  return withTx(ctx.db, async (db) => {
    await recordAuditEvent(db, {
      eventType: "sync.connection_created",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { connectionId: id },
      metadata: { platform: adapter.platform, baseIdentity, name: input.name },
    });
    const res = await db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING ${CONNECTION_COLUMNS}`,
      [id, org.id, adapter.platform, baseIdentity, input.name, JSON.stringify(envelope), actorIdentityId],
    );
    return res.rows[0] as PlatformConnectionRow;
  });
}

export async function listConnections(
  ctx: AppCtx,
  organizationId: string,
): Promise<(PlatformConnectionRow & { target_count: number })[]> {
  const res = await ctx.db.query(
    `SELECT ${CONNECTION_COLUMNS.split(",").map((c) => `c.${c.trim()}`).join(", ")},
            (SELECT count(*)::int FROM sync_targets t
              WHERE t.connection_id = c.id AND t.revoked_at IS NULL) AS target_count
     FROM platform_connections c
     WHERE c.organization_id = $1 AND c.revoked_at IS NULL
     ORDER BY c.created_at, c.id`,
    [organizationId],
  );
  return res.rows as (PlatformConnectionRow & { target_count: number })[];
}

export async function getConnection(
  ctx: AppCtx,
  organizationId: string,
  connectionId: string,
): Promise<PlatformConnectionRow> {
  const res = await ctx.db.query(
    `SELECT ${CONNECTION_COLUMNS} FROM platform_connections
     WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`,
    [connectionId, organizationId],
  );
  const row = res.rows[0] as PlatformConnectionRow | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Platform Connection not found");
  return row;
}

/**
 * Replace a Connection's Platform Credential (ADR-0031 §2): a new disclosure
 * grant for EVERY non-revoked referencing Target at once. The caller-supplied
 * `gate` runs each Target's write-time disclosure gate; any refusal aborts
 * the whole replacement. The Connection and Target rows are locked so the
 * check serializes with concurrent attachment and re-pointing.
 */
export async function replaceConnectionCredential(
  ctx: AppCtx,
  org: OrgRow,
  connectionId: string,
  input: { credential: string; expectedVersion: number },
  gate: (target: SyncTargetRow) => Promise<void>,
  actorIdentityId: string,
): Promise<PlatformConnectionRow> {
  if (input.credential.trim().length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Platform Credential must not be empty");
  }
  const envelope = encryptPlatformCredential(
    orgKekOf(ctx, org),
    org.id,
    connectionId,
    input.credential,
  );
  return withTx(ctx.db, async (db) => {
    const res = await db.query(
      `SELECT ${CONNECTION_COLUMNS} FROM platform_connections
       WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE`,
      [connectionId, org.id],
    );
    const row = res.rows[0] as PlatformConnectionRow | undefined;
    if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Platform Connection not found");
    if (row.version !== input.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", "Connection was modified concurrently; reload and retry");
    }
    const targets = await db.query(
      `SELECT ${TARGET_COLUMNS} FROM sync_targets
       WHERE connection_id = $1 AND revoked_at IS NULL
       ORDER BY created_at, id FOR UPDATE`,
      [connectionId],
    );
    const rows = (targets.rows as Record<string, unknown>[]).map(targetRow);
    for (const target of rows) {
      await gate(target);
    }
    const updated = await db.query(
      `UPDATE platform_connections
       SET credential_envelope = $1, version = version + 1, updated_at = now()
       WHERE id = $2 RETURNING ${CONNECTION_COLUMNS}`,
      [JSON.stringify(envelope), connectionId],
    );
    await recordAuditEvent(db, {
      eventType: "sync.connection_credential_replaced",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { connectionId },
      metadata: { reauthorizedTargets: rows.map((t) => t.id).join(",") || null },
    });
    // A replacement is a Target mutation class trigger (ADR-0031 §6):
    // enqueue directly, never via the audit cursor.
    await db.query(
      "UPDATE sync_targets SET needs_sync = true, next_attempt_at = NULL WHERE connection_id = $1 AND revoked_at IS NULL",
      [connectionId],
    );
    return updated.rows[0] as PlatformConnectionRow;
  });
}

export async function revokeConnection(
  ctx: AppCtx,
  org: OrgRow,
  connectionId: string,
  actorIdentityId: string,
): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const res = await db.query(
      `UPDATE platform_connections SET revoked_at = now(), version = version + 1, updated_at = now()
       WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id`,
      [connectionId, org.id],
    );
    if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Platform Connection not found");
    // Revoking a Connection disables every referencing Target (ADR-0031 §1).
    // They keep their destination claims: paused, not gone.
    const disabled = await db.query(
      `UPDATE sync_targets
       SET state = 'disabled', disabled_reason = 'connection-revoked', version = version + 1, updated_at = now()
       WHERE connection_id = $1 AND revoked_at IS NULL RETURNING id`,
      [connectionId],
    );
    await recordAuditEvent(db, {
      eventType: "sync.connection_revoked",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { connectionId },
      metadata: {
        disabledTargets: (disabled.rows as { id: string }[]).map((r) => r.id).join(",") || null,
      },
    });
  });
}

/** A Connection's stored credential (or a replacement for it), or a new one. */
export type CredentialInput =
  | { connectionId: string; credential?: string | undefined }
  | { platform: string; baseIdentity: string; credential: string };

export type AccessCheckInput = { destination?: Record<string, unknown> | undefined } & CredentialInput;

/**
 * A read-only access check (ADR-0031, amendment 2026-10-09): does a
 * credential reach its base identity, and the destination when one is
 * named? The credential is the one supplied now (a new Connection, or a
 * replacement for a stored one) or the Connection's stored one, and it goes
 * only to the Connection's base identity. Nothing is stored, no Value is
 * read, and no platform text comes back; the outcome is audited.
 */
export async function checkConnectionAccess(
  ctx: AppCtx,
  org: OrgRow,
  input: AccessCheckInput,
  allowedAdapters: string[] | null,
  actorIdentityId: string,
  fetchImpl?: typeof fetch,
): Promise<AccessCheck> {
  const { adapter, baseIdentity, credential, connectionId, supplied } = await resolveCredential(ctx, org, input, allowedAdapters);
  // No destination fields: the check stops at the base identity.
  const named = Object.values(input.destination ?? {}).some((v) => v !== undefined && v !== null && v !== "");
  const destination = named
    ? canonicalizeOrValidationError(() => adapter.canonicalizeDestination(input.destination ?? {}))
    : null;

  const result = await adapter.checkAccess({
    baseIdentity,
    destination: destination?.destination ?? {},
    credential,
    ...(fetchImpl ? { fetchImpl } : {}),
  });
  await recordAuditEvent(ctx.db, {
    eventType: "sync.connection_checked",
    decision: "info",
    actorIdentityId,
    organizationId: org.id,
    action: "config.sync.manage",
    resource: connectionId ? { connectionId } : null,
    metadata: {
      platform: adapter.platform,
      baseIdentity,
      destination: destination ? describeDestination(adapter.platform, destination.key) : null,
      credential: supplied ? "supplied" : "stored",
      status: result.status,
      httpStatus: result.httpStatus ?? null,
    },
  });
  return result;
}

/**
 * The destinations a credential can see on its base identity, for the
 * dashboard's pickers (ADR-0031, amendment 2026-10-09): read-only, under
 * the same rules as an access check. Only destinations the adapter can
 * canonicalize come back, and the audit records how many, never their names.
 */
export async function listConnectionDestinations(
  ctx: AppCtx,
  org: OrgRow,
  input: CredentialInput,
  allowedAdapters: string[] | null,
  actorIdentityId: string,
  fetchImpl?: typeof fetch,
): Promise<DestinationListing> {
  const { adapter, baseIdentity, credential, connectionId, supplied } = await resolveCredential(ctx, org, input, allowedAdapters);
  if (!adapter.listDestinations) {
    throw new DomainError(
      "VALIDATION_FAILED",
      "This platform has no destinations to list: the Connection's base identity is the destination",
    );
  }
  const listing = await adapter.listDestinations({ baseIdentity, destination: {}, credential, ...(fetchImpl ? { fetchImpl } : {}) });
  const items = listing.items.filter((item) => {
    try {
      adapter.canonicalizeDestination(item.destination);
      return true;
    } catch {
      return false;
    }
  });
  await recordAuditEvent(ctx.db, {
    eventType: "sync.destinations_listed",
    decision: "info",
    actorIdentityId,
    organizationId: org.id,
    action: "config.sync.manage",
    resource: connectionId ? { connectionId } : null,
    metadata: {
      platform: adapter.platform,
      baseIdentity,
      credential: supplied ? "supplied" : "stored",
      status: listing.check.status,
      httpStatus: listing.check.httpStatus ?? null,
      count: items.length,
      truncated: listing.truncated,
    },
  });
  return { ...listing, items };
}

/**
 * The credential an access check or a listing uses: supplied now (a new
 * Connection, or a replacement for a stored one) or the Connection's stored
 * one. Either way it goes only to the Connection's base identity.
 */
async function resolveCredential(
  ctx: AppCtx,
  org: OrgRow,
  input: CredentialInput,
  allowedAdapters: string[] | null,
): Promise<{ adapter: PlatformAdapter; baseIdentity: string; credential: string; connectionId: string | null; supplied: boolean }> {
  let platform: string;
  let baseIdentity: string;
  let credential: string;
  let connectionId: string | null = null;
  if ("connectionId" in input) {
    const connection = await getConnection(ctx, org.id, input.connectionId);
    connectionId = connection.id;
    platform = connection.platform;
    baseIdentity = connection.base_identity;
    if (input.credential !== undefined) {
      credential = input.credential;
    } else {
      const res = await ctx.db.query("SELECT credential_envelope FROM platform_connections WHERE id = $1", [connection.id]);
      credential = decryptPlatformCredential(
        orgKekOf(ctx, org),
        org.id,
        connection.id,
        parseJson<Envelope>((res.rows[0] as { credential_envelope: unknown }).credential_envelope),
      );
    }
  } else {
    platform = input.platform;
    baseIdentity = input.baseIdentity;
    credential = input.credential;
  }
  if (allowedAdapters && !allowedAdapters.includes(platform)) {
    throw new DomainError("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter");
  }
  const adapter = canonicalizeOrValidationError(() => getAdapter(platform));
  baseIdentity = canonicalizeOrValidationError(() => adapter.canonicalizeBaseIdentity(baseIdentity));
  if (credential.trim().length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Platform Credential must not be empty");
  }
  const supplied = !("connectionId" in input) || input.credential !== undefined;
  return { adapter, baseIdentity, credential, connectionId, supplied };
}

// ---------------------------------------------------------------------------
// Sync Targets

export interface TargetInput {
  connectionId: string;
  destination: Record<string, unknown>;
  mapping: SyncMapping;
  removeOrphans: boolean;
  redeploy: boolean;
}

export async function createTarget(
  ctx: AppCtx,
  org: OrgRow,
  projectId: string,
  environmentId: string,
  input: TargetInput,
  authz: Record<string, unknown>,
  actorIdentityId: string,
): Promise<SyncTargetRow> {
  const id = newId("syncTarget");
  return withTx(ctx.db, async (db) => {
    // Lock the Connection: attachment serializes with credential replacement.
    const connection = await lockConnection(db, org.id, input.connectionId);
    const adapter = getAdapter(connection.platform);
    const { destination, key } = canonicalizeOrValidationError(() =>
      adapter.canonicalizeDestination(input.destination),
    );
    const canonical = canonicalDestinationIdentity(
      adapter.platform,
      connection.base_identity,
      key,
    );
    await recordAuditEvent(db, {
      eventType: "sync.target_created",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { targetId: id, environmentId, connectionId: connection.id },
      authz,
      metadata: {
        platform: adapter.platform,
        destination: describeDestination(adapter.platform, key),
        mapping: mappingSummary(input.mapping),
        removeOrphans: input.removeOrphans,
      },
    });
    let res;
    try {
      res = await db.query(
        `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id,
           destination, canonical_destination, mapping, remove_orphans, redeploy, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         RETURNING ${TARGET_COLUMNS}`,
        [
          id,
          org.id,
          projectId,
          environmentId,
          connection.id,
          JSON.stringify(destination),
          canonical,
          JSON.stringify(input.mapping),
          input.removeOrphans,
          input.redeploy,
          actorIdentityId,
        ],
      );
    } catch (err) {
      throw destinationClaimError(err);
    }
    return targetRow(res.rows[0] as Record<string, unknown>);
  });
}

export interface TargetPatch {
  expectedVersion: number;
  mapping?: SyncMapping | undefined;
  destination?: Record<string, unknown> | undefined;
  connectionId?: string | undefined;
  removeOrphans?: boolean | undefined;
  redeploy?: boolean | undefined;
}

/**
 * Mutate a Target. Destination changes and Connection re-points are new
 * disclosure grants (the HTTP layer re-ran the full gate and says so in
 * `authz`); a destination-identity change atomically releases the old claim,
 * acquires the new one, and resets the ledger — the old destination's copy
 * is deliberately abandoned.
 */
export async function updateTarget(
  ctx: AppCtx,
  org: OrgRow,
  target: SyncTargetRow,
  patch: TargetPatch,
  authz: Record<string, unknown> | null,
  actorIdentityId: string,
): Promise<SyncTargetRow> {
  return withTx(ctx.db, async (db) => {
    const locked = await db.query(
      `SELECT ${TARGET_COLUMNS} FROM sync_targets WHERE id = $1 AND revoked_at IS NULL FOR UPDATE`,
      [target.id],
    );
    const current = locked.rows[0]
      ? targetRow(locked.rows[0] as Record<string, unknown>)
      : undefined;
    if (!current) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
    if (current.version !== patch.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", "Sync Target was modified concurrently; reload and retry");
    }

    // Re-point / destination change: lock the (possibly new) Connection so
    // this serializes with credential replacement.
    const connectionId = patch.connectionId ?? current.connection_id;
    const connection = await lockConnection(db, org.id, connectionId);
    if (patch.connectionId !== undefined) {
      const oldConnection = await db.query(
        "SELECT platform FROM platform_connections WHERE id = $1",
        [current.connection_id],
      );
      const oldPlatform = (oldConnection.rows[0] as { platform: string } | undefined)?.platform;
      if (oldPlatform !== undefined && connection.platform !== oldPlatform) {
        throw new DomainError(
          "VALIDATION_FAILED",
          "A Sync Target cannot be re-pointed across platform types",
        );
      }
    }
    const adapter = getAdapter(connection.platform);
    const { destination, key } = canonicalizeOrValidationError(() =>
      adapter.canonicalizeDestination(patch.destination ?? current.destination),
    );
    const canonical = canonicalDestinationIdentity(adapter.platform, connection.base_identity, key);
    const destinationChanged = canonical !== current.canonical_destination;
    const mapping = patch.mapping ?? current.mapping;

    let res;
    try {
      res = await db.query(
        `UPDATE sync_targets
         SET connection_id = $1, destination = $2, canonical_destination = $3, mapping = $4,
             remove_orphans = $5, redeploy = $6, needs_sync = true, next_attempt_at = NULL,
             version = version + 1, updated_at = now()
         WHERE id = $7 RETURNING ${TARGET_COLUMNS}`,
        [
          connection.id,
          JSON.stringify(destination),
          canonical,
          JSON.stringify(mapping),
          patch.removeOrphans ?? current.remove_orphans,
          patch.redeploy ?? current.redeploy,
          current.id,
        ],
      );
    } catch (err) {
      throw destinationClaimError(err);
    }
    if (destinationChanged) {
      // The new destination starts with an empty ledger and receives a full
      // write even when every name and value is identical (ADR-0031 §3).
      await db.query("DELETE FROM sync_ledger WHERE target_id = $1", [current.id]);
      // Fence any reconciliation still in flight against the OLD
      // destination: bumping the generation invalidates its lease, so its
      // ledger writes (serialized against this row lock) can no longer
      // repopulate the fresh ledger with old-destination successes.
      // Clearing the lease lets the next converge start immediately —
      // late remote writes to the abandoned destination are exactly the
      // abandoned-copy case the destination-change review discloses.
      await db.query(
        "UPDATE sync_targets SET generation = generation + 1, lease_expires_at = NULL WHERE id = $1",
        [current.id],
      );
    }
    await recordAuditEvent(db, {
      eventType: "sync.target_updated",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { targetId: current.id, environmentId: current.environment_id, connectionId: connection.id },
      ...(authz ? { authz } : {}),
      metadata: {
        destination: describeDestination(adapter.platform, key),
        destinationChanged,
        connectionRepointed: connection.id !== target.connection_id,
        mapping: mappingSummary(mapping),
        widened: mappingWidens(current.mapping, mapping),
      },
    });
    return targetRow(res.rows[0] as Record<string, unknown>);
  });
}

export async function setTargetState(
  ctx: AppCtx,
  org: OrgRow,
  targetId: string,
  transition: "pause" | "resume" | "revoke",
  actorIdentityId: string,
): Promise<SyncTargetRow | null> {
  return withTx(ctx.db, async (db) => {
    const locked = await db.query(
      `SELECT ${TARGET_COLUMNS} FROM sync_targets
       WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE`,
      [targetId, org.id],
    );
    const current = locked.rows[0]
      ? targetRow(locked.rows[0] as Record<string, unknown>)
      : undefined;
    if (!current) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");

    let res;
    if (transition === "revoke") {
      // Revocation is the only thing (besides a destination change) that
      // releases a destination claim for a new Target.
      res = await db.query(
        `UPDATE sync_targets SET revoked_at = now(), version = version + 1, updated_at = now()
         WHERE id = $1 RETURNING ${TARGET_COLUMNS}`,
        [targetId],
      );
    } else if (transition === "pause") {
      res = await db.query(
        `UPDATE sync_targets SET state = 'paused', version = version + 1, updated_at = now()
         WHERE id = $1 RETURNING ${TARGET_COLUMNS}`,
        [targetId],
      );
    } else {
      if (current.state === "disabled" && current.disabled_reason === "connection-revoked") {
        throw new DomainError(
          "VALIDATION_FAILED",
          "This Target's Connection is revoked; re-point it to another Connection before resuming",
        );
      }
      // Resumption triggers an immediate converge (ADR-0031 §5).
      res = await db.query(
        `UPDATE sync_targets
         SET state = 'active', disabled_reason = NULL, failure_count = 0,
             needs_sync = true, next_attempt_at = NULL, version = version + 1, updated_at = now()
         WHERE id = $1 RETURNING ${TARGET_COLUMNS}`,
        [targetId],
      );
    }
    await recordAuditEvent(db, {
      eventType:
        transition === "revoke"
          ? "sync.target_revoked"
          : transition === "pause"
            ? "sync.target_paused"
            : "sync.target_resumed",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { targetId, environmentId: current.environment_id },
    });
    return transition === "revoke" ? null : targetRow(res.rows[0] as Record<string, unknown>);
  });
}

export async function listTargets(
  ctx: AppCtx,
  filter: { organizationId: string; environmentId?: string; connectionId?: string },
): Promise<SyncTargetRow[]> {
  const clauses = ["organization_id = $1", "revoked_at IS NULL"];
  const params: unknown[] = [filter.organizationId];
  if (filter.environmentId) {
    params.push(filter.environmentId);
    clauses.push(`environment_id = $${params.length}`);
  }
  if (filter.connectionId) {
    params.push(filter.connectionId);
    clauses.push(`connection_id = $${params.length}`);
  }
  const res = await ctx.db.query(
    `SELECT ${TARGET_COLUMNS} FROM sync_targets WHERE ${clauses.join(" AND ")} ORDER BY created_at, id`,
    params,
  );
  return (res.rows as Record<string, unknown>[]).map(targetRow);
}

export async function getTarget(
  ctx: AppCtx,
  organizationId: string,
  targetId: string,
): Promise<SyncTargetRow> {
  const res = await ctx.db.query(
    `SELECT ${TARGET_COLUMNS} FROM sync_targets
     WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`,
    [targetId, organizationId],
  );
  const row = res.rows[0] as Record<string, unknown> | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
  return targetRow(row);
}

export interface LedgerEntry {
  dest_name: string;
  state: string;
  updated_at: string;
  last_error: string | null;
}

/** Per-name delivery state for status UIs — never fingerprints or values. */
export async function targetLedger(ctx: AppCtx, targetId: string): Promise<LedgerEntry[]> {
  const res = await ctx.db.query(
    `SELECT dest_name, state, updated_at, last_error FROM sync_ledger
     WHERE target_id = $1 ORDER BY dest_name`,
    [targetId],
  );
  return res.rows as LedgerEntry[];
}

/** Direct enqueue for "push now" — a Target mutation class trigger. */
export async function requestPush(ctx: AppCtx, org: OrgRow, targetId: string): Promise<void> {
  const res = await ctx.db.query(
    `UPDATE sync_targets SET needs_sync = true, next_attempt_at = NULL
     WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL RETURNING id`,
    [targetId, org.id],
  );
  if (!res.rows[0]) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
}

// ---------------------------------------------------------------------------

function mappingSummary(mapping: SyncMapping): string {
  if (mapping.kind === "wildcard") {
    return mapping.exclude?.length ? `* except ${mapping.exclude.join(",")}` : "*";
  }
  return mapping.items.map((i) => (i.rename ? `${i.name}->${i.rename}` : i.name)).join(",");
}

async function lockConnection(
  db: Querier,
  organizationId: string,
  connectionId: string,
): Promise<PlatformConnectionRow> {
  const res = await db.query(
    `SELECT ${CONNECTION_COLUMNS} FROM platform_connections
     WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL FOR UPDATE`,
    [connectionId, organizationId],
  );
  const row = res.rows[0] as PlatformConnectionRow | undefined;
  if (!row) throw new DomainError("RESOURCE_NOT_FOUND", "Platform Connection not found");
  return row;
}

function canonicalizeOrValidationError<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof AdapterError) {
      throw new DomainError("VALIDATION_FAILED", err.message);
    }
    throw err;
  }
}

function destinationClaimError(err: unknown): unknown {
  // Unique violation on the destination claim index (single-writer rule).
  if (err instanceof Error && "code" in err && (err as { code?: string }).code === "23505") {
    return new DomainError(
      "VERSION_CONFLICT",
      "Another Sync Target already claims this destination; a destination has exactly one writer",
    );
  }
  return err;
}
