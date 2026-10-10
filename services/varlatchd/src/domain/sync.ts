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
import { decryptPlatformCredential, encryptGitHubAppKey, encryptPlatformCredential } from "../crypto/hierarchy.js";
import { newId } from "../db/ids.js";
import { withTx } from "../db/tx.js";
import type { Querier } from "../db/migrate.js";
import type { AppCtx } from "./ctx.js";
import { DomainError } from "./errors.js";
import { APP_COLUMNS, appWithKey, getGitHubApp, isRsaKey, type GitHubAppRow } from "./githubapps.js";
import { GITHUB_UNREACHABLE, NOT_GITHUB, appRequest, readJwtRefusal } from "./githubjwt.js";
import {
  APP_REMOVED,
  appCredentialFrom,
  mintInstallationToken,
  readInstallation,
  type AppCredential,
  type MintUse,
} from "./githubmint.js";
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
  /** When the platform last said the stored credential expires; NULL is unknown. */
  credential_expires_at: string | null;
  credential_expiry_seen_at: string | null;
  /** 'token': a stored Platform Credential; 'github-app': none, tokens minted from the App (ADR-0047). */
  credential_kind: "token" | "github-app";
  github_app_id: string | null;
  github_installation_id: string | number | null;
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
  created_at, revoked_at, version, updated_at, credential_expires_at, credential_expiry_seen_at,
  credential_kind, github_app_id, github_installation_id`;

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

/**
 * A Connection on an installation of the Organization's GitHub App
 * (ADR-0047 Decision 2): no stored token, only the App and the
 * installation. The installation is read as the App first: it must be this
 * App's and not suspended, and its account becomes the base identity. No
 * network call holds a lock. Creation then takes the App's row lock, as
 * attachment and key rotation do, and checks the App is still live under it.
 */
export async function createAppConnection(
  ctx: AppCtx,
  org: OrgRow,
  input: { installationId: number; name: string },
  actorIdentityId: string,
  allowedAdapters: string[] | null,
  fetchImpl: typeof fetch = fetch,
): Promise<PlatformConnectionRow> {
  if (allowedAdapters && !allowedAdapters.includes("github-actions")) {
    throw new DomainError("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter");
  }
  const { app, pem } = await appWithKey(ctx, org);
  const installation = await readInstallation(
    fetchImpl,
    { githubAppId: Number(app.github_app_id), clientId: app.client_id, privateKeyPem: pem },
    input.installationId,
  );
  if (!installation.ok) {
    throw new DomainError("VALIDATION_FAILED", installation.check.message, { check: installation.check });
  }
  if (installation.suspended) {
    throw new DomainError(
      "VALIDATION_FAILED",
      `The GitHub App's installation on ${installation.account.login} is suspended. Unsuspend it on GitHub, then try again.`,
    );
  }
  const adapter = getAdapter("github-actions");
  const baseIdentity = canonicalizeOrValidationError(() => adapter.canonicalizeBaseIdentity(installation.account.login));
  const id = newId("platformConnection");
  return withTx(ctx.db, async (db) => {
    const locked = await db.query(
      "SELECT id FROM github_apps WHERE id = $1 AND organization_id = $2 AND removed_at IS NULL FOR UPDATE",
      [app.id, org.id],
    );
    if (!locked.rows[0]) {
      throw new DomainError("STATE_CHANGED", "The Organization's GitHub App was removed meanwhile");
    }
    await recordAuditEvent(db, {
      eventType: "sync.connection_created",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { connectionId: id },
      metadata: {
        platform: adapter.platform,
        baseIdentity,
        name: input.name,
        credentialKind: "github-app",
        githubAppId: app.id,
        installationId: input.installationId,
      },
    });
    const res = await db.query(
      `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope, created_by,
         credential_kind, github_app_id, github_installation_id)
       VALUES ($1,$2,$3,$4,$5,NULL,$6,'github-app',$7,$8)
       RETURNING ${CONNECTION_COLUMNS}`,
      [id, org.id, adapter.platform, baseIdentity, input.name, actorIdentityId, app.id, input.installationId],
    );
    return res.rows[0] as PlatformConnectionRow;
  });
}

export type KeyRotationOutcome = { outcome: "rotated"; app: GitHubAppRow } | ({ outcome: "failed" } & AccessCheck);

/**
 * Rotate the GitHub App's private key (ADR-0047 Decision 5). The key
 * belongs to the App, and every App Connection uses it, so a rotation is a
 * new disclosure grant for every non-revoked Target of every non-revoked
 * Connection on the App, paused and auto-disabled ones included: `gate`
 * runs each one's write-time disclosure gate, and any refusal refuses the
 * whole rotation, leaving every Connection on the old key.
 *
 * The new key is verified first, with no lock held: a JWT signed with it
 * must get the App from GET /app. GitHub keeps the old key valid until it
 * is deleted there, so the rotation works before the old key goes. Then,
 * in one transaction: the App row, its Connections, and their Targets are
 * locked in that order (each set in id order), the App's version must be
 * the one the caller saw, every Target passes the gate, the key is
 * replaced and the version moves, and every Target is queued to converge.
 */
export async function rotateGitHubAppKey(
  ctx: AppCtx,
  org: OrgRow,
  input: { privateKey: string; expectedVersion: number },
  gate: (target: SyncTargetRow) => Promise<Record<string, unknown> | undefined | void>,
  actorIdentityId: string,
  fetchImpl: typeof fetch = fetch,
  now: number = Date.now(),
): Promise<KeyRotationOutcome> {
  if (!isRsaKey(input.privateKey)) {
    throw new DomainError("VALIDATION_FAILED", "privateKey: not an RSA private key in PEM, as GitHub issues them");
  }
  const seen = await getGitHubApp(ctx, org.id);
  const githubAppId = Number(seen.github_app_id);
  const { res, claims } = await appRequest(fetchImpl, "/app", seen.client_id, input.privateKey, now);
  if (!res) return { outcome: "failed", ...GITHUB_UNREACHABLE };
  if (res.status === 401) return { outcome: "failed", ...readJwtRefusal(res, claims) };
  if (!res.ok) {
    return {
      outcome: "failed",
      status: "failed",
      where: "connection",
      httpStatus: res.status,
      message: `GitHub did not confirm the new key for the App ${seen.slug} (HTTP ${res.status}).`,
    };
  }
  const body = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
  if (!body || typeof body !== "object" || Array.isArray(body) || body.id !== githubAppId) {
    return { outcome: "failed", ...NOT_GITHUB(res.status) };
  }
  const envelope = encryptGitHubAppKey(orgKekOf(ctx, org), org.id, seen.id, input.privateKey);
  return withTx(ctx.db, async (db) => {
    const locked = (await db.query(
      "SELECT id, version FROM github_apps WHERE id = $1 AND organization_id = $2 AND removed_at IS NULL FOR UPDATE",
      [seen.id, org.id],
    )).rows[0] as { id: string; version: number } | undefined;
    if (!locked) throw new DomainError("RESOURCE_NOT_FOUND", "This Organization has no GitHub App");
    if (locked.version !== input.expectedVersion) {
      throw new DomainError("VERSION_CONFLICT", "The GitHub App was changed concurrently; reload and retry");
    }
    const { connections, targets } = await lockAppConnectionsAndTargets(db, seen.id);
    const provenance: Record<string, unknown> = {};
    for (const target of targets) provenance[target.id] = (await gate(target)) ?? null;
    const updated = await db.query(
      `UPDATE github_apps SET key_envelope = $1, version = version + 1, updated_at = now()
       WHERE id = $2 RETURNING ${APP_COLUMNS}`,
      [JSON.stringify(envelope), seen.id],
    );
    // A rotation is a Target mutation class trigger (ADR-0031 §6): enqueue directly.
    await db.query(
      "UPDATE sync_targets SET needs_sync = true, next_attempt_at = NULL WHERE id = ANY($1::text[])",
      [targets.map((t) => t.id)],
    );
    const app = updated.rows[0] as GitHubAppRow;
    await recordAuditEvent(db, {
      eventType: "sync.github_app_key_rotated",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { githubAppId: seen.id },
      // Decision 7: the gate's provenance for every Target in the set.
      authz: { reauthorizedTargets: provenance },
      metadata: {
        appId: githubAppId,
        slug: seen.slug,
        version: app.version,
        connections: connections.map((c) => c.id).join(",") || null,
        reauthorizedTargets: targets.map((t) => t.id).join(",") || null,
      },
    });
    return { outcome: "rotated" as const, app };
  });
}

/**
 * Remove the Organization's GitHub App from Varlatch (ADR-0047 Decision 5):
 * the App the caller confirmed, by its id, checked under its lock.
 * Every Connection on it is revoked in one transaction, as revocation does
 * for one: their Targets are disabled and keep their destination claims.
 * The wrapped key is deleted. Removal narrows disclosure, so it needs no
 * gate. It does not touch GitHub: the App stays registered and installed
 * there until its owner deletes it.
 */
export async function removeGitHubApp(ctx: AppCtx, org: OrgRow, appRowId: string, actorIdentityId: string): Promise<void> {
  await withTx(ctx.db, async (db) => {
    const locked = (await db.query(
      "SELECT id, github_app_id, slug FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL FOR UPDATE",
      [org.id],
    )).rows[0] as { id: string; github_app_id: string | number; slug: string } | undefined;
    if (!locked) throw new DomainError("RESOURCE_NOT_FOUND", "This Organization has no GitHub App");
    // The App the caller confirmed, and no other: another one may have
    // replaced it since (removed, then registered or imported).
    if (locked.id !== appRowId) {
      throw new DomainError("STATE_CHANGED", "The Organization's GitHub App changed since you confirmed; reload and try again");
    }
    const { connections, targets } = await lockAppConnectionsAndTargets(db, locked.id);
    await db.query(
      "UPDATE platform_connections SET revoked_at = now(), version = version + 1, updated_at = now() WHERE id = ANY($1::text[])",
      [connections.map((c) => c.id)],
    );
    await db.query(
      `UPDATE sync_targets
       SET state = 'disabled', disabled_reason = 'connection-revoked', version = version + 1, updated_at = now()
       WHERE id = ANY($1::text[])`,
      [targets.map((t) => t.id)],
    );
    await db.query(
      "UPDATE github_apps SET removed_at = now(), key_envelope = NULL, version = version + 1, updated_at = now() WHERE id = $1",
      [locked.id],
    );
    await recordAuditEvent(db, {
      eventType: "sync.github_app_removed",
      decision: "info",
      actorIdentityId,
      organizationId: org.id,
      action: "config.sync.manage",
      resource: { githubAppId: locked.id },
      metadata: {
        appId: Number(locked.github_app_id),
        slug: locked.slug,
        revokedConnections: connections.map((c) => c.id).join(",") || null,
        disabledTargets: targets.map((t) => t.id).join(",") || null,
      },
    });
  });
}

/** With the App row already locked: its non-revoked Connections, then their non-revoked Targets, each in id order. */
async function lockAppConnectionsAndTargets(
  db: Querier,
  appRowId: string,
): Promise<{ connections: PlatformConnectionRow[]; targets: SyncTargetRow[] }> {
  const connections = (await db.query(
    `SELECT ${CONNECTION_COLUMNS} FROM platform_connections
     WHERE github_app_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE`,
    [appRowId],
  )).rows as PlatformConnectionRow[];
  const targets = ((await db.query(
    `SELECT ${TARGET_COLUMNS} FROM sync_targets
     WHERE connection_id = ANY($1::text[]) AND revoked_at IS NULL ORDER BY id FOR UPDATE`,
    [connections.map((c) => c.id)],
  )).rows as Record<string, unknown>[]).map(targetRow);
  return { connections, targets };
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
  gate: (target: SyncTargetRow) => Promise<Record<string, unknown> | undefined | void>,
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
    if (row.credential_kind === "github-app") throw appHasNoCredential();
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
    const provenance: Record<string, unknown> = {};
    for (const target of rows) {
      provenance[target.id] = (await gate(target)) ?? null;
    }
    const updated = await db.query(
      `UPDATE platform_connections
       SET credential_envelope = $1, version = version + 1, updated_at = now(),
           credential_expires_at = NULL, credential_expiry_seen_at = NULL
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
      // Each re-authorized Target's write-time gate, as it decided.
      authz: { reauthorizedTargets: provenance },
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
    // An App Connection's App first (ADR-0047 Decision 5), then the
    // Connection, then its Targets.
    await lockConnectionsAndApps(db, org.id, [connectionId]);
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
  const resolved = await resolveCredential(ctx, org, input, allowedAdapters);
  const { adapter, baseIdentity, connectionId, supplied, storedVersion, storedExpiresAt } = resolved;
  // No destination fields: the check stops at the base identity.
  const named = Object.values(input.destination ?? {}).some((v) => v !== undefined && v !== null && v !== "");
  const destination = named
    ? canonicalizeOrValidationError(() => adapter.canonicalizeDestination(input.destination ?? {}))
    : null;

  const credential = await credentialForUse(resolved, destination ? "destination-check" : "connection-check", destination?.destination ?? {}, fetchImpl);
  const checked = credential.ok
    ? await adapter.checkAccess({
        baseIdentity,
        destination: destination?.destination ?? {},
        credential: credential.credential,
        credentialKind: resolved.kind,
        ...(fetchImpl ? { fetchImpl } : {}),
      })
    : credential.check;
  if (resolved.kind === "token" && connectionId && storedVersion !== null && checked.credentialExpiresAt) {
    await recordCredentialExpiry(ctx.db, connectionId, storedVersion, checked.credentialExpiresAt);
  }
  // An App Connection has no expiry (ADR-0047 Decision 4): none recorded, none returned.
  const result = resolved.kind === "token" ? withKnownExpiry(checked, storedExpiresAt) : withoutExpiry(checked);
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
      credentialKind: resolved.kind,
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
  const resolved = await resolveCredential(ctx, org, input, allowedAdapters);
  const { adapter, baseIdentity, connectionId, supplied, storedVersion, storedExpiresAt } = resolved;
  if (!adapter.listDestinations) {
    throw new DomainError(
      "VALIDATION_FAILED",
      "This platform has no destinations to list: the Connection's base identity is the destination",
    );
  }
  const credential = await credentialForUse(resolved, "listing", {}, fetchImpl);
  const listing: DestinationListing = credential.ok
    ? await adapter.listDestinations({
        baseIdentity,
        destination: {},
        credential: credential.credential,
        credentialKind: resolved.kind,
        ...(fetchImpl ? { fetchImpl } : {}),
      })
    : { check: credential.check, items: [], truncated: false };
  if (resolved.kind === "token" && connectionId && storedVersion !== null && listing.check.credentialExpiresAt) {
    await recordCredentialExpiry(ctx.db, connectionId, storedVersion, listing.check.credentialExpiresAt);
  }
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
      credentialKind: resolved.kind,
      status: listing.check.status,
      httpStatus: listing.check.httpStatus ?? null,
      count: items.length,
      truncated: listing.truncated,
    },
  });
  return {
    ...listing,
    check: resolved.kind === "token" ? withKnownExpiry(listing.check, storedExpiresAt) : withoutExpiry(listing.check),
    items,
  };
}

/**
 * GitHub does not repeat the expiry header on every answer. For a stored
 * credential, the date recorded for it stands in when this answer said
 * nothing; a supplied credential (null here) never borrows one.
 */
function withKnownExpiry(check: AccessCheck, storedExpiresAt: string | null): AccessCheck {
  return check.credentialExpiresAt || !storedExpiresAt ? check : { ...check, credentialExpiresAt: storedExpiresAt };
}

/** An App Connection's check or listing never carries a date: a minted token's expiry is not the Connection's. */
function withoutExpiry(check: AccessCheck): AccessCheck {
  const { credentialExpiresAt: _minted, ...rest } = check;
  return rest;
}

type ResolvedCredential = {
  adapter: PlatformAdapter;
  baseIdentity: string;
  connectionId: string | null;
  supplied: boolean;
  /** The Connection's version the stored credential was read at; null for a supplied one, and for an App Connection. */
  storedVersion: number | null;
  /** When the stored credential expires, as last recorded for it; null for a supplied one, and for an App Connection. */
  storedExpiresAt: string | null;
} & (
  | { kind: "token"; credential: string }
  /** An App Connection: what it mints with, or null when its App was removed. */
  | { kind: "github-app"; app: AppCredential | null }
);

/** The credential for one use: a token as stored or supplied, or one minted from the App, narrowed to the use. */
async function credentialForUse(
  resolved: ResolvedCredential,
  use: MintUse,
  destination: Record<string, string>,
  fetchImpl?: typeof fetch,
): Promise<{ ok: true; credential: string } | { ok: false; check: AccessCheck }> {
  if (resolved.kind === "token") return { ok: true, credential: resolved.credential };
  if (!resolved.app) return { ok: false, check: APP_REMOVED };
  const minted = await mintInstallationToken(fetchImpl ?? fetch, resolved.app, use, destination);
  return minted.ok ? { ok: true, credential: minted.token } : minted;
}

/**
 * The credential an access check or a listing uses: supplied now (a new
 * Connection, or a replacement for a stored one) or the Connection's stored
 * one. Either way it goes only to the Connection's base identity. An App
 * Connection has none of its own: its App's key and installation, to mint
 * from; a supplied credential is refused for it.
 */
async function resolveCredential(
  ctx: AppCtx,
  org: OrgRow,
  input: CredentialInput,
  allowedAdapters: string[] | null,
): Promise<ResolvedCredential> {
  let platform: string;
  let baseIdentity: string;
  let credential: string | null = null;
  let app: AppCredential | null = null;
  let kind: "token" | "github-app" = "token";
  let connectionId: string | null = null;
  let storedVersion: number | null = null;
  let storedExpiresAt: string | null = null;
  if ("connectionId" in input) {
    const connection = await getConnection(ctx, org.id, input.connectionId);
    connectionId = connection.id;
    platform = connection.platform;
    baseIdentity = connection.base_identity;
    if (connection.credential_kind === "github-app") {
      if (input.credential !== undefined) throw appHasNoCredential();
      kind = "github-app";
      const res = await ctx.db.query(
        `SELECT id AS app_row_id, github_app_id AS app_github_id, client_id AS app_client_id,
                key_envelope AS app_key_envelope, removed_at AS app_removed_at
         FROM github_apps WHERE id = $1 AND organization_id = $2`,
        [connection.github_app_id, org.id],
      );
      const row = res.rows[0] as Parameters<typeof appCredentialFrom>[2] | undefined;
      app = row
        ? appCredentialFrom(ctx, org, { ...row, github_installation_id: connection.github_installation_id, base_identity: connection.base_identity })
        : null;
    } else if (input.credential !== undefined) {
      credential = input.credential;
    } else {
      // The credential and its version in one read: an expiry the platform
      // reports for it is recorded only against that version.
      const res = await ctx.db.query(
        "SELECT credential_envelope, version, credential_expires_at FROM platform_connections WHERE id = $1",
        [connection.id],
      );
      const stored = res.rows[0] as { credential_envelope: unknown; version: number; credential_expires_at: string | Date | null };
      storedVersion = stored.version;
      storedExpiresAt = stored.credential_expires_at ? new Date(stored.credential_expires_at).toISOString() : null;
      credential = decryptPlatformCredential(orgKekOf(ctx, org), org.id, connection.id, parseJson<Envelope>(stored.credential_envelope));
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
  const supplied = !("connectionId" in input) || input.credential !== undefined;
  const common = { adapter, baseIdentity, connectionId, supplied, storedVersion, storedExpiresAt };
  if (kind === "github-app") return { ...common, kind, app };
  if (credential === null || credential.trim().length === 0) {
    throw new DomainError("VALIDATION_FAILED", "Platform Credential must not be empty");
  }
  return { ...common, kind, credential };
}

/**
 * Record when the platform says a stored credential expires (ADR-0031,
 * amendment 2026-10-09), but only if the Connection still holds the
 * credential that was used: `version` is the one it was read at, and a
 * replacement bumps it, so a late report about an old token never lands on
 * a new one. Not a Connection change: the version and updated_at stay.
 */
export async function recordCredentialExpiry(
  db: Querier,
  connectionId: string,
  version: number,
  expiresAt: string,
): Promise<void> {
  await db.query(
    `UPDATE platform_connections SET credential_expires_at = $3, credential_expiry_seen_at = now()
     WHERE id = $1 AND version = $2 AND revoked_at IS NULL`,
    [connectionId, version, expiresAt],
  );
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
    // Lock the Connection (and an App Connection's App before it):
    // attachment serializes with credential replacement and key rotation.
    const locked = await lockConnectionsAndApps(db, org.id, [input.connectionId]);
    const connection = usableConnection(locked, input.connectionId);
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
    // Lock order: Apps, then Connections, then the Target, as key rotation,
    // credential replacement, and Connection revocation take them, so a
    // Target edit serializes with each instead of deadlocking. The Target's
    // Connection is read unlocked to know which to lock; it and a
    // re-point's new Connection (with their Apps) are locked in id order,
    // then the Target, which is checked again under the lock.
    const seen = await db.query(
      "SELECT connection_id FROM sync_targets WHERE id = $1 AND revoked_at IS NULL",
      [target.id],
    );
    const seenConnectionId = (seen.rows[0] as { connection_id: string } | undefined)?.connection_id;
    if (!seenConnectionId) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
    const connectionId = patch.connectionId ?? seenConnectionId;
    const lockedConnections = await lockConnectionsAndApps(db, org.id, [seenConnectionId, connectionId]);
    const connections = lockedConnections.connections;

    const locked = await db.query(
      `SELECT ${TARGET_COLUMNS} FROM sync_targets WHERE id = $1 AND revoked_at IS NULL FOR UPDATE`,
      [target.id],
    );
    const current = locked.rows[0]
      ? targetRow(locked.rows[0] as Record<string, unknown>)
      : undefined;
    if (!current) throw new DomainError("RESOURCE_NOT_FOUND", "Sync Target not found");
    if (current.version !== patch.expectedVersion || current.connection_id !== seenConnectionId) {
      throw new DomainError("VERSION_CONFLICT", "Sync Target was modified concurrently; reload and retry");
    }
    const connection = usableConnection(lockedConnections, connectionId);
    if (patch.connectionId !== undefined) {
      const oldPlatform = connections.find((c) => c.id === current.connection_id)?.platform;
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

/**
 * Locks for a change that touches Connections (ADR-0047 Decision 5): the
 * Apps of App Connections first, then the Connections, each in id order,
 * so every path takes them in the order key rotation does (App,
 * Connections, Targets). A Connection's App never changes, so it is read
 * unlocked to know which to lock. Revoked Connections and removed Apps are
 * locked too; callers decide what they may still use.
 */
async function lockConnectionsAndApps(
  db: Querier,
  organizationId: string,
  connectionIds: string[],
): Promise<{ connections: PlatformConnectionRow[]; liveApps: Set<string> }> {
  const ids = [...new Set(connectionIds)];
  const appIds = ((await db.query(
    `SELECT DISTINCT github_app_id FROM platform_connections
     WHERE id = ANY($1::text[]) AND organization_id = $2 AND github_app_id IS NOT NULL`,
    [ids, organizationId],
  )).rows as { github_app_id: string }[]).map((r) => r.github_app_id);
  const apps = appIds.length === 0
    ? []
    : ((await db.query(
        "SELECT id, removed_at FROM github_apps WHERE id = ANY($1::text[]) AND organization_id = $2 ORDER BY id FOR UPDATE",
        [appIds, organizationId],
      )).rows as { id: string; removed_at: string | null }[]);
  const connections = (await db.query(
    `SELECT ${CONNECTION_COLUMNS} FROM platform_connections
     WHERE id = ANY($1::text[]) AND organization_id = $2
     ORDER BY id FOR UPDATE`,
    [ids, organizationId],
  )).rows as PlatformConnectionRow[];
  return { connections, liveApps: new Set(apps.filter((a) => a.removed_at === null).map((a) => a.id)) };
}

/** A locked Connection a Target may use: not revoked, and an App Connection's App still live. */
function usableConnection(
  locked: { connections: PlatformConnectionRow[]; liveApps: Set<string> },
  connectionId: string,
): PlatformConnectionRow {
  const connection = locked.connections.find((c) => c.id === connectionId && c.revoked_at === null);
  if (!connection) throw new DomainError("RESOURCE_NOT_FOUND", "Platform Connection not found");
  if (connection.credential_kind === "github-app" && !locked.liveApps.has(connection.github_app_id ?? "")) {
    throw new DomainError("VALIDATION_FAILED", "This Connection's GitHub App was removed from Varlatch");
  }
  return connection;
}

const appHasNoCredential = () =>
  new DomainError(
    "VALIDATION_FAILED",
    "A GitHub App Connection has no credential of its own to replace or supply: its tokens are issued from the App's key. Rotate the App's key instead.",
  );

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
