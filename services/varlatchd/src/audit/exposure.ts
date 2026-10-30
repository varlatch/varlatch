// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";

/**
 * The extraction rules of the exposure and integration indexes (ADR-0052
 * Decision 6), shared by live indexing (recordAuditEvent) and the backfill
 * of older audit events, so the two can never disagree.
 */

export type ExposureWay = "revealed" | "delivered" | "export" | "written";

export interface ExposureEntry {
  organizationId: string;
  identityId: string;
  environmentId: string;
  way: ExposureWay;
  items: { itemName: string; versionId: string }[];
}

/** The shape of an audit event the rules read: as recorded, or as a stored row. */
export interface IndexableEvent {
  eventType: string;
  actorIdentityId?: string | null | undefined;
  organizationId?: string | null | undefined;
  resource?: Record<string, unknown> | null | undefined;
  metadata?: Record<string, unknown> | null | undefined;
}

/**
 * `NAME@version` and `NAME@primary+retiring` entries of a disclosure's
 * metadata.items, both versions of a rotation included.
 */
export function parseItems(items: unknown): { itemName: string; versionId: string }[] {
  if (typeof items !== "string" || items === "") return [];
  const out: { itemName: string; versionId: string }[] = [];
  for (const entry of items.split(",")) {
    const at = entry.lastIndexOf("@");
    if (at <= 0) continue;
    const itemName = entry.slice(0, at);
    for (const versionId of entry.slice(at + 1).split("+")) {
      if (versionId) out.push({ itemName, versionId });
    }
  }
  return out;
}

/**
 * What an audit event says a person received, or null. Disclosures deliver
 * plaintext (secret.disclosed and value.disclosed, every mode, reference
 * expansion included); writes make a value known to its writer
 * (value.written, value.rotation_started, with the version in
 * resource.versionId). Validation events are not evidence of possession.
 */
export function exposureFromEvent(event: IndexableEvent): ExposureEntry | null {
  const identityId = event.actorIdentityId;
  const organizationId = event.organizationId;
  const environmentId = event.resource?.environmentId;
  if (!identityId || !organizationId || typeof environmentId !== "string") return null;
  if (event.eventType === "secret.disclosed" || event.eventType === "value.disclosed") {
    const items = parseItems(event.metadata?.items);
    if (items.length === 0) return null;
    const mode = event.metadata?.mode;
    const purpose = event.metadata?.purpose;
    // A strict retrieval (varlatch run) or a scan hands values to a process;
    // an export reads them for a file; anything else shows them.
    const way: ExposureWay =
      purpose === "export" ? "export" : mode === "strict-retrieval" || purpose === "scan" ? "delivered" : "revealed";
    return { organizationId, identityId, environmentId, way, items };
  }
  if (event.eventType === "value.written" || event.eventType === "value.rotation_started") {
    const versionId = event.resource?.versionId;
    const itemName = event.resource?.itemName;
    if (typeof versionId !== "string" || typeof itemName !== "string") return null;
    return { organizationId, identityId, environmentId, way: "written", items: [{ itemName, versionId }] };
  }
  return null;
}

export interface IntegrationEntry {
  organizationId: string;
  identityId: string;
  kind: "target" | "connection";
  resourceId: string;
  changes: ("created" | "repointed" | "destination_changed" | "credential_replaced")[];
}

/** What an audit event says a person did to a Sync Target or Platform Connection, or null. */
export function integrationFromEvent(event: IndexableEvent): IntegrationEntry | null {
  const identityId = event.actorIdentityId;
  const organizationId = event.organizationId;
  if (!identityId || !organizationId) return null;
  const targetId = event.resource?.targetId;
  const connectionId = event.resource?.connectionId;
  switch (event.eventType) {
    case "sync.target_created":
      return typeof targetId === "string" ? { organizationId, identityId, kind: "target", resourceId: targetId, changes: ["created"] } : null;
    case "sync.target_updated": {
      if (typeof targetId !== "string") return null;
      const changes: IntegrationEntry["changes"] = [];
      if (event.metadata?.connectionRepointed === true) changes.push("repointed");
      if (event.metadata?.destinationChanged === true) changes.push("destination_changed");
      return changes.length ? { organizationId, identityId, kind: "target", resourceId: targetId, changes } : null;
    }
    case "sync.connection_created":
      return typeof connectionId === "string" ? { organizationId, identityId, kind: "connection", resourceId: connectionId, changes: ["created"] } : null;
    case "sync.connection_credential_replaced":
      return typeof connectionId === "string"
        ? { organizationId, identityId, kind: "connection", resourceId: connectionId, changes: ["credential_replaced"] }
        : null;
    default:
      return null;
  }
}

/**
 * One bulk upsert for every item of one disclosure or write, for people
 * only: a machine's deliveries are machine activity, never a person's
 * exposure, and are not indexed. `at` is the event's time (null: now); the
 * first and last times only ever widen, so a replay or an overlap between
 * the backfill and live indexing changes nothing.
 */
export async function indexExposure(db: Querier, entry: ExposureEntry, at: string | Date | null = null): Promise<void> {
  await db.query(
    `INSERT INTO member_exposure (organization_id, identity_id, version_id, item_name, environment_id, way, first_at, last_at)
     SELECT $1, $2, u.version_id, u.item_name, $3, $4, COALESCE($7::timestamptz, now()), COALESCE($7::timestamptz, now())
     FROM unnest($5::text[], $6::text[]) AS u(version_id, item_name)
     WHERE EXISTS (SELECT 1 FROM identities WHERE id = $2 AND kind = 'human')
     ON CONFLICT (organization_id, identity_id, version_id, environment_id, way) DO UPDATE SET
       first_at = LEAST(member_exposure.first_at, EXCLUDED.first_at),
       last_at = GREATEST(member_exposure.last_at, EXCLUDED.last_at)`,
    [
      entry.organizationId,
      entry.identityId,
      entry.environmentId,
      entry.way,
      entry.items.map((i) => i.versionId),
      entry.items.map((i) => i.itemName),
      at,
    ],
  );
}

/** The integration index's upsert, with an event's time for the backfill (null: now). */
export async function indexIntegration(db: Querier, entry: IntegrationEntry, at: string | Date | null = null): Promise<void> {
  await db.query(
    `INSERT INTO member_integrations (organization_id, identity_id, kind, resource_id, changes, first_at, last_at)
     VALUES ($1,$2,$3,$4,$5,COALESCE($6::timestamptz, now()),COALESCE($6::timestamptz, now()))
     ON CONFLICT (organization_id, identity_id, kind, resource_id) DO UPDATE SET
       changes = ARRAY(SELECT DISTINCT unnest(member_integrations.changes || EXCLUDED.changes) ORDER BY 1),
       first_at = LEAST(member_integrations.first_at, EXCLUDED.first_at),
       last_at = GREATEST(member_integrations.last_at, EXCLUDED.last_at)`,
    [entry.organizationId, entry.identityId, entry.kind, entry.resourceId, entry.changes, at],
  );
}
