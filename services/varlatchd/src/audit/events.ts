// SPDX-License-Identifier: AGPL-3.0-or-later
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { withTx } from "../db/tx.js";
import { currentAttribution } from "./attribution.js";
import { exposureFromEvent, indexExposures } from "./exposure.js";

/**
 * Security Audit Events (ADR-0016). Events are written through this module
 * only, inside the caller's transaction for state mutations, and before
 * material leaves the process for disclosures. The input shape structurally
 * excludes plaintext/key/credential material; identifiers only.
 *
 * Inside an authenticated /v1 request (attribution.ts), an event whose actor
 * is the request's identity also names the credential that made the request
 * and its client, unless the caller set those fields itself: a caller's
 * value always wins, null included. Some events name the credential they
 * are about rather than the acting one (credential.issued,
 * credential.revoked); they set credentialId explicitly, so it is never
 * replaced.
 */

export type AuditDecision = "allow" | "deny" | "info";

/**
 * Every audit event type varlatchd records. AuditEventInput takes only
 * these, so a new type is added here first; test/sync-triggers.test.ts then
 * makes it decide whether it marks Sync Targets for a converge.
 */
export const AUDIT_EVENT_TYPES = [
  "audit_tombstone.reader_removed",
  "authentication.device_approved",
  "authentication.device_code_locked",
  "authentication.device_code_rejected",
  "authentication.device_collected",
  "authentication.device_denied",
  "authentication.device_requested",
  "authentication.failed",
  "authentication.passkey_enrollment_started",
  "authorization.denied",
  "bootstrap.completed",
  "bootstrap.grant_issued",
  "capability.denied",
  "capability.exercised",
  "capability.issued",
  "capability.revoked",
  "contract.activated",
  "contract.revision_pushed",
  "credential.issued",
  "credential.revoked",
  "environment.created",
  "environment.deleted",
  "exposure.revocation_confirmed",
  "grant.created",
  "grant.revoked",
  "group.created",
  "group.deleted",
  "group.member_added",
  "group.member_removed",
  "group.updated",
  "identity.created",
  "identity.profile_updated",
  "identity.reactivated",
  "identity.renamed",
  "identity.retired",
  "installation.custody_attested",
  "installation.initialized",
  "installation.public_url_changed",
  "installation.restored",
  "invitation.accepted",
  "invitation.issued",
  "invitation.revoked",
  "membership.removed",
  "membership.role_changed",
  "oidc_binding.created",
  "oidc_binding.revoked",
  "organization.created",
  "organization.deleted",
  "organization.deletion_approved",
  "organization.deletion_cancelled",
  "organization.deletion_scheduled",
  "organization.renamed",
  "project.created",
  "project.deleted",
  "project.renamed",
  "recovery.completed",
  "recovery.grant_issued",
  "recovery.identity_reenabled",
  "reenrollment.completed",
  "reenrollment.grant_issued",
  "requirement.created",
  "requirement.revoked",
  "requirement.updated",
  "role.created",
  "role.deleted",
  "role.updated",
  "secret.disclosed",
  "secret.validated",
  "setup.grant_rejected",
  "sync.connection_checked",
  "sync.connection_created",
  "sync.connection_credential_replaced",
  "sync.connection_revoked",
  "sync.destinations_listed",
  "sync.drift_detected",
  "sync.github_app_installations_listed",
  "sync.github_app_key_rotated",
  "sync.github_app_registered",
  "sync.github_app_registration_refused",
  "sync.github_app_removed",
  "sync.push_attempted",
  "sync.push_result",
  "sync.target_created",
  "sync.target_disabled",
  "sync.target_paused",
  "sync.target_resumed",
  "sync.target_revoked",
  "sync.target_updated",
  "sync.values_decrypted",
  "team.created",
  "team.deleted",
  "team.member_added",
  "team.member_removed",
  "team.project_added",
  "team.project_removed",
  "team.updated",
  "value.deleted",
  "value.disclosed",
  "value.rotation_completed",
  "value.rotation_started",
  "value.validated",
  "value.written",
  "webhook.created",
  "webhook.revoked",
  "webhook.updated",
] as const;
export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number];

export interface AuditEventInput {
  eventType: AuditEventType;
  decision: AuditDecision;
  actorIdentityId?: string | null;
  authenticationMethodId?: string | null;
  /** Left undefined, the acting request's credential when the actor is its identity. */
  credentialId?: string | null;
  /**
   * The acting request's client, as clientLabel() summarizes its
   * User-Agent; client-reported, never verified. Left undefined, filled
   * like credentialId.
   */
  client?: string | null;
  organizationId?: string | null;
  action?: string | null;
  resource?: Record<string, string | null> | null;
  /** Grant/Requirement provenance from the evaluator (IDs and outcomes only). */
  authz?: Record<string, unknown> | null;
  /** Left undefined, filled from the request like credentialId (ADR-0046 Decision 8). */
  tailnet?: Record<string, unknown> | null | undefined;
  /** Left undefined, filled from the request like credentialId (ADR-0046 Decision 8). */
  listener?: "ordinary" | "tailnet" | null | undefined;
  requestId?: string | null;
  metadata?: Record<string, string | number | boolean | null> | null;
}

export async function recordAuditEvent(
  db: Querier,
  event: AuditEventInput,
): Promise<string> {
  const [id] = await recordAuditEvents(db, [event]);
  return id as string;
}

/**
 * Several events in one transaction. A disclosure or a write also updates
 * the exposure index (ADR-0052 Decision 6), in the same transaction: all
 * of the events' index rows first, in one statement, then the events. So
 * the index never lags the audit log, and no transaction waits for an
 * exposure row while it holds the audit counter, which every audit insert
 * takes until commit: that order is what keeps two disclosures of the
 * same values from deadlocking.
 */
export async function recordAuditEvents(db: Querier, events: AuditEventInput[]): Promise<string[]> {
  const exposures = events.flatMap((event) => {
    const entry = exposureFromEvent(event);
    return entry ? [{ entry }] : [];
  });
  if (exposures.length === 0 && events.length === 1) return [await insertAuditEvent(db, events[0]!)];
  return withTx(db, async (tx) => {
    await indexExposures(tx, exposures);
    const ids: string[] = [];
    for (const event of events) ids.push(await insertAuditEvent(tx, event));
    return ids;
  });
}

async function insertAuditEvent(db: Querier, event: AuditEventInput): Promise<string> {
  const id = newId("auditEvent");
  // Only the request's own identity is attributed to its credential: an
  // event about someone else, or with no actor, keeps what the caller gave.
  const acting = currentAttribution();
  const attributed = acting !== undefined && event.actorIdentityId === acting.identityId;
  const credentialId = event.credentialId === undefined && attributed ? acting.credentialId : event.credentialId;
  const client = event.client === undefined && attributed ? acting.client : event.client;
  // The listener and tailnet resolution are filled the same way.
  const listener = event.listener === undefined && attributed ? acting.listener : event.listener;
  const tailnet = event.tailnet === undefined && attributed ? acting.tailnet : event.tailnet;
  await db.query(
    `INSERT INTO audit_events
       (id, schema_version, event_type, actor_identity_id, authentication_method_id,
        credential_id, organization_id, action, resource, decision, authz, tailnet,
        listener, request_id, metadata, client)
     VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
    [
      id,
      event.eventType,
      event.actorIdentityId ?? null,
      event.authenticationMethodId ?? null,
      credentialId ?? null,
      event.organizationId ?? null,
      event.action ?? null,
      event.resource ? JSON.stringify(event.resource) : null,
      event.decision,
      event.authz ? JSON.stringify(event.authz) : null,
      tailnet ? JSON.stringify(tailnet) : null,
      listener ?? null,
      event.requestId ?? null,
      event.metadata ? JSON.stringify(event.metadata) : null,
      client ?? null,
    ],
  );
  return id;
}
