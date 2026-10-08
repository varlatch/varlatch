// SPDX-License-Identifier: AGPL-3.0-or-later
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";
import { currentAttribution } from "./attribution.js";

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

export interface AuditEventInput {
  eventType: string;
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
  tailnet?: Record<string, unknown> | null;
  listener?: "ordinary" | "tailnet" | null;
  requestId?: string | null;
  metadata?: Record<string, string | number | boolean | null> | null;
}

export async function recordAuditEvent(
  db: Querier,
  event: AuditEventInput,
): Promise<string> {
  const id = newId("auditEvent");
  // Only the request's own identity is attributed to its credential: an
  // event about someone else, or with no actor, keeps what the caller gave.
  const acting = currentAttribution();
  const attributed = acting !== undefined && event.actorIdentityId === acting.identityId;
  const credentialId = event.credentialId === undefined && attributed ? acting.credentialId : event.credentialId;
  const client = event.client === undefined && attributed ? acting.client : event.client;
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
      event.tailnet ? JSON.stringify(event.tailnet) : null,
      event.listener ?? null,
      event.requestId ?? null,
      event.metadata ? JSON.stringify(event.metadata) : null,
      client ?? null,
    ],
  );
  return id;
}
