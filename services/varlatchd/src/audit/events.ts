// SPDX-License-Identifier: AGPL-3.0-or-later
import { newId } from "../db/ids.js";
import type { Querier } from "../db/migrate.js";

/**
 * Security Audit Events (ADR-0016). Events are written through this module
 * only, inside the caller's transaction for state mutations, and before
 * material leaves the process for disclosures. The input shape structurally
 * excludes plaintext/key/credential material; identifiers only.
 */

export type AuditDecision = "allow" | "deny" | "info";

export interface AuditEventInput {
  eventType: string;
  decision: AuditDecision;
  actorIdentityId?: string | null;
  authenticationMethodId?: string | null;
  credentialId?: string | null;
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
  await db.query(
    `INSERT INTO audit_events
       (id, schema_version, event_type, actor_identity_id, authentication_method_id,
        credential_id, organization_id, action, resource, decision, authz, tailnet,
        listener, request_id, metadata)
     VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [
      id,
      event.eventType,
      event.actorIdentityId ?? null,
      event.authenticationMethodId ?? null,
      event.credentialId ?? null,
      event.organizationId ?? null,
      event.action ?? null,
      event.resource ? JSON.stringify(event.resource) : null,
      event.decision,
      event.authz ? JSON.stringify(event.authz) : null,
      event.tailnet ? JSON.stringify(event.tailnet) : null,
      event.listener ?? null,
      event.requestId ?? null,
      event.metadata ? JSON.stringify(event.metadata) : null,
    ],
  );
  return id;
}
