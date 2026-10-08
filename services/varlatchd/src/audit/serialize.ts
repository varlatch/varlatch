// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Credential-safe URL for audit diffs (ADR-0029 §7): userinfo and
 * query/fragment contents are redacted — a webhook URL may carry embedded
 * tokens, and audit events must never contain credential material.
 */
export function redactWebhookUrl(url: string): string {
  try {
    const u = new URL(url);
    const base = `${u.protocol}//${u.host}${u.pathname === "/" ? "/" : "/[redacted]"}`;
    return `${base}${u.search ? "?[redacted]" : ""}${u.hash ? "#[redacted]" : ""}`;
  } catch {
    return "[invalid-url]";
  }
}

/**
 * The public wire shape of an audit event (ADR-0016 / ADR-0018), shared by
 * the /v1 audit endpoints and webhook delivery so both surfaces emit the
 * same schema.
 */
export function parseMaybe(v: unknown): unknown {
  return typeof v === "string" ? JSON.parse(v) : v;
}

export function serializeAuditEvent(r: Record<string, unknown>) {
  let metadata = parseMaybe(r.metadata);
  // Historical events predate URL redaction. Keep immutable storage intact
  // while applying the same disclosure boundary on exports and delivery.
  if (String(r.event_type).startsWith("webhook.") && metadata && typeof metadata === "object") {
    const safe = { ...metadata } as Record<string, unknown>;
    for (const key of ["url", "oldUrl", "newUrl"]) {
      if (typeof safe[key] === "string") safe[key] = redactWebhookUrl(safe[key]);
    }
    metadata = safe;
  }
  return {
    schemaVersion: r.schema_version,
    eventId: r.id,
    eventType: r.event_type,
    occurredAt: new Date(r.occurred_at as string).toISOString(),
    actorIdentityId: r.actor_identity_id,
    authenticationMethodId: r.authentication_method_id,
    credentialId: r.credential_id,
    // The acting request's client, as reported (migration 27); null before it.
    client: r.client ?? null,
    organizationId: r.organization_id,
    action: r.action,
    resource: parseMaybe(r.resource),
    decision: r.decision,
    authorization: parseMaybe(r.authz),
    tailnetContext: parseMaybe(r.tailnet),
    listener: r.listener,
    requestId: r.request_id,
    metadata,
  };
}
