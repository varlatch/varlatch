// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The audit reads of the repair of Capabilities earlier retirements left
 * live (domain/capabilityrepair.ts), by index instead of scans of the
 * audit log:
 *
 * - audit_events_identity_lifecycle_idx: an identity's identity.retired and
 *   identity.reactivated in an Organization, in audit order (its latest is
 *   the last entry);
 * - audit_events_capability_issued_idx: a Capability's capability.issued in
 *   an Organization.
 *
 * Both are partial: only those event types are indexed. Indexes only: no
 * table, column, constraint or row changes, so what a backup or a
 * migration's bundle holds is the same with or without them.
 */
export const sql = /* sql */ `
CREATE INDEX audit_events_identity_lifecycle_idx
  ON audit_events (organization_id, (resource->>'identityId'), event_order)
  WHERE event_type IN ('identity.retired', 'identity.reactivated');
CREATE INDEX audit_events_capability_issued_idx
  ON audit_events (organization_id, (resource->>'capabilityId'), event_order)
  WHERE event_type = 'capability.issued';
`;
