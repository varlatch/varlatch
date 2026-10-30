// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Deleting an Organization (ADR-0051 Decisions 4 to 8).
 *
 * organization_deletions holds each request: who scheduled it and when,
 * run_after (the earliest time it may run), whether a second admin must
 * approve and who did, cancellation, and completion. An Organization has
 * at most one open request (neither cancelled nor completed); while one is
 * open the Organization is frozen.
 *
 * Scheduling suspends what it can undo: identities.suspended_by_deletion
 * and webhooks.suspended_by_deletion name the request that disabled a
 * machine identity or suspended a webhook, so a cancel restores exactly
 * those, and ordinary reactivation refuses an identity while it is set.
 *
 * Finalization destroys the Organization KEK: wrapped_org_kek is cleared
 * and org_kek_destroyed_at set, never one without the other.
 *
 * audit_tombstone_readers fixes, at finalization, the people who may still
 * export a deleted Organization's audit log (ADR-0016 §6). An Installation
 * Admin can remove a reader (removed_at, removed_by), never add one.
 */
export const sql = /* sql */ `
CREATE TABLE organization_deletions (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  requested_by text NOT NULL REFERENCES identities(id),
  scheduled_at timestamptz NOT NULL DEFAULT now(),
  run_after timestamptz NOT NULL,
  approval_required boolean NOT NULL,
  approved_by text REFERENCES identities(id),
  approved_at timestamptz,
  cancelled_by text REFERENCES identities(id),
  cancelled_at timestamptz,
  completed_at timestamptz,
  CHECK (run_after > scheduled_at),
  CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
  CHECK (approved_by IS NULL OR approval_required),
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK ((cancelled_by IS NULL) = (cancelled_at IS NULL)),
  CHECK (cancelled_at IS NULL OR completed_at IS NULL)
);
CREATE UNIQUE INDEX organization_deletions_open ON organization_deletions (organization_id)
  WHERE cancelled_at IS NULL AND completed_at IS NULL;
CREATE INDEX organization_deletions_due ON organization_deletions (run_after)
  WHERE cancelled_at IS NULL AND completed_at IS NULL;

ALTER TABLE identities ADD COLUMN suspended_by_deletion text REFERENCES organization_deletions(id);
ALTER TABLE webhooks ADD COLUMN suspended_by_deletion text REFERENCES organization_deletions(id);

ALTER TABLE organizations ADD COLUMN org_kek_destroyed_at timestamptz;
ALTER TABLE organizations ALTER COLUMN wrapped_org_kek DROP NOT NULL;
ALTER TABLE organizations ADD CONSTRAINT organizations_kek_present_or_destroyed CHECK (
  (wrapped_org_kek IS NOT NULL AND org_kek_destroyed_at IS NULL)
  OR (wrapped_org_kek IS NULL AND org_kek_destroyed_at IS NOT NULL AND deleted_at IS NOT NULL)
);

CREATE TABLE audit_tombstone_readers (
  organization_id text NOT NULL REFERENCES organizations(id),
  identity_id text NOT NULL REFERENCES identities(id),
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  removed_by text REFERENCES identities(id),
  PRIMARY KEY (organization_id, identity_id),
  CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);
`;
