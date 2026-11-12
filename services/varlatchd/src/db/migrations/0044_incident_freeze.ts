// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The incident freeze (ADR-0055 Decision 1).
 *
 * organization_freezes holds each freeze of an Organization: who froze it
 * and when, a reason shown to members (at most 200 characters, never copied
 * into audit), and, once lifted, who lifted it, when and how (`approval`:
 * a person with a step-up approval; `operator`: `varlatchd admin
 * unfreeze`, with no person). At most one open freeze per Organization.
 * Rows are never deleted: they are the history, and they stay with a
 * deleted Organization's tombstone.
 *
 * Separate from organization_deletions: both can be open, and an operation
 * runs only if neither refuses it.
 *
 * Approval Intents gain the operation `organization.unfreeze` (bound to an
 * Organization, its target the freeze id) and the close reason `frozen`
 * (a freeze closes every open intent of its Organization).
 *
 * Lock order (domain/liveness.ts): the freeze row is written only by
 * transactions that hold the Organization row FOR UPDATE, and read without
 * a lock by others that hold it at least FOR KEY SHARE. It sits in step
 * 11, with security_controls, before the audit insert.
 */
export const sql = /* sql */ `
CREATE TABLE organization_freezes (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  frozen_by text NOT NULL REFERENCES identities(id),
  frozen_at timestamptz NOT NULL,
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 200),
  lifted_at timestamptz,
  lifted_by text REFERENCES identities(id),
  lift_method text CHECK (lift_method IN ('approval', 'operator')),
  CHECK ((lifted_at IS NULL) = (lift_method IS NULL)),
  CHECK (lifted_by IS NULL OR lift_method = 'approval'),
  CHECK (lift_method IS DISTINCT FROM 'approval' OR lifted_by IS NOT NULL),
  CHECK (lifted_at IS NULL OR lifted_at >= frozen_at)
);
CREATE UNIQUE INDEX organization_freezes_open ON organization_freezes (organization_id) WHERE lifted_at IS NULL;
CREATE INDEX organization_freezes_by_organization ON organization_freezes (organization_id, frozen_at);

ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze'));
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_unfreeze_organization
  CHECK (operation <> 'organization.unfreeze' OR organization_id IS NOT NULL);
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_close_reason_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_close_reason_check
  CHECK (close_reason IN ('cancelled', 'reset', 'organization-deleted', 'frozen'));
`;
