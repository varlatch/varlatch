// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * admin-step-up for people (ADR-0054 step 4.7).
 *
 * Approval Intents gain the operations `member.invite_admin`,
 * `member.promote`, `member.demote` and `member.remove`, all bound to an
 * Organization: the Organization itself for an admin invitation, the
 * person otherwise.
 *
 * No other change. Whether admin-step-up can be set to `enforce` is decided
 * by the release (domain/securitycontrols.ts), not by the schema.
 */
const ADMIN_STEP_UP = `'identity.create', 'credential.issue', 'identity.reactivate',
                       'oidc_binding.create', 'oidc_binding.delete',
                       'grant.create', 'grant.replace', 'grant.revoke',
                       'role.create', 'role.update', 'role.delete',
                       'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
                       'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
                       'team.project_add', 'team.project_remove',
                       'member.invite_admin', 'member.promote', 'member.demote', 'member.remove'`;

export const sql = /* sql */ `
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze',
                       'requirement.update', 'requirement.revoke',
                       ${ADMIN_STEP_UP}));
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_admin_step_up_organization;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_admin_step_up_organization
  CHECK (operation NOT IN (${ADMIN_STEP_UP}) OR organization_id IS NOT NULL);
`;
