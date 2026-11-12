// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * requirement-protection enforced (ADR-0054 step 4.2).
 *
 * Approval Intents gain the operations `requirement.update` and
 * `requirement.revoke`: editing or revoking a Tailnet Requirement while
 * the Organization enforces requirement-protection. Both are bound to an
 * Organization, their target the Requirement id.
 *
 * No other change: a control's mode was already free to hold `enforce`,
 * and which controls a change may set to it is decided by the release
 * (domain/securitycontrols.ts), not by the schema.
 */
export const sql = /* sql */ `
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze',
                       'requirement.update', 'requirement.revoke'));
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_requirement_organization
  CHECK (operation NOT IN ('requirement.update', 'requirement.revoke') OR organization_id IS NOT NULL);
`;
