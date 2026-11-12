// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * admin-step-up for machine identities, credentials and OIDC bindings
 * (ADR-0054 step 4.5).
 *
 * Approval Intents gain the operations `identity.create`,
 * `credential.issue`, `identity.reactivate`, `oidc_binding.create` and
 * `oidc_binding.delete`, all bound to an Organization: the Organization
 * itself for a creation, the identity (and the binding) otherwise.
 *
 * No other change. Whether admin-step-up can be set to `enforce` is decided
 * by the release (domain/securitycontrols.ts), not by the schema.
 */
export const sql = /* sql */ `
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze',
                       'requirement.update', 'requirement.revoke',
                       'identity.create', 'credential.issue', 'identity.reactivate',
                       'oidc_binding.create', 'oidc_binding.delete'));
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_admin_step_up_organization
  CHECK (operation NOT IN ('identity.create', 'credential.issue', 'identity.reactivate',
                           'oidc_binding.create', 'oidc_binding.delete') OR organization_id IS NOT NULL);
`;
