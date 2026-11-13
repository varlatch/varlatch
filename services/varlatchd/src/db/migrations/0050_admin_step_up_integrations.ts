// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * admin-step-up for integrations (ADR-0054 step 4.8).
 *
 * 1. Approval Intents gain the operations `webhook.create`,
 *    `webhook.update`, `webhook.delete`, `connection.create`,
 *    `connection.replace_credential`, `connection.delete`,
 *    `github_app.register`, `github_app.import`, `github_app.replace_key`
 *    and `github_app.remove`, all bound to an Organization.
 *
 * 2. GitHub App registration is staged (amendment D). A registration gains
 *    a stable id, its target from the start on, and the conversion GitHub
 *    hands over is stored on it as pending until it is attached, discarded,
 *    refused or expires:
 *    - the App's id, slug, client id and owner;
 *    - its private key, wrapped under the Organization KEK and bound to the
 *      registration id (`pending_key_envelope`);
 *    - when it was stored, and when it expires: one hour later.
 *    Pending material is written once and never updated: a trigger refuses
 *    any change to it, except the deletion of the key when the registration
 *    ends (`ended_at`, `end_reason`). A key exists only while the
 *    registration is pending.
 *
 *    Registrations in flight at the upgrade get an id derived from their
 *    state hash; none of them has a conversion yet. The server names new
 *    ones itself; the column default covers any other insert.
 *
 * Whether admin-step-up can be set to `enforce` is decided by the release
 * (domain/securitycontrols.ts), not by the schema.
 */
const ADMIN_STEP_UP = `'identity.create', 'credential.issue', 'identity.reactivate',
                       'oidc_binding.create', 'oidc_binding.delete',
                       'grant.create', 'grant.replace', 'grant.revoke',
                       'role.create', 'role.update', 'role.delete',
                       'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
                       'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
                       'team.project_add', 'team.project_remove',
                       'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
                       'webhook.create', 'webhook.update', 'webhook.delete',
                       'connection.create', 'connection.replace_credential', 'connection.delete',
                       'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove'`;

export const sql = /* sql */ `
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_operation_check;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_operation_check
  CHECK (operation IN ('security_control.change', 'passkey.remove', 'organization.unfreeze',
                       'requirement.update', 'requirement.revoke',
                       ${ADMIN_STEP_UP}));
ALTER TABLE approval_intents DROP CONSTRAINT approval_intents_admin_step_up_organization;
ALTER TABLE approval_intents ADD CONSTRAINT approval_intents_admin_step_up_organization
  CHECK (operation NOT IN (${ADMIN_STEP_UP}) OR organization_id IS NOT NULL);

ALTER TABLE github_app_registrations ADD COLUMN id text;
UPDATE github_app_registrations SET id = 'ghr_' || substr(md5(state_hash), 1, 26);
ALTER TABLE github_app_registrations ALTER COLUMN id SET NOT NULL;
ALTER TABLE github_app_registrations ALTER COLUMN id SET DEFAULT ('ghr_' || substr(md5(random()::text || clock_timestamp()::text), 1, 26));
ALTER TABLE github_app_registrations ADD CONSTRAINT github_app_registrations_id_key UNIQUE (id);

ALTER TABLE github_app_registrations
  ADD COLUMN converted_at timestamptz,
  ADD COLUMN pending_expires_at timestamptz,
  ADD COLUMN pending_github_app_id bigint CHECK (pending_github_app_id > 0),
  ADD COLUMN pending_slug text,
  ADD COLUMN pending_client_id text,
  ADD COLUMN pending_owner_login text,
  ADD COLUMN pending_owner_id bigint CHECK (pending_owner_id > 0),
  ADD COLUMN pending_owner_type text CHECK (pending_owner_type IN ('organization', 'user')),
  ADD COLUMN pending_key_envelope jsonb,
  ADD COLUMN ended_at timestamptz,
  ADD COLUMN end_reason text CHECK (end_reason IN ('attached', 'discarded', 'expired', 'refused'));

ALTER TABLE github_app_registrations ADD CONSTRAINT github_app_registrations_conversion_complete
  CHECK (converted_at IS NULL OR (
    consumed_at IS NOT NULL AND pending_expires_at > converted_at AND pending_github_app_id IS NOT NULL
    AND pending_slug IS NOT NULL AND pending_client_id IS NOT NULL AND pending_owner_login IS NOT NULL
    AND pending_owner_id IS NOT NULL AND pending_owner_type IS NOT NULL));
ALTER TABLE github_app_registrations ADD CONSTRAINT github_app_registrations_ended_after_conversion
  CHECK ((ended_at IS NULL) = (end_reason IS NULL) AND (ended_at IS NULL OR converted_at IS NOT NULL));
ALTER TABLE github_app_registrations ADD CONSTRAINT github_app_registrations_key_while_pending
  CHECK ((pending_key_envelope IS NOT NULL) = (converted_at IS NOT NULL AND ended_at IS NULL));

CREATE INDEX github_app_registrations_pending_expiry ON github_app_registrations(pending_expires_at)
  WHERE converted_at IS NOT NULL AND ended_at IS NULL;

CREATE FUNCTION github_app_registrations_pending_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.converted_at IS NOT NULL AND (
       NEW.id IS DISTINCT FROM OLD.id OR NEW.state_hash IS DISTINCT FROM OLD.state_hash
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.actor_identity_id IS DISTINCT FROM OLD.actor_identity_id
       OR NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.converted_at IS DISTINCT FROM OLD.converted_at OR NEW.pending_expires_at IS DISTINCT FROM OLD.pending_expires_at
       OR NEW.pending_github_app_id IS DISTINCT FROM OLD.pending_github_app_id OR NEW.pending_slug IS DISTINCT FROM OLD.pending_slug
       OR NEW.pending_client_id IS DISTINCT FROM OLD.pending_client_id OR NEW.pending_owner_login IS DISTINCT FROM OLD.pending_owner_login
       OR NEW.pending_owner_id IS DISTINCT FROM OLD.pending_owner_id OR NEW.pending_owner_type IS DISTINCT FROM OLD.pending_owner_type
       OR (NEW.pending_key_envelope IS NOT NULL AND NEW.pending_key_envelope IS DISTINCT FROM OLD.pending_key_envelope)
       OR (OLD.ended_at IS NOT NULL AND (NEW.ended_at IS DISTINCT FROM OLD.ended_at OR NEW.end_reason IS DISTINCT FROM OLD.end_reason))
     ) THEN
    RAISE EXCEPTION 'a GitHub App registration''s pending conversion is written once and never updated'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER github_app_registrations_pending_once BEFORE UPDATE ON github_app_registrations
  FOR EACH ROW EXECUTE FUNCTION github_app_registrations_pending_once();
`;
