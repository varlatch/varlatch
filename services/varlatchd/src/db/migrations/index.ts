// SPDX-License-Identifier: AGPL-3.0-or-later
import { sql as initial } from "./0001_initial.js";
import { sql as identityOrgScope } from "./0002_identity_org_scope.js";
import { sql as runtimeGrants } from "./0003_runtime_grants.js";
import { sql as signingKeys } from "./0004_signing_keys.js";
import { sql as betterAuth } from "./0005_better_auth.js";
import { sql as inviteGrants } from "./0006_invite_grants.js";
import { sql as capabilities } from "./0007_capabilities.js";
import { sql as agentRunCredentials } from "./0008_agent_run_credentials.js";
import { sql as credentialLimits } from "./0009_credential_limits.js";
import { sql as webhooks } from "./0010_webhooks.js";
import { sql as oidcBindings } from "./0011_oidc_bindings.js";
import { sql as environmentRemoval } from "./0012_environment_removal.js";
import { sql as valueRotation } from "./0013_value_rotation.js";
import { sql as rolesGroupsTeams } from "./0014_roles_groups_teams.js";
import { sql as accessEntityVersions } from "./0015_access_entity_versions.js";
import { sql as syncTargets } from "./0016_sync_targets.js";
import { sql as auditOrder } from "./0017_audit_order.js";

import { sql as backupKeys } from "./0018_backup_keys.js";
import { sql as identityLifecycle } from "./0019_identity_lifecycle.js";
import { sql as captureReadAccess } from "./0020_capture_read_access.js";
import { sql as dropEnvironmentNameMapping } from "./0021_drop_environment_name_mapping.js";
import { sql as capabilityTargets } from "./0022_capability_targets.js";
import { sql as invitationRevocation } from "./0023_invitation_revocation.js";

export interface Migration {
  id: number;
  name: string;
  sql: string;
}

/** Append-only. Never edit a shipped migration; add a new one. */
export const MIGRATIONS: Migration[] = [
  { id: 1, name: "initial", sql: initial },
  { id: 2, name: "identity_org_scope", sql: identityOrgScope },
  { id: 3, name: "runtime_grants", sql: runtimeGrants },
  { id: 4, name: "signing_keys", sql: signingKeys },
  { id: 5, name: "better_auth", sql: betterAuth },
  { id: 6, name: "invite_grants", sql: inviteGrants },
  { id: 7, name: "capabilities", sql: capabilities },
  { id: 8, name: "agent_run_credentials", sql: agentRunCredentials },
  { id: 9, name: "credential_limits", sql: credentialLimits },
  { id: 10, name: "webhooks", sql: webhooks },
  { id: 11, name: "oidc_bindings", sql: oidcBindings },
  { id: 12, name: "environment_removal", sql: environmentRemoval },
  { id: 13, name: "value_rotation", sql: valueRotation },
  { id: 14, name: "roles_groups_teams", sql: rolesGroupsTeams },
  { id: 15, name: "access_entity_versions", sql: accessEntityVersions },
  { id: 16, name: "sync_targets", sql: syncTargets },
  { id: 17, name: "audit_order", sql: auditOrder },
  { id: 18, name: "backup_keys", sql: backupKeys },
  { id: 19, name: "identity_lifecycle", sql: identityLifecycle },
  { id: 20, name: "capture_read_access", sql: captureReadAccess },
  { id: 21, name: "drop_environment_name_mapping", sql: dropEnvironmentNameMapping },
  { id: 22, name: "capability_targets", sql: capabilityTargets },
  { id: 23, name: "invitation_revocation", sql: invitationRevocation },
];
