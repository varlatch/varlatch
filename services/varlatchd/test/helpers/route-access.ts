// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Where each /v1/organizations/:org route decides passkey-verification
 * (ADR-0054 Decision 7, src/domain/requestaccess.ts): its checkpoint, after
 * the route's authorized existence checks and before its first protected
 * effect.
 *
 * - `read`: an effect-free metadata read, decided once it looked everything
 *   up, before its answer leaves (http/organization.ts
 *   settleOrganizationAccess). Nothing before that point writes, audits,
 *   decrypts or calls out; the lock-order harness fails a write before the
 *   checkpoint, and assertOrganizationAccessChecked a disclosure audit,
 *   decryption or outbound call.
 * - `stream`: a read whose answer streams: decided before the stream starts.
 * - `snapshot`: a retrieval, validation, disclosure or Capability exercise,
 *   decided inside its read-only snapshot, after it captured what exists and
 *   before any disclosure audit or decryption; nothing is read again.
 * - `transaction`: a write, decided under the Organization row lock in the
 *   transaction that writes (lockLiveScope, prepareProtectedOperation,
 *   createApproval, or the writer's own call after a lookup that follows
 *   the lock).
 * - `external`: an operation that decrypts or uses a credential, calls out
 *   or spends a one-use artifact, in one transaction holding the
 *   Organization row from its checkpoint (after its local lookups) until
 *   the effect and the write that goes with it are done (liveness.ts
 *   withExternalEffect). Outbound policy DNS checks are validation, before.
 *
 * test/organization-entry.test.ts fails for a route missing here or listed
 * but gone; test/passkey-verification.test.ts checks at runtime that the
 * `read` routes, and only they, are decided at their answer.
 */
export type AccessCheckpoint = "read" | "stream" | "snapshot" | "transaction" | "external";

export const ROUTE_ACCESS: Record<string, AccessCheckpoint> = {
  "GET /v1/organizations/:org": "read",
  "GET /v1/organizations/:org/me/permissions": "read",
  "PATCH /v1/organizations/:org": "transaction",
  "GET /v1/organizations/:org/deletion": "read",
  "POST /v1/organizations/:org/deletion": "transaction",
  "POST /v1/organizations/:org/deletion/:deletion/approve": "transaction",
  "POST /v1/organizations/:org/deletion/:deletion/cancel": "transaction",
  "GET /v1/organizations/:org/incident-freeze": "read",
  "POST /v1/organizations/:org/incident-freeze": "transaction",
  "POST /v1/organizations/:org/incident-freeze/:freeze/lift": "transaction",
  "GET /v1/organizations/:org/config-items": "read",
  "GET /v1/organizations/:org/projects": "read",
  "POST /v1/organizations/:org/projects": "transaction",
  "GET /v1/organizations/:org/projects/:project": "read",
  "PATCH /v1/organizations/:org/projects/:project": "transaction",
  "DELETE /v1/organizations/:org/projects/:project": "transaction",
  "GET /v1/organizations/:org/projects/:project/environments": "read",
  "POST /v1/organizations/:org/projects/:project/environments": "transaction",
  "GET /v1/organizations/:org/projects/:project/environments/:environment": "read",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/validate": "snapshot",
  "PUT /v1/organizations/:org/projects/:project/environments/:environment/values/:item": "transaction",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/values/:item": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/values/:item/rotations/complete": "transaction",
  "GET /v1/organizations/:org/projects/:project/environments/:environment/effective-configuration": "snapshot",
  // An export under admin-step-up's enforce is decided in its snapshot too,
  // then again in its phase-2 transaction under the Organization lock,
  // before its approval is consumed or an intent created
  // (domain/exportstepup.ts).
  "POST /v1/organizations/:org/projects/:project/environments/:environment/disclosures": "snapshot",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/retrievals": "snapshot",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities": "transaction",
  "GET /v1/organizations/:org/projects/:project/environments/:environment/capabilities": "read",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/capabilities/:capability/exercises": "snapshot",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/changes": "transaction",
  "GET /v1/organizations/:org/projects/:project/contract": "read",
  "POST /v1/organizations/:org/projects/:project/contract/revisions": "transaction",
  "GET /v1/organizations/:org/projects/:project/contract/revisions/:revision": "read",
  "POST /v1/organizations/:org/projects/:project/contract/revisions/:revision/activate": "transaction",
  "GET /v1/organizations/:org/identities": "read",
  "POST /v1/organizations/:org/identities": "transaction",
  "POST /v1/organizations/:org/identities/:identity/credentials": "transaction",
  "DELETE /v1/organizations/:org/identities/:identity/credentials/:credential": "transaction",
  "GET /v1/organizations/:org/identities/:identity/credentials": "read",
  "GET /v1/organizations/:org/security/credential-review": "read",
  "POST /v1/organizations/:org/identities/:identity/retire": "transaction",
  "POST /v1/organizations/:org/identities/:identity/reactivate": "transaction",
  "GET /v1/organizations/:org/security/controls": "read",
  "GET /v1/organizations/:org/security/control-report": "read",
  "GET /v1/organizations/:org/security/approval-keys": "read",
  "GET /v1/organizations/:org/security/refused-destinations": "read",
  "PATCH /v1/organizations/:org/security/controls/:control": "transaction",
  "GET /v1/organizations/:org/identities/:identity/reach": "read",
  "PATCH /v1/organizations/:org/identities/:identity": "transaction",
  "POST /v1/organizations/:org/identities/:identity/oidc-bindings": "transaction",
  "GET /v1/organizations/:org/identities/:identity/oidc-bindings": "read",
  "DELETE /v1/organizations/:org/identities/:identity/oidc-bindings/:binding": "transaction",
  "GET /v1/organizations/:org/members/:member/review": "read",
  "DELETE /v1/organizations/:org/members/:member": "transaction",
  "PATCH /v1/organizations/:org/members/:member": "transaction",
  "GET /v1/organizations/:org/members/:member/exposure": "read",
  "POST /v1/organizations/:org/members/:member/exposure/confirmations": "transaction",
  "POST /v1/organizations/:org/invitations": "transaction",
  "GET /v1/organizations/:org/invitations": "read",
  "DELETE /v1/organizations/:org/invitations/:invitation": "transaction",
  "GET /v1/organizations/:org/grants": "read",
  "POST /v1/organizations/:org/grants": "transaction",
  "DELETE /v1/organizations/:org/grants/:grant": "transaction",
  "POST /v1/organizations/:org/grants/:grant/replace": "transaction",
  "GET /v1/organizations/:org/roles": "read",
  "POST /v1/organizations/:org/roles": "transaction",
  "PATCH /v1/organizations/:org/roles/:role": "transaction",
  "DELETE /v1/organizations/:org/roles/:role": "transaction",
  "GET /v1/organizations/:org/groups": "read",
  "POST /v1/organizations/:org/groups": "transaction",
  "PATCH /v1/organizations/:org/groups/:group": "transaction",
  "DELETE /v1/organizations/:org/groups/:group": "transaction",
  "GET /v1/organizations/:org/groups/:group/members": "read",
  "POST /v1/organizations/:org/groups/:group/members": "transaction",
  "DELETE /v1/organizations/:org/groups/:group/members/:identity": "transaction",
  "GET /v1/organizations/:org/teams": "read",
  "POST /v1/organizations/:org/teams": "transaction",
  "PATCH /v1/organizations/:org/teams/:team": "transaction",
  "DELETE /v1/organizations/:org/teams/:team": "transaction",
  "GET /v1/organizations/:org/teams/:team/members": "read",
  "POST /v1/organizations/:org/teams/:team/members": "transaction",
  "DELETE /v1/organizations/:org/teams/:team/members/:identity": "transaction",
  "GET /v1/organizations/:org/teams/:team/projects": "read",
  "POST /v1/organizations/:org/teams/:team/projects": "transaction",
  "DELETE /v1/organizations/:org/teams/:team/projects/:project": "transaction",
  "GET /v1/organizations/:org/requirements": "read",
  "POST /v1/organizations/:org/requirements": "transaction",
  "PATCH /v1/organizations/:org/requirements/:requirement": "transaction",
  "DELETE /v1/organizations/:org/requirements/:requirement": "transaction",
  "POST /v1/organizations/:org/webhooks": "transaction",
  "GET /v1/organizations/:org/webhooks": "read",
  "PATCH /v1/organizations/:org/webhooks/:webhook": "transaction",
  "DELETE /v1/organizations/:org/webhooks/:webhook": "transaction",
  "GET /v1/organizations/:org/platform-connections": "read",
  "POST /v1/organizations/:org/platform-connections": "external",
  "POST /v1/organizations/:org/platform-connections/check": "external",
  "POST /v1/organizations/:org/platform-connections/destinations": "external",
  "GET /v1/organizations/:org/platform-connections/:connection": "read",
  "POST /v1/organizations/:org/platform-connections/:connection/credential": "transaction",
  "DELETE /v1/organizations/:org/platform-connections/:connection": "transaction",
  "GET /v1/organizations/:org/github-app": "read",
  "POST /v1/organizations/:org/github-app/registrations": "transaction",
  "POST /v1/organizations/:org/github-app/registrations/complete": "external",
  // A pending registration's attachment (ADR-0054 amendment D): a write in
  // one transaction through prepareProtectedOperation, which decides after
  // finding the registration; the pending key is decrypted only after that
  // checkpoint, in the same transaction. It calls nothing outside Varlatch.
  "POST /v1/organizations/:org/github-app/registrations/:registration/attach": "transaction",
  // Discarding one: a write, decided after the registration is found.
  "DELETE /v1/organizations/:org/github-app/registrations/:registration": "transaction",
  "POST /v1/organizations/:org/github-app/import": "external",
  "POST /v1/organizations/:org/github-app/key": "external",
  "DELETE /v1/organizations/:org/github-app": "transaction",
  "GET /v1/organizations/:org/github-app/installations": "external",
  "GET /v1/organizations/:org/sync-targets": "read",
  "GET /v1/organizations/:org/projects/:project/environments/:environment/sync-targets": "read",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets": "transaction",
  "GET /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": "read",
  "PATCH /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/push": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/pause": "transaction",
  "POST /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target/resume": "transaction",
  "DELETE /v1/organizations/:org/projects/:project/environments/:environment/sync-targets/:target": "transaction",
  "GET /v1/organizations/:org/audit-events": "read",
  "GET /v1/organizations/:org/audit-events/export": "stream",
};
