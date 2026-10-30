// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { AUDIT_EVENT_TYPES } from "../src/audit/events.js";
import { NON_TRIGGERING_EVENTS } from "../src/domain/syncdelivery.js";

/**
 * Which audit events mark Sync Targets for a converge (#59). Every type in
 * AUDIT_EVENT_TYPES, which AuditEventInput is typed with, is classified
 * here: one that names an environment (or, for contract events, a
 * project) marks its Targets unless it is in NON_TRIGGERING_EVENTS. A new
 * event type fails this test until it is put on one side on purpose: a
 * read must not start converging Targets again, and a write must not stop.
 */

const TRIGGERING = [
  "audit_tombstone.reader_removed",
  "bootstrap.completed",
  "group.created",
  "group.deleted",
  "group.member_added",
  "group.member_removed",
  "group.updated",
  "installation.custody_attested",
  "installation.restored",
  "invitation.accepted",
  "recovery.completed",
  "reenrollment.completed",
  "team.created",
  "team.deleted",
  "team.member_added",
  "team.member_removed",
  "team.updated",
  "authentication.device_approved",
  "authentication.device_code_locked",
  "authentication.device_code_rejected",
  "authentication.device_collected",
  "authentication.device_denied",
  "authentication.device_requested",
  "authentication.failed",
  "authentication.passkey_enrollment_started",
  "bootstrap.grant_issued",
  "contract.activated",
  "contract.revision_pushed",
  "credential.issued",
  "credential.revoked",
  "environment.created",
  "environment.deleted",
  "grant.created",
  "grant.revoked",
  "identity.created",
  "identity.profile_updated",
  "identity.reactivated",
  "identity.renamed",
  "identity.retired",
  "installation.initialized",
  "installation.public_url_changed",
  "invitation.issued",
  "invitation.revoked",
  "membership.removed",
  "membership.role_changed",
  "oidc_binding.created",
  "oidc_binding.revoked",
  "organization.created",
  "organization.deleted",
  "organization.deletion_approved",
  "organization.deletion_cancelled",
  "organization.deletion_scheduled",
  "organization.renamed",
  "project.created",
  "project.deleted",
  "project.renamed",
  "recovery.grant_issued",
  "recovery.identity_reenabled",
  "reenrollment.grant_issued",
  "requirement.created",
  "requirement.revoked",
  "requirement.updated",
  "role.created",
  "role.deleted",
  "role.updated",
  "setup.grant_rejected",
  "team.project_added",
  "team.project_removed",
  "value.deleted",
  "value.rotation_completed",
  "value.rotation_started",
  "value.written",
  "webhook.created",
  "webhook.revoked",
  "webhook.updated",
];

describe("the sync trigger scan's event classification", () => {
  // sync.* events never reach the scan: delivery never triggers delivery.
  const scanned = AUDIT_EVENT_TYPES.filter((type) => !type.startsWith("sync.")).sort();

  it("puts every registered event type on one side, and only registered ones", () => {
    expect([...TRIGGERING, ...NON_TRIGGERING_EVENTS].sort()).toEqual(scanned);
    for (const type of NON_TRIGGERING_EVENTS) expect(TRIGGERING, type).not.toContain(type);
  });

  it("never lets a write go untriggered", () => {
    for (const type of NON_TRIGGERING_EVENTS) {
      expect(type, type).toMatch(/\.(disclosed|validated|issued|exercised|revoked|denied|revocation_confirmed)$/);
      expect(type.startsWith("value.") && !/\.(disclosed|validated)$/.test(type), type).toBe(false);
    }
  });
});
