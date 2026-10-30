// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { NON_TRIGGERING_EVENTS } from "../src/domain/syncdelivery.js";

/**
 * Which audit events mark Sync Targets for a converge (#59). Every event
 * type varlatchd records is classified here: one that names an environment
 * (or, for contract events, a project) marks its Targets unless it is in
 * NON_TRIGGERING_EVENTS. A new event type fails this test until it is put
 * on one side on purpose: a read must not start converging Targets again,
 * and a write must not stop.
 */

const TRIGGERING = [
  "audit_tombstone.reader_removed",
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

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (path.endsWith(".ts")) out.push(path);
  }
  return out;
}

describe("the sync trigger scan's event classification", () => {
  const recorded = new Set<string>();
  for (const file of sources(fileURLToPath(new URL("../src", import.meta.url)))) {
    for (const match of readFileSync(file, "utf8").matchAll(/eventType:\s*"([a-z_]+\.[a-z_.]+)"/g)) recorded.add(match[1]!);
  }
  // sync.* events never reach the scan: delivery never triggers delivery.
  const scanned = [...recorded].filter((type) => !type.startsWith("sync.")).sort();

  it("puts every recorded event type on one side, and only recorded ones", () => {
    expect(scanned.length).toBeGreaterThan(50);
    const classified = [...TRIGGERING, ...NON_TRIGGERING_EVENTS].sort();
    expect(scanned).toEqual(classified);
    for (const type of NON_TRIGGERING_EVENTS) expect(TRIGGERING, type).not.toContain(type);
  });

  it("never lets a write go untriggered", () => {
    for (const type of NON_TRIGGERING_EVENTS) {
      expect(type, type).toMatch(/\.(disclosed|validated|issued|exercised|revoked|denied|revocation_confirmed)$/);
      expect(type.startsWith("value.") && !type.endsWith(".disclosed"), type).toBe(false);
    }
  });
});
