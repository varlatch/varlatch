// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { AccessCheck } from "@varlatch/protocol";
import { accessTitle, accessTone, fixStep } from "../src/features/sync/accessCheck";
import { describeEvent, emptyResolver, segmentsText } from "../src/features/audit/describe";

const check = (over: Partial<AccessCheck>): AccessCheck => ({ status: "ok", where: "destination", message: "m", ...over });

describe("access check", () => {
  it("sends a failure back to the step that fixes it", () => {
    expect(fixStep(check({ status: "credential-rejected", where: "connection" }))).toBe(0);
    expect(fixStep(check({ status: "not-found", where: "connection" }))).toBe(0);
    expect(fixStep(check({ status: "permission-missing", where: "destination" }))).toBe(0);
    expect(fixStep(check({ status: "not-found", where: "destination" }))).toBe(1);
  });

  it("offers no step when trying again is the fix, or nothing needs fixing", () => {
    expect(fixStep(check({ status: "unreachable" }))).toBeNull();
    expect(fixStep(check({ status: "ok" }))).toBeNull();
  });

  it("reads an unreachable platform as a warning, a refusal as a problem", () => {
    expect(accessTone(check({ status: "ok" }))).toBe("success");
    expect(accessTone(check({ status: "unreachable" }))).toBe("warn");
    expect(accessTone(check({ status: "credential-rejected" }))).toBe("danger");
    expect(accessTitle(check({ status: "not-found", where: "destination" }))).toBe("Destination not found");
    expect(accessTitle(check({ status: "not-found", where: "connection" }))).toBe("Account or instance not found");
  });

  it("describes the audited check with its outcome", () => {
    const sentence = (metadata: Record<string, unknown>) =>
      segmentsText(
        describeEvent(
          { eventId: "evt_1", eventType: "sync.connection_checked", occurredAt: "2026-10-09T09:00:00Z", decision: "info", actorIdentityId: null, metadata },
          emptyResolver,
        ).segments,
      );
    expect(sentence({ platform: "coolify", baseIdentity: "https://coolify.example.com", destination: "coolify:app1", status: "ok" })).toBe(
      "checked access to Coolify coolify:app1",
    );
    expect(sentence({ platform: "github-actions", baseIdentity: "acme", status: "credential-rejected" })).toBe(
      "checked access to GitHub Actions acme: credential rejected",
    );
  });
});
