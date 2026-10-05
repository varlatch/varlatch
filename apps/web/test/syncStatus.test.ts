// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { PlatformConnection, SyncTarget } from "@varlatch/protocol";
import {
  connectionHealth,
  isCredentialError,
  mappingSummary,
  targetDestination,
  targetStatus,
} from "../src/features/sync/status";

const target = (over: Partial<SyncTarget>): SyncTarget => ({
  id: "snt_1",
  organizationId: "org_1",
  projectId: "prj_1",
  environmentId: "env_1",
  connectionId: "pcn_1",
  destination: { repo: "api", environment: "production" },
  mapping: { kind: "wildcard" },
  removeOrphans: false,
  redeploy: false,
  state: "active",
  disabledReason: null,
  failureCount: 0,
  needsSync: false,
  lastAttemptAt: "2026-10-02T09:00:00Z",
  lastResult: "ok",
  createdAt: "2026-10-01T09:00:00Z",
  version: 1,
  updatedAt: null,
  ...over,
});

const github: PlatformConnection = {
  id: "pcn_1",
  organizationId: "org_1",
  platform: "github-actions",
  baseIdentity: "acme-org",
  name: "GitHub",
  createdAt: "2026-09-01T00:00:00Z",
  version: 1,
  updatedAt: null,
};

describe("targetStatus", () => {
  it("is in sync after a clean push", () => {
    expect(targetStatus(target({})).label).toBe("In sync");
  });

  it("is in sync when a pass finds nothing to change", () => {
    // varlatchd records "converged", not "ok", when the destination already matches.
    expect(targetStatus(target({ lastResult: "converged" }))).toMatchObject({ tone: "ok", label: "In sync" });
  });

  it("warns, without failing, when the values landed but the redeploy did not", () => {
    expect(targetStatus(target({ lastResult: "ok; redeploy failed (Coolify deploy failed (403))" }))).toMatchObject({
      tone: "warn",
      label: "Redeploy failed",
      error: "Coolify deploy failed (403)",
    });
  });

  it("offers a credential replacement when the platform refuses it", () => {
    const s = targetStatus(target({ failureCount: 3, lastResult: "AdapterError: GitHub public key fetch failed (401)" }));
    expect(s).toMatchObject({ tone: "error", label: "Failing", detail: "3 attempts", fix: "replace-credential" });
    expect(s.error).toBe("GitHub public key fetch failed (401)");
  });

  it("offers a retry for other failures", () => {
    expect(targetStatus(target({ failureCount: 1, lastResult: "TypeError: fetch failed" })).fix).toBe("retry");
  });

  it("reports paused and stopped targets", () => {
    expect(targetStatus(target({ state: "paused" })).label).toBe("Paused");
    expect(targetStatus(target({ state: "disabled", disabledReason: "connection-revoked" }))).toMatchObject({
      label: "Stopped",
      fix: "reconnect",
    });
  });

  it("asks for re-affirmation when a mapped item became a secret", () => {
    expect(targetStatus(target({ lastResult: "degraded: re-affirmation required for API_KEY" })).fix).toBe("reaffirm");
  });

  it("waits for the first push", () => {
    expect(targetStatus(target({ lastAttemptAt: null, lastResult: null, needsSync: true })).label).toBe("Waiting for first push");
  });
});

describe("destinations and mappings", () => {
  it("joins the GitHub owner and repository", () => {
    expect(targetDestination(target({}), github)).toEqual({ primary: "acme-org/api", qualifier: "environment production" });
  });

  it("uses the deployment host for Convex", () => {
    expect(
      targetDestination(target({ destination: {} }), { ...github, platform: "convex", baseIdentity: "https://happy-animal-123.convex.cloud" }),
    ).toEqual({ primary: "happy-animal-123.convex.cloud" });
  });

  it("summarizes mappings", () => {
    expect(mappingSummary(target({ mapping: { kind: "wildcard", exclude: ["CONVEX_*"] } }))).toMatchObject({
      label: "All items except",
      excluded: ["CONVEX_*"],
    });
    expect(
      mappingSummary(target({ mapping: { kind: "explicit", items: [{ name: "A", secretAffirmed: false }, { name: "B", rename: "C", secretAffirmed: false }] } })),
    ).toEqual({ label: "Explicit list · 2 items", renames: 1 });
  });
});

describe("connectionHealth", () => {
  it("is healthy when every live target is in sync", () => {
    expect(connectionHealth([target({}), target({ state: "paused", failureCount: 4, lastResult: "401" })]).label).toBe("Healthy");
  });

  it("is healthy when passes find nothing to change", () => {
    expect(connectionHealth([target({ lastResult: "converged" }), target({ lastResult: "converged" })])).toMatchObject({
      tone: "ok",
      label: "Healthy",
    });
  });

  it("counts failed targets only", () => {
    expect(connectionHealth([target({ lastResult: "converged" }), target({ failureCount: 1, lastResult: "TypeError: fetch failed" })]).label).toBe(
      "1 target failing",
    );
  });

  it("warns about a failed redeploy", () => {
    expect(connectionHealth([target({ lastResult: "converged" }), target({ lastResult: "ok; redeploy failed (Coolify deploy failed (500))" })])).toMatchObject({
      tone: "warn",
      label: "1 redeploy failed",
    });
  });

  it("reports a rejected credential", () => {
    expect(connectionHealth([target({ failureCount: 2, lastResult: "401 Unauthorized" })])).toMatchObject({
      tone: "error",
      credentialRejected: true,
    });
  });

  it("is unused without targets", () => {
    expect(connectionHealth([]).label).toBe("Not used yet");
  });

  it("recognizes credential errors", () => {
    expect(isCredentialError("Bad credentials")).toBe(true);
    expect(isCredentialError("fetch failed")).toBe(false);
  });
});
