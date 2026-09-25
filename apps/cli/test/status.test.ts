// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { LocalState, ResolvedContext } from "@varlatch/context";
import { expiryState, expiryWarning, formatStatusHuman, repoStatus, serverStatus } from "../src/status.js";

const SERVER = "https://varlatch.example.com";

describe("expiryWarning (ADR-0032)", () => {
  const issuedAt = "2026-09-22T00:00:00.000Z";
  const expiresAt = "2026-09-22T12:00:00.000Z"; // 12h lifetime → warn under 2h24m left
  const cred = { token: "vlt_cli_x", issuedAt, expiresAt };

  it("stays silent while more than 20% of the lifetime remains", () => {
    expect(expiryWarning(SERVER, cred, Date.parse("2026-09-22T09:00:00Z"))).toBeNull();
  });

  it("warns proportionally, not on an absolute window", () => {
    const warning = expiryWarning(SERVER, cred, Date.parse("2026-09-22T10:30:00Z"));
    expect(warning).toMatch(/expires 2026-09-22T12:00:00.000Z/);
    expect(warning).toMatch(/varlatch login --server https:\/\/varlatch\.example\.com/);
  });

  it("reports outright expiry", () => {
    expect(expiryWarning(SERVER, cred, Date.parse("2026-09-22T13:00:00Z"))).toMatch(/expired/);
  });

  it("stays silent on pre-ADR-0032 entries and garbage timestamps", () => {
    expect(expiryWarning(SERVER, { token: "vlt_cli_x" })).toBeNull();
    expect(expiryWarning(SERVER, null)).toBeNull();
    expect(expiryWarning(SERVER, { token: "x", issuedAt: "nope", expiresAt })).toBeNull();
    expect(expiryWarning(SERVER, { token: "x", issuedAt: expiresAt, expiresAt: issuedAt })).toBeNull();
  });

  it("expiryState classifies the same windows the warning uses", () => {
    expect(expiryState(cred, Date.parse("2026-09-22T09:00:00Z"))).toBe("ok");
    expect(expiryState(cred, Date.parse("2026-09-22T10:30:00Z"))).toBe("expiring");
    expect(expiryState(cred, Date.parse("2026-09-22T13:00:00Z"))).toBe("expired");
    expect(expiryState({ token: "x" })).toBeNull();
  });

  it("serverStatus exposes expiring so consumers need not re-derive the rule", () => {
    expect(serverStatus(SERVER, cred, Date.parse("2026-09-22T09:00:00Z"))).toMatchObject({ expiring: false, expired: false });
    expect(serverStatus(SERVER, cred, Date.parse("2026-09-22T10:30:00Z"))).toMatchObject({ expiring: true, expired: false });
    expect(serverStatus(SERVER, cred, Date.parse("2026-09-22T13:00:00Z"))).toMatchObject({ expiring: false, expired: true });
  });
});

describe("status document", () => {
  const ctx: ResolvedContext = {
    server: SERVER,
    organization: "acme",
    project: "api",
    environment: "production",
    environmentSource: "local-selection",
    repoRoot: "/repo",
  };

  it("serverStatus flags expiry and tolerates metadata-free entries", () => {
    expect(serverStatus(SERVER, { token: "x" })).toMatchObject({
      server: SERVER,
      expiresAt: null,
      expired: null,
      expiring: null,
      credentialId: null,
    });
    expect(serverStatus(SERVER, { token: "x", expiresAt: "2000-01-01T00:00:00Z" }).expired).toBe(true);
  });

  it("repoStatus surfaces the cached tier only for the locally selected environment", () => {
    const local: LocalState = {
      selectedEnvironment: "production",
      selectedTier: "production",
      tierCachedAt: "2026-09-22T08:00:00.000Z",
    };
    expect(repoStatus(ctx, local)).toMatchObject({
      tier: "production",
      tierCachedAt: "2026-09-22T08:00:00.000Z",
    });
    // A -e/VARLATCH_ENV override selects a different environment: its tier is unknown.
    expect(repoStatus({ ...ctx, environment: "staging", environmentSource: "flag" }, local).tier).toBeNull();
    expect(repoStatus(ctx, {}).tier).toBeNull();
  });

  it("human format covers empty store, expiry, and repo context", () => {
    expect(formatStatusHuman({ version: 1, servers: [], repo: null })).toMatch(/No stored credentials/);
    const doc = {
      version: 1 as const,
      servers: [
        {
          ...serverStatus(SERVER, { token: "x", expiresAt: "2000-01-01T00:00:00Z" }),
          probe: { state: "invalid" as const, detail: "UNAUTHENTICATED" },
        },
      ],
      repo: repoStatus(ctx, { selectedEnvironment: "production", selectedTier: "production" }),
    };
    const text = formatStatusHuman(doc);
    expect(text).toMatch(/EXPIRED/);
    expect(text).toMatch(/probe: invalid \(UNAUTHENTICATED\)/);
    expect(text).toMatch(/production \(local-selection, tier production\)/);
  });
});
