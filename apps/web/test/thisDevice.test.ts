// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from "vitest";
import type { TailnetConnection } from "../src/lib/tailnetConnection";

// The connection module loads the session, which needs a browser; these tests need neither.
vi.mock("../src/lib/session", () => ({ useSession: () => ({}) }));
const { deviceOutcome, tailnetSuggestion } = await import("../src/features/access/thisDevice");

/**
 * "This device" uses only a Connect answer newer than the click, adds only
 * the verified node ID, and never changes the tailnet; the suggestion for a
 * new requirement's tailnet prefers the verified device, then the endpoint.
 */

const ENDPOINT = "https://varlatch.example.ts.net:8688";
const device = { recognized: true, tailnet: "example.ts.net", nodeId: "nDev42CNTRL", nodeName: "laptop", tags: ["tag:x"], userLogin: "bob@example.com" };
const connected = (checkedAt: number, d: Partial<typeof device> = {}): TailnetConnection => ({ status: "connected", endpoint: ENDPOINT, device: { ...device, ...d }, checkedAt });

describe("deviceOutcome", () => {
  it("uses only an answer newer than the request", () => {
    expect(deviceOutcome(connected(99), 100, "example.ts.net")).toEqual({ kind: "waiting" });
    expect(deviceOutcome({ status: "connecting", endpoint: ENDPOINT }, 100, "example.ts.net")).toEqual({ kind: "waiting" });
    expect(deviceOutcome({ status: "idle", endpoint: ENDPOINT }, 100, "example.ts.net")).toEqual({ kind: "waiting" });
    expect(deviceOutcome({ status: "unreachable", endpoint: ENDPOINT, blockedByPolicy: false, checkedAt: 99 }, 100, "example.ts.net")).toEqual({ kind: "waiting" });
    expect(deviceOutcome(connected(100), 100, "example.ts.net")).toEqual({ kind: "add", nodeId: "nDev42CNTRL", nodeName: "laptop" });
  });

  it("a failed Connect adds nothing, and says why", () => {
    const unreachable = deviceOutcome({ status: "unreachable", endpoint: ENDPOINT, blockedByPolicy: false, checkedAt: 200 }, 100, "example.ts.net");
    expect(unreachable).toMatchObject({ kind: "failed", message: expect.stringContaining("did not answer") });
    const blocked = deviceOutcome({ status: "unreachable", endpoint: ENDPOINT, blockedByPolicy: true, checkedAt: 200 }, 100, "example.ts.net");
    expect(blocked).toMatchObject({ kind: "failed", message: expect.stringContaining("security policy") });
    const shared = deviceOutcome({ status: "unrecognized", endpoint: ENDPOINT, reason: "shared", checkedAt: 200 }, 100, "example.ts.net");
    expect(shared).toMatchObject({ kind: "failed", message: expect.stringContaining("shared devices are refused") });
    expect(deviceOutcome({ status: "unavailable" }, 100, "example.ts.net")).toMatchObject({ kind: "failed" });
  });

  it("refuses an answer without a usable node ID", () => {
    expect(deviceOutcome(connected(200, { nodeId: "" }), 100, "example.ts.net")).toMatchObject({ kind: "failed" });
    expect(deviceOutcome(connected(200, { nodeId: "n bad" }), 100, "example.ts.net")).toMatchObject({ kind: "failed" });
    expect(deviceOutcome(connected(200, { recognized: false }), 100, "example.ts.net")).toMatchObject({ kind: "failed" });
  });

  it("a device on another tailnet, compared exactly, is not added", () => {
    expect(deviceOutcome(connected(200), 100, "other.ts.net")).toEqual({ kind: "other-tailnet", nodeId: "nDev42CNTRL", nodeName: "laptop", deviceTailnet: "example.ts.net" });
    expect(deviceOutcome(connected(200), 100, "EXAMPLE.TS.NET")).toMatchObject({ kind: "other-tailnet" });
    expect(deviceOutcome(connected(200), 100, "")).toMatchObject({ kind: "other-tailnet" });
  });
});

describe("tailnetSuggestion", () => {
  it("prefers the verified device's tailnet, then the endpoint's host, then nothing", () => {
    expect(tailnetSuggestion(connected(1, { tailnet: "corp.ts.net" }))).toEqual({ tailnet: "corp.ts.net", source: "device" });
    expect(tailnetSuggestion({ status: "idle", endpoint: ENDPOINT })).toEqual({ tailnet: "example.ts.net", source: "endpoint" });
    expect(tailnetSuggestion({ status: "unrecognized", endpoint: ENDPOINT, reason: "other-tailnet", checkedAt: 1 })).toEqual({ tailnet: "example.ts.net", source: "endpoint" });
    expect(tailnetSuggestion({ status: "unavailable" })).toBeNull();
    expect(tailnetSuggestion({ status: "idle", endpoint: "https://localhost:8688" })).toBeNull();
  });
});
