// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { backendOf } from "./backend";

describe("the clients /v1/meta chooses", () => {
  it("keeps Better Auth and Convex for the TypeScript server", () => {
    expect(backendOf(["auth.device", "identity.whoami"])).toEqual({ session: "better-auth", realtime: "convex" });
    expect(backendOf(null)).toEqual({ session: "better-auth", realtime: "convex" });
    expect(backendOf(undefined)).toEqual({ session: "better-auth", realtime: "convex" });
  });
  it("takes the Go server's own session, and no Convex client, with auth.session", () => {
    expect(backendOf(["identity.whoami", "auth.session"])).toEqual({ session: "varlatchd", realtime: "none" });
  });
});
