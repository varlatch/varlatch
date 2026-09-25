// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { VarlatchApiError } from "@varlatch/sdk";
import { replacedCredential, revokeStoredCredential } from "../src/revoke.js";

describe("revokeStoredCredential", () => {
  const cred = { token: "vlt_cli_old", credentialId: "cred_1" };

  it("revokes by the stored credential id", async () => {
    const calls: string[] = [];
    expect(await revokeStoredCredential(cred, async (id) => calls.push(id))).toBeNull();
    expect(calls).toEqual(["cred_1"]);
  });

  it("reports why revocation did not happen instead of throwing", async () => {
    expect(await revokeStoredCredential({ token: "x" }, async () => {})).toMatch(/no credential id/);
    const apiError = new VarlatchApiError(401, { code: "UNAUTHENTICATED", message: "nope", requestId: "r" } as never);
    expect(await revokeStoredCredential(cred, async () => { throw apiError; })).toBe("UNAUTHENTICATED");
    expect(await revokeStoredCredential(cred, async () => { throw new Error("ECONNREFUSED"); })).toBe("ECONNREFUSED");
  });
});

describe("replacedCredential (login renew path)", () => {
  const now = Date.parse("2026-09-22T10:00:00Z");
  const previous = { token: "vlt_cli_old", credentialId: "cred_1", expiresAt: "2026-09-22T12:00:00Z" };

  it("returns a still-live previous entry that the new token replaces", () => {
    expect(replacedCredential(previous, "vlt_cli_new", now)).toBe(previous);
    // No recorded expiry: may be live, so it is still a revocation target.
    expect(replacedCredential({ token: "vlt_cli_old" }, "vlt_cli_new", now)).toEqual({ token: "vlt_cli_old" });
  });

  it("skips first logins, same-token re-logins, and already-expired entries", () => {
    expect(replacedCredential(null, "vlt_cli_new", now)).toBeNull();
    expect(replacedCredential(previous, "vlt_cli_old", now)).toBeNull();
    expect(replacedCredential({ ...previous, expiresAt: "2026-09-22T09:00:00Z" }, "vlt_cli_new", now)).toBeNull();
  });
});
