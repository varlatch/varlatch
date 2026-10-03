// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { DeviceSignInRedirectError, VarlatchApiError, VarlatchClient } from "../src/index.js";

/** The CLI's device sign-in calls: one request each, no redirect followed, answers mapped to states. */
function client(response: () => Response) {
  const inits: RequestInit[] = [];
  const fetchImpl: typeof fetch = async (_input, init) => {
    inits.push(init ?? {});
    return response();
  };
  return { inits, client: new VarlatchClient({ server: "https://v.example", fetch: fetchImpl, userAgent: "varlatch-cli/0.14.0 (linux; x64)" }) };
}
const error = (status: number, code: string, details?: Record<string, unknown>) => () =>
  new Response(JSON.stringify({ error: { code, message: code, requestId: "req_1", ...(details ? { details } : {}) } }), { status });

describe("device sign-in", () => {
  it("never follows a redirect, sends no bearer, and passes the abort signal", async () => {
    const { inits, client: c } = client(() => new Response(null, { status: 307, headers: { Location: "http://evil.example/token" } }));
    const signal = AbortSignal.timeout(1000);
    const thrown = await c.pollDeviceSignIn("dc", { signal }).catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(DeviceSignInRedirectError);
    expect(thrown).toMatchObject({ status: 307, location: "http://evil.example/token" });
    expect(inits[0]).toMatchObject({ method: "POST", redirect: "manual", signal });
    expect(inits[0]!.headers).not.toHaveProperty("Authorization");
    expect(JSON.parse(String(inits[0]!.body))).toEqual({ deviceCode: "dc" });
    await expect(client(() => new Response(null, { status: 308 })).client.startDeviceSignIn()).rejects.toBeInstanceOf(DeviceSignInRedirectError);
  });

  it("maps each poll answer to a state", async () => {
    const poll = (r: () => Response) => client(r).client.pollDeviceSignIn("dc");
    await expect(poll(error(428, "AUTHORIZATION_PENDING", { interval: 5 }))).resolves.toEqual({ state: "pending", interval: 5 });
    await expect(poll(error(429, "SLOW_DOWN", { interval: 10 }))).resolves.toEqual({ state: "slow_down", interval: 10 });
    await expect(poll(error(403, "ACCESS_DENIED"))).resolves.toEqual({ state: "denied" });
    await expect(poll(error(410, "EXPIRED"))).resolves.toEqual({ state: "expired" });
    await expect(poll(error(410, "CONSUMED", { credentialId: "crd_1" }))).resolves.toEqual({ state: "consumed", credentialId: "crd_1" });
    const credential = { id: "crd_1", token: "vlt_cli_x", expiresAt: "2030-01-01T00:00:00.000Z" };
    await expect(poll(() => new Response(JSON.stringify(credential), { status: 201 }))).resolves.toEqual({ state: "issued", credential });
    // Anything else stays an error: maintenance, a missing endpoint, an unexpected success.
    await expect(poll(error(503, "MAINTENANCE"))).rejects.toBeInstanceOf(VarlatchApiError);
    await expect(poll(error(404, "RESOURCE_NOT_FOUND"))).rejects.toMatchObject({ status: 404 });
    await expect(poll(() => new Response("{}", { status: 200 }))).rejects.toBeInstanceOf(VarlatchApiError);
  });

  it("does not retry a maintenance answer on its own", async () => {
    let calls = 0;
    const c = new VarlatchClient({ server: "https://v.example", fetch: async () => { calls++; return error(503, "MAINTENANCE")(); } });
    await expect(c.startDeviceSignIn()).rejects.toMatchObject({ code: "MAINTENANCE" });
    expect(calls).toBe(1);
  });
});
