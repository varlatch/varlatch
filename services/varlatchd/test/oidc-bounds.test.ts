// SPDX-License-Identifier: AGPL-3.0-or-later
import { createSign, generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearJwksCache, OIDC_BOUNDS, oidcCacheSizes, verifyOidcToken } from "../src/auth/oidc.js";
import { OutboundPolicy } from "../src/net/outbound.js";

/**
 * The OIDC fetch bounds (ADR-0057 Decision 7): the exchange needs no
 * credential, so how often varlatchd fetches an issuer's documents must not
 * depend on how many tokens a caller sends.
 */

const ISSUER = "https://ci.example";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = (key: typeof publicKey, kid: string) => ({ ...(key.export({ format: "jwk" }) as Record<string, string>), kid, alg: "RS256", use: "sig" });

function token(opts: { iss?: string; kid?: string; exp?: number; key?: typeof privateKey } = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const h = b64({ alg: "RS256", kid: opts.kid ?? "k1" });
  const p = b64({ iss: opts.iss ?? ISSUER, aud: "varlatch", sub: "repo:acme/api", exp: opts.exp ?? now + 300 });
  const s = createSign("RSA-SHA256");
  s.update(`${h}.${p}`);
  return `${h}.${p}.${s.sign(opts.key ?? privateKey).toString("base64url")}`;
}

/** A fake issuer counting its fetches; `mode` decides what it answers. */
function issuer(iss = ISSUER) {
  const counts = { discovery: 0, jwks: 0 };
  const state = { mode: "ok" as "ok" | "discovery-fails" | "jwks-fails", keys: [jwk(publicKey, "k1")], delayMs: 0 };
  const fetchImpl = (async (url: unknown) => {
    const u = String(url);
    if (state.delayMs) await new Promise((r) => setTimeout(r, state.delayMs));
    if (u === `${iss}/.well-known/openid-configuration`) {
      counts.discovery++;
      if (state.mode === "discovery-fails") return new Response(null, { status: 503 });
      return Response.json({ issuer: iss, jwks_uri: `${iss}/jwks` });
    }
    if (u === `${iss}/jwks`) {
      counts.jwks++;
      if (state.mode === "jwks-fails") return new Response(null, { status: 500 });
      return Response.json({ keys: state.keys });
    }
    return new Response(null, { status: 404 });
  }) as typeof fetch;
  return { counts, state, fetchImpl };
}

beforeEach(() => {
  clearJwksCache();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-11T12:00:00Z"));
});
afterEach(() => {
  vi.useRealTimers();
});

describe("OIDC fetch bounds (Decision 7)", () => {
  it("makes one discovery and one JWKS fetch for 100 concurrent exchanges, and gives all the same result", async () => {
    const ok = issuer();
    ok.state.delayMs = 5;
    const results = await Promise.allSettled(Array.from({ length: 100 }, () => verifyOidcToken(token(), ISSUER, ok.fetchImpl)));
    expect(results.every((r) => r.status === "fulfilled")).toBe(true);
    expect(ok.counts).toEqual({ discovery: 1, jwks: 1 });

    clearJwksCache();
    const failing = issuer();
    failing.state.mode = "discovery-fails";
    failing.state.delayMs = 5;
    const failed = await Promise.allSettled(Array.from({ length: 100 }, () => verifyOidcToken(token(), ISSUER, failing.fetchImpl)));
    expect(failed.every((r) => r.status === "rejected")).toBe(true);
    expect(failing.counts).toEqual({ discovery: 1, jwks: 0 });
  });

  it("keeps a successful JWKS five minutes", async () => {
    const ok = issuer();
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.jwksTtlMs - 1000);
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    expect(ok.counts).toEqual({ discovery: 1, jwks: 1 });
    vi.setSystemTime(Date.now() + 2000);
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    expect(ok.counts).toEqual({ discovery: 2, jwks: 2 });
  });

  it.each(["discovery-fails", "jwks-fails", "refused"] as const)("backs off after a failure (%s): 30 s, doubling to 10 minutes, reset by a success", async (mode) => {
    const fake = issuer();
    const policy = new OutboundPolicy("", { log: () => {}, resolve: async () => [{ address: "10.0.0.9", family: 4 }] });
    const fetchImpl = mode === "refused" ? policy.fetch("oidc") : fake.fetchImpl;
    if (mode !== "refused") fake.state.mode = mode;
    const attempts = () => (mode === "refused" ? refusedCalls : fake.counts.discovery);
    let refusedCalls = 0;
    const counted = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      refusedCalls++;
      return fetchImpl(input, init);
    }) as typeof fetch;
    const verify = () => verifyOidcToken(token(), ISSUER, mode === "refused" ? counted : fetchImpl).catch((e: Error) => e);

    await verify();
    expect(attempts()).toBe(1);
    // Within the backoff nothing is fetched, whatever the number of callers.
    for (let i = 0; i < 20; i++) expect(await verify()).toBeInstanceOf(Error);
    expect(attempts()).toBe(1);
    let backoff = OIDC_BOUNDS.firstBackoffMs;
    for (let round = 2; round <= 7; round++) {
      vi.setSystemTime(Date.now() + backoff - 1);
      await verify();
      expect(attempts(), `round ${round}, before the backoff`).toBe(round - 1);
      vi.setSystemTime(Date.now() + 1);
      await verify();
      expect(attempts(), `round ${round}, after the backoff`).toBe(round);
      backoff = Math.min(backoff * 2, OIDC_BOUNDS.maxBackoffMs);
    }
    expect(backoff).toBe(OIDC_BOUNDS.maxBackoffMs);
    await policy.close();
    if (mode === "refused") return;
    // A success resets the backoff.
    fake.state.mode = "ok";
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.maxBackoffMs);
    await expect(verifyOidcToken(token(), ISSUER, fetchImpl)).resolves.toMatchObject({ iss: ISSUER });
    fake.state.mode = "discovery-fails";
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.jwksTtlMs + 1);
    const before = fake.counts.discovery;
    await verify();
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.firstBackoffMs);
    await verify();
    expect(fake.counts.discovery).toBe(before + 2);
  });

  it("never lets a bad token touch either cache", async () => {
    const ok = issuer();
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    const sizes = oidcCacheSizes();
    for (let i = 0; i < 50; i++) {
      await expect(verifyOidcToken(token({ key: other.privateKey }), ISSUER, ok.fetchImpl)).rejects.toThrow(/Signature/);
      await expect(verifyOidcToken(token({ exp: Math.floor(Date.now() / 1000) - 3600 }), ISSUER, ok.fetchImpl)).rejects.toThrow(/expired/);
      await expect(verifyOidcToken(token({ iss: "https://elsewhere.example" }), ISSUER, ok.fetchImpl)).rejects.toThrow(/Issuer mismatch/);
    }
    expect(ok.counts).toEqual({ discovery: 1, jwks: 1 });
    expect(oidcCacheSizes()).toEqual(sizes);
    // The good token still verifies from the cache.
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    expect(ok.counts).toEqual({ discovery: 1, jwks: 1 });
  });

  it("refreshes for an unknown key id at most once per issuer per minute, shared by concurrent callers", async () => {
    const ok = issuer();
    await verifyOidcToken(token(), ISSUER, ok.fetchImpl);
    ok.state.delayMs = 5;
    const unknown = await Promise.allSettled(Array.from({ length: 20 }, () => verifyOidcToken(token({ kid: "k2", key: other.privateKey }), ISSUER, ok.fetchImpl)));
    expect(unknown.every((r) => r.status === "rejected")).toBe(true);
    expect(ok.counts).toEqual({ discovery: 2, jwks: 2 });
    for (let i = 0; i < 20; i++) await expect(verifyOidcToken(token({ kid: "k2", key: other.privateKey }), ISSUER, ok.fetchImpl)).rejects.toThrow(/Unknown signing key/);
    expect(ok.counts).toEqual({ discovery: 2, jwks: 2 });
    // The issuer rotates: after the minute, one refresh finds the new key.
    ok.state.keys = [jwk(publicKey, "k1"), jwk(other.publicKey, "k2")];
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.refreshIntervalMs);
    await expect(verifyOidcToken(token({ kid: "k2", key: other.privateKey }), ISSUER, ok.fetchImpl)).resolves.toMatchObject({ iss: ISSUER });
    expect(ok.counts).toEqual({ discovery: 3, jwks: 3 });
  });

  it("keeps each cache within 1,000 issuers and drops expired entries", async () => {
    for (let i = 0; i < 1100; i++) {
      const iss = `https://ci${i}.example`;
      const ok = issuer(iss);
      await verifyOidcToken(token({ iss }), iss, ok.fetchImpl);
      const bad = issuer(iss);
      bad.state.mode = "discovery-fails";
    }
    expect(oidcCacheSizes().jwks).toBeLessThanOrEqual(OIDC_BOUNDS.maxIssuers);
    for (let i = 0; i < 1100; i++) {
      const iss = `https://bad${i}.example`;
      const bad = issuer(iss);
      bad.state.mode = "jwks-fails";
      await verifyOidcToken(token({ iss }), iss, bad.fetchImpl).catch(() => {});
    }
    expect(oidcCacheSizes().failures).toBeLessThanOrEqual(OIDC_BOUNDS.maxIssuers);
    // Expired: after the longest retention, a new entry sweeps all old ones.
    vi.setSystemTime(Date.now() + OIDC_BOUNDS.maxBackoffMs * 3);
    const last = issuer("https://last.example");
    last.state.mode = "jwks-fails";
    await verifyOidcToken(token({ iss: "https://last.example" }), "https://last.example", last.fetchImpl).catch(() => {});
    expect(oidcCacheSizes().failures).toBe(1);
    const fresh = issuer("https://fresh.example");
    await verifyOidcToken(token({ iss: "https://fresh.example" }), "https://fresh.example", fresh.fetchImpl);
    expect(oidcCacheSizes().jwks).toBe(1);
    expect(oidcCacheSizes().inFlight).toBe(0);
  });

  it("requires an https jwks_uri and refuses redirects", async () => {
    const plain = (async (url: unknown) =>
      String(url).endsWith("openid-configuration") ? Response.json({ issuer: ISSUER, jwks_uri: "http://ci.example/jwks" }) : Response.json({ keys: [jwk(publicKey, "k1")] })) as typeof fetch;
    await expect(verifyOidcToken(token(), ISSUER, plain)).rejects.toThrow(/not https/);
    clearJwksCache();
    const inits: RequestInit[] = [];
    const recording = (async (_url: unknown, init?: RequestInit) => {
      inits.push(init ?? {});
      return new Response(null, { status: 503 });
    }) as typeof fetch;
    await verifyOidcToken(token(), ISSUER, recording).catch(() => {});
    expect(inits[0]?.redirect).toBe("error");
  });
});
