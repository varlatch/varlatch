// SPDX-License-Identifier: AGPL-3.0-or-later
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

/** Structural JWK shape (the @types/node global, narrowed to what we read). */
interface JsonWebKey {
  kty?: string;
  kid?: string;
  [param: string]: unknown;
}

/**
 * Minimal OIDC token verification on node:crypto only (no JWT library in
 * the Secret Plane, matching jwt.ts). Verifies a compact JWS against the
 * issuer's published JWKS (RFC 8414 / OIDC discovery), with strict issuer
 * echo-back, an algorithm allowlist, and clock checks. Claim-to-binding
 * matching is the caller's job — this module only answers "is this token
 * genuinely from that issuer and currently valid".
 */

const ALLOWED_ALGS = new Set(["RS256", "ES256"]);
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_TTL_MS = 5 * 60_000;
const FETCH_TIMEOUT_MS = 10_000;

export interface OidcClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  [claim: string]: unknown;
}

export class OidcVerificationError extends Error {
  override name = "OidcVerificationError";
}

function fail(message: string): never {
  throw new OidcVerificationError(message);
}

function decodeSegment<T>(segment: string, what: string): T {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as T;
  } catch {
    fail(`Malformed token ${what}`);
  }
}

/** Unverified peek at the claims — for binding lookup only, never trust. */
export function decodeUnverified(token: string): OidcClaims {
  const parts = token.split(".");
  if (parts.length !== 3) fail("Malformed token");
  return decodeSegment<OidcClaims>(parts[1] as string, "payload");
}

interface CachedJwks {
  fetchedAt: number;
  keys: JsonWebKey[];
}

const jwksCache = new Map<string, CachedJwks>();

async function getJson(
  url: string,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown>> {
  const res = await fetchImpl(url, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) fail(`Issuer metadata fetch failed (${res.status})`);
  return (await res.json()) as Record<string, unknown>;
}

async function jwksFor(issuer: string, fetchImpl: typeof fetch): Promise<JsonWebKey[]> {
  const cached = jwksCache.get(issuer);
  if (cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL_MS) return cached.keys;
  const configUrl = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const config = await getJson(configUrl, fetchImpl);
  // Echo-back check (RFC 8414 §3.3): the document must claim this issuer.
  if (config.issuer !== issuer) fail("Issuer metadata mismatch");
  if (typeof config.jwks_uri !== "string") fail("Issuer metadata missing jwks_uri");
  const jwks = await getJson(config.jwks_uri, fetchImpl);
  const keys = Array.isArray(jwks.keys) ? (jwks.keys as JsonWebKey[]) : [];
  if (keys.length === 0) fail("Issuer JWKS is empty");
  jwksCache.set(issuer, { fetchedAt: Date.now(), keys });
  return keys;
}

/** Test hook: drop cached JWKS so rotated keys are re-fetched. */
export function clearJwksCache(): void {
  jwksCache.clear();
}

function verifySignature(
  alg: string,
  kid: string | undefined,
  signingInput: Buffer,
  signature: Buffer,
  keys: JsonWebKey[],
): boolean {
  const kty = alg === "RS256" ? "RSA" : "EC";
  const candidates = keys.filter(
    (k) => k.kty === kty && (!kid || !k.kid || k.kid === kid),
  );
  for (const jwk of candidates) {
    try {
      const key = createPublicKey({ key: jwk, format: "jwk" });
      const options =
        alg === "ES256" ? { key, dsaEncoding: "ieee-p1363" as const } : key;
      if (cryptoVerify("sha256", signingInput, options, signature)) return true;
    } catch {
      // Unusable key — try the next candidate.
    }
  }
  return false;
}

/**
 * Verify signature, issuer and clock validity of a compact JWS against the
 * expected issuer's JWKS. Returns the verified claims; throws
 * OidcVerificationError with a terse reason otherwise.
 */
export async function verifyOidcToken(
  token: string,
  expectedIssuer: string,
  fetchImpl: typeof fetch = fetch,
): Promise<OidcClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) fail("Malformed token");
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  const header = decodeSegment<{ alg?: string; kid?: string }>(headerB64, "header");
  if (!header.alg || !ALLOWED_ALGS.has(header.alg)) fail("Unsupported algorithm");
  const claims = decodeSegment<OidcClaims>(payloadB64, "payload");
  if (claims.iss !== expectedIssuer) fail("Issuer mismatch");
  if (typeof claims.sub !== "string" || claims.sub.length === 0) fail("Missing sub");

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= now - CLOCK_SKEW_SECONDS) {
    fail("Token expired");
  }
  const nbf = claims.nbf;
  if (typeof nbf === "number" && nbf > now + CLOCK_SKEW_SECONDS) fail("Token not yet valid");

  const keys = await jwksFor(expectedIssuer, fetchImpl);
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
  const signature = Buffer.from(signatureB64, "base64url");
  if (!verifySignature(header.alg, header.kid, signingInput, signature, keys)) {
    fail("Signature verification failed");
  }
  return claims;
}
