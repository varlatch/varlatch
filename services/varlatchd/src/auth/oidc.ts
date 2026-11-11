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

/**
 * Issuer documents, fetched within bounds (ADR-0057 Decision 7). The token
 * exchange needs no credential, so a caller could otherwise make varlatchd
 * fetch an issuer's documents as often as it sends tokens:
 *
 * - one discovery-and-JWKS operation at a time per issuer; concurrent
 *   callers share its result, success or failure;
 * - a successful JWKS is kept five minutes;
 * - a failure (discovery, JWKS, or a policy refusal of either) is kept
 *   30 seconds, doubling on each consecutive failure up to 10 minutes;
 *   while it lasts nothing is fetched. A success resets it;
 * - a bad token (signature, audience, expiry, claims) is the token's
 *   failure: it never touches either cache;
 * - a `kid` no cached key carries triggers at most one refresh per issuer
 *   per 60 seconds, through the same shared operation;
 * - each cache holds at most 1,000 issuers, and expired entries go.
 */
export const OIDC_BOUNDS = {
  jwksTtlMs: JWKS_CACHE_TTL_MS,
  firstBackoffMs: 30_000,
  maxBackoffMs: 10 * 60_000,
  refreshIntervalMs: 60_000,
  maxIssuers: 1000,
} as const;

interface CachedJwks {
  fetchedAt: number;
  keys: JsonWebKey[];
}

interface Failure {
  /** Nothing is fetched before this instant. */
  until: number;
  backoffMs: number;
}

const jwksCache = new Map<string, CachedJwks>();
const failures = new Map<string, Failure>();
const lastRefresh = new Map<string, number>();
const inFlight = new Map<string, Promise<JsonWebKey[]>>();

/** Drop expired entries, then the oldest ones, so `map` holds at most maxIssuers keys after one insert. */
function bound<V>(map: Map<string, V>, expired: (value: V) => boolean): void {
  for (const [key, value] of map) if (expired(value)) map.delete(key);
  while (map.size >= OIDC_BOUNDS.maxIssuers) map.delete(map.keys().next().value as string);
}

/** Sizes of the bounded state, for tests. */
export function oidcCacheSizes(): { jwks: number; failures: number; refreshes: number; inFlight: number } {
  return { jwks: jwksCache.size, failures: failures.size, refreshes: lastRefresh.size, inFlight: inFlight.size };
}

/** A fetch failure of the issuer's own documents: the issuer's failure, cached. */
export class OidcIssuerError extends OidcVerificationError {
  override name = "OidcIssuerError";
}

function issuerFail(message: string, cause?: unknown): never {
  throw new OidcIssuerError(message, cause === undefined ? undefined : { cause });
}

async function getJson(
  url: string,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      // A redirect is refused (ADR-0057 Decision 3): bind the final URL instead.
      redirect: "error",
    });
  } catch (err) {
    issuerFail("Issuer metadata fetch failed", err);
  }
  if (!res.ok) issuerFail(`Issuer metadata fetch failed (${res.status})`);
  try {
    return (await res.json()) as Record<string, unknown>;
  } catch (err) {
    issuerFail("Issuer metadata is not JSON", err);
  }
}

async function fetchJwks(issuer: string, fetchImpl: typeof fetch): Promise<JsonWebKey[]> {
  const configUrl = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const config = await getJson(configUrl, fetchImpl);
  // Echo-back check (RFC 8414 §3.3): the document must claim this issuer.
  if (config.issuer !== issuer) issuerFail("Issuer metadata mismatch");
  if (typeof config.jwks_uri !== "string") issuerFail("Issuer metadata missing jwks_uri");
  let jwksUrl: URL;
  try {
    jwksUrl = new URL(config.jwks_uri);
  } catch {
    issuerFail("Issuer jwks_uri is not a URL");
  }
  if (jwksUrl.protocol !== "https:") issuerFail("Issuer jwks_uri is not https");
  const jwks = await getJson(jwksUrl.toString(), fetchImpl);
  const keys = Array.isArray(jwks.keys) ? (jwks.keys as JsonWebKey[]) : [];
  if (keys.length === 0) issuerFail("Issuer JWKS is empty");
  return keys;
}

/** The one shared discovery-and-JWKS operation for an issuer; records success or failure. */
function sharedFetch(issuer: string, fetchImpl: typeof fetch): Promise<JsonWebKey[]> {
  const running = inFlight.get(issuer);
  if (running) return running;
  const operation = fetchJwks(issuer, fetchImpl).then(
    (keys) => {
      const now = Date.now();
      failures.delete(issuer);
      jwksCache.delete(issuer);
      bound(jwksCache, (c) => now - c.fetchedAt >= OIDC_BOUNDS.jwksTtlMs);
      jwksCache.set(issuer, { fetchedAt: now, keys });
      return keys;
    },
    (err: unknown) => {
      const now = Date.now();
      const previous = failures.get(issuer);
      // Consecutive: the previous failure's backoff has not been followed by a success.
      const backoffMs = previous ? Math.min(previous.backoffMs * 2, OIDC_BOUNDS.maxBackoffMs) : OIDC_BOUNDS.firstBackoffMs;
      failures.delete(issuer);
      // A failure is remembered for its backoff plus the longest one, so the next doubles.
      bound(failures, (f) => now >= f.until + OIDC_BOUNDS.maxBackoffMs);
      failures.set(issuer, { until: now + backoffMs, backoffMs });
      throw err;
    },
  ).finally(() => inFlight.delete(issuer));
  inFlight.set(issuer, operation);
  return operation;
}

async function jwksFor(issuer: string, fetchImpl: typeof fetch): Promise<JsonWebKey[]> {
  const cached = jwksCache.get(issuer);
  if (cached && Date.now() - cached.fetchedAt < OIDC_BOUNDS.jwksTtlMs) return cached.keys;
  const failed = failures.get(issuer);
  if (failed && Date.now() < failed.until) issuerFail("Issuer temporarily unavailable");
  return sharedFetch(issuer, fetchImpl);
}

/**
 * One refresh for a key id no cached key carries, at most once per issuer
 * per refreshIntervalMs; null when the interval has not passed (or the
 * issuer is backing off).
 */
async function refreshForUnknownKey(issuer: string, fetchImpl: typeof fetch): Promise<JsonWebKey[] | null> {
  const running = inFlight.get(issuer);
  if (running) return running;
  const now = Date.now();
  const last = lastRefresh.get(issuer);
  if (last !== undefined && now - last < OIDC_BOUNDS.refreshIntervalMs) return null;
  const failed = failures.get(issuer);
  if (failed && now < failed.until) return null;
  lastRefresh.delete(issuer);
  bound(lastRefresh, (at) => now - at >= OIDC_BOUNDS.refreshIntervalMs);
  lastRefresh.set(issuer, now);
  return sharedFetch(issuer, fetchImpl);
}

/** Test hook: drop every cached JWKS, failure and refresh record. */
export function clearJwksCache(): void {
  jwksCache.clear();
  failures.clear();
  lastRefresh.clear();
}

function candidates(alg: string, kid: string | undefined, keys: JsonWebKey[]): JsonWebKey[] {
  const kty = alg === "RS256" ? "RSA" : "EC";
  return keys.filter((k) => k.kty === kty && (!kid || !k.kid || k.kid === kid));
}

function hasCandidate(alg: string, kid: string | undefined, keys: JsonWebKey[]): boolean {
  return candidates(alg, kid, keys).length > 0;
}

function verifySignature(
  alg: string,
  kid: string | undefined,
  signingInput: Buffer,
  signature: Buffer,
  keys: JsonWebKey[],
): boolean {
  for (const jwk of candidates(alg, kid, keys)) {
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
  /** The outbound policy's fetch (ADR-0057); tests pass their own. */
  fetchImpl: typeof fetch,
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

  let keys = await jwksFor(expectedIssuer, fetchImpl);
  if (!hasCandidate(header.alg, header.kid, keys)) {
    // A key id no cached key carries: perhaps a rotation. One bounded refresh.
    keys = (await refreshForUnknownKey(expectedIssuer, fetchImpl)) ?? keys;
    if (!hasCandidate(header.alg, header.kid, keys)) fail("Unknown signing key");
  }
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
  const signature = Buffer.from(signatureB64, "base64url");
  if (!verifySignature(header.alg, header.kid, signingInput, signature, keys)) {
    fail("Signature verification failed");
  }
  return claims;
}
