// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { decrypt, encrypt, type Envelope } from "../crypto/aead.js";
import { newId } from "../db/ids.js";
import type { AppCtx } from "../domain/ctx.js";
import { withTx } from "../db/tx.js";

/**
 * Application Plane token issuer (ADR-0007 §2, ADR-0018 §6): varlatchd mints
 * short-lived, audience-scoped ES256 JWTs verified by Convex against
 * /.well-known/jwks.json. One-way trust — these tokens are NEVER accepted by
 * varlatchd itself as Secret Plane credentials. Built on node:crypto only
 * (no JWT library in the Secret Plane); private keys persist only wrapped
 * under the root KEK.
 */

export const CONVEX_AUDIENCE = "convex";
const TOKEN_TTL_SECONDS = 10 * 60;

interface SigningKeyRow {
  id: string;
  public_jwk: Record<string, string> | string;
  private_key_wrapped: Envelope | string;
}

function parseJson<T>(v: T | string): T {
  return typeof v === "string" ? (JSON.parse(v) as T) : v;
}

function keyWrapContext(keyId: string) {
  return { purpose: "jwt-signing-key", keyId };
}

export async function ensureSigningKey(ctx: AppCtx): Promise<SigningKeyRow> {
  const existing = await ctx.db.query(
    "SELECT id, public_jwk, private_key_wrapped FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
  );
  if (existing.rows[0]) return existing.rows[0] as SigningKeyRow;
  return withTx(ctx.db, async (db) => {
    const raced = await db.query(
      "SELECT id, public_jwk, private_key_wrapped FROM signing_keys WHERE retired_at IS NULL LIMIT 1",
    );
    if (raced.rows[0]) return raced.rows[0] as SigningKeyRow;
    const id = newId("credential").replace("crd_", "key_");
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
    publicJwk.kid = id;
    publicJwk.alg = "ES256";
    publicJwk.use = "sig";
    const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
    const wrapped = encrypt(ctx.rootKek, Buffer.from(privatePem, "utf8"), keyWrapContext(id));
    await db.query(
      "INSERT INTO signing_keys (id, algorithm, public_jwk, private_key_wrapped) VALUES ($1,'ES256',$2,$3)",
      [id, JSON.stringify(publicJwk), JSON.stringify(wrapped)],
    );
    return { id, public_jwk: publicJwk, private_key_wrapped: wrapped };
  });
}

export async function publicJwks(ctx: AppCtx): Promise<{ keys: Record<string, string>[] }> {
  const res = await ctx.db.query(
    "SELECT public_jwk FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at",
  );
  return {
    keys: (res.rows as SigningKeyRow[]).map((r) => parseJson(r.public_jwk)),
  };
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

export interface ConvexTokenClaims {
  /** Varlatch Identity ID (or the dedicated mirror identity). */
  sub: string;
  name: string;
  orgIds: string[];
  installationAdmin: boolean;
  /** "mirror" marks varlatchd's own narrow sync identity (ADR-0019 §6). */
  role?: "mirror";
}

/** Mint a short-lived Application Plane JWT. Rights stay server-side. */
export async function mintConvexToken(
  ctx: AppCtx,
  issuer: string,
  claims: ConvexTokenClaims,
): Promise<{ token: string; expiresAt: string }> {
  const key = await ensureSigningKey(ctx);
  const privatePem = decrypt(
    ctx.rootKek,
    parseJson(key.private_key_wrapped),
    keyWrapContext(key.id),
  ).toString("utf8");
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key.id };
  const payload = {
    iss: issuer,
    aud: CONVEX_AUDIENCE,
    sub: claims.sub,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS,
    jti: b64url(randomBytes(12)),
    name: claims.name,
    orgIds: claims.orgIds,
    installationAdmin: claims.installationAdmin,
    ...(claims.role ? { role: claims.role } : {}),
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = createSign("SHA256")
    .update(signingInput)
    .sign({ key: createPrivateKey(privatePem), dsaEncoding: "ieee-p1363" });
  return {
    token: `${signingInput}.${signature.toString("base64url")}`,
    expiresAt: new Date((now + TOKEN_TTL_SECONDS) * 1000).toISOString(),
  };
}

/**
 * Test/diagnostic verification against the published JWKS. varlatchd's own
 * authentication path never calls this — Application Plane tokens are not
 * Secret Plane credentials.
 */
export function verifyConvexToken(
  jwks: { keys: Record<string, string>[] },
  token: string,
  expectedIssuer: string,
): Record<string, unknown> | null {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return null;
  const header = JSON.parse(Buffer.from(h, "base64url").toString()) as { alg: string; kid: string };
  if (header.alg !== "ES256") return null;
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  let ok = false;
  try {
    const publicKey = createPublicKey({ key: jwk as never, format: "jwk" });
    ok = createVerify("SHA256")
      .update(`${h}.${p}`)
      .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  } catch {
    return null;
  }
  if (!ok) return null;
  const payload = JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>;
  if (payload.iss !== expectedIssuer) return null;
  if (typeof payload.exp !== "number" || payload.exp <= Date.now() / 1000) return null;
  return payload;
}
