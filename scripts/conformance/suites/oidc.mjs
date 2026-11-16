#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * OIDC workload identity (capability auth.oidc; ADR-0059 step 4.8), against
 * a local issuer over https (the oidc-issuer capability): a binding of an
 * issuer, an audience and a subject to a machine identity, and the exchange
 * of a token the issuer signed for a short-lived oidc credential. Discovery
 * and the keys, claim matching, audiences, credential lifetimes, failures
 * that answer alike, a key rotation, revocation and a refused issuer
 * address. The suite's own Organization; the tokens are signed here, the
 * issuer serves their keys.
 *
 *   oidc.mjs <origin> <api token>   (run by scripts/conformance/run.mjs)
 */
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin, token] = process.argv.slice(2);
if (!origin || !token) {
  console.error("Usage: oidc.mjs <origin> <api token>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });

async function api(method, path, { body, bearer = token } = {}) {
  const res = await fetch(new URL(path, origin), {
    method,
    headers: {
      ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}),
      "User-Agent": "varlatch-conformance-oidc",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON: kept as text for the detail.
  }
  return { status: res.status, json, text, headers: res.headers };
}

const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: ${r.status} ${r.text}`);
  return r.json;
};

const b64 = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
const keyPair = (kid) => {
  const k = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { kid, privateKey: k.privateKey, jwk: { ...k.publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" } };
};
function sign(key, claims) {
  const h = b64({ alg: "RS256", kid: key.kid, typ: "JWT" });
  const p = b64(claims);
  const s = createSign("RSA-SHA256");
  s.update(`${h}.${p}`);
  return `${h}.${p}.${s.sign(key.privateKey).toString("base64url")}`;
}
const setKeys = (keys) => targetOp("oidc-issuer", ["keys", JSON.stringify({ keys: keys.map((k) => k.jwk) })]);
const counts = () => JSON.parse(targetOp("oidc-issuer", ["counts"]));

const suffix = randomBytes(4).toString("hex");
const slug = `oidc-${suffix}`;
const now = () => Math.floor(Date.now() / 1000);

try {
  ok(await api("GET", "/v1/me"), "whoami");
  ok(await api("POST", "/v1/organizations", { body: { name: "OIDC suite", slug } }), "creating the Organization");
  const ci = ok(await api("POST", `/v1/organizations/${slug}/identities`, { body: { name: "oidc-ci", kind: "ci" } }), "creating the identity");
  const { issuer } = JSON.parse(targetOp("oidc-issuer", ["start"]));
  const k1 = keyPair("k1");
  const k2 = keyPair("k2");
  setKeys([k1]);
  const before = counts();
  const bindings = `/v1/organizations/${slug}/identities/${ci.id}/oidc-bindings`;
  const binding = ok(await api("POST", bindings, {
    body: { issuer, audience: "varlatch-conf", subject: "repo:conf/api:*", claims: { ref: "refs/heads/main" } },
  }), "creating the binding");
  const claims = (more = {}) => ({ iss: issuer, aud: "varlatch-conf", sub: "repo:conf/api:ref:refs/heads/main", ref: "refs/heads/main", iat: now(), exp: now() + 300, ...more });
  const exchange = (t, more = {}) => api("POST", "/v1/oidc/token", { bearer: null, body: { token: t, organization: slug, ...more } });

  // Discovery and the keys: the first exchange fetches each once.
  const first = await exchange(sign(k1, claims()));
  const me = first.json?.token ? await api("GET", "/v1/me", { bearer: first.json.token }) : null;
  const expires = Date.parse(first.json?.expiresAt ?? "");
  const fetched = counts();
  check(
    "oidc.exchange",
    "a token the bound issuer signed is exchanged for a short-lived oidc credential of the bound identity, which authenticates; the issuer's discovery document and keys are fetched once",
    first.status === 201 && first.json.identityId === ci.id && first.json.token.startsWith("vlt_oidc_") && first.headers.get("cache-control") === "no-store" &&
      Math.abs(expires - (Date.now() + 600_000)) < 60_000 && me?.status === 200 && JSON.stringify(me.json).includes(ci.id) &&
      fetched.discovery - before.discovery === 1 && fetched.jwks - before.jwks === 1,
    JSON.stringify({ status: first.status, body: first.json && { ...first.json, token: "(masked)" }, me: me?.status, fetched, before }),
  );

  const short = await exchange(sign(k1, claims()), { ttlSeconds: 60 });
  const tooLong = await exchange(sign(k1, claims()), { ttlSeconds: 3601 });
  const shortExpiry = Date.parse(short.json?.expiresAt ?? "");
  check(
    "oidc.lifetimes",
    "the credential lives as long as asked, up to an hour, ten minutes by default; a longer lifetime is refused",
    short.status === 201 && Math.abs(shortExpiry - (Date.now() + 60_000)) < 30_000 && tooLong.status === 422 && tooLong.json?.error?.code === "VALIDATION_FAILED",
    JSON.stringify({ short: short.status, expiresAt: short.json?.expiresAt, tooLong: tooLong.status }),
  );

  const prefix = await exchange(sign(k1, claims({ sub: "repo:conf/api:pull/7" })));
  const otherSubject = await exchange(sign(k1, claims({ sub: "repo:conf/web:ref:main" })));
  const otherRef = await exchange(sign(k1, claims({ ref: "refs/heads/dev" })));
  const noRef = await exchange(sign(k1, claims({ ref: undefined })));
  check(
    "oidc.claim-matching",
    "a subject ending in * matches by prefix, any other exactly; every claim the binding names must be equal",
    prefix.status === 201 && [otherSubject, otherRef, noRef].every((r) => r.status === 401 && r.json?.error?.code === "INVALID_CREDENTIAL"),
    JSON.stringify([prefix.status, otherSubject.status, otherRef.status, noRef.status]),
  );

  const inArray = await exchange(sign(k1, claims({ aud: ["other", "varlatch-conf"] })));
  const otherAudience = await exchange(sign(k1, claims({ aud: "other" })));
  check(
    "oidc.audiences",
    "the binding's audience may be the token's aud or one of its members; another audience is refused",
    inArray.status === 201 && otherAudience.status === 401,
    JSON.stringify([inArray.status, otherAudience.status]),
  );

  const failures = [
    await exchange(sign(k1, claims({ exp: now() - 3600 }))),
    await exchange(`${sign(k1, claims()).slice(0, -6)}AAAAAA`),
    await exchange(sign(k1, claims({ iss: "https://nobody.invalid" }))),
    await exchange("not-a-token"),
  ];
  const shapes = failures.map((r) => JSON.stringify({ status: r.status, code: r.json?.error?.code, message: r.json?.error?.message, keys: Object.keys(r.json?.error ?? {}) }));
  check(
    "oidc.failures-alike",
    "an expired token, a bad signature, an unknown issuer and a malformed token all answer the same 401 INVALID_CREDENTIAL, telling nothing apart",
    failures.every((r) => r.status === 401) && new Set(shapes).size === 1 && failures[0].json?.error?.code === "INVALID_CREDENTIAL",
    shapes.join(" | "),
  );

  // The issuer rotates its key: a token by the new key refreshes the keys once.
  setKeys([k2]);
  const beforeRotation = counts();
  const rotated = await exchange(sign(k2, claims()));
  const retired = await exchange(sign(k1, claims()));
  const afterRotation = counts();
  check(
    "oidc.key-rotation",
    "after the issuer rotates its keys, a token by the new key is accepted after one refresh of its keys, and the old key's tokens are refused",
    rotated.status === 201 && retired.status === 401 && afterRotation.jwks - beforeRotation.jwks === 1 && afterRotation.discovery - beforeRotation.discovery === 1,
    JSON.stringify({ rotated: rotated.status, retired: retired.status, beforeRotation, afterRotation }),
  );

  const listed = ok(await api("GET", bindings), "listing the bindings");
  const revoked = await api("DELETE", `${bindings}/${binding.id}`);
  const after = await exchange(sign(k2, claims()));
  const listedAfter = ok(await api("GET", bindings), "listing the bindings again");
  check(
    "oidc.revocation",
    "a revoked binding is no longer listed and its tokens are no longer exchanged",
    listed.items.some((b) => b.id === binding.id && b.issuer === issuer && b.claims?.ref === "refs/heads/main") && revoked.status === 204 &&
      after.status === 401 && !listedAfter.items.some((b) => b.id === binding.id),
    JSON.stringify({ listed: listed.items.length, revoked: revoked.status, after: after.status, listedAfter: listedAfter.items.length }),
  );

  const refused = await api("POST", bindings, { body: { issuer: "https://10.255.0.1", audience: "a", subject: "s" } });
  check(
    "oidc.refused-issuer",
    "an issuer at a private address the host has not allowed is refused with the outbound policy's reason",
    refused.status === 422 && refused.json?.error?.details?.outbound === "private_address" && !refused.text.includes("10.255.0.1"),
    refused.text,
  );
} catch (err) {
  error(err instanceof Error ? err.stack ?? err.message : String(err));
}
finish("OIDC checks");
