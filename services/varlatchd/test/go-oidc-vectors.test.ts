// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Step 4.8's vectors (ADR-0059 step 4, feature-parity decision 3): the
 * OIDC token verifier (auth/oidc.ts verifyOidcToken) and its fetch bounds,
 * as this code answers them. go/server/oidc's tests replay the file
 * against the Go verifier.
 *
 * - `verify`: one token, the issuer's documents (by URL: status and body,
 *   or a network failure), the clock, a fresh cache; the claims, or the
 *   reason the exchange would audit (the verification error's message, or
 *   "verification-error" for anything else), and the URLs fetched.
 * - `bounds`: steps on one cache with a moving clock and an issuer whose
 *   answers change: each step's outcome and the fetch counts after it.
 *
 * Keys are generated when the file is written; the tokens are signed then.
 * Each run of this test replays the file here too and requires the same.
 *
 * After a change, regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-oidc-vectors.test.ts
 */
import { createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { clearJwksCache, OidcVerificationError, verifyOidcToken } from "../src/auth/oidc.js";

const FILE = new URL("../../../go/server/oidc/testdata/ts-vectors.json", import.meta.url);
const ISSUER = "https://issuer.example";
const NOW = Date.parse("2026-11-16T12:00:00.000Z");
const SECONDS = Math.floor(NOW / 1000);

type Doc = { status: number; body: string } | { error: true };
type Documents = Record<string, Doc>;
interface VerifyCase {
  name: string;
  issuer: string;
  now: number;
  token: string;
  documents: Documents;
  expect?: { claims?: unknown; reason?: string; fetched?: string[] };
}
interface BoundsStep {
  /** Milliseconds the clock moves before the step. */
  advance: number;
  /** The issuer's answers from this step on: ok, discovery-fails, jwks-fails, rotated (the second key only). */
  mode?: "ok" | "discovery-fails" | "jwks-fails" | "rotated";
  token: string;
  expect?: { outcome: string; discovery: number; jwks: number };
}
interface BoundsCase {
  name: string;
  steps: BoundsStep[];
}
interface Vectors {
  comment: string;
  verify: VerifyCase[];
  bounds: { issuer: string; jwks: { ok: unknown[]; rotated: unknown[] }; scenarios: BoundsCase[] };
}

const b64 = (s: string | Buffer) => Buffer.from(s).toString("base64url");
const json = (o: unknown) => b64(JSON.stringify(o));
const configOf = (issuer: string, jwksUri: string) => JSON.stringify({ issuer, jwks_uri: jwksUri });

function sign(alg: "RS256" | "ES256", key: KeyObject, input: string): Buffer {
  const s = createSign("SHA256");
  s.update(input);
  return alg === "ES256" ? s.sign({ key, dsaEncoding: "ieee-p1363" }) : s.sign(key);
}

/** Writes the vectors: keys, tokens and cases. */
function build(): Vectors {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsa2 = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = (k: KeyObject, extra: Record<string, unknown>) => ({ ...(k.export({ format: "jwk" }) as Record<string, unknown>), ...extra });
  const rsaJwk = pub(rsa.publicKey, { kid: "r1", alg: "RS256", use: "sig" });
  const rsa2Jwk = pub(rsa2.publicKey, { kid: "r2", alg: "RS256", use: "sig" });
  const ecJwk = pub(ec.publicKey, { kid: "e1", alg: "ES256", use: "sig" });
  const claims = { iss: ISSUER, aud: "varlatch", sub: "repo:acme/api:ref:refs/heads/main", iat: SECONDS, exp: SECONDS + 300 };
  const token = (o: { header?: unknown; payload?: unknown; rawHeader?: string; rawPayload?: string; alg?: "RS256" | "ES256"; key?: KeyObject; sig?: (s: string) => string } = {}) => {
    const alg = o.alg ?? "RS256";
    const h = o.rawHeader ?? json(o.header ?? { alg, kid: alg === "ES256" ? "e1" : "r1", typ: "JWT" });
    const p = o.rawPayload ?? json(o.payload ?? claims);
    const s = b64(sign(alg, o.key ?? (alg === "ES256" ? ec.privateKey : rsa.privateKey), `${h}.${p}`));
    return `${h}.${p}.${o.sig ? o.sig(s) : s}`;
  };
  const docs = (keys: unknown[], extra: Documents = {}): Documents => ({
    [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: configOf(ISSUER, `${ISSUER}/jwks`) },
    [`${ISSUER}/jwks`]: { status: 200, body: JSON.stringify({ keys }) },
    ...extra,
  });
  const ok = docs([rsaJwk, ecJwk]);
  const c = (name: string, tok: string, documents: Documents = ok, issuer = ISSUER, now = NOW): VerifyCase => ({ name, issuer, now, token: tok, documents });
  const config = `${ISSUER}/.well-known/openid-configuration`;
  /**
   * A valid token with text inserted after the fourth character of one
   * part (0 header, 1 payload, 2 signature): Buffer decodes base64 from the
   * string's UTF-16 code units, by their low byte.
   */
  const inserted = (part: number, text: string, base = token()) =>
    base.split(".").map((seg, i) => (i === part ? `${seg.slice(0, 4)}${text}${seg.slice(4)}` : seg)).join(".");
  const units: [string, string][] = [
    ["U+013D (low byte =)", "\u013d"],
    ["U+0141 (low byte A)", "\u0141"],
    ["U+00E9 (low byte outside base64)", "\u00e9"],
    ["U+012E (low byte .)", "\u012e"],
    ["a surrogate pair whose high unit's low byte is =", "\u{1F600}"],
    ["a surrogate pair whose low unit's low byte is A", "\u{1F041}"],
    ["a lone surrogate (low byte A)", "\ud841"],
  ];
  const unicode = (["header", "payload", "signature"] as const).flatMap((part, i) =>
    units.map(([what, text]) => c(`${what} in the ${part}`, inserted(i, text))));
  const verify: VerifyCase[] = [
    c("RS256", token()),
    c("ES256", token({ alg: "ES256" })),
    c("two parts", "a.b"),
    c("four parts", `${token()}.x`),
    c("a header that is not JSON", token({ rawHeader: b64("{nope") })),
    c("a null header", token({ rawHeader: b64("null") })),
    c("an array header", token({ rawHeader: b64("[]") })),
    c("a number header", token({ rawHeader: b64("5") })),
    c("alg none", token({ header: { alg: "none", kid: "r1" } })),
    c("alg HS256", token({ header: { alg: "HS256", kid: "r1" } })),
    c("alg in lower case", token({ header: { alg: "rs256", kid: "r1" } })),
    c("alg a number", token({ header: { alg: 256, kid: "r1" } })),
    c("a payload that is not JSON", token({ rawPayload: b64("{iss") })),
    c("a null payload", token({ rawPayload: b64("null") })),
    c("a string payload", token({ rawPayload: b64('"x"') })),
    c("another issuer", token({ payload: { ...claims, iss: "https://other.example" } })),
    c("no issuer", token({ payload: { ...claims, iss: undefined } })),
    c("an issuer that is a number", token({ payload: { ...claims, iss: 5 } })),
    c("no sub", token({ payload: { ...claims, sub: undefined } })),
    c("an empty sub", token({ payload: { ...claims, sub: "" } })),
    c("a sub that is a number", token({ payload: { ...claims, sub: 7 } })),
    c("no exp", token({ payload: { ...claims, exp: undefined } })),
    c("an exp that is a string", token({ payload: { ...claims, exp: String(SECONDS + 300) } })),
    c("exp at the skew's edge", token({ payload: { ...claims, exp: SECONDS - 60 } })),
    c("exp just inside the skew", token({ payload: { ...claims, exp: SECONDS - 59 } })),
    c("a fractional exp", token({ payload: { ...claims, exp: SECONDS - 59.5 } })),
    c("nbf past the skew", token({ payload: { ...claims, nbf: SECONDS + 61 } })),
    c("nbf at the skew's edge", token({ payload: { ...claims, nbf: SECONDS + 60 } })),
    c("an nbf that is a string", token({ payload: { ...claims, nbf: String(SECONDS + 600) } })),
    c("a repeated claim: the last one counts", token({ rawPayload: b64(`{"iss":"https://other.example","sub":"s","exp":${SECONDS + 300},"iss":"${ISSUER}"}`) })),
    c("Unicode and an invalid UTF-8 byte in a claim", token({ rawPayload: b64(Buffer.concat([Buffer.from(`{"iss":"${ISSUER}","sub":"é ✓ `), Buffer.from([0xff, 0xe2, 0x82]), Buffer.from(`","exp":${SECONDS + 300}}`)])) })),
    c("a lone surrogate escaped in a claim", token({ rawPayload: b64(`{"iss":"${ISSUER}","sub":"a\\ud800b","exp":${SECONDS + 300}}`) })),
    c("padding in each segment", (() => { const [h, p, s] = token().split("."); return `${h}==.${p}=.${s}==`; })()),
    c("characters outside base64url", (() => { const [h, p, s] = token().split("."); return `${h!.slice(0, 4)} !${h!.slice(4)}.${p}.${s}`; })()),
    c("the base64 alphabet", token({ sig: (s) => s.replaceAll("-", "+").replaceAll("_", "/") })),
    c("a bad signature", token({ sig: (s) => `${s.slice(0, -4)}AAAA` })),
    c("a signature by another key", token({ key: rsa2.privateKey })), // gitleaks:allow (a key generated for the vectors)
    c("an empty signature", token({ sig: () => "" })),
    c("an ES256 signature in DER", (() => { const [h, p] = token({ alg: "ES256" }).split("."); const s = createSign("SHA256"); s.update(`${h}.${p}`); return `${h}.${p}.${b64(s.sign(ec.privateKey))}`; })()),
    c("RS256 with an EC key's kid", token({ header: { alg: "RS256", kid: "e1" } })),
    c("an unknown kid: one refresh, then refused", token({ header: { alg: "RS256", kid: "nope" } })),
    c("no kid: every key of the type", token({ header: { alg: "RS256" } })),
    c("a kid that is a number", token({ header: { alg: "RS256", kid: 5 } })),
    c("an empty kid", token({ header: { alg: "RS256", kid: "" } })),
    c("keys without kid", token(), docs([{ ...rsaJwk, kid: undefined }])),
    c("a key with an empty kid", token(), docs([{ ...rsaJwk, kid: "" }])),
    c("a null key", token(), docs([null, rsaJwk])),
    c("a string key and an unusable one before the good one", token(), docs(["k", { kty: "RSA", kid: "r1", n: "AQAB", e: "AQAB" }, rsaJwk])),
    c("a key with extra members", token(), docs([{ ...rsaJwk, x5c: ["bm90IGEgY2VydA"], key_ops: ["verify"] }])),
    c("an EC key on P-384 for ES256", token({ alg: "ES256" }), docs([pub(generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey, { kid: "e1" }), ecJwk])),
    c("discovery answers 404", token(), { [config]: { status: 404, body: "" } }),
    c("discovery fails", token(), { [config]: { error: true } }),
    c("discovery is not JSON", token(), { [config]: { status: 200, body: "<html>" } }),
    c("discovery with a byte order mark", token(), { ...ok, [config]: { status: 200, body: `﻿${configOf(ISSUER, `${ISSUER}/jwks`)}` } }),
    c("discovery names another issuer", token(), { ...ok, [config]: { status: 200, body: configOf("https://other.example", `${ISSUER}/jwks`) } }),
    c("discovery is null", token(), { [config]: { status: 200, body: "null" } }),
    c("discovery is an array", token(), { [config]: { status: 200, body: "[]" } }),
    c("no jwks_uri", token(), { [config]: { status: 200, body: JSON.stringify({ issuer: ISSUER }) } }),
    c("a jwks_uri that is not a URL", token(), { [config]: { status: 200, body: configOf(ISSUER, "not a url") } }),
    c("an http jwks_uri", token(), { [config]: { status: 200, body: configOf(ISSUER, "http://issuer.example/jwks") } }),
    c("a jwks_uri fetch serializes", token(), {
      [config]: { status: 200, body: configOf(ISSUER, "HTTPS://Issuer.Example:443/a b/../keys?x=1 2&y=é#frag") },
      "https://issuer.example/keys?x=1%202&y=%C3%A9#frag": { status: 200, body: JSON.stringify({ keys: [rsaJwk] }) },
    }),
    c("the JWKS answers 500", token(), { ...ok, [`${ISSUER}/jwks`]: { status: 500, body: "" } }),
    c("an empty JWKS", token(), docs([])),
    c("keys that are not an array", token(), { ...ok, [`${ISSUER}/jwks`]: { status: 200, body: JSON.stringify({ keys: { a: 1 } }) } }),
    c("a null JWKS", token(), { ...ok, [`${ISSUER}/jwks`]: { status: 200, body: "null" } }),
    ...unicode,
    c("an issuer with a trailing slash", token({ payload: { ...claims, iss: `${ISSUER}/` } }), {
      [config]: { status: 200, body: configOf(`${ISSUER}/`, `${ISSUER}/jwks`) },
      [`${ISSUER}/jwks`]: { status: 200, body: JSON.stringify({ keys: [rsaJwk] }) },
    }, `${ISSUER}/`),
  ];

  const step = (advance: number, tok: string, mode?: BoundsStep["mode"]): BoundsStep => ({ advance, token: tok, ...(mode ? { mode } : {}) });
  // Valid for the scenarios' whole span, so only the issuer's answers and
  // the caches decide.
  const lasting = { ...claims, exp: SECONDS + 30 * 86_400 };
  const good = token({ payload: lasting });
  const rotated = token({ header: { alg: "RS256", kid: "r2" }, key: rsa2.privateKey, payload: lasting });
  const expired = token({ payload: { ...claims, exp: SECONDS - 3600 } });
  const unknown = token({ header: { alg: "RS256", kid: "nope" }, payload: lasting });
  const scenarios: BoundsCase[] = [
    { name: "a JWKS is kept five minutes", steps: [step(0, good, "ok"), step(299_000, good), step(1_999, good)] },
    { name: "a bad token never touches the caches", steps: [step(0, expired, "ok"), step(0, expired), step(0, good), step(0, expired)] },
    {
      name: "a discovery failure backs off 30 s, doubling to 10 minutes",
      steps: [step(0, good, "discovery-fails"), step(29_999, good), step(1, good), step(59_999, good), step(1, good), step(119_999, good), step(1, good),
        step(239_999, good), step(1, good), step(479_999, good), step(1, good), step(599_999, good), step(1, good), step(600_000, good, "ok"),
        step(0, good)],
    },
    { name: "a JWKS failure backs off too", steps: [step(0, good, "jwks-fails"), step(0, good), step(30_000, good, "ok"), step(0, good)] },
    {
      name: "a key rotation: an unknown kid refreshes once a minute",
      steps: [step(0, good, "ok"), step(0, rotated, "rotated"), step(0, unknown), step(30_000, unknown), step(30_000, unknown), step(1, good)],
    },
    {
      name: "a success resets the backoff",
      steps: [step(0, good, "discovery-fails"), step(30_000, good), step(60_000, good, "ok"), step(300_001, good, "discovery-fails"), step(30_000, good)],
    },
  ];
  return {
    comment: "Written by services/varlatchd/test/go-oidc-vectors.test.ts from the TypeScript verifier's own answers; do not edit.",
    verify,
    bounds: { issuer: ISSUER, jwks: { ok: [rsaJwk, ecJwk], rotated: [rsa2Jwk] }, scenarios },
  };
}

/** A fetch answering from documents, recording each URL. */
function fetchFrom(documents: Documents, fetched: string[]): typeof fetch {
  return (async (url: unknown) => {
    const u = String(url);
    fetched.push(u);
    const d = documents[u];
    if (!d) return new Response(null, { status: 404 });
    if ("error" in d) throw new TypeError("fetch failed");
    return new Response(d.body, { status: d.status });
  }) as typeof fetch;
}

const reasonOf = (err: unknown) => (err instanceof OidcVerificationError ? err.message : "verification-error");

async function answer(v: VerifyCase): Promise<NonNullable<VerifyCase["expect"]>> {
  clearJwksCache();
  vi.setSystemTime(new Date(v.now));
  const fetched: string[] = [];
  try {
    const claims = await verifyOidcToken(v.token, v.issuer, fetchFrom(v.documents, fetched));
    return { claims, fetched };
  } catch (err) {
    return { reason: reasonOf(err), fetched };
  }
}

async function run(b: Vectors["bounds"], s: BoundsCase): Promise<BoundsStep[]> {
  clearJwksCache();
  let now = NOW;
  let mode: NonNullable<BoundsStep["mode"]> = "ok";
  const counts = { discovery: 0, jwks: 0 };
  const config = `${b.issuer}/.well-known/openid-configuration`;
  const fetchImpl = (async (url: unknown) => {
    const u = String(url);
    if (u === config) {
      counts.discovery++;
      if (mode === "discovery-fails") return new Response(null, { status: 503 });
      return Response.json({ issuer: b.issuer, jwks_uri: `${b.issuer}/jwks` });
    }
    counts.jwks++;
    if (mode === "jwks-fails") return new Response(null, { status: 500 });
    return Response.json({ keys: mode === "rotated" ? b.jwks.rotated : b.jwks.ok });
  }) as typeof fetch;
  const out: BoundsStep[] = [];
  for (const st of s.steps) {
    now += st.advance;
    if (st.mode) mode = st.mode;
    vi.setSystemTime(new Date(now));
    let outcome = "ok";
    try {
      await verifyOidcToken(st.token, b.issuer, fetchImpl);
    } catch (err) {
      outcome = reasonOf(err);
    }
    out.push({ ...st, expect: { outcome, ...counts } });
  }
  return out;
}

async function record(v: Vectors): Promise<Vectors> {
  vi.useFakeTimers({ toFake: ["Date"] });
  const verify: VerifyCase[] = [];
  for (const c of v.verify) verify.push({ ...c, expect: await answer(c) });
  const scenarios: BoundsCase[] = [];
  for (const s of v.bounds.scenarios) scenarios.push({ ...s, steps: await run(v.bounds, s) });
  return { ...v, verify, bounds: { ...v.bounds, scenarios } };
}

afterEach(() => {
  vi.useRealTimers();
  clearJwksCache();
});

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the OIDC vectors", () => {
  it("builds the keys and tokens, records the verifier's answers, and writes the file", async () => {
    writeFileSync(FILE, JSON.stringify(await record(build()), null, 2) + "\n");
  });
});

describe("the OIDC vectors are this verifier's answers", () => {
  it("ts-vectors.json", async () => {
    const file = JSON.parse(readFileSync(FILE, "utf8")) as Vectors;
    expect(file.verify.length).toBeGreaterThan(50);
    expect(await record(file)).toEqual(file);
  });
});
