#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Cross-language fixtures for go/lib/envelope (ADR-0059 Order step 3:
 * "fixtures encrypted by the TypeScript server decrypt in Go and the
 * reverse"). Both commands run the TypeScript server's own crypto code:
 * services/varlatchd/src/crypto/{aead,hierarchy,canary}.ts and
 * packages/contract/src/canonical.ts, loaded with Node's type stripping.
 *
 *   node tsfixtures.mjs generate [--ref <git ref>] <out.json>
 *       Seals a key hierarchy (canary, org KEKs, values, webhook secrets,
 *       platform credentials, GitHub App keys, audit export credentials and
 *       their drain copies (0.22.0 and later), JWT signing keys) and writes
 *       it with canonical-JSON and Root KEK parsing vectors. Without --ref
 *       the working tree's sources are used.
 *   node tsfixtures.mjs verify [--ref <git ref>] <sealed.json>
 *       Opens every envelope in a file of the same shape (written by the Go
 *       tests) and checks every plaintext. Exits 1 on any mismatch.
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const SOURCES = {
  "aead.ts": "services/varlatchd/src/crypto/aead.ts",
  "hierarchy.ts": "services/varlatchd/src/crypto/hierarchy.ts",
  "canary.ts": "services/varlatchd/src/crypto/canary.ts",
  "canonical.ts": "packages/contract/src/canonical.ts",
};
// Read only to check that the generator's copies of their rules still match.
const CHECKED = {
  jwt: "services/varlatchd/src/auth/jwt.ts",
  config: "services/varlatchd/src/config.ts",
};

function source(ref, path) {
  if (!ref) return readFileSync(join(repoRoot, path), "utf8");
  return execFileSync("git", ["-C", repoRoot, "show", `${ref}:${path}`], { encoding: "utf8" });
}

async function loadTs(ref) {
  const dir = mkdtempSync(join(tmpdir(), "varlatch-tsfixtures-"));
  try {
    writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
    for (const [name, path] of Object.entries(SOURCES)) {
      const text = source(ref, path)
        .replaceAll('from "@varlatch/contract"', 'from "./canonical.ts"')
        .replace(/from "\.\/(aead|hierarchy|canary)\.js"/g, 'from "./$1.ts"');
      writeFileSync(join(dir, name), text);
    }
    const load = (name) => import(pathToFileURL(join(dir, name)).href);
    return {
      aead: await load("aead.ts"),
      hierarchy: await load("hierarchy.ts"),
      canary: await load("canary.ts"),
      canonical: await load("canonical.ts"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// jwt.ts imports the database layer, so its AAD context is copied here; fail
// if the source no longer has it.
function jwtContext(ref, keyId) {
  if (!source(ref, CHECKED.jwt).includes('return { purpose: "jwt-signing-key", keyId };')) {
    throw new Error("jwt.ts no longer builds its AAD context as this generator assumes");
  }
  return { purpose: "jwt-signing-key", keyId };
}

// config.ts's parseKekMaterial is not exported and config.ts imports the
// rest of the server, so the function's own text is cut out of the file and
// run, with a stand-in for its ConfigError.
let kekParser;
async function parseKekMaterial(ref, material) {
  if (!kekParser) {
    const text = source(ref, CHECKED.config);
    const start = text.indexOf("function parseKekMaterial(");
    const end = text.indexOf("\n}\n", start);
    if (start < 0 || end < 0) throw new Error("config.ts no longer has parseKekMaterial");
    const dir = mkdtempSync(join(tmpdir(), "varlatch-tsfixtures-"));
    try {
      writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
      writeFileSync(join(dir, "kek.ts"), `class ConfigError extends Error {}\nexport ${text.slice(start, end + 2)}\n`);
      kekParser = (await import(pathToFileURL(join(dir, "kek.ts")).href)).parseKekMaterial;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  try {
    return kekParser(material, "fixture").toString("hex");
  } catch (e) {
    if (e.constructor.name !== "ConfigError") throw e;
    return null;
  }
}

const b64 = (buf) => Buffer.from(buf).toString("base64");
const id = (prefix, n) => `${prefix}_${"abcdefghijklmnopqrstuvwxyz234567".slice(n, n + 26).padEnd(26, "a")}`;

const PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";

function plaintexts() {
  return [
    Buffer.alloc(0),
    Buffer.from("hello", "utf8"),
    Buffer.from("héllo wörld ✓ 🔑   <&> \"quoted\" \\ back", "utf8"),
    Buffer.from(PEM, "utf8"),
    randomBytes(37),
    randomBytes(70_000),
  ];
}

async function generate(ref, out) {
  const ts = await loadTs(ref);
  const rootKek = ts.aead.generateKey();
  const installationId = id("ins", 0);
  const fixture = {
    comment: "Written by tsfixtures.mjs from the TypeScript server's crypto code; do not edit.",
    ref: ref ?? "(working tree)",
    node: process.version,
    rootKek: rootKek.toString("hex"),
    installationId,
    canary: ts.canary.createCanary(rootKek, installationId),
    organizations: [],
    jwtSigningKeys: [],
  };
  for (let o = 0; o < 2; o++) {
    const organizationId = id("org", o);
    const { orgKek, wrapped } = ts.hierarchy.createWrappedOrgKek(rootKek, organizationId);
    const org = { organizationId, orgKek: orgKek.toString("hex"), wrappedOrgKek: wrapped, values: [], webhooks: [], connections: [], githubApps: [] };
    // ADR-0056's audit export, since 0.22.0: its S3 credential (JSON) under
    // the org KEK, and the copy under the Root KEK that drains it after the
    // Organization is deleted. Older refs have neither.
    if (ts.hierarchy.encryptAuditExportCredential) {
      const exportId = id("aex", o);
      const credential = JSON.stringify({ accessKeyId: `AKIA${randomBytes(8).toString("hex").toUpperCase()}`, secretAccessKey: randomBytes(30).toString("base64") });
      org.auditExports = [{
        exportId,
        credential,
        envelope: ts.hierarchy.encryptAuditExportCredential(orgKek, organizationId, exportId, credential),
        drainEnvelope: ts.hierarchy.encryptAuditExportDrainCredential(rootKek, organizationId, exportId, credential),
      }];
    }
    plaintexts().forEach((plaintext, i) => {
      const secretId = id("val", o * 8 + i);
      const versionId = id("ver", o * 8 + i);
      const enc = ts.hierarchy.encryptValue(orgKek, organizationId, secretId, versionId, plaintext);
      org.values.push({ secretId, versionId, plaintext: b64(plaintext), payload: enc.payload, wrappedDek: enc.wrappedDek });
    });
    const webhookId = id("whk", o);
    const secret = `vlt_whsec_${randomBytes(32).toString("base64url")}`;
    org.webhooks.push({ webhookId, secret, envelope: ts.hierarchy.encryptWebhookSecret(orgKek, organizationId, webhookId, secret) });
    const connectionId = id("pcn", o);
    const credential = `ghp_${randomBytes(18).toString("hex")} ✓`;
    org.connections.push({ connectionId, credential, envelope: ts.hierarchy.encryptPlatformCredential(orgKek, organizationId, connectionId, credential) });
    const githubAppId = id("gha", o);
    org.githubApps.push({ githubAppId, privateKeyPem: PEM, envelope: ts.hierarchy.encryptGitHubAppKey(orgKek, organizationId, githubAppId, PEM) });
    fixture.organizations.push(org);
  }
  const keyId = id("key", 0);
  fixture.jwtSigningKeys.push({ keyId, privateKeyPem: PEM, envelope: ts.aead.encrypt(rootKek, Buffer.from(PEM, "utf8"), jwtContext(ref, keyId)) });

  // canonicalJson vectors: the AAD encoding, including what Go's encoding/json
  // would get wrong (HTML escaping, U+2028/U+2029, UTF-16 key order).
  const control = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join("") + "\u007f";
  fixture.canonical = [
    { purpose: "org-kek", organizationId: id("org", 0) },
    { purpose: "kek-escrow", kdfAlgorithm: "scrypt", N: 131072, r: 8, p: 1, salt: "AAECAwQFBgcICQoLDA0ODw==" },
    { s: `quote " backslash \\ slash / ${control} <tag> &     é 🔑` },
    { "￿": 1, "😀": 2, a: 3, B: 4, _: 5, "": 6, "é": 7 },
    { n: [0, -1, 9007199254740991, -9007199254740991], t: true, f: false, z: null, nested: { b: [], a: {} } },
  ].map((value) => ({ value, canonical: ts.canonical.canonicalJson(value) }));

  // Root KEK material as an operator might write it, parsed by Node.
  const hex = rootKek.toString("hex");
  const std = rootKek.toString("base64");
  const inputs = [
    hex, hex.toUpperCase(), `  ${hex}\n`, `﻿${hex}\r\n`, `${hex.slice(0, 32)} ${hex.slice(32)}`,
    std, std.replace(/=+$/, ""), rootKek.toString("base64url"), `${std}\n`, ` ${std.slice(0, 20)}\n${std.slice(20)} `,
    `${std.slice(0, 10)}$%${std.slice(10)}`, `${std}junk`, `=${std}`, std.slice(0, 40), `${std.replace(/=+$/, "")}AAAA`,
    `\u0085${std} `, `${std.slice(0, 5)}é${std.slice(5)}`, `Ł${std.slice(1)}`, `${std.slice(0, 43)}İ`,
    hex.slice(0, 63), `${hex}0`, "", "   ",
  ];
  fixture.kekMaterial = [];
  for (const input of inputs) fixture.kekMaterial.push({ input, key: await parseKekMaterial(ref, input) });

  // Node's lenient base64 decoder, which reads envelope fields and Root KEK
  // material: it reads each UTF-16 code unit's low byte, skips characters
  // outside both alphabets and stops at the first "=".
  fixture.nodeBase64 = [
    "QUJD", "QUJ", "QU", "Q", "QUJDRA==", "QUJDRA=", "QUJDRA", "QU JD\nRA==", "QU$JDRA==", "QUJD=RA==",
    "-_-_", "+/+/", "=QUJD", "QUJ=D", "\u00e9QUJD", "QUJD\u0000QU", "\u0141UJD", "\u0130UJD", "QU\ud83d\ude00JD",
    "QU\ude00JD", "QU\ud855JD", "QU\udc2dJD", "QUJD\u2028", "\ufeffQUJD", "",
  ].map((input) => ({ input, hex: Buffer.from(input, "base64").toString("hex") }));

  // Envelopes stored in unusual but valid encodings, each checked here to
  // open in the TypeScript code: a lone surrogate standing for the base64
  // character in its low byte, the URL alphabet without padding, and
  // characters Node skips.
  {
    const context = { purpose: "kek-canary", installationId };
    const plaintext = Buffer.from("loose encodings", "utf8");
    const env = ts.aead.encrypt(rootKek, plaintext, context);
    const high = (s) => String.fromCharCode(0xd800 | s.charCodeAt(0)) + s.slice(1);
    const low = (s) => String.fromCharCode(0xdc00 | s.charCodeAt(0)) + s.slice(1);
    const variants = {
      "lone high surrogate in nonce": { ...env, nonce: high(env.nonce) },
      "lone low surrogate in tag": { ...env, authTag: low(env.authTag) },
      "URL alphabet, unpadded": { ...env, ciphertext: Buffer.from(env.ciphertext, "base64").toString("base64url") },
      "skipped characters": { ...env, nonce: `${env.nonce.slice(0, 4)} \n$${env.nonce.slice(4)}` },
    };
    fixture.looseEnvelopes = Object.entries(variants).map(([name, envelope]) => {
      if (!ts.aead.decrypt(rootKek, envelope, context).equals(plaintext)) throw new Error(`${name} does not open in TypeScript`);
      return { name, envelope, plaintext: b64(plaintext) };
    });
  }

  // The UTF-16 code units JavaScript's String.prototype.trim removes.
  fixture.jsTrimCodeUnits = [];
  for (let c = 0; c <= 0xffff; c++) {
    if (String.fromCharCode(c).trim() === "") fixture.jsTrimCodeUnits.push(c);
  }

  writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`wrote ${out}`);
}

async function verify(ref, file) {
  const ts = await loadTs(ref);
  const f = JSON.parse(readFileSync(file, "utf8"));
  const rootKek = Buffer.from(f.rootKek, "hex");
  let checked = 0;
  const fail = (what) => {
    console.error(`MISMATCH: ${what}`);
    process.exitCode = 1;
  };
  const same = (what, got, want) => {
    checked++;
    if (!Buffer.from(got).equals(Buffer.from(want))) fail(what);
  };
  if (!ts.canary.verifyKekAgainstCanary(rootKek, f.canary, f.installationId)) fail("canary");
  checked++;
  for (const org of f.organizations) {
    const orgKek = ts.hierarchy.unwrapOrgKek(rootKek, org.wrappedOrgKek, org.organizationId);
    same(`org KEK ${org.organizationId}`, orgKek, Buffer.from(org.orgKek, "hex"));
    for (const v of org.values) {
      const got = ts.hierarchy.decryptValue(orgKek, org.organizationId, v.secretId, v.versionId, { payload: v.payload, wrappedDek: v.wrappedDek });
      same(`value ${v.secretId}`, got, Buffer.from(v.plaintext, "base64"));
    }
    for (const w of org.webhooks) same(`webhook ${w.webhookId}`, Buffer.from(ts.hierarchy.decryptWebhookSecret(orgKek, org.organizationId, w.webhookId, w.envelope)), Buffer.from(w.secret));
    for (const c of org.connections) same(`connection ${c.connectionId}`, Buffer.from(ts.hierarchy.decryptPlatformCredential(orgKek, org.organizationId, c.connectionId, c.envelope)), Buffer.from(c.credential));
    for (const g of org.githubApps) same(`GitHub App ${g.githubAppId}`, Buffer.from(ts.hierarchy.decryptGitHubAppKey(orgKek, org.organizationId, g.githubAppId, g.envelope)), Buffer.from(g.privateKeyPem));
    for (const a of org.auditExports ?? []) {
      same(`audit export ${a.exportId}`, Buffer.from(ts.hierarchy.decryptAuditExportCredential(orgKek, org.organizationId, a.exportId, a.envelope)), Buffer.from(a.credential));
      same(`audit export drain ${a.exportId}`, Buffer.from(ts.hierarchy.decryptAuditExportDrainCredential(rootKek, org.organizationId, a.exportId, a.drainEnvelope)), Buffer.from(a.credential));
    }
  }
  for (const k of f.jwtSigningKeys) same(`JWT key ${k.keyId}`, ts.aead.decrypt(rootKek, k.envelope, jwtContext(ref, k.keyId)), Buffer.from(k.privateKeyPem));
  for (const l of f.looseEnvelopes ?? []) {
    same(`loose envelope: ${l.name}`, ts.aead.decrypt(rootKek, l.envelope, { purpose: "kek-canary", installationId: f.installationId }), Buffer.from(l.plaintext, "base64"));
  }
  for (const c of f.canonical ?? []) {
    checked++;
    if (ts.canonical.canonicalJson(c.value) !== c.canonical) fail(`canonical ${JSON.stringify(c.value)}`);
  }
  console.log(`${process.exitCode ? "FAILED" : "ok"}: ${checked} checks against the TypeScript code (${ref ?? "working tree"})`);
}

const args = process.argv.slice(2);
const cmd = args.shift();
let ref;
if (args[0] === "--ref") {
  args.shift();
  ref = args.shift();
}
if ((cmd !== "generate" && cmd !== "verify") || args.length !== 1) {
  console.error("usage: tsfixtures.mjs generate|verify [--ref <git ref>] <file>");
  process.exit(2);
}
await (cmd === "generate" ? generate(ref, args[0]) : verify(ref, args[0]));
