// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Backup and key-custody vectors in both directions (ADR-0059 step 4.14):
 * the BEK seal (packages/backup archive.ts) and the passphrase escrow and
 * Shamir split (crypto/escrow.ts), with this server's own code.
 *
 *   go/lib/backup/testdata/ts-vectors.json: archives this code sealed (a
 *   key file BEK and a passphrase BEK, format-2 manifests with their
 *   canaries) and manifests with zod's verdict on each; the Go tests open
 *   the archives and parse the manifests with the same verdicts.
 *   go/server/custody/testdata/ts-vectors.json: escrow blobs and Shamir
 *   splits this code made, and the refusals with this code's messages; the
 *   Go tests restore, combine and refuse the same.
 *
 * Every run opens the committed files here too. With
 * VARLATCH_GO_BACKUP_VECTORS and VARLATCH_GO_CUSTODY_VECTORS (files the Go
 * tests write: go test ./lib/backup -run TestGoVectors -args
 * -write-go-vectors=<file>, and ./server/custody likewise), this code
 * opens what Go sealed, restores what Go escrowed and combines what Go
 * split (go.yml, go-binary job).
 *
 * After a change, regenerate:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-backup-vectors.test.ts
 */
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkKeys, describeComponents, EMBEDDED_RELEASE, manifestSchema, openArchive, sealArchive, type Bek, type Manifest } from "@varlatch/backup";
import { createCanary } from "../src/crypto/canary.js";
import { combineKek, exportKekEscrow, restoreKekEscrow, splitKek, type EscrowBlob } from "../src/crypto/escrow.js";

const BACKUP_FILE = new URL("../../../go/lib/backup/testdata/ts-vectors.json", import.meta.url);
const CUSTODY_FILE = new URL("../../../go/server/custody/testdata/ts-vectors.json", import.meta.url);
const COMMENT = "Written by services/varlatchd/test/go-backup-vectors.test.ts with the TypeScript server's own code; do not edit.";

interface ArchiveVector {
  name: string;
  bek: { kind: "key" | "passphrase"; material: string }; // key: hex; passphrase: the text
  rootKek: string; // hex, key version 1
  archive: string; // base64
  manifest: Manifest;
  components: Record<string, string>; // base64
}
interface ManifestVector { name: string; json: string; valid: boolean }
interface BackupVectors { comment: string; archives: ArchiveVector[]; manifests: ManifestVector[] }
interface CustodyVectors {
  comment: string;
  escrow: { name: string; passphrase: string; kek: string; blob: EscrowBlob }[];
  escrowRefusals: { name: string; passphrase: string; blob: unknown; message: string }[];
  shamir: { name: string; kek: string; shares: number; threshold: number; split: string[]; fingerprint: string }[];
  combineRefusals: { name: string; shares: string[]; message: string }[];
}

const bekOf = (b: ArchiveVector["bek"]): Bek =>
  b.kind === "key" ? { kind: "key", material: Buffer.from(b.material, "hex") } : { kind: "passphrase", material: Buffer.from(b.material, "utf8") };
const message = (f: () => unknown) => {
  try {
    f();
    return "(no error)";
  } catch (e) {
    return (e as Error).message;
  }
};

/** Opens an archive as restore does, and checks it against its vector. */
async function openVector(v: ArchiveVector) {
  const dir = mkdtempSync(join(tmpdir(), "backup-vector-"));
  try {
    const path = join(dir, "archive");
    writeFileSync(path, Buffer.from(v.archive, "base64"));
    await openArchive(path, bekOf(v.bek), async (manifest, unpacked) => {
      expect(manifest).toEqual(v.manifest);
      expect(checkKeys(manifest, new Map([[1, Buffer.from(v.rootKek, "hex")]]))).toBe(true);
      expect(checkKeys(manifest, new Map([[1, randomBytes(32)]]))).toBe(false);
      for (const [name, data] of Object.entries(v.components)) expect(readFileSync(join(unpacked, name)).toString("base64"), `${v.name}: ${name}`).toBe(data);
    }, dir);
    // A changed byte, or another BEK, is refused.
    const bytes = Buffer.from(v.archive, "base64");
    bytes[bytes.length - 20]! ^= 1;
    writeFileSync(path, bytes);
    await expect(openArchive(path, bekOf(v.bek), async () => null, dir)).rejects.toThrow(/integrity/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function makeBackupVectors(): Promise<BackupVectors> {
  const archives: ArchiveVector[] = [];
  for (const [name, bek, size] of [
    ["a key file BEK", { kind: "key", material: randomBytes(32).toString("hex") }, 70_001],
    ["a passphrase BEK", { kind: "passphrase", material: "correct horse battery staple" }, 5],
    ["an empty component", { kind: "passphrase", material: "an empty one, sealed" }, 0],
  ] as const) {
    const dir = mkdtempSync(join(tmpdir(), "backup-vector-"));
    try {
      const data = randomBytes(size);
      writeFileSync(join(dir, "secret-plane.dump"), data);
      const rootKek = randomBytes(32);
      const manifest: Manifest = {
        formatVersion: 2, archiveId: randomUUID(), installationId: "inst_vectors", createdAt: new Date().toISOString(),
        release: EMBEDDED_RELEASE, requiredKeyVersions: [1],
        canaries: [{ version: 1, envelope: createCanary(rootKek, "inst_vectors") }],
        components: await describeComponents(dir, 2),
      };
      const out = join(dir, "archive");
      await sealArchive(dir, manifest, bekOf(bek), out);
      archives.push({ name, bek, rootKek: rootKek.toString("hex"), archive: readFileSync(out).toString("base64"), manifest, components: { "secret-plane.dump": data.toString("base64") } });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  // Manifests, each with zod's verdict (formats 1 and 2: the TypeScript schema's).
  const base = archives[0]!.manifest;
  const three = {
    ...base, formatVersion: 1,
    components: ["secret-plane.dump", "application-plane.dump", "convex-storage.tar"].map((n) => ({ name: n, bytes: 1, sha256: "a".repeat(64) })),
  };
  const variants: [string, unknown][] = [
    ["valid", base],
    ["format 1 with its three components", three],
    ["format 1 with one component", { ...three, components: three.components.slice(0, 1) }],
    ["format 2 with format 1's components", { ...base, components: three.components }],
    ["format 2 with another component's name", { ...base, components: [{ ...base.components[0]!, name: "application-plane.dump" }] }],
    ["an unknown member", { ...base, extra: true }],
    ["no createdAt", (({ createdAt: _c, ...m }) => m)(base)],
    ["formatVersion as a string", { ...base, formatVersion: "2" }],
    ["formatVersion 3 (Go's)", { ...base, formatVersion: 3 }],
    ["an upper-case archive id", { ...base, archiveId: base.archiveId.toUpperCase() }],
    ["an archive id of version 9", { ...base, archiveId: "0b1c2d3e-0000-9000-8000-000000000000" }],
    ["the nil archive id", { ...base, archiveId: "00000000-0000-0000-0000-000000000000" }],
    ["an installation id without inst_", { ...base, installationId: "vectors" }],
    ["createdAt with an offset", { ...base, createdAt: "2026-11-15T12:00:00+01:00" }],
    ["createdAt without seconds", { ...base, createdAt: "2026-11-15T12:00Z" }],
    ["createdAt with nine fraction digits", { ...base, createdAt: "2026-11-15T12:00:00.123456789Z" }],
    ["createdAt on February 29 of 2100", { ...base, createdAt: "2100-02-29T12:00:00Z" }],
    ["a release with an unknown member", { ...base, release: { ...base.release, extra: 1 } }],
    ["a release of schema version 2", { ...base, release: { ...base.release, schemaVersion: 2 } }],
    ["a release with api major 0", { ...base, release: { ...base.release, apiMajor: 0 } }],
    ["a release with migration version -1", { ...base, release: { ...base.release, migrationVersion: -1 } }],
    ["a release without restore sources", { ...base, release: (({ supportedRestoreSources: _s, ...r }) => r)(base.release) }],
    ["a release with an empty version", { ...base, release: { ...base.release, version: "" } }],
    ["no key versions", { ...base, requiredKeyVersions: [] }],
    ["a key version twice", { ...base, requiredKeyVersions: [1, 1], canaries: [base.canaries[0], base.canaries[0]] }],
    ["two key versions, one canary", { ...base, requiredKeyVersions: [1, 2] }],
    ["key version 0", { ...base, requiredKeyVersions: [0], canaries: [{ ...base.canaries[0]!, version: 0 }] }],
    ["a canary of another version", { ...base, canaries: [{ ...base.canaries[0]!, version: 2 }] }],
    ["a canary with an unknown member", { ...base, canaries: [{ ...base.canaries[0]!, extra: 1 }] }],
    ["an envelope with an unknown member", { ...base, canaries: [{ ...base.canaries[0]!, envelope: { ...base.canaries[0]!.envelope, extra: 1 } }] }],
    ["an envelope nonce of 33 characters", { ...base, canaries: [{ ...base.canaries[0]!, envelope: { ...base.canaries[0]!.envelope, nonce: "n".repeat(33) } }] }],
    ["an envelope of format 2", { ...base, canaries: [{ ...base.canaries[0]!, envelope: { ...base.canaries[0]!.envelope, formatVersion: 2 } }] }],
    ["no components", { ...base, components: [] }],
    ["negative bytes", { ...base, components: [{ ...base.components[0]!, bytes: -1 }] }],
    ["fractional bytes", { ...base, components: [{ ...base.components[0]!, bytes: 1.5 }] }],
    ["an upper-case checksum", { ...base, components: [{ ...base.components[0]!, sha256: "A".repeat(64) }] }],
    ["a component with an unknown member", { ...base, components: [{ ...base.components[0]!, extra: 1 }] }],
    ["an array", [base]],
    ["null", null],
  ];
  const manifests: ManifestVector[] = variants.map(([name, value]) => ({ name, json: JSON.stringify(value), valid: manifestSchema.safeParse(value).success }));
  // Number spellings JSON.stringify never writes.
  const text = JSON.stringify(base);
  for (const [name, json] of [
    ["bytes as 1.0", text.replace(`"bytes":${base.components[0]!.bytes}`, `"bytes":${base.components[0]!.bytes}.0`)],
    ["bytes as an exponent", text.replace(`"bytes":${base.components[0]!.bytes}`, `"bytes":7.0001e4`)],
    ["bytes beyond the safe integers", text.replace(`"bytes":${base.components[0]!.bytes}`, `"bytes":9007199254740993`)],
    ["a duplicate member, the last one valid", text.replace(`"formatVersion":2`, `"formatVersion":7,"formatVersion":2`)],
  ] as const) {
    manifests.push({ name, json, valid: manifestSchema.safeParse(JSON.parse(json)).success });
  }
  return { comment: COMMENT, archives, manifests };
}

function makeCustodyVectors(): CustodyVectors {
  const escrow = [
    ["an escrow", "a long passphrase here"],
    ["a passphrase beyond ASCII", "pässphrase ✓ 😀 long"],
  ].map(([name, passphrase]) => {
    const kek = randomBytes(32);
    return { name: name!, passphrase: passphrase!, kek: kek.toString("hex"), blob: exportKekEscrow(kek, passphrase!) };
  });
  const blob = escrow[0]!.blob;
  const escrowRefusals = [
    ["a wrong passphrase", "another passphrase", blob],
    ["another kind", escrow[0]!.passphrase, { ...blob, kind: "something-else" }],
    ["format 2", escrow[0]!.passphrase, { ...blob, formatVersion: 2 }],
    ["another KDF", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, algorithm: "argon2" } }],
    ["a weakened N", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, N: 1 << 10 } }],
    ["a weakened r", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, r: 4 } }],
    ["a changed salt", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, salt: randomBytes(16).toString("base64") } }],
    ["an N not a power of two", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, N: 3 << 15 } }],
    // Last: OpenSSL keeps this error queued, and a later scrypt failure in
    // the same process would report it.
    ["a raised N", escrow[0]!.passphrase, { ...blob, kdf: { ...blob.kdf, N: 1 << 18 } }],
  ].map(([name, passphrase, b]) => ({ name: name as string, passphrase: passphrase as string, blob: b, message: message(() => restoreKekEscrow(b as EscrowBlob, passphrase as string)) }));
  const shamir = ([[2, 2], [3, 2], [5, 3], [5, 5], [255, 2], [255, 255]] as const).map(([n, k]) => {
    const kek = randomBytes(32);
    const { shares, fingerprint } = splitKek(kek, { shares: n, threshold: k });
    return { name: `${k} of ${n}`, kek: kek.toString("hex"), shares: n, threshold: k, split: shares, fingerprint };
  });
  const s = shamir[2]!.split; // 3 of 5
  const other = shamir[1]!.split; // 2 of 3, another key
  const tweak = (share: string) => {
    const p = share.split(".");
    const y = Buffer.from(p[3]!, "base64url");
    y[0]! ^= 1;
    return [p[0], p[1], p[2], y.toString("base64url"), p[4]].join(".");
  };
  const combineRefusals = [
    ["none", []],
    ["too few", s.slice(0, 2)],
    ["a share twice", [s[0]!, s[0]!, s[1]!]],
    ["mixed splits", [s[0]!, s[1]!, other[0]!]],
    ["a changed share", [tweak(s[0]!), s[1]!, s[2]!]],
    ["a malformed share", ["vlks1.1.3.abc", s[1]!, s[2]!]],
    ["another prefix", [s[0]!.replace("vlks1", "vlks2"), s[1]!, s[2]!]],
    ["x 0", [s[0]!.replace(/^vlks1\.1\./, "vlks1.0."), s[1]!, s[2]!]],
    ["threshold 1", [s[0]!.replace(/^vlks1\.1\.3\./, "vlks1.1.1.")]],
    ["an upper-case fingerprint", [s[0]!.replace(/\.[0-9a-f]{8}$/, (m) => m.toUpperCase()), s[1]!, s[2]!]],
    ["a huge threshold", [s[0]!, s[1]!, s[2]!].map((x) => x.replace(/^(vlks1\.\d+)\.3\./, "$1.1e300."))],
  ].map(([name, shares]) => ({ name: name as string, shares: shares as string[], message: message(() => combineKek(shares as string[])) }));
  return { comment: COMMENT, escrow, escrowRefusals, shamir, combineRefusals };
}

function checkCustody(v: CustodyVectors) {
  for (const e of v.escrow) expect(restoreKekEscrow(e.blob, e.passphrase).toString("hex"), e.name).toBe(e.kek);
  for (const r of v.escrowRefusals) expect(message(() => restoreKekEscrow(r.blob as EscrowBlob, r.passphrase)), r.name).toBe(r.message);
  for (const sh of v.shamir) {
    expect(sh.split, sh.name).toHaveLength(sh.shares);
    // Any threshold of them, in any order: the first ones, the last ones reversed.
    expect(combineKek(sh.split.slice(0, sh.threshold)).toString("hex"), sh.name).toBe(sh.kek);
    expect(combineKek(sh.split.slice(-sh.threshold).reverse()).toString("hex"), sh.name).toBe(sh.kek);
    expect(sh.split.every((x) => x.endsWith(`.${sh.fingerprint}`))).toBe(true);
  }
  for (const r of v.combineRefusals) expect(message(() => combineKek(r.shares)), r.name).toBe(r.message);
}

describe.skipIf(process.env.VARLATCH_WRITE_GO_VECTORS !== "1")("writing the backup and custody vectors", () => {
  it("writes both files", async () => {
    writeFileSync(BACKUP_FILE, JSON.stringify(await makeBackupVectors(), null, 2) + "\n");
    writeFileSync(CUSTODY_FILE, JSON.stringify(makeCustodyVectors(), null, 2) + "\n");
  }, 120_000);
});

describe("the backup and custody vectors are this server's", () => {
  it("ts-vectors.json (backup): the archives open, the manifests have zod's verdicts", async () => {
    const v = JSON.parse(readFileSync(BACKUP_FILE, "utf8")) as BackupVectors;
    expect(v.archives.length).toBeGreaterThanOrEqual(3);
    for (const a of v.archives) await openVector(a);
    for (const m of v.manifests) expect(manifestSchema.safeParse(JSON.parse(m.json)).success, m.name).toBe(m.valid);
  }, 120_000);

  it("ts-vectors.json (custody): escrows restore, splits combine, refusals keep their messages", () => {
    checkCustody(JSON.parse(readFileSync(CUSTODY_FILE, "utf8")) as CustodyVectors);
  }, 120_000);

  const goBackup = process.env.VARLATCH_GO_BACKUP_VECTORS;
  it.skipIf(!goBackup)("archives Go sealed open here", async () => {
    if (!existsSync(goBackup!)) throw new Error(`${goBackup}: no such file`);
    const v = JSON.parse(readFileSync(goBackup!, "utf8")) as BackupVectors;
    expect(v.comment).toMatch(/Go/);
    expect(v.archives.length).toBeGreaterThanOrEqual(3);
    for (const a of v.archives) await openVector(a);
  }, 120_000);

  const goCustody = process.env.VARLATCH_GO_CUSTODY_VECTORS;
  it.skipIf(!goCustody)("escrows Go made restore here, and Go's splits combine", () => {
    if (!existsSync(goCustody!)) throw new Error(`${goCustody}: no such file`);
    const v = JSON.parse(readFileSync(goCustody!, "utf8")) as CustodyVectors;
    expect(v.comment).toMatch(/Go/);
    checkCustody(v);
  }, 120_000);
});
