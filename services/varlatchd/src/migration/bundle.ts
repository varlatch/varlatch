// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { Writable } from "node:stream";
import { encodeRow, jsonbKeyOrder, type ColumnType, type Value } from "./canonical.js";
// Imported, not read from beside the module, so the build carries it into dist.
import manifestJson from "./manifest-v1.json" with { type: "json" };

/**
 * The migration's bundle, bundle-v1 (ADR-0059 step 7, internal
 * docs/design/go-step7.md decision 2; the format is varlatchd's,
 * go/server/migration/bundle/BUNDLE.md): one JSON value per line, the
 * header; for each table the manifest copies or transforms, in the
 * manifest's order, a table line and its canonical rows; the digest
 * section (decision 7); the decision section (decision 8); then the end
 * line with the counts and the SHA-256 of every byte before it. The source
 * bundle's direction is `forward`. test/migration/bundle-small.jsonl is
 * varlatchd's own vector, reproduced byte for byte, and no case of
 * test/migration/bundle-refused.json is ever written.
 */

export interface ManifestColumn {
  source: string;
  type: ColumnType;
  target?: string;
  /** Present when the column is never exported: the reason. */
  leftOut?: string;
}

export interface ManifestTable {
  source: string;
  action: "copy" | "transform" | "leftOut";
  columns: ManifestColumn[];
  orderBy?: string[];
  physicalOrder?: boolean;
  precondition?: string;
}

export interface Manifest {
  version: number;
  encoding: string;
  source: { release: string; schema: string; migrations: string[] };
  tables: ManifestTable[];
}

/** The manifest this release exports by (manifest-v1.json, varlatchd's v1.json). */
export function loadManifest(): Manifest {
  return manifestJson as unknown as Manifest;
}

/** The tables a bundle carries: every one the manifest copies or transforms, in its order. */
export function bundleTables(manifest: Manifest): ManifestTable[] {
  return manifest.tables.filter((t) => t.action !== "leftOut");
}

/** Where the writer read from. */
export interface FrozenPoint {
  /** The last audit position, as decimal digits ("0" for none). */
  auditPosition: string;
  /** The PostgreSQL snapshot read from (a forward bundle names one). */
  snapshot: string;
}

/**
 * A table's row count and its rows, each its values in the manifest's
 * column order, read from one snapshot (so the count holds). The rows are
 * streamed: a table is never held whole.
 */
export type RowSource = (table: ManifestTable) => Promise<{ count: number; rows: AsyncIterable<Value[]> }>;

/**
 * The kind of a canonical encoder's refusal, from its message, which can
 * hold the refused value and so is never shown itself.
 */
export function refusalKind(err: unknown): "integer-out-of-range" | "jsonb-number-not-exact" | "not-encodable" {
  const message = err instanceof Error ? err.message : "";
  if (/outside an integer's 32 bits/.test(message)) return "integer-out-of-range";
  if (/jsonb number .* is not exactly a double/.test(message)) return "jsonb-number-not-exact";
  return "not-encodable";
}

export class BundleError extends Error {
  override name = "BundleError";
}

/** Counts the bundle's end line carries. */
export interface BundleSummary {
  tables: number;
  rows: number;
  digests: number;
  decisions: number;
  sha256: string;
}

/** One encrypted item's keyed digest (BUNDLE.md section 3). */
export interface Digest {
  class: string;
  /** The item's envelope context without its purpose; every member a string. */
  ids: Record<string, string>;
  /** HMAC-SHA256 under the run key: 64 lowercase hex digits. */
  hmac: string;
}

/** A Tailnet Context a decision assumes. */
export interface DecisionTailnet {
  tailnet: string;
  nodeId: string;
  tags: string[];
  userLogin: string | null;
}

/** One decision of the old evaluator (BUNDLE.md section 4). */
export interface Decision {
  credential: string;
  state: "active" | "expired" | "revoked";
  organization: string;
  project: string | null;
  environment: string | null;
  action: string;
  tailnet: DecisionTailnet | null;
  allowed: boolean;
  /** The denial's error code; null when allowed. */
  code: string | null;
}

/** The decision section: how many, the moment they were evaluated at (Unix microseconds), and the decisions, streamed. */
export interface DecisionSource {
  count: number;
  at: bigint;
  decisions: AsyncIterable<Decision>;
}

const DIGITS = /^(0|[1-9][0-9]*)$/;
const HMAC = /^[0-9a-f]{64}$/;
const STATES: readonly string[] = ["active", "expired", "revoked"];

/** A digest's ids as the bundle writes them: members in jsonb's order (shorter keys first, then by bytes). */
export function idsText(ids: Readonly<Record<string, string>>): string {
  const keys = Object.keys(ids).sort(jsonbKeyOrder);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(ids[k])}`).join(",")}}`;
}

/** The digests' order: by class, then by the bytes of their ids as written. */
export function compareDigests(a: Digest, b: Digest): number {
  return Buffer.compare(Buffer.from(a.class, "utf8"), Buffer.from(b.class, "utf8")) ||
    Buffer.compare(Buffer.from(idsText(a.ids), "utf8"), Buffer.from(idsText(b.ids), "utf8"));
}

/** A digest's line, exactly as BUNDLE.md writes it; refuses one the format does not allow. */
export function digestLine(d: Digest): string {
  if (!d.class) throw new BundleError("bundle: a digest without its class");
  const keys = Object.keys(d.ids);
  if (keys.length === 0) throw new BundleError(`bundle: a ${d.class} digest without its ids`);
  if (keys.some((k) => typeof d.ids[k] !== "string")) throw new BundleError(`bundle: a ${d.class} digest whose ids are not all strings`);
  if (!HMAC.test(d.hmac)) throw new BundleError(`bundle: a ${d.class} digest that is not 64 lowercase hex digits`);
  return `{"class":${JSON.stringify(d.class)},"ids":${idsText(d.ids)},"hmac":${JSON.stringify(d.hmac)}}`;
}

/** A decision's line, exactly as BUNDLE.md writes it; refuses one the format does not allow. */
export function decisionLine(d: Decision): string {
  if (!d.credential || !d.organization || !d.action) throw new BundleError("bundle: a decision without its credential, organization or action");
  if (!STATES.includes(d.state)) throw new BundleError("bundle: a decision in a state other than active, expired or revoked");
  if (d.project === "" || d.environment === "") throw new BundleError("bundle: a decision naming an empty project or environment");
  if (d.environment !== null && d.project === null) throw new BundleError("bundle: a decision on an environment outside a Project");
  if (d.allowed !== (d.code === null) || d.code === "") throw new BundleError("bundle: a decision allowed with an error code, or denied without one");
  let tailnet = "null";
  if (d.tailnet) {
    const t = d.tailnet;
    if (!t.tailnet || !t.nodeId) throw new BundleError("bundle: a decision's Tailnet Context without its tailnet or node");
    tailnet = `{"tailnet":${JSON.stringify(t.tailnet)},"nodeId":${JSON.stringify(t.nodeId)},"tags":${JSON.stringify(t.tags)},"userLogin":${JSON.stringify(t.userLogin)}}`;
  }
  const orNull = (v: string | null) => (v === null ? "null" : JSON.stringify(v));
  return `{"credential":${JSON.stringify(d.credential)},"state":${JSON.stringify(d.state)},"organization":${JSON.stringify(d.organization)},` +
    `"project":${orNull(d.project)},"environment":${orNull(d.environment)},"action":${JSON.stringify(d.action)},` +
    `"tailnet":${tailnet},"allowed":${d.allowed},"code":${orNull(d.code)}}`;
}

/**
 * Lines to out, each into the running SHA-256. A write error (ENOSPC, say)
 * is held from the moment it happens and fails the next write, or the wait
 * for drain: the writer stops, never hangs.
 */
class LineSink {
  readonly hash = createHash("sha256");
  private failed: Error | null = null;
  private readonly onError = (err: Error) => {
    this.failed ??= err;
  };
  constructor(private readonly out: Writable) {
    // Kept for the stream's life: an error after the last line is held, never unhandled.
    out.on("error", this.onError);
  }
  async line(text: string, hashed = true): Promise<void> {
    if (this.failed) throw this.failed;
    const bytes = Buffer.from(text + "\n", "utf8");
    if (hashed) this.hash.update(bytes);
    if (this.out.write(bytes)) return;
    await new Promise<void>((resolve, reject) => {
      const done = (err?: Error) => {
        this.out.off("drain", onDrain);
        this.out.off("error", onFail);
        if (err) reject(err);
        else resolve();
      };
      const onDrain = () => done();
      const onFail = (err: Error) => done(err);
      if (this.failed) return reject(this.failed);
      this.out.once("drain", onDrain);
      this.out.once("error", onFail);
    });
    if (this.failed) throw this.failed;
  }
}

/**
 * Writes the source bundle to out: header, tables and rows from rows(), the
 * digest section (sorted here, by class then ids, each item once), the
 * decision section, end line. A left-out column (the session's token) is
 * written as null whatever the source holds, so it never leaves the
 * process. The writer stops at the first row it cannot encode, naming the
 * table, never the value, and at any line the format does not allow.
 */
export async function writeBundle(
  out: Writable,
  opts: { manifest: Manifest; frozenPoint: FrozenPoint; rows: RowSource; digests: readonly Digest[]; decisions: DecisionSource },
): Promise<BundleSummary> {
  const { manifest, frozenPoint } = opts;
  if (!DIGITS.test(frozenPoint.auditPosition)) throw new BundleError("bundle: the audit position is not a non-negative integer");
  if (!frozenPoint.snapshot) throw new BundleError("bundle: a forward bundle names the snapshot it read from");
  if (opts.decisions.at < 0n || !Number.isInteger(opts.decisions.count) || opts.decisions.count < 0) throw new BundleError("bundle: a decision section with a negative count or moment");
  const sink = new LineSink(out);
  // Control lines are written member by member, exactly as BUNDLE.md spells them.
  await sink.line(
    `{"bundle":"varlatch-migration","format":1,"manifest":${manifest.version},"encoding":${JSON.stringify(manifest.encoding)},` +
      `"direction":"forward","release":${JSON.stringify(manifest.source.release)},` +
      `"frozenPoint":{"auditPosition":${frozenPoint.auditPosition},"snapshot":${JSON.stringify(frozenPoint.snapshot)}},"sequences":[]}`,
  );
  let tables = 0;
  let total = 0;
  for (const table of bundleTables(manifest)) {
    const types = table.columns.map((c) => c.type);
    const leftOut = table.columns.map((c) => c.leftOut !== undefined);
    const { count, rows } = await opts.rows(table);
    await sink.line(`{"table":${JSON.stringify(table.source)},"rows":${count}}`);
    let written = 0;
    for await (const values of rows) {
      if (values.length !== types.length) throw new BundleError(`bundle: a row of ${table.source} has ${values.length} values, not ${types.length}`);
      const row = values.map((v, i) => (leftOut[i] ? null : v));
      let line: string;
      try {
        line = encodeRow(types, row);
      } catch (err) {
        // The encoder's message can hold the value (a number, say): only its kind leaves.
        throw new BundleError(`bundle: a row of ${table.source} cannot be encoded (${refusalKind(err)}); run the export's preflight to find it`);
      }
      await sink.line(line);
      written++;
    }
    if (written !== count) throw new BundleError(`bundle: ${table.source} counted ${count} rows but read ${written}; the snapshot changed`);
    tables++;
    total += count;
  }

  const digests = [...opts.digests].sort(compareDigests);
  for (let i = 1; i < digests.length; i++) {
    if (compareDigests(digests[i - 1]!, digests[i]!) === 0) throw new BundleError(`bundle: a ${digests[i]!.class} item digested twice`);
  }
  await sink.line(`{"digests":${digests.length}}`);
  for (const d of digests) await sink.line(digestLine(d));

  const { count, at } = opts.decisions;
  await sink.line(`{"decisions":${count},"at":${at}}`);
  let decided = 0;
  for await (const d of opts.decisions.decisions) {
    if (++decided > count) break;
    await sink.line(decisionLine(d));
  }
  if (decided !== count) throw new BundleError(`bundle: the decision section counted ${count} decisions but has ${decided}`);

  const sha256 = sink.hash.digest("hex");
  // The end line is not part of the digest.
  await sink.line(`{"end":{"tables":${tables},"rows":${total},"digests":${digests.length},"decisions":${count},"sha256":"${sha256}"}}`, false);
  return { tables, rows: total, digests: digests.length, decisions: count, sha256 };
}
