// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { Writable } from "node:stream";
import { encodeRow, type ColumnType, type Value } from "./canonical.js";
// Imported, not read from beside the module, so the build carries it into dist.
import manifestJson from "./manifest-v1.json" with { type: "json" };

/**
 * The migration's bundle, bundle-v1 (ADR-0059 step 7, internal
 * docs/design/go-step7.md decision 2; the format is varlatchd's,
 * go/server/migration/bundle/BUNDLE.md): one JSON value per line, the
 * header, then for each table the manifest copies or transforms, in the
 * manifest's order, a table line and its canonical rows, then the end line
 * with the counts and the SHA-256 of every byte before it. The source
 * bundle's direction is `forward`. test/migration/bundle-small.jsonl is
 * varlatchd's own vector, reproduced byte for byte.
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
  sha256: string;
}

const DIGITS = /^(0|[1-9][0-9]*)$/;

/**
 * Writes the source bundle to out: header, tables and rows from rows(), end
 * line. A left-out column (the session's token) is written as null whatever
 * the source holds, so it never leaves the process. The writer stops at the
 * first row it cannot encode, naming the table and column, never the value.
 */
export async function writeBundle(
  out: Writable,
  opts: { manifest: Manifest; frozenPoint: FrozenPoint; rows: RowSource },
): Promise<BundleSummary> {
  const { manifest, frozenPoint } = opts;
  if (!DIGITS.test(frozenPoint.auditPosition)) throw new BundleError("bundle: the audit position is not a non-negative integer");
  if (!frozenPoint.snapshot) throw new BundleError("bundle: a forward bundle names the snapshot it read from");
  const hash = createHash("sha256");
  const write = async (line: string) => {
    const bytes = Buffer.from(line + "\n", "utf8");
    hash.update(bytes);
    if (!out.write(bytes)) await new Promise<void>((resolve, reject) => {
      out.once("drain", resolve);
      out.once("error", reject);
    });
  };
  // Control lines are written member by member, exactly as BUNDLE.md spells them.
  await write(
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
    await write(`{"table":${JSON.stringify(table.source)},"rows":${count}}`);
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
      await write(line);
      written++;
    }
    if (written !== count) throw new BundleError(`bundle: ${table.source} counted ${count} rows but read ${written}; the snapshot changed`);
    tables++;
    total += count;
  }
  const sha256 = hash.digest("hex");
  // The end line is not part of the digest.
  const end = Buffer.from(`{"end":{"tables":${tables},"rows":${total},"sha256":"${sha256}"}}\n`, "utf8");
  if (!out.write(end)) await new Promise<void>((resolve) => out.once("drain", resolve));
  return { tables, rows: total, sha256 };
}
