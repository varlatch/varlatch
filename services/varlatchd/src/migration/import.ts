// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { Envelope } from "../crypto/aead.js";
import { verifyKekAgainstCanary } from "../crypto/canary.js";
import { migrationStatus, runMigrations } from "../db/migrate.js";
import { manifestMigrations } from "../db/migrations/index.js";
import type { PoolQuerier } from "../db/tx.js";
import { bundleTables, compareDigests, decisionLine, digestLine, loadManifest, type Decision, type Digest, type Manifest, type ManifestTable } from "./bundle.js";
import { decodeRow, type ColumnType, type Value } from "./canonical.js";

/**
 * `varlatchd admin migration import` (ADR-0059 step 7, go-step7 slice 7.2c,
 * decision 16): the TypeScript release starts on a database rebuilt from the
 * reverse bundle varlatchd's `admin migrate export --reverse` wrote.
 *
 * In order:
 *   1. The whole bundle is read and verified before anything is written:
 *      the header (bundle-v1, this manifest, `reverse`), every table in the
 *      manifest's order with its count, every row canonical, no browser
 *      session (a reverse bundle has none: people sign in again, and a
 *      session's token never travels), no value in a column the manifest
 *      leaves out, the digest and decision sections well formed (empty until
 *      the reverse checks, slice 7.6), the end line's counts and SHA-256,
 *      nothing after it. The last audit position is the header's frozen
 *      point. A bundle that fails is refused whole.
 *   2. The database must be fresh: nothing in it, or a schema of this line
 *      (the migrate job may have built it, at any level) holding no row but
 *      what its migrations seed. That is decided before any migration runs,
 *      so an older database holding rows is refused as it is, never moved
 *      forward first. The schema is then built at this release's level,
 *      whose migrations are the manifest's, and holds no sequence (every id
 *      is the application's; one that appears would need restoring). A line
 *      longer than varlatchd's reader takes (64 MiB) is refused unread.
 *   3. One transaction loads every row as the bundle holds it, read a second
 *      time, which must be byte for byte the first (its SHA-256):
 *      - as decision 16's replica load does, nothing is renumbered or
 *        recomputed: the user triggers are off for the load (so
 *        assign_audit_position keeps event_order), and the foreign keys
 *        are dropped and added again after it, which checks every one.
 *        This needs only the owning role the migrate job runs as, not a
 *        superuser's session_replication_role;
 *      - `requirements` is inserted in the bundle's order, which is its
 *        physical order;
 *      - `audit_position` is set to the last position, so the next event
 *        follows it; the audit cursors are rows and keep their places;
 *      - the Root KEK must open the installation's canary;
 *      then it commits. A refusal at any point rolls the load back: the
 *      database holds the schema and no row, and the import can run again.
 *
 * The Application Plane (Convex) is rebuilt, not loaded, as after a restore:
 * the host resets it and deploys this release's functions, and the mirror
 * publisher publishes every read model from the rebuilt database.
 *
 * Nothing it reports holds a value of a row: refusals name the line, the
 * table and the column.
 */

export class ImportRefused extends Error {
  override name = "ImportRefused";
}

/** What a verified reverse bundle holds. */
export interface ReverseBundle {
  release: string;
  /** The last audit position: installation.migrated's. */
  auditPosition: string;
  tables: number;
  rows: number;
  perTable: Record<string, number>;
  digests: number;
  decisions: number;
  sha256: string;
  installationId: string;
  /** The installation's KEK canary, as its row holds it. */
  canary: Envelope;
  auditEvents: number;
}

export interface ImportResult {
  bundle: ReverseBundle;
  /** The database already held this bundle (an import that committed, then stopped before lifting the gate). */
  alreadyImported: boolean;
}

/** The tables migrations seed with rows, and how many each may hold before the load. */
const SEEDED: Readonly<Record<string, number>> = { exposure_backfill: 1 };
/** Tables of the manifest that are this schema's own bookkeeping, never data the import checks for emptiness. */
const BOOKKEEPING = new Set(["audit_position", "varlatch_migrations"]);

/** A bundle's line holds fewer bytes than this: varlatchd's reader's limit (bundle.go maxLine). */
export const MAX_LINE = 64 << 20;

/**
 * The advisory lock one import holds on its database from the first look
 * at it to the commit, so a second import refuses cleanly instead of
 * racing it through the schema's build.
 */
export const IMPORT_LOCK = 7_302_003_001n;

/**
 * The bundle's lines, each without its "\n"; a last line without one is the
 * bundle cut short, and a line past {@link MAX_LINE} is refused before it is
 * held whole. A line's pieces are joined once, when it ends.
 */
async function* readLines(path: string): AsyncGenerator<Buffer> {
  let pending: Buffer[] = [];
  let pendingLength = 0;
  const tooLong = () => new ImportRefused(`the bundle holds a line of ${MAX_LINE >> 20} MiB or more, which no bundle-v1 writer writes`);
  for await (const chunk of createReadStream(path) as AsyncIterable<Buffer>) {
    let start = 0;
    let nl: number;
    while ((nl = chunk.indexOf(0x0a, start)) !== -1) {
      const length = pendingLength + (nl - start);
      if (length >= MAX_LINE) throw tooLong();
      yield pending.length > 0 ? Buffer.concat([...pending, chunk.subarray(start, nl)], length) : chunk.subarray(start, nl);
      pending = [];
      pendingLength = 0;
      start = nl + 1;
    }
    if (start < chunk.length) {
      pending.push(chunk.subarray(start));
      pendingLength += chunk.length - start;
      if (pendingLength >= MAX_LINE) throw tooLong();
    }
  }
  if (pendingLength > 0) throw new ImportRefused("the bundle is cut short: its last line does not end");
}

const COUNT = "(0|[1-9][0-9]*)";

/**
 * Reads and verifies a reverse bundle, handing each row to onRow (the load)
 * as it goes. Nothing is trusted until it returns: the caller that writes
 * runs inside a transaction it rolls back on a refusal.
 */
export async function readReverseBundle(
  path: string,
  manifest: Manifest,
  onRow?: (table: ManifestTable, values: Value[]) => Promise<void>,
): Promise<ReverseBundle> {
  const hash = createHash("sha256");
  const lines = readLines(path);
  let lineNo = 0;
  const next = async (what: string): Promise<string> => {
    const r = await lines.next();
    if (r.done) throw new ImportRefused(`the bundle is cut short: ${what} was due at line ${lineNo + 1}`);
    lineNo++;
    const bytes = r.value;
    if (bytes.length === 0) throw new ImportRefused(`line ${lineNo} is blank`);
    if (bytes.includes(0x0d)) throw new ImportRefused(`line ${lineNo} holds a carriage return: bundle lines end in "\\n" alone`);
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes)) throw new ImportRefused(`line ${lineNo} is not UTF-8`);
    return text;
  };
  const hashed = (text: string) => hash.update(text + "\n", "utf8");

  // The header.
  const header = await next("the header");
  let h: Record<string, unknown>;
  try {
    h = JSON.parse(header) as Record<string, unknown>;
  } catch {
    throw new ImportRefused("line 1 is not a bundle's header");
  }
  if (h.bundle !== "varlatch-migration" || h.format !== 1) throw new ImportRefused("line 1 is not a bundle-v1 header");
  if (h.direction === "forward") throw new ImportRefused("this is a forward bundle; the import takes the reverse bundle varlatchd admin migrate export --reverse writes");
  if (h.manifest !== manifest.version || h.encoding !== manifest.encoding) {
    throw new ImportRefused(`the bundle was written by manifest ${String(h.manifest)} (${String(h.encoding)}); this release reads manifest ${manifest.version} (${manifest.encoding})`);
  }
  const release = typeof h.release === "string" && h.release.length > 0 && h.release.length <= 100 ? h.release : null;
  const position = new RegExp(`"frozenPoint":\\{"auditPosition":${COUNT}\\}`).exec(header)?.[1];
  const expected = release !== null && position !== undefined
    ? `{"bundle":"varlatch-migration","format":1,"manifest":${manifest.version},"encoding":${JSON.stringify(manifest.encoding)},` +
      `"direction":"reverse","release":${JSON.stringify(release)},"frozenPoint":{"auditPosition":${position}},"sequences":[]}`
    : null;
  if (header !== expected) throw new ImportRefused("line 1 is not a reverse bundle's header as bundle-v1 writes it (members, their order, the frozen point, no sequence)");
  hashed(header);

  // The tables.
  const perTable: Record<string, number> = {};
  let rows = 0;
  let installationId: string | null = null;
  let canary: Envelope | null = null;
  let auditEvents = 0;
  let lastPosition = 0n;
  for (const table of bundleTables(manifest)) {
    const line = await next(`${table.source}'s table line`);
    const m = new RegExp(`^\\{"table":"([a-z_]+)","rows":${COUNT}\\}$`).exec(line);
    if (!m || m[1] !== table.source) throw new ImportRefused(`line ${lineNo}: ${table.source}'s table line was due (the tables come in the manifest's order, each once)`);
    hashed(line);
    const count = Number(m[2]);
    if (!Number.isSafeInteger(count)) throw new ImportRefused(`line ${lineNo}: ${table.source}'s row count is out of range`);
    if (table.source === "session" && count > 0) {
      throw new ImportRefused("the bundle carries browser sessions: a reverse bundle has none (every session ends and people sign in again), and a session's token never travels");
    }
    const types = table.columns.map((c) => c.type as ColumnType);
    const leftOut = table.columns.flatMap((c, i) => (c.leftOut !== undefined ? [i] : []));
    const id = table.columns.findIndex((c) => c.source === "id");
    const order = table.columns.findIndex((c) => c.source === "event_order");
    const kekCanary = table.columns.findIndex((c) => c.source === "kek_canary");
    for (let i = 0; i < count; i++) {
      const row = await next(`row ${i + 1} of ${table.source}`);
      let values: Value[];
      try {
        values = decodeRow(types, row);
      } catch {
        // The decoder's message names a column; the row's text is never shown.
        throw new ImportRefused(`line ${lineNo}: row ${i + 1} of ${table.source} is not a canonical row of its columns`);
      }
      for (const c of leftOut) {
        if (values[c] !== null) throw new ImportRefused(`line ${lineNo}: row ${i + 1} of ${table.source} carries ${table.columns[c]!.source}, which the manifest leaves out`);
      }
      hashed(row);
      if (table.source === "installation") {
        installationId = String(values[id]);
        try {
          canary = JSON.parse(String(values[kekCanary])) as Envelope;
        } catch {
          throw new ImportRefused(`line ${lineNo}: the installation's KEK canary is not an envelope`);
        }
      }
      if (table.source === "audit_events") {
        auditEvents++;
        const p = values[order] as bigint;
        if (p > lastPosition) lastPosition = p;
      }
      await onRow?.(table, values);
    }
    perTable[table.source] = count;
    rows += count;
  }

  // The digest section: well formed and in order (the reverse checks fill it, slice 7.6).
  const digestsLine = await next("the digest section");
  const dm = new RegExp(`^\\{"digests":${COUNT}\\}$`).exec(digestsLine);
  if (!dm) throw new ImportRefused(`line ${lineNo}: the digest section was due`);
  hashed(digestsLine);
  const digests = Number(dm[1]);
  let previous: Digest | null = null;
  for (let i = 0; i < digests; i++) {
    const line = await next(`digest ${i + 1}`);
    let d: Digest;
    try {
      d = JSON.parse(line) as Digest;
      if (digestLine(d) !== line) throw new Error();
    } catch {
      throw new ImportRefused(`line ${lineNo}: digest ${i + 1} is not a digest line as bundle-v1 writes it`);
    }
    if (previous && compareDigests(previous, d) >= 0) throw new ImportRefused(`line ${lineNo}: digest ${i + 1} is out of order, or an item digested twice`);
    previous = d;
    hashed(line);
  }

  // The decision section.
  const decisionsLine = await next("the decision section");
  const em = new RegExp(`^\\{"decisions":${COUNT},"at":${COUNT}\\}$`).exec(decisionsLine);
  if (!em) throw new ImportRefused(`line ${lineNo}: the decision section was due`);
  hashed(decisionsLine);
  const decisions = Number(em[1]);
  for (let i = 0; i < decisions; i++) {
    const line = await next(`decision ${i + 1}`);
    try {
      if (decisionLine(JSON.parse(line) as Decision) !== line) throw new Error();
    } catch {
      throw new ImportRefused(`line ${lineNo}: decision ${i + 1} is not a decision line as bundle-v1 writes it`);
    }
    hashed(line);
  }

  // The end line, and nothing after it.
  const sha256 = hash.digest("hex");
  const end = await next("the end line");
  const tables = bundleTables(manifest).length;
  if (end !== `{"end":{"tables":${tables},"rows":${rows},"digests":${digests},"decisions":${decisions},"sha256":"${sha256}"}}`) {
    throw new ImportRefused(`line ${lineNo}: the end line does not hold: its counts or its SHA-256 are not the bundle's (damaged, or cut short)`);
  }
  try {
    if (!(await lines.next()).done) throw new ImportRefused("the bundle holds text after its end line");
  } catch (err) {
    if (err instanceof ImportRefused && err.message.startsWith("the bundle is cut short")) throw new ImportRefused("the bundle holds text after its end line");
    throw err;
  }

  if (installationId === null || canary === null || perTable.installation !== 1) throw new ImportRefused("the bundle holds no installation, or more than one");
  if (lastPosition.toString() !== position) {
    throw new ImportRefused(`the bundle's last audit position is ${lastPosition}, not its header's ${position}`);
  }
  return { release: release!, auditPosition: position!, tables, rows, perTable, digests, decisions, sha256, installationId, canary, auditEvents };
}

const quoteIdent = (name: string) => `"${name.replaceAll('"', '""')}"`;

/** A column's placeholder: its parameter cast to its type; a timestamp from its microseconds, exactly. */
function placeholder(type: ColumnType, n: number): string {
  switch (type) {
    case "timestamp with time zone":
      return `$${n}::timestamptz`;
    case "text[]":
      return `$${n}::text[]`;
    default:
      return `$${n}::${type}`;
  }
}

/** Microseconds since the epoch as ISO 8601 text PostgreSQL reads exactly. */
function timestampText(us: bigint): string {
  let seconds = us / 1_000_000n;
  let micros = us % 1_000_000n;
  if (micros < 0n) {
    micros += 1_000_000n;
    seconds -= 1n;
  }
  const whole = new Date(Number(seconds) * 1000).toISOString().replace(/\.000Z$/, "");
  return `${whole}.${micros.toString().padStart(6, "0")}Z`;
}

function parameter(type: ColumnType, v: Value): unknown {
  if (v === null) return null;
  switch (type) {
    case "timestamp with time zone":
      return timestampText(v as bigint);
    case "integer":
    case "bigint":
      return (v as bigint).toString();
    default:
      return v;
  }
}

/** Rows to one table, a batch at a time, in the order they come. */
class Loader {
  private table: ManifestTable | null = null;
  private batch: Value[][] = [];
  constructor(private readonly client: Awaited<ReturnType<PoolQuerier["connect"]>>) {}
  async row(table: ManifestTable, values: Value[]): Promise<void> {
    if (this.table !== table) await this.flush();
    this.table = table;
    this.batch.push(values);
    if (this.batch.length * table.columns.length >= 20_000 || this.batch.length >= 500) await this.flush();
  }
  /**
   * The one write of a table named at run time (every table the manifest
   * copies): the caller graph's catalogue lists it as such, reached from
   * the host command only (test/admin-step-up-catalogue.test.ts WRITERS).
   */
  async flush(): Promise<void> {
    const table = this.table;
    if (!table || this.batch.length === 0) return;
    const types = table.columns.map((c) => c.type as ColumnType);
    const params: unknown[] = [];
    const tuples = this.batch.map((values) => `(${values.map((v, i) => {
      params.push(parameter(types[i]!, v));
      return placeholder(types[i]!, params.length);
    }).join(", ")})`);
    this.batch = [];
    try {
      await this.client.query(
        `INSERT INTO ${quoteIdent(table.source)} (${table.columns.map((c) => quoteIdent(c.source)).join(", ")}) VALUES ${tuples.join(", ")}`,
        params,
      );
    } catch {
      // PostgreSQL's message can quote a value: only the table is named.
      throw new ImportRefused(`the rows of ${table.source} do not load: a row breaks one of its constraints (a check, a unique key or a type)`);
    }
  }
}

/**
 * This release's migrations as the manifest names them: those of indexes
 * only aside (manifestMigrations), which the schema the import builds has
 * too, and which change no table or column the bundle fills.
 */
function releaseMigrations(): string[] {
  return manifestMigrations();
}

export async function importReverse(db: PoolQuerier, opts: { path: string; rootKek: Buffer }): Promise<ImportResult> {
  const manifest = loadManifest();
  if (JSON.stringify(releaseMigrations()) !== JSON.stringify(manifest.source.migrations)) {
    throw new ImportRefused("this release's migrations are not the manifest's: the import builds the schema the bundle was written for, and this release builds another");
  }
  // 1. Verified whole, before anything is written; the Root KEK too.
  const bundle = await readReverseBundle(opts.path, manifest);
  if (!verifyKekAgainstCanary(opts.rootKek, bundle.canary, bundle.installationId)) {
    throw new ImportRefused("the Root KEK does not open the installation's canary: this is not the installation's key file; nothing was loaded");
  }

  const client = await db.connect();
  let locked = false;
  try {
    locked = ((await client.query("SELECT pg_try_advisory_lock($1::bigint) AS ok", [IMPORT_LOCK.toString()])).rows[0] as { ok: boolean }).ok;
    if (!locked) throw new ImportRefused("another import is running on this database; nothing was loaded");
    // 2. A fresh database, at this release's schema. Whether it is fresh is
    // decided before any migration runs: an older schema holding rows is
    // refused as it is, never moved forward first (its own release could
    // not start on it after).
    const status = await migrationStatus(client);
    if (status.unknownApplied.length > 0) throw new ImportRefused("the database holds a newer schema than this release: the import builds a fresh database");
    if (status.appliedIds.length === 0) {
      const present = (await client.query(
        `SELECT count(*)::int AS n FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p', 'v', 'm', 'S', 'f')`,
      )).rows[0] as { n: number };
      if (present.n > 0) throw new ImportRefused("the database is not empty: it holds relations of another schema; the import builds a fresh database");
    } else {
      const holding = await tablesHoldingRows(client, (await client.query(
        `SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p') ORDER BY relname`,
      )).rows.map((r) => (r as { relname: string }).relname));
      if (holding.length > 0) {
        // This bundle, imported already: by this release, or by an earlier
        // one before an index-only migration (indexesOnly) existed. Those
        // change no table or column the bundle filled, so once its rows
        // are found to be the bundle's, they are applied here, under the
        // import's lock, and the import is finished. Anything else pending
        // is an older schema: refused as it is.
        if (status.pending.every((m) => m.indexesOnly) && (await holdsThisBundle(client, bundle))) {
          if (status.pending.length > 0) await migrate(client);
          return { bundle, alreadyImported: true };
        }
        throw notEmpty(holding);
      }
    }
    await migrate(client);
    const sequences = (await client.query(
      `SELECT count(*)::int AS n FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'S'`,
    )).rows[0] as { n: number };
    if (sequences.n > 0) throw new ImportRefused("the schema holds a sequence: every id is the application's, and a sequence would need restoring, which this import does not do");
    // And as built: every table of the manifest holds no row but its seed.
    const holding = await tablesHoldingRows(client, manifest.tables.map((t) => t.source));
    if (holding.length > 0) throw notEmpty(holding);

    // 3. One transaction.
    await client.query("BEGIN");
    try {
      const fks = (await client.query(
        `SELECT conrelid::regclass::text AS tbl, conname, pg_get_constraintdef(oid) AS def
           FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace
          ORDER BY conrelid::regclass::text, conname`,
      )).rows as { tbl: string; conname: string; def: string }[];
      for (const fk of fks) await client.query(`ALTER TABLE ${fk.tbl} DROP CONSTRAINT ${quoteIdent(fk.conname)}`);
      const triggered = ((await client.query(
        `SELECT DISTINCT tgrelid::regclass::text AS tbl FROM pg_trigger WHERE NOT tgisinternal ORDER BY 1`,
      )).rows as { tbl: string }[]).map((r) => r.tbl);
      for (const t of triggered) await client.query(`ALTER TABLE ${t} DISABLE TRIGGER USER`);
      // The migrations' seed row: the bundle's replaces it (SEEDED names it).
      await client.query("DELETE FROM exposure_backfill");

      const loader = new Loader(client);
      const again = await readReverseBundle(opts.path, manifest, (table, values) => loader.row(table, values));
      await loader.flush();
      if (again.sha256 !== bundle.sha256) throw new ImportRefused("the bundle changed while it was imported; nothing was loaded");

      for (const t of triggered) await client.query(`ALTER TABLE ${t} ENABLE TRIGGER USER`);
      for (const fk of fks) {
        try {
          await client.query(`ALTER TABLE ${fk.tbl} ADD CONSTRAINT ${quoteIdent(fk.conname)} ${fk.def}`);
        } catch {
          // Its message quotes the key: only the constraint is named.
          throw new ImportRefused(`a foreign key does not hold in the bundle's rows: ${fk.tbl}.${fk.conname}`);
        }
      }
      const last = ((await client.query("SELECT coalesce(max(event_order), 0)::text AS p FROM audit_events")).rows[0] as { p: string }).p;
      if (last !== bundle.auditPosition) throw new ImportRefused(`the loaded audit ends at ${last}, not the bundle's ${bundle.auditPosition}`);
      await client.query("UPDATE audit_position SET value = $1::bigint WHERE singleton", [last]);

      // Checked again as loaded, before the commit.
      const installation = (await client.query("SELECT id, kek_canary FROM installation")).rows as { id: string; kek_canary: Envelope | string }[];
      const canary = installation[0] && (typeof installation[0].kek_canary === "string" ? (JSON.parse(installation[0].kek_canary) as Envelope) : installation[0].kek_canary);
      if (installation.length !== 1 || !canary || !verifyKekAgainstCanary(opts.rootKek, canary, installation[0]!.id)) {
        throw new ImportRefused("the Root KEK does not open the installation's canary: this is not the installation's key file; nothing was loaded");
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    }
    return { bundle, alreadyImported: false };
  } finally {
    if (locked) await client.query("SELECT pg_advisory_unlock($1::bigint)", [IMPORT_LOCK.toString()]).catch(() => {});
    client.release();
  }
}

type Client = Awaited<ReturnType<PoolQuerier["connect"]>>;

/** Of the given tables, those holding a row beyond the migrations' seed (bookkeeping aside). */
async function tablesHoldingRows(client: Client, tables: string[]): Promise<string[]> {
  const holding: string[] = [];
  for (const t of tables) {
    if (BOOKKEEPING.has(t)) continue;
    const n = ((await client.query(`SELECT count(*)::int AS n FROM ${quoteIdent(t)}`)).rows[0] as { n: number }).n;
    if (n > (SEEDED[t] ?? 0)) holding.push(t);
  }
  return holding;
}

/** This release's migrations on the import's connection; a failure names only the migration. */
async function migrate(client: Client): Promise<void> {
  try {
    await runMigrations(client);
  } catch (err) {
    // Its message carries PostgreSQL's text: only the migration is named.
    const step = /^Migration ([0-9]+) \(([a-z0-9_]+)\) failed/.exec(err instanceof Error ? err.message : "");
    throw new ImportRefused(`the schema could not be built at this release's level${step ? ` (migration ${step[1]}, ${step[2]})` : ""}; nothing was loaded`);
  }
}

const notEmpty = (holding: string[]) =>
  new ImportRefused(`the database is not empty (${holding.slice(0, 5).join(", ")}${holding.length > 5 ? ", ..." : ""} hold rows): the import builds a fresh database`);

/**
 * Whether the database is this bundle already imported: an import that
 * committed and then stopped before the gate was lifted runs again to
 * finish. The installation, the last audit position, and every table's
 * row count are the bundle's.
 */
async function holdsThisBundle(client: Client, bundle: ReverseBundle): Promise<boolean> {
  const r = (await client.query(
    `SELECT (SELECT array_agg(id) FROM installation) AS ids,
            (SELECT coalesce(max(event_order), 0)::text FROM audit_events) AS last`,
  )).rows[0] as { ids: string[] | null; last: string };
  if (r.ids?.length !== 1 || r.ids[0] !== bundle.installationId || r.last !== bundle.auditPosition) return false;
  for (const [table, rows] of Object.entries(bundle.perTable)) {
    const n = ((await client.query(`SELECT count(*)::int AS n FROM ${quoteIdent(table)}`)).rows[0] as { n: number }).n;
    if (n !== rows) return false;
  }
  return true;
}
