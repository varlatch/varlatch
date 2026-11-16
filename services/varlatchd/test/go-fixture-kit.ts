// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The parity kit (ADR-0059 step 4, feature-parity decision 3): a database
 * this server built through its own /v1 API, a table of requests, and this
 * server's answer to each, written to a file that the Go server's tests
 * (go/server/paritytest) replay against varlatchd. Generalized from
 * go-values-fixture.test.ts for the slices that write.
 *
 * Per request the file holds the status, the headers that matter, the body
 * byte for byte, the audit events it wrote, and the rows it inserted,
 * updated and deleted in the slice's side tables (`sideTables`, diffed by
 * primary key); at the end, the Security Control report counts. A request
 * with `concurrent: n` is sent n times at once, and its answers are kept
 * sorted. Every answer is recorded on the file's own rows, loaded into a
 * fresh database (loadRows), the way the check replays it, so a file never
 * drifts from this code: each run of a fixture's test replays the file
 * here too, requires the same answers, and rebuilds the database to check
 * the file's rows are still what this code makes (expectSameRows).
 *
 * Rows are compared in PostgreSQL's typed form, as the pg driver reads
 * them (times as ISO strings, booleans, jsonb parsed, bigint as text): the
 * Go side converts its SQLite rows back to that form with the schema's
 * column types. One canonical text (canonical(): object keys sorted,
 * JSON.stringify's escaping) orders and compares them on both sides.
 *
 * Writes make what the file cannot hold fixed: new domain IDs, new
 * timestamps, new envelopes. Both sides normalize them the same way
 * (Normalizer):
 *   - a domain ID the file's rows do not hold becomes `{<prefix>#<n>}`,
 *     numbered per prefix by first appearance: in the body, then the
 *     audit events (keys walked sorted), then the side rows, table by
 *     table, inserted, updated, deleted, each group ordered by the
 *     table's stable semantic key (`sortBy`) with the IDs not numbered
 *     yet masked. Two rows of a group that the masked key cannot tell
 *     apart fail the recording: anchor them in the body or the audit
 *     events, or declare a key that does;
 *   - an ISO timestamp the rows do not hold becomes `{time}`;
 *   - in a side row, a `volatile` column whose value the file's rows do
 *     not hold for that column becomes `{fresh}` (the Go side checks such
 *     an envelope opens, with the file's Root KEK). Every column a write
 *     fills with a new time or envelope must be listed;
 *   - the request id becomes `{requestId}`.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { canonicalJson } from "@varlatch/contract";
import { expect } from "vitest";
import type { Envelope } from "../src/crypto/aead.js";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";

export type Row = Record<string, unknown>;

/** One table of the file: its rows' order, which their foreign keys allow. */
export interface Table {
  name: string;
  orderBy: string;
  /**
   * Columns whose values each build makes anew (random keys, hashes,
   * envelopes), for expectSameRows: relabelled one to one, like domain IDs,
   * so a foreign key into them (auth_user_links to user) keeps its meaning.
   */
  random?: string[];
}

/** A table whose inserted, updated and deleted rows each request records. */
export interface SideTable {
  name: string;
  /** The primary key's columns: rows are diffed by them. */
  key: string[];
  /** A stable semantic key: orders a group of rows before fresh IDs are numbered. */
  sortBy: string[];
  /** Columns a write fills with what cannot be fixed (a time, an envelope). */
  volatile?: string[];
}

export interface RequestCase {
  /** Stable: the method and the name, unique in the table. */
  id: string;
  name: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  credential: string;
  /** A JSON body, or the exact text of one that is not JSON (or holds what JSON.stringify would rewrite). */
  body?: unknown;
  rawBody?: string;
  userAgent?: string;
  /** Sent as they are (an Idempotency-Key). */
  headers?: Record<string, string>;
  /**
   * Members of the answer's body (a string, or a flat object) masked as
   * "{masked}", wherever they occur: a digest over rows a request made, which cannot repeat (the
   * read path's stateDigest after writes; the values fixture pins it).
   */
  masked?: string[];
  /** Sent this many times at once; the answers are kept sorted. */
  concurrent?: number;
}

export interface Answer {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface SideChange {
  inserted?: Row[];
  updated?: Row[];
  deleted?: Row[];
}

export interface Recorded extends RequestCase {
  expect: Answer;
  /** Every answer of a concurrent request, sorted. */
  answers?: Answer[];
  audit: Row[];
  side: Record<string, SideChange>;
}

/** What one request produced before normalization (record's inspect). */
export interface RawAnswer {
  /** When the request was sent and when every answer was in, in milliseconds. */
  sent: number;
  done: number;
  statuses: number[];
  bodies: string[];
  /** The audit events it wrote, and the side rows it inserted or updated, as PostgreSQL returns them. */
  audit: Row[];
  side: Record<string, Row[]>;
}

export interface Fixture {
  comment: string;
  /** The release whose code sealed the rows' envelopes. */
  ref: string;
  /** The SERVER_VERSION of the server that answered (the installation release read reports it); ref when absent. */
  serverVersion?: string;
  rootKek: string;
  tokens: Record<string, string>;
  rows: Record<string, Row[]>;
  sideTables: SideTable[];
  requests: Recorded[];
  counters: Row[];
}

/** The CLI's User-Agent, sent when a request names none. */
export const CLI_AGENT = "varlatch-cli/0.22.0 (linux; x64)";
const REQUEST_ID = "{requestId}";
const HEADERS = ["Cache-Control", "Retry-After", "Content-Type", "Varlatch-Credential-Expires", "Location"];
const AUDIT_COLUMNS =
  "event_type, actor_identity_id, credential_id, organization_id, action, resource, decision, authz, tailnet, listener, request_id, metadata, client, schema_version";

/** Request ids from a table, checked unique. */
export function withIds(cases: Omit<RequestCase, "id">[]): RequestCase[] {
  const out = cases.map((c) => ({ id: `${c.method} ${c.name}`, ...c }));
  if (new Set(out.map((c) => c.id)).size !== out.length) throw new Error("two requests share an id");
  return out;
}

/** A column's value as JSON holds it: a time as its ISO text, a bytea as PostgreSQL's text form (\\x and hex). */
const json = (v: unknown): unknown => (v instanceof Date ? v.toISOString() : Buffer.isBuffer(v) || v instanceof Uint8Array ? `\\x${Buffer.from(v).toString("hex")}` : v);

/** The canonical text: object keys sorted, JSON.stringify's escaping and numbers. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const o = v as Row;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

/** The tables' rows as PostgreSQL holds them, in their order. */
export async function exportRows(db: AppCtx["db"], tables: readonly Pick<Table, "name" | "orderBy">[]): Promise<Record<string, Row[]>> {
  const out: Record<string, Row[]> = {};
  for (const t of tables) {
    const res = await db.query(`SELECT * FROM "${t.name}" ORDER BY ${t.orderBy}`);
    out[t.name] = (res.rows as Row[]).map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, json(v)])));
  }
  return out;
}

/** A file's rows in a fresh database, as they were exported. */
export async function loadRows(rows: Record<string, Row[]>, tables: readonly Table[]): Promise<AppCtx["db"] & { close: () => Promise<void> }> {
  const db = await migratedTestDb();
  // Foreign keys are the source database's; their triggers are not needed.
  await db.query("SET session_replication_role = replica");
  for (const t of tables) {
    for (const row of rows[t.name] ?? []) {
      const cols = Object.keys(row);
      const values = cols.map((c) => {
        const v = row[c];
        // A bytea in PostgreSQL's text form (exportRows), as PGlite takes it.
        if (typeof v === "string" && /^\\x(?:[0-9a-f]{2})*$/.test(v)) return Buffer.from(v.slice(2), "hex");
        return v !== null && typeof v === "object" && !Array.isArray(v) ? JSON.stringify(v) : v;
      });
      await db.query(`INSERT INTO "${t.name}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`, values);
    }
  }
  await db.query("SET session_replication_role = DEFAULT");
  return db;
}

const ID = /\b([a-z]{2,4})_[a-z2-7]{26}\b/g;
/** A domain ID, or a random column's token in relabel (`r_rand` and 21 letters: prefix `r`). */
const TOKEN_OR_ID = /\b([a-z]{1,4})_(?:rand[a-j]{21}|[a-z2-7]{26})\b/g;
const ISO = /\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\b/g;

/** The normalization both sides apply (see the header). */
export class Normalizer {
  private readonly known = new Set<string>();
  private readonly columns = new Map<string, Set<string>>();
  private readonly fresh = new Map<string, string>();
  private readonly counts = new Map<string, number>();

  constructor(rows: Record<string, Row[]>) {
    const walk = (v: unknown) => {
      if (typeof v === "string") {
        for (const m of v.matchAll(ID)) this.known.add(m[0]);
        for (const m of v.matchAll(ISO)) this.known.add(m[0]);
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (v !== null && typeof v === "object") Object.values(v).forEach(walk);
    };
    for (const [table, list] of Object.entries(rows)) {
      for (const row of list) {
        walk(row);
        for (const [col, v] of Object.entries(row)) {
          const key = `${table}.${col}`;
          if (!this.columns.has(key)) this.columns.set(key, new Set());
          this.columns.get(key)!.add(canonical(v));
        }
      }
    }
  }

  text(s: string, requestId = ""): string {
    let out = requestId ? s.replaceAll(requestId, REQUEST_ID) : s;
    out = out.replace(ID, (m, prefix: string) => {
      if (this.known.has(m)) return m;
      let p = this.fresh.get(m);
      if (!p) {
        const n = (this.counts.get(prefix) ?? 0) + 1;
        this.counts.set(prefix, n);
        p = `{${prefix}#${n}}`;
        this.fresh.set(m, p);
      }
      return p;
    });
    return out.replace(ISO, (m) => (this.known.has(m) ? m : "{time}"));
  }

  /** A JSON value, its object keys walked in sorted order. */
  value(v: unknown, requestId = ""): unknown {
    if (typeof v === "string") return this.text(v, requestId);
    if (Array.isArray(v)) return v.map((e) => this.value(e, requestId));
    if (v !== null && typeof v === "object") {
      const o = v as Row;
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, this.value(o[k], requestId)]));
    }
    return v;
  }

  /** IDs not numbered yet masked as {prefix}: a group's order before its numbering. */
  private masked(v: unknown): string {
    return canonical(v).replace(ID, (m, p: string) => (this.known.has(m) ? m : (this.fresh.get(m) ?? `{${p}}`)));
  }

  /** One group of side rows (a table's inserted, updated or deleted rows), normalized. */
  side(table: SideTable, rows: Row[]): Row[] {
    const marked = rows.map((r) =>
      Object.fromEntries(Object.entries(r).map(([c, v]) =>
        [c, table.volatile?.includes(c) && v !== null && !this.columns.get(`${table.name}.${c}`)?.has(canonical(v)) ? "{fresh}" : v])),
    );
    const keyed = marked.map((r) => ({ r, k: this.masked(table.sortBy.map((c) => r[c] ?? null)) }));
    keyed.sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : 0));
    for (let i = 1; i < keyed.length; i++) {
      const [a, b] = [keyed[i - 1]!, keyed[i]!];
      if (a.k === b.k && (this.unnumbered(a.r) || this.unnumbered(b.r))) {
        throw new Error(`${table.name}: two rows share the semantic key ${b.k}: anchor their new IDs in the body or the audit events, or declare a sortBy that tells them apart`);
      }
    }
    // Numbered in that order, then kept in the order of their normalized text.
    return keyed.map(({ r }) => this.value(r) as Row).sort((a, b) => (canonical(a) < canonical(b) ? -1 : canonical(a) > canonical(b) ? 1 : 0));
  }

  /** Whether a row holds a new ID not numbered yet. */
  private unnumbered(r: Row): boolean {
    return [...canonical(r).matchAll(ID)].some((m) => !this.known.has(m[0]) && !this.fresh.has(m[0]));
  }
}

const by = (keys: string[]) => (r: Row) => canonical(keys.map((k) => r[k] ?? null));

/** What a request changed in a side table, by primary key. */
function diff(t: SideTable, before: Row[], after: Row[]): { inserted: Row[]; updated: Row[]; deleted: Row[] } {
  const key = by(t.key);
  const was = new Map(before.map((r) => [key(r), r]));
  const now = new Map(after.map((r) => [key(r), r]));
  return {
    inserted: after.filter((r) => !was.has(key(r))),
    updated: after.filter((r) => was.has(key(r)) && canonical(was.get(key(r))) !== canonical(r)),
    deleted: before.filter((r) => !now.has(key(r))),
  };
}

const sha256Of = (v: unknown) => `sha256:${createHash("sha256").update(canonicalJson(v), "utf8").digest("hex")}`;

/**
 * An answer's state digests, recomputed from the manifest in the same
 * answer (manifest.ts stateDigest and categoryDigests), so a digest the
 * file masks is still checked: each is the manifest's, which the file
 * compares, normalized, byte for byte. Throws on a mismatch.
 */
export function checkDigests(text: string, where: string): void {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return;
  }
  if (body === null || typeof body !== "object" || !("manifest" in body)) return;
  const b = body as { manifest: Record<string, unknown> & { items: Record<string, unknown>[] }; stateDigest?: string; stateDigests?: Record<string, string> };
  const m = b.manifest;
  if (b.stateDigest !== undefined && b.stateDigest !== sha256Of(m)) throw new Error(`${where}: stateDigest is not its manifest's`);
  if (b.stateDigests !== undefined) {
    const want = {
      environment: sha256Of({ projectId: m.projectId, environment: m.environment }),
      contract: sha256Of(m.contract),
      items: sha256Of(m.items.map((i) => ({ name: i.name, source: i.source, valueRowId: i.valueRowId, versionId: i.versionId }))),
      rotation: sha256Of(m.items.flatMap((i) => (i.retiringVersionId ? [{ name: i.name, retiringVersionId: i.retiringVersionId }] : []))),
    };
    if (JSON.stringify(b.stateDigests) !== JSON.stringify(want)) throw new Error(`${where}: stateDigests are not its manifest's`);
  }
}

/** The answer's text with the members named masked (RequestCase.masked). */
export function mask(text: string, members: string[] | undefined): string {
  let out = text;
  for (const m of members ?? []) {
    const key = JSON.stringify(m).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // A string, or a flat object (stateDigests: digests only).
    out = out.replace(new RegExp("(" + key + ':)(?:"(?:[^"\\\\]|\\\\.)*"|\\{[^{}]*\\})', "g"), '$1"{masked}"');
  }
  return out;
}

const answerOrder = (a: Answer, b: Answer) => (a.status - b.status) || (a.body < b.body ? -1 : a.body > b.body ? 1 : 0);

/**
 * How many requests each app of a recording answers: a fresh app (a fresh
 * request window) before every 500th, so no request meets the window (600
 * per minute per client), however long a fixture grows. The Go replay
 * restarts its server at the same requests (paritytest.WindowBatch).
 */
export const WINDOW_BATCH = 500;

type App = { request: (path: string, init: RequestInit) => Response | Promise<Response> };

/**
 * Runs the table against a database, recording each answer and what it
 * wrote. `app` is the app, or a function that makes one: a function is
 * called again every WINDOW_BATCH requests (a fresh request window), and a
 * table longer than that needs one. `path` fills a request's path (ids of
 * the file's own rows).
 */
export async function record(
  ctx: AppCtx,
  app: App | (() => App),
  f: Pick<Fixture, "rows" | "tokens" | "sideTables">,
  cases: RequestCase[],
  /** Fills a request's placeholders, in its path and its body. */
  path: (p: string) => string = (p) => p,
  /**
   * Sees each request's answers, audit events and side rows before any
   * normalization, with when it was sent and answered (as the Go replay's
   * Target.Inspect): for checks the normalized comparison cannot make.
   */
  inspect?: (c: RequestCase, raw: RawAnswer) => void,
): Promise<{ requests: Recorded[]; counters: Row[] }> {
  const norm = new Normalizer(f.rows);
  const out: Recorded[] = [];
  const dump = async (t: SideTable) => (await exportRows(ctx.db, [{ name: t.name, orderBy: t.key.map((k) => `"${k}"`).join(", ") }]))[t.name]!;
  const newApp = typeof app === "function" ? app : null;
  if (!newApp && cases.length > WINDOW_BATCH) {
    throw new Error(`record: ${cases.length} requests pass the request window: pass a function that makes the app, so it is made afresh every ${WINDOW_BATCH}`);
  }
  let current = newApp ? newApp() : (app as App);
  for (const [index, c] of cases.entries()) {
    if (newApp && index > 0 && index % WINDOW_BATCH === 0) current = newApp();
    const before = Number(((await ctx.db.query("SELECT max(event_order) AS n FROM audit_events")).rows[0] as { n: unknown }).n ?? 0);
    const sideBefore = new Map<string, Row[]>();
    for (const t of f.sideTables) sideBefore.set(t.name, await dump(t));
    const headers: Record<string, string> = { "Content-Type": "application/json", "User-Agent": c.userAgent ?? CLI_AGENT };
    if (c.credential !== "none") headers.Authorization = `Bearer ${f.tokens[c.credential]}`;
    Object.assign(headers, c.headers ?? {});
    const init: RequestInit = { method: c.method, headers };
    // Placeholders are filled in the body as in the path.
    if (c.rawBody !== undefined) init.body = path(c.rawBody);
    else if ("body" in c) init.body = path(JSON.stringify(c.body));
    const sent = Date.now();
    const responses = await Promise.all(Array.from({ length: c.concurrent ?? 1 }, () => current.request(path(c.path), init)));
    const done = Date.now();
    const raw = await Promise.all(responses.map(async (res) => ({ res, id: res.headers.get("X-Request-Id") ?? "", text: await res.text() })));
    // Sorted before normalizing (a request id differs per answer), so the
    // fresh IDs are numbered in the sorted order.
    // An answer without the header (a streamed one) names no request id.
    const pre = raw.map(({ res, id, text }) => ({ res, id, status: res.status, text: id ? text.replaceAll(id, REQUEST_ID) : text }));
    pre.sort((a, b) => (a.status - b.status) || (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
    const answers: Answer[] = pre.map(({ res, id, status, text }) => {
      const kept: Record<string, string> = {};
      for (const h of HEADERS) {
        const v = res.headers.get(h);
        if (v !== null) kept[h] = norm.text(v, id);
      }
      checkDigests(text, c.id);
      return { status, headers: kept, body: norm.text(mask(text, c.masked)) };
    });
    answers.sort(answerOrder);
    await accessCountsSettled();
    const ids = new Set(raw.map((r) => r.id));
    const rawAudit = (await ctx.db.query(`SELECT ${AUDIT_COLUMNS} FROM audit_events WHERE event_order > $1 ORDER BY event_order`, [before])).rows as Row[];
    const audit = rawAudit.map((r) => norm.value({ ...r, request_id: ids.has(r.request_id as string) ? REQUEST_ID : r.request_id }) as Row);
    const side: Record<string, SideChange> = {};
    const rawSide: Record<string, Row[]> = {};
    for (const t of f.sideTables) {
      const d = diff(t, sideBefore.get(t.name)!, await dump(t));
      rawSide[t.name] = [...d.inserted, ...d.updated];
      const change: SideChange = {};
      for (const k of ["inserted", "updated", "deleted"] as const) if (d[k].length > 0) change[k] = norm.side(t, d[k]);
      if (Object.keys(change).length > 0) side[t.name] = change;
    }
    inspect?.(c, { sent, done, statuses: raw.map((r) => r.res.status), bodies: raw.map((r) => r.text), audit: rawAudit, side: rawSide });
    out.push({ ...c, expect: answers[0]!, ...(c.concurrent ? { answers } : {}), audit, side });
  }
  const counters = ((await ctx.db.query(
    "SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason",
  )).rows as Row[]).map((r) => norm.value({ ...r, count: Number(r.count) }) as Row);
  return { requests: out, counters };
}

/** The request definitions of a table, in order, without answers. */
export function definitions(cases: RequestCase[]): RequestCase[] {
  return cases.map((c) => ({
    id: c.id, name: c.name, method: c.method, path: c.path, credential: c.credential,
    ...("body" in c ? { body: c.body } : {}), ...(c.rawBody !== undefined ? { rawBody: c.rawBody } : {}),
    ...(c.userAgent !== undefined ? { userAgent: c.userAgent } : {}), ...(c.headers !== undefined ? { headers: c.headers } : {}),
    ...(c.masked !== undefined ? { masked: c.masked } : {}),
    ...(c.concurrent !== undefined ? { concurrent: c.concurrent } : {}),
  }));
}

/** A committed file's requests must be the table's, in its order: one added, removed, moved or changed and not regenerated fails. */
export function expectCurrentTable(f: Fixture, want: RequestCase[]) {
  expect(definitions(f.requests).map((c) => c.id), "the file's requests are not the table's, in its order: regenerate it").toEqual(definitions(want).map((c) => c.id));
  expect(definitions(f.requests), "a request changed since the file was written: regenerate it").toEqual(definitions(want));
}

export function expectSameAnswers(f: Fixture, got: { requests: Recorded[]; counters: Row[] }) {
  for (const [i, want] of f.requests.entries()) {
    const have = got.requests[i]!;
    expect({ name: want.name, ...have.expect, answers: have.answers }).toEqual({ name: want.name, ...want.expect, answers: want.answers });
    expect({ name: want.name, audit: have.audit }).toEqual({ name: want.name, audit: want.audit });
    expect({ name: want.name, side: have.side }).toEqual({ name: want.name, side: want.side });
  }
  expect(got.counters).toEqual(f.counters);
}

/**
 * The file's rows are still what this code builds: a fresh build's rows
 * against the file's, per table, as multisets. What each build makes anew
 * is relabelled, never dropped: times become {time}; every domain ID, and
 * every value of a table's `random` columns (whatever its form: a Better
 * Auth user id, a hash, an envelope), a placeholder of its own, one to one
 * ({org#1}, {r#1}), numbered by first appearance as the tables are walked
 * in their order, each table's rows ordered by their text with what is not
 * numbered yet masked. The same random value in two places (a user's id,
 * and an auth link's reference to it) gets the same label. So a
 * relationship survives: a membership moved to another Organization, an
 * auth link moved to another user, or two rows that swap IDs, compare
 * different; nothing is masked away. Two rows that the walk cannot order
 * (the same text with new labels masked) fail the check until a table's
 * earlier rows anchor them.
 */
export function expectSameRows(tables: readonly Table[], file: Record<string, Row[]>, built: Record<string, Row[]>) {
  const a = relabel(tables, file);
  const b = relabel(tables, built);
  for (const t of tables) {
    expect({ table: t.name, rows: a.get(t.name) }, "the file's rows are not what this code builds now: regenerate it").toEqual({ table: t.name, rows: b.get(t.name) });
  }
}

/** Each table's rows as texts, relabelled one to one (see expectSameRows). */
export function relabel(tables: readonly Table[], rows: Record<string, Row[]>): Map<string, string[]> {
  const ids = new Map<string, string>();
  const counts = new Map<string, number>();
  // A random column's value is a token here, labelled like an ID: the same
  // value, wherever it appears, the same token.
  const tokens = new Map<string, string>();
  const token = (v: unknown) => {
    const key = canonical(v);
    let t = tokens.get(key);
    if (!t) {
      t = `r_rand${String(tokens.size).padStart(21, "a").replace(/[0-9]/g, (d) => "abcdefghij"[Number(d)]!)}`;
      tokens.set(key, t);
    }
    return t;
  };
  const label = (text: string, number: boolean) =>
    text.replace(TOKEN_OR_ID, (m, p: string) => {
      let l = ids.get(m);
      if (!l && number) {
        const n = (counts.get(p) ?? 0) + 1;
        counts.set(p, n);
        l = `{${p}#${n}}`;
        ids.set(m, l);
      }
      return l ?? `{?${p}}`;
    });
  const out = new Map<string, string[]>();
  for (const t of tables) {
    const texts = (rows[t.name] ?? []).map((r) =>
      canonical(Object.fromEntries(Object.entries(r).map(([c, v]) => [c, t.random?.includes(c) && v !== null ? token(v) : v]))).replace(ISO, "{time}"),
    );
    const keyed = texts.map((text) => ({ text, k: label(text, false) })).sort((x, y) => (x.k < y.k ? -1 : x.k > y.k ? 1 : 0));
    for (let i = 1; i < keyed.length; i++) {
      // The same text with IDs left to number: their order, and so their
      // labels, would be a guess.
      if (keyed[i]!.k === keyed[i - 1]!.k && keyed[i]!.k.includes("{?")) {
        throw new Error(`${t.name}: two rows cannot be told apart once their new IDs are masked (${keyed[i]!.k})`);
      }
    }
    out.set(t.name, keyed.map(({ text }) => label(text, true)).sort());
  }
  return out;
}

const REPO_ROOT = new URL("../../../", import.meta.url);

/**
 * A v0.21.0 installation's data after its upgrade to 0.22.0 (no migration
 * between the two touches a ciphertext): the rows with every envelope the
 * read path opens sealed again by that release's code, in place. The
 * installation's canary; each live Organization's KEK (a new one, wrapped
 * by the Root KEK; a destroyed one stays destroyed); each value version,
 * with plaintextOf(version) under its Organization's new KEK; and, with
 * secretOf, each webhook's signing secret, secretOf(webhook) under it.
 */
export async function resealWith(
  ref: string,
  rootKek: Buffer,
  rows: Record<string, Row[]>,
  plaintextOf: (version: Row) => string,
  /** A webhook's signing secret, when the rows hold webhooks to seal again. */
  secretOf?: (webhook: Row) => string,
): Promise<void> {
  const crypto = await loadHierarchy(ref);
  for (const inst of rows.installation!) inst.kek_canary = crypto.createCanary(rootKek, inst.id as string) as Envelope;
  const kekOf = new Map<string, Buffer>();
  for (const org of rows.organizations!) {
    if (org.wrapped_org_kek === null) continue;
    const { orgKek, wrapped } = crypto.createWrappedOrgKek(rootKek, org.id as string) as { orgKek: Buffer; wrapped: Envelope };
    kekOf.set(org.id as string, orgKek);
    org.wrapped_org_kek = wrapped;
  }
  if (secretOf) {
    for (const w of rows.webhooks ?? []) {
      const orgKek = kekOf.get(w.organization_id as string);
      if (!orgKek) throw new Error(`webhook ${String(w.id)}: its Organization has no KEK to seal it under`);
      w.secret_envelope = crypto.encryptWebhookSecret(orgKek, w.organization_id as string, w.id as string, secretOf(w)) as Envelope;
    }
  }
  const envOf = new Map((rows.environments ?? []).map((e) => [e.id, e]));
  const projectOf = new Map((rows.projects ?? []).map((p) => [p.id, p]));
  const valueOf = new Map((rows.env_values ?? []).map((v) => [v.id, v]));
  for (const version of rows.value_versions ?? []) {
    const value = valueOf.get(version.value_id)!;
    const orgId = projectOf.get(envOf.get(value.environment_id)!.project_id)!.organization_id as string;
    const orgKek = kekOf.get(orgId);
    if (!orgKek) throw new Error(`value version ${String(version.id)}: its Organization has no KEK to seal it under`);
    const sealed = crypto.encryptValue(orgKek, orgId, value.id as string, version.id as string, Buffer.from(plaintextOf(version), "utf8")) as {
      payload: Envelope;
      wrappedDek: Envelope;
    };
    version.payload = sealed.payload;
    version.wrapped_dek = sealed.wrappedDek;
  }
}

/** A release's hierarchy.ts and canary.ts with their aead.ts and canonical JSON, from git (as go/lib/envelope/testdata/tsfixtures.mjs loads them). */
async function loadHierarchy(ref: string): Promise<Record<string, (...args: unknown[]) => unknown>> {
  const show = (path: string) => execFileSync("git", ["-C", REPO_ROOT.pathname, "show", `${ref}:${path}`], { encoding: "utf8" });
  const dir = mkdtempSync(join(tmpdir(), "varlatch-values-"));
  try {
    writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
    for (const [name, path] of [
      ["aead.ts", "services/varlatchd/src/crypto/aead.ts"],
      ["hierarchy.ts", "services/varlatchd/src/crypto/hierarchy.ts"],
      ["canary.ts", "services/varlatchd/src/crypto/canary.ts"],
      ["canonical.ts", "packages/contract/src/canonical.ts"],
    ]) {
      writeFileSync(
        join(dir, name!),
        show(path!).replaceAll('from "@varlatch/contract"', 'from "./canonical.ts"').replace(/from "\.\/(aead|hierarchy|canary)\.js"/g, 'from "./$1.ts"'),
      );
    }
    const load = (name: string) => import(/* @vite-ignore */ pathToFileURL(join(dir, name)).href);
    return { ...(await load("hierarchy.ts")), ...(await load("canary.ts")) } as Record<string, (...args: unknown[]) => unknown>;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
