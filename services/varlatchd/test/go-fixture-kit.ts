// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The parity kit (ADR-0059 step 4, feature-parity decision 3): a database
 * this server built through its own /v1 API, a table of requests, and this
 * server's answer to each, written to a file that the Go server's tests
 * (go/server/paritytest) replay against varlatchd. Generalized from
 * go-values-fixture.test.ts for the slices that write.
 *
 * Per request the file holds the status, the headers that matter, the body
 * byte for byte, the audit events it wrote, and the rows it added or
 * changed in the slice's side tables (`sideTables`); at the end, the
 * Security Control report counts. Every answer is recorded on the file's
 * own rows, loaded into a fresh database (loadRows), the way the check
 * replays it, so a file never drifts from this code: each run of the
 * fixture's test replays the file here too and requires the same answers.
 *
 * Writes make what the file cannot hold fixed: new domain IDs, new
 * timestamps, new envelopes. Both sides normalize them the same way
 * (normalize): a domain ID that the file's rows do not hold becomes
 * `{<prefix>#<n>}`, numbered per prefix by first appearance across the
 * run (the body, then the audit events walked with their keys sorted,
 * then the side rows); an ISO timestamp the rows do not hold becomes
 * `{time}`; in a side table, a column listed `volatile` whose value the
 * file's rows do not hold for that column becomes `{fresh}` (the Go side
 * checks such an envelope opens, with the file's Root KEK). The request id
 * is `{requestId}`.
 */
import { expect } from "vitest";
import type { AppCtx } from "../src/domain/ctx.js";
import { accessCountsSettled } from "../src/domain/securityreport.js";
import { migratedTestDb } from "./helpers/pglite.js";

export type Row = Record<string, unknown>;

/** One table of the file: its rows' order, which their foreign keys allow. */
export interface Table {
  name: string;
  orderBy: string;
}

/** A table whose added or changed rows each request records. */
export interface SideTable extends Table {
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
  /** A JSON body, or the exact text of one that is not JSON. */
  body?: unknown;
  rawBody?: string;
  userAgent?: string;
}

export interface Recorded extends RequestCase {
  expect: { status: number; headers: Record<string, string>; body: string };
  audit: Row[];
  /** Side table to the rows the request added or changed, normalized. */
  side: Record<string, Row[]>;
}

export interface Fixture {
  comment: string;
  ref: string;
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

const json = (v: unknown): unknown => (v instanceof Date ? v.toISOString() : v);

/** The tables' rows as PostgreSQL holds them, in their order. */
export async function exportRows(db: AppCtx["db"], tables: readonly Table[]): Promise<Record<string, Row[]>> {
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
        return v !== null && typeof v === "object" && !Array.isArray(v) ? JSON.stringify(v) : v;
      });
      await db.query(`INSERT INTO "${t.name}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(", ")})`, values);
    }
  }
  await db.query("SET session_replication_role = DEFAULT");
  return db;
}

const ID = /\b([a-z]{3,4})_[a-z2-7]{26}\b/g;
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
          this.columns.get(key)!.add(JSON.stringify(v));
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

  /** Side rows: volatile columns first, then sorted by their form with new IDs masked, then numbered. */
  side(table: SideTable, rows: Row[]): Row[] {
    const marked = rows.map((r) =>
      Object.fromEntries(Object.entries(r).map(([c, v]) =>
        [c, table.volatile?.includes(c) && v !== null && !this.columns.get(`${table.name}.${c}`)?.has(JSON.stringify(v)) ? "{fresh}" : v])),
    );
    const mask = (r: Row) => JSON.stringify(sortKeys(r)).replace(ID, (m, p: string) => (this.known.has(m) ? m : `{${p}}`));
    return marked.sort((a, b) => (mask(a) < mask(b) ? -1 : mask(a) > mask(b) ? 1 : 0)).map((r) => this.value(r) as Row);
  }
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.keys(v as Row).sort().map((k) => [k, sortKeys((v as Row)[k])]));
  return v;
}

/**
 * Runs the table against a database, recording each answer and what it
 * wrote. `path` fills a request's path (ids of the file's own rows).
 */
export async function record(
  ctx: AppCtx,
  app: { request: (path: string, init: RequestInit) => Response | Promise<Response> },
  f: Pick<Fixture, "rows" | "tokens" | "sideTables">,
  cases: RequestCase[],
  path: (p: string) => string = (p) => p,
): Promise<{ requests: Recorded[]; counters: Row[] }> {
  const norm = new Normalizer(f.rows);
  const out: Recorded[] = [];
  const dump = async (t: SideTable) => (await exportRows(ctx.db, [t]))[t.name]!;
  for (const c of cases) {
    const before = Number(((await ctx.db.query("SELECT max(event_order) AS n FROM audit_events")).rows[0] as { n: unknown }).n ?? 0);
    const sideBefore = new Map<string, Set<string>>();
    for (const t of f.sideTables) sideBefore.set(t.name, new Set((await dump(t)).map((r) => JSON.stringify(r))));
    const headers: Record<string, string> = { "Content-Type": "application/json", "User-Agent": c.userAgent ?? CLI_AGENT };
    if (c.credential !== "none") headers.Authorization = `Bearer ${f.tokens[c.credential]}`;
    const init: RequestInit = { method: c.method, headers };
    if (c.rawBody !== undefined) init.body = c.rawBody;
    else if ("body" in c) init.body = JSON.stringify(c.body);
    const res = await app.request(path(c.path), init);
    const requestId = res.headers.get("X-Request-Id") ?? "";
    const body = norm.text(await res.text(), requestId);
    const kept: Record<string, string> = {};
    for (const h of HEADERS) {
      const v = res.headers.get(h);
      if (v !== null) kept[h] = norm.text(v, requestId);
    }
    await accessCountsSettled();
    const audit = ((await ctx.db.query(`SELECT ${AUDIT_COLUMNS} FROM audit_events WHERE event_order > $1 ORDER BY event_order`, [before])).rows as Row[])
      .map((r) => norm.value(r, requestId) as Row);
    const side: Record<string, Row[]> = {};
    for (const t of f.sideTables) {
      const changed = (await dump(t)).filter((r) => !sideBefore.get(t.name)!.has(JSON.stringify(r)));
      if (changed.length > 0) side[t.name] = norm.side(t, changed);
    }
    out.push({ ...c, expect: { status: res.status, headers: kept, body }, audit, side });
  }
  const counters = ((await ctx.db.query(
    "SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason",
  )).rows as Row[]).map((r) => norm.value({ ...r, count: Number(r.count) }) as Row);
  return { requests: out, counters };
}

/** The request definitions of a table, by id, without answers. */
export function definitions(cases: RequestCase[]): Map<string, RequestCase> {
  return new Map(cases.map((c) => [c.id, {
    id: c.id, name: c.name, method: c.method, path: c.path, credential: c.credential,
    ...("body" in c ? { body: c.body } : {}), ...(c.rawBody !== undefined ? { rawBody: c.rawBody } : {}), ...(c.userAgent !== undefined ? { userAgent: c.userAgent } : {}),
  }]));
}

/** A committed file's requests must be the table's: one added, removed or changed and not regenerated fails. */
export function expectCurrentTable(f: Fixture, want: RequestCase[]) {
  const w = definitions(want);
  const have = definitions(f.requests);
  expect([...have.keys()].sort(), "the file's requests are not the table's: regenerate it").toEqual([...w.keys()].sort());
  for (const [id, def] of w) expect(have.get(id), `${id}: changed since the file was written; regenerate it`).toEqual(def);
}

export function expectSameAnswers(f: Fixture, got: { requests: Recorded[]; counters: Row[] }) {
  for (const [i, want] of f.requests.entries()) {
    const have = got.requests[i]!;
    expect({ name: want.name, ...have.expect }).toEqual({ name: want.name, ...want.expect });
    expect({ name: want.name, audit: have.audit }).toEqual({ name: want.name, audit: want.audit });
    expect({ name: want.name, side: have.side }).toEqual({ name: want.name, side: want.side });
  }
  expect(got.counters).toEqual(f.counters);
}
