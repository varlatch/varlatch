// SPDX-License-Identifier: AGPL-3.0-or-later
import { appendFileSync } from "node:fs";
import { LOCK_TAG } from "../../src/db/locks.js";
import type { Querier } from "../../src/db/migrate.js";

/**
 * The lock-order completeness check (ADR-0054 amendment E), test-time only:
 * nothing here is part of a migration or a production build.
 *
 * - One trace per transaction, in a test-only table: the transaction
 *   (txid_current()), a sequence number from a test-only sequence shared by
 *   every kind of entry, the table, the row's key, the mode and the kind.
 * - Explicit locks: the wrapper below runs every statement of the test
 *   database. A statement with a locking clause must carry the tag that
 *   src/db/locks.ts writes (lockedQuery, lockLiveScope, lockPeople); the
 *   wrapper refuses it otherwise, through `query` and `exec` alike. After
 *   a tagged statement it records each returned key, in the order the rows
 *   were locked, in the same transaction.
 * - Writes: a row trigger on every table records an UPDATE (FOR NO KEY
 *   UPDATE, or FOR UPDATE when a key column changes), a DELETE (FOR UPDATE)
 *   and an INSERT (a row the transaction created and holds).
 * - References: the same trigger records, for every foreign key of an
 *   inserted row or a changed foreign key, the referenced row's key with the
 *   FOR KEY SHARE that the foreign-key check takes.
 * - At COMMIT the wrapper reads the transaction's trace and checks it (see
 *   {@link checkTrace}); a violation fails the running test (setup file
 *   lock-trace-setup.ts).
 *
 * Gating (VARLATCH_LOCK_ORDER): "all" enforces every transaction; "migrated"
 * (the default while the remaining writers move to the order) enforces the
 * transactions begun by the writers in {@link MIGRATED} and only reports the
 * others (to the file named by VARLATCH_LOCK_TRACE_REPORT, when set);
 * "report" enforces nothing and reports every violation there; "off"
 * installs nothing.
 */

export type LockOrderMode = "off" | "report" | "migrated" | "all";

export function lockOrderMode(): LockOrderMode {
  const raw = process.env.VARLATCH_LOCK_ORDER ?? "migrated";
  if (raw === "off" || raw === "report" || raw === "migrated" || raw === "all") return raw;
  throw new Error(`VARLATCH_LOCK_ORDER must be off, report, migrated or all, not ${raw}`);
}

/**
 * Writers on amendment E's order, named by the function that begins their
 * transaction. Their transactions are checked under "migrated".
 */
export const MIGRATED = new Set<string>([
  // values.ts
  "setValue",
  "deleteValue",
  "beginRotation",
  "completeRotation",
  "applyChangeSet",
  // contracts.ts
  "pushRevision",
  "activateRevision",
  // projects.ts
  "renameProject",
  "deleteProject",
  // environments.ts
  "createEnvironment",
  "deleteEnvironment",
  // capabilities.ts
  "issueCapability",
  // sync.ts
  "createTarget",
  "updateTarget",
  // policy.ts
  "addTeamProject",
  // approvals: the two consuming operations
  "changeControl",
  "removeOwnPasskey",
  // freeze.ts: the incident freeze (ADR-0055 Decision 9)
  "freezeOrganization",
  "liftFreeze",
  "operatorUnfreeze",
]);

const SCHEMA = "varlatch_lock_trace";

/** Steps of amendment E, as [step, position within the step]. */
export function stepOf(table: string): [number, number] {
  switch (table) {
    case "installation":
      return [0, 5];
    case "organizations":
      return [1, 0];
    case "organization_deletions":
      return [1, 1];
    case "identities":
      return [2, 0];
    case "idempotency_keys":
      return [2, 5];
    case "passkey":
      return [3, 0];
    case "approval_intents":
      return [4, 0];
    case "approval_intent_challenges":
      return [5, 0];
    case "passkey_confirmation_challenges":
      return [5, 1];
    case "session":
      return [6, 0];
    case "credentials":
      return [7, 0];
    case "projects":
      return [8, 0];
    case "environments":
      return [9, 0];
    case "env_values":
    case "value_versions":
      return [10, 0];
    case "github_apps":
      return [10, 1];
    case "platform_connections":
      return [10, 2];
    case "sync_targets":
      return [10, 3];
    case "security_controls":
    case "passkey_provenance":
    case "organization_freezes":
      return [11, 0];
    case "security_control_counters":
      return [11, 1];
    case "member_exposure":
    case "member_integrations":
      return [11, 2];
    case "audit_position":
    case "audit_events":
      return [11, 3];
    default:
      // Every other domain row, in its writer's documented order.
      return [10, 4];
  }
}

// ---------------------------------------------------------------------------
// Installation (into the migrated test snapshot, never a migration)

const ident = (name: string) => `"${name.replaceAll('"', '""')}"`;
const lit = (s: string) => `'${s.replaceAll("'", "''")}'`;
const keyExpr = (row: "NEW" | "OLD", cols: string[]) =>
  cols.length === 1 ? `${row}.${ident(cols[0]!)}::text` : `concat_ws('|', ${cols.map((c) => `${row}.${ident(c)}::text`).join(", ")})`;

interface ForeignKey { cols: string[]; ref: string; refCols: string[] }

export async function installLockTrace(db: Querier): Promise<void> {
  const run = async (sql: string) => (db.exec ? db.exec(sql) : db.query(sql));
  await run(`
    CREATE SCHEMA ${SCHEMA};
    CREATE SEQUENCE ${SCHEMA}.seq;
    CREATE TABLE ${SCHEMA}.trace (txid bigint NOT NULL, seq bigint NOT NULL, tbl text NOT NULL, key text NOT NULL, mode text NOT NULL, kind text NOT NULL);
    CREATE INDEX ON ${SCHEMA}.trace (txid, seq);
  `);
  const tables = (await db.query(
    `SELECT c.oid::int AS oid, c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname`,
  )).rows as { oid: number; name: string }[];
  const cols = async (sql: string, params: unknown[]) => ((await db.query(sql, params)).rows as { cols: string[] }[]).map((r) => r.cols);
  for (const t of tables) {
    const [pk] = await cols(
      `SELECT array_agg(a.attname::text ORDER BY k.ord) AS cols FROM pg_index i
       CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
       JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
       WHERE i.indrelid = $1 AND i.indisprimary GROUP BY i.indexrelid`,
      [t.oid],
    );
    if (!pk) throw new Error(`lock trace: ${t.name} has no primary key`);
    // PostgreSQL takes FOR UPDATE (not FOR NO KEY UPDATE) for an UPDATE that
    // changes a column of a unique index usable by a foreign key: not
    // partial, not on expressions.
    const keyCols = [...new Set((await cols(
      `SELECT array_agg(a.attname::text) AS cols FROM pg_index i
       CROSS JOIN LATERAL unnest(i.indkey) k(attnum)
       JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
       WHERE i.indrelid = $1 AND i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL GROUP BY i.indexrelid`,
      [t.oid],
    )).flat())];
    const fks = (await db.query(
      `SELECT c.confrelid::regclass::text AS ref,
              array_agg(a.attname::text ORDER BY k.ord) AS cols,
              array_agg(ra.attname::text ORDER BY k.ord) AS "refCols"
       FROM pg_constraint c
       CROSS JOIN LATERAL unnest(c.conkey, c.confkey) WITH ORDINALITY k(attnum, refnum, ord)
       JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
       JOIN pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = k.refnum
       WHERE c.conrelid = $1 AND c.contype = 'f' GROUP BY c.oid ORDER BY c.oid`,
      [t.oid],
    )).rows as ForeignKey[];
    const refs: string[] = [];
    for (const fk of fks) {
      const ref = fk.ref.replace(/^"|"$/g, "");
      const refOid = tables.find((x) => x.name === ref)?.oid;
      const [refPk] = refOid === undefined ? [] : await cols(
        `SELECT array_agg(a.attname::text ORDER BY k.ord) AS cols FROM pg_index i
         CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
         WHERE i.indrelid = $1 AND i.indisprimary GROUP BY i.indexrelid`,
        [refOid],
      );
      if (!refPk) throw new Error(`lock trace: ${ref} has no primary key`);
      // The referenced row's primary key, from the referencing columns.
      const mapped = refPk.map((c) => fk.cols[fk.refCols.indexOf(c)]);
      const refKey = mapped.every((c) => c !== undefined)
        ? keyExpr("NEW", mapped as string[])
        : `(SELECT ${keyExpr("NEW", refPk).replaceAll("NEW.", "r.")} FROM public.${ident(ref)} r WHERE ${fk.refCols.map((c, i) => `r.${ident(c)} = NEW.${ident(fk.cols[i]!)}`).join(" AND ")})`;
      const present = fk.cols.map((c) => `NEW.${ident(c)} IS NOT NULL`).join(" AND ");
      const changed = fk.cols.map((c) => `NEW.${ident(c)} IS DISTINCT FROM OLD.${ident(c)}`).join(" OR ");
      refs.push(`
    IF ${present} AND (TG_OP = 'INSERT' OR ${changed}) THEN
      INSERT INTO ${SCHEMA}.trace VALUES (txid_current(), nextval('${SCHEMA}.seq'), ${lit(ref)}, ${refKey}, 'key share', 'reference');
    END IF;`);
    }
    const keyChanged = keyCols.length === 0 ? "false" : keyCols.map((c) => `NEW.${ident(c)} IS DISTINCT FROM OLD.${ident(c)}`).join(" OR ");
    const fn = `${SCHEMA}.${ident(`t_${t.name}`)}`;
    await run(`
CREATE FUNCTION ${fn}() RETURNS trigger LANGUAGE plpgsql AS $trace$
BEGIN
  IF TG_OP = 'DELETE' THEN
    INSERT INTO ${SCHEMA}.trace VALUES (txid_current(), nextval('${SCHEMA}.seq'), ${lit(t.name)}, ${keyExpr("OLD", pk)}, 'update', 'write');
    RETURN OLD;
  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO ${SCHEMA}.trace VALUES (txid_current(), nextval('${SCHEMA}.seq'), ${lit(t.name)}, ${keyExpr("OLD", pk)},
      CASE WHEN ${keyChanged} THEN 'update' ELSE 'no key update' END, 'write');
  ELSE
    INSERT INTO ${SCHEMA}.trace VALUES (txid_current(), nextval('${SCHEMA}.seq'), ${lit(t.name)}, ${keyExpr("NEW", pk)}, 'insert', 'insert');
  END IF;${refs.join("")}
  RETURN NEW;
END $trace$;
CREATE TRIGGER varlatch_lock_trace AFTER INSERT OR UPDATE OR DELETE ON public.${ident(t.name)}
  FOR EACH ROW EXECUTE FUNCTION ${fn}();`);
  }
}

// ---------------------------------------------------------------------------
// The check

export interface TraceRow { seq: number; tbl: string; key: string; mode: string; kind: "explicit" | "write" | "insert" | "reference" }

const STRENGTH: Record<string, number> = { "key share": 1, share: 2, "no key update": 3, update: 4, insert: 5 };
const cmpStep = (a: [number, number], b: [number, number]) => a[0] - b[0] || a[1] - b[1];

/**
 * The violations in one committed transaction's trace (amendment E):
 * - a referenced identity that the transaction had not taken before (at
 *   step 2, explicitly or by a write, or created itself);
 * - an upgrade: a row acquired again in a stronger mode than it held;
 * - a step going backwards: a first acquisition of a row not held yet at
 *   an earlier step (or, at step 10, an earlier type) than a first
 *   acquisition before it;
 * - rows of one table first acquired out of ascending key order;
 * - a person's row changed without an explicit FOR UPDATE prelock on it
 *   first (step 2; PostgreSQL's implicit lock of the update does not count).
 * A later entry for a row already held, in the same or a weaker mode, is
 * reuse and passes. Rows the transaction inserted are held from the start
 * and never order against anything.
 */
export function checkTrace(rows: TraceRow[]): string[] {
  const problems: string[] = [];
  const held = new Map<string, number>();
  const lastKey = new Map<string, string>();
  const prelocked = new Set<string>();
  let maxStep: [number, number] | null = null;
  let maxAt = "";
  const show = (r: TraceRow) => `${r.tbl}[${r.key}] ${r.mode} (${r.kind}, #${r.seq})`;
  for (const r of rows) {
    const id = `${r.tbl}\u0000${r.key}`;
    const before = held.get(id);
    const strength = STRENGTH[r.mode] ?? 0;
    if (r.kind === "insert") {
      held.set(id, STRENGTH.insert!);
      if (r.tbl === "identities") prelocked.add(r.key);
      continue;
    }
    if (r.tbl === "identities" && r.kind === "explicit" && r.mode === "update") prelocked.add(r.key);
    if (r.tbl === "identities" && r.kind === "write" && !prelocked.has(r.key)) {
      problems.push(`a person's row changed without an explicit FOR UPDATE prelock at step 2: ${show(r)}`);
    }
    if (r.tbl === "identities" && r.kind === "reference" && before === undefined) {
      problems.push(`identity referenced without being locked at step 2 first: ${show(r)}`);
    }
    if (before !== undefined) {
      if (strength > before) {
        problems.push(`upgrade: ${show(r)}, held in a weaker mode`);
        held.set(id, strength);
      }
      continue;
    }
    held.set(id, strength);
    const step = stepOf(r.tbl);
    if (maxStep && cmpStep(step, maxStep) < 0) {
      problems.push(`step went back: ${show(r)} at step ${step.join(".")} after ${maxAt} at step ${maxStep.join(".")}`);
    } else if (!maxStep || cmpStep(step, maxStep) > 0) {
      maxStep = step;
      maxAt = show(r);
    }
    const last = lastKey.get(r.tbl);
    if (last !== undefined && r.key < last) problems.push(`out of id order: ${show(r)} after ${r.tbl}[${last}]`);
    if (last === undefined || r.key > last) lastKey.set(r.tbl, r.key);
  }
  return problems;
}

// ---------------------------------------------------------------------------
// The wrapper

export interface LockViolation { label: string; problems: string[]; trace: TraceRow[] }

/** Enforced violations since the last {@link takeLockViolations}; the setup file fails the test on any. */
const enforced: LockViolation[] = [];

export function takeLockViolations(): LockViolation[] {
  return enforced.splice(0, enforced.length);
}

const MODE_OF: Record<string, string> = { "no-key-update": "no key update", "key-share": "key share", share: "share", update: "update" };

/**
 * A SQL-aware scan of a statement text: comments (line comments and nested block comments)
 * become a space, and their text is collected (lock tags live there);
 * string literals ('…' with '' escapes, E'…' with backslash escapes too)
 * and dollar-quoted bodies become an empty literal; double-quoted
 * identifiers stay, with any character in them that could read as syntax
 * replaced. What is left can be split on `;` and searched for keywords.
 */
export function scanSql(sql: string): { bare: string; comments: string[] } {
  let bare = "";
  const comments: string[] = [];
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i]!;
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      const end = sql.indexOf("\n", i);
      comments.push(sql.slice(i, end < 0 ? n : end));
      i = end < 0 ? n : end;
      bare += " ";
    } else if (c === "/" && next === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (sql[j] === "/" && sql[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (sql[j] === "*" && sql[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      comments.push(sql.slice(i, j));
      i = j;
      bare += " ";
    } else if (c === "'") {
      // An E'…' string (the E right before the quote, not part of a word) also takes backslash escapes.
      const escaped = /[eE]/.test(bare.slice(-1)) && !/\w/.test(bare.slice(-2, -1));
      if (escaped) bare = bare.slice(0, -1);
      let j = i + 1;
      while (j < n) {
        if (escaped && sql[j] === "\\") j += 2;
        else if (sql[j] === "'" && sql[j + 1] === "'") j += 2;
        else if (sql[j] === "'") break;
        else j++;
      }
      i = j + 1;
      bare += "''";
    } else if (c === '"') {
      let j = i + 1;
      let name = "";
      while (j < n) {
        if (sql[j] === '"' && sql[j + 1] === '"') {
          name += "_";
          j += 2;
        } else if (sql[j] === '"') break;
        else {
          name += /[\w.]/.test(sql[j]!) ? sql[j] : "_";
          j++;
        }
      }
      i = j + 1;
      bare += `"${name}"`;
    } else if (c === "$" && !/\w/.test(bare.slice(-1))) {
      const tag = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i));
      if (!tag) {
        bare += c;
        i++;
        continue;
      }
      const end = sql.indexOf(tag[0], i + tag[0].length);
      i = end < 0 ? n : end + tag[0].length;
      bare += "''";
    } else {
      bare += c;
      i++;
    }
  }
  return { bare, comments };
}

function bareSql(sql: string): string {
  return scanSql(sql).bare;
}

/** The statements of a (possibly compound) SQL text. */
export function statementsOf(sql: string): string[] {
  return bareSql(sql).split(";").map((s) => s.trim()).filter(Boolean);
}

const BOUNDARY = /^(BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION)\b/i;

/**
 * The grammar a statement with a locking clause may use, and nothing else:
 * the checker refuses rather than parses anything outside it (Codex's
 * review of #106). At the locking clause's query level:
 * - FROM is one or more plain base tables, optionally schema-qualified,
 *   joined by commas or by [INNER | LEFT [OUTER]] JOIN … ON <condition>,
 *   each with an optional simple, unquoted alias that is not a keyword;
 * - no quoted identifier anywhere in the FROM clause or the locking clause;
 * - no subquery, LATERAL, function, VALUES or CTE in FROM, and no WITH
 *   (subqueries in WHERE stay allowed: they lock nothing);
 * - the clause is FOR <mode> [OF <item>] [NOWAIT | SKIP LOCKED] and locks
 *   exactly one FROM item: OF names one item of that FROM, or the FROM has
 *   a single item (a self-join or a second locked item could otherwise
 *   lock rows the trace never records).
 * A query outside this grammar is to be simplified or split, as
 * Organization deletion's environment lock was.
 */
const SIMPLE_NAME = /^[a-z_][a-z0-9_]*$/i;
const TABLE_NAME = /^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?$/i;
const KEYWORDS = new Set([
  "all", "and", "any", "as", "by", "cross", "except", "fetch", "for", "from", "full", "group", "having", "in", "inner", "intersect",
  "is", "join", "lateral", "left", "limit", "natural", "not", "null", "offset", "on", "only", "or", "order", "outer", "returning",
  "right", "rows", "select", "set", "tablesample", "union", "using", "values", "where", "window", "with",
]);
const CLAUSE_END = /\b(?:WHERE|GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT|OFFSET|FETCH|FOR|WINDOW|UNION|INTERSECT|EXCEPT|RETURNING)\b/i;
const JOIN = /^(?:INNER\s+|LEFT\s+(?:OUTER\s+)?)?JOIN$/i;

function outsideGrammar(sql: string, why: string): Error {
  return new Error(
    `lock trace: a locking statement outside the allowed grammar (${why}). Use plain base tables joined by commas or JOIN … ON, ` +
      `simple unquoted aliases, and FOR … OF those aliases; no quoting, subqueries, LATERAL, functions, VALUES or CTEs in FROM. ` +
      `Simplify or split the query: ${sql.slice(0, 200)}`,
  );
}

/** Replaces every parenthesized group, innermost first, with a marker: what is left is one query level. */
function flatten(text: string): string {
  let out = text;
  for (let prev = ""; prev !== out; ) {
    prev = out;
    out = out.replace(/\([^()]*\)/g, " § ");
  }
  return out;
}

/** The FROM items of one flattened query level, under the grammar above. */
function fromItems(level: string, sql: string): { table: string; name: string }[] {
  const from = /\bFROM\b/i.exec(level);
  if (!from) throw outsideGrammar(sql, "no FROM");
  let text = level.slice(from.index + from[0].length);
  const end = CLAUSE_END.exec(text);
  if (end) text = text.slice(0, end.index);
  if (/["§]/.test(text)) throw outsideGrammar(sql, "a quoted identifier, a subquery or a function in FROM");
  const tokens = text.replace(/,/g, " , ").trim().split(/\s+/).filter(Boolean);
  const items: { table: string; name: string }[] = [];
  let i = 0;
  const readItem = () => {
    const table = tokens[i++];
    if (!table || !TABLE_NAME.test(table) || KEYWORDS.has(table.toLowerCase())) throw outsideGrammar(sql, `FROM item "${table ?? ""}"`);
    let alias: string | null = null;
    if (tokens[i]?.toLowerCase() === "as") i++;
    const next = tokens[i];
    if (next && next !== "," && !KEYWORDS.has(next.toLowerCase())) {
      if (!SIMPLE_NAME.test(next)) throw outsideGrammar(sql, `alias "${next}"`);
      alias = next.toLowerCase();
      i++;
    }
    const relation = table.toLowerCase().replace(/^public\./, "");
    items.push({ table: relation, name: alias ?? relation });
  };
  readItem();
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t === ",") {
      i++;
      readItem();
      continue;
    }
    // [INNER | LEFT [OUTER]] JOIN item ON condition
    let j = i;
    while (j < tokens.length && !/^JOIN$/i.test(tokens[j]!) && j - i < 3) j++;
    if (!JOIN.test(tokens.slice(i, j + 1).join(" "))) throw outsideGrammar(sql, `"${tokens.slice(i, j + 1).join(" ")}" in FROM`);
    i = j + 1;
    readItem();
    if (tokens[i]?.toUpperCase() !== "ON") throw outsideGrammar(sql, "a JOIN without ON");
    i++;
    // The condition: everything up to the next item separator.
    while (i < tokens.length && tokens[i] !== "," && !/^(?:INNER|LEFT|JOIN|RIGHT|FULL|CROSS|NATURAL)$/i.test(tokens[i]!)) i++;
  }
  return items;
}

const LOCKING_CLAUSE = /\bFOR\s+(NO\s+KEY\s+UPDATE|KEY\s+SHARE|UPDATE|SHARE)\b((?:\s+OF\s+[^\s,]+(?:\s*,\s*[^\s,]+)*)?)(\s+(?:NOWAIT|SKIP\s+LOCKED))?/gi;

/**
 * The locking clauses of a statement and, for each, the relations it locks:
 * those named by FOR … OF, or else every item of its query level's FROM.
 * Anything outside the grammar above is refused.
 */
export function lockingClauses(sql: string): { mode: string; relations: string[] }[] {
  const bare = bareSql(sql);
  const clauses = [...bare.matchAll(LOCKING_CLAUSE)];
  if (clauses.length > 0 && /^\s*WITH\b/i.test(bare)) throw outsideGrammar(sql, "WITH");
  return clauses.map((m) => {
    const at = m.index!;
    // The innermost parenthesized group around the clause, if any.
    const open: number[] = [];
    for (let i = 0; i < at; i++) {
      if (bare[i] === "(") open.push(i);
      else if (bare[i] === ")") open.pop();
    }
    const start = open.length > 0 ? open[open.length - 1]! + 1 : 0;
    let end = bare.length;
    for (let i = at, depth = 0; i < bare.length; i++) {
      if (bare[i] === "(") depth++;
      else if (bare[i] === ")") {
        if (depth === 0) {
          end = i;
          break;
        }
        depth--;
      }
    }
    const level = flatten(bare.slice(start, end));
    if (/^\s*WITH\b/i.test(level)) throw outsideGrammar(sql, "WITH");
    const items = fromItems(level, sql);
    const ofText = m[2]?.replace(/^\s+OF\s+/i, "");
    if (ofText && /["§]/.test(ofText)) throw outsideGrammar(sql, "a quoted name after OF");
    const of = ofText ? ofText.split(",").map((a) => a.trim().toLowerCase()) : null;
    // Exactly one locked FROM item, counted as items, not tables: a
    // self-join locks two rows of one table.
    if (of ? of.length !== 1 : items.length !== 1) {
      throw outsideGrammar(sql, of ? "FOR … OF naming more than one item" : "a locking clause without OF over several FROM items");
    }
    const relations = of
      ? of.map((a) => {
        const item = items.find((x) => x.name === a);
        if (!item) throw new Error(`lock trace: FOR … OF ${a} names no relation of its query: ${sql.slice(0, 200)}`);
        return item.table;
      })
      : items.map((x) => x.table);
    return { mode: m[1]!.toLowerCase().replace(/\s+/g, " "), relations };
  });
}

/** The lock tags of a statement: only from its comments, never from a string literal. */
function tagsOf(sql: string): { table: string; mode: string; key: string }[] {
  return scanSql(sql).comments.flatMap((comment) =>
    [...comment.matchAll(LOCK_TAG)].map((m) => ({ table: m[1]!, mode: MODE_OF[m[2]!]!, key: m[3]! })));
}

/**
 * The tag of a statement that takes row locks, checked against what the
 * statement locks: one tag, the same mode, and the one relation it names.
 * A statement that locks rows of several relations, or of a relation the
 * tag does not name, is refused. Null when the statement locks nothing.
 */
export function lockTagOf(sql: string): { table: string; mode: string; key: string } | null {
  const clauses = lockingClauses(sql);
  const tags = tagsOf(sql);
  if (clauses.length === 0) {
    if (tags.length > 0) throw new Error(`lock trace: a lock tag on a statement without a locking clause: ${sql.slice(0, 160)}`);
    return null;
  }
  if (tags.length !== 1) throw new Error(`lock trace: untagged locking clause (use lockedQuery or a lock helper): ${sql.slice(0, 200)}`);
  const tag = tags[0]!;
  for (const clause of clauses) {
    if (clause.mode !== tag.mode) throw new Error(`lock trace: the tag says ${tag.mode}, the statement locks ${clause.mode}: ${sql.slice(0, 200)}`);
    if (clause.relations.length !== 1) {
      throw new Error(`lock trace: one locking clause locks ${clause.relations.length === 0 ? "no relation it names" : `several relations (${clause.relations.join(", ")}); name one with FOR … OF`}: ${sql.slice(0, 200)}`);
    }
    if (clause.relations[0] !== tag.table) {
      throw new Error(`lock trace: the tag names ${tag.table}, the statement locks ${clause.relations[0]}: ${sql.slice(0, 200)}`);
    }
  }
  return tag;
}

/** The function in src/ that began the transaction, for reports and gating. */
function writerLabel(): string {
  const limit = Error.stackTraceLimit;
  Error.stackTraceLimit = 60;
  const stack = new Error().stack ?? "";
  Error.stackTraceLimit = limit;
  const lines = stack.split("\n").slice(1);
  for (const line of lines) {
    const m = /at (?:async )?(?:(\S+) \()?(?:file:\/\/)?([^()\s]*\/services\/varlatchd\/src\/([^:()]+)):(\d+)/.exec(line);
    if (!m || m[3]!.startsWith("db/")) continue;
    const name = m[1]?.replace(/^(Object|Module)\./, "");
    return name && name !== "<anonymous>" ? name : `${m[3]}:${m[4]}`;
  }
  const test = lines.map((l) => /\/services\/varlatchd\/(test\/[^:()]+:\d+)/.exec(l)?.[1]).find((t) => t && !t.includes("/helpers/"));
  return `(test) ${test ?? lines.slice(0, 6).join(" | ")}`;
}

/**
 * Wraps a single-connection test database (PGlite) with the trace: refuses
 * untagged locking clauses, records tagged ones, and checks each
 * transaction at COMMIT.
 */
export function lockTraced<Q extends Querier>(db: Q, mode: Exclude<LockOrderMode, "off">): Q {
  let inTx = false;
  let label = "";
  const report = process.env.VARLATCH_LOCK_TRACE_REPORT;

  /**
   * The statements of a text, refusing a compound one that begins or ends
   * a transaction: the wrapper sees transaction boundaries only as
   * statements of their own, so `BEGIN; …; COMMIT` in one call would
   * escape the check.
   */
  const split = (text: string) => {
    const statements = statementsOf(text);
    if (statements.length > 1 && statements.some((s) => BOUNDARY.test(s))) {
      throw new Error(`lock trace: send BEGIN, COMMIT and ROLLBACK as statements of their own, not in a compound statement: ${text.slice(0, 160)}`);
    }
    return statements;
  };

  const check = async () => {
    let rows: TraceRow[];
    try {
      const tx = ((await db.query("SELECT txid_current_if_assigned()::text AS x")).rows[0] as { x: string | null }).x;
      if (tx === null) return;
      rows = ((await db.query(`SELECT seq::int AS seq, tbl, key, mode, kind FROM ${SCHEMA}.trace WHERE txid = $1::bigint ORDER BY seq`, [tx])).rows as TraceRow[]);
      await db.query(`DELETE FROM ${SCHEMA}.trace WHERE txid = $1::bigint`, [tx]);
    } catch {
      return; // an aborted transaction: COMMIT rolls it back
    }
    const problems = checkTrace(rows);
    // VARLATCH_LOCK_TRACE_LABELS: one line per checked transaction, to see what a run covered.
    if (process.env.VARLATCH_LOCK_TRACE_LABELS) appendFileSync(process.env.VARLATCH_LOCK_TRACE_LABELS, `${label}\t${problems.length}\n`);
    if (problems.length === 0) return;
    const violation = { label, problems, trace: rows };
    if (mode === "all" || (mode === "migrated" && MIGRATED.has(label))) enforced.push(violation);
    else if (report) appendFileSync(report, `${JSON.stringify({ file: process.env.VITEST_TEST_FILE ?? null, label, problems })}\n`);
  };

  const query = async (text: string, params?: unknown[]) => {
    const first = split(text)[0] ?? "";
    if (/^(BEGIN|START\s+TRANSACTION)\b/i.test(first)) {
      // Before any await: the stack still shows who began the transaction.
      const began = writerLabel();
      if (!inTx) await db.query(`DELETE FROM ${SCHEMA}.trace`);
      const res = await db.query(text, params);
      inTx = true;
      label = began;
      return res;
    }
    if (/^(COMMIT|END)\b/i.test(first) && !/^COMMIT\s+PREPARED\b/i.test(first)) {
      if (inTx) await check();
      inTx = false;
      return db.query(text, params);
    }
    if (/^(ROLLBACK|ABORT)(\s+(WORK|TRANSACTION))?$/i.test(first)) {
      inTx = false;
      return db.query(text, params);
    }
    const tag = lockTagOf(text);
    const res = await db.query(text, params);
    if (tag && tag.key !== "-") {
      const param = /^\$(\d+)$/.exec(tag.key);
      for (const row of res.rows as Record<string, unknown>[]) {
        const key = param ? params?.[Number(param[1]) - 1] : row[tag.key];
        if (key === undefined || key === null) throw new Error(`lock trace: the locked rows carry no ${tag.key} column: ${text.slice(0, 200)}`);
        await db.query(
          `INSERT INTO ${SCHEMA}.trace VALUES (txid_current(), nextval('${SCHEMA}.seq'), $1, $2, $3, 'explicit')`,
          [tag.table, String(key), tag.mode],
        );
      }
    }
    return res;
  };

  const exec = async (text: string) => {
    const statements = split(text);
    if (statements.length === 1 && BOUNDARY.test(statements[0]!)) return query(text);
    if (lockTagOf(text)) throw new Error(`lock trace: run tagged locks through query, not exec: ${text.slice(0, 160)}`);
    const run = () => (db.exec ? db.exec(text) : db.query(text));
    if (inTx || statements.length < 2) return run();
    // Several statements outside a transaction run as one implicit
    // transaction; run them in an explicit one instead (the same effect),
    // so its trace is checked at COMMIT like any other.
    await query("BEGIN");
    try {
      const res = await run();
      await query("COMMIT");
      return res;
    } catch (err) {
      await query("ROLLBACK");
      throw err;
    }
  };

  return { ...db, query, exec };
}
