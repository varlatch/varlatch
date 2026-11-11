// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { lockedQuery } from "../src/db/locks.js";
import { withTx } from "../src/db/tx.js";
import { lockPeople } from "../src/domain/personlocks.js";
import { checkTrace, installLockTrace, lockOrderMode, lockTagOf, lockTraced, scanSql, statementsOf, takeLockViolations, type TraceRow } from "./helpers/lock-trace.js";
import { checkAuditBeforeDecryption, isKeyOnlyLock, traceLog } from "./helpers/trace.js";
import { migratedTestDb } from "./helpers/pglite.js";

/** The lock-order check itself (ADR-0054 amendment E): the rules, then the trace it reads. */

const row = (seq: number, tbl: string, key: string, mode: string, kind: TraceRow["kind"] = "explicit"): TraceRow => ({ seq, tbl, key, mode, kind });

describe("the retrieval snapshot check and tagged locks", () => {
  const after = (text: string) => {
    const log = traceLog();
    log.entries.push(
      { kind: "sql", text: "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", params: [] },
      { kind: "sql", text: "COMMIT", params: [] },
      { kind: "sql", text: "BEGIN", params: [] },
      { kind: "sql", text, params: [] },
      { kind: "sql", text: "COMMIT", params: [] },
    );
    return () => checkAuditBeforeDecryption(log);
  };

  it("lets a key-only lock of a snapshot table through, and refuses a tagged read of retrieval data", () => {
    const keyOnly = "SELECT id FROM organizations WHERE id = ANY($1) ORDER BY id FOR KEY SHARE /* varlatch-lock organizations key-share id */";
    expect(isKeyOnlyLock(keyOnly)).toBe(true);
    expect(after(keyOnly)).not.toThrow();
    const tagged = "SELECT * FROM value_versions WHERE id = ANY($1) ORDER BY id FOR SHARE /* varlatch-lock value_versions share id */";
    expect(isKeyOnlyLock(tagged)).toBe(false);
    expect(after(tagged)).toThrow(/read after the snapshot/);
    expect(isKeyOnlyLock("SELECT deleted_at FROM organizations WHERE id = $1 FOR KEY SHARE /* varlatch-lock organizations key-share $1 */")).toBe(false);
    expect(isKeyOnlyLock("SELECT id, payload FROM value_versions FOR SHARE /* varlatch-lock value_versions share id */")).toBe(false);
    // A tag naming a data column as its key is not a key-only lock.
    const payloadKey = "SELECT payload FROM value_versions WHERE id = $1 FOR SHARE /* varlatch-lock value_versions share payload */";
    expect(isKeyOnlyLock(payloadKey)).toBe(false);
    expect(after(payloadKey)).toThrow(/read after the snapshot/);
  });
});

describe("checkTrace", () => {
  it("fails an approval consumed without its person held FOR UPDATE first", () => {
    expect(checkTrace([
      row(1, "identities", "idn_a", "key share"),
      row(2, "approval_intents", "apr_a", "no key update", "write"),
      row(3, "identities", "idn_a", "update", "consume"),
    ])).toEqual([expect.stringMatching(/^an approval consumed without its person locked FOR UPDATE/)]);
    expect(checkTrace([
      row(1, "identities", "idn_a", "update"),
      row(2, "approval_intents", "apr_a", "no key update", "write"),
      row(3, "identities", "idn_a", "update", "consume"),
    ])).toEqual([]);
  });

  it("passes the order: Organization, people, Project, environment, value, audit, and reuse of a held person", () => {
    expect(checkTrace([
      row(1, "organizations", "org_a", "key share"),
      row(2, "identities", "idn_a", "key share"),
      row(3, "projects", "prj_a", "key share"),
      row(4, "environments", "env_a", "no key update"),
      row(5, "env_values", "val_a", "no key update"),
      row(6, "value_versions", "ver_a", "insert", "insert"),
      row(7, "env_values", "val_a", "key share", "reference"),
      row(8, "identities", "idn_a", "key share", "reference"),
      row(9, "audit_position", "true", "no key update", "write"),
      row(10, "audit_events", "evt_a", "insert", "insert"),
    ])).toEqual([]);
  });

  it("fails a referenced identity that was not locked first", () => {
    expect(checkTrace([
      row(1, "organizations", "org_a", "key share"),
      row(2, "value_versions", "ver_a", "insert", "insert"),
      row(3, "identities", "idn_a", "key share", "reference"),
    ])).toEqual([expect.stringMatching(/^identity referenced without being locked at step 2 first/)]);
  });

  it("passes a reference to an identity the transaction created", () => {
    expect(checkTrace([
      row(1, "identities", "idn_new", "insert", "insert"),
      row(2, "credentials", "crd_a", "insert", "insert"),
      row(3, "identities", "idn_new", "key share", "reference"),
    ])).toEqual([]);
  });

  it("fails an upgrade of one row, and tells it from locks on two rows", () => {
    expect(checkTrace([
      row(1, "sync_targets", "tgt_a", "share"),
      row(2, "sync_targets", "tgt_a", "no key update", "write"),
    ])).toEqual([expect.stringMatching(/^upgrade: sync_targets\[tgt_a\] no key update/)]);
    expect(checkTrace([
      row(1, "sync_targets", "tgt_a", "share"),
      row(2, "sync_targets", "tgt_b", "no key update", "write"),
    ])).toEqual([]);
  });

  it("fails a step that goes back, and the step-10 types out of order", () => {
    expect(checkTrace([
      row(1, "organizations", "org_a", "key share"),
      row(2, "environments", "env_a", "no key update"),
      row(3, "identities", "idn_a", "key share"),
    ])).toEqual([expect.stringMatching(/^step went back: identities\[idn_a\]/)]);
    expect(checkTrace([
      row(1, "sync_targets", "tgt_a", "update"),
      row(2, "platform_connections", "con_a", "share"),
    ])).toEqual([expect.stringMatching(/^step went back: platform_connections\[con_a\] share .* at step 10\.2 after sync_targets/)]);
    expect(checkTrace([
      row(1, "audit_position", "true", "no key update", "write"),
      row(2, "env_values", "val_a", "no key update", "write"),
    ])).toEqual([expect.stringMatching(/^step went back: env_values/)]);
  });

  it("fails a change of a person's row without an explicit FOR UPDATE prelock", () => {
    expect(checkTrace([
      row(1, "identities", "idn_a", "key share"),
      row(2, "identities", "idn_a", "no key update", "write"),
    ])).toEqual([
      expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock/),
      expect.stringMatching(/^upgrade: identities\[idn_a\]/),
    ]);
    expect(checkTrace([row(1, "identities", "idn_a", "no key update", "write")]))
      .toEqual([expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock/)]);
    expect(checkTrace([
      row(1, "identities", "idn_a", "update"),
      row(2, "identities", "idn_a", "no key update", "write"),
    ])).toEqual([]);
  });

  it("places the installation row at step 0.5 and Idempotency-Key claims at step 2.5", () => {
    expect(checkTrace([
      row(1, "installation", "inst_a", "update"),
      row(2, "organizations", "org_a", "key share"),
      row(3, "identities", "idn_a", "key share"),
      row(4, "idempotency_keys", "idn_a|ep|k", "insert", "insert"),
      row(5, "identities", "idn_a", "key share", "reference"),
      row(6, "projects", "prj_a", "key share"),
    ])).toEqual([]);
    expect(checkTrace([
      row(1, "organizations", "org_a", "key share"),
      row(2, "installation", "inst_a", "update"),
    ])).toEqual([expect.stringMatching(/^step went back: installation/)]);
  });

  it("fails rows of one table out of id order, within a step", () => {
    expect(checkTrace([
      row(1, "environments", "env_b", "share"),
      row(2, "environments", "env_a", "share"),
    ])).toEqual([expect.stringMatching(/^out of id order: environments\[env_a\]/)]);
  });
});

describe("scanSql", () => {
  it("reads statements the way PostgreSQL does: strings, identifiers, dollar quotes and comments", () => {
    expect(statementsOf("SELECT '--'; BEGIN; UPDATE t SET a = 1; COMMIT;")).toEqual(["SELECT ''", "BEGIN", "UPDATE t SET a = 1", "COMMIT"]);
    expect(statementsOf("SELECT 'it''s; here' /* a; /* nested; */ b; */ FROM t")).toHaveLength(1);
    expect(statementsOf("SELECT E'\\'; BEGIN'; COMMIT")).toEqual(["SELECT ''", "COMMIT"]);
    expect(statementsOf('SELECT "a;b" FROM t; COMMIT')).toEqual(['SELECT "a_b" FROM t', "COMMIT"]);
    expect(statementsOf("DO $x$ BEGIN; END $x$; SELECT $1::text")).toEqual(["DO ''", "SELECT $1::text"]);
    expect(statementsOf("SELECT 1 -- ; COMMIT\n; COMMIT")).toEqual(["SELECT 1", "COMMIT"]);
    expect(scanSql("SELECT '/* varlatch-lock identities update id */' FOR UPDATE").comments).toEqual([]);
  });
});

describe("the grammar a locking statement may use (refused rather than parsed outside it)", () => {
  const tag = (table: string) => ` /* varlatch-lock ${table} update id */`;
  const refused = (sql: string) => expect(() => lockTagOf(sql), sql).toThrow(/outside the allowed grammar/);

  it("refuses quoted identifiers in FROM or after OF", () => {
    // Codex: a quoted keyword alias used to cut the FROM clause short and hide the JOIN.
    refused(`SELECT "where".id FROM identities "where" JOIN organizations o ON o.id = "where".organization_id FOR UPDATE${tag("identities")}`);
    refused(`SELECT id FROM "identities" FOR UPDATE${tag("identities")}`);
    refused(`SELECT i.id FROM identities i JOIN organizations o ON o.id = i."organization_id" FOR UPDATE OF i${tag("identities")}`);
    refused(`SELECT i.id FROM identities i FOR UPDATE OF "i"${tag("identities")}`);
  });

  it("refuses subqueries, LATERAL, functions, VALUES, ONLY and CTEs in FROM", () => {
    // Codex: a LATERAL subquery's alias read as a base relation, while PostgreSQL locks organizations.
    refused(`SELECT id FROM LATERAL (SELECT id FROM organizations) identities FOR UPDATE${tag("identities")}`);
    refused(`SELECT id FROM LATERAL (SELECT id FROM organizations) identities FOR UPDATE OF identities${tag("identities")}`);
    refused(`SELECT id FROM (SELECT id FROM organizations) identities FOR UPDATE${tag("identities")}`);
    refused(`SELECT i.id FROM identities i JOIN (SELECT id FROM organizations) o ON o.id = i.organization_id FOR UPDATE OF i${tag("identities")}`);
    refused(`SELECT id FROM unnest($1::text[]) identities(id) FOR UPDATE${tag("identities")}`);
    refused(`SELECT id FROM (VALUES ('a')) identities(id) FOR UPDATE${tag("identities")}`);
    refused(`SELECT id FROM ONLY identities FOR UPDATE${tag("identities")}`);
    refused(`WITH x AS (SELECT id FROM organizations) SELECT id FROM identities FOR UPDATE${tag("identities")}`);
    refused(`SELECT i.id FROM identities i RIGHT JOIN organizations o ON o.id = i.organization_id FOR UPDATE OF i${tag("identities")}`);
  });

  it("refuses a clause that locks more than one FROM item, a self-join included", () => {
    // Codex: a self-join locked two rows of one table while the trace recorded one.
    const selfJoin = "SELECT a.id FROM identities a JOIN identities b ON b.id <> a.id WHERE a.id = 'idn_b' AND b.id = 'idn_a'";
    refused(`${selfJoin} FOR UPDATE OF a, b${tag("identities")}`);
    refused(`${selfJoin} FOR UPDATE${tag("identities")}`);
    refused(`SELECT a.id FROM identities a, identities b WHERE b.id <> a.id FOR UPDATE${tag("identities")}`);
    refused(`SELECT i.id FROM identities i JOIN organizations o ON o.id = i.organization_id FOR UPDATE OF i, o${tag("identities")}`);
    // One locked item of a self-join is fine: only its rows are locked.
    expect(lockTagOf(`${selfJoin} FOR UPDATE OF a${tag("identities")}`)?.table).toBe("identities");
  });

  it("refuses a second locking clause, and a locking clause in a subquery whose keys would not be its own", () => {
    // The reviewer's probe (#106 at 2fb2680).
    refused(`SELECT a.id FROM identities a JOIN identities b ON b.id = a.organization_id FOR UPDATE OF a FOR UPDATE OF b${tag("identities")}`);
    refused(`SELECT a.id FROM identities a, identities b WHERE b.id = $2 AND a.id = $1 FOR UPDATE OF a FOR UPDATE OF b${tag("identities")}`);
    refused(`SELECT id FROM identities WHERE id = $1 AND EXISTS (SELECT 1 FROM identities x WHERE x.id = $2 FOR UPDATE) FOR UPDATE${tag("identities")}`);
    refused(`SELECT id FROM identities WHERE id IN (SELECT id FROM identities WHERE organization_id = $1 FOR UPDATE)${tag("identities")}`);
    refused(`SELECT id FROM projects WHERE organization_id IN (SELECT id FROM organizations WHERE id = $1 FOR UPDATE)${tag("organizations")}`);
    refused(`SELECT p.id FROM projects p WHERE p.id = $1 AND EXISTS (SELECT 1 FROM environments e WHERE e.project_id = p.id FOR UPDATE)${tag("environments")}`);
    refused(`SELECT a.id FROM identities a JOIN identities b ON true FOR UPDATE OF a, b${tag("identities")}`);
    // A nested lock even in a DELETE needs key "-", and a top-level one needs recorded keys.
    refused(`DELETE FROM identities WHERE id IN (SELECT id FROM identities FOR UPDATE SKIP LOCKED)${tag("identities")}`);
    refused("SELECT id FROM identities FOR UPDATE /* varlatch-lock identities update - */");
    // Codex: an UPDATE of another table hid a person lock behind its own write.
    refused("UPDATE organizations SET name = 'A2' WHERE id = 'org_a' AND EXISTS (SELECT 1 FROM identities WHERE id = 'idn_a' FOR UPDATE) /* varlatch-lock identities update - */");
    refused("DELETE FROM organizations WHERE id IN (SELECT organization_id FROM identities FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */");
    expect(() => lockTagOf("DELETE FROM identities WHERE id IN (SELECT id FROM identities FOR UPDATE SKIP LOCKED) /* varlatch-lock organizations update - */"))
      .toThrow(/the tag names organizations, the statement locks identities/);
    // A same-table nested lock that locks rows it does not write.
    refused("UPDATE identities SET name = 'x' WHERE id = 'a' AND EXISTS (SELECT 1 FROM identities WHERE id = 'b' FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */");
    refused("DELETE FROM identities WHERE id IN (SELECT id FROM identities FOR UPDATE) /* varlatch-lock identities update - */");
    refused("DELETE FROM identities WHERE id IN (SELECT organization_id FROM identities FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */");
    refused("DELETE FROM identities i USING (SELECT id, name FROM identities FOR UPDATE SKIP LOCKED) d WHERE i.id = d.id /* varlatch-lock identities update - */");
    // A top-level lock outside a plain SELECT returns no locked keys.
    refused(`INSERT INTO organizations (id, slug) SELECT id, id FROM identities WHERE id = 'a' FOR UPDATE${tag("identities")}`);
    refused(`SELECT id INTO TEMP t FROM identities WHERE id = 'a' FOR UPDATE${tag("identities")}`);
    refused(`DECLARE c CURSOR FOR SELECT id FROM identities WHERE id = 'a' FOR UPDATE${tag("identities")}`);
    // The sweep's IN column must be the target's, and an UPDATE … FROM writes other rows.
    refused("UPDATE identities SET name = 'x' FROM organizations o WHERE o.id IN (SELECT id FROM identities WHERE id = 'b' FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */");
    refused("DELETE FROM identities i WHERE o.id IN (SELECT id FROM identities FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */");
    // The selected column must be the locked item's, not a joined unlocked one's.
    refused("DELETE FROM identities WHERE id IN (SELECT o.id FROM identities i JOIN organizations o ON o.id = i.organization_id FOR UPDATE OF i SKIP LOCKED) /* varlatch-lock identities update - */");
    refused("DELETE FROM identities WHERE id IN (SELECT id FROM identities i JOIN organizations o ON o.id = i.organization_id FOR UPDATE OF i SKIP LOCKED) /* varlatch-lock identities update - */");
    // Exactly one subquery level.
    refused("DELETE FROM identities WHERE id IN (SELECT id FROM identities WHERE id = 'a' AND id IN (SELECT id FROM identities FOR UPDATE SKIP LOCKED)) /* varlatch-lock identities update - */");
    // A qualified column of the locked item, or its alias, stays allowed.
    expect(lockTagOf("DELETE FROM identities t WHERE t.id IN (SELECT i.id FROM identities i JOIN organizations o ON o.id = i.organization_id FOR UPDATE OF i SKIP LOCKED) /* varlatch-lock identities update - */")?.key).toBe("-");
    // The sweep pattern stays allowed, in both shapes the code uses.
    expect(lockTagOf(
      "DELETE FROM security_control_counters c USING (SELECT organization_id, control FROM security_control_counters k ORDER BY organization_id LIMIT $2 FOR UPDATE SKIP LOCKED) d WHERE c.organization_id = d.organization_id AND c.control = d.control RETURNING 1 /* varlatch-lock security_control_counters update - */",
    )?.key).toBe("-");
    expect(lockTagOf("DELETE FROM identities WHERE id IN (SELECT id FROM identities ORDER BY id FOR UPDATE SKIP LOCKED) /* varlatch-lock identities update - */")?.key).toBe("-");
  });

  it("accepts the grammar the code uses", () => {
    expect(lockTagOf(`SELECT id FROM identities WHERE organization_id IN (SELECT id FROM organizations) ORDER BY id FOR UPDATE${tag("identities")}`)?.table).toBe("identities");
    expect(lockTagOf(`SELECT i.id FROM identities i JOIN organizations o ON o.id = i.organization_id WHERE o.id = $1 FOR UPDATE OF i${tag("identities")}`)?.table).toBe("identities");
    expect(lockTagOf(`SELECT p.id FROM passkey p LEFT JOIN passkey_provenance pp ON pp.passkey_id = p.id, auth_user_links l WHERE l.better_auth_user_id = p."userId" FOR UPDATE OF p /* varlatch-lock passkey update id */`)?.table).toBe("passkey");
    expect(lockTagOf(`SELECT id FROM public.sync_targets WHERE id = ANY($1) ORDER BY id FOR UPDATE SKIP LOCKED /* varlatch-lock sync_targets update id */`)?.table).toBe("sync_targets");
  });
});

describe.skipIf(lockOrderMode() === "off")("the trace on the test database", () => {
  let db: Awaited<ReturnType<typeof migratedTestDb>>;
  beforeEach(async () => {
    // Every transaction enforced, whoever began it.
    db = await migratedTestDb({ lockOrder: "all" });
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'a', 'A', '{}'::jsonb)");
    await db.query("INSERT INTO identities (id, organization_id, kind, name) VALUES ('idn_b', 'org_a', 'service', 'b'), ('idn_a', 'org_a', 'service', 'a')");
  });
  afterEach(async () => {
    takeLockViolations();
    await db.close();
  });

  it("refuses a locking statement no helper tagged, through query and exec", async () => {
    await expect(db.query("SELECT id FROM identities WHERE id = 'idn_a' FOR UPDATE")).rejects.toThrow(/untagged locking clause/);
    await expect(db.exec!("SELECT id FROM identities WHERE id = 'idn_a' FOR KEY SHARE")).rejects.toThrow(/untagged locking clause/);
    await expect(lockedQuery(db, { table: "identities", mode: "share" }, "SELECT id FROM identities FOR UPDATE")).rejects.toThrow(/the tag says share/);
  });

  it("refuses a compound statement that begins or ends a transaction, through exec and query", async () => {
    await expect(db.exec!(
      "BEGIN; UPDATE identities SET name = 'b2' WHERE id = 'idn_b'; UPDATE organizations SET name = 'A2' WHERE id = 'org_a'; COMMIT;",
    )).rejects.toThrow(/statements of their own/);
    await expect(db.query("SELECT 1; COMMIT")).rejects.toThrow(/statements of their own/);
    // A comment marker inside a string literal does not hide the rest.
    await expect(db.exec!(
      "SELECT '--'; BEGIN; UPDATE identities SET name = 'b2' WHERE id = 'idn_b'; UPDATE organizations SET name = 'A2' WHERE id = 'org_a'; COMMIT;",
    )).rejects.toThrow(/statements of their own/);
    expect((await db.query("SELECT name FROM organizations WHERE id = 'org_a'")).rows).toEqual([{ name: "A" }]);
    expect((await db.query("SELECT name FROM identities WHERE id = 'idn_b'")).rows).toEqual([{ name: "b" }]);
    expect(takeLockViolations()).toEqual([]);
  });

  it("checks the statements of one exec outside a transaction as one transaction", async () => {
    await db.exec!("UPDATE identities SET name = 'b2' WHERE id = 'idn_b'; UPDATE organizations SET name = 'A2' WHERE id = 'org_a'");
    const violations = takeLockViolations();
    expect(violations.map((v) => v.problems)).toEqual([[
      expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock at step 2: identities\[idn_b\]/),
      expect.stringMatching(/^step went back: organizations\[org_a\] no key update \(write/),
    ]]);
    expect((await db.query("SELECT name FROM organizations WHERE id = 'org_a'")).rows).toEqual([{ name: "A2" }]);
  });

  it("refuses a tag that names another relation than the statement locks, and one clause locking several relations", async () => {
    await expect(db.query("SELECT id FROM identities FOR UPDATE /* varlatch-lock organizations update id */"))
      .rejects.toThrow(/the tag names organizations, the statement locks identities/);
    const join = "SELECT i.id FROM identities i JOIN organizations o ON o.id = i.organization_id";
    await expect(lockedQuery(db, { table: "organizations", mode: "update" }, `${join} FOR UPDATE`)).rejects.toThrow(/without OF over several FROM items/);
    await expect(lockedQuery(db, { table: "organizations", mode: "update" }, `${join} FOR UPDATE OF i`))
      .rejects.toThrow(/the tag names organizations, the statement locks identities/);
    await expect(lockedQuery(db, { table: "identities", mode: "update" }, `${join} FOR UPDATE OF x`)).rejects.toThrow(/OF x names no relation/);
    // Comma-separated FROM items lock every relation, as a join does.
    const commas = "SELECT i.id FROM identities i, organizations o WHERE o.id = i.organization_id";
    await expect(lockedQuery(db, { table: "identities", mode: "update" }, `${commas} FOR UPDATE`)).rejects.toThrow(/without OF over several FROM items/);
    await expect(lockedQuery(db, { table: "identities", mode: "update" }, `${commas} FOR UPDATE OF o`))
      .rejects.toThrow(/the tag names identities, the statement locks organizations/);
    // A tag inside a string literal is not a tag.
    await expect(db.query("SELECT id, '/* varlatch-lock identities update id */' AS t FROM identities FOR UPDATE"))
      .rejects.toThrow(/untagged locking clause/);
    // Accepted: FOR … OF the tagged relation's alias; a subquery in WHERE locks nothing.
    await withTx(db, async (q) => {
      await lockedQuery(q, { table: "identities", mode: "key share" }, `${join} WHERE o.id = 'org_a' ORDER BY i.id FOR KEY SHARE OF i`);
      await lockedQuery(q, { table: "identities", mode: "key share" }, "SELECT id FROM identities WHERE organization_id IN (SELECT id FROM organizations) ORDER BY id FOR KEY SHARE");
      await lockedQuery(q, { table: "identities", mode: "key share" }, `${commas} ORDER BY i.id FOR KEY SHARE OF i`);
    });
    expect(takeLockViolations()).toEqual([]);
  });

  it("checks a lone statement outside a transaction once it takes more than one row lock", async () => {
    // Statements this test issues itself count as production's here (a
    // test's own fixture statements are otherwise not checked).
    const own = await migratedTestDb({ lockOrder: "all", checkTestStatements: true });
    await db.close();
    db = own;
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'a', 'A', '{}'::jsonb)");
    await db.query("INSERT INTO identities (id, organization_id, kind, name) VALUES ('idn_b', 'org_a', 'service', 'b'), ('idn_a', 'org_a', 'service', 'a')");
    // One row: it cannot hold a lock while waiting for another.
    await db.query("UPDATE identities SET name = 'a2' WHERE id = 'idn_a'");
    expect(takeLockViolations()).toEqual([]);
    // Two rows of people changed, neither prelocked: checked, and refused.
    await db.query("UPDATE identities SET name = name || '!' WHERE id IN ('idn_a', 'idn_b')");
    // (and, depending on the rows' physical order, taken out of id order)
    const lone = takeLockViolations();
    expect(lone).toHaveLength(1);
    expect(lone[0]!.problems.filter((p) => /^a person's row changed without an explicit FOR UPDATE prelock/.test(p))).toHaveLength(2);
    expect((await db.query("SELECT name FROM identities WHERE id = 'idn_b'")).rows).toEqual([{ name: "b!" }]);
    // References count: a lone insert referencing two parents, a lone update
    // changing a foreign key, each takes two row locks and is checked.
    await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_a', 'member')");
    expect(takeLockViolations().flatMap((v) => v.problems)).toEqual(expect.arrayContaining([expect.stringMatching(/^identity referenced without being locked at step 2 first: identities\[idn_a\]/)]));
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_b', 'b', 'B', '{}'::jsonb)");
    await db.query("UPDATE identities SET organization_id = 'org_b' WHERE id = 'idn_b'");
    expect(takeLockViolations().flatMap((v) => v.problems)).toEqual(expect.arrayContaining([expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock/)]));
  });

  it("serializes lone statements against each other and a transaction on the one PGlite connection", async () => {
    // Two lone writes and a transaction that fails, all at once: the failed
    // transaction's write is rolled back alone, and the lone writes stay.
    const results = await Promise.allSettled([
      db.query("UPDATE identities SET name = 'a3' WHERE id = 'idn_a'"),
      withTx(db, async (q) => {
        await q.query("UPDATE organizations SET name = 'A3' WHERE id = 'org_a'");
        throw new Error("refused");
      }),
      db.query("UPDATE identities SET name = 'b3' WHERE id = 'idn_b'"),
    ]);
    expect(results.map((r) => r.status)).toEqual(["fulfilled", "rejected", "fulfilled"]);
    takeLockViolations();
    expect((await db.query("SELECT id, name FROM identities ORDER BY id")).rows).toEqual([{ id: "idn_a", name: "a3" }, { id: "idn_b", name: "b3" }]);
    expect((await db.query("SELECT name FROM organizations WHERE id = 'org_a'")).rows).toEqual([{ name: "A" }]);
  });

  // Concurrent flows on the one connection can share a transaction: the
  // second flow's BEGIN only warns. The first COMMIT ends it for both.
  it("checks a transaction that concurrent flows share once, on its whole trace", async () => {
    // A traced database whose connection shows when a check clears the trace.
    const raw = await migratedTestDb({ lockOrder: "off" });
    await installLockTrace(raw);
    let onClear: (() => void) | undefined;
    const shared = lockTraced({
      ...raw,
      query: (text: string, params?: unknown[]) => {
        const res = raw.query(text, params);
        if (/^DELETE FROM varlatch_lock_trace\.trace WHERE txid/.test(text)) {
          const hook = onClear;
          onClear = undefined;
          hook?.();
        }
        return res;
      },
    }, "all", { checkTestStatements: true });
    try {
      await shared.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'a', 'A', '{}'::jsonb)");
      await shared.query("INSERT INTO identities (id, organization_id, kind, name) VALUES ('idn_b', 'org_a', 'service', 'b'), ('idn_a', 'org_a', 'service', 'a')");
      await shared.query("BEGIN");
      await shared.query("BEGIN");
      await lockPeople(shared, ["idn_a", "idn_b"]);
      // The second flow's insert and COMMIT arrive while the first COMMIT's
      // check is clearing the trace, before the first COMMIT runs.
      let late: Promise<unknown>[] = [];
      onClear = () => {
        late = [
          shared.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_a', 'member')"),
          shared.query("COMMIT"),
        ];
      };
      await shared.query("COMMIT");
      expect(late).toHaveLength(2);
      await Promise.all(late);
      // Checked once, with the step-2 locks: not the insert's references alone.
      expect(takeLockViolations()).toEqual([]);
      expect((await shared.query("SELECT identity_id FROM org_memberships")).rows).toEqual([{ identity_id: "idn_a" }]);
    } finally {
      await raw.close();
    }
  });

  it("leaves a flow's statements unchecked after another flow's COMMIT ended their shared transaction", async () => {
    const own = await migratedTestDb({ lockOrder: "all", checkTestStatements: true });
    await db.close();
    db = own;
    await db.query("INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'a', 'A', '{}'::jsonb)");
    await db.query("INSERT INTO identities (id, organization_id, kind, name) VALUES ('idn_b', 'org_a', 'service', 'b'), ('idn_a', 'org_a', 'service', 'a')");
    await db.query("BEGIN");
    await db.query("BEGIN");
    await lockPeople(db, ["idn_a", "idn_b"]);
    await db.query("COMMIT");
    // The second flow's insert, outside a transaction only because the first
    // flow's COMMIT ended the one they shared: not a lone statement.
    await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_a', 'member')");
    await db.query("COMMIT");
    expect(takeLockViolations()).toEqual([]);
    // Once both flows have ended, a lone insert referencing two rows is checked again.
    await db.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_b', 'member')");
    expect(takeLockViolations().flatMap((v) => v.problems))
      .toEqual(expect.arrayContaining([expect.stringMatching(/^identity referenced without being locked at step 2 first: identities\[idn_b\]/)]));
  });

  it("checks a transaction that ends in a rollback too, and skips an aborted one", async () => {
    // A refusal after the locks (a version conflict, an approval needed) rolls back.
    await expect(withTx(db, async (q) => {
      await lockPeople(q, ["idn_a"]);
      await q.query("UPDATE organizations SET name = 'A2' WHERE id = 'org_a'");
      throw new Error("refused");
    })).rejects.toThrow("refused");
    expect(takeLockViolations().map((v) => v.problems)).toEqual([[expect.stringMatching(/^step went back: organizations\[org_a\]/)]]);
    // An aborted transaction cannot be read: nothing is reported, nothing breaks.
    await expect(withTx(db, async (q) => {
      await lockPeople(q, ["idn_b"]);
      await q.query("SELECT 1/0");
    })).rejects.toThrow(/division by zero/);
    expect(takeLockViolations()).toEqual([]);
  });

  it("records explicit locks, writes and references, and fails the transaction that breaks the order", async () => {
    // Enforced at its COMMIT (lockOrder "all"); the trace is read before it.
    const rows = await withTx(db, async (q) => {
      await lockPeople(q, ["idn_b", { id: "idn_a", mode: "update" }]);
      await q.query("UPDATE identities SET name = 'b2' WHERE id = 'idn_b'");
      await q.query("INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_a', 'member')");
      return (await q.query("SELECT tbl, key, mode, kind FROM varlatch_lock_trace.trace WHERE txid = txid_current() ORDER BY seq")).rows;
    });
    expect(rows).toEqual([
      { tbl: "identities", key: "idn_a", mode: "update", kind: "explicit" },
      { tbl: "identities", key: "idn_b", mode: "key share", kind: "explicit" },
      { tbl: "identities", key: "idn_b", mode: "no key update", kind: "write" },
      { tbl: "org_memberships", key: "org_a|idn_a", mode: "insert", kind: "insert" },
      { tbl: "organizations", key: "org_a", mode: "key share", kind: "reference" },
      { tbl: "identities", key: "idn_a", mode: "key share", kind: "reference" },
    ]);
    // The transaction itself was enforced at its COMMIT, with the same verdict.
    const unnumbered = (problems: string[]) => problems.map((p) => p.replace(/#\d+/g, "#"));
    expect(takeLockViolations().map((v) => unnumbered(v.problems)))
      .toEqual([unnumbered(checkTrace(rows.map((r, i) => ({ ...(r as TraceRow), seq: i + 1 }))))]);
    expect(checkTrace(rows.map((r, i) => ({ ...(r as TraceRow), seq: i + 1 })))).toEqual([
      expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock at step 2: identities\[idn_b\]/),
      expect.stringMatching(/^upgrade: identities\[idn_b\] no key update/),
      expect.stringMatching(/^step went back: organizations\[org_a\]/),
    ]);
  });
});
