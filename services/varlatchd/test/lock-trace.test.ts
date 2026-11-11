// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { lockedQuery } from "../src/db/locks.js";
import { withTx } from "../src/db/tx.js";
import { lockPeople } from "../src/domain/personlocks.js";
import { checkTrace, lockOrderMode, scanSql, statementsOf, takeLockViolations, type TraceRow } from "./helpers/lock-trace.js";
import { migratedTestDb } from "./helpers/pglite.js";

/** The lock-order check itself (ADR-0054 amendment E): the rules, then the trace it reads. */

const row = (seq: number, tbl: string, key: string, mode: string, kind: TraceRow["kind"] = "explicit"): TraceRow => ({ seq, tbl, key, mode, kind });

describe("checkTrace", () => {
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
    await expect(lockedQuery(db, { table: "organizations", mode: "update" }, `${join} FOR UPDATE`)).rejects.toThrow(/several relations \(identities, organizations\)/);
    await expect(lockedQuery(db, { table: "organizations", mode: "update" }, `${join} FOR UPDATE OF i`))
      .rejects.toThrow(/the tag names organizations, the statement locks identities/);
    await expect(lockedQuery(db, { table: "identities", mode: "update" }, `${join} FOR UPDATE OF x`)).rejects.toThrow(/OF x names no relation/);
    // Comma-separated FROM items lock every relation, as a join does.
    const commas = "SELECT i.id FROM identities i, organizations o WHERE o.id = i.organization_id";
    await expect(lockedQuery(db, { table: "identities", mode: "update" }, `${commas} FOR UPDATE`)).rejects.toThrow(/several relations \(identities, organizations\)/);
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
