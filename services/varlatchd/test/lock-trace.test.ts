// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { lockedQuery } from "../src/db/locks.js";
import { withTx } from "../src/db/tx.js";
import { lockPeople } from "../src/domain/personlocks.js";
import { checkTrace, lockOrderMode, takeLockViolations, type TraceRow } from "./helpers/lock-trace.js";
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
      expect.stringMatching(/^upgrade: identities\[idn_a\]/),
      expect.stringMatching(/^a person's row changed without an explicit FOR UPDATE prelock/),
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

describe.skipIf(lockOrderMode() === "off")("the trace on the test database", () => {
  let db: Awaited<ReturnType<typeof migratedTestDb>>;
  beforeEach(async () => {
    db = await migratedTestDb();
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

  it("records explicit locks, writes and references, and fails the transaction that breaks the order", async () => {
    // Labelled from this test, so enforced under "all" only: read the trace directly.
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
    expect(checkTrace(rows.map((r, i) => ({ ...(r as TraceRow), seq: i + 1 })))).toEqual([
      expect.stringMatching(/^upgrade: identities\[idn_b\] no key update/),
      expect.stringMatching(/^step went back: organizations\[org_a\]/),
    ]);
  });
});
