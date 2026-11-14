// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A v0.22.0 database's people, passkeys and credentials, for the Go
 * server's passkey tests (ADR-0059 step 3.4, gate G4: trusted, unconfirmed
 * and quarantined passkeys keep their status). The rows are made the way
 * this server makes them, then exported as PostgreSQL holds them:
 *
 * - before migration 39, as Better Auth stored them, two passkeys sharing a
 *   credential id (Alice's first, then Bob's): migration 39 quarantines
 *   Bob's and makes every remaining passkey trusted (existing-at-upgrade);
 * - after it, as this server records them (domain/passkeys.ts): a passkey a
 *   re-enrollment link enrolled (trusted, setup-grant), one a signed-in
 *   session added (unconfirmed), one then confirmed by a trusted one (the
 *   statement confirmPasskey runs), and one with no provenance row (counts
 *   as unconfirmed);
 * - sign-in evidence and credentials: a browser hand-off CLI credential
 *   whose session's evidence is user-verified with a trusted passkey, a
 *   device sign-in credential without user verification, one whose
 *   session signed in with an unconfirmed passkey, and one with none.
 *
 * Alice's and Bob's keys are fixed test keys (their PKCS #8 is in the
 * file), so the Go test signs assertions with them: Alice's passkey signs
 * in to Go; Bob's quarantined one does not.
 *
 * go/server/auth/fixture_test.go loads the rows through the schema mapping
 * (go/server/db/mapping.json) and checks each status. The file is checked
 * here, the times now() and clock_timestamp() write left out: it must
 * equal what this code produces. After a change, regenerate it and commit
 * the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-passkey-fixture.test.ts
 */
import { createPrivateKey, type JsonWebKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { expect, it } from "vitest";
import { MIGRATIONS } from "../src/db/migrations/index.js";
import { runMigrations } from "../src/db/migrate.js";
import { credentialEvidence, listOwnPasskeys, recordPasskeyProvenance, recordSessionEvidence } from "../src/domain/passkeys.js";
import { verificationGap } from "../src/domain/passkeyverification.js";
import { testDb } from "./helpers/pglite.js";

const OUT = new URL("../../../go/server/auth/testdata/passkeys-v0.22.0.json", import.meta.url);

const KEYS = {
  alice: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguvT9AHcdT8qZ5g2P4ZbAAoY5CuSjhKfzaYgPUfd3ceahRANCAATL0zTtatWm1Oy979IClZitMxIDP+52CzIDihCSsuIuUoe27qfQlA0b0Gz38ZiPK5/2ATzE/FMMNeNvuvo3WVUw",
  bob: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBE6XbNePsW1TGy+tmRVJbLda6k2xUFBl22Bst0nLDm+hRANCAARowP92CY00Px8tBHHyxwnV5TZ4DZWhn+TpPJ/pmQap7eFls0ysm7gKHMtGd8wFSNq3SAY9Pq5Zeqy5fpGhpx/a",
} as const;

/** A P-256 key's public half as Better Auth stores it: the COSE_Key in standard base64. */
function cosePublicKey(pkcs8: string): string {
  const jwk = createPrivateKey({ key: Buffer.from(pkcs8, "base64"), format: "der", type: "pkcs8" }).export({ format: "jwk" }) as JsonWebKey;
  const cose = new Map<number, number | Uint8Array>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x!, "base64url"))],
    [-3, new Uint8Array(Buffer.from(jwk.y!, "base64url"))],
  ]);
  return Buffer.from(isoCBOR.encode(cose)).toString("base64");
}

/** Columns written by now() or clock_timestamp(): exported, but not compared. */
const CLOCK = new Set(["trusted_at", "quarantined_at", "recorded_at", "applied_at"]);

const TABLES: Record<string, string> = {
  identities: "SELECT * FROM identities ORDER BY id",
  user: `SELECT * FROM "user" ORDER BY id`,
  auth_user_links: "SELECT * FROM auth_user_links ORDER BY better_auth_user_id",
  passkey: "SELECT * FROM passkey ORDER BY id",
  passkey_provenance: "SELECT * FROM passkey_provenance ORDER BY passkey_id",
  passkey_quarantine: "SELECT * FROM passkey_quarantine ORDER BY id",
  auth_session_evidence: "SELECT * FROM auth_session_evidence ORDER BY session_id",
  credentials: "SELECT * FROM credentials ORDER BY id",
};

const json = (v: unknown): unknown => (v instanceof Date ? v.toISOString() : v);

async function build() {
  const db = await testDb();
  try {
    // v0.21.0's schema, up to the migration before 39.
    await db.exec!(`CREATE TABLE IF NOT EXISTS varlatch_migrations (id integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    for (const m of MIGRATIONS.filter((m) => m.id < 39)) {
      await db.exec!(m.sql);
      await db.query("INSERT INTO varlatch_migrations (id, name) VALUES ($1, $2)", [m.id, m.name]);
    }
    const t = (s: string) => `2026-0${s}`;
    for (const [id, name, admin] of [["idn_alice", "Alice", true], ["idn_bob", "Bob", false], ["idn_carol", "Carol", false]] as const) {
      await db.query("INSERT INTO identities (id, kind, name, installation_admin, created_at) VALUES ($1, 'human', $2, $3, $4)", [id, name, admin, t("1-01T00:00:00.000Z")]);
      await db.query(`INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt") VALUES ($1, $2, $3, false, $4, $4)`,
        [`bau_${id}`, name, `${id}@varlatch.placeholder.invalid`, t("1-01T00:00:00.000Z")]);
      await db.query("INSERT INTO auth_user_links (better_auth_user_id, identity_id, created_at) VALUES ($1, $2, $3)", [`bau_${id}`, id, t("1-01T00:00:00.000Z")]);
    }
    const passkey = (id: string, user: string, credentialId: string, key: string, createdAt: string, counter = 0) =>
      db.query(
        `INSERT INTO passkey (id, name, "publicKey", "userId", "credentialID", counter, "deviceType", "backedUp", transports, "createdAt", aaguid)
         VALUES ($1, $2, $3, $4, $5, $6, 'singleDevice', false, 'internal', $7, '00000000-0000-0000-0000-000000000000')`,
        [id, `${id} key`, key, user, credentialId, counter, createdAt],
      );
    // Better Auth before migration 39 refused no duplicate credential id.
    await passkey("pk_alice_shared", "bau_idn_alice", "Y3JlZC1zaGFyZWQ", cosePublicKey(KEYS.alice), t("1-02T00:00:00.000Z"), 7);
    await passkey("pk_bob_shared", "bau_idn_bob", "Y3JlZC1zaGFyZWQ", cosePublicKey(KEYS.bob), t("1-03T00:00:00.000Z"), 3);
    await passkey("pk_alice_laptop", "bau_idn_alice", "Y3JlZC1hbGljZS1sYXB0b3A", cosePublicKey(KEYS.alice), t("1-04T00:00:00.000Z"), 41);
    // v0.22.0: migration 39 and every later one.
    await runMigrations(db);
    // After the upgrade, as this server records new passkeys.
    await passkey("pk_bob_reenrolled", "bau_idn_bob", "Y3JlZC1ib2ItcmVlbnJvbGxlZA", cosePublicKey(KEYS.bob), t("2-01T00:00:00.000Z"));
    await recordPasskeyProvenance(db, "pk_bob_reenrolled", { setupGrantKind: "reenroll" });
    await passkey("pk_bob_added", "bau_idn_bob", "Y3JlZC1ib2ItYWRkZWQ", cosePublicKey(KEYS.bob), t("2-02T00:00:00.000Z"));
    await recordPasskeyProvenance(db, "pk_bob_added", { addedBySession: true });
    await passkey("pk_alice_phone", "bau_idn_alice", "Y3JlZC1hbGljZS1waG9uZQ", cosePublicKey(KEYS.alice), t("2-03T00:00:00.000Z"));
    await recordPasskeyProvenance(db, "pk_alice_phone", { addedBySession: true });
    // confirmPasskey's statement, confirmed by Alice's laptop key.
    await db.query(
      `INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at, confirmed_by_passkey_id)
       VALUES ($1, 'trusted', 'confirmed', clock_timestamp(), $2)
       ON CONFLICT (passkey_id) DO UPDATE SET trust = 'trusted', trusted_via = 'confirmed',
         trusted_at = clock_timestamp(), confirmed_by_passkey_id = $2, setup_grant_kind = NULL
       WHERE passkey_provenance.trust = 'unconfirmed'`,
      ["pk_alice_phone", "pk_alice_laptop"],
    );
    await passkey("pk_carol_unrecorded", "bau_idn_carol", "Y3JlZC1jYXJvbA", cosePublicKey(KEYS.bob), t("2-04T00:00:00.000Z"));
    // Sign-in evidence of two sessions (ended: no "session" row), and the
    // credentials that carry evidence.
    const credential = (id: string, identity: string, sessionId: string | null, evidence: [boolean, string] | null) =>
      db.query(
        `INSERT INTO credentials (id, identity_id, kind, name, token_hash, auth_session_id, evidence_user_verified, evidence_passkey_id, created_at, expires_at)
         VALUES ($1, $2, 'cli', $1, $3, $4, $5, $6, '2026-02-10T00:00:00.000Z', '2099-01-01T00:00:00.000Z')`,
        [id, identity, `hash-of-${id}`, sessionId, evidence?.[0] ?? null, evidence?.[1] ?? null],
      );
    await credential("crd_alice_handoff", "idn_alice", "ses_alice", null);
    await credential("crd_alice_device", "idn_alice", null, [false, "pk_alice_laptop"]);
    await credential("crd_bob_handoff", "idn_bob", "ses_bob", null);
    await credential("crd_carol_cli", "idn_carol", null, null);
    // recordSessionEvidence sweeps evidence no live credential links; the
    // credentials above link both sessions.
    await recordSessionEvidence(db, { sessionId: "ses_alice", betterAuthUserId: "bau_idn_alice", credentialId: "Y3JlZC1hbGljZS1sYXB0b3A", userVerified: true, ceremony: "sign-in" });
    await recordSessionEvidence(db, { sessionId: "ses_bob", betterAuthUserId: "bau_idn_bob", credentialId: "Y3JlZC1ib2ItYWRkZWQ", userVerified: true, ceremony: "sign-in" });

    const rows: Record<string, Record<string, unknown>[]> = {};
    for (const [table, sql] of Object.entries(TABLES)) {
      rows[table] = (await db.query(sql)).rows.map((r) =>
        Object.fromEntries(Object.entries(r as Record<string, unknown>).map(([k, v]) => [k, json(v)])),
      );
    }
    // What this server says of them, which Go must say too.
    const expected = {
      passkeys: Object.fromEntries(
        await Promise.all(["idn_alice", "idn_bob", "idn_carol"].map(async (id) => [id, await listOwnPasskeys(db, id)] as const)),
      ),
      gaps: Object.fromEntries(
        await Promise.all(["crd_alice_handoff", "crd_alice_device", "crd_bob_handoff", "crd_carol_cli"].map(async (id) => [id, await verificationGap(db, id, "cli")] as const)),
      ),
      evidence: Object.fromEntries(
        await Promise.all(["crd_alice_handoff", "crd_alice_device", "crd_bob_handoff", "crd_carol_cli"].map(async (id) => [id, await credentialEvidence(db, id)] as const)),
      ),
    };
    return { keys: KEYS, rows, expected };
  } finally {
    await db.close();
  }
}

/** The fixture without the times the clock wrote. */
function comparable(fixture: unknown): unknown {
  return JSON.parse(JSON.stringify(fixture), (k, v) => (CLOCK.has(k) || k === "trustedAt" ? undefined : v));
}

it("go/server/auth/testdata/passkeys-v0.22.0.json is what this server's code makes", async () => {
  const fixture = await build();
  // The status each kind of passkey keeps.
  const bob = (fixture.expected.passkeys.idn_bob as { id: string; trust: string }[]).map((p) => `${p.id}:${p.trust}`);
  expect(bob).toEqual(["pk_bob_reenrolled:trusted", "pk_bob_added:unconfirmed"]);
  expect(fixture.rows.passkey_quarantine.map((r) => r.id)).toEqual(["pk_bob_shared"]);
  if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
    writeFileSync(OUT, `${JSON.stringify(fixture, null, 2)}\n`);
    return;
  }
  expect(comparable(JSON.parse(readFileSync(OUT, "utf8")))).toEqual(comparable(fixture));
});
