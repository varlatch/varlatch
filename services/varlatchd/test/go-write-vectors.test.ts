// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for the Go write path (ADR-0059 step 4.1a,
 * go/server/write/testdata/ts-vectors.json, read by vectors_test.go):
 *
 * - bodyHash: http/support.ts bodyHash, the digest an Idempotency-Key claim
 *   stores, for bodies of every JSON shape a route hands it (strings beyond
 *   ASCII, lone surrogates, numbers JSON.stringify rewrites, nested values,
 *   null and undefined), under a fixed key;
 * - replay: what withIdempotency answers on a replay. The response is
 *   stored as JSON.stringify({ status, payload }) in a jsonb column and
 *   read back through the pg driver, so a replay's body has jsonb's member
 *   order, not the first answer's. Each vector is a payload, its first
 *   answer and its replay, read back from a real database.
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-write-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { expect, it } from "vitest";
import { bodyHash } from "../src/http/support.js";
import { migratedTestDb } from "./helpers/pglite.js";

const OUT = new URL("../../../go/server/write/testdata/ts-vectors.json", import.meta.url);

const KEY = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");

/** Bodies as routes hand them to withIdempotency (zod's output). */
const BODIES: [string, unknown][] = [
  ["a value", { value: "postgres://app@db/app" }],
  ["a value with an expected version", { value: "x", expectedVersionId: "ver_abc" }],
  ["an empty value", { value: "" }],
  ["text beyond ASCII", { value: "héllo wörld ✓ 𝄞" }],
  ["a lone surrogate", { value: "a\ud800b" }],
  ["escapes", { value: "line\nbreak\t\"quoted\"\\\u0001\u007f " }],
  ["numbers", { a: 1, b: -0, c: 1e21, d: 0.1, e: 1.5e-7, f: 123456789012345680000 }],
  ["integer-like keys", { "10": "ten", "2": "two", b: "bee", a: "ay" }],
  ["a change set", { changes: [{ op: "set", item: "A", value: "1" }, { op: "delete", item: "B" }] }],
  ["nested", { a: { b: [1, { c: null }, true, false] } }],
  ["null", null],
  ["undefined", undefined],
  ["an empty object", {}],
];

/** Payloads as routes answer them, and their replays. */
const PAYLOADS: [string, number, unknown][] = [
  ["setValue's answer", 200, { versionId: "ver_1", itemName: "A", environmentId: "env_1", sensitive: true, previousVersionId: null, createdAt: "2026-01-01T00:00:00.000Z" }],
  ["integer-like and long keys", 201, { zeta: 1, "10": 2, a: [{ longer: 1, b: 2 }], "1": "x" }],
  ["a list", 200, { items: [{ id: "x", name: "y" }], nextCursor: null }],
];

it("go/server/write/testdata/ts-vectors.json is this server's answers", async () => {
  const bodyHashes = BODIES.map(([name, body]) => ({
    name,
    // The body as JSON text the Go side parses (null for undefined).
    body: JSON.stringify(body) ?? null,
    undefined: body === undefined,
    hash: bodyHash(body, KEY),
  }));
  const db = await migratedTestDb();
  try {
    await db.query("INSERT INTO identities (id, kind, name) VALUES ('idn_vectors', 'human', 'Vectors')");
    const replays = [];
    for (const [i, [name, status, payload]] of PAYLOADS.entries()) {
      const key = `k${i}`;
      await db.query(
        `INSERT INTO idempotency_keys (identity_id, endpoint, idempotency_key, body_hash, response) VALUES ('idn_vectors', 'vectors', $1, 'h', $2)`,
        [key, JSON.stringify({ status, payload })],
      );
      const row = (await db.query("SELECT response FROM idempotency_keys WHERE idempotency_key = $1", [key])).rows[0] as { response: unknown };
      const stored = (typeof row.response === "string" ? JSON.parse(row.response) : row.response) as { status: number; payload: unknown };
      replays.push({ name, status, first: JSON.stringify(payload), stored: JSON.stringify(stored), replay: JSON.stringify(stored.payload), replayStatus: stored.status });
    }
    const text = JSON.stringify({ comment: "Written by services/varlatchd/test/go-write-vectors.test.ts; never edit.", key: KEY.toString("hex"), bodyHashes, replays }, null, 2) + "\n";
    if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
      writeFileSync(OUT, text);
      return;
    }
    expect(readFileSync(OUT, "utf8") === text, "go/server/write/testdata/ts-vectors.json is stale: regenerate it (see the header of this file)").toBe(true);
  } finally {
    await db.close();
  }
});
