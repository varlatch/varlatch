// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared vectors for go/server/environments (ADR-0059 step 4.1c,
 * testdata/pg-timestamps.json, read by environments_test.go): what
 * PostgreSQL stores for an environment's expiresAt, a string zod's
 * z.string().datetime() accepted, which the TypeScript server hands to
 * timestamptz as it is. Each vector is the string and either the
 * microseconds since the epoch PostgreSQL keeps (its fraction rounded to
 * microseconds) and the ISO form the API answers with: the column's text
 * as node-postgres (the server's driver) parses it with postgres-date into
 * a Date, then toISOString (milliseconds; years past 9999 as +YYYYYY). Or
 * that PostgreSQL refuses it (the insert fails: 500). PGlite's own parser
 * is not used: it reads years below 100 as 19xx or 20xx, which the server
 * never does. The parity fixture masks new times, so these pin the
 * rounding.
 *
 * The file is checked here: it must equal what this code produces now.
 * After a change, regenerate it and commit the result:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/varlatchd exec vitest run test/go-timestamp-vectors.test.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, it } from "vitest";
import { migratedTestDb } from "./helpers/pglite.js";

const require = createRequire(import.meta.url);
/** node-postgres's timestamptz parser, as the server's driver loads it. */
const parseDate = require(require.resolve("postgres-date", { paths: [require.resolve("pg")] })) as (text: string) => Date;

const OUT = new URL("../../../go/server/environments/testdata/pg-timestamps.json", import.meta.url);

const INPUTS = [
  "2099-01-01T00:00:00Z",
  "2099-01-01T00:00:00.000Z",
  "2099-06-30T12:34:56.1234567Z",
  "2099-06-30T12:34:56.9999996Z",
  "2099-06-30T12:34:56.9999995Z",
  "2099-06-30T12:34:56.0000005Z",
  "2099-06-30T12:34:56.0000015Z",
  "2099-06-30T12:34:56.0000025Z",
  "2099-06-30T12:34:56.00000049999Z",
  "2099-06-30T12:34:56.000000500000000001Z",
  "2099-06-30T12:34:56.123456789012345678901234567890Z",
  "2099-06-30T12:34:56.1Z",
  "2099-06-30T12:34:56.0009Z",
  "2096-02-29T23:59:59.9999999Z",
  "2000-02-29T00:00:00Z",
  "1970-01-01T00:00:00Z",
  "1969-12-31T23:59:59.9999995Z",
  "1969-12-31T23:59:59.9994Z",
  "1900-01-01T00:00:00.5Z",
  "0001-01-01T00:00:00Z",
  "0000-01-01T00:00:00Z",
  "9999-12-31T23:59:59.999999Z",
  "9999-12-31T23:59:59.9999995Z",
  "0099-06-01T00:00:00Z",
];

it("go/server/environments/testdata/pg-timestamps.json is PostgreSQL's answers", async () => {
  const db = await migratedTestDb();
  try {
    const vectors = [];
    for (const input of INPUTS) {
      try {
        await db.query("SET TimeZone = 'UTC'");
        const res = await db.query("SELECT (extract(epoch FROM $1::timestamptz) * 1000000)::numeric(30,0)::text AS micros, $1::timestamptz::text AS t", [input]);
        const row = res.rows[0] as { micros: string; t: string };
        vectors.push({ input, micros: row.micros, iso: parseDate(row.t).toISOString() });
      } catch {
        vectors.push({ input, refused: true });
      }
    }
    const out = JSON.stringify({ comment: "Written by services/varlatchd/test/go-timestamp-vectors.test.ts from PostgreSQL (PGlite); never edit.", vectors }, null, 2) + "\n";
    if (process.env.VARLATCH_WRITE_GO_VECTORS === "1") {
      writeFileSync(OUT, out);
      return;
    }
    expect(readFileSync(OUT, "utf8") === out, "go/server/environments/testdata/pg-timestamps.json is stale: regenerate it (see the header of this file)").toBe(true);
  } finally {
    await db.close();
  }
});
