// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Timestamp input vectors for the Go server (ADR-0059 step 4.3c,
 * feature-parity decision 3). The audit log's cursor carries a time this
 * server hands to PostgreSQL as $3::timestamptz (app.ts, GET
 * …/audit-events), so whatever text PostgreSQL's timestamptz input reads
 * is a valid cursor time, and what it refuses fails the request with
 * INTERNAL. go/server/pgtime ports that input; its test replays
 * go/server/pgtime/testdata/timestamptz-vectors.json, PostgreSQL 17.6's
 * answers (postgres:17.6, a UTC session) to a corpus of date-only, ISO,
 * special, abbreviated, zone-named, POSIX-zoned, textual, Julian,
 * run-together and malformed inputs.
 *
 * This test checks the same file against the PGlite these tests run the
 * server on: every answer that does not depend on the clock (now, today,
 * tomorrow, yesterday) or on which tz database the server has is the
 * same. Zone names are read from the server's tz database, so this
 * server's answer for them depends on its host: PGlite's database has
 * names the postgres:17.6 image's (Debian trixie, tzdata 2025b, without
 * the legacy links) has not (US/Eastern, Japan, Asia/Calcutta), lacks
 * files it has (localtime, posixrules), and holds EST5EDT and CST6CDT as
 * zone files where it reads them as POSIX zone strings. Those inputs are
 * left out here; every other zone name in the corpus gives the same.
 *
 * The corpus and its answers are written by
 * go/server/pgtime/testdata/gen-vectors.py and probe.sql (see there).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { testDb } from "./helpers/pglite.js";

const FILE = new URL("../../../go/server/pgtime/testdata/timestamptz-vectors.json", import.meta.url);
const RELATIVE = /now|today|tomorrow|yesterday/i;
const DATABASE_DEPENDENT = /US\/Eastern|Japan|Asia\/Calcutta|localtime|posixrules|EST5EDT|CST6CDT/i;

describe("timestamptz input vectors", () => {
  it("PGlite reads every clock-free input as PostgreSQL 17.6 did", async () => {
    const { vectors } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: [string, string][] };
    const db = await testDb();
    try {
      const differ: string[] = [];
      let compared = 0;
      for (const [input, want] of vectors) {
        if (RELATIVE.test(input) || DATABASE_DEPENDENT.test(input)) continue;
        compared++;
        let got: string;
        try {
          const { rows } = await db.query<{ r: string }>(
            `SELECT CASE WHEN t = 'infinity' THEN 'infinity' WHEN t = '-infinity' THEN '-infinity'
               ELSE (extract(epoch from (t - '2000-01-01 00:00:00+00'::timestamptz)) * 1000000)::numeric(40,0)::text END AS r
             FROM (SELECT $1::timestamptz AS t) s`,
            [input],
          );
          got = rows[0]!.r;
        } catch (err) {
          got = `ERROR ${(err as { code?: string }).code}`;
        }
        if (got !== want) differ.push(`${JSON.stringify(input)}: ${got}, PostgreSQL ${want}`);
      }
      expect(compared).toBeGreaterThan(4000);
      expect(differ).toEqual([]);
    } finally {
      await db.close();
    }
  }, 120_000);
});
