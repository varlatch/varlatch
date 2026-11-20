// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import { CanonicalError, encodeValue, type Value } from "./canonical.js";
import { bundleTables, refusalKind, type Manifest } from "./bundle.js";
import { pgRowSource } from "./source.js";

/**
 * The export's preflight (ADR-0059 step 7, go-step7 slice 7.2b): what
 * refuses a migration, each failure named, and what it lists for the
 * operator. It reads inside the export's own snapshot and writes nothing.
 * No value is ever reported: a row that cannot be encoded is named by its
 * table, its id and its column, with the kind of failure.
 *
 * The rows check is the manifest's rule from this side: a value
 * canonical-v1 refuses (a jsonb number a double does not hold exactly, for
 * one) fails its row, never changes, so the preflight reports such rows
 * before any bundle is written. (The TypeScript note varlatchd's v1.json
 * does not carry: manifest-v1.json is its copy, byte for byte.)
 */

export interface PreflightFailure {
  check: "exposure-backfill" | "key-rotation" | "account" | "row";
  message: string;
  /** For check "row": where, never the value. */
  table?: string;
  id?: string | null;
  column?: string;
  reason?: "integer-out-of-range" | "jsonb-number-not-exact" | "not-encodable";
}

export interface CrossOrganizationGrant {
  grantId: string;
  organizationId: string;
  /** The group or role it names, and that one's Organization. */
  names: "group" | "role";
  namedId: string;
  namedOrganizationId: string;
}

export interface Preflight {
  ok: boolean;
  failures: PreflightFailure[];
  /** Listed, not refused. */
  verificationRows: number;
  crossOrganizationGrants: CrossOrganizationGrant[];
}

export async function preflight(client: Querier, manifest: Manifest): Promise<Preflight> {
  const failures: PreflightFailure[] = [];
  const one = async <T>(sql: string) => (await client.query(sql)).rows[0] as T | undefined;

  const backfill = await one<{ finished: boolean }>("SELECT finished_at IS NOT NULL AS finished FROM exposure_backfill");
  if (!backfill?.finished) {
    failures.push({ check: "exposure-backfill", message: "the exposure backfill has not finished: let varlatchd run until it has (it runs in the background), then export again" });
  }
  const rotation = await one<{ state: string }>("SELECT key_rotation_state AS state FROM installation");
  if (rotation && rotation.state !== "idle") {
    failures.push({ check: "key-rotation", message: `a Root KEK rotation is in progress (${rotation.state}): finish it, then export again` });
  }
  const accounts = Number((await one<{ n: string }>(`SELECT count(*)::text AS n FROM "account"`))?.n ?? "0");
  if (accounts > 0) {
    failures.push({ check: "account", message: `the account table holds ${accounts} row(s); this installation never writes one, so the migration refuses to drop them` });
  }

  // Every row the bundle carries, through the bundle's own encoder, value
  // by value, so a failure names its column.
  const rows = pgRowSource(client);
  for (const table of bundleTables(manifest)) {
    const idColumn = table.columns.findIndex((c) => c.source === "id");
    const { rows: values } = await rows(table);
    for await (const row of values) {
      for (let i = 0; i < table.columns.length; i++) {
        const column = table.columns[i]!;
        if (column.leftOut !== undefined) continue;
        try {
          encodeValue(column.type, row[i] as Value);
        } catch (err) {
          if (!(err instanceof CanonicalError)) throw err;
          const id = idColumn >= 0 && typeof row[idColumn] === "string" ? (row[idColumn] as string) : null;
          const reason = refusalKind(err);
          failures.push({
            check: "row", table: table.source, id, column: column.source, reason,
            message: `${table.source}${id ? ` ${id}` : ""}: ${column.source} cannot be carried (${reason})`,
          });
        }
      }
    }
  }

  const verificationRows = Number((await one<{ n: string }>(`SELECT count(*)::text AS n FROM "verification"`))?.n ?? "0");
  const crossOrganizationGrants = (
    await client.query(
      `SELECT * FROM (
         SELECT g.id AS "grantId", g.organization_id AS "organizationId", 'group' AS names, gr.id AS "namedId", gr.organization_id AS "namedOrganizationId"
           FROM grants g JOIN groups gr ON gr.id = g.subject_group_id WHERE gr.organization_id <> g.organization_id
         UNION ALL
         SELECT g.id, g.organization_id, 'role', r.id, r.organization_id
           FROM grants g JOIN roles r ON r.id = g.role_id WHERE r.organization_id <> g.organization_id
       ) cross_organization ORDER BY "grantId" COLLATE "C", names COLLATE "C"`,
    )
  ).rows as CrossOrganizationGrant[];
  return { ok: failures.length === 0, failures, verificationRows, crossOrganizationGrants };
}
