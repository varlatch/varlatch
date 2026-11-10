// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";

/**
 * Row locks on a person and their passkeys, taken in the lock order that
 * domain/approvals.ts writes down (steps 2 and 3): approvals, Security
 * Controls, passkey confirmation and passkey removal all use these.
 */

/** Step 2: the person's identities row. FOR UPDATE to serialize with their other approval and passkey work; FOR KEY SHARE to reference it. */
export async function lockPerson(db: Querier, identityId: string, mode: "update" | "key share"): Promise<void> {
  await db.query(`SELECT id FROM identities WHERE id = $1 ${mode === "update" ? "FOR UPDATE" : "FOR KEY SHARE"}`, [identityId]);
}

/** Step 2 for several people: in id order. */
export async function lockPeople(db: Querier, identityIds: readonly string[], mode: "update" | "key share"): Promise<void> {
  const ids = [...new Set(identityIds)].sort();
  if (ids.length === 0) return;
  await db.query(
    `SELECT id FROM identities WHERE id = ANY($1) ORDER BY id ${mode === "update" ? "FOR UPDATE" : "FOR KEY SHARE"}`,
    [ids],
  );
}

/**
 * Step 3: every passkey of the person, in id order, FOR UPDATE. Taken
 * before an assertion is verified (which advances the asserting passkey's
 * counter, and which passkey that is is only known then) and before a
 * confirmation writes provenance.
 */
export async function lockPersonPasskeys(db: Querier, identityId: string): Promise<void> {
  await db.query(
    `SELECT p.id FROM passkey p JOIN auth_user_links l ON l.better_auth_user_id = p."userId"
     WHERE l.identity_id = $1 ORDER BY p.id FOR UPDATE OF p`,
    [identityId],
  );
}
