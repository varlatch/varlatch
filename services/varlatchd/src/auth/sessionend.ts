// SPDX-License-Identifier: AGPL-3.0-or-later
import { lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";

/**
 * Whose browser sessions a bulk sign-out ends: a person's (every Better
 * Auth user linked to the identity), or one Better Auth user's.
 */
export type SessionOwner = { identityId: string } | { betterAuthUserId: string };

/**
 * Ends browser sessions of one owner in the one lock order every bulk
 * sign-out takes (domain/liveness.ts), so that two of them, or one and
 * Better Auth's own bulk revocation (humanauth.ts), never wait on each
 * other in a cycle:
 *
 *   1. every session of the owner, the one that stays included, in id
 *      order (step 6);
 *   2. the credentials named in `credentials` (the presenting bearer) and
 *      the live browser credentials of the sessions it ends, which the
 *      session-end trigger (migration 43) revokes, in id order, in its
 *      mode (step 7);
 *   3. `check`, once everything is held: a reason found there to refuse
 *      (a session or bearer no longer live) is thrown, and nothing is
 *      deleted;
 *   4. the sessions but `keep` deleted, the trigger revoking their browser
 *      bearers, one credential.revoked each.
 *
 * Runs in the caller's transaction. Returns the ids of the sessions it
 * ended.
 */
export async function endSessionsInOrder(
  db: Querier,
  owner: SessionOwner,
  opts: { keep?: string | null; credentials?: readonly string[]; check?: (db: Querier) => Promise<void> } = {},
): Promise<string[]> {
  // No expression of the session is read here: PostgreSQL evaluates the
  // target list below the row locks, before any wait for them, so what
  // must hold once the locks are held is read by `check` afterwards.
  const sessions = (
    "identityId" in owner
      ? await lockedQuery(
          db,
          { table: "session", mode: "update" },
          `SELECT s.id FROM session s, auth_user_links l
           WHERE l.better_auth_user_id = s."userId" AND l.identity_id = $1
           ORDER BY s.id FOR UPDATE OF s`,
          [owner.identityId],
        )
      : await lockedQuery(
          db,
          { table: "session", mode: "update" },
          `SELECT id FROM session WHERE "userId" = $1 ORDER BY id FOR UPDATE`,
          [owner.betterAuthUserId],
        )
  ).rows as { id: string }[];
  const keep = opts.keep ?? null;
  const ended = sessions.map((s) => s.id).filter((id) => id !== keep);
  const credentials = [...(opts.credentials ?? [])];
  if (ended.length > 0 || credentials.length > 0) {
    await lockedQuery(
      db,
      { table: "credentials", mode: "update" },
      `SELECT id FROM credentials
       WHERE id = ANY($1::text[])
          OR (auth_session_id = ANY($2::text[]) AND kind = 'browser' AND revoked_at IS NULL)
       ORDER BY id FOR UPDATE`,
      [credentials, ended],
    );
  }
  await opts.check?.(db);
  if (ended.length > 0) await db.query(`DELETE FROM "session" WHERE id = ANY($1::text[])`, [ended]);
  return ended;
}
