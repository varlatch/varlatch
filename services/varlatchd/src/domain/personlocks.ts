// SPDX-License-Identifier: AGPL-3.0-or-later
import { lockClause, lockedQuery } from "../db/locks.js";
import type { Querier } from "../db/migrate.js";

/**
 * Row locks on people and their passkeys: steps 2 and 3 of the one lock
 * order (top of domain/liveness.ts). Every writer takes its people here, at
 * step 2, before any Project, environment or domain row (lockLiveScope
 * calls lockPeople); approvals, Security Controls, passkey confirmation and
 * passkey removal too.
 */

/**
 * FOR UPDATE: the person whose approval is consumed, or whose row the
 * transaction changes, in any column (an explicit prelock: the implicit
 * FOR NO KEY UPDATE of an update that changes no key column does not
 * replace it). FOR SHARE: a person whose row must not change until the
 * transaction ends (an issuance that checks the identity is enabled, so a
 * disable in flight waits). FOR KEY SHARE: a person only referenced (a
 * foreign key, an index row).
 */
export type PersonLockMode = "key share" | "share" | "update";

/** A person to lock: an id alone is taken in the default mode (FOR KEY SHARE); null and undefined are skipped. */
export type PersonRef = string | { id: string; mode: PersonLockMode } | null | undefined;

const STRENGTH: Record<PersonLockMode, number> = { "key share": 1, share: 2, update: 3 };

/**
 * Step 2: all of the transaction's people, in id order, in one step, each
 * in the strongest mode asked for it. Consecutive people in one mode share
 * a statement.
 */
export async function lockPeople(db: Querier, people: readonly PersonRef[], mode: PersonLockMode = "key share"): Promise<void> {
  const modes = new Map<string, PersonLockMode>();
  for (const ref of people) {
    if (ref === null || ref === undefined) continue;
    const { id, mode: m } = typeof ref === "string" ? { id: ref, mode } : ref;
    const before = modes.get(id);
    if (!before || STRENGTH[m] > STRENGTH[before]) modes.set(id, m);
  }
  const ids = [...modes.keys()].sort();
  for (let i = 0; i < ids.length; ) {
    const m = modes.get(ids[i]!)!;
    let j = i + 1;
    while (j < ids.length && modes.get(ids[j]!) === m) j++;
    await lockedQuery(
      db,
      { table: "identities", mode: m },
      `SELECT id FROM identities WHERE id = ANY($1) ORDER BY id ${lockClause(m)}`,
      [ids.slice(i, j)],
    );
    i = j;
  }
}

/** Step 2 for one person. */
export async function lockPerson(db: Querier, identityId: string, mode: PersonLockMode): Promise<void> {
  await lockPeople(db, [{ id: identityId, mode }]);
}

/**
 * Steps 2 and 3 for every person who has a Better Auth account (the
 * public-URL change, which ends everyone's passkeys, sessions and browser
 * credentials): the people in id order, FOR KEY SHARE, then all their
 * passkeys in id order, FOR UPDATE.
 *
 * KEY SHARE on the people is enough to wait for every approval, confirmation
 * and consumption in flight (they hold their person FOR UPDATE), and it is
 * compatible with the KEY SHARE that any write referencing people through a
 * foreign key takes. Re-enrollment's NO KEY UPDATE is compatible with it too.
 */
export async function lockAllPeopleAndPasskeys(db: Querier): Promise<void> {
  await lockedQuery(
    db,
    { table: "identities", mode: "key share" },
    `SELECT i.id FROM identities i JOIN auth_user_links l ON l.identity_id = i.id ORDER BY i.id FOR KEY SHARE OF i`,
  );
  await lockedQuery(
    db,
    { table: "passkey", mode: "update" },
    `SELECT p.id FROM passkey p, auth_user_links l WHERE l.better_auth_user_id = p."userId" ORDER BY p.id FOR UPDATE OF p`,
  );
}

/**
 * Step 3: every passkey of the person, in id order, FOR UPDATE. Taken
 * before an assertion is verified (which advances the asserting passkey's
 * counter, and which passkey that is is only known then) and before a
 * confirmation writes provenance.
 */
export async function lockPersonPasskeys(db: Querier, identityId: string): Promise<void> {
  await lockedQuery(
    db,
    { table: "passkey", mode: "update" },
    `SELECT p.id FROM passkey p, auth_user_links l
     WHERE l.better_auth_user_id = p."userId" AND l.identity_id = $1 ORDER BY p.id FOR UPDATE OF p`,
    [identityId],
  );
}
