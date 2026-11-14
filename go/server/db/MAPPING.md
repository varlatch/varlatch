# From PostgreSQL to SQLite

How the TypeScript server's PostgreSQL schema at v0.22.0 maps to
`schema.sql` (ADR-0059 Decision 2). The migration manifest of Decision 9
(step 7) is built from this mapping.

- `testdata/pg-v0.22.0.json` is the PostgreSQL side: every table, column
  (type, nullability, default), constraint (with its definition), index
  (with its predicate), trigger and trigger function the 52 migrations of
  v0.22.0 leave, and the rows they insert themselves. It is generated, never
  edited (see "Regenerating the dump").
- `mapping.json` maps every one of them to its SQLite form, or gives the
  reason it was dropped. Names map to themselves unless the entry says
  otherwise.
- `mapping_test.go` checks the mapping against both sides. It opens a new
  database through `lib/storage`, runs `Init`, and reads the result
  (`sqlite_schema`, `pragma_table_xinfo`, `pragma_index_list`,
  `pragma_index_xinfo`, `pragma_foreign_key_list`). For every item in the
  dump it requires an entry, and for every entry an item in the dump. For
  every mapped item it requires the SQLite counterpart:
  - a column of the type its type rule gives, with the same nullability and
    the same default, after the default rules below;
  - a primary key or unique index over the mapped columns;
  - a foreign key with the same columns, referenced table and columns, and
    `ON DELETE` and `ON UPDATE` actions;
  - a `CHECK` of the same name with PostgreSQL's expression, unless the
    entry marks it rewritten and says why. Both sides are parsed into an
    expression tree (`expr_test.go`) and compared by structure: grouping,
    string literals and the kind of every leaf count exactly (an
    identifier, a number and a string stay distinct, so `"64"` is not
    `64`); only dialect spellings are made equal (casts such as `::text`,
    `= ANY (ARRAY[...])` as `IN` and `<> ALL (ARRAY[...])` as `NOT IN`,
    other quantified comparisons kept as they are,
    `char_length` as `length`, `IS DISTINCT FROM` as `IS NOT`, `BETWEEN` as
    `>=` and `<=`, the case of keywords and identifiers, redundant
    parentheses, the grouping of a chain of `AND`s or `OR`s);
  - an index with the same uniqueness, keys, key order (`DESC`) and
    predicate.

  The other way round, every SQLite table, column, index, foreign key,
  named `CHECK` and trigger must be the image of something in PostgreSQL,
  follow from a type rule (`int4_<column>`), or be listed under `added`.
  Every `integer` column is checked against its range (below), and every
  `text[]` column for its element triggers. `TestSQLCBooleanOverrides` checks that sqlc maps
  exactly the boolean columns to Go's `bool`.

## Type rules

| PostgreSQL | SQLite | Rule |
| --- | --- | --- |
| `text` | `TEXT` | Unchanged. |
| `timestamp with time zone` | `INTEGER` | Microseconds since the Unix epoch, UTC. PostgreSQL stores microseconds, so no value changes. |
| `integer` | `INTEGER` | Kept to PostgreSQL's range, -2147483648 to 2147483647, by `CHECK int4_<column>` (below). |
| `bigint` | `INTEGER` | Unchanged. |
| `boolean` | `INTEGER` | 0 or 1, with `CHECK (c IN (0, 1))`; sqlc maps it to `bool` or `sql.NullBool`. |
| `jsonb` | `TEXT` | JSON text, with `CHECK (json_valid(c))`. SQLite compares it as text, PostgreSQL by value. |
| `text[]` | `TEXT` | A JSON array whose elements are strings or null, with `CHECK (json_valid(c) AND json_type(c) = 'array')` and element triggers (below). A query's `= ANY ($1)` becomes `json_each(?)` or `IN`. |
| `bytea` | `BLOB` | The same bytes. |

Every table is `STRICT`, so a value of the wrong type is refused rather than
converted. Foreign keys are enforced on every connection (`lib/storage`).
There is no `smallint` at v0.22.0; one would be kept to -32768 to 32767 by
`CHECK int2_<column>` in the same way.

### Integer ranges

SQLite's `INTEGER` is 64-bit, PostgreSQL's `integer` 32-bit. So that every
value varlatchd stores can go back to PostgreSQL (the reverse migration,
Decision 9), each of the 30 `integer` columns keeps PostgreSQL's range, and
`bigint` stays 64-bit:

- where PostgreSQL has no bound of its own, `CHECK int4_<column>` holds
  the whole range (18 columns);
- where PostgreSQL bounds one side (`version > 0`, `failures >= 0`), the
  check adds only the other, `<= 2147483647` (10 columns);
- where PostgreSQL bounds both (`requested_ttl` 60 to 86400,
  `retention_days` 1 to 3650), there is none.

`mapping_test.go` holds every `integer` column to that: one past either end
is refused, the range check accepts both ends, bounds no side PostgreSQL
already bounds, and does not exist where PostgreSQL bounds both.

WebAuthn signature counters (`passkeys.counter`,
`passkey_quarantine.counter`) are unsigned 32-bit numbers, and the
authenticator may send one above 2147483647. They keep PostgreSQL's signed
range for now: such a counter is refused, never reinterpreted as a negative
number. Widening them to the unsigned range needs an agreed change on the
PostgreSQL side as well (a `bigint` column there), or the reverse migration
could not write them back; that is a later decision.

### Array elements

PostgreSQL's `text[]` holds strings and NULL elements. SQLite's column holds
the JSON array; a `CHECK` keeps it an array, but cannot look inside it (no
subqueries in a `CHECK`). So each table with `text[]` columns has two
triggers, `<table>_text_arrays_insert` and `<table>_text_arrays_update`
(`BEFORE UPDATE OF` the array columns), which refuse an element that is not
a string or null (`json_each`). Text that is not a JSON array is left to the
`CHECK`. Nested arrays are refused: varlatchd never wrote a
multidimensional array, and the migration refuses one. Any other array type
would follow the same policy, with elements of its element type. The
columns: `roles.actions`, `grants.actions`, `capabilities.items`,
`capabilities.destinations`, `member_integrations.changes`,
`webhooks.event_types`.

### REPLACE

SQLite carries out `INSERT OR REPLACE` (and `UPDATE OR REPLACE`) by
deleting the row it conflicts with, and fires no delete trigger for that
deletion while `recursive_triggers` is off, as it is in `lib/storage`. Every
guarantee below that rests on a trigger could be bypassed that way: a
replaced audit event disappears past `audit_events_no_delete` and leaves a
gap; a replaced session ends without revoking its browser credentials; a
replaced passkey starts again at any counter; a replaced GitHub App
registration loses its pending conversion.

So `audit_events`, `auth_sessions`, `passkeys` and
`github_app_registrations` have `<table>_no_replace_insert` (and, except
`audit_events`, whose updates are refused anyway, `_no_replace_update`):
`BEFORE` triggers that refuse a row colliding with an existing row's unique
key (its primary key or a `UNIQUE` column) before SQLite resolves the
conflict. These tables take no `REPLACE`, no upsert and no `INSERT OR
IGNORE`: an insert that collides is refused, and a change is an `UPDATE`.
A collision is reported by the guard rather than by SQLite's unique check.

The guards compare the table's keys, so no key may be hidden from them. A
rowid table has one, reachable as `rowid`, `oid` and `_rowid_`:
`UPDATE OR REPLACE auth_sessions SET rowid = 1 WHERE id = 's2'` would delete
the session in rowid 1 without its trigger. So the guarded tables whose
primary key is text, `auth_sessions`, `passkeys` and
`github_app_registrations`, are `WITHOUT ROWID`: there is no hidden key to
collide on, and naming one is an error. `audit_events` keeps its rowid,
because the rowid is `event_order`: its guards see it under every alias
(an insert naming a taken position is refused by
`audit_events_no_replace_insert`, any other but the next by
`audit_events_position`), and every update is refused by
`audit_events_no_update`. `mapping_test.go` requires every table with a
`_no_replace` guard to be `WITHOUT ROWID` or keyed by its rowid;
`TestGuardedTablesHaveNoHiddenRowid` and
`TestAuditPositionUnderEveryRowidAlias` try every alias, on insert and on
update. sqlc and the mapping test read `WITHOUT ROWID` tables like the
others.

A `REPLACE` of a parent row needs no guard: the foreign key cascade from
it does fire the children's delete triggers. Replacing a user ends its
sessions through `session_end_revokes_browser_credentials`
(`TestReplacingAUserStillEndsItsSessions` holds SQLite to that).

Defaults:

| PostgreSQL | SQLite |
| --- | --- |
| `now()` | `CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000`: the database clock in microseconds, at millisecond resolution. varlatchd passes its own times; the default covers inserts that leave a time out. |
| `true`, `false` | `1`, `0` |
| `'x'::text` | `'x'` |
| `github_app_registrations.id`: `'ghr_' \|\| substr(md5(random() \|\| clock_timestamp()), 1, 26)` | `'ghr_' \|\| lower(hex(randomblob(13)))`: the same shape, 26 hex digits. |

## Tables

59 tables in SQLite: 58 of PostgreSQL's 62, and `schema_version`. Identifiers
in rows are kept as they are: they are part of every envelope's associated
data, and a passkey's user id is its WebAuthn user handle.

By domain, as `schema.sql` orders them:

- **Installation and keys:** `installation`, `signing_keys`.
- **Identities, credentials and setup grants:** `identities`, `credentials`,
  `setup_grants`, `idempotency_keys`.
- **People, browser sessions and passkeys:** `auth_users` (PostgreSQL
  `"user"`), `auth_sessions` (`"session"`), `auth_user_links`,
  `auth_session_evidence`, `passkeys` (`"passkey"`), `passkey_provenance`,
  `passkey_quarantine`, `passkey_confirmation_challenges`, `device_sign_ins`,
  `device_sign_in_challenges`, `device_code_attempt_windows`.
- **Organizations, membership and removal:** `organizations`,
  `org_memberships`, `membership_removals`, `removal_authority`,
  `removal_requirements`, `removal_conditions`, `member_integrations`,
  `member_exposure`, `exposure_backfill`, `exposure_confirmations`,
  `organization_deletions`, `organization_freezes`, `audit_tombstone_readers`.
- **Projects, environments, values and Contracts:** `projects`,
  `environments`, `env_values`, `value_versions`, `contract_revisions`.
- **Access:** `roles`, `groups`, `group_members`, `team_projects`, `grants`,
  `requirements`, `oidc_bindings`, `capabilities`.
- **Security Controls and approvals:** `security_controls`,
  `security_control_counters`, `approval_intents`,
  `approval_intent_challenges`.
- **Audit:** `audit_events`, `webhooks`, `audit_exports`,
  `audit_export_plans`.
- **Integrations:** `platform_connections`, `github_apps`,
  `github_app_registrations`, `sync_targets`, `sync_ledger`, `sync_runs`,
  `sync_cursor`.

### Renamed

Better Auth's tables were in its adapter's shape (quoted, camelCase).
varlatchd owns them now, so they and their columns take snake_case names:

| PostgreSQL | SQLite |
| --- | --- |
| `"user"` (`"emailVerified"`, `"createdAt"`, `"updatedAt"`) | `auth_users` (`email_verified`, `created_at`, `updated_at`) |
| `"session"` (`"expiresAt"`, `token`, `"createdAt"`, `"updatedAt"`, `"ipAddress"`, `"userAgent"`, `"userId"`) | `auth_sessions` (`expires_at`, `token_hash`, `created_at`, `updated_at`, `ip_address`, `user_agent`, `user_id`) |
| `"passkey"` (`"publicKey"`, `"userId"`, `"credentialID"`, `"deviceType"`, `"backedUp"`, `"createdAt"`) | `passkeys` (`public_key`, `user_id`, `credential_id`, `device_type`, `backed_up`, `created_at`) |
| `passkey_quarantine`'s copies of those columns | the same snake_case names |
| indexes `"session_userId_idx"`, `"passkey_userId_idx"`, `passkey_credential_id_unique` | `auth_sessions_user_id_idx`, `passkeys_user_id_idx`, `passkeys_credential_id_unique` |

`session.token` becomes `auth_sessions.token_hash`: Better Auth stored the
session token itself, varlatchd stores its hash (step 3.4). No session row
is copied by the migration: every browser session ends there (Decision 9).

### Dropped

| PostgreSQL | Reason |
| --- | --- |
| table `account` | Better Auth's provider accounts (passwords, OAuth tokens). Varlatch signs people in with passkeys only and creates their users itself, so no row is ever written. The migration checks that the table is empty. |
| table `verification` | Better Auth's ceremony challenges, minutes long. varlatchd keeps its own ceremony challenges (step 3.4); none needs to survive a migration that ends every browser session. |
| table `varlatch_migrations` | The migration runner's bookkeeping. The SQLite schema is created whole and records its version in `schema_version`. |
| table `audit_position` | The commit-order counter (see "Audit positions"). The highest position is `max(event_order)`, `query.LastAuditPosition`. |
| index `"passkey_credentialID_idx"` | Redundant: the unique index on the same column (migration 0039) serves every lookup. |
| function `new_audit_event_id` | Inlined in the session trigger. |
| function `assign_audit_position` | Replaced by the rowid and the trigger `audit_events_position`. |

The other three trigger functions became the bodies or `WHEN` clauses of
their triggers.

### Kept without a Go reader

`signing_keys` holds the JWT signer's keys, whose only user is Convex. The
Go server has no Convex (Decision 4), so nothing in Go reads the table yet.
It is kept because its envelope class (`jwt-signing-key`) is part of the key
hierarchy the migration checks, and a reverse migration must give the
TypeScript server its keys back. Whether it goes is step 7's decision.

### Added

| SQLite | Why |
| --- | --- |
| table `schema_version` | The schema's version (`db.go`). |
| triggers `audit_events_no_update`, `audit_events_no_delete` | Audit events are append-only. PostgreSQL withheld `UPDATE` and `DELETE` on `audit_events` from the runtime role (migration 0003); SQLite has no roles. |
| triggers `*_no_replace_insert`, `*_no_replace_update` | REPLACE guards (above). |
| triggers `*_text_arrays_insert`, `*_text_arrays_update` | Array elements (above). |
| checks `int4_<column>` | Integer ranges (above): a type rule, not a PostgreSQL constraint. |

### Privileges

Migrations 0003, 0004, 0017 and 0020 grant and revoke privileges for the
deployment's runtime role, only when that role exists (so PGlite, which has
none, leaves no trace of them in the dump). SQLite has no roles: varlatchd
is the only process that opens the file. What the grants protected is kept
where the database can keep it: audit events stay append-only (the two
triggers above). The counter row whose privileges 0017 and 0020 adjusted no
longer exists.

### Rows a new database starts with

PostgreSQL's migrations insert two rows. `exposure_backfill` gets its one
row in `schema.sql` as well: cursor 0, until position 0, finished at once,
since a new database has no audit history to backfill (migration 0036).
`audit_position`'s row went with its table.

## CHECK constraints rewritten

Every `CHECK` keeps its PostgreSQL name, including the generated ones
(`approval_intents_check1`), so an error names the same constraint on both
servers. These are spelled differently, because SQLite lacks what they used:

| Constraint | PostgreSQL | SQLite |
| --- | --- | --- |
| `device_sign_ins_user_code_check` | `~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'` | `length = 8 AND NOT GLOB '*[^BCDFGHJKLMNPQRSTVWXZ]*'` |
| `github_app_registrations_account_login_check` | `~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'` | length 1 to 39, `GLOB '[A-Za-z0-9]*'`, `NOT GLOB '*[^A-Za-z0-9-]*'` |
| `audit_export_plans_sha256_check`, `_md5_check` | `~ '^[0-9a-f]{64}$'`, `{32}` | length 64 or 32, `NOT GLOB '*[^0-9a-f]*'` |
| `security_control_counters_operation_check` | `~ '^[a-z][a-z_-]*(\.[a-z][a-z_-]*)+$'` | `GLOB '[a-z]*.[a-z]*'`, only `[a-z_.-]`, every `.` followed by `[a-z]`, no final `.` |
| `installation_singleton` | `id LIKE 'inst_%'` (`_` is any one character) | `id GLOB 'inst?*'` |
| `security_control_counters_bucket_hour_check` | `bucket_hour = date_trunc('hour', bucket_hour, 'UTC')` | `bucket_hour % 3600000000 = 0` |
| `security_controls_config_check` | `jsonb_typeof(...) = 'number'`, `(config ->> k)::numeric` | `json_type(...) IN ('integer', 'real')`, `json_extract(config, '$.k')`, behind `json_valid` |
| `approval_intents_target_check` | `jsonb_typeof(target) = 'object'` | `json_valid(target) AND json_type(target) = 'object'` |
| `exposure_backfill_singleton_check`, `sync_cursor_singleton_check` | `CHECK (singleton)` | `CHECK (singleton = 1)` |

`TestRewrittenPatternChecks` evaluates each pattern rewrite, as `schema.sql`
spells it, on about 8,000 generated strings and requires the same verdict as
PostgreSQL's pattern. `TestCredentialLifetimeConfigCheck` holds the config
check to verdicts taken from PostgreSQL. Both accept a config missing either
key, as PostgreSQL did: the expression is then NULL, which a `CHECK` lets
through.

## The four trigger guarantees

### Audit positions in commit order (migration 0017)

PostgreSQL gave each event the next value of a counter row, which the
inserting transaction held locked until it committed, so no visible higher
position could overtake an uncommitted lower one.

In SQLite, `event_order` is the `INTEGER PRIMARY KEY` of `audit_events`, its
rowid: an insert gets `max(event_order) + 1`. Every write runs on
`lib/storage`'s single writer, one job at a time inside one `BEGIN
IMMEDIATE` transaction per batch, and a batch commits as a whole. So:

- jobs run one after another, so each takes its positions after the
  previous job's;
- a reader (WAL snapshot) sees a batch's events all at once or not at all,
  so it never sees a position whose predecessors are not visible;
- a job rolled back to its savepoint gives its positions back before the
  next job runs, so positions have no gaps.

What the database can enforce, it does: the trigger `audit_events_position`
refuses an insert that is not the new highest position right after its
predecessor (an insert naming its own `event_order`), and
`audit_events_no_update`, `audit_events_no_delete` and
`audit_events_no_replace_insert` keep the table append-only, so the
invariant cannot be broken afterwards, by `REPLACE` either.

Tests: `TestAuditPositionsFollowInsertOrder`,
`TestAuditPositionsAreAssignedByTheDatabase`, `TestAuditEventsAreAppendOnly`,
`TestAuditPositionNeverOvertakesAnUncommittedOne` (from
`postgres-concurrency.test.ts`), and
`TestAuditPositionsHaveNoGapsUnderConcurrentWrites` (concurrent writers with
failing jobs, while readers check they only ever see positions 1 to n), and
`TestAuditEventsCannotBeReplaced`.

### Passkey counters only move forward (migration 0040)

The trigger `passkey_counter_forward` (`BEFORE UPDATE OF counter ON
passkeys`) refuses a new counter that is not greater than the stored one,
when either is above zero; 0 over 0 is allowed. It is the PostgreSQL
function's condition as a `WHEN` clause. Its refusal is
`SQLITE_CONSTRAINT_TRIGGER`, which `lib/storage` counts as the job's own
error: only that job fails. On the single writer the read, verification and
write of one sign-in happen in one job, so two sign-ins cannot both verify
against the same stored counter; the trigger still applies whoever writes.

Tests: `TestPasskeyCounterOnlyMovesForward`, `TestPasskeyCounterRaces`,
`TestPasskeyRenameIsNotACounterWrite` (from `passkey-evidence-postgres.test.ts`),
`TestPasskeysCannotBeReplaced`.

### A session's end revokes its browser credentials (migration 0043)

The trigger `session_end_revokes_browser_credentials` (`AFTER DELETE ON
auth_sessions`) revokes, in the deleting statement, every live `browser`
credential that carries the session's id, and writes one `credential.revoked`
audit event for each (no actor, no Organization, resource `{"identityId":
...}`, metadata `{"kind": "browser", "reason": "session-ended"}`). CLI
credentials from the browser hand-off carry the session id too and are left
alone. It fires for every delete: an explicit one, a bulk one, and the
cascade from a deleted user.

Differences from PostgreSQL:

- SQLite has row triggers only. One statement deleting several sessions
  writes their events session by session, each session's in credential id
  order; PostgreSQL's statement trigger wrote all of them in credential id
  order. The set of events is the same.
- No locks: the single writer holds the only write transaction, so the lock
  order PostgreSQL needed (session, credential, audit) has nothing to
  order.
- Event ids are `evt_` and 26 lowercase base32 characters from SQLite's
  `random()`, the last one carrying 3 bits: the TypeScript server's shape
  (128 bits). PostgreSQL hashed two random UUIDs.
- The JSON is SQLite's `json_object` text (`{"identityId":"..."}`), not
  PostgreSQL's jsonb spelling.
- A `REPLACE` that would remove a session row is refused by
  `auth_sessions_no_replace_*` (see "REPLACE").

Tests (from `session-end-revocation.test.ts`):
`TestSessionEndRevokesItsBrowserCredentials`,
`TestSessionEndLeavesEndedCredentialsAlone`,
`TestSessionWithoutCredentialsEndsWithoutAuditLine`,
`TestSessionEndCoversBulkDeletesAndTheUserCascade`,
`TestSessionEndAfterAnotherRevocationRecordsOnce`, and
`TestSessionEndIsInTheDeletingTransaction` (a job that deletes a session and
then fails leaves the session, its credentials and the audit log as they
were); `TestSessionsCannotBeReplaced` and
`TestReplacingAUserStillEndsItsSessions`.

### Pending GitHub App conversions are written once (migration 0050)

The trigger `github_app_registrations_pending_once` (`BEFORE UPDATE`) is the
PostgreSQL function's condition as a `WHEN` clause, with `IS DISTINCT FROM`
as `IS NOT`: once `converted_at` is set, nothing of the registration changes
but the deletion of the key when it ends, and an ended registration's end
never changes. The columns PostgreSQL left unguarded (`account_login`,
`account_type`, `created_at`, `expires_at`) stay unguarded. The pending key
is compared as text, so writing the same key in another spelling is refused
as well; PostgreSQL compared jsonb by value.

Test (from `migrate.test.ts`):
`TestGitHubAppRegistrationPendingMaterialIsWrittenOnce`, every guarded
column changed to another value and to NULL;
`TestGitHubAppRegistrationsCannotBeReplaced`.

## For the migration manifest (step 7)

What a copy from PostgreSQL has to do, beyond copying names that are the
same:

- times: `timestamptz` to microseconds since the epoch (exact);
- `jsonb`: PostgreSQL's text output, or a canonical JSON spelling the
  manifest fixes; equality checks must parse both sides, since SQLite
  compares text;
- `boolean` to 0 or 1, `text[]` to a JSON array (a multidimensional array
  is refused), `bytea` to the same bytes;
- the renamed tables and columns above; `session` rows are not copied,
  their browser credentials are revoked with audit events instead (Decision
  9); `account` must be empty; `verification` is not copied;
- `audit_events` in `event_order` order, with their positions: PostgreSQL's
  are 1 to n without gaps, which `audit_events_position` requires;
- `exposure_backfill`: the source's row replaces the new database's.

## Regenerating the dump

```sh
pnpm install --frozen-lockfile      # at the repository root, for PGlite
node go/server/db/testdata/pgschema.mjs go/server/db/testdata/pg-v0.22.0.json
```

The script reads the migrations of the tag v0.22.0 with `git show` (`--ref`
picks another), runs them with the server's own runner on PGlite, and reads
the catalog. The same ref gives the same file. The TypeScript server is
frozen at v0.22.0, so the file only changes if the script does.
