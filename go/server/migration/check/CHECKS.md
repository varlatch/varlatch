# The migration's checks

ADR-0059 Decision 9 phase 4; internal docs/design/go-step7.md slice 7.3b,
decisions 7 and 8. After an import, `varlatchd admin migrate check --in
<bundle>` holds the target database against the forward bundle it was
imported from (`../bundle/BUNDLE.md`). Every check runs, whatever another
found, so each fault shows at its own check; the command exits 1 when
one fails.

The read side is its own: the checks query SQLite directly, every table
and column name taken from the manifest (`../manifest/v1.json`), and never
import `server/migration/migrate` (`TestTheChecksDoNotImportTheImport`
walks the import graph). A fault of the import cannot hide behind the
code that made it.

## rows

Every table the bundle carries, row by row:

- each target row is written as a canonical-v1 row (the manifest's
  column types, a left-out column as `null`) and compared, byte for
  byte, with the source's;
- rows are matched by the manifest's `orderBy` key, in SQLite's order, so
  a missing row and an extra row are each named as such; `requirements`,
  which the manifest keeps in the source's physical order, is compared
  position by position in rowid order, and rows that are all there but out
  of that order are named so;
- `audit_events` is compared up to the frozen point (the audit check reads
  what follows it);
- a credential the migration revoked (the audit check names it) is
  expected with its `revoked_at` at its revocation event's moment,
  exactly: the trigger writes both in the one DELETE statement, and
  SQLite reads the time once per statement, so they are the same instant;
- the `session` table leaves no row in `auth_sessions`;
- the target holds no table the manifest does not account for; of its
  target-only tables, `schema_version` holds its one row and any other
  none.

A fault names the table, the row's position in the source's order and the
differing columns, never a value.

## encryption-classes

Every encrypted item of the target is opened with the Root KEK (and the
keys under it), digested as the bundle's digests are (HMAC-SHA256 under
the run key over `canonical.DigestInput(class, ids, plaintext)`), and
held against the bundle's digest of the same item. The plaintext is
cleared once digested.

| Class | Read from | Key | ids |
|---|---|---|---|
| `kek-canary` | `installation.kek_canary` | Root KEK | `installationId` |
| `org-kek` | `organizations.wrapped_org_kek` | Root KEK | `organizationId` |
| `dek` | `value_versions.wrapped_dek` | org KEK | `organizationId`, `secretId` (the env value's id), `versionId` |
| `value` | `value_versions.payload` | the version's DEK | as `dek` |
| `webhook-secret` | `webhooks.secret_envelope` | org KEK | `organizationId`, `webhookId` |
| `platform-credential` | `platform_connections.credential_envelope` | org KEK | `organizationId`, `connectionId` |
| `github-app-key` | `github_apps.key_envelope` (`gha_` ids) and `github_app_registrations.pending_key_envelope` (`ghr_` ids) | org KEK | `organizationId`, `githubAppId` |
| `audit-export-credential` | `audit_exports.credential_envelope`, state not `draining` (an export that ended, `removed`, `completed` or `abandoned`, holds none) | org KEK | `organizationId`, `exportId` |
| `audit-export-drain` | `audit_exports.credential_envelope`, state `draining` | Root KEK | `organizationId`, `exportId` |
| `jwt-signing-key` | `signing_keys.private_key_wrapped` | Root KEK | `keyId` |

One class is varlatchd's own (schema version 8), so no bundle has its
digests: each item is opened and held against the plaintext its row keeps
beside it, which the rows check holds against the bundle. An import writes
none (varlatchd seals them from `url` when it starts), so they are met in
the reverse checks, whose target is Go's copy.

| Class | Read from | Key | ids | Held against |
|---|---|---|---|---|
| `webhook-url` | `webhooks.url_envelope` | org KEK | `organizationId`, `webhookId` | the row's `url` |

The ids are the item's envelope context without its `purpose`. A null
envelope column is no item; an erased value version is none. An item
under an Organization KEK that was destroyed (`org_kek_destroyed_at`) is
opened on neither side: no key opens it, and its bytes are the rows
check's. A fault names the class and the item's ids: an item missing or
not opening, one the source does not have, or one whose plaintext is not
the source's.

Not in 7.3b: decision 7's recomputation of a sample of the Root
KEK-keyed HMACs and sync fingerprints from their inputs. Their bytes are
copied and compared by the rows check.

## audit

- The bundle's last audit position is its header's frozen point.
- The target's events up to the frozen point are the source's, by id at
  each position.
- After it come only `credential.revoked` events for the reason
  `session-ended`, each for a distinct credential the migration ends (a
  browser credential minted from a source session, live in the source and
  unexpired at the event's moment), then one `installation.migrated`, the
  last event, whose metadata is the bundle's direction, release, manifest
  version and frozen point, and the counts of the sessions ended and the
  credentials revoked.
- Every audit cursor is where the source left it, read on its own by its
  row's key: `webhooks` (`cursor_order`, `cursor_occurred_at`,
  `cursor_event_id`), `audit_exports` (`cursor_order`), `sync_cursor`
  (`cursor_order`, `occurred_at`, `event_id`) and `exposure_backfill`
  (`cursor`, `until_order`).

## authorization

The differential of decision 8: each decision of the bundle's table is
evaluated again on the target and the answers compared, streamed. A
decision names a credential, the credential state it assumes, the
resource, the action and a Tailnet Context or none:

- a credential that is not `active` (`expired`, `revoked`) is refused
  before authorization: `UNAUTHENTICATED`;
- an active one is its identity (a machine identity with its
  Organization), deciding with `authz.Decide` on the Organization, the
  Project and the environment named (its root and tier read from the
  target), with the Tailnet Context named, existence not hidden; a denial
  is its error code.

A bundle with no decision table fails the check when the target has a
live credential. A fault names the decision's position, credential,
state, action and resource, and both answers.

## authentication

Each source row of the tables that decide who can sign in, with what and
until when is looked up in the target by its key, on its own, and these
columns compared:

| Table | Columns |
|---|---|
| `identities` | `kind`, `disabled`, `organization_id`, `installation_admin`, `suspended_by_deletion` |
| `user` | `email`, `emailVerified` |
| `auth_user_links` | `identity_id` |
| `passkey` | `userId`, `credentialID`, `publicKey`, `counter`, `deviceType`, `backedUp`, `transports` |
| `passkey_provenance` | `trust`, `trusted_via`, `trusted_at`, `setup_grant_kind`, `confirmed_by_passkey_id` |
| `credentials` | `identity_id`, `kind`, `token_hash`, `expires_at`, `revoked_at` (as the rows check expects it), `max_uses`, `auth_session_id` |
| `oidc_bindings` | `identity_id`, `organization_id`, `issuer`, `audience`, `subject`, `claims`, `revoked_at` |
| `setup_grants` | `kind`, `subject_identity_id`, `token_hash`, `expires_at`, `consumed_at`, `revoked_at` |
| `device_sign_ins` | `device_code_hash`, `status`, `expires_at`, `approved_by_identity_id`, `issued_credential_id` |

Then: none of these tables holds a row the source does not have, no
browser session is kept, and every live browser credential of a source
session, unexpired at `installation.migrated`'s moment, is revoked. A
fault names the table, the row by its id (or its key's columns where the
key is a hash) and the changed columns.

## The reverse checks

A reverse migration (internal docs/design/go-step7.md decision 16, slice
7.6a) runs the same five checks the other way round, with `--reverse`:

```
varlatchd admin migrate export --reverse --out <reverse bundle> --keep <dir>
  (the TypeScript release imports the reverse bundle onto a fresh database,
   then exports that database: admin migration export --dry-run --digests)
varlatchd admin migrate check --reverse --in <its export> --scratch <dir>
```

- The **target** is the transformed copy the reverse export kept (`--keep`):
  the Go installation at the barrier's frozen point with the reverse's two
  transformations applied, its browser sessions ended and
  `installation.migrated` appended. It is the state the reverse bundle
  carries.
- The **bundle** is the TypeScript release's export of the database it
  rebuilt from the reverse bundle: its rows as that database holds them,
  its digests (its own decryption of every item, under the run key) and its
  evaluator's decision table. It is a forward bundle, by its header.
- The rebuilt database holds the copy's state exactly, so nothing comes
  between the two: the rows are compared byte for byte, as above; no event
  follows the frozen point (the bundle's last position is the copy's
  last); the bundle holds no browser session; every cursor is where the
  copy left it; every item's plaintext is the same on both sides; every
  decision of the TypeScript evaluator's table is varlatchd's on the copy;
  the authentication state is the same row for row.
- A check of a scratch directory runs beside a running varlatchd: it reads
  that directory only, so the Go installation keeps running behind its
  barrier while the reverse is checked.

The reverse bundle's own digest and decision sections stay empty
(`../bundle/BUNDLE.md`): the TypeScript side's digests and decisions arrive
with its export, and varlatchd computes its own from the copy.

## The report

`--json` prints one object: `passed`, `reverse` for the reverse checks, the bundle's counts and, per check,
`passed`, how many items it `checked`, its `failures` (each with its
`table` or `class` and `what`; at most 50, `more` counting the rest).
Without it, one line per check and its faults. Both name checks, tables,
classes, row positions, columns, ids and counts; neither holds any other
value of a row, a plaintext, a digest, the Root KEK or the run key: the tests scan
every report for each seeded plaintext, key and digest, as bytes, hex and
base64.
