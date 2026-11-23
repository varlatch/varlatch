-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- varlatchd's SQLite schema (ADR-0059 Decision 2): a fresh schema for the
-- tables the TypeScript server's 52 PostgreSQL migrations leave at v0.22.0,
-- not a replay of them. MAPPING.md and mapping.json record, for every
-- PostgreSQL table, column, constraint, index and trigger, its form here or
-- why it was dropped; mapping_test.go checks both against a dump of v0.22.0
-- (testdata/pg-v0.22.0.json) and against this file.
--
-- Conventions (each is a type rule in MAPPING.md):
--   * Every table is STRICT; foreign keys are enforced (lib/storage turns
--     them on for every connection).
--   * Identifiers are kept exactly: they are part of every envelope's
--     associated data.
--   * Times (timestamptz) are INTEGER microseconds since the Unix epoch, UTC.
--     A default of now() is NOW below, the database clock at millisecond
--     resolution; varlatchd passes its own times.
--   * jsonb is TEXT holding JSON (json_valid), text[] is TEXT holding a JSON
--     array of strings or nulls (a CHECK for the array, triggers for its
--     elements), boolean is INTEGER 0 or 1, bytea is BLOB, bigint is
--     INTEGER.
--   * integer is INTEGER kept to PostgreSQL's 32-bit range by a CHECK named
--     int4_<column>, so every value can go back to PostgreSQL (the reverse
--     migration, Decision 9). Where PostgreSQL already bounds a side, the
--     check adds only the other; where it bounds both, there is none.
--   * REPLACE: SQLite carries out INSERT OR REPLACE (and UPDATE OR REPLACE)
--     by deleting the conflicting row without firing delete triggers
--     (recursive_triggers is off in lib/storage). Every table whose
--     guarantee rests on a trigger refuses a write that collides with an
--     existing row's unique key before any replacement can happen (the
--     *_no_replace triggers). Those tables take no REPLACE, no upsert and
--     no INSERT OR IGNORE: an insert that collides is refused, and a change
--     is an UPDATE. A REPLACE of a parent row needs no guard: the foreign
--     key cascade from it does fire the children's delete triggers
--     (auth_users into auth_sessions, tested).
--   * Hidden rowids: a guarded table whose primary key is not an integer
--     is WITHOUT ROWID (auth_sessions, passkeys, github_app_registrations),
--     so no write can collide on a rowid, oid or _rowid_ the guards do not
--     see. audit_events keeps its rowid: it is event_order, which its
--     guards check under every alias, and no update of it is allowed.
--   * CHECK constraints keep their PostgreSQL names. Regular expressions
--     (~) become GLOB patterns with length checks, since SQLite has no
--     regular expressions; mapping_test.go compares them on generated input.
--
-- NOW is (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000).
--
-- This file is executed once, by Init, in one write job, on an empty
-- database. It holds no PRAGMA: the storage engine sets them.

-- ---------------------------------------------------------------------------
-- The schema's own version (Init, db.go)
-- ---------------------------------------------------------------------------

-- One row. version is the schema this file describes (SchemaVersion in
-- db.go). compatible_from is the oldest schema version whose varlatchd may
-- still open the database: a rollback-safe release (ADR-0059 Decision 8)
-- leaves it at the previous version, any other release raises it to its own.
CREATE TABLE schema_version (
  singleton INTEGER NOT NULL PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
  version INTEGER NOT NULL CHECK (version > 0),
  compatible_from INTEGER NOT NULL CHECK (compatible_from > 0 AND compatible_from <= version),
  created_at INTEGER NOT NULL,
  created_by_release TEXT NOT NULL CHECK (length(created_by_release) BETWEEN 1 AND 64),
  updated_at INTEGER NOT NULL,
  updated_by_release TEXT NOT NULL CHECK (length(updated_by_release) BETWEEN 1 AND 64)
) STRICT;

-- ---------------------------------------------------------------------------
-- Installation and keys
-- ---------------------------------------------------------------------------

CREATE TABLE installation (
  -- PostgreSQL's LIKE 'inst_%' reads _ as any one character.
  id TEXT NOT NULL PRIMARY KEY CONSTRAINT installation_singleton CHECK (id GLOB 'inst?*'),
  kek_canary TEXT NOT NULL CHECK (json_valid(kek_canary)),
  bootstrapped_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  root_kek_version INTEGER NOT NULL DEFAULT 1 CONSTRAINT installation_root_kek_version_check CHECK (root_kek_version > 0) CONSTRAINT int4_root_kek_version CHECK (root_kek_version <= 2147483647),
  key_rotation_state TEXT NOT NULL DEFAULT 'idle'
    CONSTRAINT installation_key_rotation_state_check CHECK (key_rotation_state IN ('idle', 'rewrapping', 'verifying')),
  public_url TEXT
) STRICT;

-- The JWT signer's keys (ADR-0007), wrapped under the Root KEK. Kept with
-- their envelope class (lib/envelope's jwt-signing-key purpose); see
-- MAPPING.md, "Kept without a Go reader".
CREATE TABLE signing_keys (
  id TEXT NOT NULL PRIMARY KEY,
  algorithm TEXT NOT NULL CONSTRAINT signing_keys_algorithm_check CHECK (algorithm = 'ES256'),
  public_jwk TEXT NOT NULL CHECK (json_valid(public_jwk)),
  private_key_wrapped TEXT NOT NULL CHECK (json_valid(private_key_wrapped)),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  retired_at INTEGER
) STRICT;

-- ---------------------------------------------------------------------------
-- Identities, credentials and setup grants
-- ---------------------------------------------------------------------------

CREATE TABLE identities (
  id TEXT NOT NULL PRIMARY KEY,
  kind TEXT NOT NULL
    CONSTRAINT identities_kind_check CHECK (kind IN ('human', 'service', 'workload', 'ci', 'broker', 'agent')),
  name TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  installation_admin INTEGER NOT NULL DEFAULT 0 CHECK (installation_admin IN (0, 1)),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  organization_id TEXT REFERENCES organizations (id),
  last_seen_at INTEGER,
  suspended_by_deletion TEXT REFERENCES organization_deletions (id),
  CONSTRAINT identity_org_scope CHECK (
    (kind = 'human' AND organization_id IS NULL)
    OR (kind <> 'human' AND organization_id IS NOT NULL))
) STRICT;
CREATE INDEX identities_org_idx ON identities (organization_id);

CREATE TABLE credentials (
  id TEXT NOT NULL PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL
    CONSTRAINT credentials_kind_check CHECK (kind IN ('service', 'cli', 'browser', 'agent-run', 'oidc')),
  name TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  expires_at INTEGER,
  revoked_at INTEGER,
  max_uses INTEGER CONSTRAINT credentials_max_uses_check CHECK (max_uses > 0) CONSTRAINT int4_max_uses CHECK (max_uses <= 2147483647),
  use_count INTEGER NOT NULL DEFAULT 0 CONSTRAINT int4_use_count CHECK (use_count BETWEEN -2147483648 AND 2147483647),
  last_used_at INTEGER,
  client TEXT CONSTRAINT credentials_client_check CHECK (client IS NULL OR length(client) BETWEEN 1 AND 64),
  auth_session_id TEXT,
  issued_by TEXT REFERENCES identities (id),
  evidence_user_verified INTEGER CHECK (evidence_user_verified IN (0, 1)),
  evidence_passkey_id TEXT,
  CONSTRAINT credentials_auth_session_id_check CHECK (
    auth_session_id IS NULL
    OR (kind IN ('browser', 'cli') AND length(auth_session_id) BETWEEN 1 AND 200)),
  CONSTRAINT credentials_evidence_check CHECK (
    (evidence_user_verified IS NULL) = (evidence_passkey_id IS NULL)
    AND (evidence_passkey_id IS NULL OR (kind = 'cli' AND auth_session_id IS NULL)))
) STRICT;
CREATE INDEX credentials_identity_idx ON credentials (identity_id);
CREATE INDEX credentials_issued_by ON credentials (issued_by) WHERE issued_by IS NOT NULL;
CREATE INDEX credentials_auth_session_id ON credentials (auth_session_id) WHERE auth_session_id IS NOT NULL;

CREATE TABLE setup_grants (
  id TEXT NOT NULL PRIMARY KEY,
  kind TEXT NOT NULL
    CONSTRAINT setup_grants_kind_check CHECK (kind IN ('bootstrap', 'recover', 'invite', 'reenroll')),
  subject_identity_id TEXT REFERENCES identities (id),
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  invite_organization_id TEXT REFERENCES organizations (id),
  invite_role TEXT CONSTRAINT setup_grants_invite_role_check CHECK (invite_role IN ('admin', 'member')),
  invite_name TEXT,
  revoked_at INTEGER,
  created_by TEXT REFERENCES identities (id),
  CONSTRAINT invite_fields CHECK (
    (kind = 'invite' AND invite_organization_id IS NOT NULL AND invite_role IS NOT NULL)
    OR (kind <> 'invite' AND invite_organization_id IS NULL AND invite_role IS NULL)),
  CONSTRAINT reenroll_subject CHECK (kind <> 'reenroll' OR subject_identity_id IS NOT NULL),
  CONSTRAINT setup_grants_single_terminal_state CHECK (revoked_at IS NULL OR consumed_at IS NULL)
) STRICT;
CREATE INDEX setup_grants_invite_org_idx
  ON setup_grants (invite_organization_id, created_at DESC, id DESC) WHERE kind = 'invite';

CREATE TABLE idempotency_keys (
  identity_id TEXT NOT NULL REFERENCES identities (id),
  endpoint TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  response TEXT NOT NULL CHECK (json_valid(response)),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  PRIMARY KEY (identity_id, endpoint, idempotency_key)
) STRICT;

-- ---------------------------------------------------------------------------
-- People, browser sessions and passkeys
--
-- PostgreSQL's "user", "session" and "passkey" were Better Auth's tables, in
-- its adapter's shape (quoted camelCase). varlatchd owns them now, so they
-- take snake_case names here; their rows' ids are kept (a passkey's user
-- id is its WebAuthn user handle). Better Auth's "account" and
-- "verification" are dropped (MAPPING.md).
-- ---------------------------------------------------------------------------

-- PostgreSQL "user".
CREATE TABLE auth_users (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
  image TEXT,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  updated_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000)
) STRICT;


-- PostgreSQL "session". A session's token is stored as its hash (step 3.4);
-- no session is copied by the migration (ADR-0059 Decision 9: browser
-- sessions end), so no plaintext token ever lands here.
CREATE TABLE auth_sessions (
  id TEXT NOT NULL PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  updated_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  ip_address TEXT,
  user_agent TEXT,
  user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX auth_sessions_user_id_idx ON auth_sessions (user_id);

-- No REPLACE (see the header): replacing a session would end it without
-- session_end_revokes_browser_credentials.
CREATE TRIGGER auth_sessions_no_replace_insert BEFORE INSERT ON auth_sessions
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM auth_sessions WHERE id = NEW.id OR token_hash = NEW.token_hash)
BEGIN
  SELECT RAISE(ABORT, 'auth_sessions_no_replace: the row collides with an existing one; auth_sessions takes no REPLACE or upsert');
END;
CREATE TRIGGER auth_sessions_no_replace_update BEFORE UPDATE OF id, token_hash ON auth_sessions
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM auth_sessions WHERE id <> OLD.id AND (id = NEW.id OR token_hash = NEW.token_hash))
BEGIN
  SELECT RAISE(ABORT, 'auth_sessions_no_replace: the row collides with an existing one; auth_sessions takes no REPLACE or upsert');
END;

-- A browser credential ends with the session it was minted from (PostgreSQL
-- migration 0043): deleting a session row revokes, in the deleting
-- statement, every live `browser` credential carrying its id, and records
-- each revocation as a credential.revoked audit event (no actor; the reason
-- `session-ended`). It covers every delete: sign-out, session revocation,
-- expiry sweeps, the cascade from a deleted user, an operator's SQL. CLI
-- credentials from the browser hand-off carry the session id too and are
-- left alone (ADR-0024).
--
-- SQLite has row triggers only: a statement deleting several sessions
-- writes their events session by session, each session's in credential id
-- order. Event ids have the shape of the TypeScript server's ids: `evt_` and
-- 26 lowercase base32 characters, the last one carrying 3 bits (128 bits in
-- all), from SQLite's random(). auth_sessions_no_replace_* keep REPLACE
-- from removing a session row without this trigger.
CREATE TRIGGER session_end_revokes_browser_credentials AFTER DELETE ON auth_sessions
FOR EACH ROW
BEGIN
  INSERT INTO audit_events (id, schema_version, event_type, decision, credential_id, resource, metadata)
  SELECT 'evt_'
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('abcdefghijklmnopqrstuvwxyz234567', (random() & 31) + 1, 1)
         || substr('aeimquy4', (random() & 7) + 1, 1),
         1, 'credential.revoked', 'info', c.id,
         json_object('identityId', c.identity_id),
         json_object('kind', 'browser', 'reason', 'session-ended')
    FROM credentials c
   WHERE c.auth_session_id = OLD.id AND c.kind = 'browser' AND c.revoked_at IS NULL
     AND (c.expires_at IS NULL OR c.expires_at > (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000))
   ORDER BY c.id;
  UPDATE credentials SET revoked_at = (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000)
   WHERE auth_session_id = OLD.id AND kind = 'browser' AND revoked_at IS NULL
     AND (expires_at IS NULL OR expires_at > (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000));
END;

-- Better Auth user to Varlatch Identity.
CREATE TABLE auth_user_links (
  better_auth_user_id TEXT NOT NULL PRIMARY KEY REFERENCES auth_users (id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL UNIQUE REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000)
) STRICT;

-- What the ceremony that created a session proved. No foreign key to the
-- session: a CLI hand-off credential keeps its session's evidence.
CREATE TABLE auth_session_evidence (
  session_id TEXT NOT NULL PRIMARY KEY
    CONSTRAINT auth_session_evidence_session_id_check CHECK (length(session_id) BETWEEN 1 AND 200),
  ceremony TEXT NOT NULL CONSTRAINT auth_session_evidence_ceremony_check CHECK (ceremony IN ('sign-in', 'enrollment')),
  user_verified INTEGER NOT NULL CHECK (user_verified IN (0, 1)),
  passkey_id TEXT NOT NULL,
  recorded_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000)
) STRICT;

-- PostgreSQL "passkey". A credential id names one passkey.
CREATE TABLE passkeys (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT,
  public_key TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL,
  counter INTEGER NOT NULL CONSTRAINT int4_counter CHECK (counter BETWEEN -2147483648 AND 2147483647),
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  transports TEXT,
  created_at INTEGER,
  aaguid TEXT
) STRICT, WITHOUT ROWID;
CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);
CREATE UNIQUE INDEX passkeys_credential_id_unique ON passkeys (credential_id);

-- No REPLACE (see the header): replacing a passkey would write a new row,
-- counter and all, past passkey_counter_forward.
CREATE TRIGGER passkeys_no_replace_insert BEFORE INSERT ON passkeys
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM passkeys WHERE id = NEW.id OR credential_id = NEW.credential_id)
BEGIN
  SELECT RAISE(ABORT, 'passkeys_no_replace: the row collides with an existing one; passkeys takes no REPLACE or upsert');
END;
CREATE TRIGGER passkeys_no_replace_update BEFORE UPDATE OF id, credential_id ON passkeys
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM passkeys WHERE id <> OLD.id AND (id = NEW.id OR credential_id = NEW.credential_id))
BEGIN
  SELECT RAISE(ABORT, 'passkeys_no_replace: the row collides with an existing one; passkeys takes no REPLACE or upsert');
END;

-- A passkey's signature counter only moves forward, whoever writes it
-- (PostgreSQL migration 0040): when the stored or the new counter is above
-- zero, the new one must be greater. 0 over 0 is allowed (authenticators
-- without a counter). An UPDATE that does not set the counter is not
-- checked.
--
-- WebAuthn counters are unsigned 32-bit numbers, but the column keeps
-- PostgreSQL's signed range (int4_counter): a counter above 2147483647 is
-- refused, never stored as a negative number. Widening it needs an agreed
-- change on the PostgreSQL side too, for the reverse migration.
CREATE TRIGGER passkey_counter_forward BEFORE UPDATE OF counter ON passkeys
FOR EACH ROW
WHEN (NEW.counter > 0 OR OLD.counter > 0) AND NEW.counter <= OLD.counter
BEGIN
  SELECT RAISE(ABORT, 'passkey_counter_forward: a passkey''s signature counter must be greater than the stored one');
END;

CREATE TABLE passkey_provenance (
  passkey_id TEXT NOT NULL PRIMARY KEY REFERENCES passkeys (id) ON DELETE CASCADE,
  trust TEXT NOT NULL CONSTRAINT passkey_provenance_trust_check CHECK (trust IN ('trusted', 'unconfirmed')),
  trusted_via TEXT
    CONSTRAINT passkey_provenance_trusted_via_check CHECK (trusted_via IN ('existing-at-upgrade', 'setup-grant', 'confirmed')),
  trusted_at INTEGER,
  setup_grant_kind TEXT
    CONSTRAINT passkey_provenance_setup_grant_kind_check CHECK (setup_grant_kind IN ('bootstrap', 'recover', 'invite', 'reenroll')),
  confirmed_by_passkey_id TEXT,
  recorded_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  CONSTRAINT passkey_provenance_check CHECK ((trust = 'trusted') = (trusted_via IS NOT NULL)),
  CONSTRAINT passkey_provenance_check1 CHECK ((trusted_via IS NULL) = (trusted_at IS NULL)),
  CONSTRAINT passkey_provenance_check2 CHECK ((trusted_via IS 'setup-grant') = (setup_grant_kind IS NOT NULL)),
  CONSTRAINT passkey_provenance_check3 CHECK ((trusted_via IS 'confirmed') = (confirmed_by_passkey_id IS NOT NULL)),
  CONSTRAINT passkey_provenance_check4 CHECK (confirmed_by_passkey_id IS NULL OR confirmed_by_passkey_id <> passkey_id)
) STRICT;

-- Duplicate credential ids moved aside by PostgreSQL migration 0039.
CREATE TABLE passkey_quarantine (
  id TEXT NOT NULL PRIMARY KEY,
  name TEXT,
  public_key TEXT NOT NULL,
  user_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  counter INTEGER NOT NULL CONSTRAINT int4_counter CHECK (counter BETWEEN -2147483648 AND 2147483647),
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  transports TEXT,
  created_at INTEGER,
  aaguid TEXT,
  quarantined_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  reason TEXT NOT NULL CONSTRAINT passkey_quarantine_reason_check CHECK (reason = 'duplicate-credential-id'),
  kept_passkey_id TEXT NOT NULL
) STRICT;

CREATE TABLE passkey_confirmation_challenges (
  id TEXT NOT NULL PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT NOT NULL,
  target_passkey_id TEXT NOT NULL REFERENCES passkeys (id) ON DELETE CASCADE,
  challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT;
CREATE INDEX passkey_confirmation_challenges_identity ON passkey_confirmation_challenges (identity_id, created_at);

-- Device-authorization sign-in (ADR-0043).
CREATE TABLE device_sign_ins (
  id TEXT NOT NULL PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  -- PostgreSQL: user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{8}$'.
  user_code TEXT NOT NULL CONSTRAINT device_sign_ins_user_code_check
    CHECK (length(user_code) = 8 AND user_code NOT GLOB '*[^BCDFGHJKLMNPQRSTVWXZ]*'),
  status TEXT NOT NULL DEFAULT 'pending'
    CONSTRAINT device_sign_ins_status_check CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
  requested_ttl INTEGER NOT NULL CONSTRAINT device_sign_ins_requested_ttl_check CHECK (requested_ttl BETWEEN 60 AND 86400),
  requested_name TEXT CONSTRAINT device_sign_ins_requested_name_check
    CHECK (requested_name IS NULL OR length(requested_name) BETWEEN 1 AND 200),
  requester_ip TEXT,
  requester_user_agent TEXT CONSTRAINT device_sign_ins_requester_user_agent_check
    CHECK (requester_user_agent IS NULL OR length(requester_user_agent) <= 512),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  expires_at INTEGER NOT NULL,
  approved_by_identity_id TEXT REFERENCES identities (id),
  decided_at INTEGER,
  last_polled_at INTEGER,
  poll_interval INTEGER NOT NULL DEFAULT 5 CONSTRAINT device_sign_ins_poll_interval_check CHECK (poll_interval > 0) CONSTRAINT int4_poll_interval CHECK (poll_interval <= 2147483647),
  issued_credential_id TEXT REFERENCES credentials (id),
  approval_user_verified INTEGER CHECK (approval_user_verified IN (0, 1)),
  approval_passkey_id TEXT,
  CONSTRAINT device_sign_ins_approval_evidence_check CHECK ((approval_user_verified IS NULL) = (approval_passkey_id IS NULL))
) STRICT;
CREATE UNIQUE INDEX device_sign_ins_pending_user_code ON device_sign_ins (user_code) WHERE status = 'pending';
CREATE INDEX device_sign_ins_expires_at ON device_sign_ins (expires_at);

CREATE TABLE device_sign_in_challenges (
  id TEXT NOT NULL PRIMARY KEY,
  device_sign_in_id TEXT NOT NULL REFERENCES device_sign_ins (id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT NOT NULL,
  challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT;
CREATE INDEX device_sign_in_challenges_sign_in ON device_sign_in_challenges (device_sign_in_id);

CREATE TABLE device_code_attempt_windows (
  scope TEXT NOT NULL CONSTRAINT device_code_attempt_windows_scope_check CHECK (scope IN ('identity', 'peer', 'global')),
  key TEXT NOT NULL,
  window_started_at INTEGER NOT NULL,
  failures INTEGER NOT NULL DEFAULT 0 CONSTRAINT device_code_attempt_windows_failures_check CHECK (failures >= 0) CONSTRAINT int4_failures CHECK (failures <= 2147483647),
  PRIMARY KEY (scope, key)
) STRICT;

-- ---------------------------------------------------------------------------
-- Organizations, membership and their removal
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
  id TEXT NOT NULL PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  wrapped_org_kek TEXT CHECK (json_valid(wrapped_org_kek)),
  deleted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  root_kek_version INTEGER NOT NULL DEFAULT 1 CONSTRAINT organizations_root_kek_version_check CHECK (root_kek_version > 0) CONSTRAINT int4_root_kek_version CHECK (root_kek_version <= 2147483647),
  key_rotation_state TEXT NOT NULL DEFAULT 'idle'
    CONSTRAINT organizations_key_rotation_state_check CHECK (key_rotation_state IN ('idle', 'rewrapping', 'verifying')),
  org_kek_destroyed_at INTEGER,
  security_epoch INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT organizations_kek_present_or_destroyed CHECK (
    (wrapped_org_kek IS NOT NULL AND org_kek_destroyed_at IS NULL)
    OR (wrapped_org_kek IS NULL AND org_kek_destroyed_at IS NOT NULL AND deleted_at IS NOT NULL))
) STRICT;

CREATE TABLE org_memberships (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  role TEXT NOT NULL CONSTRAINT org_memberships_role_check CHECK (role IN ('admin', 'member')),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  removed_at INTEGER,
  version INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (organization_id, identity_id)
) STRICT;
CREATE INDEX org_memberships_live_identity ON org_memberships (identity_id) WHERE removed_at IS NULL;

-- Removing a person from an Organization (ADR-0052).
CREATE TABLE membership_removals (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  role TEXT NOT NULL CONSTRAINT membership_removals_role_check CHECK (role IN ('admin', 'member')),
  actor_identity_id TEXT NOT NULL REFERENCES identities (id),
  removed_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  UNIQUE (organization_id, identity_id)
) STRICT;

CREATE TABLE removal_authority (
  removal_id TEXT NOT NULL REFERENCES membership_removals (id),
  environment_id TEXT NOT NULL REFERENCES environments (id),
  action TEXT NOT NULL CONSTRAINT removal_authority_action_check
    CHECK (action IN ('config.metadata.read', 'config.value.read', 'secret.reveal', 'secret.use')),
  source TEXT NOT NULL,
  role TEXT CONSTRAINT removal_authority_role_check CHECK (role IN ('admin', 'member')),
  grant_id TEXT,
  via_group_id TEXT,
  role_id TEXT,
  PRIMARY KEY (removal_id, environment_id, action, source)
) STRICT;

CREATE TABLE removal_requirements (
  removal_id TEXT NOT NULL REFERENCES membership_removals (id),
  requirement_id TEXT NOT NULL,
  requirement_version INTEGER CONSTRAINT int4_requirement_version CHECK (requirement_version BETWEEN -2147483648 AND 2147483647),
  target TEXT NOT NULL CHECK (json_valid(target)),
  selector TEXT NOT NULL CHECK (json_valid(selector)),
  PRIMARY KEY (removal_id, requirement_id)
) STRICT;

CREATE TABLE removal_conditions (
  removal_id TEXT NOT NULL REFERENCES membership_removals (id),
  environment_id TEXT NOT NULL REFERENCES environments (id),
  requirement_id TEXT NOT NULL,
  PRIMARY KEY (removal_id, environment_id, requirement_id),
  FOREIGN KEY (removal_id, requirement_id) REFERENCES removal_requirements (removal_id, requirement_id)
) STRICT;

CREATE TABLE member_integrations (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  kind TEXT NOT NULL CONSTRAINT member_integrations_kind_check CHECK (kind IN ('target', 'connection')),
  resource_id TEXT NOT NULL,
  changes TEXT NOT NULL CHECK (json_valid(changes) AND json_type(changes) = 'array'),
  first_at INTEGER NOT NULL,
  last_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, identity_id, kind, resource_id)
) STRICT;

-- changes: PostgreSQL text[], here a JSON array of strings or nulls. The
-- CHECK keeps the array; these keep its elements (a CHECK cannot read
-- json_each). Text that is not a JSON array is left to the CHECK.
CREATE TRIGGER member_integrations_text_arrays_insert BEFORE INSERT ON member_integrations
FOR EACH ROW
WHEN (json_valid(NEW.changes) AND json_type(NEW.changes) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.changes) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'member_integrations_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;
CREATE TRIGGER member_integrations_text_arrays_update BEFORE UPDATE OF changes ON member_integrations
FOR EACH ROW
WHEN (json_valid(NEW.changes) AND json_type(NEW.changes) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.changes) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'member_integrations_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;

-- What a person received (ADR-0052 Decisions 6 and 7). No foreign key to
-- value_versions: the evidence outlives the value.
CREATE TABLE member_exposure (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  version_id TEXT NOT NULL,
  item_name TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  way TEXT NOT NULL CONSTRAINT member_exposure_way_check CHECK (way IN ('revealed', 'delivered', 'export', 'written')),
  first_at INTEGER NOT NULL,
  last_at INTEGER NOT NULL,
  PRIMARY KEY (organization_id, identity_id, version_id, environment_id, way)
) STRICT;

-- The exposure backfill's position: one row, from the start.
CREATE TABLE exposure_backfill (
  singleton INTEGER NOT NULL PRIMARY KEY CONSTRAINT exposure_backfill_singleton_check CHECK (singleton = 1),
  cursor INTEGER NOT NULL,
  until_order INTEGER NOT NULL,
  finished_at INTEGER
) STRICT;
-- As PostgreSQL migration 0036 left a database without audit history:
-- nothing to backfill, so finished at once.
INSERT INTO exposure_backfill (singleton, cursor, until_order, finished_at)
  VALUES (1, 0, 0, (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000));

CREATE TABLE exposure_confirmations (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  version_id TEXT NOT NULL,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  actor_identity_id TEXT NOT NULL REFERENCES identities (id),
  confirmed_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  PRIMARY KEY (organization_id, version_id)
) STRICT;

-- Deleting an Organization (ADR-0051 Decisions 4 to 8).
CREATE TABLE organization_deletions (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  requested_by TEXT NOT NULL REFERENCES identities (id),
  scheduled_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  run_after INTEGER NOT NULL,
  approval_required INTEGER NOT NULL CHECK (approval_required IN (0, 1)),
  approved_by TEXT REFERENCES identities (id),
  approved_at INTEGER,
  cancelled_by TEXT REFERENCES identities (id),
  cancelled_at INTEGER,
  completed_at INTEGER,
  CONSTRAINT organization_deletions_check CHECK (run_after > scheduled_at),
  CONSTRAINT organization_deletions_check1 CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
  CONSTRAINT organization_deletions_check2 CHECK (approved_by IS NULL OR approval_required),
  CONSTRAINT organization_deletions_check3 CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CONSTRAINT organization_deletions_check4 CHECK ((cancelled_by IS NULL) = (cancelled_at IS NULL)),
  CONSTRAINT organization_deletions_check5 CHECK (cancelled_at IS NULL OR completed_at IS NULL)
) STRICT;
CREATE UNIQUE INDEX organization_deletions_open ON organization_deletions (organization_id)
  WHERE cancelled_at IS NULL AND completed_at IS NULL;
CREATE INDEX organization_deletions_due ON organization_deletions (run_after)
  WHERE cancelled_at IS NULL AND completed_at IS NULL;

-- The incident freeze (ADR-0055 Decision 1).
CREATE TABLE organization_freezes (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  frozen_by TEXT NOT NULL REFERENCES identities (id),
  frozen_at INTEGER NOT NULL,
  reason TEXT NOT NULL CONSTRAINT organization_freezes_reason_check CHECK (length(reason) BETWEEN 1 AND 200),
  lifted_at INTEGER,
  lifted_by TEXT REFERENCES identities (id),
  lift_method TEXT CONSTRAINT organization_freezes_lift_method_check CHECK (lift_method IN ('approval', 'operator')),
  CONSTRAINT organization_freezes_check CHECK ((lifted_at IS NULL) = (lift_method IS NULL)),
  CONSTRAINT organization_freezes_check1 CHECK (lifted_by IS NULL OR lift_method = 'approval'),
  CONSTRAINT organization_freezes_check2 CHECK (lift_method IS NOT 'approval' OR lifted_by IS NOT NULL),
  CONSTRAINT organization_freezes_check3 CHECK (lifted_at IS NULL OR lifted_at >= frozen_at)
) STRICT;
CREATE UNIQUE INDEX organization_freezes_open ON organization_freezes (organization_id) WHERE lifted_at IS NULL;
CREATE INDEX organization_freezes_by_organization ON organization_freezes (organization_id, frozen_at);

CREATE TABLE audit_tombstone_readers (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  added_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  removed_at INTEGER,
  removed_by TEXT REFERENCES identities (id),
  PRIMARY KEY (organization_id, identity_id),
  CONSTRAINT audit_tombstone_readers_check CHECK ((removed_at IS NULL) = (removed_by IS NULL))
) STRICT;

-- ---------------------------------------------------------------------------
-- Projects, environments, values and Contracts
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  contract_authority TEXT NOT NULL CONSTRAINT projects_contract_authority_check CHECK (contract_authority IN ('git', 'managed')),
  active_contract_revision_id TEXT,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  deleted_at INTEGER
) STRICT;
CREATE UNIQUE INDEX projects_live_slug ON projects (organization_id, slug) WHERE deleted_at IS NULL;

CREATE TABLE environments (
  id TEXT NOT NULL PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CONSTRAINT environments_kind_check CHECK (kind IN ('shared', 'personal', 'preview')),
  tier TEXT NOT NULL CONSTRAINT environments_tier_check CHECK (tier IN ('development', 'staging', 'production')),
  parent_environment_id TEXT REFERENCES environments (id),
  owner_identity_id TEXT REFERENCES identities (id),
  expires_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  deleted_at INTEGER,
  CONSTRAINT derived_env_kind CHECK (
    (parent_environment_id IS NULL AND kind = 'shared')
    OR (parent_environment_id IS NOT NULL AND kind IN ('personal', 'preview')))
) STRICT;
CREATE UNIQUE INDEX environments_live_name_key ON environments (project_id, name) WHERE deleted_at IS NULL;

CREATE TABLE env_values (
  id TEXT NOT NULL PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id),
  item_name TEXT NOT NULL,
  current_version_id TEXT,
  deleted_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  retiring_version_id TEXT REFERENCES value_versions (id),
  rotation_deadline INTEGER,
  rotation_started_at INTEGER,
  UNIQUE (environment_id, item_name)
) STRICT;

CREATE TABLE value_versions (
  id TEXT NOT NULL PRIMARY KEY,
  value_id TEXT NOT NULL REFERENCES env_values (id),
  payload TEXT CHECK (json_valid(payload)),
  wrapped_dek TEXT CHECK (json_valid(wrapped_dek)),
  previous_version_id TEXT REFERENCES value_versions (id),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  erased_at INTEGER,
  CONSTRAINT value_versions_intact_or_erased CHECK (
    (erased_at IS NULL AND payload IS NOT NULL AND wrapped_dek IS NOT NULL)
    OR (erased_at IS NOT NULL AND payload IS NULL AND wrapped_dek IS NULL))
) STRICT;
CREATE INDEX value_versions_value_idx ON value_versions (value_id);

CREATE TABLE contract_revisions (
  id TEXT NOT NULL PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id),
  content_hash TEXT NOT NULL,
  contract TEXT NOT NULL CHECK (json_valid(contract)),
  provenance TEXT CHECK (json_valid(provenance)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  UNIQUE (project_id, content_hash)
) STRICT;

-- ---------------------------------------------------------------------------
-- Access: Grants, Roles, Groups and Teams, Requirements, OIDC, Capabilities
-- ---------------------------------------------------------------------------

CREATE TABLE roles (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  name TEXT NOT NULL,
  actions TEXT NOT NULL CHECK (json_valid(actions) AND json_type(actions) = 'array'),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER
) STRICT;
CREATE UNIQUE INDEX roles_org_name_key ON roles (organization_id, name) WHERE revoked_at IS NULL;

-- actions: PostgreSQL text[], here a JSON array of strings or nulls. The
-- CHECK keeps the array; these keep its elements (a CHECK cannot read
-- json_each). Text that is not a JSON array is left to the CHECK.
CREATE TRIGGER roles_text_arrays_insert BEFORE INSERT ON roles
FOR EACH ROW
WHEN (json_valid(NEW.actions) AND json_type(NEW.actions) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.actions) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'roles_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;
CREATE TRIGGER roles_text_arrays_update BEFORE UPDATE OF actions ON roles
FOR EACH ROW
WHEN (json_valid(NEW.actions) AND json_type(NEW.actions) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.actions) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'roles_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;

CREATE TABLE groups (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  name TEXT NOT NULL,
  kind TEXT NOT NULL CONSTRAINT groups_kind_check CHECK (kind IN ('group', 'team')),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER
) STRICT;
CREATE UNIQUE INDEX groups_org_name_key ON groups (organization_id, name) WHERE revoked_at IS NULL;

CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  PRIMARY KEY (group_id, identity_id)
) STRICT;
CREATE INDEX group_members_identity_idx ON group_members (identity_id);

CREATE TABLE team_projects (
  team_id TEXT NOT NULL REFERENCES groups (id),
  project_id TEXT NOT NULL REFERENCES projects (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  PRIMARY KEY (team_id, project_id)
) STRICT;

-- A Grant's subject is an identity or a group; its permissions literal
-- actions or a Role.
CREATE TABLE grants (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  subject_identity_id TEXT REFERENCES identities (id),
  scope TEXT NOT NULL CHECK (json_valid(scope)),
  actions TEXT CHECK (json_valid(actions) AND json_type(actions) = 'array'),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  subject_group_id TEXT REFERENCES groups (id),
  role_id TEXT REFERENCES roles (id),
  CONSTRAINT grants_subject_one CHECK ((subject_identity_id IS NOT NULL) <> (subject_group_id IS NOT NULL)),
  CONSTRAINT grants_permission_one CHECK (actions IS NOT NULL OR role_id IS NOT NULL)
) STRICT;
CREATE INDEX grants_subject_idx ON grants (subject_identity_id) WHERE revoked_at IS NULL;
CREATE INDEX grants_subject_group_idx ON grants (subject_group_id) WHERE revoked_at IS NULL;

-- actions: PostgreSQL text[], here a JSON array of strings or nulls. The
-- CHECK keeps the array; these keep its elements (a CHECK cannot read
-- json_each). Text that is not a JSON array is left to the CHECK.
CREATE TRIGGER grants_text_arrays_insert BEFORE INSERT ON grants
FOR EACH ROW
WHEN (json_valid(NEW.actions) AND json_type(NEW.actions) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.actions) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'grants_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;
CREATE TRIGGER grants_text_arrays_update BEFORE UPDATE OF actions ON grants
FOR EACH ROW
WHEN (json_valid(NEW.actions) AND json_type(NEW.actions) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.actions) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'grants_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;

CREATE TABLE requirements (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  kind TEXT NOT NULL CONSTRAINT requirements_kind_check CHECK (kind = 'tailnet'),
  target TEXT NOT NULL CHECK (json_valid(target)),
  config TEXT NOT NULL CHECK (json_valid(config)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER
) STRICT;

CREATE TABLE oidc_bindings (
  id TEXT NOT NULL PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  issuer TEXT NOT NULL,
  audience TEXT NOT NULL,
  subject TEXT NOT NULL,
  claims TEXT CHECK (json_valid(claims)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER
) STRICT;
CREATE INDEX oidc_bindings_issuer_idx ON oidc_bindings (issuer) WHERE revoked_at IS NULL;

-- Broker Capabilities (ADR-0022, ADR-0039).
CREATE TABLE capabilities (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  broker_identity_id TEXT NOT NULL REFERENCES identities (id),
  agent_identity_id TEXT NOT NULL REFERENCES identities (id),
  project_id TEXT NOT NULL REFERENCES projects (id),
  environment_id TEXT NOT NULL REFERENCES environments (id),
  items TEXT NOT NULL CHECK (json_valid(items) AND json_type(items) = 'array'),
  destinations TEXT NOT NULL CHECK (json_valid(destinations) AND json_type(destinations) = 'array'),
  secret_hash TEXT NOT NULL,
  run_id TEXT,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  created_by TEXT NOT NULL REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  targets TEXT CHECK (json_valid(targets))
) STRICT;
CREATE INDEX capabilities_org_idx ON capabilities (organization_id, created_at);
CREATE INDEX capabilities_broker_idx ON capabilities (broker_identity_id);

-- items and destinations: PostgreSQL text[], here a JSON array of strings or nulls. The
-- CHECK keeps the array; these keep its elements (a CHECK cannot read
-- json_each). Text that is not a JSON array is left to the CHECK.
CREATE TRIGGER capabilities_text_arrays_insert BEFORE INSERT ON capabilities
FOR EACH ROW
WHEN (json_valid(NEW.items) AND json_type(NEW.items) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.items) WHERE type NOT IN ('text', 'null')))
  OR (json_valid(NEW.destinations) AND json_type(NEW.destinations) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.destinations) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'capabilities_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;
CREATE TRIGGER capabilities_text_arrays_update BEFORE UPDATE OF items, destinations ON capabilities
FOR EACH ROW
WHEN (json_valid(NEW.items) AND json_type(NEW.items) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.items) WHERE type NOT IN ('text', 'null')))
  OR (json_valid(NEW.destinations) AND json_type(NEW.destinations) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.destinations) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'capabilities_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;

-- ---------------------------------------------------------------------------
-- Security Controls and step-up approvals (ADR-0054, ADR-0055)
-- ---------------------------------------------------------------------------

CREATE TABLE security_controls (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  control TEXT NOT NULL CONSTRAINT security_controls_control_check
    CHECK (control IN ('requirement-protection', 'admin-step-up', 'passkey-verification', 'credential-lifetime')),
  mode TEXT NOT NULL CONSTRAINT security_controls_mode_check CHECK (mode IN ('off', 'report', 'enforce')),
  config TEXT CHECK (json_valid(config)),
  version INTEGER NOT NULL CONSTRAINT security_controls_version_check CHECK (version > 0) CONSTRAINT int4_version CHECK (version <= 2147483647),
  changed_by TEXT REFERENCES identities (id),
  changed_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  PRIMARY KEY (organization_id, control),
  CONSTRAINT security_controls_check CHECK (config IS NULL OR control = 'credential-lifetime'),
  -- PostgreSQL: jsonb_typeof(...) = 'number' and ->> ... ::numeric.
  CONSTRAINT security_controls_config_check CHECK (config IS NULL OR (
    json_valid(config)
    AND json_type(config) = 'object'
    AND json_type(config, '$.defaultTtlSeconds') IN ('integer', 'real')
    AND json_type(config, '$.maxTtlSeconds') IN ('integer', 'real')
    AND json_extract(config, '$.defaultTtlSeconds') > 0
    AND json_extract(config, '$.defaultTtlSeconds') <= json_extract(config, '$.maxTtlSeconds')))
) STRICT;

-- Report counters (ADR-0054 Decision 9). No foreign keys, as in
-- PostgreSQL: the ids are identifiers only.
CREATE TABLE security_control_counters (
  organization_id TEXT NOT NULL
    CONSTRAINT security_control_counters_organization_id_check CHECK (length(organization_id) BETWEEN 1 AND 200),
  control TEXT NOT NULL CONSTRAINT security_control_counters_control_check
    CHECK (control IN ('requirement-protection', 'admin-step-up', 'passkey-verification', 'credential-lifetime')),
  config_version INTEGER NOT NULL CONSTRAINT security_control_counters_config_version_check CHECK (config_version > 0) CONSTRAINT int4_config_version CHECK (config_version <= 2147483647),
  -- PostgreSQL: operation ~ '^[a-z][a-z_-]*(\.[a-z][a-z_-]*)+$'.
  operation TEXT NOT NULL CONSTRAINT security_control_counters_operation_check CHECK (
    length(operation) <= 64
    AND operation GLOB '[a-z]*.[a-z]*'
    AND operation NOT GLOB '*[^a-z_.-]*'
    AND operation NOT GLOB '*.[^a-z]*'
    AND operation NOT GLOB '*.'),
  actor_identity_id TEXT NOT NULL
    CONSTRAINT security_control_counters_actor_identity_id_check CHECK (length(actor_identity_id) BETWEEN 1 AND 200),
  reason TEXT NOT NULL CONSTRAINT security_control_counters_reason_check CHECK (reason IN (
    'no-approval', 'machine-credential',
    'no-evidence', 'not-user-verified', 'untrusted-passkey',
    'would-default', 'would-refuse')),
  -- PostgreSQL: bucket_hour = date_trunc('hour', bucket_hour, 'UTC').
  bucket_hour INTEGER NOT NULL CONSTRAINT security_control_counters_bucket_hour_check CHECK (bucket_hour % 3600000000 = 0),
  count INTEGER NOT NULL CONSTRAINT security_control_counters_count_check CHECK (count > 0),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  emitted_at INTEGER,
  CONSTRAINT security_control_counters_check CHECK (last_seen >= first_seen),
  PRIMARY KEY (organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour)
) STRICT;
CREATE INDEX security_control_counters_unemitted ON security_control_counters (bucket_hour) WHERE emitted_at IS NULL;
CREATE INDEX security_control_counters_emitted ON security_control_counters (emitted_at) WHERE emitted_at IS NOT NULL;
CREATE INDEX security_control_counters_organization ON security_control_counters (organization_id, bucket_hour);

-- One person's step-up approval for one exact operation.
CREATE TABLE approval_intents (
  id TEXT NOT NULL PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES credentials (id),
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT CONSTRAINT approval_intents_auth_session_id_check
    CHECK (auth_session_id IS NULL OR length(auth_session_id) BETWEEN 1 AND 200),
  organization_id TEXT REFERENCES organizations (id),
  operation TEXT NOT NULL CONSTRAINT approval_intents_operation_check CHECK (operation IN (
    'security_control.change', 'passkey.remove', 'organization.unfreeze',
    'requirement.update', 'requirement.revoke',
    'identity.create', 'credential.issue', 'identity.reactivate',
    'oidc_binding.create', 'oidc_binding.delete',
    'grant.create', 'grant.replace', 'grant.revoke',
    'role.create', 'role.update', 'role.delete',
    'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
    'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
    'team.project_add', 'team.project_remove',
    'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
    'webhook.create', 'webhook.update', 'webhook.delete',
    'connection.create', 'connection.replace_credential', 'connection.delete',
    'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove',
    'project.delete', 'organization.delete', 'secret.export',
    'audit_export.change', 'audit_export.remove')),
  target TEXT NOT NULL CONSTRAINT approval_intents_target_check CHECK (json_valid(target) AND json_type(target) = 'object'),
  body_hash TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  expected_version INTEGER CONSTRAINT int4_expected_version CHECK (expected_version BETWEEN -2147483648 AND 2147483647),
  summary TEXT NOT NULL CHECK (json_valid(summary)),
  origin TEXT NOT NULL CONSTRAINT approval_intents_origin_check CHECK (origin IN ('dashboard', 'cli')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  approved_with_passkey_id TEXT,
  approval_user_verified INTEGER CHECK (approval_user_verified IN (0, 1)),
  consumed_at INTEGER,
  closed_at INTEGER,
  close_reason TEXT CONSTRAINT approval_intents_close_reason_check
    CHECK (close_reason IN ('cancelled', 'reset', 'organization-deleted', 'frozen')),
  poll_interval INTEGER NOT NULL CONSTRAINT approval_intents_poll_interval_check CHECK (poll_interval > 0) CONSTRAINT int4_poll_interval CHECK (poll_interval <= 2147483647),
  last_polled_at INTEGER,
  CONSTRAINT approval_intents_check CHECK (expires_at > created_at),
  CONSTRAINT approval_intents_check1 CHECK ((origin = 'dashboard') = (auth_session_id IS NOT NULL)),
  CONSTRAINT approval_intents_check2 CHECK ((approved_at IS NULL) = (approved_with_passkey_id IS NULL)),
  CONSTRAINT approval_intents_check3 CHECK ((approved_at IS NULL) = (approval_user_verified IS NULL)),
  CONSTRAINT approval_intents_check4 CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
  CONSTRAINT approval_intents_check5 CHECK ((closed_at IS NULL) = (close_reason IS NULL)),
  CONSTRAINT approval_intents_check6 CHECK (consumed_at IS NULL OR closed_at IS NULL),
  CONSTRAINT approval_intents_check7 CHECK (operation <> 'passkey.remove' OR organization_id IS NULL),
  CONSTRAINT approval_intents_check8 CHECK (operation <> 'security_control.change' OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_unfreeze_organization CHECK (operation <> 'organization.unfreeze' OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_requirement_organization
    CHECK (operation NOT IN ('requirement.update', 'requirement.revoke') OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_admin_step_up_organization CHECK (operation NOT IN (
    'identity.create', 'credential.issue', 'identity.reactivate',
    'oidc_binding.create', 'oidc_binding.delete',
    'grant.create', 'grant.replace', 'grant.revoke',
    'role.create', 'role.update', 'role.delete',
    'group.create', 'group.update', 'group.delete', 'group.member_add', 'group.member_remove',
    'team.create', 'team.update', 'team.delete', 'team.member_add', 'team.member_remove',
    'team.project_add', 'team.project_remove',
    'member.invite_admin', 'member.promote', 'member.demote', 'member.remove',
    'webhook.create', 'webhook.update', 'webhook.delete',
    'connection.create', 'connection.replace_credential', 'connection.delete',
    'github_app.register', 'github_app.import', 'github_app.replace_key', 'github_app.remove',
    'project.delete', 'organization.delete', 'secret.export') OR organization_id IS NOT NULL),
  CONSTRAINT approval_intents_audit_export_organization
    CHECK (operation NOT IN ('audit_export.change', 'audit_export.remove') OR organization_id IS NOT NULL)
) STRICT;
CREATE INDEX approval_intents_open_by_credential ON approval_intents (credential_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_open_by_organization ON approval_intents (organization_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_identity_created ON approval_intents (identity_id, created_at);
CREATE INDEX approval_intents_expires ON approval_intents (expires_at);

CREATE TABLE approval_intent_challenges (
  id TEXT NOT NULL PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES approval_intents (id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities (id),
  auth_session_id TEXT NOT NULL
    CONSTRAINT approval_intent_challenges_auth_session_id_check CHECK (length(auth_session_id) BETWEEN 1 AND 200),
  challenge TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  CONSTRAINT approval_intent_challenges_check CHECK (expires_at > created_at)
) STRICT;
CREATE INDEX approval_intent_challenges_identity ON approval_intent_challenges (identity_id, created_at);
CREATE INDEX approval_intent_challenges_intent ON approval_intent_challenges (intent_id);

-- ---------------------------------------------------------------------------
-- Audit: events, webhooks and exports
-- ---------------------------------------------------------------------------

-- Security Audit Events. event_order, the commit-ordered position
-- (PostgreSQL migration 0017), is the table's rowid: SQLite gives an
-- inserted row max(event_order) + 1. PostgreSQL needed a counter row locked
-- until commit so that no visible higher position could overtake an
-- uncommitted lower one; here every write runs on lib/storage's single
-- writer, one job after another, and a batch commits as a whole, so a
-- reader never sees a position whose predecessors are not visible too. A
-- job rolled back to its savepoint gives its positions back before the next
-- job takes them, so positions have no gaps. The triggers below enforce
-- what the database can: positions are assigned in order with no gap,
-- whoever inserts, and the table is append-only (PostgreSQL withheld UPDATE
-- and DELETE from the runtime role, migration 0003; SQLite has no roles).
CREATE TABLE audit_events (
  event_order INTEGER NOT NULL PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  schema_version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_schema_version CHECK (schema_version BETWEEN -2147483648 AND 2147483647),
  event_type TEXT NOT NULL,
  occurred_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  actor_identity_id TEXT,
  authentication_method_id TEXT,
  credential_id TEXT,
  organization_id TEXT,
  action TEXT,
  resource TEXT CHECK (json_valid(resource)),
  decision TEXT NOT NULL CONSTRAINT audit_events_decision_check CHECK (decision IN ('allow', 'deny', 'info')),
  authz TEXT CHECK (json_valid(authz)),
  tailnet TEXT CHECK (json_valid(tailnet)),
  listener TEXT CONSTRAINT audit_events_listener_check CHECK (listener IN ('ordinary', 'tailnet')),
  request_id TEXT,
  metadata TEXT CHECK (json_valid(metadata)),
  client TEXT CONSTRAINT audit_events_client_check CHECK (client IS NULL OR length(client) BETWEEN 1 AND 64)
) STRICT;
CREATE INDEX audit_events_org_time_idx ON audit_events (organization_id, occurred_at DESC, id DESC);
CREATE INDEX audit_events_org_order_idx ON audit_events (organization_id, event_order);

-- No REPLACE (see the header): replacing an event would delete it past
-- audit_events_no_delete and leave a gap audit_events_position cannot see.
-- UPDATE OR REPLACE is refused by audit_events_no_update, which runs first.
-- An insert that leaves event_order to SQLite has none to collide with.
CREATE TRIGGER audit_events_no_replace_insert BEFORE INSERT ON audit_events
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM audit_events WHERE id = NEW.id OR event_order = NEW.event_order)
BEGIN
  SELECT RAISE(ABORT, 'audit_events_no_replace: the row collides with an existing one; audit_events takes no REPLACE or upsert');
END;

-- The new row must be the last, right after its predecessor: an insert
-- that names its own event_order is refused unless it names exactly that.
CREATE TRIGGER audit_events_position AFTER INSERT ON audit_events
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM audit_events WHERE event_order > NEW.event_order)
  OR NEW.event_order <> 1 + coalesce((SELECT max(event_order) FROM audit_events WHERE event_order < NEW.event_order), 0)
BEGIN
  SELECT RAISE(ABORT, 'audit_events_position: audit positions are assigned in commit order, without gaps');
END;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events_no_update: audit events are append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events_no_delete: audit events are append-only');
END;

-- Audit webhooks: delivery follows a cursor over audit_events.
CREATE TABLE webhooks (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  url TEXT NOT NULL,
  event_types TEXT CHECK (json_valid(event_types) AND json_type(event_types) = 'array'),
  secret_envelope TEXT NOT NULL CHECK (json_valid(secret_envelope)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  cursor_occurred_at INTEGER NOT NULL,
  cursor_event_id TEXT NOT NULL DEFAULT '',
  failure_count INTEGER NOT NULL DEFAULT 0 CONSTRAINT int4_failure_count CHECK (failure_count BETWEEN -2147483648 AND 2147483647),
  last_attempt_at INTEGER,
  last_status TEXT,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER,
  cursor_order INTEGER NOT NULL DEFAULT 0,
  suspended_by_deletion TEXT REFERENCES organization_deletions (id)
) STRICT;
CREATE INDEX webhooks_org_idx ON webhooks (organization_id) WHERE revoked_at IS NULL;

-- event_types: PostgreSQL text[], here a JSON array of strings or nulls. The
-- CHECK keeps the array; these keep its elements (a CHECK cannot read
-- json_each). Text that is not a JSON array is left to the CHECK.
CREATE TRIGGER webhooks_text_arrays_insert BEFORE INSERT ON webhooks
FOR EACH ROW
WHEN (json_valid(NEW.event_types) AND json_type(NEW.event_types) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.event_types) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'webhooks_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;
CREATE TRIGGER webhooks_text_arrays_update BEFORE UPDATE OF event_types ON webhooks
FOR EACH ROW
WHEN (json_valid(NEW.event_types) AND json_type(NEW.event_types) = 'array'
      AND EXISTS (SELECT 1 FROM json_each(NEW.event_types) WHERE type NOT IN ('text', 'null')))
BEGIN
  SELECT RAISE(ABORT, 'webhooks_text_arrays: a text[] column holds a JSON array of strings or nulls');
END;

-- Audit export to object storage (ADR-0056).
CREATE TABLE audit_exports (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  endpoint TEXT NOT NULL CONSTRAINT audit_exports_endpoint_check CHECK (length(endpoint) BETWEEN 1 AND 2048),
  region TEXT NOT NULL CONSTRAINT audit_exports_region_check CHECK (length(region) BETWEEN 1 AND 64),
  bucket TEXT NOT NULL CONSTRAINT audit_exports_bucket_check CHECK (length(bucket) BETWEEN 3 AND 63),
  prefix TEXT NOT NULL CONSTRAINT audit_exports_prefix_check CHECK (length(prefix) <= 256),
  path_style INTEGER NOT NULL CHECK (path_style IN (0, 1)),
  credential_envelope TEXT CHECK (json_valid(credential_envelope)),
  retention_mode TEXT CONSTRAINT audit_exports_retention_mode_check CHECK (retention_mode IN ('compliance', 'governance')),
  retention_days INTEGER CONSTRAINT audit_exports_retention_days_check CHECK (retention_days BETWEEN 1 AND 3650),
  stream_id TEXT NOT NULL,
  stream_started_at INTEGER NOT NULL,
  cursor_order INTEGER NOT NULL CONSTRAINT audit_exports_cursor_order_check CHECK (cursor_order >= 0),
  generation INTEGER NOT NULL DEFAULT 0,
  lease_expires_at INTEGER,
  state TEXT NOT NULL CONSTRAINT audit_exports_state_check
    CHECK (state IN ('active', 'draining', 'removed', 'completed', 'abandoned')),
  drain_deadline INTEGER,
  last_attempt_at INTEGER,
  last_success_at INTEGER,
  last_error TEXT,
  failing_since INTEGER,
  failing_recorded INTEGER NOT NULL DEFAULT 0 CHECK (failing_recorded IN (0, 1)),
  key_can_read INTEGER CHECK (key_can_read IN (0, 1)),
  retention_readable INTEGER CHECK (retention_readable IN (0, 1)),
  stopped_reason TEXT CONSTRAINT audit_exports_stopped_reason_check
    CHECK (stopped_reason IN ('object_conflict', 'unsupported_format')),
  conditional_checked_at INTEGER,
  lock_verified INTEGER CHECK (lock_verified IN (0, 1)),
  last_heartbeat_hour INTEGER,
  created_by TEXT NOT NULL REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  updated_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  removed_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT audit_exports_version_check CHECK (version > 0) CONSTRAINT int4_version CHECK (version <= 2147483647),
  CONSTRAINT audit_exports_check CHECK ((retention_mode IS NULL) = (retention_days IS NULL)),
  CONSTRAINT audit_exports_check1 CHECK ((credential_envelope IS NOT NULL) = (state IN ('active', 'draining'))),
  CONSTRAINT audit_exports_check2 CHECK ((drain_deadline IS NOT NULL) = (state IN ('draining', 'completed', 'abandoned'))),
  CONSTRAINT audit_exports_check3 CHECK ((removed_at IS NOT NULL) = (state = 'removed'))
) STRICT;
CREATE UNIQUE INDEX audit_exports_live_idx ON audit_exports (organization_id) WHERE state IN ('active', 'draining');
CREATE INDEX audit_exports_draining_idx ON audit_exports (drain_deadline) WHERE state = 'draining';

CREATE TABLE audit_export_plans (
  id TEXT NOT NULL PRIMARY KEY,
  export_id TEXT NOT NULL UNIQUE REFERENCES audit_exports (id),
  export_version INTEGER NOT NULL CONSTRAINT int4_export_version CHECK (export_version BETWEEN -2147483648 AND 2147483647),
  stream_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  kind TEXT NOT NULL CONSTRAINT audit_export_plans_kind_check CHECK (kind IN ('manifest', 'batch', 'heartbeat')),
  object_name TEXT NOT NULL CONSTRAINT audit_export_plans_object_name_check CHECK (length(object_name) BETWEEN 1 AND 1024),
  body BLOB NOT NULL,
  -- PostgreSQL: sha256 ~ '^[0-9a-f]{64}$', md5 ~ '^[0-9a-f]{32}$'.
  sha256 TEXT NOT NULL CONSTRAINT audit_export_plans_sha256_check
    CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
  md5 TEXT NOT NULL CONSTRAINT audit_export_plans_md5_check CHECK (length(md5) = 32 AND md5 NOT GLOB '*[^0-9a-f]*'),
  content_type TEXT NOT NULL,
  content_encoding TEXT CONSTRAINT audit_export_plans_content_encoding_check CHECK (content_encoding = 'gzip'),
  format_version INTEGER NOT NULL CONSTRAINT audit_export_plans_format_version_check CHECK (format_version > 0) CONSTRAINT int4_format_version CHECK (format_version <= 2147483647),
  retention_mode TEXT CONSTRAINT audit_export_plans_retention_mode_check CHECK (retention_mode IN ('compliance', 'governance')),
  retain_until INTEGER,
  first_order INTEGER,
  last_order INTEGER,
  event_count INTEGER CONSTRAINT int4_event_count CHECK (event_count BETWEEN -2147483648 AND 2147483647),
  heartbeat_hour INTEGER,
  planned_at INTEGER NOT NULL,
  CONSTRAINT audit_export_plans_check CHECK ((retention_mode IS NULL) = (retain_until IS NULL)),
  CONSTRAINT audit_export_plans_check1
    CHECK ((kind = 'batch') = (first_order IS NOT NULL AND last_order IS NOT NULL AND event_count IS NOT NULL)),
  CONSTRAINT audit_export_plans_check2 CHECK ((kind = 'heartbeat') = (heartbeat_hour IS NOT NULL))
) STRICT;

-- ---------------------------------------------------------------------------
-- Integrations: Platform Connections, GitHub Apps and Sync Targets
-- ---------------------------------------------------------------------------

CREATE TABLE platform_connections (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  platform TEXT NOT NULL,
  base_identity TEXT NOT NULL,
  name TEXT NOT NULL,
  credential_envelope TEXT CHECK (json_valid(credential_envelope)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER,
  credential_expires_at INTEGER,
  credential_expiry_seen_at INTEGER,
  credential_kind TEXT NOT NULL DEFAULT 'token'
    CONSTRAINT platform_connections_credential_kind_check CHECK (credential_kind IN ('token', 'github-app')),
  github_app_id TEXT,
  github_installation_id INTEGER,
  CONSTRAINT platform_connections_github_app_fk
    FOREIGN KEY (github_app_id, organization_id) REFERENCES github_apps (id, organization_id),
  CONSTRAINT platform_connections_credential_expiry_seen
    CHECK ((credential_expires_at IS NULL) = (credential_expiry_seen_at IS NULL)),
  CONSTRAINT platform_connections_credential_kind_shape CHECK (
    (credential_kind = 'token'
      AND credential_envelope IS NOT NULL
      AND github_app_id IS NULL AND github_installation_id IS NULL)
    OR
    (credential_kind = 'github-app'
      AND platform = 'github-actions'
      AND credential_envelope IS NULL
      AND github_app_id IS NOT NULL AND github_installation_id IS NOT NULL
      AND credential_expires_at IS NULL AND credential_expiry_seen_at IS NULL))
) STRICT;
CREATE INDEX platform_connections_org_idx ON platform_connections (organization_id) WHERE revoked_at IS NULL;
CREATE INDEX platform_connections_github_app_idx ON platform_connections (github_app_id)
  WHERE revoked_at IS NULL AND github_app_id IS NOT NULL;

-- GitHub App connections (ADR-0047).
CREATE TABLE github_apps (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  github_app_id INTEGER NOT NULL,
  slug TEXT NOT NULL,
  client_id TEXT NOT NULL,
  owner_login TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  owner_type TEXT NOT NULL CONSTRAINT github_apps_owner_type_check CHECK (owner_type IN ('organization', 'user')),
  key_envelope TEXT CHECK (json_valid(key_envelope)),
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  removed_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER,
  UNIQUE (id, organization_id),
  CONSTRAINT github_apps_key_until_removed CHECK ((removed_at IS NULL) = (key_envelope IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX github_apps_live_app ON github_apps (github_app_id) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX github_apps_live_org ON github_apps (organization_id) WHERE removed_at IS NULL;

-- GitHub App registrations in flight, and their staged conversion
-- (ADR-0047 amendment D).
CREATE TABLE github_app_registrations (
  state_hash TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  actor_identity_id TEXT NOT NULL REFERENCES identities (id),
  -- PostgreSQL: account_login ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'.
  account_login TEXT NOT NULL CONSTRAINT github_app_registrations_account_login_check CHECK (
    length(account_login) BETWEEN 1 AND 39
    AND account_login GLOB '[A-Za-z0-9]*'
    AND account_login NOT GLOB '*[^A-Za-z0-9-]*'),
  account_type TEXT NOT NULL CONSTRAINT github_app_registrations_account_type_check CHECK (account_type IN ('organization', 'user')),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  -- PostgreSQL: 'ghr_' and the first 26 hex digits of an md5 of random()
  -- and the clock; here 13 random bytes in lowercase hex.
  id TEXT NOT NULL UNIQUE DEFAULT ('ghr_' || lower(hex(randomblob(13)))),
  converted_at INTEGER,
  pending_expires_at INTEGER,
  pending_github_app_id INTEGER CONSTRAINT github_app_registrations_pending_github_app_id_check CHECK (pending_github_app_id > 0),
  pending_slug TEXT,
  pending_client_id TEXT,
  pending_owner_login TEXT,
  pending_owner_id INTEGER CONSTRAINT github_app_registrations_pending_owner_id_check CHECK (pending_owner_id > 0),
  pending_owner_type TEXT CONSTRAINT github_app_registrations_pending_owner_type_check
    CHECK (pending_owner_type IN ('organization', 'user')),
  pending_key_envelope TEXT CHECK (json_valid(pending_key_envelope)),
  ended_at INTEGER,
  end_reason TEXT CONSTRAINT github_app_registrations_end_reason_check
    CHECK (end_reason IN ('attached', 'discarded', 'expired', 'refused')),
  CONSTRAINT github_app_registrations_check CHECK (expires_at > created_at),
  CONSTRAINT github_app_registrations_conversion_complete CHECK (converted_at IS NULL OR (
    consumed_at IS NOT NULL AND pending_expires_at > converted_at AND pending_github_app_id IS NOT NULL
    AND pending_slug IS NOT NULL AND pending_client_id IS NOT NULL AND pending_owner_login IS NOT NULL
    AND pending_owner_id IS NOT NULL AND pending_owner_type IS NOT NULL)),
  CONSTRAINT github_app_registrations_ended_after_conversion
    CHECK ((ended_at IS NULL) = (end_reason IS NULL) AND (ended_at IS NULL OR converted_at IS NOT NULL)),
  CONSTRAINT github_app_registrations_key_while_pending
    CHECK ((pending_key_envelope IS NOT NULL) = (converted_at IS NOT NULL AND ended_at IS NULL))
) STRICT, WITHOUT ROWID;
CREATE INDEX github_app_registrations_expiry ON github_app_registrations (expires_at);
CREATE INDEX github_app_registrations_pending_expiry ON github_app_registrations (pending_expires_at)
  WHERE converted_at IS NOT NULL AND ended_at IS NULL;

-- No REPLACE (see the header): replacing a registration would delete its
-- pending conversion past github_app_registrations_pending_once.
CREATE TRIGGER github_app_registrations_no_replace_insert BEFORE INSERT ON github_app_registrations
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM github_app_registrations WHERE state_hash = NEW.state_hash OR id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'github_app_registrations_no_replace: the row collides with an existing one; github_app_registrations takes no REPLACE or upsert');
END;
CREATE TRIGGER github_app_registrations_no_replace_update BEFORE UPDATE OF state_hash, id ON github_app_registrations
FOR EACH ROW
WHEN EXISTS (SELECT 1 FROM github_app_registrations WHERE state_hash <> OLD.state_hash AND (state_hash = NEW.state_hash OR id = NEW.id))
BEGIN
  SELECT RAISE(ABORT, 'github_app_registrations_no_replace: the row collides with an existing one; github_app_registrations takes no REPLACE or upsert');
END;

-- Pending conversion material is written once (PostgreSQL migration 0050):
-- once converted_at is set, nothing of the registration changes except the
-- deletion of the key when the registration ends (ended_at, end_reason),
-- and an ended registration's end never changes. The key's own rule (it
-- exists only while pending) is github_app_registrations_key_while_pending.
-- JSON is compared as text, so rewriting the key in another spelling is
-- refused too.
CREATE TRIGGER github_app_registrations_pending_once BEFORE UPDATE ON github_app_registrations
FOR EACH ROW
WHEN OLD.converted_at IS NOT NULL AND (
     NEW.id IS NOT OLD.id OR NEW.state_hash IS NOT OLD.state_hash
  OR NEW.organization_id IS NOT OLD.organization_id OR NEW.actor_identity_id IS NOT OLD.actor_identity_id
  OR NEW.consumed_at IS NOT OLD.consumed_at
  OR NEW.converted_at IS NOT OLD.converted_at OR NEW.pending_expires_at IS NOT OLD.pending_expires_at
  OR NEW.pending_github_app_id IS NOT OLD.pending_github_app_id OR NEW.pending_slug IS NOT OLD.pending_slug
  OR NEW.pending_client_id IS NOT OLD.pending_client_id OR NEW.pending_owner_login IS NOT OLD.pending_owner_login
  OR NEW.pending_owner_id IS NOT OLD.pending_owner_id OR NEW.pending_owner_type IS NOT OLD.pending_owner_type
  OR (NEW.pending_key_envelope IS NOT NULL AND NEW.pending_key_envelope IS NOT OLD.pending_key_envelope)
  OR (OLD.ended_at IS NOT NULL AND (NEW.ended_at IS NOT OLD.ended_at OR NEW.end_reason IS NOT OLD.end_reason)))
BEGIN
  SELECT RAISE(ABORT, 'github_app_registrations_pending_once: a GitHub App registration''s pending conversion is written once and never updated');
END;

-- Sync Targets (ADR-0031, ADR-0050).
CREATE TABLE sync_targets (
  id TEXT NOT NULL PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  project_id TEXT NOT NULL REFERENCES projects (id),
  environment_id TEXT NOT NULL REFERENCES environments (id),
  connection_id TEXT NOT NULL REFERENCES platform_connections (id),
  destination TEXT NOT NULL CHECK (json_valid(destination)),
  canonical_destination TEXT NOT NULL,
  mapping TEXT NOT NULL CHECK (json_valid(mapping)),
  remove_orphans INTEGER NOT NULL DEFAULT 0 CHECK (remove_orphans IN (0, 1)),
  redeploy INTEGER NOT NULL DEFAULT 0 CHECK (redeploy IN (0, 1)),
  state TEXT NOT NULL DEFAULT 'active' CONSTRAINT sync_targets_state_check CHECK (state IN ('active', 'paused', 'disabled')),
  disabled_reason TEXT,
  failure_count INTEGER NOT NULL DEFAULT 0 CONSTRAINT int4_failure_count CHECK (failure_count BETWEEN -2147483648 AND 2147483647),
  needs_sync INTEGER NOT NULL DEFAULT 1 CHECK (needs_sync IN (0, 1)),
  next_attempt_at INTEGER,
  last_attempt_at INTEGER,
  last_result TEXT,
  last_repair_at INTEGER,
  generation INTEGER NOT NULL DEFAULT 0,
  lease_expires_at INTEGER,
  created_by TEXT REFERENCES identities (id),
  created_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  revoked_at INTEGER,
  version INTEGER NOT NULL DEFAULT 1 CONSTRAINT int4_version CHECK (version BETWEEN -2147483648 AND 2147483647),
  updated_at INTEGER,
  last_notes TEXT CHECK (json_valid(last_notes)),
  repair_cycle_started_at INTEGER,
  redeploy_owed INTEGER NOT NULL DEFAULT 0,
  redeploy_paid INTEGER NOT NULL DEFAULT 0,
  last_drift_at INTEGER,
  last_drift_count INTEGER CONSTRAINT int4_last_drift_count CHECK (last_drift_count BETWEEN -2147483648 AND 2147483647),
  last_drift_names TEXT CHECK (json_valid(last_drift_names)),
  last_drift_event_id TEXT
) STRICT;
CREATE UNIQUE INDEX sync_targets_destination_claim ON sync_targets (canonical_destination) WHERE revoked_at IS NULL;
CREATE INDEX sync_targets_env_idx ON sync_targets (environment_id) WHERE revoked_at IS NULL;
CREATE INDEX sync_targets_connection_idx ON sync_targets (connection_id) WHERE revoked_at IS NULL;

CREATE TABLE sync_ledger (
  target_id TEXT NOT NULL REFERENCES sync_targets (id),
  dest_name TEXT NOT NULL,
  fingerprint TEXT,
  state TEXT NOT NULL CONSTRAINT sync_ledger_state_check
    CHECK (state IN ('intent-write', 'written', 'failed-write', 'intent-delete', 'tombstone', 'failed-delete')),
  generation INTEGER NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  last_error TEXT,
  repaired_at INTEGER,
  PRIMARY KEY (target_id, dest_name)
) STRICT;

CREATE TABLE sync_runs (
  target_id TEXT NOT NULL REFERENCES sync_targets (id),
  generation INTEGER NOT NULL,
  started_at INTEGER NOT NULL DEFAULT (CAST(round(unixepoch('subsec') * 1000) AS INTEGER) * 1000),
  deadline INTEGER NOT NULL,
  PRIMARY KEY (target_id, generation)
) STRICT;
CREATE INDEX sync_runs_target_deadline ON sync_runs (target_id, deadline);

-- The trigger scanner's position in audit_events.
CREATE TABLE sync_cursor (
  singleton INTEGER NOT NULL PRIMARY KEY DEFAULT 1 CONSTRAINT sync_cursor_singleton_check CHECK (singleton = 1),
  occurred_at INTEGER NOT NULL,
  event_id TEXT NOT NULL DEFAULT '',
  cursor_order INTEGER NOT NULL DEFAULT 0
) STRICT;
