// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Passkey provenance and sign-in evidence (ADR-0054 Decisions 4 and 6).
 * Recorded whatever the Security Controls say; nothing here gates access.
 *
 * - passkey_provenance: one row per passkey, keyed by Better Auth's passkey
 *   id (a side table: Better Auth's own tables keep the shape its adapter
 *   reads and returns). `trusted` keys may approve; `unconfirmed` ones were
 *   added by a signed-in session and become trusted through a confirmation
 *   ceremony with a trusted key. A passkey without a row counts as
 *   unconfirmed, so a failure to record never trusts a key. Every passkey
 *   that exists now is trusted (`existing-at-upgrade`), except a later
 *   duplicate of a credential id (below), which is unconfirmed.
 * - passkey."credentialID" becomes unique, so a credential id names one
 *   passkey and the evidence a sign-in records is unambiguous; two
 *   concurrent registrations of one credential id cannot both be stored.
 *   Duplicates registered before this migration are not deleted: the
 *   oldest of each credential id (by "createdAt", then id) stays in the
 *   unique index, and the later ones are left out of it by id (a partial
 *   index) and recorded as unconfirmed. Every new row is unique against the
 *   indexed ones.
 * - auth_session_evidence: what the ceremony that created a Better Auth
 *   session proved: whether the authenticator verified the user, and which
 *   passkey asserted (its provenance is read when the evidence is used, so a
 *   key confirmed later counts). Keyed by the session id and written only
 *   for the session that ceremony created. No foreign key to "session": a
 *   CLI credential from the browser handoff keeps its session's evidence
 *   after that session ends. A row is swept once its session has ended and
 *   no live credential links that session.
 *   Sessions from before this migration have none: unverified.
 * - credentials: a `cli` credential from device sign-in carries the
 *   approval's evidence itself (evidence_user_verified,
 *   evidence_passkey_id). Browser credentials and, from now on, the CLI
 *   handoff's carry auth_session_id instead and read the session's.
 * - device_sign_ins: the approval's evidence, kept until collection copies
 *   it onto the credential.
 * - passkey_confirmation_challenges: confirmation ceremonies, each bound to
 *   the person, their dashboard session and the unconfirmed key it
 *   confirms; single use, short-lived, consumed on use.
 */
export const sql = /* sql */ `
CREATE TABLE passkey_provenance (
  passkey_id text PRIMARY KEY REFERENCES passkey(id) ON DELETE CASCADE,
  trust text NOT NULL CHECK (trust IN ('trusted', 'unconfirmed')),
  trusted_via text CHECK (trusted_via IN ('existing-at-upgrade', 'setup-grant', 'confirmed')),
  trusted_at timestamptz,
  setup_grant_kind text CHECK (setup_grant_kind IN ('bootstrap', 'recover', 'invite', 'reenroll')),
  confirmed_by_passkey_id text,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((trust = 'trusted') = (trusted_via IS NOT NULL)),
  CHECK ((trusted_via IS NULL) = (trusted_at IS NULL)),
  CHECK ((trusted_via IS NOT DISTINCT FROM 'setup-grant') = (setup_grant_kind IS NOT NULL)),
  CHECK ((trusted_via IS NOT DISTINCT FROM 'confirmed') = (confirmed_by_passkey_id IS NOT NULL)),
  CHECK (confirmed_by_passkey_id IS NULL OR confirmed_by_passkey_id <> passkey_id)
);

INSERT INTO passkey_provenance (passkey_id, trust, trusted_via, trusted_at)
  SELECT id,
         CASE WHEN n = 1 THEN 'trusted' ELSE 'unconfirmed' END,
         CASE WHEN n = 1 THEN 'existing-at-upgrade' END,
         CASE WHEN n = 1 THEN now() END
  FROM (SELECT id, row_number() OVER (PARTITION BY "credentialID" ORDER BY "createdAt" NULLS FIRST, id) AS n FROM passkey) ranked;

DO $$
DECLARE
  later_duplicates text[];
BEGIN
  SELECT coalesce(array_agg(id ORDER BY id), '{}') INTO later_duplicates
  FROM (SELECT id, row_number() OVER (PARTITION BY "credentialID" ORDER BY "createdAt" NULLS FIRST, id) AS n FROM passkey) ranked
  WHERE n > 1;
  IF cardinality(later_duplicates) = 0 THEN
    CREATE UNIQUE INDEX passkey_credential_id_unique ON passkey ("credentialID");
  ELSE
    RAISE NOTICE 'passkeys sharing a credential id with an older one, left out of the unique index and unconfirmed: %', later_duplicates;
    EXECUTE format(
      'CREATE UNIQUE INDEX passkey_credential_id_unique ON passkey ("credentialID") WHERE id <> ALL (%L::text[])',
      later_duplicates
    );
  END IF;
END $$;

CREATE TABLE auth_session_evidence (
  session_id text PRIMARY KEY CHECK (char_length(session_id) BETWEEN 1 AND 200),
  ceremony text NOT NULL CHECK (ceremony IN ('sign-in', 'enrollment')),
  user_verified boolean NOT NULL,
  passkey_id text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);

-- 0025's column check, which PostgreSQL named credentials_check (it reads two columns).
ALTER TABLE credentials DROP CONSTRAINT credentials_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_auth_session_id_check
  CHECK (auth_session_id IS NULL OR (kind IN ('browser', 'cli') AND char_length(auth_session_id) BETWEEN 1 AND 200));
-- The evidence sweep looks credentials up by session.
CREATE INDEX credentials_auth_session_id ON credentials (auth_session_id) WHERE auth_session_id IS NOT NULL;
ALTER TABLE credentials ADD COLUMN evidence_user_verified boolean;
ALTER TABLE credentials ADD COLUMN evidence_passkey_id text;
ALTER TABLE credentials ADD CONSTRAINT credentials_evidence_check CHECK (
  (evidence_user_verified IS NULL) = (evidence_passkey_id IS NULL)
  AND (evidence_passkey_id IS NULL OR (kind = 'cli' AND auth_session_id IS NULL))
);

ALTER TABLE device_sign_ins ADD COLUMN approval_user_verified boolean;
ALTER TABLE device_sign_ins ADD COLUMN approval_passkey_id text;
ALTER TABLE device_sign_ins ADD CONSTRAINT device_sign_ins_approval_evidence_check
  CHECK ((approval_user_verified IS NULL) = (approval_passkey_id IS NULL));

CREATE TABLE passkey_confirmation_challenges (
  id text PRIMARY KEY,
  identity_id text NOT NULL REFERENCES identities(id),
  auth_session_id text NOT NULL,
  target_passkey_id text NOT NULL REFERENCES passkey(id) ON DELETE CASCADE,
  challenge text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX passkey_confirmation_challenges_identity ON passkey_confirmation_challenges (identity_id, created_at);
`;
