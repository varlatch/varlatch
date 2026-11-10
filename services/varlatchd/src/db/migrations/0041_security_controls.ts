// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Security Controls and step-up approvals (ADR-0054 Decisions 1 to 3, 10).
 *
 * - security_controls: one row per Organization and control, written on the
 *   first change. A missing row means `off` at version 0. Rows are never
 *   deleted: turning a control off writes `off`, so there is no deletion
 *   path to protect. Organization deletion keeps them with the
 *   Organization's tombstone row (organizations are never deleted, only
 *   marked). `config` is credential-lifetime's pair of lifetimes, 0 <
 *   defaultTtlSeconds <= maxTtlSeconds; the other controls have none.
 *   changed_by is null for the host operator's reset. The table accepts
 *   `enforce`; the API refuses it (CONTROL_MODE_UNAVAILABLE) until the
 *   enforcement step ships.
 * - approval_intents: one person's step-up approval for one exact
 *   operation. It records the requesting credential and its human
 *   identity (an intent the dashboard asked for is bound to the Better
 *   Auth session behind the requesting browser bearer, auth_session_id, so
 *   a silent refresh of the bearer keeps it usable; a CLI intent is bound
 *   to its exact credential), the Organization (null for an account operation such as
 *   passkey.remove), the semantic operation, the stable target ids, HMACs
 *   of the normalized request body and of the query parameters the
 *   operation reads, the target's expected version, and a summary the
 *   server wrote for the approver (never a secret value). Its lifetime is
 *   fixed at creation (2 minutes from the dashboard, 10 from the CLI);
 *   approval never extends it. Consumption is one conditional update in
 *   the operation's transaction. Rows are deleted a day after they end.
 * - approval_intent_challenges: WebAuthn challenges for approving an
 *   intent, bound to it, to the approving identity and to the approving
 *   browser session; single use, and expiring no later than the intent.
 */
export const sql = /* sql */ `
CREATE TABLE security_controls (
  organization_id text NOT NULL REFERENCES organizations(id),
  control text NOT NULL
    CHECK (control IN ('requirement-protection', 'admin-step-up', 'passkey-verification', 'credential-lifetime')),
  mode text NOT NULL CHECK (mode IN ('off', 'report', 'enforce')),
  config jsonb,
  version integer NOT NULL CHECK (version > 0),
  changed_by text REFERENCES identities(id),
  changed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, control),
  CHECK (config IS NULL OR control = 'credential-lifetime'),
  CHECK (config IS NULL OR (
    jsonb_typeof(config) = 'object'
    AND jsonb_typeof(config -> 'defaultTtlSeconds') = 'number'
    AND jsonb_typeof(config -> 'maxTtlSeconds') = 'number'
    AND (config ->> 'defaultTtlSeconds')::numeric > 0
    AND (config ->> 'defaultTtlSeconds')::numeric <= (config ->> 'maxTtlSeconds')::numeric
  ))
);

CREATE TABLE approval_intents (
  id text PRIMARY KEY,
  credential_id text NOT NULL REFERENCES credentials(id),
  identity_id text NOT NULL REFERENCES identities(id),
  auth_session_id text CHECK (auth_session_id IS NULL OR char_length(auth_session_id) BETWEEN 1 AND 200),
  organization_id text REFERENCES organizations(id),
  operation text NOT NULL CHECK (operation IN ('security_control.change', 'passkey.remove')),
  target jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object'),
  body_hash text NOT NULL,
  query_hash text NOT NULL,
  expected_version integer,
  summary jsonb NOT NULL,
  origin text NOT NULL CHECK (origin IN ('dashboard', 'cli')),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  approved_with_passkey_id text,
  approval_user_verified boolean,
  consumed_at timestamptz,
  closed_at timestamptz,
  close_reason text CHECK (close_reason IN ('cancelled', 'reset', 'organization-deleted')),
  poll_interval integer NOT NULL CHECK (poll_interval > 0),
  last_polled_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((origin = 'dashboard') = (auth_session_id IS NOT NULL)),
  CHECK ((approved_at IS NULL) = (approved_with_passkey_id IS NULL)),
  CHECK ((approved_at IS NULL) = (approval_user_verified IS NULL)),
  CHECK (consumed_at IS NULL OR approved_at IS NOT NULL),
  CHECK ((closed_at IS NULL) = (close_reason IS NULL)),
  CHECK (consumed_at IS NULL OR closed_at IS NULL),
  CHECK (operation <> 'passkey.remove' OR organization_id IS NULL),
  CHECK (operation <> 'security_control.change' OR organization_id IS NOT NULL)
);
CREATE INDEX approval_intents_open_by_credential ON approval_intents (credential_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_open_by_organization ON approval_intents (organization_id)
  WHERE consumed_at IS NULL AND closed_at IS NULL;
CREATE INDEX approval_intents_identity_created ON approval_intents (identity_id, created_at);
CREATE INDEX approval_intents_expires ON approval_intents (expires_at);

CREATE TABLE approval_intent_challenges (
  id text PRIMARY KEY,
  intent_id text NOT NULL REFERENCES approval_intents(id) ON DELETE CASCADE,
  identity_id text NOT NULL REFERENCES identities(id),
  auth_session_id text NOT NULL CHECK (char_length(auth_session_id) BETWEEN 1 AND 200),
  challenge text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > created_at)
);
CREATE INDEX approval_intent_challenges_identity ON approval_intent_challenges (identity_id, created_at);
CREATE INDEX approval_intent_challenges_intent ON approval_intent_challenges (intent_id);
`;
