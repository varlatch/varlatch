// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A browser credential ends with the Better Auth session it was minted from.
 *
 * The dashboard's 15-minute `browser` bearer (POST /auth/varlatch-token)
 * carries the id of the session it came from (credentials.auth_session_id,
 * migration 25). Signing out deletes the session row, but the bearer used
 * to stay valid until it expired. This trigger revokes, in the deleting
 * statement's own transaction, every live `browser` credential of every
 * session row a statement deletes, whoever deletes it: Better Auth's
 * sign-out, its revoke-session(s) and revoke-other-sessions endpoints, its
 * removal of an expired session, a cascade from a deleted Better Auth user,
 * the public-URL change, or an operator's SQL. A Better Auth delete hook
 * would run after the commit, in the daemon process, and only for Better
 * Auth's own deletes.
 *
 * Only `browser` credentials. A `cli` credential from the browser handoff
 * also carries the session id, as a link to the sign-in's evidence (ADR-0054
 * Decision 6), but it is meant to outlive the browser session (ADR-0024:
 * 12 hours by default, up to 24); `varlatch logout` and the dashboard's
 * Active sessions revoke it.
 *
 * Lock order (domain/approvals.ts): the deleted session rows (step 6) are
 * held by the DELETE; the credentials (step 7) are locked in id order,
 * then revoked; the audit events (step 8) come last. A statement-level
 * trigger, so one bulk delete locks all its credentials before its first
 * audit insert.
 *
 * Each revocation is a credential.revoked event, as every other revocation
 * path writes: the credential, its person, its kind, and the reason
 * `session-ended`. No actor: the trigger cannot tell who ended the session.
 * Event ids have the shape of db/ids.ts (`evt_` and 128 random bits in
 * lowercase base32).
 */
export const sql = /* sql */ `
CREATE FUNCTION new_audit_event_id() RETURNS text LANGUAGE plpgsql VOLATILE
SET search_path = pg_catalog AS $$
DECLARE
  bytes bytea := substring(sha256(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())) FROM 1 FOR 16);
  alphabet constant text := 'abcdefghijklmnopqrstuvwxyz234567';
  encoded text := '';
  acc bigint := 0;
  bits integer := 0;
BEGIN
  FOR i IN 0..15 LOOP
    acc := (acc << 8) | get_byte(bytes, i);
    bits := bits + 8;
    WHILE bits >= 5 LOOP
      encoded := encoded || substr(alphabet, ((acc >> (bits - 5)) & 31)::integer + 1, 1);
      bits := bits - 5;
    END LOOP;
    acc := acc & ((1::bigint << bits) - 1);
  END LOOP;
  IF bits > 0 THEN
    encoded := encoded || substr(alphabet, ((acc << (5 - bits)) & 31)::integer + 1, 1);
  END IF;
  RETURN 'evt_' || encoded;
END $$;

CREATE FUNCTION revoke_browser_credentials_of_ended_sessions() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM 1 FROM public.credentials c
   WHERE c.auth_session_id IN (SELECT e.id FROM ended e)
     AND c.kind = 'browser' AND c.revoked_at IS NULL
     AND (c.expires_at IS NULL OR c.expires_at > now())
   ORDER BY c.id
   FOR UPDATE OF c;
  WITH revoked AS (
    UPDATE public.credentials c SET revoked_at = now()
     WHERE c.auth_session_id IN (SELECT e.id FROM ended e)
       AND c.kind = 'browser' AND c.revoked_at IS NULL
       AND (c.expires_at IS NULL OR c.expires_at > now())
    RETURNING c.id, c.identity_id
  )
  INSERT INTO public.audit_events (id, schema_version, event_type, decision, credential_id, resource, metadata)
  SELECT public.new_audit_event_id(), 1, 'credential.revoked', 'info', r.id,
         jsonb_build_object('identityId', r.identity_id),
         jsonb_build_object('kind', 'browser', 'reason', 'session-ended')
    FROM revoked r
   ORDER BY r.id;
  RETURN NULL;
END $$;

CREATE TRIGGER session_end_revokes_browser_credentials AFTER DELETE ON "session"
REFERENCING OLD TABLE AS ended
FOR EACH STATEMENT EXECUTE FUNCTION revoke_browser_credentials_of_ended_sessions();
`;
