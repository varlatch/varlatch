// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * A passkey's signature counter only moves forward, whoever writes it.
 *
 * Each sign-in reads the stored counter, verifies the assertion against it
 * (a counter that does not increase is refused as a cloned or replayed
 * authenticator), then writes the assertion's counter. Better Auth's
 * passkey sign-in writes it unconditionally, so two concurrent sign-ins
 * with one passkey could both verify against the same stored value and the
 * later write could lower the counter (counter 2 committed, then 1
 * overwriting it), and a lowered counter accepts assertions it should
 * refuse.
 *
 * The trigger applies the verifier's own rule (@simplewebauthn/server) at
 * the write, against the row as committed: when the stored or the new
 * counter is above zero, the new one must be greater than the stored one.
 * Counter 0 written over counter 0 is allowed: authenticators without a
 * counter (most synced passkeys) always report 0. A refused write raises
 * check_violation; Better Auth's sign-in answers it as a failed sign-in
 * before it creates a session. An UPDATE that does not set the counter
 * (renaming a passkey) is not checked.
 */
export const sql = /* sql */ `
CREATE FUNCTION passkey_counter_forward() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public AS $$
BEGIN
  IF (NEW.counter > 0 OR OLD.counter > 0) AND NEW.counter <= OLD.counter THEN
    RAISE EXCEPTION 'passkey % signature counter % is not greater than the stored %', OLD.id, NEW.counter, OLD.counter
      USING ERRCODE = 'check_violation', CONSTRAINT = 'passkey_counter_forward';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER passkey_counter_forward BEFORE UPDATE OF counter ON passkey
FOR EACH ROW EXECUTE FUNCTION passkey_counter_forward();
`;
