-- SPDX-License-Identifier: Apache-2.0
--
-- G6's negative fixture: appended to schema.sql, a change a rollback-safe
-- release may not make. A new trigger on an existing table refuses what
-- the previous release's varlatchd writes there, so G6 must fail a release
-- that declares itself rollback-safe and carries it.
CREATE TRIGGER g6_breaking_no_new_identities BEFORE INSERT ON identities
BEGIN
  SELECT RAISE(ABORT, 'identities are closed');
END;
