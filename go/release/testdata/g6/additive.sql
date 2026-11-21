-- SPDX-License-Identifier: Apache-2.0
--
-- G6's additive fixture: appended to schema.sql, the change the g6fixture
-- build's step makes (go/server/db/version_g6fixture.go), which a
-- rollback-safe release may make.
CREATE TABLE g6_fixture (
  id INTEGER NOT NULL PRIMARY KEY,
  note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 64)
) STRICT;
ALTER TABLE installation ADD COLUMN g6_note TEXT CHECK (g6_note IS NULL OR length(g6_note) <= 64);
