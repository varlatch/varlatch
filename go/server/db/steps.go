// SPDX-License-Identifier: AGPL-3.0-or-later

package db

// releaseSteps are the schema upgrades of the released schema versions, in
// order: releaseSteps[i] upgrades version i+1 to i+2 (version.go). The
// g6fixture build adds its synthetic step after them.
var releaseSteps = []Step{
	// 2: the certificate issuance count (step 6 decision 16). A new table
	// only, so rollback-safe: schema 1's varlatchd may open the database
	// and never reads the table.
	{To: 2, CompatibleFrom: 1, SQL: `
CREATE TABLE certificate_issuances (
  id INTEGER NOT NULL PRIMARY KEY,
  name TEXT NOT NULL CONSTRAINT certificate_issuances_name_check CHECK (length(name) BETWEEN 1 AND 253 AND name = lower(name)),
  started_at INTEGER NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'started' CONSTRAINT certificate_issuances_outcome_check CHECK (outcome IN ('started', 'issued', 'refused')),
  ended_at INTEGER
) STRICT;
CREATE INDEX certificate_issuances_name_started ON certificate_issuances (name, started_at);
`},
}
