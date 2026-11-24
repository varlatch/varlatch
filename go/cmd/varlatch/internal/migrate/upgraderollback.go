// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"fmt"
	"time"
)

// BeforeUpgrade is whether an upgrade begun at began, to the release to,
// may be rolled back (`varlatch upgrade --rollback`) on the Go installation
// whose data directory is dir: never migrated, or with a migration open or
// finished that switched before the upgrade began. One under way holds the
// installation, and one that switched later made it what neither the
// release nor the snapshot the rollback returns to knows. The answer is
// what the rollback leaves of the migration's rollback window, "" with
// none open when the upgrade began or now.
func BeforeUpgrade(dir, to string, began, now time.Time) (string, error) {
	j, err := readJournal(dir)
	switch {
	case err != nil:
		return "", fmt.Errorf("the migration journal: %w", err)
	case j == nil:
		return "", nil
	case j.Phase != Open && j.Phase != Finished:
		return "", fmt.Errorf("the migration %s into %s is in phase %s: finish or abort it first (varlatch migrate --status)", j.ID, dir, j.Phase)
	}
	at, ok := switchedAt(j)
	if !ok {
		return "", fmt.Errorf("the migration journal in %s does not say when the migration switched", dir)
	}
	if !at.Before(began) {
		return "", fmt.Errorf("this installation was migrated (%s) after the upgrade to %s began (%s): the release and the snapshot a rollback returns to are from before the migration", at.UTC().Format(time.RFC3339), to, began.UTC().Format(time.RFC3339))
	}
	ends := at.Add(RollbackWindow)
	switch {
	case j.Phase == Finished || now.After(ends):
		return "", nil
	case j.WindowEnded != nil:
		return fmt.Sprintf("its rollback window was ended by the upgrade to %s, and stays ended: varlatch migrate --rollback still refuses", j.WindowEnded.Release), nil
	}
	return fmt.Sprintf("its rollback window stays open until %s: a varlatch migrate --rollback until then takes back what is served after this", ends.UTC().Format(time.RFC3339)), nil
}
