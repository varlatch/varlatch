// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
	"github.com/varlatch/varlatch/go/server/config"
)

// The host helper's records (ADR-0065 Decisions 1 and 7), written as the
// data directory's owner, beside a running varlatchd or not, never through
// it, as `admin release-check record` writes the release check:
//
//	varlatchd admin upgrade-request record --request <id> --phase <phase>
//	    [--version <version>] [--reason <class>] [--journal <id>]
//	    what the helper did with a request it took (upgrade-request/
//	    status.json), which the request's route and the audit events read
//	varlatchd admin upgrade-request heartbeat --helper-version <version>
//	    --enabled <true|false>
//	    that the helper is there and whether the host accepts requests
//	    (upgrade-request/helper.json), at each release check

const upgradeRequestUsage = "Usage: varlatchd admin upgrade-request record --request <id> --phase <taken|verifying|backing-up|restarting|checking|done|refused|failed|undone> [--version <version>] [--reason <class>] [--journal <id>] [--config <file>]\n" +
	"       varlatchd admin upgrade-request heartbeat --helper-version <version> --enabled <true|false> [--config <file>]"

// upgradeRequestArgs reads the command's arguments: the record it writes.
func upgradeRequestArgs(rest []string) (any, string) {
	if len(rest) == 0 {
		return nil, upgradeRequestUsage
	}
	now := time.Now().UTC().Format(upgraderequest.TimeLayout)
	switch rest[0] {
	case "record":
		v, ok := pairs(rest[1:], "--request", "--phase", "--version", "--reason", "--journal")
		if !ok || v["--request"] == "" || v["--phase"] == "" {
			return nil, upgradeRequestUsage
		}
		s := upgraderequest.Status{Format: upgraderequest.Format, RequestID: v["--request"], Version: v["--version"], Phase: upgraderequest.Phase(v["--phase"]),
			Reason: v["--reason"], JournalID: v["--journal"], UpdatedAt: now}
		if err := s.Check(); err != nil {
			return nil, upgradeRequestUsage + "\n" + err.Error()
		}
		return s, ""
	case "heartbeat":
		v, ok := pairs(rest[1:], "--helper-version", "--enabled")
		if !ok || len(v) != 2 || v["--enabled"] != "true" && v["--enabled"] != "false" || !release.ValidVersion(v["--helper-version"]) {
			return nil, upgradeRequestUsage
		}
		return upgraderequest.Helper{Format: upgraderequest.Format, Version: v["--helper-version"], Enabled: v["--enabled"] == "true", HeartbeatAt: now}, ""
	}
	return nil, upgradeRequestUsage
}

// runUpgradeRequest is `admin upgrade-request`: a file in the data
// directory's upgrade-request directory, written whole.
func runUpgradeRequest(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	what := "varlatchd admin upgrade-request " + rest[0]
	record, _ := upgradeRequestArgs(rest)
	if _, _, err := checkClientDir(cfg.DataDir, os.Getuid()); err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was written\n", what, err)
		return ExitConfig
	}
	var err error
	switch r := record.(type) {
	case upgraderequest.Status:
		err = upgraderequest.WriteStatus(cfg.DataDir, r)
	case upgraderequest.Helper:
		err = upgraderequest.WriteHelper(cfg.DataDir, r)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was written\n", what, err)
		return ExitFailure
	}
	b, _ := json.Marshal(record)
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}
