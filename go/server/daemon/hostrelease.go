// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
)

// The release commands `varlatch upgrade` runs (ADR-0059 Decision 8;
// internal docs/design/go-step6.md, slice 6.6b, decisions 2 and 6):
//
//	varlatchd admin status [--json]
//	    the running varlatchd's release, schema and readiness, through its
//	    control socket only: a varlatchd that does not answer is not
//	    running (exit 1), and nothing is opened or locked to find out
//	varlatchd admin release-check record --repo <owner/name>
//	    (--version <version> [--published-at <time>] | --failed <reason>)
//	    the host's last look for a newer release (ADR-0049), which
//	    GET /v1/installation/release reads; written in the data directory,
//	    beside a running varlatchd or not, never through it
//	varlatchd admin release-check record-target --version <version>
//	    (--schema-version <n> --compatible-from <n> --rollback-safe <bool>
//	    [--previous <version> --previous-schema <n>]
//	    --ends-rollback-window <bool> --image <reference> | --failed <reason>)
//	    what that release's verified release.json and varlatchd-image.txt
//	    declare, or why they could not be verified (ADR-0065 Decision 3):
//	    release-target.json, beside the release check, written the same way

const (
	statusUsage       = "Usage: varlatchd admin status [--json] [--config <file>]"
	releaseCheckUsage = "Usage: varlatchd admin release-check record --repo <owner/name> (--version <version> [--published-at <time>] | --failed <unreachable|rate-limited|not-found|invalid-answer>) [--config <file>]\n" +
		"       varlatchd admin release-check record-target --version <version> (--schema-version <n> --compatible-from <n> --rollback-safe <true|false> [--previous <version> --previous-schema <n>] --ends-rollback-window <true|false> --image <reference> | --failed <unreachable|rate-limited|not-found|not-verified|invalid-release>) [--config <file>]"
)

func statusArgs(rest []string) (asJSON bool, msg string) {
	for _, a := range rest {
		if a != "--json" || asJSON {
			return false, statusUsage
		}
		asJSON = true
	}
	return asJSON, ""
}

// statusJSON is what admin status answers.
type statusJSON struct {
	Version       string `json:"version"`
	SchemaVersion int64  `json:"schemaVersion"`
	// Serving is whether the HTTP listener serves; Ready the /readyz
	// checks, all of them true for a varlatchd that serves its database.
	Serving bool `json:"serving"`
	Ready   struct {
		Schema       bool `json:"schema"`
		RootKEK      bool `json:"rootKek"`
		Installation bool `json:"installation"`
	} `json:"ready"`
	// Installation is its installation's id, once it is ready.
	Installation string `json:"installation,omitempty"`
	// UpgradeHold is why an upgrade holds it (server/maintenance): its
	// listeners answer 503. "" when none does.
	UpgradeHold string `json:"upgradeHold,omitempty"`
	// Held is whether a restore's hold stands (backup.Hold).
	Held bool `json:"held,omitempty"`
}

// statusOnline is `admin status` in this process: the running varlatchd
// answers it, or nothing does.
func statusOnline(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	const what = "varlatchd admin status"
	owner, _, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", what, err)
		return ExitConfig
	}
	uc, status := daemonConn(cfg, owner, what, stderr)
	if status != ExitOK {
		return status
	}
	if uc == nil {
		fmt.Fprintf(stderr, "%s: no varlatchd answers on %s's control socket: it is not running\n", what, cfg.DataDir)
		return ExitFailure
	}
	return viaSocket(uc, what, append([]string{"status"}, rest...), stdout, stderr)
}

// runStatus answers `admin status` in the running varlatchd.
func runStatus(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	asJSON, msg := statusArgs(rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	if env.serving == nil {
		fmt.Fprintln(stderr, "varlatchd admin status: varlatchd is not running")
		return ExitFailure
	}
	var st statusJSON
	st.Version, st.SchemaVersion, st.Serving = buildinfo.Version, db.SchemaVersion, env.serving.Load()
	if env.ready != nil {
		st.Ready.Schema, st.Ready.RootKEK, st.Ready.Installation = env.ready(ctx)
	}
	if st.Ready.Installation && env.store != nil {
		if id, err := (&backend{store: env.store, rootKEK: env.rootKEK}).InstallationID(ctx); err == nil {
			st.Installation = id
		}
	}
	if env.admission != nil {
		st.UpgradeHold = env.admission.UpgradeHold()
	}
	st.Held = env.admission != nil && env.admission.Held()
	if asJSON {
		return printJSON(stdout, stderr, "varlatchd admin status", st)
	}
	fmt.Fprintf(stdout, "varlatchd %s (schema version %d) is running; serving: %v; schema ready: %v, Root KEK: %v, installation: %v.\n",
		st.Version, st.SchemaVersion, st.Serving, st.Ready.Schema, st.Ready.RootKEK, st.Ready.Installation)
	if st.Held {
		fmt.Fprintln(stdout, "It was restored from an archive and is held: varlatchd admin restore resume ends that.")
	}
	return ExitOK
}

// releaseCheckArgs reads `admin release-check record`'s and `record-target`'s
// arguments: an outcome, or a target.
func releaseCheckArgs(rest []string) (any, string) {
	if len(rest) > 0 && rest[0] == "record-target" {
		t, msg := releaseTargetArgs(rest[1:])
		if msg != "" {
			return nil, msg
		}
		return t, ""
	}
	o, msg := releaseOutcomeArgs(rest)
	if msg != "" {
		return nil, msg
	}
	return o, ""
}

// pairs reads --name value pairs, each name one of names, at most once.
func pairs(rest []string, names ...string) (map[string]string, bool) {
	v := map[string]string{}
	for i := 0; i < len(rest); i += 2 {
		k := rest[i]
		if !slices.Contains(names, k) || i+1 >= len(rest) || rest[i+1] == "" {
			return nil, false
		}
		if _, dup := v[k]; dup {
			return nil, false
		}
		v[k] = rest[i+1]
	}
	return v, true
}

// releaseTargetArgs reads `admin release-check record-target`'s arguments.
func releaseTargetArgs(rest []string) (release.Target, string) {
	v, ok := pairs(rest, "--version", "--schema-version", "--compatible-from", "--rollback-safe", "--previous", "--previous-schema", "--ends-rollback-window", "--image", "--failed")
	if !ok || v["--version"] == "" {
		return release.Target{}, releaseCheckUsage
	}
	t := release.Target{Version: v["--version"]}
	if f, failed := v["--failed"]; failed {
		if len(v) != 2 {
			return release.Target{}, releaseCheckUsage
		}
		t.Failed = &f
		return t, ""
	}
	number := func(k string) (int64, bool) {
		n, err := strconv.ParseInt(v[k], 10, 64)
		return n, err == nil
	}
	boolean := func(k string) (bool, bool) {
		switch v[k] {
		case "true":
			return true, true
		case "false":
			return false, true
		}
		return false, false
	}
	var vt release.VerifiedTarget
	var ok1, ok2, ok3, ok4 bool
	vt.SchemaVersion, ok1 = number("--schema-version")
	vt.CompatibleFrom, ok2 = number("--compatible-from")
	vt.RollbackSafe, ok3 = boolean("--rollback-safe")
	vt.EndsRollbackWindow, ok4 = boolean("--ends-rollback-window")
	vt.Image = v["--image"]
	if !ok1 || !ok2 || !ok3 || !ok4 || vt.Image == "" {
		return release.Target{}, releaseCheckUsage
	}
	_, hasPrevious := v["--previous"]
	_, hasSchema := v["--previous-schema"]
	if hasPrevious != hasSchema {
		return release.Target{}, releaseCheckUsage
	}
	if hasPrevious {
		n, ok := number("--previous-schema")
		if !ok {
			return release.Target{}, releaseCheckUsage
		}
		vt.Previous = &release.Previous{Version: v["--previous"], SchemaVersion: n}
	}
	t.Verified = &vt
	return t, ""
}

// releaseOutcomeArgs reads `admin release-check record`'s arguments.
func releaseOutcomeArgs(rest []string) (release.CheckOutcome, string) {
	if len(rest) == 0 || rest[0] != "record" {
		return release.CheckOutcome{}, releaseCheckUsage
	}
	v := map[string]string{}
	for i := 1; i < len(rest); i += 2 {
		k := rest[i]
		if k != "--repo" && k != "--version" && k != "--published-at" && k != "--failed" || i+1 >= len(rest) || rest[i+1] == "" {
			return release.CheckOutcome{}, releaseCheckUsage
		}
		if _, dup := v[k]; dup {
			return release.CheckOutcome{}, releaseCheckUsage
		}
		v[k] = rest[i+1]
	}
	o := release.CheckOutcome{Repo: v["--repo"], Failed: v["--failed"], ReleaseSet: true}
	switch {
	case o.Repo == "", (v["--version"] == "") == (v["--failed"] == ""), v["--failed"] != "" && v["--published-at"] != "":
		return release.CheckOutcome{}, releaseCheckUsage
	case v["--version"] != "":
		o.Latest = &release.Latest{Version: v["--version"]}
		if p, ok := v["--published-at"]; ok {
			o.Latest.PublishedAt = &p
		}
	}
	return o, ""
}

// runReleaseCheck is `admin release-check record`: a file in the data
// directory, written whole, readable by the varlatchd that serves it.
func runReleaseCheck(cfg *config.Config, rest []string, stdout, stderr io.Writer) int {
	what := "varlatchd admin release-check " + rest[0]
	parsed, _ := releaseCheckArgs(rest)
	if _, _, err := checkClientDir(cfg.DataDir, os.Getuid()); err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was written\n", what, err)
		return ExitConfig
	}
	var record any
	var err error
	switch p := parsed.(type) {
	case release.Target:
		record, err = release.RecordReleaseTarget(cfg.DataDir, p, time.Now())
	case release.CheckOutcome:
		record, err = release.RecordReleaseCheck(cfg.DataDir, p, time.Now())
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was written\n", what, err)
		return ExitFailure
	}
	b, _ := json.Marshal(record)
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}
