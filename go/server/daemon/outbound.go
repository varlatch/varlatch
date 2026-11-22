// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// `varlatchd admin outbound check [--allow <value>] [--org <org>] [--json]`
// (ADR-0057 Decision 10; cli.ts): every live destination an Organization
// configured, with the outbound policy's verdict, and the allow list value
// that would open the refused ones. Read-only: it reads the database
// read-only, in this process, with or without a daemon, and makes DNS
// lookups only, never a request. --allow checks a candidate allow list
// instead of outbound_allow. Exit 0 when everything is allowed, 1 when
// something is refused, 2 when nothing is refused but something did not
// resolve.

const outboundUsage = "Usage: varlatchd admin outbound check [--allow <value>] [--org <org>] [--json]"

type outboundOpts struct {
	allow  *string
	org    string
	asJSON bool
}

func outboundArgs(rest []string) (outboundOpts, string) {
	var o outboundOpts
	if len(rest) == 0 || rest[0] != "check" {
		return o, outboundUsage
	}
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case "--json":
			o.asJSON = true
		case "--allow", "--org":
			if i+1 >= len(rest) {
				return o, outboundUsage
			}
			if rest[i] == "--allow" {
				v := rest[i+1]
				o.allow = &v
			} else {
				o.org = rest[i+1]
			}
			i++
		default:
			return o, outboundUsage
		}
	}
	return o, ""
}

// outboundSetting names the allow list as a Go installation has it:
// outbound_allow in its configuration file (varlatchd reads no
// VARLATCH_OUTBOUND_ALLOW), and how to restart varlatchd after changing
// it, on a host install or in the image.
func outboundSetting(path string) outbound.Setting {
	restart := "sudo systemctl restart varlatchd"
	if os.Getenv(keyenv.ImageMarker) != "" {
		restart = "restart its container"
	}
	return outbound.Setting{Name: "outbound_allow (" + path + ")", Suggest: func(v string) []string {
		return []string{"Suggested: set this line in " + path + ", then restart varlatchd (" + restart + "):", "  outbound_allow = " + v}
	}}
}

func runOutboundCheck(cfg *config.Config, path string, rest []string, stdout, stderr io.Writer) int {
	o, _ := outboundArgs(rest)
	spec := cfg.OutboundAllow
	if o.allow != nil {
		spec = *o.allow
	}
	entries, err := outbound.ParseAllow(spec)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return ExitFailure
	}
	policy := outbound.New(entries, outbound.Options{})
	conn, err := openReadOnly(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin outbound check: %v\n", err)
		return ExitFailure
	}
	var db query.DBTX // none yet: nothing is configured
	if conn != nil {
		defer conn.Close()
		db = conn
	}
	// The GitHub Sync Targets' connections too (RunAdminCheck): GitHub's
	// API is public, but a policy or a resolver can still refuse it.
	report, err := policy.RunAdminCheck(context.Background(), db, o.org, time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin outbound check: %v\n", err)
		return ExitFailure
	}
	if o.asJSON {
		b, err := json.Marshal(report)
		if err != nil {
			fmt.Fprintf(stderr, "varlatchd admin outbound check: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintln(stdout, string(b))
	} else {
		for _, l := range report.LinesFor(outboundSetting(path)) {
			fmt.Fprintln(stdout, l)
		}
	}
	return report.ExitCode
}
