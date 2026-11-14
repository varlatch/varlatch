// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The conformance harness's probes (scripts/conformance README, "The
// target contract"): fixed, named reads of server state that /v1 does not
// show, which the go-binary target runs as `varlatchd admin
// conformance-probe <name> [args] --config <file>`. Built only with the
// conformance build tag: a release has none of this.
//
//	expire-pending-device-sign-ins   every pending device sign-in expires now
//	device-sign-in-addresses <name>  [{"requesterIp": ...}] of the sign-ins requested under <name>
//	proxy-addresses                  [] (nothing stands in front of varlatchd)

var probeName = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func init() {
	conformanceProbe = func(args []string, stdout, stderr io.Writer) int {
		path := config.DefaultPath
		var rest []string
		for i := 0; i < len(args); i++ {
			if args[i] == "--config" && i+1 < len(args) {
				path = args[i+1]
				i++
				continue
			}
			rest = append(rest, args[i])
		}
		fail := func(err error) int {
			fmt.Fprintf(stderr, "varlatchd admin conformance-probe: %v\n", err)
			return ExitFailure
		}
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "varlatchd admin conformance-probe: no probe")
			return 64
		}
		if rest[0] == "proxy-addresses" {
			fmt.Fprintln(stdout, "[]")
			return ExitOK
		}
		cfg, err := config.Load(path)
		if err != nil {
			return fail(err)
		}
		ctx := context.Background()
		store, err := storage.Open(ctx, storage.Options{Path: cfg.DatabasePath()})
		if err != nil {
			return fail(err)
		}
		defer store.Close()
		var out any
		switch rest[0] {
		case "expire-pending-device-sign-ins":
			err = store.Write(ctx, func(tx *storage.Tx) error {
				return query.New(tx).ExpirePendingDeviceSignIns(ctx, time.Now().Add(-time.Second).UnixMicro())
			})
			out = true
		case "device-sign-in-addresses":
			if len(rest) != 2 || !probeName.MatchString(rest[1]) {
				return fail(fmt.Errorf("device-sign-in-addresses: name must be lower-case letters, digits and dashes"))
			}
			var ips []sql.NullString
			ips, err = query.New(store.Reader()).DeviceSignInRequesters(ctx, sql.NullString{String: rest[1], Valid: true})
			rows := []map[string]any{}
			for _, ip := range ips {
				var v any
				if ip.Valid {
					v = ip.String
				}
				rows = append(rows, map[string]any{"requesterIp": v})
			}
			out = rows
		default:
			fmt.Fprintf(stderr, "varlatchd admin conformance-probe: unknown probe %s\n", rest[0])
			return 64
		}
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
}
