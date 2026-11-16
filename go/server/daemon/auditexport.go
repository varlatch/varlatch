// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// AuditExportUsage is the TypeScript admin CLI's usage line for
// `admin audit-export`.
const AuditExportUsage = "Usage: varlatchd admin audit-export discard-plan --export <id> --reason <expired|unsupported-format> [--json]"

type discardArgs struct {
	export, reason string
	json           bool
}

// auditExportArgs reads `admin audit-export`'s arguments (--config
// already taken out); a non-empty message is the usage line.
func auditExportArgs(rest []string) (discardArgs, string) {
	var a discardArgs
	if len(rest) == 0 || rest[0] != "discard-plan" {
		return a, AuditExportUsage
	}
	for r := rest[1:]; len(r) > 0; {
		switch {
		case r[0] == "--json":
			a.json, r = true, r[1:]
		case (r[0] == "--export" || r[0] == "--reason") && len(r) > 1:
			if r[0] == "--export" {
				a.export = r[1]
			} else {
				a.reason = r[1]
			}
			r = r[2:]
		default:
			return a, AuditExportUsage
		}
	}
	if a.export == "" || (a.reason != "expired" && a.reason != "unsupported-format") {
		return a, AuditExportUsage
	}
	return a, ""
}

// runAuditExport is `varlatchd admin audit-export discard-plan` (ADR-0056
// Decision 2): the host's escape hatch for a pending plan that can no
// longer be uploaded, the same stream restart the worker runs, refused
// for a plan that is neither expired nor in a format this release cannot
// upload. It takes the export's gate (feature-parity decision 11), so in
// the daemon it waits for a change whose probe holds the export.
func runAuditExport(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	a, msg := auditExportArgs(rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	svc := &auditexport.Service{Writer: &write.Writer{Store: env.store, Gates: env.gates}, RootKEK: env.rootKEK, Now: time.Now, Log: env.log}
	streamID, err := svc.DiscardPlan(ctx, a.export, a.reason)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin audit-export: %s\n", err.Error())
		return ExitFailure
	}
	if a.json {
		fmt.Fprintln(stdout, string(jsvalue.Stringify(jsvalue.Object{{Key: "exportId", Value: a.export}, {Key: "streamId", Value: streamID}})))
	} else {
		fmt.Fprintf(stdout, "Discarded the pending plan of %s; the export continues in a new stream, %s, from its committed position.\n", a.export, streamID)
	}
	return ExitOK
}
