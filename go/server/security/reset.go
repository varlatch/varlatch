// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// ResetOutcome is ResetOutcome: what the host operator's reset did.
type ResetOutcome struct {
	OrganizationID, OrganizationSlug string
	Reset                            []ResetControl
	ApprovalsClosed                  int
	// StillFrozen: the reset never lifts an incident freeze.
	StillFrozen bool
}

// ResetControl is one control the reset named: its mode before, and its
// version after.
type ResetControl struct {
	Control, From string
	Version       int64
}

// JS is the outcome as `--json` prints it (JSON.stringify(outcome)).
func (o ResetOutcome) JS() jsvalue.Object {
	reset := make([]any, len(o.Reset))
	for i, r := range o.Reset {
		reset[i] = jsvalue.Object{{Key: "control", Value: r.Control}, {Key: "from", Value: r.From}, {Key: "version", Value: r.Version}}
	}
	return jsvalue.Object{
		{Key: "organization", Value: jsvalue.Object{{Key: "id", Value: o.OrganizationID}, {Key: "slug", Value: o.OrganizationSlug}}},
		{Key: "reset", Value: reset}, {Key: "approvalsClosed", Value: o.ApprovalsClosed}, {Key: "stillFrozen", Value: o.StillFrozen},
	}
}

// Lines is resetReportLines: what the reset prints for a person.
func (o ResetOutcome) Lines() []string {
	lines := []string{fmt.Sprintf("Security controls of %s [%s] reset to off:", o.OrganizationSlug, o.OrganizationID)}
	for _, r := range o.Reset {
		if r.From == Off {
			lines = append(lines, "  "+r.Control+": already off")
		} else {
			lines = append(lines, fmt.Sprintf("  %s: %s -> off (version %d)", r.Control, r.From, r.Version))
		}
	}
	lines = append(lines, fmt.Sprintf("Open approvals closed: %d.", o.ApprovalsClosed),
		"Deletion, suspended identities, passkeys and Grants were not touched. Recorded as security_control.reset.")
	if o.StillFrozen {
		lines = append(lines, o.OrganizationSlug+" is still frozen for an incident: a reset never lifts a freeze. Lift it with an approval, or with varlatchd admin unfreeze.")
	}
	return lines
}

// ResetUsage is RESET_USAGE.
var ResetUsage = "Usage: varlatchd admin security reset --org <slug or id> (--control <name> ... | --all) [--json]\nControls: " + strings.Join(Controls, ", ")

// ResetArgs are `admin security reset`'s arguments.
type ResetArgs struct {
	Organization string
	// Controls are the named controls; nil for --all.
	Controls []string
	JSON     bool
}

// ParseResetArgs is parseResetArgs (after "security reset"): the
// arguments, or why they are wrong.
func ParseResetArgs(args []string) (ResetArgs, string) {
	var a ResetArgs
	all, named := false, []string{}
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			i++
			return ""
		}
		switch args[i] {
		case "--org":
			a.Organization = next()
		case "--control":
			named = append(named, next())
		case "--all":
			all = true
		case "--json":
			a.JSON = true
		default:
			return a, "Unknown argument: " + args[i] + "\n" + ResetUsage
		}
	}
	if a.Organization == "" || all == (len(named) > 0) {
		return a, ResetUsage
	}
	var unknown []string
	for _, n := range named {
		if !IsControl(n) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		return a, "Unknown control: " + strings.Join(unknown, ", ") + "\n" + ResetUsage
	}
	if !all {
		a.Controls = named
	}
	return a, ""
}

// ResetControls is resetControls, the host operator's reset (ADR-0054
// Decision 10): the named controls (nil: every one) set to off, their open
// approvals closed, and security_control.reset recorded for each, with no
// actor. It works while the Organization is frozen or being deleted, and
// touches neither, nor suspended identities, passkeys or Grants. A control
// already off keeps its row and version; its open approvals are still
// closed. The Organization's gate is taken exclusive (the TypeScript reset
// takes the Organization row FOR UPDATE), so it waits for every external
// effect of the Organization.
func ResetControls(ctx context.Context, w *write.Writer, approvals *auth.Service, organization string, named []string, now func() time.Time) (ResetOutcome, error) {
	controls := slices.Clone(Controls)
	if named != nil {
		controls = slices.DeleteFunc(controls, func(c string) bool { return !slices.Contains(named, c) })
	}
	if len(controls) == 0 {
		return ResetOutcome{}, domainerr.New("VALIDATION_FAILED", "Name at least one control, or all")
	}
	notFound := domainerr.New("RESOURCE_NOT_FOUND", "No live Organization "+organization)
	org, err := query.New(w.Store.Reader()).LiveOrganizationBySlugOrID(ctx, organization)
	if errors.Is(err, sql.ErrNoRows) {
		return ResetOutcome{}, notFound
	}
	if err != nil {
		return ResetOutcome{}, err
	}
	var out ResetOutcome
	err = w.Job(ctx, []write.Gate{write.Organization(org.ID, write.Exclusive)}, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		live, err := q.LiveOrganizationBySlugOrID(ctx, organization)
		if errors.Is(err, sql.ErrNoRows) || err == nil && live.ID != org.ID {
			return notFound
		}
		if err != nil {
			return err
		}
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID, AllowDeleting: true, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		closed, err := approvals.CloseOpenApprovals(ctx, tx, org.ID, auth.CloseReset, controls, nil)
		if err != nil {
			return err
		}
		at := now().UnixMicro()
		before := map[string]State{}
		changed := false
		for _, control := range slices.Sorted(slices.Values(controls)) {
			current, err := Read(ctx, tx, org.ID, control)
			if err != nil {
				return err
			}
			before[control] = current
			if current.Mode != Off {
				changed = true
				if err := q.ResetSecurityControl(ctx, query.ResetSecurityControlParams{Version: current.Version + 1, Now: at, OrganizationID: org.ID, Control: control}); err != nil {
					return err
				}
			}
		}
		if changed {
			if err := q.BumpSecurityEpoch(ctx, org.ID); err != nil {
				return err
			}
		}
		out = ResetOutcome{OrganizationID: org.ID, OrganizationSlug: org.Slug, ApprovalsClosed: closed}
		events := make([]audit.Event, 0, len(controls))
		for _, control := range controls {
			current := before[control]
			version := current.Version
			if current.Mode != Off {
				version++
			}
			out.Reset = append(out.Reset, ResetControl{Control: control, From: current.Mode, Version: version})
			md := jsvalue.Object{{Key: "control", Value: control}, {Key: "operator", Value: true}}
			md = append(md, stateMetadata("from", current.Mode, current.Version, current.Config)...)
			md = append(md, stateMetadata("to", Off, version, current.Config)...)
			md = append(md, jsvalue.Member{Key: "approvalsClosed", Value: closed})
			orgID := org.ID
			events = append(events, audit.Event{
				Type: "security_control.reset", Decision: audit.Info, OrganizationID: &orgID,
				Resource: jsvalue.Object{{Key: "control", Value: control}}, Metadata: md,
			})
		}
		if _, err := audit.Record(ctx, tx, events...); err != nil {
			return err
		}
		frozen, err := q.OpenFreeze(ctx, org.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		out.StillFrozen = err == nil && frozen.ID != ""
		return nil
	})
	return out, err
}
