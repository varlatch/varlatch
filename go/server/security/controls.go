// SPDX-License-Identifier: AGPL-3.0-or-later

// Package security is the Organization's Security Controls (ADR-0054;
// ADR-0059 step 4.3): the controls and their changes
// (domain/securitycontrols.ts), what report mode counts and the hourly
// summaries of it (securityreport.ts), the framework every protected
// operation runs in (protected.ts), and the admins' approval keys
// (approvalKeys.ts).
//
// The write path is go/server/write's: a control change takes the
// Organization's gate exclusive, as the TypeScript change takes the
// Organization row FOR UPDATE, so it waits for every external effect of
// the Organization (each holds the gate shared for its whole life) and
// every effect started after it sees the new mode. Everything the
// TypeScript code checks under that lock is checked again inside the
// change's write job.
package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
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

// The controls (SECURITY_CONTROLS), in their order.
const (
	RequirementProtection = "requirement-protection"
	AdminStepUp           = "admin-step-up"
	PasskeyVerification   = "passkey-verification"
	CredentialLifetime    = "credential-lifetime"
)

// Controls is SECURITY_CONTROLS.
var Controls = []string{RequirementProtection, AdminStepUp, PasskeyVerification, CredentialLifetime}

// Modes.
const (
	Off     = "off"
	Report  = "report"
	Enforce = "enforce"
)

// AvailableModes is AVAILABLE_MODES: the modes every control accepts.
var AvailableModes = []string{Off, Report}

// enforceable is ENFORCEABLE_CONTROLS: since the TypeScript step 4.9b
// every control can be enforced.
var enforceable = map[string]bool{RequirementProtection: true, CredentialLifetime: true, PasskeyVerification: true, AdminStepUp: true}

// AvailableModesOf is availableModesOf: the modes a change may set for the
// control in this release.
func AvailableModesOf(control string) []string {
	if enforceable[control] {
		return append(slices.Clone(AvailableModes), Enforce)
	}
	return slices.Clone(AvailableModes)
}

// IsControl reports whether name is a control.
func IsControl(name string) bool { return slices.Contains(Controls, name) }

var modeRank = map[string]int{Off: 0, Report: 1, Enforce: 2}

// Lifetime is credential-lifetime's configuration (LifetimeConfig).
type Lifetime struct {
	DefaultTTLSeconds int64
	MaxTTLSeconds     int64
}

// JS is the configuration as the API shows it.
func (l *Lifetime) JS() any {
	if l == nil {
		return nil
	}
	return jsvalue.Object{{Key: "defaultTtlSeconds", Value: l.DefaultTTLSeconds}, {Key: "maxTtlSeconds", Value: l.MaxTTLSeconds}}
}

func sameLifetime(a, b *Lifetime) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// parseLifetime reads a stored configuration; nil for none.
func parseLifetime(s sql.NullString) (*Lifetime, error) {
	if !s.Valid {
		return nil, nil
	}
	var raw struct {
		Default float64 `json:"defaultTtlSeconds"`
		Max     float64 `json:"maxTtlSeconds"`
	}
	if err := json.Unmarshal([]byte(s.String), &raw); err != nil {
		return nil, fmt.Errorf("security: a control's configuration: %w", err)
	}
	return &Lifetime{DefaultTTLSeconds: int64(raw.Default), MaxTTLSeconds: int64(raw.Max)}, nil
}

func storeLifetime(l *Lifetime) sql.NullString {
	if l == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(jsvalue.Stringify(l.JS())), Valid: true}
}

// State is a control's state (ControlState). A control nobody changed is
// off at version 0, never changed.
type State struct {
	Control string
	Mode    string
	Config  *Lifetime
	Version int64
	// ChangedAt is in microseconds since the epoch; 0 for never.
	ChangedAt     int64
	ChangedByID   string
	ChangedByName *string
}

// JS is the state as the API shows it.
func (s State) JS() jsvalue.Object {
	var changedAt, changedBy any
	if s.Version > 0 {
		changedAt = audit.ISOTime(s.ChangedAt)
	}
	if s.ChangedByID != "" {
		var name any
		if s.ChangedByName != nil {
			name = *s.ChangedByName
		}
		changedBy = jsvalue.Object{{Key: "id", Value: s.ChangedByID}, {Key: "name", Value: name}}
	}
	return jsvalue.Object{
		{Key: "control", Value: s.Control}, {Key: "mode", Value: s.Mode}, {Key: "config", Value: s.Config.JS()},
		{Key: "version", Value: s.Version}, {Key: "changedAt", Value: changedAt}, {Key: "changedBy", Value: changedBy},
	}
}

func offState(control string) State { return State{Control: control, Mode: Off} }

// List is listControls: every control of the Organization, in their
// order, a missing one off at version 0.
func List(ctx context.Context, db query.DBTX, organizationID string) ([]State, error) {
	rows, err := query.New(db).SecurityControlsOf(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]State, 0, len(Controls))
	for _, control := range Controls {
		st := offState(control)
		for _, r := range rows {
			if r.Control != control {
				continue
			}
			cfg, err := parseLifetime(r.Config)
			if err != nil {
				return nil, err
			}
			st = State{Control: control, Mode: r.Mode, Config: cfg, Version: r.Version, ChangedAt: r.ChangedAt, ChangedByID: r.ChangedBy.String}
			if r.ChangedByName.Valid {
				name := r.ChangedByName.String
				st.ChangedByName = &name
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// Read is readControl: one control's state.
func Read(ctx context.Context, db query.DBTX, organizationID, control string) (State, error) {
	all, err := List(ctx, db, organizationID)
	if err != nil {
		return State{}, err
	}
	for _, s := range all {
		if s.Control == control {
			return s, nil
		}
	}
	return offState(control), nil
}

// AnyOn is anyControlOn: whether any control is at report or enforce.
func AnyOn(ctx context.Context, db query.DBTX, organizationID string) (bool, error) {
	n, err := query.New(db).AnySecurityControlOn(ctx, organizationID)
	return n > 0, err
}

// ModeUnavailable is controlModeUnavailable.
func ModeUnavailable(control, mode string) error {
	modes := AvailableModesOf(control)
	list := make([]any, len(modes))
	for i, m := range modes {
		list[i] = m
	}
	return &domainerr.Error{Code: "CONTROL_MODE_UNAVAILABLE",
		Message: fmt.Sprintf("This server does not offer %s for %s yet: it can be %s", mode, control, strings.Join(modes, " or ")),
		Details: jsvalue.Object{{Key: "control", Value: control}, {Key: "mode", Value: mode}, {Key: "availableModes", Value: list}}}
}

func describeTTL(v *int64) *string {
	if v == nil {
		return nil
	}
	s := strconv.FormatInt(*v, 10)
	return &s
}

// ClassifyChange is classifyChange: what changes, field by field, and
// which of the changes loosen the control. The mode moving towards off, a
// lifetime growing and configuration being cleared loosen; a lifetime set
// where there was none, or shrunk, tightens.
func ClassifyChange(beforeMode string, beforeConfig *Lifetime, afterMode string, afterConfig *Lifetime) (changes []auth.ApprovalChange, loosened []string) {
	str := func(s string) *string { return &s }
	if beforeMode != afterMode {
		changes = append(changes, auth.ApprovalChange{Field: "mode", From: str(beforeMode), To: str(afterMode), Loosens: modeRank[afterMode] < modeRank[beforeMode]})
	}
	field := func(l *Lifetime, name string) *int64 {
		if l == nil {
			return nil
		}
		v := l.DefaultTTLSeconds
		if name == "maxTtlSeconds" {
			v = l.MaxTTLSeconds
		}
		return &v
	}
	for _, name := range []string{"defaultTtlSeconds", "maxTtlSeconds"} {
		from, to := field(beforeConfig, name), field(afterConfig, name)
		if from == nil && to == nil || from != nil && to != nil && *from == *to {
			continue
		}
		// Cleared (a bound removed) or grown loosens; newly set or shrunk tightens.
		loosens := from != nil && (to == nil || *to > *from)
		changes = append(changes, auth.ApprovalChange{Field: name, From: describeTTL(from), To: describeTTL(to), Loosens: loosens})
	}
	for _, c := range changes {
		if c.Loosens {
			loosened = append(loosened, c.Field)
		}
	}
	return changes, loosened
}

// stateMetadata is stateMetadata: a state as flat audit metadata.
func stateMetadata(prefix, mode string, version int64, config *Lifetime) jsvalue.Object {
	var def, max any
	if config != nil {
		def, max = config.DefaultTTLSeconds, config.MaxTTLSeconds
	}
	return jsvalue.Object{
		{Key: prefix + "Mode", Value: mode}, {Key: prefix + "Version", Value: version},
		{Key: prefix + "DefaultTtlSeconds", Value: def}, {Key: prefix + "MaxTtlSeconds", Value: max},
	}
}

// ConfigChange is what a change does to the configuration: keep it (the
// request did not name it), clear it (null) or set it.
type ConfigChange struct {
	Keep bool
	Set  *Lifetime
}

// ChangeInput is one control change, as the route parsed it.
type ChangeInput struct {
	OrganizationID string
	Control        string
	// Mode is nil to keep the mode.
	Mode            *string
	Config          ConfigChange
	ExpectedVersion int64
	Principal       *auth.Principal
	// ApprovalID is the Varlatch-Approval header's approval id, "" for none.
	ApprovalID string
	RequestID  string
}

// Change is ControlChange: the control after the request, whether the
// request changed it, and whether that loosened it.
type Change struct {
	Control  State
	Changed  bool
	Loosened bool
}

// JS is the change as the API answers it.
func (c Change) JS() jsvalue.Object {
	return jsvalue.Object{{Key: "control", Value: c.Control.JS()}, {Key: "changed", Value: c.Changed}, {Key: "loosened", Value: c.Loosened}}
}

// DeferredDenial is an authorization denial found by a recheck inside a
// write job that the refusal rolls back (authorizeInControlledTransaction):
// its audit event is recorded after the job, by the caller (app.onError's
// auditDeferredDenial).
type DeferredDenial struct {
	Err   *domainerr.Error
	Event audit.Event
}

func (e *DeferredDenial) Error() string { return e.Err.Error() }
func (e *DeferredDenial) Unwrap() error { return e.Err }

// AuthorizeControlled is authorizeInControlledTransaction: organization.manage
// rechecked in the job of an operation that runs whatever the controls'
// modes (a control change, freezing and lifting a freeze). A denial keeps
// its audit event for after the job only when a control is on in the
// state the job decided on; with every control off it records nothing,
// as the TypeScript event is rolled back with the refusal.
func AuthorizeControlled(ctx context.Context, tx query.DBTX, p *auth.Principal, action, organizationID, requestID string) error {
	ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
	if p.Identity.OrganizationID != nil {
		ap.OrganizationID = *p.Identity.OrganizationID
	}
	d, err := authz.Decide(ctx, tx, ap, action, authz.Resource{OrganizationID: organizationID},
		authz.Options{HideExistence: true, RequestID: requestID})
	if err != nil {
		return err
	}
	if d.Allowed {
		return nil
	}
	on, err := AnyOn(ctx, tx, organizationID)
	if err != nil || !on || d.DenialEvent == nil {
		// A failed read answers the denial itself, never a 500.
		return d.Err
	}
	return &DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
}

// ValidateChange is changeControl's checks before its job: the mode
// offered for the control, configuration only for credential-lifetime,
// and 0 < defaultTtlSeconds <= maxTtlSeconds.
func ValidateChange(in ChangeInput) error {
	if in.Mode != nil && !slices.Contains(AvailableModesOf(in.Control), *in.Mode) {
		return ModeUnavailable(in.Control, *in.Mode)
	}
	if c := in.Config.Set; c != nil {
		if in.Control != CredentialLifetime {
			return domainerr.New("VALIDATION_FAILED", "config: "+in.Control+" has no configuration")
		}
		if !(c.DefaultTTLSeconds > 0 && c.DefaultTTLSeconds <= c.MaxTTLSeconds) {
			return domainerr.New("VALIDATION_FAILED", "config: 0 < defaultTtlSeconds <= maxTtlSeconds")
		}
	}
	return nil
}

// ChangeControl is changeControl. The Organization's gate exclusive and
// the requester's person gate (exclusive when the request carries an
// approval it may consume, as the TypeScript change locks the person FOR
// UPDATE when it consumes) are taken before the job; in the job: the
// Organization live and not being deleted (a change is recovery while
// frozen), the requester's passkey-verification checkpoint,
// organization.manage rechecked, the expected version, then, for a change
// that changes something, its classification and, when it loosens, the
// approval bound to exactly this change consumed (or *auth.ApprovalNeeded,
// which rolls the job back). Then the new state with the next version, the
// security epoch, and security_control.changed. A request that changes
// nothing records nothing and needs no approval. It returns the report
// counts to record once the request succeeds.
func ChangeControl(ctx context.Context, w *write.Writer, approvals *auth.Service, in ChangeInput, now func() time.Time) (Change, []auth.PendingReport, error) {
	if err := ValidateChange(in); err != nil {
		return Change{}, nil, err
	}
	actor := in.Principal.Identity.ID
	person := write.Shared
	if in.ApprovalID != "" {
		person = write.Exclusive
	}
	gates := []write.Gate{write.Organization(in.OrganizationID, write.Exclusive), write.Person(actor, person)}
	var out Change
	var reports []auth.PendingReport
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		out, reports = Change{}, nil
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: in.OrganizationID, DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, in.Principal, in.OrganizationID); err != nil {
			return err
		}
		if err := AuthorizeControlled(ctx, tx, in.Principal, "organization.manage", in.OrganizationID, in.RequestID); err != nil {
			return err
		}
		current, err := Read(ctx, tx, in.OrganizationID, in.Control)
		if err != nil {
			return err
		}
		if current.Version != in.ExpectedVersion {
			return &domainerr.Error{Code: "VERSION_CONFLICT",
				Message: fmt.Sprintf("%s is at version %d, not %d: it changed meanwhile. Read it again", in.Control, current.Version, in.ExpectedVersion),
				Details: jsvalue.Object{{Key: "currentVersion", Value: current.Version}}}
		}
		nextMode, nextConfig := current.Mode, current.Config
		if in.Mode != nil {
			nextMode = *in.Mode
		}
		if !in.Config.Keep {
			nextConfig = in.Config.Set
		}
		if in.Control == CredentialLifetime && nextMode != Off && nextConfig == nil {
			return domainerr.New("VALIDATION_FAILED", "config: credential-lifetime needs defaultTtlSeconds and maxTtlSeconds unless it is off")
		}
		if nextMode == current.Mode && sameLifetime(nextConfig, current.Config) {
			out = Change{Control: current}
			return nil
		}
		changes, loosened := ClassifyChange(current.Mode, current.Config, nextMode, nextConfig)
		var used *auth.UsedApproval
		if len(loosened) > 0 {
			name, err := query.New(tx).OrganizationNames(ctx, in.OrganizationID)
			if err != nil {
				return err
			}
			title := "Loosen the " + in.Control + " security control of " + name.Name
			if nextMode == Off && current.Mode != Off {
				title = "Turn off the " + in.Control + " security control of " + name.Name
			}
			expected := in.ExpectedVersion
			org := in.OrganizationID
			b := auth.Binding{
				Operation: "security_control.change", OrganizationID: &org,
				Target: map[string]string{"control": in.Control},
				// The normalized request: the state it asks for, and the version it expects.
				Body: jsvalue.Object{
					{Key: "mode", Value: nextMode}, {Key: "config", Value: nextConfig.JS()}, {Key: "expectedVersion", Value: expected},
				},
				Query: map[string]string{}, ExpectedVersion: &expected,
				Summary: auth.ApprovalSummary{Title: title, Changes: changes},
			}
			if in.ApprovalID == "" {
				return &auth.ApprovalNeeded{Binding: b}
			}
			u, err := approvals.ConsumeApproval(ctx, tx, auth.RequesterOf(in.Principal), in.ApprovalID, b)
			if err != nil {
				return err
			}
			used = &u
		}
		at := now().UnixMicro()
		q := query.New(tx)
		if err := q.UpsertSecurityControl(ctx, query.UpsertSecurityControlParams{
			OrganizationID: in.OrganizationID, Control: in.Control, Mode: nextMode, Config: storeLifetime(nextConfig),
			Version: current.Version + 1, ChangedBy: sql.NullString{String: actor, Valid: true}, ChangedAt: at,
		}); err != nil {
			return err
		}
		if err := q.BumpSecurityEpoch(ctx, in.OrganizationID); err != nil {
			return err
		}
		updated, err := Read(ctx, tx, in.OrganizationID, in.Control)
		if err != nil {
			return err
		}
		var approvalID any
		md := jsvalue.Object{{Key: "control", Value: in.Control}}
		md = append(md, stateMetadata("from", current.Mode, current.Version, current.Config)...)
		md = append(md, stateMetadata("to", updated.Mode, updated.Version, updated.Config)...)
		if used != nil {
			approvalID = used.ID
		}
		md = append(md,
			jsvalue.Member{Key: "loosened", Value: len(loosened) > 0},
			// The fields that weakened the control, comma-separated; empty for tightening.
			jsvalue.Member{Key: "loosenedFields", Value: strings.Join(loosened, ",")},
			jsvalue.Member{Key: "approvalId", Value: approvalID})
		if used != nil {
			md = append(md, jsvalue.Member{Key: "approvalPasskeyId", Value: used.PasskeyID}, jsvalue.Member{Key: "approvalUserVerified", Value: used.UserVerified})
		}
		action := "organization.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "security_control.changed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &in.OrganizationID,
			Action: &action, RequestID: &in.RequestID, Resource: jsvalue.Object{{Key: "control", Value: in.Control}}, Metadata: md,
		}); err != nil {
			return err
		}
		out = Change{Control: updated, Changed: true, Loosened: len(loosened) > 0}
		return nil
	})
	if err != nil {
		return Change{}, nil, err
	}
	return out, reports, nil
}

// ApprovalMetadata is approvalMetadata: the approval an operation used, as
// flat audit metadata; nothing when it used none.
func ApprovalMetadata(used *auth.UsedApproval) jsvalue.Object {
	if used == nil {
		return nil
	}
	return jsvalue.Object{{Key: "approvalId", Value: used.ID}, {Key: "approvalPasskeyId", Value: used.PasskeyID}, {Key: "approvalUserVerified", Value: used.UserVerified}}
}
