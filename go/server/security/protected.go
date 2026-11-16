// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Enforcement of the Security Controls (ADR-0054 step 4; protected.ts),
// shared by every protected operation. In TypeScript a protected operation
// runs prepareProtectedOperation inside its own transaction, in amendment
// E's lock order. In varlatchd the locks are gates taken before the job
// (Request.Gates: the Organization shared, the operation's people, the
// requester exclusive when the request carries an approval it may
// consume), and Prepare runs the same checks in the same order inside the
// operation's write job:
//
//  1. the Organization live, not being deleted and not frozen unless the
//     operation runs under an exception (CheckLive): a refusal there comes
//     before any approval, so nobody approves an operation that cannot run;
//  2. the controls at report or enforce, read in the job, so a control
//     change (Organization gate exclusive) committed before or waits;
//  3. credential-lifetime for an operation that issues a machine
//     credential: at enforce a TTL above the maximum is refused before any
//     approval is asked for, and a request without one gets the default;
//  4. the operation's existence preflight, then the requester's
//     passkey-verification checkpoint, whatever the other controls' modes;
//  5. only when a control at enforce asks for an approval, the exact
//     binding (nil when the request changes nothing); a machine credential
//     is refused, since it can never pass an approval; a request without
//     one answers *auth.ApprovalNeeded, which rolls the job back;
//  6. the approval consumed, then the operation's authorization rechecked;
//  7. the scope's Project and environments.
//
// The operation then writes its rows, counts what report mode returns
// (Prepared.Count) and records its audit events, all in the same job.

// approvalControls are the controls whose enforce asks for an approval.
var approvalControls = map[string]bool{RequirementProtection: true, AdminStepUp: true}

// Protected is a protected operation (ProtectedOperationInput).
type Protected struct {
	// Scope is the operation's scope: the Organization, and its Project
	// and environments when it has them.
	Scope write.Scope
	// Checks are the controls that may act on the operation.
	Checks []Check
	// Binding is the exact binding of this request, asked for only when a
	// control at enforce needs an approval; nil when the request changes
	// nothing. It runs the operation's refusals that do not depend on the
	// approval first. effectiveTTL is credential-lifetime's decision.
	Binding func(ctx context.Context, tx query.DBTX, effectiveTTL *int64) (*auth.Binding, error)
	// Preflight is the operation's existence checks, run whatever the
	// controls' modes, before the passkey-verification checkpoint; nil for
	// none.
	Preflight func(ctx context.Context, tx query.DBTX) error
	// ScopeBeforeCheckpoint checks the scope's Project and environments
	// before the checkpoint (lockScopeBeforeCheckpoint), so the target's
	// not-found answers first.
	ScopeBeforeCheckpoint bool
	// AuthorizeIn rechecks the requester's authorization once an approval
	// was consumed; nil for none.
	AuthorizeIn func(ctx context.Context, tx query.DBTX) error
}

// Request is who asks for a protected operation and with which approval
// (withApproval's ProtectedGate).
type Request struct {
	Principal *auth.Principal
	// ApprovalID is the Varlatch-Approval header's approval id, "" for none.
	ApprovalID string
	// ApprovalMalformed is a Varlatch-Approval header that cannot be an
	// approval id: checked only when an approval is consumed, where it is
	// not found (withApproval's require).
	ApprovalMalformed bool
	Approvals         *auth.Service
}

// carries reports whether the request sent a Varlatch-Approval header.
func (r Request) carries() bool { return r.ApprovalID != "" || r.ApprovalMalformed }

func (r Request) requester() auth.Requester { return auth.RequesterOf(r.Principal) }

// RequesterGate is effectRequester: the requester's person gate,
// exclusive when the request carries an approval it may consume, so its
// consumption never upgrades a weaker hold.
func (r Request) RequesterGate() write.Gate {
	mode := write.Shared
	if r.carries() {
		mode = write.Exclusive
	}
	return write.Person(r.Principal.Identity.ID, mode)
}

// Gates are the gates a protected operation takes before its job: the
// Organization shared, its people, and the requester (RequesterGate).
func (r Request) Gates(organizationID string, people ...write.Gate) []write.Gate {
	return append([]write.Gate{write.Organization(organizationID, write.Shared), r.RequesterGate()}, people...)
}

func isPersonCredential(p *auth.Principal) bool {
	return p.Identity.Kind == "human" && (p.Credential.Kind == auth.KindBrowser || p.Credential.Kind == auth.KindCLI)
}

// MachineCannotApprove is machineCannotApprove: an operation that needs an
// approval, asked for by a machine credential under enforce, refused
// without an intent.
func MachineCannotApprove(operation string) error {
	return &domainerr.Error{Code: "PERMISSION_DENIED",
		Message: operation + " needs a person's approval with a passkey under this organization's security controls, which a machine credential cannot give",
		Details: jsvalue.Object{{Key: "reason", Value: "machine-credential"}}}
}

// CredentialLifetimeExceeded is credentialLifetimeExceeded.
func CredentialLifetimeExceeded(requested, max int64) error {
	return &domainerr.Error{Code: "CREDENTIAL_LIFETIME_EXCEEDED",
		Message: fmt.Sprintf("This organization's credential-lifetime control allows machine credentials of at most %d seconds, "+
			"not %d: ask for a shorter lifetime, or none to get the organization's default. Nothing was issued", max, requested),
		Details: jsvalue.Object{{Key: "control", Value: CredentialLifetime}, {Key: "requestedTtlSeconds", Value: requested}, {Key: "maxTtlSeconds", Value: max}}}
}

// Prepared is what a protected operation was decided to be
// (PreparedOperation).
type Prepared struct {
	// Approval is the approval consumed for this request; nil when none
	// was needed.
	Approval *auth.UsedApproval
	// Binding is what the approval was bound to; nil when none was needed.
	Binding *auth.Binding
	// Reports are what the controls in report mode would have done,
	// counted only by Count.
	Reports []WouldBlock
	// EffectiveTTL is the issuance TTL credential-lifetime makes of the
	// requested one; TTLDefaulted when it is the default.
	EffectiveTTL *int64
	TTLDefaulted bool
	// Access are the passkey-verification counts the checkpoint found, to
	// record once the request succeeds.
	Access []auth.PendingReport

	organizationID string
	at             int64
	now            func() time.Time
}

// Count counts the report entries in the operation's job: call it once the
// operation changed something, after its domain rows and before its audit
// events. A refused, failed or unchanged request is not counted.
func (p *Prepared) Count(ctx context.Context, tx query.DBTX) error {
	return CountWouldBlock(ctx, tx, p.organizationID, p.Reports, p.at, p.now)
}

// Prepare is prepareProtectedOperation, in the operation's write job (see
// the top of this file).
func Prepare(ctx context.Context, tx query.DBTX, r Request, op Protected, now func() time.Time) (*Prepared, error) {
	p := &Prepared{organizationID: op.Scope.OrganizationID, at: now().UnixMicro(), now: now}
	org := write.Scope{OrganizationID: op.Scope.OrganizationID, AllowDeleting: op.Scope.AllowDeleting, DuringFreeze: op.Scope.DuringFreeze}
	if err := write.CheckLive(ctx, tx, org); err != nil {
		return nil, err
	}
	active, err := activeControls(ctx, tx, op.Scope.OrganizationID)
	if err != nil {
		return nil, err
	}
	requester := r.Principal
	needsApproval := false
	approvalReason := ""
	for _, c := range op.Checks {
		ctl, on := active[c.Control]
		if c.Control == CredentialLifetime {
			p.EffectiveTTL = c.TTLSeconds
			if !on {
				continue
			}
			if ctl.mode == Report {
				if reason := LifetimeReason(ctl.config, c.TTLSeconds); reason != "" {
					p.Reports = append(p.Reports, WouldBlock{Control: c.Control, ConfigVersion: ctl.version, Operation: c.Operation, ActorIdentityID: requester.Identity.ID, Reason: reason})
				}
			} else if ctl.mode == Enforce && ctl.config != nil {
				switch {
				case c.TTLSeconds == nil:
					def := ctl.config.DefaultTTLSeconds
					p.EffectiveTTL, p.TTLDefaulted = &def, true
				case *c.TTLSeconds <= 0:
					// A direct caller's 0 would mean "never expires", which enforce rules out.
					return nil, domainerr.New("VALIDATION_FAILED", "A credential's lifetime must be a whole number of seconds above zero")
				case *c.TTLSeconds > ctl.config.MaxTTLSeconds:
					return nil, CredentialLifetimeExceeded(*c.TTLSeconds, ctl.config.MaxTTLSeconds)
				}
			}
			continue
		}
		if !on || !approvalControls[c.Control] {
			continue
		}
		if ctl.mode == Enforce {
			needsApproval = true
		} else if ctl.mode == Report {
			if approvalReason == "" {
				approvalReason = ReasonMachineCredential
				if requester.Identity.Kind == "human" {
					approvalReason = ReasonNoApproval
				}
			}
			p.Reports = append(p.Reports, WouldBlock{Control: c.Control, ConfigVersion: ctl.version, Operation: c.Operation, ActorIdentityID: requester.Identity.ID, Reason: approvalReason})
		}
	}

	if op.Preflight != nil {
		if err := op.Preflight(ctx, tx); err != nil {
			return nil, err
		}
	}
	// A request that consumes nothing checks its scope's Project and
	// environments before the checkpoint when the operation asks for it, so
	// a target being deleted answers its not-found; one that consumes checks
	// them after its consumption, unless the checkpoint refuses it, when its
	// not-found still answers first.
	consumes := needsApproval && r.carries()
	scopeFirst := op.ScopeBeforeCheckpoint && op.Scope.ProjectID != ""
	if scopeFirst && !consumes {
		if err := write.CheckLive(ctx, tx, op.Scope); err != nil {
			return nil, err
		}
	}
	if p.Access, err = write.Checkpoint(ctx, tx, requester, op.Scope.OrganizationID); err != nil {
		var refusal *auth.VerificationRefusal
		if scopeFirst && consumes && errors.As(err, &refusal) {
			if lerr := write.CheckLive(ctx, tx, op.Scope); lerr != nil {
				return nil, lerr
			}
		}
		return nil, err
	}
	if needsApproval {
		if p.Binding, err = op.Binding(ctx, tx, p.EffectiveTTL); err != nil {
			return nil, err
		}
		if p.Binding != nil && !isPersonCredential(requester) {
			return nil, MachineCannotApprove(p.Binding.Operation)
		}
	}
	if p.Binding != nil {
		if !r.carries() {
			return nil, &auth.ApprovalNeeded{Binding: *p.Binding}
		}
		if r.ApprovalMalformed {
			return nil, auth.ApprovalInvalid("not-found", nil)
		}
		used, err := r.Approvals.ConsumeApproval(ctx, tx, r.requester(), r.ApprovalID, *p.Binding)
		if err != nil {
			return nil, err
		}
		p.Approval = &used
		if op.AuthorizeIn != nil {
			if err := op.AuthorizeIn(ctx, tx); err != nil {
				return nil, err
			}
		}
	}
	if op.Scope.ProjectID != "" {
		if err := write.CheckLive(ctx, tx, op.Scope); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// RefuseMachineUnderEnforce is refuseMachineUnderEnforce: an early
// refusal, read outside any job, for a request whose protected step comes
// after an external effect it would waste. A machine credential is refused
// when a control at enforce would ask the operation for an approval. It
// decides nothing by itself: Prepare refuses again.
func RefuseMachineUnderEnforce(ctx context.Context, db query.DBTX, p *auth.Principal, organizationID string, checks []Check) error {
	if isPersonCredential(p) {
		return nil
	}
	active, err := activeControls(ctx, db, organizationID)
	if err != nil {
		return err
	}
	for _, c := range checks {
		if ctl, on := active[c.Control]; on && approvalControls[c.Control] && ctl.mode == Enforce {
			return MachineCannotApprove(c.Operation)
		}
	}
	return nil
}

// WithApproval is withApproval: run a protected operation; when it needs
// an approval it was not given, store an Approval Intent for the binding
// and answer STEP_UP_REQUIRED with it. Anything else passes through.
func WithApproval[T any](ctx context.Context, approvals *auth.Service, requester auth.Requester, run func() (T, error)) (T, error) {
	out, err := run()
	var needed *auth.ApprovalNeeded
	if errors.As(err, &needed) {
		var zero T
		return zero, approvals.StepUpRequired(ctx, requester, needed.Binding)
	}
	return out, err
}

// IdempotentProtected runs a protected write under an Idempotency-Key
// claim (withIdempotency inside withApproval): the Organization's gate and
// the requester's (exclusive when it carries an approval) taken first; a
// replay runs the requester's checkpoint before answering from the claim.
func IdempotentProtected(ctx context.Context, w *write.Writer, r Request, organizationID string, claim write.Claim,
	run func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error)) (write.Response, []auth.PendingReport, error) {
	ctx, release, err := w.Gates.Acquire(ctx, r.Gates(organizationID)...)
	if err != nil {
		return write.Response{}, nil, err
	}
	defer release()
	var reports []auth.PendingReport
	resp, _, err := write.Idempotent(ctx, w.Store, claim,
		func(tx *storage.Tx) error {
			var err error
			reports, err = write.Checkpoint(ctx, tx, r.Principal, organizationID)
			return err
		},
		func(tx *storage.Tx) (write.Response, error) { return run(ctx, tx, &reports) })
	return resp, reports, err
}
