// SPDX-License-Identifier: Apache-2.0

// Package tailhandoff moves a tailnet name from the node that serves it to
// another, and back when anything fails (ADR-0059 Decision 9 phase 5;
// internal docs/design/go-step7.md decision 11, slice 7.5b): the forward
// handoff of a migration, its reverse, and the restore handoff of 6.4c.
//
// A handoff is a resumable state machine on top of lib/tailcontrol:
//
//   - Prepare, before any barrier: the names are checked (the name held by
//     exactly the serving node, the incoming node under exactly its
//     temporary name, the serving node's temporary name free, all
//     case-insensitively), the issuance count allows a certificate, and,
//     on the Tailscale certificate path, the incoming node proves it can
//     obtain one now and the serving node's certificate is checked against
//     the rollback window. Nothing is renamed.
//   - Switch, under the barrier: the serving installation lets go of the
//     tailnet, the serving node is renamed to its temporary name and the
//     incoming node to the name, back to back, each read back (a name
//     Tailscale has not released yet, which it applies suffixed, -1, is
//     renamed to again until it reads back, within the deadline); the
//     incoming node obtains the name's certificate; a client must reach
//     the incoming node by the name; only then does it open. Everything
//     from the first rename runs under one deadline.
//   - Any failure after the first change starts the undo: the incoming
//     node gives the name back, the serving node takes it again (read
//     back), and the serving installation reopens. An undo that cannot
//     reach the control plane keeps both installations closed, journals
//     how far it got, and Resume finishes it later. Nothing is ever opened
//     under a name that was not read back.
//
// The callers (varlatch migrate, varlatchd's restore) supply the parts that
// are theirs: the journal (Journal), the certificates (Certificates), the
// issuance count kept in the installation's records (Ledger), the
// installations' listeners (Endpoints), the check from a client node
// (Resolver), and the control plane, built with their own *http.Client
// (varlatchd passes the outbound policy's).
package tailhandoff

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
)

// Kind is which handoff a Plan is.
type Kind string

const (
	// Forward is a migration's: the TypeScript installation's node gives
	// the name to the new varlatchd's.
	Forward Kind = "forward"
	// Reverse is a migration's rollback: varlatchd's node gives the name
	// back to the retained old node.
	Reverse Kind = "reverse"
	// Restore is a restore onto a new host: the dead node gives the name
	// to the new one.
	Restore Kind = "restore"
)

// Defaults of decision 11.
const (
	DefaultDeadline     = 180 * time.Second // from the first change (the close) to the final check
	DefaultCertWait     = 120 * time.Second // the name's certificate, inside the deadline
	DefaultCertAttempts = 3                 // for fast server errors
	DefaultUndoWait     = 60 * time.Second  // an undo keeps trying the control plane this long
	WeeklyLimit         = 5                 // Let's Encrypt's certificates per exact name per week
	RenewMargin         = 7 * 24 * time.Hour
)

// Role is which of the two nodes a call concerns.
type Role string

const (
	Serving  Role = "serving"  // the node that holds the name now
	Incoming Role = "incoming" // the node that takes it
)

// Plan is one handoff, as its caller describes it.
type Plan struct {
	Kind Kind `json:"kind"`
	// Operation is the handoff's identifier (tailcontrol.NewOperationID).
	Operation string `json:"operation"`
	// Name is the tailnet name that moves.
	Name string `json:"name"`
	// ServingID and IncomingID are the two nodes' control-plane ids.
	ServingID  string `json:"servingId"`
	IncomingID string `json:"incomingId"`
	// IncomingName is the name the incoming node holds now: its temporary
	// name (forward, restore: <name>-vl-<op>-n), or, on a reverse, the
	// retained old node's (<name>-vl-<forward op>-o).
	IncomingName string `json:"incomingName"`
	// Certificates is whether the tailnet ingress serves Tailscale HTTPS
	// certificates, which follow the name (decision 11); Headscale's HTTPS
	// comes from the public or own-proxy path, so false.
	Certificates bool `json:"certificates"`
	// RetainUntil is when the rollback window ends (forward only): the
	// serving node's certificate must outlive it by RenewMargin, or be
	// renewed now while the node still holds the name.
	RetainUntil time.Time `json:"retainUntil"`
	// AcceptRollbackCertificate is the operator's acceptance that a
	// rollback after the serving certificate's expiry needs a new
	// certificate (about 40 s of downtime and one issuance), when renewing
	// it now failed.
	AcceptRollbackCertificate bool `json:"acceptRollbackCertificate"`
}

// ServingTemp is the temporary name the serving node is renamed to.
func (p Plan) ServingTemp() (string, error) {
	role := tailcontrol.RoleOld
	if p.Kind == Reverse {
		// varlatchd's node gets a temporary name of the reverse operation.
		role = tailcontrol.RoleNew
	}
	return tailcontrol.TempName(p.Name, p.Operation, role)
}

// NewForward is a migration's handoff: the incoming node enrolled under its
// temporary name <name>-vl-<op>-n.
func NewForward(op, name, servingID, incomingID string, certificates bool, retainUntil time.Time) (Plan, error) {
	in, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Kind: Forward, Operation: op, Name: name, ServingID: servingID, IncomingID: incomingID, IncomingName: in, Certificates: certificates, RetainUntil: retainUntil}, nil
}

// NewReverse is a migration's rollback: the retained old node, holding the
// forward handoff's -o name, takes the name back from varlatchd's node.
func NewReverse(op, name, servingID, retainedID, retainedName string, certificates bool) Plan {
	return Plan{Kind: Reverse, Operation: op, Name: name, ServingID: servingID, IncomingID: retainedID, IncomingName: retainedName, Certificates: certificates}
}

// NewRestore is a restore onto a new host: the new node, enrolled under
// <name>-vl-<op>-n, takes the name from the dead one.
func NewRestore(op, name, deadID, incomingID string, certificates bool) (Plan, error) {
	in, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Kind: Restore, Operation: op, Name: name, ServingID: deadID, IncomingID: incomingID, IncomingName: in, Certificates: certificates}, nil
}

// Phase is how far a handoff got.
type Phase string

const (
	Prepared  Phase = "prepared"  // checked; nothing renamed
	Switching Phase = "switching" // under the barrier; Steps says what is done
	Done      Phase = "done"      // the incoming node holds the name and is open
	Undoing   Phase = "undoing"   // the undo is running
	Undone    Phase = "undone"    // the serving node holds the name again and is open
	// UndoPending is an undo the control plane cut short: both
	// installations closed, Resume finishes it.
	UndoPending Phase = "undo-pending"
)

// State is a handoff's journal entry, written after every change, so a
// crash or a lost control plane leaves it resumable.
type State struct {
	Version int   `json:"version"`
	Plan    Plan  `json:"plan"`
	Phase   Phase `json:"phase"`
	// ServingTemp is the serving node's temporary name.
	ServingTemp string `json:"servingTemp"`
	// What the switch did, so an undo reverts exactly that.
	ServingClosed   bool `json:"servingClosed"`
	ServingRenamed  bool `json:"servingRenamed"`
	IncomingRenamed bool `json:"incomingRenamed"`
	IncomingOpened  bool `json:"incomingOpened"`
	// ServingCertExpiry is the serving node's certificate's expiry, read
	// before the barrier (forward; zero without certificates).
	ServingCertExpiry time.Time `json:"servingCertExpiry"`
	// RollbackNeedsCertificate is set when that certificate ends before the
	// rollback window does and the operator accepted it.
	RollbackNeedsCertificate bool `json:"rollbackNeedsCertificate"`
	// ServingGone is set when a Restore's dead node was deleted from the
	// tailnet during the switch: its name was free, and the restored node
	// took it without the dead node's rename (takeFreedName).
	ServingGone bool `json:"servingGone,omitempty"`
	// SwitchStarted is when the first change under the barrier was made.
	SwitchStarted time.Time `json:"switchStarted"`
	// Failure is why a switch was undone, or why an undo is pending.
	Failure string `json:"failure,omitempty"`
}

// StateVersion is the journal entry's format.
const StateVersion = 1

// Journal keeps the handoff's State where its caller keeps its own journal.
type Journal interface {
	// Load answers the operation's State, or nil when there is none.
	Load(ctx context.Context, operation string) (*State, error)
	// Save writes it durably before the handoff goes on.
	Save(ctx context.Context, s *State) error
}

// Certificates is the tailnet's certificates, on either node.
type Certificates interface {
	// Obtain asks a node for a certificate for name: one attempt. A refusal
	// for the CA's rate limit wraps ErrRateLimited; a timeout ends with the
	// context's error; any other error is a fast server error, tried again.
	Obtain(ctx context.Context, node Role, name string) error
	// Expiry is when a node's certificate for name ends, and whether it
	// holds one.
	Expiry(ctx context.Context, node Role, name string) (time.Time, bool, error)
}

// ErrRateLimited is the CA's rate-limit refusal: no attempt follows it.
var ErrRateLimited = errors.New("the certificate authority refused for its rate limit")

// Outcome is how a certificate attempt ended.
type Outcome string

const (
	Issued  Outcome = "issued"
	Refused Outcome = "refused"
)

// Ledger is the installation's issuance count (go-step6.md decision 16;
// the certificate_issuances table): every attempt it started for a name,
// across operations, restores and renewals. An attempt that never ended
// (it timed out) counts as issued, since it may have been.
type Ledger interface {
	// Count is how many attempts for name started at or after since and
	// did not end refused.
	Count(ctx context.Context, name string, since time.Time) (int, error)
	// Start records an attempt before it is made, and answers its id.
	Start(ctx context.Context, name string, at time.Time) (string, error)
	// End records how it ended.
	End(ctx context.Context, id string, outcome Outcome, at time.Time) error
}

// Endpoints is what the two installations do at the switch.
type Endpoints interface {
	// CloseServing closes the serving installation's tailnet listener and
	// every established tailnet connection: a rename does not end them.
	// A dead node's (Restore) does nothing.
	CloseServing(ctx context.Context) error
	// ReopenServing opens it again, after an undo confirmed its name. It
	// does nothing when the listener is already open: after a crash, Resume
	// calls it again whether or not it ran. A Restore's serving node is
	// dead, so the engine never closes or reopens it.
	ReopenServing(ctx context.Context) error
	// OpenIncoming opens the incoming installation's tailnet listener, once
	// its name and certificate are confirmed and a client reaches it. It
	// opens all or nothing: an error means it is not open. Called again
	// after a crash (Resume), it must do nothing when already open.
	OpenIncoming(ctx context.Context) error
}

// Resolver checks from a client node of the tailnet: the control plane's
// device list alone does not prove a name reaches a node.
type Resolver interface {
	// Reaches reports whether name, resolved from a client node, reaches
	// the node with this stable id.
	Reaches(ctx context.Context, name, nodeID string) (bool, error)
}

// Engine runs handoffs. Zero durations take the defaults.
type Engine struct {
	Control   tailcontrol.ControlPlane
	Certs     Certificates // nil when no plan uses certificates
	Ledger    Ledger       // nil when no plan uses certificates
	Endpoints Endpoints
	Resolver  Resolver
	Journal   Journal

	Deadline     time.Duration
	CertWait     time.Duration
	CertAttempts int
	UndoWait     time.Duration
	// RetryEvery is the wait between tries of a control-plane call that
	// failed in a way that may pass (a server restarting); 1 s by default.
	RetryEvery time.Duration
	// Waiting, when set, is told the name a rename waits for the control
	// plane to release (tailcontrol.RenameReleased), once per wait: a
	// progress line for the operator. It must not block.
	Waiting func(name string)
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// HandoffError is a failed handoff: what failed, and in which phase the
// handoff stands now (Prepared when it failed before any change, Undone
// when the undo returned the name, UndoPending when it is to be resumed,
// Switching when a resumed open could not be verified again: the incoming
// installation may be open, so nothing is undone).
type HandoffError struct {
	Phase Phase
	Err   error
}

func (e *HandoffError) Error() string {
	switch e.Phase {
	case Undone:
		return fmt.Sprintf("the handoff failed and was undone, the serving installation is open again at its name: %v", e.Err)
	case Switching:
		return fmt.Sprintf("the handoff was interrupted while opening the incoming installation and its name, certificate or reach could not be verified again: the incoming installation may be open, so it is not undone (an undo would take the name from an open listener); close the incoming installation, or run a reverse handoff, or resume it once the check holds: %v", e.Err)
	case UndoPending:
		// A device holding the name is the operator's step, so it leads,
		// even when the device the name was to go back to is gone too.
		// A refusal no listed device explains is said as such: there is no
		// device to look for in the listing.
		if unlisted := (*UnlistedHolderError)(nil); errors.As(e.Err, &unlisted) {
			return fmt.Sprintf("the handoff failed and its undo could not give the name %s back: the tailnet's control plane still refuses it as taken, but lists no device holding it, and neither installation is opened on the tailnet. Look the name up in the tailnet's admin console, correct its assignment there if needed, then resume (varlatch migrate --resume): %v", unlisted.Name, e.Err)
		}
		if errors.Is(e.Err, tailcontrol.ErrNameTaken) {
			return fmt.Sprintf("the handoff failed and its undo could not give a name back: another device holds it now, and neither installation is opened on the tailnet. Rename or delete that device in the tailnet's admin console, then resume: %v", e.Err)
		}
		if gone := (*GoneError)(nil); errors.As(e.Err, &gone) {
			return fmt.Sprintf("the handoff failed and its undo cannot give the name back: the device %s is no longer in the tailnet (deleted during the handoff), and neither installation is opened on the tailnet: %v", gone.ID, e.Err)
		}
		return fmt.Sprintf("the handoff failed and its undo could not finish: neither installation is opened on the tailnet (the serving one closed, or closing when the failure came first); resume it once the control plane answers: %v", e.Err)
	default:
		return fmt.Sprintf("the handoff did not start: %v", e.Err)
	}
}

func (e *HandoffError) Unwrap() error { return e.Err }

// Prepare checks a plan before any barrier and journals it. Nothing is
// renamed and no installation closed; a refusal leaves everything as it
// was.
func (e *Engine) Prepare(ctx context.Context, p Plan) (*State, error) {
	fail := func(err error) (*State, error) { return nil, &HandoffError{Phase: Prepared, Err: err} }
	if p.Kind != Forward && p.Kind != Reverse && p.Kind != Restore {
		return fail(fmt.Errorf("unknown handoff %q", p.Kind))
	}
	if p.ServingID == "" || p.IncomingID == "" || p.ServingID == p.IncomingID {
		return fail(errors.New("the serving and the incoming node must be two nodes"))
	}
	servingTemp, err := p.ServingTemp()
	if err != nil {
		return fail(err)
	}
	if !tailcontrol.Canonical(p.IncomingName) {
		return fail(fmt.Errorf("the incoming node's name %q is not in canonical form", p.IncomingName))
	}
	if prev, err := e.Journal.Load(ctx, p.Operation); err != nil {
		return fail(fmt.Errorf("reading the journal: %w", err))
	} else if prev != nil && prev.Phase != Prepared {
		return fail(fmt.Errorf("operation %s is already %s", p.Operation, prev.Phase))
	}
	if p.Certificates && (e.Certs == nil || e.Ledger == nil) {
		return fail(errors.New("the plan uses certificates, but the engine has no certificates or issuance count"))
	}
	devices, err := e.Control.Devices(ctx)
	if err != nil {
		return fail(err)
	}
	if err := checkPlanNames(devices, p, servingTemp); err != nil {
		return fail(err)
	}
	s := &State{Version: StateVersion, Plan: p, Phase: Prepared, ServingTemp: servingTemp}
	if p.Certificates {
		// The name's certificate is needed under the barrier: refuse now
		// if the count would pass the CA's weekly limit. A reverse to the
		// retained node, whose certificate is still valid, issues none.
		cached := false
		if p.Kind == Reverse {
			if expiry, ok, err := e.Certs.Expiry(ctx, Incoming, p.Name); err == nil && ok && expiry.After(e.now()) {
				cached = true
			}
		}
		if !cached {
			if err := e.allowIssuance(ctx, p.Name, 1); err != nil {
				return fail(err)
			}
		}
		if p.Kind == Forward {
			// Proven now, outside the downtime: the incoming node obtains
			// a certificate for its temporary name.
			if err := e.obtain(ctx, Incoming, p.IncomingName, e.now().Add(orDefault(e.CertWait, DefaultCertWait))); err != nil {
				return fail(fmt.Errorf("the incoming node cannot obtain a certificate for %s now: %w", p.IncomingName, err))
			}
			if err := e.checkServingCertificate(ctx, s); err != nil {
				return fail(err)
			}
		}
	}
	if err := e.Journal.Save(ctx, s); err != nil {
		return fail(fmt.Errorf("writing the journal: %w", err))
	}
	return s, nil
}

// checkPlanNames is Prepare's name check, case-insensitive against every
// device: the name held by exactly the serving node, its temporary name
// free, and the incoming node listed under exactly its current name, which
// no other node holds (an enrolment under a taken name comes back
// suffixed, -1).
func checkPlanNames(devices []tailcontrol.Device, p Plan, servingTemp string) error {
	if err := tailcontrol.CheckNames(devices, tailcontrol.NamePlan{Name: p.Name, Holder: p.ServingID, Temporary: []string{servingTemp}}); err != nil {
		return err
	}
	var in *tailcontrol.Device
	for i, d := range devices {
		if d.ID == p.IncomingID {
			in = &devices[i]
		} else if strings.EqualFold(d.Name, p.IncomingName) {
			return fmt.Errorf("the incoming node's name %q is also held by %s", p.IncomingName, d)
		}
	}
	switch {
	case in == nil:
		return fmt.Errorf("the control plane does not list the incoming node %s", p.IncomingID)
	case in.Name != p.IncomingName:
		return fmt.Errorf("the incoming node %s is listed as %q, not %q (an enrolment under a taken name is suffixed)", p.IncomingID, in.Name, p.IncomingName)
	}
	return nil
}

// checkServingCertificate reads the serving node's certificate for the name
// before the barrier: it must last through the rollback window and seven
// days more, or be renewed now, while the node still holds the name. When
// renewing fails, the operator's acceptance of a new certificate on a
// rollback is required.
func (e *Engine) checkServingCertificate(ctx context.Context, s *State) error {
	p := s.Plan
	expiry, ok, err := e.Certs.Expiry(ctx, Serving, p.Name)
	if err != nil {
		return fmt.Errorf("reading the serving node's certificate: %w", err)
	}
	if ok && !expiry.Before(p.RetainUntil.Add(RenewMargin)) {
		s.ServingCertExpiry = expiry
		return nil
	}
	// The renewal is one issuance for the name, and the switch needs
	// another: both must fit the CA's weekly limit, or neither is spent.
	if err := e.allowIssuance(ctx, p.Name, 2); err != nil {
		return fmt.Errorf("the serving node's certificate for %s must be renewed before the barrier: %w", p.Name, err)
	}
	renewErr := e.obtain(ctx, Serving, p.Name, e.now().Add(orDefault(e.CertWait, DefaultCertWait)))
	if renewErr == nil {
		expiry, ok, err = e.Certs.Expiry(ctx, Serving, p.Name)
		if err == nil && ok && !expiry.Before(p.RetainUntil.Add(RenewMargin)) {
			s.ServingCertExpiry = expiry
			return nil
		}
		if err == nil {
			renewErr = fmt.Errorf("the renewed certificate ends at %s, before the rollback window does (the CA's lifetimes are shorter than the window)", expiry.UTC().Format(time.RFC3339))
		} else {
			renewErr = err
		}
	}
	if !p.AcceptRollbackCertificate {
		return fmt.Errorf("the serving node's certificate for %s will not last through the rollback window and could not be renewed (%v): a rollback after it ends needs a new certificate, about 40 s of downtime and one issuance; accept that to go on (varlatch migrate --accept-rollback-certificate)", p.Name, renewErr)
	}
	s.ServingCertExpiry = expiry
	s.RollbackNeedsCertificate = true
	return nil
}

// Switch runs a prepared handoff under the barrier. It answers the final
// State: Done, or, with a HandoffError, Undone or UndoPending.
func (e *Engine) Switch(ctx context.Context, operation string) (*State, error) {
	s, err := e.Journal.Load(ctx, operation)
	if err != nil {
		return nil, fmt.Errorf("reading the journal: %w", err)
	}
	if s == nil || s.Phase != Prepared {
		phase := Phase("none")
		if s != nil {
			phase = s.Phase
		}
		return s, fmt.Errorf("operation %s is %s, not prepared", operation, phase)
	}
	s.Phase = Switching
	s.SwitchStarted = e.now()
	if err := e.Journal.Save(ctx, s); err != nil {
		return s, fmt.Errorf("writing the journal: %w", err)
	}
	// One deadline from the first change to the final check.
	sctx, cancel := context.WithDeadline(ctx, s.SwitchStarted.Add(orDefault(e.Deadline, DefaultDeadline)))
	defer cancel()
	if err := e.switchSteps(sctx, s); err != nil {
		return e.undo(ctx, s, err)
	}
	return s, nil
}

func (e *Engine) save(ctx context.Context, s *State) error {
	if err := e.Journal.Save(ctx, s); err != nil {
		return fmt.Errorf("writing the journal: %w", err)
	}
	return nil
}

func (e *Engine) switchSteps(ctx context.Context, s *State) error {
	p := s.Plan
	// The serving installation lets go first: a rename does not end an
	// established connection. A Restore's serving node is dead: there is
	// nothing to close, and so nothing to reopen.
	if p.Kind != Restore {
		s.ServingClosed = true
		if err := e.save(ctx, s); err != nil {
			return err
		}
		if err := e.Endpoints.CloseServing(ctx); err != nil {
			return fmt.Errorf("closing the serving installation's tailnet listener: %w", err)
		}
	}
	// The two renames, back to back; each recorded before it is made, so an
	// undo after a crash checks it whichever way it went.
	s.ServingRenamed = true
	if err := e.save(ctx, s); err != nil {
		return err
	}
	if err := e.rename(ctx, p.ServingID, s.ServingTemp); err != nil {
		return err
	}
	return e.incomingSteps(ctx, s)
}

// incomingSteps is the switch once the name is free: the incoming node
// renamed to it, its certificate, a client's reach, then the open.
func (e *Engine) incomingSteps(ctx context.Context, s *State) error {
	p := s.Plan
	s.IncomingRenamed = true
	if err := e.save(ctx, s); err != nil {
		return err
	}
	if err := e.rename(ctx, p.IncomingID, p.Name); err != nil {
		return err
	}
	if p.Certificates {
		if err := e.nameCertificate(ctx, s); err != nil {
			return err
		}
	}
	nodeID, err := e.incomingStableID(ctx, p.IncomingID)
	if err != nil {
		return err
	}
	if err := e.reaches(ctx, p.Name, nodeID); err != nil {
		return err
	}
	s.IncomingOpened = true
	if err := e.save(ctx, s); err != nil {
		return err
	}
	if err := e.Endpoints.OpenIncoming(ctx); err != nil {
		// It did not open (OpenIncoming is all or nothing): the undo may
		// take the name back.
		s.IncomingOpened = false
		return errors.Join(fmt.Errorf("opening the incoming installation: %w", err), e.save(ctx, s))
	}
	s.Phase = Done
	return e.save(ctx, s)
}

// nameCertificate gets the name's certificate on the incoming node: a valid
// one it holds already (a reverse to the retained node before its
// certificate's expiry issues none), else one obtained now.
func (e *Engine) nameCertificate(ctx context.Context, s *State) error {
	p := s.Plan
	if expiry, ok, err := e.Certs.Expiry(ctx, Incoming, p.Name); err == nil && ok && expiry.After(e.now()) {
		return nil
	}
	if err := e.allowIssuance(ctx, p.Name, 1); err != nil {
		return err
	}
	wait := e.now().Add(orDefault(e.CertWait, DefaultCertWait))
	if dl, ok := ctx.Deadline(); ok && dl.Before(wait) {
		wait = dl
	}
	if err := e.obtain(ctx, Incoming, p.Name, wait); err != nil {
		return fmt.Errorf("the incoming node's certificate for %s: %w", p.Name, err)
	}
	return nil
}

// allowIssuance refuses when requesting need more certificates for name
// would pass the CA's weekly limit, by the installation's own count.
func (e *Engine) allowIssuance(ctx context.Context, name string, need int) error {
	n, err := e.Ledger.Count(ctx, name, e.now().Add(-7*24*time.Hour))
	if err != nil {
		return fmt.Errorf("reading the certificate issuance count: %w", err)
	}
	if n+need > WeeklyLimit {
		more := "one more"
		if need > 1 {
			more = fmt.Sprintf("%d more", need)
		}
		return fmt.Errorf("%d certificates for %s were requested in the last seven days: %s would pass the CA's limit of %d per name per week", n, name, more, WeeklyLimit)
	}
	return nil
}

// obtain makes up to CertAttempts attempts before until, each counted
// before it is made: a fast server error is tried again, a rate-limit
// refusal ends at once, and a timed-out attempt stays counted as issued.
func (e *Engine) obtain(ctx context.Context, node Role, name string, until time.Time) error {
	cctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	attempts := e.CertAttempts
	if attempts <= 0 {
		attempts = DefaultCertAttempts
	}
	var last error
	for i := 0; i < attempts; i++ {
		id, err := e.Ledger.Start(cctx, name, e.now())
		if err != nil {
			return fmt.Errorf("recording the certificate attempt: %w", err)
		}
		err = e.Certs.Obtain(cctx, node, name)
		switch {
		case err == nil:
			return e.Ledger.End(ctx, id, Issued, e.now())
		case cctx.Err() != nil:
			// Timed out: it may have been issued, so it stays counted.
			return fmt.Errorf("no certificate in time: %w", errors.Join(err, cctx.Err()))
		case errors.Is(err, ErrRateLimited):
			_ = e.Ledger.End(ctx, id, Refused, e.now())
			return err
		}
		_ = e.Ledger.End(ctx, id, Refused, e.now())
		last = err
	}
	return fmt.Errorf("%d attempts failed: %w", attempts, last)
}

// rename renames a device and reads it back, trying again while the
// control plane fails in a way that may pass (a restart, a lost
// connection) until ctx ends. A name the control plane has not released
// yet is waited for, within tailcontrol.ReleaseBudget and ctx
// (renameReleased); after that, a taken name or a read-back that differs
// is final.
func (e *Engine) rename(ctx context.Context, id, name string) error {
	return e.retry(ctx, func() error {
		err := e.renameReleased(ctx, id, name)
		if err != nil && !final(err) && e.unlisted(ctx, id) {
			return &GoneError{ID: id}
		}
		return err
	})
}

// renameReleased is tailcontrol.RenameReleased, telling Waiting.
func (e *Engine) renameReleased(ctx context.Context, id, name string) error {
	var waiting func()
	if e.Waiting != nil {
		waiting = func() { e.Waiting(name) }
	}
	_, err := tailcontrol.RenameReleased(ctx, e.Control, id, name, waiting)
	return err
}

// GoneError is a device the control plane no longer lists: deleted from
// the tailnet. Trying again does not bring it back.
type GoneError struct{ ID string }

func (e *GoneError) Error() string {
	return fmt.Sprintf("the control plane no longer lists the device %s (deleted from the tailnet)", e.ID)
}

// unlisted reports whether a listing that answers lacks the device.
func (e *Engine) unlisted(ctx context.Context, id string) bool {
	devices, err := e.Control.Devices(ctx)
	return err == nil && !slices.ContainsFunc(devices, func(d tailcontrol.Device) bool { return d.ID == id })
}

// goneDevice reports whether a failure is that device's being gone.
func goneDevice(err error, id string) bool {
	var gone *GoneError
	return errors.As(err, &gone) && gone.ID == id
}

// PermanentError is a failure that trying again does not change: a program
// or a file that is not there, or not permitted. A check that fails so is
// not tried again.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// final reports whether a control-plane failure will not pass by trying
// again.
func final(err error) bool {
	var rb *tailcontrol.ReadBackError
	var gone *GoneError
	var perm *PermanentError
	return errors.Is(err, tailcontrol.ErrNameTaken) || errors.As(err, &rb) || errors.As(err, &gone) || errors.As(err, &perm)
}

func (e *Engine) retry(ctx context.Context, f func() error) error {
	every := orDefault(e.RetryEvery, time.Second)
	for {
		err := f()
		if err == nil || final(err) {
			return err
		}
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(every):
		}
	}
}

// incomingStableID is the id a client's resolution must reach: the node's
// stable id (Tailscale's nodeId), or its control-plane id.
func (e *Engine) incomingStableID(ctx context.Context, id string) (string, error) {
	var nodeID string
	err := e.retry(ctx, func() error {
		devices, err := e.Control.Devices(ctx)
		if err != nil {
			return err
		}
		for _, d := range devices {
			if d.ID == id {
				nodeID = d.NodeID
				if nodeID == "" {
					nodeID = d.ID
				}
				return nil
			}
		}
		return fmt.Errorf("the incoming node %s is no longer listed", id)
	})
	return nodeID, err
}

// reaches waits until name, from a client node, reaches the node; the
// operation's deadline bounds it.
func (e *Engine) reaches(ctx context.Context, name, nodeID string) error {
	every := orDefault(e.RetryEvery, time.Second)
	for {
		ok, err := e.Resolver.Reaches(ctx, name, nodeID)
		if err == nil && ok {
			return nil
		}
		if final(err) {
			return fmt.Errorf("%s does not reach the incoming node from a client: %w", name, err)
		}
		select {
		case <-ctx.Done():
			// Whatever the last check answered, what failed is the reach.
			// The last check's error is kept unless it is the deadline
			// itself, so the deadline is said once.
			cause := ctx.Err()
			if err != nil && !errors.Is(err, cause) {
				cause = errors.Join(err, cause)
			}
			return fmt.Errorf("%s does not reach the incoming node from a client: %w", name, cause)
		case <-time.After(every):
		}
	}
}

// undo returns the serving installation to its name after a failed switch.
// It runs on a context of its own (the switch's deadline may be what
// failed), for UndoWait.
func (e *Engine) undo(ctx context.Context, s *State, cause error) (*State, error) {
	return e.undoOrForward(ctx, s, cause, true)
}

// undoOrForward is undo; with forward, a Restore whose dead node was
// deleted from the tailnet is finished forward instead (takeFreedName):
// its name is free, and nothing is left to give it back to.
func (e *Engine) undoOrForward(ctx context.Context, s *State, cause error, forward bool) (*State, error) {
	s.Phase = Undoing
	s.Failure = cause.Error()
	if err := e.Journal.Save(ctx, s); err != nil {
		return s, &HandoffError{Phase: UndoPending, Err: errors.Join(cause, fmt.Errorf("writing the journal: %w", err))}
	}
	if err := e.undoSteps(ctx, s); err != nil {
		if forward && s.Plan.Kind == Restore && !s.IncomingOpened && goneDevice(err, s.Plan.ServingID) {
			return e.takeFreedName(ctx, s)
		}
		s.Phase = UndoPending
		s.Failure = errors.Join(cause, err).Error()
		_ = e.Journal.Save(ctx, s)
		return s, &HandoffError{Phase: UndoPending, Err: errors.Join(cause, err)}
	}
	s.Phase = Undone
	if err := e.Journal.Save(ctx, s); err != nil {
		return s, &HandoffError{Phase: Undone, Err: errors.Join(cause, fmt.Errorf("writing the journal: %w", err))}
	}
	return s, &HandoffError{Phase: Undone, Err: cause}
}

// undoSteps reverts what the switch did, from the control plane's own
// listing, so it holds whichever way an interrupted step went: the
// incoming node back to its name of before, the serving node back to the
// name (read back), then the serving installation reopened. Nothing is
// reopened before the name is confirmed.
func (e *Engine) undoSteps(parent context.Context, s *State) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), orDefault(e.UndoWait, DefaultUndoWait))
	defer cancel()
	p := s.Plan
	if s.IncomingOpened {
		// The incoming installation opened: it is not closed by an undo of
		// the handoff; that is a rollback (a reverse handoff).
		return errors.New("the incoming installation is open: undo it with a reverse handoff, not an undo")
	}
	if s.IncomingRenamed {
		if err := e.retry(ctx, func() error { return e.restoreName(ctx, p.IncomingID, p.IncomingName) }); err != nil {
			return fmt.Errorf("giving the incoming node back %s: %w", p.IncomingName, err)
		}
	}
	if s.ServingRenamed {
		if err := e.retry(ctx, func() error { return e.restoreName(ctx, p.ServingID, p.Name) }); err != nil {
			return fmt.Errorf("giving the serving node back %s: %w", p.Name, err)
		}
	}
	// The name is the serving node's again, read back: only now may it open.
	if err := e.retry(ctx, func() error { return e.confirm(ctx, p.ServingID, p.Name) }); err != nil {
		return err
	}
	if s.ServingClosed && p.Kind != Restore {
		if err := e.retry(ctx, func() error { return e.Endpoints.ReopenServing(ctx) }); err != nil {
			return fmt.Errorf("reopening the serving installation: %w", err)
		}
	}
	return nil
}

// takeFreedName finishes a Restore forward once its dead node is gone from
// the tailnet (deleted by the operator mid-handoff): the name is free, so
// the restored node takes it, under a deadline of its own, without the dead
// node's rename. If that fails, the restored node is given its own name
// back and the undo is pending (resumed, it tries forward again).
func (e *Engine) takeFreedName(ctx context.Context, s *State) (*State, error) {
	s.Phase, s.ServingGone, s.Failure = Switching, true, ""
	s.SwitchStarted = e.now()
	if err := e.save(ctx, s); err != nil {
		return s, &HandoffError{Phase: UndoPending, Err: err}
	}
	sctx, cancel := context.WithDeadline(ctx, s.SwitchStarted.Add(orDefault(e.Deadline, DefaultDeadline)))
	defer cancel()
	if err := e.incomingSteps(sctx, s); err != nil {
		cause := fmt.Errorf("the dead node %s was deleted from the tailnet, and the restored node could not take its free name: %w", s.Plan.ServingID, err)
		if errors.Is(err, tailcontrol.ErrNameTaken) {
			// Another device took the freed name first: name it.
			cause = fmt.Errorf("the dead node %s was deleted from the tailnet, and another device took its free name before the restored node could: %w", s.Plan.ServingID, err)
			if holder, ok := e.holder(ctx, s.Plan.Name, s.Plan.IncomingID, nil); ok {
				cause = fmt.Errorf("the dead node %s was deleted from the tailnet, and %s took its free name before the restored node could: %w", s.Plan.ServingID, holder, err)
			}
		}
		return e.undoOrForward(ctx, s, cause, false)
	}
	return s, nil
}

// holder is the device other than except holding name: from devices when
// it is there, else from a fresh listing.
func (e *Engine) holder(ctx context.Context, name, except string, devices []tailcontrol.Device) (tailcontrol.Device, bool) {
	find := func(ds []tailcontrol.Device) (tailcontrol.Device, bool) {
		for _, d := range ds {
			if d.ID != except && strings.EqualFold(d.Name, name) {
				return d, true
			}
		}
		return tailcontrol.Device{}, false
	}
	if d, ok := find(devices); ok {
		return d, true
	}
	if again, err := e.Control.Devices(ctx); err == nil {
		return find(again)
	}
	return tailcontrol.Device{}, false
}

// restoreName renames a device to name unless it is listed under it
// already, waiting for the control plane to release a name let go of a
// moment ago (renameReleased); a device no longer listed is gone
// (GoneError).
func (e *Engine) restoreName(ctx context.Context, id, name string) error {
	devices, err := e.Control.Devices(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(devices, func(d tailcontrol.Device) bool { return d.ID == id }) {
		return &GoneError{ID: id}
	}
	for _, d := range devices {
		if d.ID == id && d.Name == name {
			return nil
		}
	}
	err = e.renameReleased(ctx, id, name)
	if errors.Is(err, tailcontrol.ErrNameTaken) {
		// Another device took the name while it was free: say which, so
		// the operator can rename or delete it. When a fresh listing shows
		// none, say that instead: the refusal is the control plane's own.
		if d, ok := e.holder(ctx, name, id, devices); ok {
			return fmt.Errorf("%w: it is held by %s now", err, d)
		}
		if again, lerr := e.Control.Devices(ctx); lerr == nil && !slices.ContainsFunc(again, func(d tailcontrol.Device) bool {
			return d.ID != id && strings.EqualFold(d.Name, name)
		}) {
			return &UnlistedHolderError{Name: name, Err: err}
		}
	}
	return err
}

// UnlistedHolderError is a rename refused as taken while the control plane
// lists no other device under the name: kept refusing through the wait for
// its release (tailcontrol.RenameReleased).
type UnlistedHolderError struct {
	Name string
	Err  error
}

func (e *UnlistedHolderError) Error() string {
	return fmt.Sprintf("%v (no device is listed under %s)", e.Err, e.Name)
}

func (e *UnlistedHolderError) Unwrap() error { return e.Err }

func (e *Engine) confirm(ctx context.Context, id, name string) error {
	devices, err := e.Control.Devices(ctx)
	if err != nil {
		return err
	}
	for _, d := range devices {
		if d.ID == id {
			if d.Name != name {
				return &tailcontrol.ReadBackError{Want: name, Got: d.Name}
			}
			return nil
		}
	}
	return &GoneError{ID: id}
}

// finishOpen completes a switch interrupted after it decided to open the
// incoming installation: the name is read back again first.
func (e *Engine) finishOpen(ctx context.Context, s *State) (*State, error) {
	// Everything the open rested on is checked again, under a deadline of
	// its own: the name, the certificate and a client's reach. The crash may
	// have come after the listener opened, so a failed check is not undone
	// (undoSteps refuses an open incoming installation for the same reason):
	// the journal keeps IncomingOpened and the failure, and the operator
	// closes the incoming installation, runs a reverse handoff, or resumes
	// once the check holds.
	vctx, cancel := context.WithTimeout(ctx, orDefault(e.Deadline, DefaultDeadline))
	defer cancel()
	verify := func() error {
		if err := e.retry(vctx, func() error { return e.confirm(vctx, s.Plan.IncomingID, s.Plan.Name) }); err != nil {
			return fmt.Errorf("the incoming node's name before opening it: %w", err)
		}
		if s.Plan.Certificates {
			if err := e.nameCertificate(vctx, s); err != nil {
				return err
			}
		}
		nodeID, err := e.incomingStableID(vctx, s.Plan.IncomingID)
		if err != nil {
			return err
		}
		return e.reaches(vctx, s.Plan.Name, nodeID)
	}
	if err := verify(); err != nil {
		s.Failure = err.Error()
		if serr := e.save(ctx, s); serr != nil {
			err = errors.Join(err, serr)
		}
		return s, &HandoffError{Phase: Switching, Err: err}
	}
	if err := e.Endpoints.OpenIncoming(ctx); err != nil {
		// It is not open (OpenIncoming is all or nothing, and does nothing
		// when open already): the undo may take the name back.
		s.IncomingOpened = false
		return e.undo(ctx, s, fmt.Errorf("opening the incoming installation: %w", err))
	}
	s.Phase = Done
	return s, e.save(ctx, s)
}

// Resume finishes a handoff a crash or a lost control plane interrupted: a
// switch that did not finish, or an undo, is undone (the serving
// installation takes its name back and reopens), except one interrupted
// while opening the incoming installation, which is finished if its checks
// hold again and otherwise left as it is (finishOpen); a prepared, done or
// undone one is answered as it is.
func (e *Engine) Resume(ctx context.Context, operation string) (*State, error) {
	s, err := e.Journal.Load(ctx, operation)
	if err != nil {
		return nil, fmt.Errorf("reading the journal: %w", err)
	}
	if s == nil {
		return nil, fmt.Errorf("no handoff %s in the journal", operation)
	}
	switch s.Phase {
	case Switching:
		if s.IncomingOpened {
			// Interrupted while opening the incoming installation: its name
			// and certificate were confirmed and a client reached it, so the
			// handoff is finished, not undone.
			return e.finishOpen(ctx, s)
		}
		fallthrough
	case Undoing, UndoPending:
		cause := errors.New("resumed after an interruption")
		if s.Failure != "" {
			cause = errors.New(s.Failure)
		}
		return e.undo(ctx, s, cause)
	}
	return s, nil
}
