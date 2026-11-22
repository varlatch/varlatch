// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// The tailnet handoff in a migration (go-step7 decisions 11 and 12, slice
// 7.5b): when the source serves a tailnet address (its Tailscale
// sidecar), the name moves to the target's own node, by rename.
//
//   - Preflight: the target's node enrolls under its temporary name
//     (<name>-vl-<op>-n), held, with a certificate when the tailnet serves
//     Tailscale HTTPS (varlatchd admin tailnet enroll); its pin must be the
//     source's tailnet; then tailhandoff's Prepare (the names, the
//     issuance count, the old node's certificate against the rollback
//     window). Nothing is renamed.
//   - The transfer, after the public or Coolify address answers from the
//     target (decision 12's fixed order): tailhandoff's Switch (the
//     sidecar stopped without logging out, both renames read back, the
//     certificate, a client node's reach, the target's tailnet listener
//     opened), then the combined final check, the public URL again.
//   - An undo before the switch gives the tailnet name back first, then the
//     address: an unfinished handoff is resumed (which undoes it), a done
//     one reversed.
//
// The handoff's state is journalled in migrate's journal, both places,
// before each act (tailhandoff.Journal). The control plane's authority is
// the operator's (O4: a Tailscale OAuth client with devices:core only),
// given in a file, never an argument or the environment; so is the new
// node's auth key, written to the target's tailnet_auth_key_file through
// admin migrate keys. Tailscale only: Headscale support in varlatchd is
// slice 7.5c.

// TailnetInfo is a source's tailnet ingress.
type TailnetInfo struct {
	// Enabled is the Tailscale sidecar in the source's Compose project.
	Enabled bool `json:"enabled"`
	// Machine is the sidecar's node name (VARLATCH_TAILNET_MACHINE,
	// "varlatch" by default): the name that moves.
	Machine string `json:"machine"`
	// Suffix is the tailnet's MagicDNS suffix (VARLATCH_TAILNET_NAME), the
	// one the TypeScript server pins.
	Suffix string `json:"suffix"`
	// HTTPS is the tailnet HTTPS overlay: Tailscale certificates follow
	// the name.
	HTTPS bool `json:"https"`
}

// TailnetSource is a source's tailnet side.
type TailnetSource interface {
	Tailnet(ctx context.Context) (TailnetInfo, error)
	// StopTailnet stops the sidecar without logging out (its state is kept
	// for the rollback window), closing every connection through it.
	StopTailnet(ctx context.Context) error
	// StartTailnet starts it again, and the server that shares its network.
	StartTailnet(ctx context.Context) error
	// TailnetCertExpiry is when the sidecar's cached certificate for
	// domain ends (false: none), read without asking for one.
	TailnetCertExpiry(ctx context.Context, domain string) (time.Time, bool, error)
	// RenewTailnetCert asks the sidecar for a certificate for domain valid
	// at least minValidity.
	RenewTailnetCert(ctx context.Context, domain string, minValidity time.Duration) error
}

// TargetTailnet is a target's tailnet settings and its node's handoff
// state (admin migrate state's).
type TargetTailnet struct {
	Hostname  string   `json:"hostname"`
	Tags      []string `json:"tags"`
	HTTPSPort int      `json:"httpsPort"`
	AuthKey   bool     `json:"authKey"`
	Enrolled  bool     `json:"enrolled"`
	HeldAs    string   `json:"heldAs"`
	PinnedTo  string   `json:"pinnedTo"`
}

// EnrolledNode is varlatchd admin tailnet enroll's answer.
type EnrolledNode struct {
	DNSName             string     `json:"dnsName"`
	StableID            string     `json:"stableId"`
	Suffix              string     `json:"suffix"`
	Pinned              string     `json:"pinned"`
	Open                bool       `json:"open"`
	CertificateNotAfter *time.Time `json:"certificateNotAfter,omitempty"`
}

// TailnetTarget is a target's tailnet side: its node's handoff commands.
type TailnetTarget interface {
	TailnetEnroll(ctx context.Context, hostname string, certificate bool) (EnrolledNode, error)
	// TailnetCertificate is one attempt at the node's certificate for name;
	// a rate-limit refusal wraps tailhandoff.ErrRateLimited.
	TailnetCertificate(ctx context.Context, name string) error
	TailnetCertExpiry(ctx context.Context, name string) (time.Time, bool, error)
	TailnetOpen(ctx context.Context) error
	TailnetReaches(ctx context.Context, name, stableID string, wait time.Duration) (bool, error)
}

// TailnetOptions are the handoff's authority and limits; nil when the
// migration has none (the source serves no tailnet address).
type TailnetOptions struct {
	// Control is the tailnet's control plane, built with the operator's
	// OAuth client and the CLI's own *http.Client.
	Control tailcontrol.ControlPlane
	// Deadline, UndoWait and RetryEvery are tailhandoff's (zero: its
	// defaults).
	Deadline, UndoWait, RetryEvery time.Duration
	// AcceptRollbackCertificate is tailhandoff's: a rollback after the old
	// node's certificate ends needs a new one.
	AcceptRollbackCertificate bool
}

// TailnetRecord is the handoff, as the journal holds it.
type TailnetRecord struct {
	Name         string `json:"name"`
	Suffix       string `json:"suffix"`
	Operation    string `json:"operation"`
	Certificates bool   `json:"certificates"`
	ServingID    string `json:"servingId"`
	IncomingID   string `json:"incomingId"`
	StableID     string `json:"stableId"`
	// Handoff is the forward handoff's state; Reverse the one that undoes
	// it, when it was done and the migration is undone before its switch;
	// Rollback a reverse migration's (--rollback), under its own operation.
	Handoff           *tailhandoff.State `json:"handoff,omitempty"`
	Reverse           *tailhandoff.State `json:"reverse,omitempty"`
	Rollback          *tailhandoff.State `json:"rollback,omitempty"`
	RollbackOperation string             `json:"rollbackOperation,omitempty"`
	// Checked is when the combined final check passed (decision 12).
	Checked string `json:"checked,omitempty"`
	// Recorded is set, in the source's journal, once the ledger's
	// attempts are in Go's count; until then --finish, a finished
	// migration's included, writes them again (issuances.go).
	Recorded bool `json:"recorded,omitempty"`
}

// ErrNoTailnetAuthority is a source with a tailnet address and no
// authority given.
var ErrNoTailnetAuthority = errors.New("the source serves a tailnet address: the handoff needs the tailnet's authority (--tailscale-oauth-client-file, an OAuth client with the devices:core scope only) and the new node's auth key (--tailnet-auth-key-file)")

// tailnetSides are the two sides' tailnet halves.
func (e *Engine) tailnetSides() (TailnetSource, TailnetTarget, error) {
	ts, ok := e.Source.(TailnetSource)
	if !ok {
		return nil, nil, errors.New("this source has no tailnet side")
	}
	tt, ok := e.Target.(TailnetTarget)
	if !ok {
		return nil, nil, errors.New("this target has no tailnet side")
	}
	return ts, tt, nil
}

// handoffSlot is which of the journal's handoffs: the forward one, the
// reverse that undoes it before the switch, or a rollback's.
type handoffSlot int

const (
	slotForward handoffSlot = iota
	slotUndo
	slotRollback
)

// handoffJournal keeps the handoff's state in migrate's journal (its
// slot), written in both places before the handoff goes on.
type handoffJournal struct {
	e    *Engine
	j    *Journal
	slot handoffSlot
}

func (h handoffJournal) at() **tailhandoff.State {
	switch h.slot {
	case slotUndo:
		return &h.j.Tailnet.Reverse
	case slotRollback:
		return &h.j.Tailnet.Rollback
	}
	return &h.j.Tailnet.Handoff
}

func (h handoffJournal) Load(_ context.Context, op string) (*tailhandoff.State, error) {
	s := *h.at()
	if s == nil || s.Plan.Operation != op {
		return nil, nil
	}
	c := *s
	return &c, nil
}

func (h handoffJournal) Save(ctx context.Context, s *tailhandoff.State) error {
	c := *s
	*h.at() = &c
	return h.e.save(ctx, h.j)
}

// handoffCerts are the certificates on either node: the sidecar's
// (serving, forward) and the target's (incoming).
type handoffCerts struct {
	src     TailnetSource
	tgt     TailnetTarget
	suffix  string
	retain  time.Time
	now     func() time.Time
	reverse bool
}

func (c handoffCerts) onSource(role tailhandoff.Role) bool {
	return (role == tailhandoff.Serving) != c.reverse
}

func (c handoffCerts) Obtain(ctx context.Context, role tailhandoff.Role, name string) error {
	if c.onSource(role) {
		// The old node's renewal (forward, before the barrier): valid until
		// the rollback window's end and its margin.
		min := c.retain.Add(tailhandoff.RenewMargin).Sub(c.now())
		if min < 24*time.Hour {
			min = 24 * time.Hour
		}
		return c.src.RenewTailnetCert(ctx, name+"."+c.suffix, min)
	}
	return c.tgt.TailnetCertificate(ctx, name)
}

func (c handoffCerts) Expiry(ctx context.Context, role tailhandoff.Role, name string) (time.Time, bool, error) {
	if c.onSource(role) {
		return c.src.TailnetCertExpiry(ctx, name+"."+c.suffix)
	}
	return c.tgt.TailnetCertExpiry(ctx, name)
}

// handoffEndpoints are the listeners: forward, the sidecar serves and the
// target takes over; reverse (an undo before the switch), the other way.
type handoffEndpoints struct {
	src     TailnetSource
	tgt     TailnetTarget
	target  Target
	reverse bool
}

func (p handoffEndpoints) CloseServing(ctx context.Context) error {
	if p.reverse {
		// The target serves nothing yet but /v1/meta (the transfer's gate);
		// stopping it closes its tailnet listener, as the undo does anyway.
		return p.target.Stop(ctx)
	}
	return p.src.StopTailnet(ctx)
}

func (p handoffEndpoints) ReopenServing(ctx context.Context) error {
	if p.reverse {
		return p.target.Start(ctx)
	}
	return p.src.StartTailnet(ctx)
}

func (p handoffEndpoints) OpenIncoming(ctx context.Context) error {
	if p.reverse {
		return p.src.StartTailnet(ctx)
	}
	return p.tgt.TailnetOpen(ctx)
}

// handoffResolver is the reach check, through the target's probe (a
// client node joined with the new node's auth key).
type handoffResolver struct{ tgt TailnetTarget }

func (r handoffResolver) Reaches(ctx context.Context, name, nodeID string) (bool, error) {
	wait := 30 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl) - 5*time.Second; left < wait {
			wait = max(left, 0)
		}
	}
	return r.tgt.TailnetReaches(ctx, name, nodeID, wait)
}

// handoffEngine is tailhandoff's engine for this migration.
func (e *Engine) handoffEngine(j *Journal, slot handoffSlot) (*tailhandoff.Engine, error) {
	// Every handoff needs the tailnet's authority: a run resumed without
	// it is refused here, whoever asks, before anything is touched.
	if e.Tailnet == nil || e.Tailnet.Control == nil {
		return nil, fmt.Errorf("%w: the migration's tailnet handoff goes on with them (varlatch migrate --resume --tailscale-oauth-client-file <file> --tailnet-auth-key-file <file>)", ErrNoTailnetAuthority)
	}
	if j.Tailnet == nil {
		return nil, errors.New("the journal records no tailnet handoff")
	}
	reverse := slot != slotForward
	ts, tt, err := e.tailnetSides()
	if err != nil {
		return nil, err
	}
	rec := j.Tailnet
	retain := e.now().Add(RollbackWindow)
	if at, ok := switchedAt(j); ok {
		retain = at.Add(RollbackWindow)
	}
	o := e.Tailnet
	return &tailhandoff.Engine{
		Control:    o.Control,
		Certs:      handoffCerts{src: ts, tgt: tt, suffix: rec.Suffix, retain: retain, now: e.now, reverse: reverse},
		Ledger:     &fileLedger{path: e.ledgerPath()},
		Endpoints:  handoffEndpoints{src: ts, tgt: tt, target: e.Target, reverse: reverse},
		Resolver:   handoffResolver{tgt: tt},
		Journal:    handoffJournal{e: e, j: j, slot: slot},
		Deadline:   o.Deadline,
		UndoWait:   o.UndoWait,
		RetryEvery: o.RetryEvery,
		// Real time, never the migration's clock: the handoff's deadlines
		// are contexts', and its issuance count's week is the CA's.
	}, nil
}

// operationOf is the handoff operation a temporary name carries
// (<name>-vl-<op>-n), "" when it is not one of name's.
func operationOf(name, held string) string {
	_, rest, ok := strings.Cut(held, "-vl-")
	if !ok {
		return ""
	}
	op, ok := strings.CutSuffix(rest, "-"+tailcontrol.RoleNew)
	if !ok {
		return ""
	}
	if want, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew); err != nil || want != held {
		return ""
	}
	return op
}

// errHandoffUnderway is a tailnet handoff past prepared at the preflight:
// the run is not recorded as stopped (a new run must not start over a
// name that moved); --resume goes on with it.
var errHandoffUnderway = errors.New("the handoff is underway")

// prepareTailnet is the handoff's preflight (after the keys, before the
// dry run): the target's node enrolled, held, under its temporary name,
// the plan made and prepared. Nothing is renamed. It does nothing for a
// source without a tailnet address.
func (e *Engine) prepareTailnet(ctx context.Context, j *Journal) error {
	ts, ok := e.Source.(TailnetSource)
	if !ok {
		return nil
	}
	info, err := ts.Tailnet(ctx)
	if err != nil {
		return fmt.Errorf("preflight: the source's tailnet: %w", err)
	}
	if !info.Enabled {
		if e.Tailnet != nil {
			return errors.New("preflight: the tailnet's authority was given, but the source serves no tailnet address (no Tailscale sidecar): nothing was done")
		}
		return nil
	}
	if e.Tailnet == nil || e.Tailnet.Control == nil {
		return fmt.Errorf("preflight: %w; nothing was done", ErrNoTailnetAuthority)
	}
	_, tt, err := e.tailnetSides()
	if err != nil {
		return err
	}
	tgt, _, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	tn := tgt.Tailnet
	switch {
	case tn == nil:
		return fmt.Errorf("preflight: the source serves the tailnet address %s.%s, and the target's configuration has tailnet = off: set tailnet = on, tailnet_hostname = %s and its tags; nothing was done", info.Machine, info.Suffix, info.Machine)
	case !strings.EqualFold(tn.Hostname, info.Machine):
		return fmt.Errorf("preflight: the target's tailnet_hostname is %s, the source's node %s: the name moves as it is, so set tailnet_hostname = %s; nothing was done", tn.Hostname, info.Machine, info.Machine)
	case info.HTTPS && tn.HTTPSPort == 0:
		return errors.New("preflight: the source serves the tailnet browser endpoint over HTTPS (Tailscale certificates), and the target's configuration has no tailnet_https_port: set it; nothing was done")
	case tn.Enrolled && tn.HeldAs == "" && (j.Tailnet == nil || j.Tailnet.Operation == ""):
		// (A node a migration enrolled is held again by whatever gives its
		// name back, an undo past the switch or a completed reverse
		// (reholdTarget), so it never comes here.)
		return errors.New("preflight: the target's tailnet node is enrolled and not held for a handoff: a migration's target node joins under a temporary name; remove its state (the tailnet directory and pin in its data directory) and its device in the tailnet; nothing was done")
	case !tn.AuthKey && !tn.Enrolled:
		return fmt.Errorf("preflight: the target has no tailnet auth key: %w; nothing was done", ErrNoTailnetAuthority)
	}
	name := strings.ToLower(info.Machine)
	op := ""
	switch {
	case tn.HeldAs != "":
		if op = operationOf(name, tn.HeldAs); op == "" {
			return fmt.Errorf("preflight: the target's node is held as %s, not a temporary name of %s: nothing was done", tn.HeldAs, name)
		}
	case j.Tailnet != nil && j.Tailnet.Operation != "":
		op = j.Tailnet.Operation
	default:
		if op, err = tailcontrol.NewOperationID(); err != nil {
			return err
		}
	}
	temp, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew)
	if err != nil {
		return err
	}
	e.say("Tailnet: the target's node joins as %s (held: it serves nothing on the tailnet until the transfer).", temp)
	node, err := tt.TailnetEnroll(ctx, temp, info.HTTPS)
	if err != nil {
		return fmt.Errorf("preflight: enrolling the target's node: %w", err)
	}
	if info.Suffix != "" && !strings.EqualFold(node.Suffix, info.Suffix) {
		return fmt.Errorf("preflight: the target's node joined the tailnet %s, the source's is %s: give it an auth key of the source's tailnet; nothing was renamed", node.Suffix, info.Suffix)
	}
	devices, err := e.Tailnet.Control.Devices(ctx)
	if err != nil {
		return fmt.Errorf("preflight: listing the tailnet's devices: %w", err)
	}
	var serving, incoming []tailcontrol.Device
	for _, d := range devices {
		if strings.EqualFold(d.Name, name) {
			serving = append(serving, d)
		}
		if d.NodeID == node.StableID || d.ID == node.StableID {
			incoming = append(incoming, d)
		}
	}
	if len(serving) != 1 {
		return fmt.Errorf("preflight: %d devices are named %s in the tailnet, not exactly the source's node: nothing was renamed", len(serving), name)
	}
	if len(incoming) != 1 {
		return fmt.Errorf("preflight: the control plane does not list the target's node %s exactly once: nothing was renamed", node.StableID)
	}
	plan, err := tailhandoff.NewForward(op, name, serving[0].ID, incoming[0].ID, info.HTTPS, e.now().Add(RollbackWindow))
	if err != nil {
		return err
	}
	plan.AcceptRollbackCertificate = e.Tailnet.AcceptRollbackCertificate
	rec := j.Tailnet
	if rec == nil || rec.Operation != op {
		rec = &TailnetRecord{}
	}
	rec.Name, rec.Suffix, rec.Operation, rec.Certificates = name, strings.ToLower(info.Suffix), op, info.HTTPS
	rec.ServingID, rec.IncomingID, rec.StableID = serving[0].ID, incoming[0].ID, node.StableID
	if rec.Handoff != nil && rec.Handoff.Phase != tailhandoff.Prepared {
		// Only a handoff that changed nothing is prepared again.
		return fmt.Errorf("preflight: the tailnet handoff %s is %s, not prepared: varlatch migrate --resume: %w", op, rec.Handoff.Phase, errHandoffUnderway)
	}
	j.Tailnet = rec
	if rec.Suffix == "" {
		rec.Suffix = strings.ToLower(node.Suffix)
	}
	if err := e.save(ctx, j); err != nil {
		return err
	}
	he, err := e.handoffEngine(j, slotForward)
	if err != nil {
		return err
	}
	if _, err := he.Prepare(ctx, plan); err != nil {
		return fmt.Errorf("preflight: the tailnet handoff: %w", err)
	}
	return nil
}

// switchTailnet is the transfer's second part (decision 12): the tailnet
// name moved, after the address answered from the target, then the
// combined final check. A handoff that failed and was undone undoes the
// migration (the address back); one whose undo is pending, or whose open
// could not be verified again, waits for --resume with both closed.
func (e *Engine) switchTailnet(ctx context.Context, j *Journal) error {
	rec := j.Tailnet
	if rec == nil {
		return nil
	}
	if rec.Checked != "" {
		return nil
	}
	he, err := e.handoffEngine(j, slotForward)
	if err != nil {
		return err
	}
	var st *tailhandoff.State
	switch {
	case rec.Handoff == nil:
		return errors.New("the journal records the tailnet handoff without its state: varlatch migrate --abort")
	case rec.Handoff.Phase == tailhandoff.Prepared:
		e.say("Tailnet: the name %s moves to the target's node.", rec.Name)
		crashPoint("tailnet switch")
		st, err = he.Switch(ctx, rec.Operation)
	case rec.Handoff.Phase == tailhandoff.Done:
		st = rec.Handoff
	default:
		e.say("Tailnet: the handoff was interrupted (%s): it is resumed.", rec.Handoff.Phase)
		st, err = he.Resume(ctx, rec.Operation)
		if rec.Handoff != nil && rec.Handoff.Phase == tailhandoff.Undone {
			// tailhandoff undoes a switch a crash cut short; --resume goes
			// on with the migration, so the name moves again (--abort is
			// what undoes it).
			e.say("Tailnet: the interrupted handoff was undone; the name moves again.")
			plan := rec.Handoff.Plan
			rec.Handoff = nil
			if _, err = he.Prepare(ctx, plan); err == nil {
				st, err = he.Switch(ctx, rec.Operation)
			}
		}
	}
	var herr *tailhandoff.HandoffError
	if errors.As(err, &herr) {
		switch herr.Phase {
		case tailhandoff.Undone, tailhandoff.Prepared:
			return e.undo(ctx, j, fmt.Errorf("the tailnet handoff: %w", err))
		default:
			return fmt.Errorf("the tailnet handoff: %w; varlatch migrate --resume goes on", err)
		}
	}
	if err != nil {
		return fmt.Errorf("the tailnet handoff: %w; varlatch migrate --resume goes on", err)
	}
	if st == nil || st.Phase != tailhandoff.Done {
		return fmt.Errorf("the tailnet handoff ended %v, not done; varlatch migrate --resume goes on", st)
	}
	// The combined final check: the public URL again, from the target.
	if err := e.waitForTarget(ctx, j); err != nil {
		return e.undo(ctx, j, fmt.Errorf("the combined final check: %w", err))
	}
	rec.Checked = e.now().UTC().Format(time.RFC3339Nano)
	if err := e.save(ctx, j); err != nil {
		return err
	}
	e.recordNow(ctx, j)
	return nil
}

// recordNow writes the handoff's certificate attempts into Go's count
// (issuances.go; each attempt once, so writing again changes nothing). A
// failure is said: the ledger keeps the attempts, varlatch migrate
// --finish writes them again, and the migration goes on either way.
func (e *Engine) recordNow(ctx context.Context, j *Journal) {
	rec := j.Tailnet
	if rec == nil || !rec.Certificates || rec.Recorded {
		return
	}
	if err := e.recordIssuances(ctx, rec); err != nil {
		e.say("Tailnet: the certificate issuance count is not in Go's installation yet (%v): %s keeps it, and varlatch migrate --finish writes it (run it again once Go answers, even after the migration is finished).", err, e.ledgerPath())
		return
	}
	// The source's journal only: beside a running varlatchd, Go's copy is
	// not written past the switch, and this flag is the source's to keep.
	rec.Recorded = true
	if err := writeJournal(e.Source.Dir(), j); err != nil {
		e.say("Tailnet: the certificate issuance count is in Go's installation, but the journal could not say so (%v): --finish writes it again, each attempt once.", err)
	}
}

// ledgerPath is the handoff's issuance ledger, in the source's directory.
func (e *Engine) ledgerPath() string {
	return filepath.Join(e.Source.Dir(), LedgerFile)
}

// unwindTailnet gives the tailnet name back during an undo, before the
// address (decision 12's reverse order): an unfinished handoff resumed
// (tailhandoff undoes it), a done one reversed, the old node taking the
// name back from the target's. Nothing for one that changed nothing.
func (e *Engine) unwindTailnet(ctx context.Context, j *Journal) error {
	rec := j.Tailnet
	if rec == nil || rec.Handoff == nil {
		return nil
	}
	switch {
	case rec.Handoff.Phase == tailhandoff.Prepared, rec.Handoff.Phase == tailhandoff.Undone:
		return nil
	case rec.Handoff.Phase == tailhandoff.Done && rec.Reverse != nil && rec.Reverse.Phase == tailhandoff.Done:
		// The reverse gave the name back; the target's node is held again
		// under its temporary name, which needs no tailnet authority (a
		// run that died between the two, resumed without it, still holds
		// it), as rollbackTailnet does.
		return e.reholdTarget(ctx, rec)
	case e.Tailnet == nil:
		return fmt.Errorf("%w: the tailnet name must be given back first", ErrNoTailnetAuthority)
	}
	switch rec.Handoff.Phase {
	case tailhandoff.Done:
	default:
		he, err := e.handoffEngine(j, slotForward)
		if err != nil {
			return err
		}
		st, err := he.Resume(ctx, rec.Operation)
		if st != nil && st.Phase == tailhandoff.Done {
			break
		}
		var herr *tailhandoff.HandoffError
		if err == nil || (errors.As(err, &herr) && herr.Phase == tailhandoff.Undone) {
			return nil
		}
		return fmt.Errorf("giving the tailnet name back: %w", err)
	}
	// Done: the reverse, the target's node giving the name back.
	if rec.Reverse != nil && rec.Reverse.Phase == tailhandoff.Done {
		return e.reholdTarget(ctx, rec)
	}
	he, err := e.handoffEngine(j, slotUndo)
	if err != nil {
		return err
	}
	retained, err := tailcontrol.TempName(rec.Name, rec.Operation, tailcontrol.RoleOld)
	if err != nil {
		return err
	}
	// A reverse that changed nothing in the end (undone: an image's
	// service still running, say) is planned again, under the same
	// operation, so the target's node returns to its temporary name.
	if rec.Reverse != nil && rec.Reverse.Phase == tailhandoff.Undone {
		rec.Reverse = nil
	}
	if rec.Reverse == nil {
		plan := tailhandoff.NewReverse(rec.Operation, rec.Name, rec.IncomingID, rec.ServingID, retained, rec.Certificates)
		if _, err := he.Prepare(ctx, plan); err != nil {
			return fmt.Errorf("giving the tailnet name back: %w", err)
		}
	}
	var st *tailhandoff.State
	if rec.Reverse != nil && rec.Reverse.Phase == tailhandoff.Prepared {
		st, err = he.Switch(ctx, rec.Operation)
	} else {
		st, err = he.Resume(ctx, rec.Operation)
		if rec.Reverse != nil && rec.Reverse.Phase == tailhandoff.Undone {
			// A reverse a crash cut short, undone by tailhandoff (the name
			// with the target's node again): planned and switched again.
			rec.Reverse = nil
			plan := tailhandoff.NewReverse(rec.Operation, rec.Name, rec.IncomingID, rec.ServingID, retained, rec.Certificates)
			if _, err = he.Prepare(ctx, plan); err == nil {
				st, err = he.Switch(ctx, rec.Operation)
			}
		}
	}
	var human *HumanStep
	if errors.As(err, &human) {
		// An image's service is the operator's to stop: until it is, the
		// name stays with the target's node (the reverse was undone, and
		// is planned again on --resume).
		e.say("To undo, by hand: %s The tailnet name %s stays with the target's (Go's) node until the service is stopped. "+
			"Then varlatch migrate --resume (or --abort) gives the name back to the TypeScript node, then the address.", human.Instruction, rec.Name)
		return fmt.Errorf("%w: the tailnet name is with Go's node until its service is stopped", ErrAwaitingOperator)
	}
	if err != nil || st == nil || st.Phase != tailhandoff.Done {
		return fmt.Errorf("giving the tailnet name back: %v", errors.Join(err, errors.New("the reverse handoff did not finish")))
	}
	return e.reholdTarget(ctx, rec)
}

// reholdTarget holds the target's node again once the reverse gave the
// name back: the open had removed its hold, and its node is named its
// temporary name again, which enroll checks (it holds again only a node the
// control plane names exactly that). A new migration to the same target
// then goes on with it.
func (e *Engine) reholdTarget(ctx context.Context, rec *TailnetRecord) error {
	return e.reholdTargetAs(ctx, rec.Name, rec.Operation)
}

// reholdTargetAs holds the target's node again under the temporary name of
// operation op (a reverse migration's own, after its return of the name).
func (e *Engine) reholdTargetAs(ctx context.Context, name, op string) error {
	_, tt, err := e.tailnetSides()
	if err != nil {
		return err
	}
	temp, err := tailcontrol.TempName(name, op, tailcontrol.RoleNew)
	if err != nil {
		return err
	}
	if _, err := tt.TailnetEnroll(ctx, temp, false); err != nil {
		return fmt.Errorf("holding the target's node again under %s: %w", temp, err)
	}
	return nil
}

// rollbackTailnet gives the tailnet name back to the retained old node in
// a reverse migration (decision 17), after the address answers from the
// TypeScript release: the reverse handoff, under an operation of its own,
// Go's node closing (stopped) and the sidecar opening. A failure undone by
// the handoff undoes the reverse (the address back to Go); one pending
// waits for --resume. Nothing when the forward migration moved no name.
func (e *Engine) rollbackTailnet(ctx context.Context, j *Journal) error {
	rec := j.Tailnet
	if rec == nil || rec.Handoff == nil || rec.Handoff.Phase != tailhandoff.Done {
		return nil
	}
	if rec.Rollback != nil && rec.Rollback.Phase == tailhandoff.Done {
		return e.reholdTargetAs(ctx, rec.Name, rec.RollbackOperation)
	}
	if e.Tailnet == nil || e.Tailnet.Control == nil {
		return fmt.Errorf("%w: the reverse gives the tailnet name back; varlatch migrate --resume with them goes on", ErrNoTailnetAuthority)
	}
	he, err := e.handoffEngine(j, slotRollback)
	if err != nil {
		return err
	}
	var st *tailhandoff.State
	switch {
	case rec.Rollback == nil || rec.Rollback.Phase == tailhandoff.Undone:
		op, err := tailcontrol.NewOperationID()
		if err != nil {
			return err
		}
		retained, err := tailcontrol.TempName(rec.Name, rec.Operation, tailcontrol.RoleOld)
		if err != nil {
			return err
		}
		// Go's attempts for the name count too: merged into the ledger
		// before the name moves back (issuances.go).
		if rec.Certificates {
			if err := e.mergeIssuances(ctx, rec); err != nil {
				return fmt.Errorf("the tailnet name back: %w; varlatch migrate --resume goes on", err)
			}
		}
		rec.RollbackOperation, rec.Rollback = op, nil
		plan := tailhandoff.NewReverse(op, rec.Name, rec.IncomingID, rec.ServingID, retained, rec.Certificates)
		e.say("Tailnet: the name %s goes back to the TypeScript release's node.", rec.Name)
		if _, err := he.Prepare(ctx, plan); err != nil {
			return e.undoReverse(ctx, j, fmt.Errorf("the tailnet name back: %w", err))
		}
		crashPoint("rollback tailnet switch")
		st, err = he.Switch(ctx, op)
		if err != nil {
			return e.rollbackTailnetFailed(ctx, j, err)
		}
	case rec.Rollback.Phase == tailhandoff.Prepared:
		if st, err = he.Switch(ctx, rec.RollbackOperation); err != nil {
			return e.rollbackTailnetFailed(ctx, j, err)
		}
	default:
		e.say("Tailnet: the name's return was interrupted (%s): it is resumed.", rec.Rollback.Phase)
		st, err = he.Resume(ctx, rec.RollbackOperation)
		if rec.Rollback != nil && rec.Rollback.Phase == tailhandoff.Undone {
			// Undone by tailhandoff (a switch cut short): --resume goes on
			// with the reverse, the name handed back again under a new
			// operation; --abort is what undoes it.
			e.say("Tailnet: the interrupted return was undone; the name goes back again.")
			return e.rollbackTailnet(ctx, j)
		}
		if err != nil {
			return e.rollbackTailnetFailed(ctx, j, err)
		}
	}
	if st == nil || st.Phase != tailhandoff.Done {
		return fmt.Errorf("the tailnet name back ended %v, not done; varlatch migrate --resume goes on", st)
	}
	// Go's node carries the reverse's temporary name now, unheld (its
	// open removed the hold): held again under it, a new migration to this
	// target goes on with it.
	return e.reholdTargetAs(ctx, rec.Name, rec.RollbackOperation)
}

func (e *Engine) rollbackTailnetFailed(ctx context.Context, j *Journal, err error) error {
	var herr *tailhandoff.HandoffError
	if errors.As(err, &herr) && (herr.Phase == tailhandoff.Undone || herr.Phase == tailhandoff.Prepared) {
		return e.undoReverse(ctx, j, fmt.Errorf("the tailnet name back: %w", err))
	}
	return fmt.Errorf("the tailnet name back: %w; varlatch migrate --resume goes on", err)
}

// unwindRollbackTailnet, in the reverse's undo before the address goes
// back to Go: a return of the name interrupted is resumed (tailhandoff
// undoes it, the name with Go's node again). One done cannot be undone
// here: the TypeScript release holds the name, so the reverse goes on.
func (e *Engine) unwindRollbackTailnet(ctx context.Context, j *Journal) error {
	rec := j.Tailnet
	if rec == nil || rec.Rollback == nil {
		return nil
	}
	switch rec.Rollback.Phase {
	case tailhandoff.Prepared, tailhandoff.Undone:
		return nil
	case tailhandoff.Done:
		return errors.New("the tailnet name is the TypeScript release's again: the reverse cannot be undone now; varlatch migrate --resume finishes it")
	}
	if e.Tailnet == nil || e.Tailnet.Control == nil {
		return fmt.Errorf("%w: the tailnet name must go back to Go's node first", ErrNoTailnetAuthority)
	}
	he, err := e.handoffEngine(j, slotRollback)
	if err != nil {
		return err
	}
	st, err := he.Resume(ctx, rec.RollbackOperation)
	if st != nil && st.Phase == tailhandoff.Done {
		return errors.New("the tailnet name went back to the TypeScript release's node meanwhile: varlatch migrate --resume finishes the reverse")
	}
	var herr *tailhandoff.HandoffError
	if err == nil || (errors.As(err, &herr) && herr.Phase == tailhandoff.Undone) {
		return nil
	}
	return fmt.Errorf("giving the tailnet name back to Go's node: %w", err)
}

// tailnetEstimate is the tailnet name's share of the transfer (decision
// 19): about 40 s on Tailscale's certificate path, seconds without.
func tailnetEstimate(rec *TailnetRecord) time.Duration {
	switch {
	case rec == nil:
		return 0
	case rec.Certificates:
		return 40 * time.Second
	}
	return 10 * time.Second
}

// LedgerFile is the migration's certificate issuance count, in the
// source's directory (go-step6 decision 16's count, kept here because the
// target has no database before the final copy): kept across runs, so a
// migration started again counts what an earlier one asked for.
const LedgerFile = "migration-issuances.json"

// fileLedger is tailhandoff.Ledger on LedgerFile (0600, replaced whole and
// synced; the migration's lock makes it this run's alone).
type fileLedger struct{ path string }

type ledgerEntry struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	StartedAt time.Time           `json:"startedAt"`
	EndedAt   *time.Time          `json:"endedAt,omitempty"`
	Outcome   tailhandoff.Outcome `json:"outcome,omitempty"`
}

func (l *fileLedger) read() ([]ledgerEntry, error) {
	b, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ledgerEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the issuance count %s is not readable: %w", l.path, err)
	}
	return out, nil
}

func (l *fileLedger) write(entries []ledgerEntry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeFileDurably(l.path, append(b, '\n'), 0o600)
}

func (l *fileLedger) Count(_ context.Context, name string, since time.Time) (int, error) {
	entries, err := l.read()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range entries {
		if strings.EqualFold(x.Name, name) && !x.StartedAt.Before(since) && x.Outcome != tailhandoff.Refused {
			n++
		}
	}
	return n, nil
}

func (l *fileLedger) Start(_ context.Context, name string, at time.Time) (string, error) {
	entries, err := l.read()
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	entries = append(entries, ledgerEntry{ID: id, Name: strings.ToLower(name), StartedAt: attemptTime(at)})
	return id, l.write(entries)
}

func (l *fileLedger) End(_ context.Context, id string, outcome tailhandoff.Outcome, at time.Time) error {
	entries, err := l.read()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(entries, func(x ledgerEntry) bool { return x.ID == id })
	if i < 0 {
		return fmt.Errorf("the issuance count has no attempt %s", id)
	}
	t := attemptTime(at)
	entries[i].EndedAt, entries[i].Outcome = &t, outcome
	return l.write(entries)
}
