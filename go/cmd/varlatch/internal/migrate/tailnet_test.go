// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// tnSource is a source with a Tailscale sidecar.
type tnSource struct {
	*fakeSource
	info TailnetInfo
	// expiry is the sidecar's certificate's end (zero: none); renewErr
	// what a renewal answers.
	expiry   time.Time
	renewErr error
	mu       sync.Mutex
	running  bool // the sidecar
	stops    int
	starts   int
}

func (s *tnSource) Tailnet(context.Context) (TailnetInfo, error) { return s.info, nil }
func (s *tnSource) StopTailnet(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.stops = false, s.stops+1
	return s.call("stop tailnet")
}
func (s *tnSource) StartTailnet(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.starts = true, s.starts+1
	return s.call("start tailnet")
}
func (s *tnSource) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
func (s *tnSource) TailnetCertExpiry(context.Context, string) (time.Time, bool, error) {
	return s.expiry, !s.expiry.IsZero(), nil
}
func (s *tnSource) RenewTailnetCert(context.Context, string, time.Duration) error { return s.renewErr }

// tnTarget is a target whose node enrolls in the fake control plane.
type tnTarget struct {
	*fakeTarget
	cp       *tailcontroltest.Tailscale
	plane    tailcontrol.ControlPlane
	newID    string // the target's device
	opened   bool
	openErr  error
	never    bool // no client node ever sees the name reach the target
	enrolled string
	// count is Go's certificate issuance count; recordErr what recording
	// into it answers.
	count     []IssuanceAttempt
	recordErr error
	recorded  int // RecordIssuances calls that wrote
}

// Issuances and RecordIssuances keep the count as varlatchd's does: times
// to the microsecond (time.UnixMicro), an attempt once by name and start.
func (t *tnTarget) Issuances(context.Context) ([]IssuanceAttempt, error) {
	return slices.Clone(t.count), nil
}

func (t *tnTarget) RecordIssuances(_ context.Context, attempts []IssuanceAttempt) error {
	if t.recordErr != nil {
		return t.recordErr
	}
	t.recorded++
	for _, a := range attempts {
		a.StartedAt = time.UnixMicro(a.StartedAt.UnixMicro()).UTC()
		if a.EndedAt != nil {
			end := time.UnixMicro(a.EndedAt.UnixMicro()).UTC()
			a.EndedAt = &end
		}
		if !slices.ContainsFunc(t.count, func(x IssuanceAttempt) bool {
			return x.Name == a.Name && x.StartedAt.UnixMicro() == a.StartedAt.UnixMicro()
		}) {
			t.count = append(t.count, a)
		}
	}
	return nil
}

func (t *tnTarget) TailnetEnroll(ctx context.Context, hostname string, _ bool) (EnrolledNode, error) {
	if err := t.call("enroll " + hostname); err != nil {
		return EnrolledNode{}, err
	}
	// Enrolled already: held again only while the control plane names it
	// exactly that (varlatchd's enroll).
	if t.enrolled == hostname {
		for _, d := range t.cp.Nodes() {
			if d.ID == t.newID && d.Name != hostname {
				return EnrolledNode{}, errors.New("varlatchd admin tailnet enroll: the node is enrolled as " + d.Name + " and not held for a handoff")
			}
		}
	}
	// The node joins under its temporary name.
	if t.enrolled != hostname {
		if _, err := tailcontrol.RenameAndReadBack(ctx, t.plane, t.newID, hostname); err != nil {
			return EnrolledNode{}, err
		}
		t.enrolled = hostname
	}
	t.info.Tailnet.Enrolled, t.info.Tailnet.HeldAs = true, hostname
	return EnrolledNode{DNSName: hostname + "." + t.cp.Suffix, StableID: "n" + t.newID, Suffix: t.cp.Suffix, Pinned: t.cp.Suffix, Open: true}, nil
}
func (t *tnTarget) TailnetCertificate(context.Context, string) error { return nil }
func (t *tnTarget) TailnetCertExpiry(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (t *tnTarget) TailnetOpen(context.Context) error {
	if err := t.call("tailnet open"); err != nil {
		return err
	}
	if t.openErr != nil {
		return t.openErr
	}
	t.opened = true
	t.info.Tailnet.HeldAs = ""
	return nil
}
func (t *tnTarget) TailnetReaches(_ context.Context, name, stableID string, _ time.Duration) (bool, error) {
	if t.never {
		return false, nil
	}
	n := 0
	ok := false
	for _, d := range t.cp.Nodes() {
		if strings.EqualFold(d.Name, name) {
			n++
			ok = d.NodeID == stableID
		}
	}
	return n == 1 && ok, nil
}

// failingProber answers as the world's prober, but fails once the
// target's tailnet listener opened (the combined final check).
type failingProber struct {
	*fakeProber
	t *tnTarget
}

func (p failingProber) Probe(ctx context.Context, origin string) (string, string, error) {
	if p.t.opened {
		return "", "", errors.New("connection reset")
	}
	return p.fakeProber.Probe(ctx, origin)
}

type tnWorld struct {
	*world
	src *tnSource
	tgt *tnTarget
	cp  *tailcontroltest.Tailscale
}

func newTailnetWorld(t *testing.T) *tnWorld {
	t.Helper()
	w := newWorld(t)
	cp := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "old", NodeID: "nold", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "new", NodeID: "nnew", Name: "localhost-1", Online: true},
	)
	t.Cleanup(cp.Close)
	plane, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: cp.URL, ClientID: cp.ClientID, ClientSecret: cp.ClientSecret, HTTP: cp.Client()})
	if err != nil {
		t.Fatal(err)
	}
	src := &tnSource{fakeSource: w.src, info: TailnetInfo{Enabled: true, Machine: "vault", Suffix: cp.Suffix}, running: true}
	w.tgt.info.Tailnet = &TargetTailnet{Hostname: "vault", Tags: []string{"tag:varlatch"}, AuthKey: true}
	tgt := &tnTarget{fakeTarget: w.tgt, cp: cp, plane: plane, newID: "new"}
	w.eng.Source, w.eng.Target = src, tgt
	w.eng.Tailnet = &TailnetOptions{Control: plane, Deadline: 3 * time.Second, UndoWait: 3 * time.Second, RetryEvery: 20 * time.Millisecond}
	return &tnWorld{world: w, src: src, tgt: tgt, cp: cp}
}

func (w *tnWorld) names() map[string]string {
	out := map[string]string{}
	for _, n := range w.cp.Nodes() {
		out[n.ID] = n.Name
	}
	return out
}

// The tailnet name moves with the migration (decisions 11 and 12): the
// target's node enrolled, held, before the barrier; the public address
// first, then the name, then the combined check; open. The handoff's
// state is in the journal, both places.
func TestTheTailnetNameMoves(t *testing.T) {
	w := newTailnetWorld(t)
	j, err := w.eng.Run(context.Background(), false)
	if err != nil || j.Phase != Open {
		t.Fatalf("%v %+v", err, j)
	}
	rec := j.Tailnet
	if rec == nil || rec.Handoff == nil || rec.Handoff.Phase != tailhandoff.Done || rec.Checked == "" || rec.ServingID != "old" || rec.IncomingID != "new" {
		t.Fatalf("the handoff's record: %+v", rec)
	}
	old, _ := tailcontrol.TempName("vault", rec.Operation, tailcontrol.RoleOld)
	if n := w.names(); n["new"] != "vault" || n["old"] != old {
		t.Fatalf("names %v", n)
	}
	if w.src.running || !w.tgt.opened {
		t.Fatalf("sidecar running %v, target's tailnet open %v", w.src.running, w.tgt.opened)
	}
	// Decision 12's order: the public address before the tailnet name.
	calls := w.src.calls
	if i, k := index(calls, "stop public"), index(calls, "stop tailnet"); i < 0 || k < 0 || i > k {
		t.Fatalf("the order: %q", calls)
	}
	// The journal holds the handoff, in both places, and no secret.
	saved, err := readJournal(w.src.dir)
	if err != nil || saved.Tailnet == nil || saved.Tailnet.Handoff.Phase != tailhandoff.Done {
		t.Fatalf("the journal: %+v %v", saved, err)
	}
	if last := w.tgt.journals[len(w.tgt.journals)-1]; !strings.Contains(string(last), `"handoff"`) {
		t.Fatalf("the target's journal has no handoff: %s", last)
	}
	w.noSecrets(t)
	for _, f := range w.tgt.journals {
		if strings.Contains(string(f), w.cp.ClientSecret) {
			t.Fatal("the OAuth client's secret in a journal")
		}
	}
	if _, err := os.Stat(filepath.Join(w.src.dir, LedgerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func index(calls []string, c string) int {
	for i, x := range calls {
		if x == c {
			return i
		}
	}
	return -1
}

// A handoff that fails (no client reaches the name) is undone by
// tailhandoff, then the migration is: the old node holds the name and its
// sidecar serves again, the address goes back, the barrier is lifted.
func TestATailnetFailureUndoesTheMigration(t *testing.T) {
	w := newTailnetWorld(t)
	w.tgt.never = true
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || j.Phase != Released || !strings.Contains(err.Error(), "the tailnet handoff") {
		t.Fatalf("%v %+v", err, j)
	}
	temp, _ := tailcontrol.TempName("vault", j.Tailnet.Operation, tailcontrol.RoleNew)
	if n := w.names(); n["old"] != "vault" || n["new"] != temp {
		t.Fatalf("names %v", n)
	}
	if !w.src.running || w.tgt.opened || w.src.ingressDown {
		t.Fatalf("sidecar running %v, target's tailnet open %v, the source's ingress down %v", w.src.running, w.tgt.opened, w.src.ingressDown)
	}
	if j.Tailnet.Handoff.Phase != tailhandoff.Undone {
		t.Fatalf("the handoff: %+v", j.Tailnet.Handoff)
	}
	// A new run goes on with the same node, held under the same name.
	w.tgt.never = false
	j2, err := w.eng.Run(context.Background(), false)
	if err != nil || j2.Phase != Open || j2.Tailnet.Operation != j.Tailnet.Operation {
		t.Fatalf("the next run: %v %+v", err, j2)
	}
}

// The combined final check fails after the name moved: the undo gives the
// name back first (the reverse handoff: the old node takes it from the
// target's), then the address.
func TestTheCombinedCheckFailureGivesTheNameBack(t *testing.T) {
	w := newTailnetWorld(t)
	w.eng.Prober = failingProber{fakeProber: w.prober, t: w.tgt}
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || j.Phase != Released || !strings.Contains(err.Error(), "the combined final check") {
		t.Fatalf("%v %+v", err, j)
	}
	if j.Tailnet.Reverse == nil || j.Tailnet.Reverse.Phase != tailhandoff.Done {
		t.Fatalf("the reverse: %+v", j.Tailnet.Reverse)
	}
	if n := w.names(); n["old"] != "vault" {
		t.Fatalf("names %v", n)
	}
	if !w.src.running || w.tgt.running || w.src.ingressDown {
		t.Fatalf("sidecar running %v, target running %v, the source's ingress down %v", w.src.running, w.tgt.running, w.src.ingressDown)
	}
	// The undo held the target's node again under its temporary name: a
	// new migration to the same target goes on with it.
	temp, _ := tailcontrol.TempName("vault", j.Tailnet.Operation, tailcontrol.RoleNew)
	if w.tgt.info.Tailnet.HeldAs != temp || w.names()["new"] != temp {
		t.Fatalf("not held again: %q, names %v", w.tgt.info.Tailnet.HeldAs, w.names())
	}
	w.eng.Prober = w.prober
	j2, err := w.eng.Run(context.Background(), false)
	if err != nil || j2.Phase != Open || j2.Tailnet.Operation != j.Tailnet.Operation || w.names()["new"] != "vault" {
		t.Fatalf("the next migration: %v %+v %v", err, j2, w.names())
	}
}

// Every handoff needs the tailnet's authority: a run resumed without it
// is refused, never a crash, whichever step asks.
func TestAResumeWithoutTheAuthorityIsRefused(t *testing.T) {
	w := newTailnetWorld(t)
	j, err := w.eng.Run(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	w.eng.Tailnet = nil
	j.Tailnet.Handoff.Phase = tailhandoff.Prepared
	if err := w.eng.switchTailnet(context.Background(), j); !errors.Is(err, ErrNoTailnetAuthority) || !strings.Contains(err.Error(), "--resume --tailscale-oauth-client-file") {
		t.Fatalf("switch: %v", err)
	}
	j.Tailnet.Handoff.Phase = tailhandoff.Switching
	if err := w.eng.unwindTailnet(context.Background(), j); !errors.Is(err, ErrNoTailnetAuthority) {
		t.Fatalf("unwind: %v", err)
	}
	if _, err := w.eng.handoffEngine(j, slotRollback); !errors.Is(err, ErrNoTailnetAuthority) {
		t.Fatalf("handoffEngine: %v", err)
	}
}

// The old node's certificate cannot be renewed to last the rollback
// window: the preflight refuses, naming the flag; accepted, it goes on and
// the journal says a rollback needs a new certificate.
func TestTheRollbackCertificateIsAcceptedOnlyByTheFlag(t *testing.T) {
	w := newTailnetWorld(t)
	w.src.info.HTTPS = true
	w.tgt.info.Tailnet.HTTPSPort = 8443
	w.src.expiry, w.src.renewErr = time.Now().Add(48*time.Hour), errors.New("the CA refused")
	if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "--accept-rollback-certificate") {
		t.Fatalf("without the flag: %v", err)
	}
	w.eng.Tailnet.AcceptRollbackCertificate = true
	j, err := w.eng.Resume(context.Background())
	if err != nil || j.Tailnet == nil || j.Tailnet.Handoff.Phase != tailhandoff.Prepared || !j.Tailnet.Handoff.RollbackNeedsCertificate {
		t.Fatalf("with the flag: %v %+v", err, j)
	}
}

// The control plane lost while the handoff undoes: both stay closed, the
// migration waits in its transfer; --resume finishes the handoff's undo,
// then the migration's.
func TestATailnetUndoCutShortIsResumed(t *testing.T) {
	w := newTailnetWorld(t)
	// No client reaches the name until the deadline; by then the control
	// plane is gone, so the handoff's undo cannot give the name back.
	w.tgt.never = true
	w.eng.Tailnet.Deadline, w.eng.Tailnet.UndoWait = 600*time.Millisecond, 300*time.Millisecond
	stopping := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopping:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if !w.src.isRunning() {
				// The sidecar stopped: the switch began. Cut the control
				// plane once its renames are made.
				time.Sleep(250 * time.Millisecond)
				w.cp.SetUnavailable(true)
				return
			}
		}
	}()
	defer close(stopping)
	j, err := w.eng.Run(context.Background(), false)
	if err == nil || j.Phase != Transfer || !strings.Contains(err.Error(), "--resume") {
		t.Fatalf("%v %+v", err, j)
	}
	if j.Tailnet.Handoff.Phase != tailhandoff.UndoPending || w.src.running {
		t.Fatalf("the handoff %+v, sidecar running %v", j.Tailnet.Handoff, w.src.running)
	}
	w.cp.SetUnavailable(false)
	j, err = w.eng.Resume(context.Background())
	if err == nil || j.Phase != Released {
		t.Fatalf("resume: %v %+v", err, j)
	}
	if n := w.names(); n["old"] != "vault" || !w.src.running {
		t.Fatalf("names %v, sidecar running %v", n, w.src.running)
	}
}

// The authority is required for a source with a tailnet address, and
// refused for one without; the target must take the same name.
func TestTheTailnetPreflight(t *testing.T) {
	w := newTailnetWorld(t)
	w.eng.Tailnet = nil
	if _, err := w.eng.Run(context.Background(), true); err == nil || !errors.Is(err, ErrNoTailnetAuthority) {
		t.Fatalf("no authority: %v", err)
	}
	w = newTailnetWorld(t)
	w.src.info.Enabled = false
	if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "serves no tailnet address") {
		t.Fatalf("an authority without a tailnet: %v", err)
	}
	w = newTailnetWorld(t)
	w.tgt.info.Tailnet.Hostname = "other"
	if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "set tailnet_hostname = vault") {
		t.Fatalf("another hostname: %v", err)
	}
	w = newTailnetWorld(t)
	w.tgt.info.Tailnet = nil
	if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "tailnet = off") {
		t.Fatalf("tailnet off: %v", err)
	}
	// A dry run enrolls and prepares, and renames nothing.
	w = newTailnetWorld(t)
	j, err := w.eng.Run(context.Background(), true)
	if err != nil || j.Tailnet == nil || j.Tailnet.Handoff.Phase != tailhandoff.Prepared {
		t.Fatalf("dry run: %v %+v", err, j)
	}
	if n := w.names(); n["old"] != "vault" || !w.src.running {
		t.Fatalf("a dry run renamed: %v", n)
	}
	if j.DryRun.TransferMs != (transferEstimate(Public) + 10*time.Second).Milliseconds() {
		t.Fatalf("the projection's transfer: %d", j.DryRun.TransferMs)
	}
}

func TestOperationOf(t *testing.T) {
	temp, _ := tailcontrol.TempName("vault", "abcdefghij", tailcontrol.RoleNew)
	if op := operationOf("vault", temp); op != "abcdefghij" {
		t.Fatalf("%q", op)
	}
	for _, held := range []string{"vault", "vault-vl-abcdefghij-o", "other-vl-abcdefghij-n", "vault-vl--n"} {
		if op := operationOf("vault", held); op != "" {
			t.Errorf("%s: %q", held, op)
		}
	}
}

// The issuance count is kept across runs, in the source's directory.
func TestTheLedgerFile(t *testing.T) {
	l := &fileLedger{path: filepath.Join(t.TempDir(), LedgerFile)}
	ctx := context.Background()
	now := time.Now()
	a, err := l.Start(ctx, "Vault", now.Add(-8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_ = l.End(ctx, a, tailhandoff.Issued, now)
	b, _ := l.Start(ctx, "vault", now.Add(-time.Hour))
	_ = l.End(ctx, b, tailhandoff.Refused, now)
	_, _ = l.Start(ctx, "vault", now) // never ended: counts
	if n, err := l.Count(ctx, "vault", now.Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
	if st, err := os.Stat(l.path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the ledger's mode: %v %v", st, err)
	}
	if err := l.End(ctx, "nope", tailhandoff.Issued, now); err == nil {
		t.Fatal("an unknown attempt ended")
	}
}

// A reverse migration gives the name back (decision 17): after the
// forward migration moved it, the retained old node takes it from the
// target's under an operation of its own, the target's node closing
// (stopped) and the sidecar opening; run again, it changes nothing.
// The tailnet name's certificate issuance count across a migration and its
// rollback: once the handoff is checked, its attempts are in Go's count (a
// failure to write them said, and written by --finish); a rollback
// merges Go's attempts for the name into the ledger before the name moves
// back, so they count; written again, each attempt counts once.
func TestTheIssuanceCountCarriesAcrossARollback(t *testing.T) {
	ctx := context.Background()
	w := newTailnetWorld(t)
	w.src.info.HTTPS, w.src.expiry = true, time.Now().Add(80*24*time.Hour)
	w.tgt.info.Tailnet.HTTPSPort = 8443
	w.tgt.recordErr = errors.New("varlatchd is busy")
	j, err := w.eng.Run(ctx, false)
	if err != nil || j.Phase != Open {
		t.Fatalf("%v %+v", err, j)
	}
	domain := "vault." + w.cp.Suffix
	if len(w.tgt.count) != 0 || !slices.ContainsFunc(w.said, func(s string) bool { return strings.Contains(s, "varlatch migrate --finish writes it") }) {
		t.Fatalf("a failed write: count %v, said %q", w.tgt.count, w.said)
	}
	// --finish writes it (recordNow, as finishRemove runs it).
	w.tgt.recordErr = nil
	w.eng.recordNow(ctx, j)
	w.eng.recordNow(ctx, j)
	ledger := &fileLedger{path: filepath.Join(w.src.dir, LedgerFile)}
	forward, _ := ledger.read()
	if len(forward) == 0 || len(w.tgt.count) != len(forward) || !slices.ContainsFunc(w.tgt.count, func(a IssuanceAttempt) bool { return a.Name == domain && a.Outcome == "issued" }) {
		t.Fatalf("Go's count %+v, the ledger %+v", w.tgt.count, forward)
	}
	// Go renews the name's certificate during the window, and its count
	// records it.
	renewal := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	w.tgt.count = append(w.tgt.count, IssuanceAttempt{Name: domain, StartedAt: renewal, Outcome: "issued"},
		IssuanceAttempt{Name: "other.example.com", StartedAt: renewal, Outcome: "issued"})
	j.Phase = RollbackTransfer
	w.tgt.journal = &JournalHead{ID: j.ID, Phase: RollbackTransfer}
	w.tgt.running = false
	if err := w.eng.rollbackTailnet(ctx, j); err != nil {
		t.Fatal(err)
	}
	after, _ := ledger.read()
	if !slices.ContainsFunc(after, func(x ledgerEntry) bool { return x.Name == "vault" && x.StartedAt.Equal(renewal) }) ||
		slices.ContainsFunc(after, func(x ledgerEntry) bool { return strings.Contains(x.Name, "other") }) {
		t.Fatalf("the ledger after the rollback: %+v", after)
	}
	vault := len(slices.DeleteFunc(slices.Clone(after), func(x ledgerEntry) bool { return x.Name != "vault" }))
	if n, _ := ledger.Count(ctx, "vault", time.Now().Add(-7*24*time.Hour)); n != vault || n < 2 {
		t.Fatalf("the ledger counts %d of vault's %d", n, vault)
	}
	// A forward migration after it writes the ledger again: each attempt
	// once.
	before := len(w.tgt.count)
	if err := w.eng.recordIssuances(ctx, j.Tailnet); err != nil {
		t.Fatal(err)
	}
	if want := before + len(after) - len(forward) - 1; len(w.tgt.count) != want {
		t.Fatalf("Go's count has %d attempts, want %d: %+v", len(w.tgt.count), want, w.tgt.count)
	}
	if err := w.eng.mergeIssuances(ctx, j.Tailnet); err != nil {
		t.Fatal(err)
	}
	if again, _ := ledger.read(); len(again) != len(after) {
		t.Fatalf("merged twice: %d attempts, was %d", len(again), len(after))
	}
}

func TestTheRollbackGivesTheNameBack(t *testing.T) {
	w := newTailnetWorld(t)
	j, err := w.eng.Run(context.Background(), false)
	if err != nil || j.Phase != Open {
		t.Fatalf("%v %+v", err, j)
	}
	// Where the reverse gives the name back: its transfer, the address
	// answering from the TypeScript release and Go stopped.
	reverseAt := func(w *tnWorld, j *Journal) {
		j.Phase = RollbackTransfer
		w.tgt.journal = &JournalHead{ID: j.ID, Phase: RollbackTransfer}
		w.tgt.running = false
	}
	reverseAt(w, j)
	if err := w.eng.rollbackTailnet(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	rec := j.Tailnet
	if rec.Rollback == nil || rec.Rollback.Phase != tailhandoff.Done || rec.RollbackOperation == "" || rec.RollbackOperation == rec.Operation {
		t.Fatalf("the rollback's handoff: %+v", rec)
	}
	goTemp, _ := tailcontrol.TempName("vault", rec.RollbackOperation, tailcontrol.RoleNew)
	if n := w.names(); n["old"] != "vault" || n["new"] != goTemp {
		t.Fatalf("names %v", n)
	}
	if !w.src.running || w.tgt.running {
		t.Fatalf("sidecar running %v, target running %v", w.src.running, w.tgt.running)
	}
	if err := w.eng.rollbackTailnet(context.Background(), j); err != nil {
		t.Fatalf("again: %v", err)
	}
	// Go's node is held again under the reverse's temporary name.
	if w.tgt.info.Tailnet.HeldAs != goTemp {
		t.Fatalf("Go's node is not held again: %q", w.tgt.info.Tailnet.HeldAs)
	}
	if n := w.names(); n["old"] != "vault" {
		t.Fatalf("names after again %v", n)
	}
	// Without the authority, the reverse says what it needs.
	w2 := newTailnetWorld(t)
	j2, err := w2.eng.Run(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	reverseAt(w2, j2)
	w2.eng.Tailnet = nil
	if err := w2.eng.rollbackTailnet(context.Background(), j2); !errors.Is(err, ErrNoTailnetAuthority) {
		t.Fatalf("no authority: %v", err)
	}
}

// The image's service, its undo after the name moved: stopping it is the
// operator's, so the undo waits (exit 75) saying the name stays with Go's
// node until then; once it is stopped, --resume gives the name back, then
// the address.
func TestTheImageUndoAfterTheNameMovedWaitsForTheOperator(t *testing.T) {
	w := newTailnetWorld(t)
	w.tgt.human = true
	w.eng.Prober = failingProber{fakeProber: w.prober, t: w.tgt}
	// The run stops for the service's start; the operator starts it.
	if _, err := w.eng.Run(context.Background(), false); !errors.Is(err, ErrAwaitingOperator) {
		t.Fatalf("the start step: %v", err)
	}
	w.tgt.running = true
	j, err := w.eng.Resume(context.Background())
	if !errors.Is(err, ErrAwaitingOperator) || j.Phase != Transfer || !j.Undoing {
		t.Fatalf("the undo's stop step: %v %+v", err, j)
	}
	if n := w.names(); n["new"] != "vault" {
		t.Fatalf("names while waiting %v", n)
	}
	said := strings.Join(w.said, "\n")
	if !strings.Contains(said, "stays with the target's (Go's) node until the service is stopped") || !strings.Contains(said, "Stop the Go service") {
		t.Fatalf("the instruction: %s", said)
	}
	// Stopped by the operator: --resume finishes the undo.
	w.tgt.running = false
	j, err = w.eng.Resume(context.Background())
	if err == nil || j.Phase != Released {
		t.Fatalf("resume: %v %+v", err, j)
	}
	if n := w.names(); n["old"] != "vault" || !w.src.running || w.src.ingressDown {
		t.Fatalf("names %v, sidecar running %v, ingress down %v", n, w.src.running, w.src.ingressDown)
	}
}

// varlatchd keeps an attempt's start to the microsecond, and the ledger
// was written to the nanosecond, so a rollback merged every attempt in
// again and counted it twice. Through the real fileLedger: one written now
// (nanoseconds given) and one an earlier release wrote (nanoseconds kept)
// each count once over a forward, a rollback and a forward again.
func TestAnAttemptCountsOnceAtAnyPrecision(t *testing.T) {
	ctx := context.Background()
	w := newTailnetWorld(t)
	rec := &TailnetRecord{Name: "vault", Suffix: w.cp.Suffix, Certificates: true}
	l := &fileLedger{path: w.eng.ledgerPath()}
	at := time.Date(2026, 11, 21, 6, 0, 0, 123456789, time.UTC)
	id, err := l.Start(ctx, "Vault", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.End(ctx, id, tailhandoff.Issued, at.Add(time.Second+987)); err != nil {
		t.Fatal(err)
	}
	entries, _ := l.read()
	if len(entries) != 1 || !entries[0].StartedAt.Equal(at.Truncate(time.Microsecond)) || entries[0].EndedAt.Nanosecond()%1000 != 0 {
		t.Fatalf("the ledger keeps %+v, not microseconds", entries)
	}
	legacy := ledgerEntry{ID: "legacy", Name: "vault", StartedAt: at.Add(time.Hour + 321), Outcome: tailhandoff.Issued}
	if err := l.write(append(entries, legacy)); err != nil {
		t.Fatal(err)
	}
	since := at.Add(-time.Hour)
	for i, step := range []func() error{
		func() error { return w.eng.recordIssuances(ctx, rec) }, // forward
		func() error { return w.eng.mergeIssuances(ctx, rec) },  // rollback
		func() error { return w.eng.recordIssuances(ctx, rec) }, // forward again
		func() error { return w.eng.mergeIssuances(ctx, rec) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
		if got, _ := l.read(); len(got) != 2 {
			t.Fatalf("step %d: the ledger holds %d attempts: %+v", i, len(got), got)
		}
		if n, _ := l.Count(ctx, "vault", since); n != 2 {
			t.Fatalf("step %d: the ledger counts %d", i, n)
		}
		if len(w.tgt.count) != 2 {
			t.Fatalf("step %d: Go's count holds %d: %+v", i, len(w.tgt.count), w.tgt.count)
		}
	}
}

// Once the attempts are in Go's count, the source's journal says so, and
// no later run writes them again; until then, each run that reaches it
// (the switch, --finish, a finished migration's --finish) tries again.
func TestTheRecordIsJournalled(t *testing.T) {
	ctx := context.Background()
	w := newTailnetWorld(t)
	w.src.info.HTTPS, w.src.expiry = true, time.Now().Add(80*24*time.Hour)
	w.tgt.info.Tailnet.HTTPSPort = 8443
	w.tgt.recordErr = errors.New("varlatchd does not answer")
	j, err := w.eng.Run(ctx, false)
	if err != nil || j.Phase != Open {
		t.Fatalf("%v %+v", err, j)
	}
	if j.Tailnet.Recorded || w.tgt.recorded != 0 {
		t.Fatalf("a failed write: recorded %v, %d writes", j.Tailnet.Recorded, w.tgt.recorded)
	}
	w.tgt.recordErr = nil
	w.eng.recordNow(ctx, j)
	saved, err := readJournal(w.src.dir)
	if err != nil || saved == nil || !saved.Tailnet.Recorded || !j.Tailnet.Recorded || w.tgt.recorded != 1 {
		t.Fatalf("after the write: journal %+v %v, %d writes", saved, err, w.tgt.recorded)
	}
	w.eng.recordNow(ctx, j)
	if w.tgt.recorded != 1 {
		t.Fatalf("written again: %d writes", w.tgt.recorded)
	}
}
