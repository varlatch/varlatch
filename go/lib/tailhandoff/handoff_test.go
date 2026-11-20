// SPDX-License-Identifier: Apache-2.0

package tailhandoff_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

var ctx = context.Background()

func TestMain(m *testing.M) {
	tailcontrol.ReadBackRetry = 5 * time.Millisecond
	os.Exit(m.Run())
}

// memJournal keeps each State as JSON, as a file would.
type memJournal struct {
	mu    sync.Mutex
	saved map[string][]byte
	saves int
}

func (j *memJournal) Load(_ context.Context, op string) (*tailhandoff.State, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, ok := j.saved[op]
	if !ok {
		return nil, nil
	}
	var s tailhandoff.State
	return &s, json.Unmarshal(b, &s)
}

func (j *memJournal) Save(_ context.Context, s *tailhandoff.State) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if j.saved == nil {
		j.saved = map[string][]byte{}
	}
	j.saved[s.Plan.Operation] = b
	j.saves++
	return nil
}

// memLedger is the installation's issuance count.
type memLedger struct {
	mu       sync.Mutex
	attempts []attempt
}

type attempt struct {
	name    string
	at      time.Time
	outcome tailhandoff.Outcome // "" while started
}

func (l *memLedger) Count(_ context.Context, name string, since time.Time) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, a := range l.attempts {
		if a.name == name && !a.at.Before(since) && a.outcome != tailhandoff.Refused {
			n++
		}
	}
	return n, nil
}

func (l *memLedger) Start(_ context.Context, name string, at time.Time) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts = append(l.attempts, attempt{name: name, at: at})
	return fmt.Sprint(len(l.attempts) - 1), nil
}

func (l *memLedger) End(_ context.Context, id string, o tailhandoff.Outcome, _ time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var i int
	fmt.Sscan(id, &i)
	l.attempts[i].outcome = o
	return nil
}

func (l *memLedger) outcomes(name string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, a := range l.attempts {
		if a.name == name {
			o := string(a.outcome)
			if o == "" {
				o = "started"
			}
			out = append(out, o)
		}
	}
	return out
}

// fakeCerts holds each node's certificates; obtain decides each attempt.
type fakeCerts struct {
	mu     sync.Mutex
	certs  map[string]time.Time // role/name -> expiry
	obtain func(ctx context.Context, role tailhandoff.Role, name string) error
	calls  []string
}

func newCerts() *fakeCerts { return &fakeCerts{certs: map[string]time.Time{}} }

func (c *fakeCerts) Obtain(ctx context.Context, role tailhandoff.Role, name string) error {
	c.mu.Lock()
	c.calls = append(c.calls, string(role)+"/"+name)
	f := c.obtain
	c.mu.Unlock()
	if f != nil {
		if err := f(ctx, role, name); err != nil {
			return err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs[string(role)+"/"+name] = time.Now().Add(90 * 24 * time.Hour)
	return nil
}

func (c *fakeCerts) Expiry(_ context.Context, role tailhandoff.Role, name string) (time.Time, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.certs[string(role)+"/"+name]
	return e, ok, nil
}

func (c *fakeCerts) set(role tailhandoff.Role, name string, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs[string(role)+"/"+name] = expiry
}

// fakeEndpoints records the two installations' tailnet listeners.
type fakeEndpoints struct {
	mu                         sync.Mutex
	servingOpen, incomingOpen  bool
	closeErr, openErr          error
	onClose                    func()
	reopens, closes, openCalls int
}

func (e *fakeEndpoints) CloseServing(context.Context) error {
	e.mu.Lock()
	err, hook := e.closeErr, e.onClose
	e.closes++
	if err == nil {
		e.servingOpen = false
	}
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (e *fakeEndpoints) ReopenServing(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reopens++
	e.servingOpen = true
	return nil
}

func (e *fakeEndpoints) OpenIncoming(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.openCalls++
	if e.openErr != nil {
		return e.openErr
	}
	e.incomingOpen = true
	return nil
}

func (e *fakeEndpoints) state() (bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.servingOpen, e.incomingOpen
}

// fakeResolver resolves from a client node: name reaches the node that the
// control plane lists under exactly it, once propagate has passed since it
// was first seen there; never when never is set.
type fakeResolver struct {
	cp        tailcontrol.ControlPlane
	propagate time.Duration
	never     atomic.Bool
	onCheck   func()
	mu        sync.Mutex
	seen      map[string]time.Time
}

func (r *fakeResolver) Reaches(ctx context.Context, name, nodeID string) (bool, error) {
	if r.onCheck != nil {
		r.onCheck()
	}
	if r.never.Load() {
		return false, nil
	}
	devices, err := r.cp.Devices(ctx)
	if err != nil {
		return false, err
	}
	for _, d := range devices {
		id := d.NodeID
		if id == "" {
			id = d.ID
		}
		if d.Name == name && id == nodeID {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.seen == nil {
				r.seen = map[string]time.Time{}
			}
			first, ok := r.seen[name+"/"+nodeID]
			if !ok {
				first = time.Now()
				r.seen[name+"/"+nodeID] = first
			}
			return time.Since(first) >= r.propagate, nil
		}
	}
	return false, nil
}

type rig struct {
	f      *tailcontroltest.Tailscale
	cp     tailcontrol.ControlPlane
	j      *memJournal
	l      *memLedger
	c      *fakeCerts
	ep     *fakeEndpoints
	r      *fakeResolver
	engine *tailhandoff.Engine
}

const op = "abcdefgh23"

// newRig is a tailnet on the Tailscale fake: the serving node "vault"
// (id 1) with its certificate, the incoming node under its temporary name
// (id 2), and two bystanders.
func newRig(t *testing.T, extra ...tailcontroltest.Node) *rig {
	t.Helper()
	in, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
	nodes := append([]tailcontroltest.Node{
		{ID: "1", NodeID: "nOld1", Name: "vault", Online: true},
		{ID: "2", NodeID: "nNew2", Name: in, Online: true},
		{ID: "3", NodeID: "nBuild3", Name: "build", Online: true},
		{ID: "4", NodeID: "nLaptop4", Name: "laptop"},
	}, extra...)
	f := tailcontroltest.NewTailscale(nodes...)
	t.Cleanup(f.Close)
	cp, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: f.URL, ClientID: f.ClientID, ClientSecret: f.ClientSecret, HTTP: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	certs := newCerts()
	certs.set(tailhandoff.Serving, "vault", time.Now().Add(80*24*time.Hour))
	ep := &fakeEndpoints{servingOpen: true}
	res := &fakeResolver{cp: cp}
	j, l := &memJournal{}, &memLedger{}
	return &rig{f: f, cp: cp, j: j, l: l, c: certs, ep: ep, r: res, engine: &tailhandoff.Engine{
		Control: cp, Certs: certs, Ledger: l, Endpoints: ep, Resolver: res, Journal: j,
		Deadline: 3 * time.Second, CertWait: time.Second, UndoWait: 2 * time.Second, RetryEvery: 20 * time.Millisecond,
	}}
}

func (r *rig) names() map[string]string {
	out := map[string]string{}
	for _, n := range r.f.Nodes() {
		out[n.ID] = n.Name
	}
	return out
}

func (r *rig) forward(t *testing.T) tailhandoff.Plan {
	t.Helper()
	p, err := tailhandoff.NewForward(op, "vault", "1", "2", true, time.Now().Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestForwardThenReverse(t *testing.T) {
	r := newRig(t)
	p := r.forward(t)
	s, err := r.engine.Prepare(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Phase != tailhandoff.Prepared || s.ServingTemp != "vault-vl-"+op+"-o" {
		t.Fatalf("%+v", s)
	}
	// Prepare renames nothing, closes nothing; the temporary name's
	// certificate proves issuance works now.
	if r.names()["1"] != "vault" || r.ep.closes != 0 || len(r.l.outcomes(p.IncomingName)) != 1 {
		t.Fatalf("prepare changed something: %v, closes %d, %v", r.names(), r.ep.closes, r.l.outcomes(p.IncomingName))
	}
	s, err = r.engine.Switch(ctx, op)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	if n := r.names(); n["1"] != "vault-vl-"+op+"-o" || n["2"] != "vault" {
		t.Fatalf("names %v", n)
	}
	if serving, incoming := r.ep.state(); serving || !incoming {
		t.Fatalf("serving open %v, incoming open %v", serving, incoming)
	}
	if got := r.l.outcomes("vault"); len(got) != 1 || got[0] != "issued" {
		t.Errorf("the name's issuances: %v", got)
	}

	// The rollback: the retained node takes the name back. Its cached
	// certificate is still valid, so nothing is issued.
	const rop = "rrrrrrrr23"
	rev := tailhandoff.NewReverse(rop, "vault", "2", "1", "vault-vl-"+op+"-o", true)
	r.c.set(tailhandoff.Incoming, "vault", time.Now().Add(40*24*time.Hour)) // the retained node's
	r.ep.servingOpen, r.ep.incomingOpen = true, false                       // roles swap: Go serves now
	if _, err := r.engine.Prepare(ctx, rev); err != nil {
		t.Fatal(err)
	}
	s, err = r.engine.Switch(ctx, rop)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("reverse: %+v, %v", s, err)
	}
	if n := r.names(); n["1"] != "vault" || n["2"] != "vault-vl-"+rop+"-n" {
		t.Fatalf("names after reverse %v", n)
	}
	if got := r.l.outcomes("vault"); len(got) != 1 {
		t.Errorf("a reverse to a valid cached certificate issued one: %v", got)
	}
}

func TestReverseAfterTheRetainedCertificateExpired(t *testing.T) {
	const rop = "rrrrrrrr24"
	// The retained old node holds the -o name; its certificate has expired.
	retained := "vault-vl-" + op + "-o"
	r := newRigWith(t, []tailcontroltest.Node{
		{ID: "1", NodeID: "nOld1", Name: retained},
		{ID: "2", NodeID: "nNew2", Name: "vault", Online: true},
	})
	r.c.set(tailhandoff.Incoming, "vault", time.Now().Add(-time.Hour))
	rev := tailhandoff.NewReverse(rop, "vault", "2", "1", retained, true)
	if _, err := r.engine.Prepare(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if s, err := r.engine.Switch(ctx, rop); err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	if got := r.l.outcomes("vault"); len(got) != 1 || got[0] != "issued" {
		t.Errorf("a rollback after the expiry needs one issuance: %v", got)
	}
}

func newRigWith(t *testing.T, nodes []tailcontroltest.Node) *rig {
	t.Helper()
	f := tailcontroltest.NewTailscale(nodes...)
	t.Cleanup(f.Close)
	cp, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: f.URL, ClientID: f.ClientID, ClientSecret: f.ClientSecret, HTTP: f.Client()})
	if err != nil {
		t.Fatal(err)
	}
	certs := newCerts()
	ep := &fakeEndpoints{servingOpen: true}
	res := &fakeResolver{cp: cp}
	j, l := &memJournal{}, &memLedger{}
	return &rig{f: f, cp: cp, j: j, l: l, c: certs, ep: ep, r: res, engine: &tailhandoff.Engine{
		Control: cp, Certs: certs, Ledger: l, Endpoints: ep, Resolver: res, Journal: j,
		Deadline: 3 * time.Second, CertWait: time.Second, UndoWait: 2 * time.Second, RetryEvery: 20 * time.Millisecond,
	}}
}

// TestRestoreOnHeadscale: the dead node, offline and expired, gives the
// name to the new one, through Headscale's CLI and without certificates
// (Headscale's HTTPS is the public or own-proxy path's).
func TestRestoreOnHeadscale(t *testing.T) {
	const rop = "ssssssss23"
	in, _ := tailcontrol.TempName("vault", rop, tailcontrol.RoleNew)
	f := tailcontroltest.NewHeadscale(time.Hour,
		tailcontroltest.Node{ID: "7", Name: "vault", Expires: time.Now().Add(-24 * time.Hour)},
		tailcontroltest.Node{ID: "8", Name: in, Online: true},
	)
	defer f.Close()
	cp := &tailcontrol.HeadscaleCLI{Run: f.Run}
	ep := &fakeEndpoints{}
	e := &tailhandoff.Engine{Control: cp, Endpoints: ep, Resolver: &fakeResolver{cp: cp}, Journal: &memJournal{}, RetryEvery: 20 * time.Millisecond, Deadline: 3 * time.Second}
	p, err := tailhandoff.NewRestore(rop, "vault", "7", "8", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Prepare(ctx, p); err != nil {
		t.Fatal(err)
	}
	if s, err := e.Switch(ctx, rop); err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	got := map[string]string{}
	for _, n := range f.Nodes() {
		got[n.ID] = n.Name
	}
	if got["7"] != "vault-vl-"+rop+"-o" || got["8"] != "vault" {
		t.Fatalf("names %v", got)
	}
	if _, incoming := ep.state(); !incoming {
		t.Error("the new installation did not open")
	}
}

// TestPrepareRefusesNames: every name problem is refused before anything
// changes.
func TestPrepareRefusesNames(t *testing.T) {
	in, _ := tailcontrol.TempName("vault", op, tailcontrol.RoleNew)
	for _, c := range []struct {
		name  string
		nodes []tailcontroltest.Node
		want  string
	}{
		{"a case variant of the name", []tailcontroltest.Node{{ID: "1", Name: "vault"}, {ID: "2", Name: in}, {ID: "9", Name: "VAULT"}}, `held by VAULT (9, offline)`},
		{"the name held by an unexpected node", []tailcontroltest.Node{{ID: "9", Name: "vault"}, {ID: "1", Name: "old"}, {ID: "2", Name: in}}, "held by vault (9, offline), not the expected device"},
		{"an enrolment under a taken name", []tailcontroltest.Node{{ID: "1", Name: "vault"}, {ID: "2", Name: in + "-1"}, {ID: "5", Name: in}}, "is also held by"},
		{"the incoming node suffixed", []tailcontroltest.Node{{ID: "1", Name: "vault"}, {ID: "2", Name: in + "-1"}}, "is listed as"},
		{"the serving node's temporary name held by an expired node", []tailcontroltest.Node{{ID: "1", Name: "vault"}, {ID: "2", Name: in}, {ID: "6", Name: "vault-vl-" + op + "-o", Expires: time.Now().Add(-time.Hour)}}, "(6, expired)"},
		{"the incoming node not listed", []tailcontroltest.Node{{ID: "1", Name: "vault"}}, "does not list the incoming node"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRigWith(t, c.nodes)
			before := r.names()
			_, err := r.engine.Prepare(ctx, r.forward(t))
			var he *tailhandoff.HandoffError
			if !errors.As(err, &he) || he.Phase != tailhandoff.Prepared || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v; want %q", err, c.want)
			}
			if after := r.names(); fmt.Sprint(after) != fmt.Sprint(before) || r.ep.closes != 0 {
				t.Errorf("a refusal changed %v to %v", before, after)
			}
		})
	}
}

// assertUndone: the serving node holds the name and is open again, the
// incoming node holds its own name and is closed.
func assertUndone(t *testing.T, r *rig, s *tailhandoff.State, err error) {
	t.Helper()
	var he *tailhandoff.HandoffError
	if !errors.As(err, &he) || he.Phase != tailhandoff.Undone || s.Phase != tailhandoff.Undone {
		t.Fatalf("not undone: %+v, %v", s, err)
	}
	if n := r.names(); n["1"] != "vault" || n["2"] != "vault-vl-"+op+"-n" {
		t.Errorf("names after the undo %v", n)
	}
	if serving, incoming := r.ep.state(); !serving || incoming {
		t.Errorf("after the undo: serving open %v, incoming open %v", serving, incoming)
	}
}

// TestAFailureAfterEachStepIsUndone: whatever step fails, the serving
// installation is back at its own address.
func TestAFailureAfterEachStepIsUndone(t *testing.T) {
	for _, c := range []struct {
		name   string
		inject func(r *rig)
		want   string
	}{
		{"closing the serving listener", func(r *rig) { r.ep.closeErr = errors.New("listener stuck") }, "listener stuck"},
		{"the serving node's rename", func(r *rig) { r.f.RewriteRename = once("vault-vl-"+op+"-o", "vault-vl-"+op+"-o-1") }, "read back 1"},
		{"the incoming node's rename", func(r *rig) { r.f.RewriteRename = once("vault", "vault-1") }, "read back 2"},
		{"a rate-limit refusal", func(r *rig) {
			r.c.obtain = func(_ context.Context, role tailhandoff.Role, name string) error {
				if name == "vault" {
					return fmt.Errorf("too many certificates: %w", tailhandoff.ErrRateLimited)
				}
				return nil
			}
		}, "rate limit"},
		{"certificate attempts exhausted", func(r *rig) {
			r.c.obtain = func(_ context.Context, _ tailhandoff.Role, name string) error {
				if name == "vault" {
					return errors.New("500 from the CA")
				}
				return nil
			}
		}, "3 attempts failed"},
		{"the deadline while the name propagates", func(r *rig) {
			r.engine.Deadline = 400 * time.Millisecond
			r.r.propagate = time.Hour
		}, "does not reach the incoming node"},
		{"opening the incoming installation", func(r *rig) { r.ep.openErr = errors.New("port in use") }, "port in use"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
				t.Fatal(err)
			}
			c.inject(r)
			s, err := r.engine.Switch(ctx, op)
			assertUndone(t, r, s, err)
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v; want %q", err, c.want)
			}
		})
	}
}

// once rewrites the first rename to from into to, then nothing.
func once(from, to string) func(string) string {
	var done atomic.Bool
	return func(s string) string {
		if s == from && done.CompareAndSwap(false, true) {
			return to
		}
		return s
	}
}

func TestCertificateAttemptsAreCounted(t *testing.T) {
	r := newRig(t)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	r.c.obtain = func(_ context.Context, _ tailhandoff.Role, name string) error {
		if name == "vault" {
			return errors.New("500 from the CA")
		}
		return nil
	}
	_, _ = r.engine.Switch(ctx, op)
	if got := r.l.outcomes("vault"); fmt.Sprint(got) != "[refused refused refused]" {
		t.Errorf("attempts %v", got)
	}
	// A timed-out attempt stays counted: it may have been issued.
	r2 := newRig(t)
	if _, err := r2.engine.Prepare(ctx, r2.forward(t)); err != nil {
		t.Fatal(err)
	}
	r2.engine.CertWait = 200 * time.Millisecond
	r2.c.obtain = func(ctx context.Context, _ tailhandoff.Role, name string) error {
		if name == "vault" {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	s, err := r2.engine.Switch(ctx, op)
	assertUndone(t, r2, s, err)
	if got := r2.l.outcomes("vault"); fmt.Sprint(got) != "[started]" {
		t.Errorf("a timed-out attempt: %v", got)
	}
	if n, _ := r2.l.Count(ctx, "vault", time.Now().Add(-time.Hour)); n != 1 {
		t.Errorf("a timed-out attempt counts %d", n)
	}
}

// TestTheCountIsCarriedAcrossOperations: issuances by earlier operations
// (restores, renewals, migrations) count against the CA's weekly limit; a
// handoff that would pass it is refused before anything changes, and
// issuances older than a week no longer count.
func TestTheCountIsCarriedAcrossOperations(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 5; i++ {
		id, _ := r.l.Start(ctx, "vault", time.Now().Add(-time.Duration(i+1)*24*time.Hour))
		_ = r.l.End(ctx, id, tailhandoff.Issued, time.Now())
	}
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err == nil || !strings.Contains(err.Error(), "would pass the CA's limit of 5") {
		t.Fatalf("a sixth certificate in a week: %v", err)
	}
	if r.names()["1"] != "vault" || r.ep.closes != 0 {
		t.Fatal("the refusal changed something")
	}
	// Refused attempts never count; one of the five a week old drops out.
	r2 := newRig(t)
	for i := 0; i < 4; i++ {
		id, _ := r2.l.Start(ctx, "vault", time.Now().Add(-time.Hour))
		_ = r2.l.End(ctx, id, tailhandoff.Issued, time.Now())
	}
	id, _ := r2.l.Start(ctx, "vault", time.Now().Add(-8*24*time.Hour))
	_ = r2.l.End(ctx, id, tailhandoff.Issued, time.Now())
	id, _ = r2.l.Start(ctx, "vault", time.Now())
	_ = r2.l.End(ctx, id, tailhandoff.Refused, time.Now())
	if _, err := r2.engine.Prepare(ctx, r2.forward(t)); err != nil {
		t.Fatalf("four in the week: %v", err)
	}
	if s, err := r2.engine.Switch(ctx, op); err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	// Now five in the week: the next handoff needing one (the retained
	// node's certificate has expired) is refused.
	r2.c.set(tailhandoff.Incoming, "vault", time.Now().Add(-time.Hour))
	const rop = "rrrrrrrr25"
	rev := tailhandoff.NewReverse(rop, "vault", "2", "1", "vault-vl-"+op+"-o", true)
	if _, err := r2.engine.Prepare(ctx, rev); err == nil || !strings.Contains(err.Error(), "would pass") {
		t.Errorf("the next operation: %v", err)
	}
}

// TestTheServingCertificateAndTheRollbackWindow: a serving certificate that
// ends before the window plus seven days is renewed while the node holds
// the name; if that fails, only the operator's acceptance lets the handoff
// go on, and the journal says the rollback will need a certificate.
func TestTheServingCertificateAndTheRollbackWindow(t *testing.T) {
	r := newRig(t)
	r.c.set(tailhandoff.Serving, "vault", time.Now().Add(10*24*time.Hour)) // before 30 + 7 days
	s, err := r.engine.Prepare(ctx, r.forward(t))
	if err != nil || s.RollbackNeedsCertificate || s.ServingCertExpiry.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("renewed: %+v, %v", s, err)
	}
	r2 := newRig(t)
	r2.c.set(tailhandoff.Serving, "vault", time.Now().Add(10*24*time.Hour))
	r2.c.obtain = func(_ context.Context, role tailhandoff.Role, _ string) error {
		if role == tailhandoff.Serving {
			return errors.New("500 from the CA")
		}
		return nil
	}
	p := r2.forward(t)
	if _, err := r2.engine.Prepare(ctx, p); err == nil || !strings.Contains(err.Error(), "accept that to go on") {
		t.Fatalf("without acceptance: %v", err)
	}
	p.AcceptRollbackCertificate = true
	s, err = r2.engine.Prepare(ctx, p)
	if err != nil || !s.RollbackNeedsCertificate {
		t.Fatalf("accepted: %+v, %v", s, err)
	}
}

// TestAControlServerRestartMidHandoff: the control plane goes away between
// closing the serving listener and the renames, and comes back: the
// renames are tried again within the deadline and the handoff completes.
func TestAControlServerRestartMidHandoff(t *testing.T) {
	r := newRig(t)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	r.ep.onClose = func() {
		r.f.SetUnavailable(true)
		go func() {
			time.Sleep(300 * time.Millisecond)
			r.f.SetUnavailable(false)
		}()
	}
	s, err := r.engine.Switch(ctx, op)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("%+v, %v", s, err)
	}
	if n := r.names(); n["2"] != "vault" {
		t.Errorf("names %v", n)
	}
}

// TestTheControlPlaneLostDuringAnUndo: the switch fails, and the control
// plane is gone for the whole undo: both installations stay closed, the
// journal says the undo is pending, and Resume finishes it once the
// control plane answers.
func TestTheControlPlaneLostDuringAnUndo(t *testing.T) {
	r := newRig(t)
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	r.engine.Deadline = 400 * time.Millisecond
	r.engine.UndoWait = 300 * time.Millisecond
	r.r.never.Store(true)
	r.r.onCheck = func() {
		// The final check never succeeds; the control plane goes with it.
		r.f.SetUnavailable(true)
	}
	s, err := r.engine.Switch(ctx, op)
	var he *tailhandoff.HandoffError
	if !errors.As(err, &he) || he.Phase != tailhandoff.UndoPending || s.Phase != tailhandoff.UndoPending {
		t.Fatalf("%+v, %v", s, err)
	}
	if serving, incoming := r.ep.state(); serving || incoming {
		t.Fatalf("an installation opened during a pending undo: serving %v, incoming %v", serving, incoming)
	}
	if saved, _ := r.j.Load(ctx, op); saved.Phase != tailhandoff.UndoPending || saved.Failure == "" {
		t.Fatalf("journal %+v", saved)
	}
	// Still unreachable: Resume keeps both closed.
	if s, err := r.engine.Resume(ctx, op); s.Phase != tailhandoff.UndoPending || err == nil {
		t.Fatalf("resume while unreachable: %+v, %v", s, err)
	}
	r.r.onCheck = nil
	r.f.SetUnavailable(false)
	s, err = r.engine.Resume(ctx, op)
	assertUndone(t, r, s, err)
}

// TestResumeAfterACrash: a switch the process died in is undone from the
// control plane's own listing, whichever way the last step went; one that
// died while opening the incoming installation is finished.
func TestResumeAfterACrash(t *testing.T) {
	r := newRig(t)
	p := r.forward(t)
	if _, err := r.engine.Prepare(ctx, p); err != nil {
		t.Fatal(err)
	}
	// The process died after the serving rename was recorded and made.
	s, _ := r.j.Load(ctx, op)
	s.Phase, s.ServingClosed, s.ServingRenamed, s.SwitchStarted = tailhandoff.Switching, true, true, time.Now()
	_ = r.j.Save(ctx, s)
	r.ep.servingOpen = false
	if _, err := tailcontrol.RenameAndReadBack(ctx, r.cp, "1", s.ServingTemp); err != nil {
		t.Fatal(err)
	}
	s, err := r.engine.Resume(ctx, op)
	assertUndone(t, r, s, err)

	// The process died after deciding to open the incoming installation.
	r2 := newRig(t)
	if _, err := r2.engine.Prepare(ctx, r2.forward(t)); err != nil {
		t.Fatal(err)
	}
	s, _ = r2.j.Load(ctx, op)
	s.Phase, s.ServingClosed, s.ServingRenamed, s.IncomingRenamed, s.IncomingOpened = tailhandoff.Switching, true, true, true, true
	_ = r2.j.Save(ctx, s)
	r2.ep.servingOpen = false
	for _, step := range [][2]string{{"1", s.ServingTemp}, {"2", "vault"}} {
		if _, err := tailcontrol.RenameAndReadBack(ctx, r2.cp, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	s, err = r2.engine.Resume(ctx, op)
	if err != nil || s.Phase != tailhandoff.Done {
		t.Fatalf("finished: %+v, %v", s, err)
	}
	if _, incoming := r2.ep.state(); !incoming {
		t.Error("the incoming installation was not opened")
	}
}

func TestSwitchNeedsAPreparedOperation(t *testing.T) {
	r := newRig(t)
	if _, err := r.engine.Switch(ctx, op); err == nil {
		t.Error("an unknown operation switched")
	}
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.engine.Switch(ctx, op); err != nil {
		t.Fatal(err)
	}
	if _, err := r.engine.Switch(ctx, op); err == nil {
		t.Error("a done operation switched again")
	}
	if _, err := r.engine.Prepare(ctx, r.forward(t)); err == nil {
		t.Error("a done operation prepared again")
	}
}
