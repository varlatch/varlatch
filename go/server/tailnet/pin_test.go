// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/tailnet/tailnettest"
)

// statusNode is a node that says what the test sets. block, when set,
// holds every Status call until it is closed.
type statusNode struct {
	mu    sync.Mutex
	st    Status
	err   error
	block chan struct{}
}

func (n *statusNode) Status(context.Context) (Status, error) {
	n.mu.Lock()
	st, err, block := n.st, n.err, n.block
	n.mu.Unlock()
	if block != nil {
		<-block
	}
	return st, err
}

func (n *statusNode) set(st Status, err error) {
	n.mu.Lock()
	n.st, n.err = st, err
	n.mu.Unlock()
}

func running(id, suffix string) Status {
	return Status{BackendState: "Running", SelfID: "nSelf", DNSName: "varlatch." + suffix, Suffix: suffix, TailnetID: id, Tags: []string{"tag:varlatch"}}
}

// enrolling is a manager over node for a node enrolling now (its pin file
// marked by BeginEnrolment, as varlatchd does for a node without state).
func enrolling(t *testing.T, node StatusNode, controlURL, dir string, now func() time.Time) *Manager {
	t.Helper()
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(node, controlURL, dir, 8687, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func open(m *Manager) bool { _, ok := m.Pinned(); return ok }

// The pin is recorded at the first Running status of an enrolling node,
// and from then on a change closes tailnet access: a suffix under the same
// tailnet is offered for re-pin (and re-pinned, with its history); a
// different tailnet StableID or control URL never is.
func TestPinLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &statusNode{st: Status{BackendState: "NeedsLogin"}}
	clock := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	m := enrolling(t, node, "", dir, func() time.Time { return clock })
	m.Check(ctx)
	if m.Closed() != "not-enrolled" {
		t.Fatalf("before the node runs: %q", m.Closed())
	}
	node.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	if suffix, open := m.Pinned(); !open || suffix != "corp.ts.net" {
		t.Fatalf("after enrolment: %q %v", suffix, open)
	}

	// The tailnet's DNS name changes: closed, offered for re-pin.
	node.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if m.Closed() != PinSuffix {
		t.Fatalf("a changed suffix: %q", m.Closed())
	}
	if v := m.RepinView(ctx); !v.Offered || v.Reason != PinSuffix || v.Closed != PinSuffix {
		t.Fatalf("the re-pin view: %+v", v)
	}
	clock = clock.Add(time.Hour)
	old, next, err := m.Repin(ctx, false)
	if err != nil || old.Suffix != "corp.ts.net" || next.Suffix != "corp-new.ts.net" || next.Closed != nil ||
		len(next.History) != 1 || next.History[0] != (Repinned{Suffix: "corp.ts.net", Until: "2026-11-17T10:00:00Z", Reason: PinSuffix}) {
		t.Fatalf("the re-pin: %+v %+v %v", old, next, err)
	}
	if saved, _ := LoadPin(filepath.Join(dir, PinFile)); saved == nil || saved.Suffix != "corp-new.ts.net" || saved.Closed != nil {
		t.Fatalf("the saved pin: %+v", saved)
	}
	if !open(m) {
		t.Fatal("re-pinned, but tailnet access is still closed")
	}

	// Another tailnet under the same name: never re-pinned.
	node.set(running("Tother9", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if m.Closed() != PinTailnet {
		t.Fatalf("another tailnet: %q", m.Closed())
	}
	if _, _, err := m.Repin(ctx, false); !errors.Is(err, ErrNotRepinnable) {
		t.Fatalf("re-pinning another tailnet: %v", err)
	}
	r := NewPinnedResolver(nil, m, nil)
	if got := r.Resolve(ctx, "100.64.0.1:1"); got.Refused != OtherTailnet {
		t.Fatalf("a peer while the pin is broken: %+v", got)
	}

	// The configured control server changes: never re-pinned either.
	dir2 := t.TempDir()
	node.set(running("Tabc123", "corp.ts.net"), nil)
	enrolling(t, node, "", dir2, nil).Check(ctx)
	m2, err := NewManager(node, "https://headscale.example.com", dir2, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m2.Check(ctx)
	if m2.Closed() != PinControlURL {
		t.Fatalf("another control server: %q", m2.Closed())
	}
	if _, _, err := m2.Repin(ctx, true); !errors.Is(err, ErrNotRepinnable) {
		t.Fatalf("re-pinning another control server: %v", err)
	}
}

// On Headscale (no tailnet StableID), a changed base_domain under the same
// control URL is the change a re-pin takes.
func TestHeadscalePin(t *testing.T) {
	ctx := context.Background()
	node := &statusNode{st: running("", "vl.example")}
	m := enrolling(t, node, "https://headscale.example.com", t.TempDir(), nil)
	m.Check(ctx)
	node.set(running("", "vl2.example"), nil)
	m.Check(ctx)
	if m.Closed() != PinSuffix {
		t.Fatalf("a changed base_domain: %q", m.Closed())
	}
	if _, next, err := m.Repin(ctx, false); err != nil || next.Suffix != "vl2.example" || next.TailnetID != "" {
		t.Fatalf("its re-pin: %+v %v", next, err)
	}
}

// #220 review P4: a check that fails, or finds the node not running or
// without a tailnet, closes access until a check succeeds; a re-pin needs
// its own fresh check to succeed, and never writes what an earlier check
// saw.
func TestAFailedCheckClosesAccess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, node, "", dir, nil)
	m.Check(ctx)
	for name, c := range map[string]struct {
		st  Status
		err error
	}{
		"the status failing": {Status{}, errors.New("down")},
		"not running":        {Status{BackendState: "Stopped"}, nil},
		"no tailnet":         {Status{BackendState: "Running", SelfID: "nSelf"}, nil},
	} {
		node.set(running("Tabc123", "corp.ts.net"), nil)
		m.Check(ctx)
		if !open(m) {
			t.Fatalf("%s: not open to begin with", name)
		}
		node.set(c.st, c.err)
		m.Check(ctx)
		if open(m) || m.Closed() != PinUnknown {
			t.Errorf("%s: open %v, closed %q", name, open(m), m.Closed())
		}
	}
	node.set(Status{BackendState: "Stopped"}, nil)
	m.Check(ctx)
	report := string(jsvalueStringify(m.Report()))
	if want := `"localApi":{"status":"pass"},"node":{"status":"fail","reason":"NOT_RUNNING"}`; !strings.Contains(report, want) {
		t.Errorf("%s lacks %s", report, want)
	}
	node.set(Status{}, errors.New("down"))
	m.Check(ctx)
	if report := string(jsvalueStringify(m.Report())); !strings.Contains(report, `"localApi":{"status":"fail","reason":"LOCALAPI_UNAVAILABLE"},"node":{"status":"unknown","reason":"NOT_CHECKED"}`) {
		t.Errorf("the node down: %s", report)
	}

	// The suffix changed, then the status fails: the re-pin's own check
	// failed, so nothing is written.
	node.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	node.set(Status{}, errors.New("down"))
	if _, next, err := m.Repin(ctx, false); !errors.Is(err, ErrNothingToRepin) || next != nil {
		t.Fatalf("a re-pin without a current observation: %+v %v", next, err)
	}
	if saved, _ := LoadPin(filepath.Join(dir, PinFile)); saved.Suffix != "corp.ts.net" || saved.Closed == nil {
		t.Fatalf("the pin after a refused re-pin: %+v", saved)
	}
}

// #220 review P4: checks are serialized, so an older, slower reading of
// the node never overwrites a newer one.
func TestChecksAreSerialized(t *testing.T) {
	ctx := context.Background()
	node := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, node, "", t.TempDir(), nil)
	m.Check(ctx)
	// An older check holds a reading of the pinned tailnet...
	node.mu.Lock()
	node.block = make(chan struct{})
	release := node.block
	node.mu.Unlock()
	older := make(chan struct{})
	go func() { m.Check(ctx); close(older) }()
	time.Sleep(20 * time.Millisecond)
	// ...while the node moves to another tailnet and a newer check starts.
	node.set(running("Tother9", "corp.ts.net"), nil)
	node.mu.Lock()
	node.block = nil
	node.mu.Unlock()
	newer := make(chan struct{})
	go func() { m.Check(ctx); close(newer) }()
	select {
	case <-newer:
		t.Fatal("a newer check ran while an older one was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-older
	<-newer
	if open(m) || m.Closed() != PinTailnet {
		t.Fatalf("after both checks: open %v, %q", open(m), m.Closed())
	}
}

// #220 review P5: a detected mismatch is latched, across restarts too,
// and only a re-pin on the host clears it, even when the tailnet changes
// back.
func TestAMismatchIsLatched(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, node, "", dir, nil)
	m.Check(ctx)
	node.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	node.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	if open(m) || m.Closed() != PinSuffix {
		t.Fatalf("changed back: open %v, %q", open(m), m.Closed())
	}
	// A restart keeps it closed.
	m, err := NewManager(node, "", dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	if open(m) || m.Closed() != PinSuffix {
		t.Fatalf("after a restart: open %v, %q", open(m), m.Closed())
	}
	if v := m.RepinView(ctx); !v.Offered || v.Reason != "" || v.Closed != PinSuffix {
		t.Fatalf("the re-pin view: %+v", v)
	}
	old, next, err := m.Repin(ctx, false)
	if err != nil || next == nil || old.Suffix != "corp.ts.net" || next.Suffix != "corp.ts.net" || next.Closed != nil || next.History[0].Reason != PinSuffix || !open(m) {
		t.Fatalf("the reopening: %+v %+v %v", old, next, err)
	}
	// A different tailnet's latch is never cleared by the tailnet changing
	// back either, and the re-pin still refuses it while it is different.
	node.set(running("Tother9", "corp.ts.net"), nil)
	m.Check(ctx)
	if _, _, err := m.Repin(ctx, false); !errors.Is(err, ErrNotRepinnable) {
		t.Fatalf("re-pinning another tailnet: %v", err)
	}
}

// #220 review P6: an enrolled node whose pin file is missing is never
// pinned silently: access stays closed until the host adopts its tailnet.
// BeginEnrolment never replaces a pin.
func TestAMissingPinIsNeverTakenSilently(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m, err := NewManager(node, "", dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	if open(m) || m.Closed() != PinMissing {
		t.Fatalf("an enrolled node without a pin: open %v, %q", open(m), m.Closed())
	}
	if _, err := os.Stat(filepath.Join(dir, PinFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pin was written: %v", err)
	}
	if v := m.RepinView(ctx); !v.Missing || !v.Offered {
		t.Fatalf("the view: %+v", v)
	}
	if _, _, err := m.Repin(ctx, false); !errors.Is(err, ErrPinMissing) || open(m) {
		t.Fatalf("a re-pin without adopting: %v", err)
	}
	old, next, err := m.Repin(ctx, true)
	if err != nil || old != nil || next.Suffix != "corp.ts.net" || next.TailnetID != "Tabc123" || !open(m) {
		t.Fatalf("adopting: %+v %+v %v", old, next, err)
	}
	if err := BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	if saved, _ := LoadPin(filepath.Join(dir, PinFile)); saved.Enrolling || saved.Suffix != "corp.ts.net" {
		t.Fatalf("BeginEnrolment replaced the pin: %+v", saved)
	}
}

// blockingNode answers WhoIs only once released.
type blockingNode struct {
	called, release chan struct{}
}

func (n *blockingNode) WhoIs(context.Context, string) (Peer, error) {
	close(n.called)
	<-n.release
	return Peer{StableID: "nPeer", Name: "build-1.corp.ts.net.", Tags: []string{"tag:prod"}}, nil
}

func (n *blockingNode) SelfID(context.Context) (string, error) { return "nSelf", nil }

// #220 review P3: a resolution in flight when access closes returns no
// Tailnet Context, and one made before stops counting at authorization.
func TestResolutionsDoNotOutliveAccess(t *testing.T) {
	ctx := context.Background()
	status := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, status, "", t.TempDir(), nil)
	m.Check(ctx)
	node := &blockingNode{called: make(chan struct{}), release: make(chan struct{})}
	r := NewPinnedResolver(node, m, nil)
	got := make(chan Resolution, 1)
	go func() { got <- r.Resolve(ctx, "100.64.0.7:1") }()
	<-node.called
	status.set(running("Tother9", "corp.ts.net"), nil)
	m.Check(ctx)
	close(node.release)
	if res := <-got; res.Context != nil || res.Refused != OtherTailnet {
		t.Fatalf("a resolution in flight when access closed: %+v", res)
	}

	// A resolution made while open, read after access closed.
	dir := t.TempDir()
	status = &statusNode{st: running("Tabc123", "corp.ts.net")}
	m = enrolling(t, status, "", dir, nil)
	m.Check(ctx)
	node = &blockingNode{called: make(chan struct{}), release: make(chan struct{})}
	close(node.release)
	res := NewPinnedResolver(node, m, nil).Resolve(ctx, "100.64.0.7:1")
	if res.Context == nil || !res.Valid() {
		t.Fatalf("a resolution while open: %+v", res)
	}
	actx := authz.WithTailnet(ctx, res.Context, res.Valid)
	if authz.TailnetFrom(actx) == nil {
		t.Fatal("no Tailnet Context while open")
	}
	status.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if res.Valid() || authz.TailnetFrom(actx) != nil {
		t.Fatal("a Tailnet Context counts after access closed")
	}
	// Reopened by a re-pin: a new period, the old resolution stays void.
	if _, _, err := m.Repin(ctx, false); err != nil || !open(m) {
		t.Fatal(err)
	}
	if res.Valid() || authz.TailnetFrom(actx) != nil {
		t.Fatal("a Tailnet Context of an earlier period counts again")
	}
}

// #220 review P1: while access is closed nothing is admitted, and what was
// admitted while it was open is cancelled when it closes.
func TestAdmission(t *testing.T) {
	ctx := context.Background()
	status := &statusNode{st: Status{BackendState: "NeedsLogin"}}
	m := enrolling(t, status, "", t.TempDir(), nil)
	m.Check(ctx)
	if _, _, ok := m.Admit(ctx); ok {
		t.Fatal("admitted before enrolment")
	}
	status.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	actx, release, ok := m.Admit(ctx)
	if !ok || actx.Err() != nil {
		t.Fatal("not admitted while open")
	}
	defer release()
	status.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if actx.Err() == nil {
		t.Fatal("a request admitted while open runs on after access closed")
	}
	if _, _, ok := m.Admit(ctx); ok {
		t.Fatal("admitted after access closed")
	}
	if _, _, err := m.Repin(ctx, false); err != nil {
		t.Fatal(err)
	}
	if again, rel, ok := m.Admit(ctx); !ok || again.Err() != nil {
		t.Fatal("not admitted after the re-pin")
	} else {
		rel()
	}
}

// #220 review P2: the node's control server is never left to tsnet's
// environment (TS_CONTROL_URL), and no tsnet environment override is
// accepted.
func TestNodeTakesItsSettingsFromTheConfigOnly(t *testing.T) {
	cfg := NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", Tags: []string{"tag:varlatch"}}
	srv, err := newServer(cfg)
	if err != nil || srv.ControlURL != TailscaleControlURL || TailscaleControlURL != config.TailscaleControlURL {
		t.Fatalf("no control URL configured: %q %v", srv.ControlURL, err)
	}
	for _, name := range tsnetEnv {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "https://headscale.example.com")
			if _, err := newServer(cfg); err == nil || !strings.Contains(err.Error(), name+" is set") {
				t.Fatalf("with %s set: %v", name, err)
			}
			if _, err := StartNode(cfg); err == nil {
				t.Fatalf("StartNode with %s set", name)
			}
		})
	}
}

// #220 re-check P1: a write that started while access was open, during
// which access closes, is rolled back at the write boundary, whatever the
// request's context; a write admitted before a closure stays refused after
// a re-pin reopens access; one admitted in an open period commits.
func TestAWriteDoesNotCommitAfterAccessCloses(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE w (n INTEGER) STRICT`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	insert := func(actx context.Context, n int, during func()) error {
		return store.Write(actx, func(tx *storage.Tx) error {
			if during != nil {
				during()
			}
			_, err := tx.ExecContext(actx, `INSERT INTO w (n) VALUES (?)`, n)
			return err
		})
	}
	rows := func() int {
		var n int
		if err := store.Reader().QueryRowContext(ctx, `SELECT count(*) FROM w`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	status := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, status, "", t.TempDir(), nil)
	m.Check(ctx)

	open1, release1, ok := m.Admit(ctx)
	if !ok {
		t.Fatal("not admitted")
	}
	defer release1()
	if err := insert(open1, 1, nil); err != nil || rows() != 1 {
		t.Fatalf("a write while open: %v, %d rows", err, rows())
	}
	// Sol's sequence: access closes inside the started job, and the job
	// goes on with the cancelled context.
	err = insert(open1, 2, func() {
		status.set(running("Tother9", "corp.ts.net"), nil)
		m.Check(ctx)
		if open1.Err() == nil {
			t.Error("the request was not cancelled when access closed")
		}
	})
	var de *domainerr.Error
	if !errors.As(err, &de) || de.Code != "TAILNET_CONTEXT_UNAVAILABLE" || rows() != 1 {
		t.Fatalf("a write during which access closed: %v, %d rows", err, rows())
	}
	// Reopened by a re-pin (the tailnet changed back): the old admission
	// stays refused, a new one commits.
	status.set(running("Tabc123", "corp.ts.net"), nil)
	if _, _, err := m.Repin(ctx, false); err != nil || !open(m) {
		t.Fatalf("the re-pin: %v", err)
	}
	// Its context was cancelled when access closed, so the write is
	// abandoned before it starts; were it started, its guard refuses.
	if err := insert(open1, 3, nil); err == nil || rows() != 1 {
		t.Fatalf("a write of an earlier period: %v, %d rows", err, rows())
	}
	stale := storage.WithCommitGuard(ctx, admissionGuard{m: m, live: 1})
	if err := insert(stale, 3, nil); !errors.As(err, &de) || rows() != 1 {
		t.Fatalf("a started write of an earlier period: %v, %d rows", err, rows())
	}
	open2, release2, ok := m.Admit(ctx)
	if !ok {
		t.Fatal("not admitted after the re-pin")
	}
	defer release2()
	if err := insert(open2, 4, nil); err != nil || rows() != 2 {
		t.Fatalf("a write of the new period: %v, %d rows", err, rows())
	}
}

// #220 re-check P2: the listeners file is written with access as it is
// after the check that changed it, on every path.
func TestTheWrittenReportFollowsAccess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	status := &statusNode{st: running("Tabc123", "corp.ts.net")}
	m := enrolling(t, status, "", dir, nil)
	file := func() string {
		b, err := os.ReadFile(filepath.Join(dir, ListenersFile))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	m.Check(ctx)
	if f := file(); !strings.Contains(f, `"node":{"status":"pass"}`) {
		t.Fatalf("after enrolment: %s", f)
	}
	status.set(running("Tabc123", "corp-new.ts.net"), nil)
	m.Check(ctx)
	if f := file(); !strings.Contains(f, `"node":{"status":"fail","reason":"OTHER_TAILNET"}`) {
		t.Fatalf("after a mismatch: %s", f)
	}
	if _, _, err := m.Repin(ctx, false); err != nil {
		t.Fatal(err)
	}
	if f := file(); !strings.Contains(f, `"node":{"status":"pass"}`) {
		t.Fatalf("after the re-pin: %s", f)

// With the browser endpoint configured, the report names its URL (once
// the tailnet is known), checks its certificate (browserTls) and both
// listeners, and fails the node when its name is no longer the endpoint's
// host (observe.ts).
func TestReportWithTheBrowserEndpoint(t *testing.T) {
	ctx := context.Background()
	node := &statusNode{st: Status{BackendState: "NeedsLogin"}}
	m := enrolling(t, node, "", t.TempDir(), nil)
	m.SetBrowser("Varlatch", 8443)
	ca, err := tailnettest.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	cert := NewCertificate(ca, m.BrowserHost, nil, nil, nil)
	m.SetCertificate(cert)
	m.Check(ctx)
	report := string(jsvalueStringify(m.Report()))
	if m.BrowserEndpoint() != "" || !strings.Contains(report, `"browserEndpoint":null`) ||
		!strings.Contains(report, `"browserTls":{"status":"fail","reason":"NO_CERTIFICATE"}`) {
		t.Fatalf("before enrolment: %q %s", m.BrowserEndpoint(), report)
	}
	node.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	m.Listening(true)
	if !cert.Refresh(ctx) {
		t.Fatal(cert.LastError())
	}
	m.Check(ctx)
	report = string(jsvalueStringify(m.Report()))
	notAfter := audit.ISOTime(cert.NotAfter().UnixMicro())
	for _, want := range []string{`"browserEndpoint":"https://varlatch.corp.ts.net:8443"`,
		`"checks":{"listener":{"status":"unknown","reason":"NOT_CHECKED"},"browserTls":{"status":"pass","certificateNotAfter":"` + notAfter + `"},"localApi":{"status":"pass"},"node":{"status":"pass"}}`} {
		if !strings.Contains(report, want) {
			t.Errorf("%s lacks %s", report, want)
		}
	}
	if m.BrowserEndpoint() != "https://varlatch.corp.ts.net:8443" || m.BrowserHost() != "varlatch.corp.ts.net" {
		t.Errorf("the endpoint: %q %q", m.BrowserEndpoint(), m.BrowserHost())
	}
	m.ListeningBrowser(false)
	m.Check(ctx)
	if report = string(jsvalueStringify(m.Report())); !strings.Contains(report, `"listener":{"status":"fail","reason":"NOT_LISTENING"}`) {
		t.Errorf("the browser endpoint not listening: %s", report)
	}
	m.ListeningBrowser(true)
	m.Check(ctx)
	if report = string(jsvalueStringify(m.Report())); !strings.Contains(report, `"listener":{"status":"pass"}`) {
		t.Errorf("both listening: %s", report)
	}
	// An admin renamed the node: its certificate no longer fits.
	renamed := running("Tabc123", "corp.ts.net")
	renamed.DNSName = "varlatch-2.corp.ts.net"
	node.set(renamed, nil)
	m.Check(ctx)
	if report = string(jsvalueStringify(m.Report())); !strings.Contains(report, `"node":{"status":"fail","reason":"NAME_CHANGED"}`) {
		t.Errorf("a renamed node: %s", report)
	}
}
