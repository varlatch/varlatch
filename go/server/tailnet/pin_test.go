// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// statusNode is a node that says what the test sets.
type statusNode struct {
	st  Status
	err error
}

func (n *statusNode) Status(context.Context) (Status, error) { return n.st, n.err }

func running(id, suffix string) Status {
	return Status{BackendState: "Running", SelfID: "nSelf", DNSName: "varlatch." + suffix, Suffix: suffix, TailnetID: id, Tags: []string{"tag:varlatch"}}
}

// The pin is recorded at the first Running status, and from then on a
// change closes tailnet access: a suffix under the same tailnet is offered
// for re-pin (and re-pinned, with its history); a different tailnet
// StableID or control URL never is.
func TestPinLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &statusNode{st: Status{BackendState: "NeedsLogin"}}
	clock := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	m, err := NewManager(node, "", dir, 8687, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	if m.Closed() != "not-enrolled" {
		t.Fatalf("before the node runs: %q", m.Closed())
	}
	node.st = running("Tabc123", "corp.ts.net")
	m.Check(ctx)
	if suffix, open := m.Pinned(); !open || suffix != "corp.ts.net" {
		t.Fatalf("after enrolment: %q %v", suffix, open)
	}

	// The tailnet's DNS name changes: closed, offered for re-pin.
	node.st = running("Tabc123", "corp-new.ts.net")
	m.Check(ctx)
	if m.Closed() != PinSuffix {
		t.Fatalf("a changed suffix: %q", m.Closed())
	}
	if v := m.RepinView(ctx); !v.Offered || v.Reason != PinSuffix {
		t.Fatalf("the re-pin view: %+v", v)
	}
	clock = clock.Add(time.Hour)
	old, next, err := m.Repin(ctx)
	if err != nil || old.Suffix != "corp.ts.net" || next.Suffix != "corp-new.ts.net" || len(next.History) != 1 || next.History[0].Suffix != "corp.ts.net" {
		t.Fatalf("the re-pin: %+v %+v %v", old, next, err)
	}
	if saved, _ := LoadPin(filepath.Join(dir, PinFile)); saved == nil || saved.Suffix != "corp-new.ts.net" {
		t.Fatalf("the saved pin: %+v", saved)
	}
	if _, open := m.Pinned(); !open {
		t.Fatal("re-pinned, but tailnet access is still closed")
	}

	// Another tailnet under the same name: never re-pinned.
	node.st = running("Tother9", "corp-new.ts.net")
	m.Check(ctx)
	if m.Closed() != PinTailnet {
		t.Fatalf("another tailnet: %q", m.Closed())
	}
	if _, _, err := m.Repin(ctx); !errors.Is(err, ErrNotRepinnable) {
		t.Fatalf("re-pinning another tailnet: %v", err)
	}

	// The configured control server changes: never re-pinned either.
	node.st = running("Tabc123", "corp-new.ts.net")
	m2, err := NewManager(node, "https://headscale.example.com", dir, 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m2.Check(ctx)
	if m2.Closed() != PinControlURL {
		t.Fatalf("another control server: %q", m2.Closed())
	}
	if _, _, err := m2.Repin(ctx); !errors.Is(err, ErrNotRepinnable) {
		t.Fatalf("re-pinning another control server: %v", err)
	}
	r := NewPinnedResolver(nil, m2, nil)
	if got := r.Resolve(ctx, "100.64.0.1:1"); got.Refused != OtherTailnet {
		t.Fatalf("a peer while the pin is broken: %+v", got)
	}
}

// On Headscale (no tailnet StableID), a changed base_domain under the same
// control URL is the change a re-pin takes.
func TestHeadscalePin(t *testing.T) {
	ctx := context.Background()
	node := &statusNode{st: running("", "vl.example")}
	m, err := NewManager(node, "https://headscale.example.com", t.TempDir(), 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	node.st = running("", "vl2.example")
	m.Check(ctx)
	if m.Closed() != PinSuffix {
		t.Fatalf("a changed base_domain: %q", m.Closed())
	}
	if _, next, err := m.Repin(ctx); err != nil || next.Suffix != "vl2.example" || next.TailnetID != "" {
		t.Fatalf("its re-pin: %+v %v", next, err)
	}
}

// The node's status failing is reported, and closes nothing that was open
// for a reason of its own (WhoIs then fails as well).
func TestReportWhenTheNodeIsDown(t *testing.T) {
	ctx := context.Background()
	node := &statusNode{st: running("", "corp.ts.net")}
	m, err := NewManager(node, "", t.TempDir(), 8687, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	node.err = errors.New("down")
	m.Check(ctx)
	report := string(jsvalueStringify(m.Report()))
	if want := `"checks":{"listener":{"status":"unknown","reason":"NOT_CHECKED"},"localApi":{"status":"fail","reason":"LOCALAPI_UNAVAILABLE"},"node":{"status":"unknown","reason":"NOT_CHECKED"}}`; !strings.Contains(report, want) {
		t.Fatalf("%s lacks %s", report, want)
	}
}
