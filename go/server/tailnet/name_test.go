// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The read-back after enrolment (decision 16): a node the control plane
// named its configured hostname with a suffix (varlatch-1) keeps tailnet
// access closed, latched, and a re-pin is refused while the name still
// carries it; once the old node is deleted and this one renamed, the
// re-pin reopens. A name an administrator chose is not a suffix.
func TestASuffixedNameKeepsAccessClosed(t *testing.T) {
	ctx := context.Background()
	for name, want := range map[string]bool{
		"varlatch.corp.ts.net": false, "Varlatch-1.corp.ts.net": true, "varlatch-12.corp.ts.net": true,
		"varlatch-prod.corp.ts.net": false, "vault.corp.ts.net": false, "varlatch-.corp.ts.net": false, "": false,
	} {
		if got := suffixedName(name, "varlatch"); got != want {
			t.Errorf("%q: %v", name, got)
		}
	}
	if suffixedName("varlatch-1.corp.ts.net", "") {
		t.Error("no configured hostname: no read-back")
	}

	node := &statusNode{st: running("Tabc123", "corp.ts.net")}
	st := node.st
	st.DNSName = "varlatch-1.corp.ts.net"
	node.set(st, nil)
	m := enrolling(t, node, "", t.TempDir(), nil)
	m.SetHostname("varlatch")
	m.Check(ctx)
	if open(m) || m.Closed() != NameSuffixed {
		t.Fatalf("a suffixed name: open %v, %q", open(m), m.Closed())
	}
	if v := m.RepinView(ctx); v.Offered || v.Reason != NameSuffixed {
		t.Fatalf("the re-pin view: %+v", v)
	}
	if _, next, err := m.Repin(ctx, false); !errors.Is(err, ErrNameSuffixed) || next != nil || open(m) {
		t.Fatalf("a re-pin while suffixed: %+v %v", next, err)
	}
	// Renamed: the re-pin reopens, with the closure in its history.
	node.set(running("Tabc123", "corp.ts.net"), nil)
	m.Check(ctx)
	if open(m) {
		t.Fatal("the closure was not latched")
	}
	if _, next, err := m.Repin(ctx, false); err != nil || next == nil || next.Closed != nil || next.History[0].Reason != NameSuffixed || !open(m) {
		t.Fatalf("the re-pin after the rename: %+v %v", next, err)
	}
	// A name an administrator chose keeps access open.
	node2 := &statusNode{}
	st2 := running("Tabc123", "corp.ts.net")
	st2.DNSName = "vault.corp.ts.net"
	node2.set(st2, nil)
	m2 := enrolling(t, node2, "", t.TempDir(), nil)
	m2.SetHostname("varlatch")
	m2.Check(ctx)
	if !open(m2) {
		t.Fatalf("an administrator's name: closed %q", m2.Closed())
	}
}

// The read-back against a control server: a restored node the control
// plane names varlatch-1 (its configured name held elsewhere) keeps
// tailnet access closed; named varlatch, access opens.
func TestTheReadBackOnTheControlPlane(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control := startControl(t)
	node := startVarlatchd(t, control, ctx)
	m := enrolling(t, node, control.BaseURL(), t.TempDir(), nil)
	m.SetHostname("varlatch")
	m.Check(ctx)
	if !open(m) {
		t.Fatalf("named varlatch: closed %q", m.Closed())
	}
	// The control plane renames it, as it suffixes a name held by another
	// node.
	for _, n := range control.AllNodes() {
		if strings.HasPrefix(n.Name, "varlatch.") {
			renamed := n.Clone()
			renamed.Name = "varlatch-1." + testSuffix + "."
			control.UpdateNode(renamed)
		}
	}
	for {
		st, err := node.Status(ctx)
		if err == nil && strings.HasPrefix(st.DNSName, "varlatch-1.") {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("the node never saw its new name: %+v %v", st, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.Check(ctx)
	if open(m) || m.Closed() != NameSuffixed {
		t.Fatalf("named varlatch-1: open %v, %q", open(m), m.Closed())
	}
}
