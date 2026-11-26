// SPDX-License-Identifier: Apache-2.0

package tailcontrol_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
	"github.com/varlatch/varlatch/go/lib/tailcontrol/tailcontroltest"
)

// shortRelease makes RenameReleased's waits and budget a test's.
func shortRelease(t *testing.T, budget time.Duration) {
	t.Helper()
	waits, b, rb := tailcontrol.ReleaseWaits, tailcontrol.ReleaseBudget, tailcontrol.ReadBackRetry
	t.Cleanup(func() { tailcontrol.ReleaseWaits, tailcontrol.ReleaseBudget, tailcontrol.ReadBackRetry = waits, b, rb })
	tailcontrol.ReleaseWaits = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	tailcontrol.ReleaseBudget = budget
	tailcontrol.ReadBackRetry = 5 * time.Millisecond
}

func TestSuffixed(t *testing.T) {
	for _, c := range []struct {
		got  string
		want bool
	}{
		{"vault-1", true}, {"vault-12", true}, {"vault", false}, {"vault-", false}, {"vault-x", false},
		{"vault-1a", false}, {"vaults-1", false}, {"other-1", false}, {"vault-vl-abc-o", false},
	} {
		if got := tailcontrol.Suffixed(c.got, "vault"); got != c.want {
			t.Errorf("Suffixed(%q, vault) = %v", c.got, got)
		}
	}
}

// A name the serving node let go of a moment ago is not given out at once:
// Tailscale applies a rename to it with a dedup suffix. The rename is made
// again until it reads back exactly.
func TestRenameReleasedWaitsForTheName(t *testing.T) {
	shortRelease(t, 5*time.Second)
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	f.ReleaseDelay = 150 * time.Millisecond
	ts := tailscaleOf(t, f, f.ClientSecret)
	if _, err := tailcontrol.RenameReleased(ctx, ts, "1", "vault-vl-abc-o", nil); err != nil {
		t.Fatal(err)
	}
	// Without the wait, the read-back fails as in production on 2026-11-26.
	if _, err := tailcontrol.RenameAndReadBack(ctx, ts, "2", "vault"); err == nil {
		t.Fatal("the name was free at once")
	}
	waited := 0
	d, err := tailcontrol.RenameReleased(ctx, ts, "2", "vault", func() { waited++ })
	if err != nil || d.Name != "vault" || waited != 1 || f.Deduped < 2 {
		t.Fatalf("%+v, %v, waited %d, deduped %d", d, err, waited, f.Deduped)
	}
}

// A name never released: the last read-back stands once the budget is
// spent, with the dedup suffix it reports.
func TestRenameReleasedGivesUpAfterTheBudget(t *testing.T) {
	shortRelease(t, 150*time.Millisecond)
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	f.ReleaseDelay = time.Hour
	ts := tailscaleOf(t, f, f.ClientSecret)
	if _, err := tailcontrol.RenameReleased(ctx, ts, "1", "vault-vl-abc-o", nil); err != nil {
		t.Fatal(err)
	}
	start, waited := time.Now(), 0
	_, err := tailcontrol.RenameReleased(ctx, ts, "2", "vault", func() { waited++ })
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &rb) || rb.Got != "vault-1" || waited != 1 {
		t.Fatalf("%v, waited %d", err, waited)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the budget of 150ms took %s", took)
	}
	// The context's deadline bounds it too: it ends with the last
	// read-back, or with the deadline when that came during a call.
	tailcontrol.ReleaseBudget = time.Hour
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err = tailcontrol.RenameReleased(short, ts, "2", "vault", nil)
	if !errors.As(err, &rb) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("under a deadline: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("a deadline of 200ms took %s", took)
	}
}

// What waiting does not change stays final at once: a name rewritten
// otherwise than with a dedup suffix, and a name another device lists.
func TestRenameReleasedKeepsOtherFailuresFinal(t *testing.T) {
	shortRelease(t, 5*time.Second)
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	ts := tailscaleOf(t, f, f.ClientSecret)
	waited := 0
	count := func() { waited++ }
	if _, err := tailcontrol.RenameReleased(ctx, ts, "2", "vault", count); !errors.Is(err, tailcontrol.ErrNameTaken) || waited != 0 {
		t.Errorf("a name another device lists: %v, waited %d", err, waited)
	}
	f.RewriteRename = func(s string) string { return s + "-x" }
	var rb *tailcontrol.ReadBackError
	if _, err := tailcontrol.RenameReleased(ctx, ts, "2", "build", count); !errors.As(err, &rb) || rb.Got != "build-x" || waited != 0 {
		t.Errorf("a name rewritten: %v, waited %d", err, waited)
	}
	// A dedup suffix while another device lists the name: Tailscale's
	// rename to a taken name, not a reservation.
	f.RewriteRename = func(s string) string {
		if s == "vault" {
			return "vault-2"
		}
		return s
	}
	if _, err := tailcontrol.RenameReleased(ctx, ts, "2", "vault", count); err == nil || waited != 0 {
		t.Errorf("a suffix while another device lists the name: %v, waited %d", err, waited)
	}
}

// Headscale releases a name at once: nothing is waited for, a suffix
// included.
func TestRenameReleasedOnHeadscaleIsRenameAndReadBack(t *testing.T) {
	shortRelease(t, 5*time.Second)
	f := tailcontroltest.NewHeadscale(50*time.Minute,
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	hs := headscaleOf(t, f, f.Key)
	if err := hs.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := tailcontrol.RenameReleased(ctx, hs, "1", "vault-vl-abc-o", nil); err != nil {
		t.Fatal(err)
	}
	f.RewriteRename = func(s string) string { return s + "-1" }
	waited := 0
	_, err := tailcontrol.RenameReleased(ctx, hs, "2", "vault", func() { waited++ })
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &rb) || rb.Got != "vault-1" || waited != 0 || f.Renames != 2 {
		t.Errorf("%v, waited %d, renames %d", err, waited, f.Renames)
	}
	f.RewriteRename = nil
	if _, err := tailcontrol.RenameReleased(ctx, hs, "2", "vault", nil); err != nil {
		t.Errorf("a free name: %v", err)
	}
}

// holdRenames holds every rename request, once armed, until its context
// ends: a control plane that does not answer a retry.
type holdRenames struct {
	next  http.RoundTripper
	armed atomic.Bool
}

func (h *holdRenames) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.armed.Load() && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/name") {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	return h.next.RoundTrip(r)
}

// The release phase is one context: a retry the control plane does not
// answer ends with the budget, not the caller's deadline, and the last
// name failure stands, not the cut-short call's.
func TestTheReleaseBudgetBoundsItsCalls(t *testing.T) {
	shortRelease(t, 45*time.Millisecond)
	f := tailcontroltest.NewTailscale(
		tailcontroltest.Node{ID: "1", Name: "vault", Online: true},
		tailcontroltest.Node{ID: "2", Name: "vault-vl-abc-n", Online: true},
	)
	defer f.Close()
	f.ReleaseDelay = time.Hour
	client := f.Client()
	hold := &holdRenames{next: client.Transport}
	client.Transport = hold
	ts, err := tailcontrol.NewTailscale(tailcontrol.TailscaleConfig{BaseURL: f.URL, ClientID: f.ClientID, ClientSecret: f.ClientSecret, HTTP: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tailcontrol.RenameAndReadBack(ctx, ts, "1", "vault-vl-abc-o"); err != nil {
		t.Fatal(err)
	}
	// The first rename answers (vault-1); every retry is held.
	first := true
	waiting := func() {
		if first {
			hold.armed.Store(true)
			first = false
		}
	}
	caller, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = tailcontrol.RenameReleased(caller, ts, "2", "vault", waiting)
	took := time.Since(start)
	var rb *tailcontrol.ReadBackError
	if !errors.As(err, &rb) || rb.Got != "vault-1" || !strings.Contains(err.Error(), "did not release") {
		t.Fatalf("the last name failure, not the held call's: %v", err)
	}
	if took >= 250*time.Millisecond || caller.Err() != nil {
		t.Errorf("the budget of 45ms took %s (the caller's deadline is 300ms)", took)
	}
}

// staleRetry is a Tailscale control plane that refuses the first rename as
// taken and accepts the next, whose read-back's first listing still shows
// the device's old name.
type staleRetry struct {
	renames atomic.Int32
}

func (c *staleRetry) Kind() string                { return "tailscale" }
func (c *staleRetry) Close(context.Context) error { return nil }
func (c *staleRetry) Devices(context.Context) ([]tailcontrol.Device, error) {
	return []tailcontrol.Device{{ID: "1", Name: "vault-vl-abc-o"}, {ID: "2", Name: "vault-vl-abc-n"}}, nil
}

func (c *staleRetry) Rename(_ context.Context, id, name string) error {
	if c.renames.Add(1) == 1 {
		return &tailcontrol.OpError{Plane: "tailscale", Op: "rename", Device: id, Err: fmt.Errorf("%w (%q): 409 machine name already in use", tailcontrol.ErrNameTaken, name)}
	}
	return nil
}

// A retry the control plane accepts, whose read-back the phase's end cuts
// short after a first, stale listing: the confirmed refusal stands, said to
// be unreleased in time, not the stale read-back.
func TestAnInterruptedReadBackKeepsTheConfirmedFailure(t *testing.T) {
	shortRelease(t, 100*time.Millisecond)
	tailcontrol.ReadBackRetry = time.Second
	cp := &staleRetry{}
	start := time.Now()
	_, err := tailcontrol.RenameReleased(ctx, cp, "2", "vault", nil)
	var rb *tailcontrol.ReadBackError
	if !errors.Is(err, tailcontrol.ErrNameTaken) || errors.As(err, &rb) || !strings.Contains(err.Error(), "did not release") {
		t.Fatalf("not the confirmed refusal: %v", err)
	}
	if n := cp.renames.Load(); n != 2 {
		t.Errorf("renames %d, want 2", n)
	}
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("the budget of 100ms took %s", took)
	}
}
