// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJoinWaitsThroughWhatPasses(t *testing.T) {
	ctx := context.Background()
	limited := errors.New("tsnet.Up: backend: node registration rate limited; will retry after 1s")
	behind := errors.New("tsnet.Up: backend: IPN bus consumer fell behind; closing watch")
	local := errors.New("tsnet.Up: unexpected EOF")
	refused := errors.New("tsnet.Up: backend: invalid authkey")
	ups := func(n *int, errs ...error) func(context.Context) error {
		return func(context.Context) error {
			err := errs[min(*n, len(errs)-1)]
			*n++
			return err
		}
	}
	for _, err := range []error{limited, behind, local} {
		n := 0
		var heard []error
		if got := join(ctx, nil, ups(&n, err, nil), func(e error) { heard = append(heard, e) }); got != nil || n != 2 || len(heard) != 1 || heard[0] != err {
			t.Errorf("%v then up: %v after %d, heard %v", err, got, n, heard)
		}
	}
	n := 0
	var r *RefusedError
	if err := join(ctx, nil, ups(&n, refused, nil), nil); !errors.As(err, &r) || n != 1 || !errors.Is(err, refused) || RateLimited(err) {
		t.Errorf("refused: %v after %d", err, n)
	}
	// A refusal whose words only resemble what passes is a refusal.
	for _, said := range []string{
		"rate limited", "this key is rate limited for good", "node registration rate limited; will retry after never",
		"node registration rate limited; will retry after 1s, no more", "invalid key: node registration rate limited; will retry after 1s",
		"node not approved: IPN bus consumer fell behind; closing watch", "IPN bus consumer fell behind; closing watch for good",
	} {
		n := 0
		err := errors.New("tsnet.Up: backend: " + said)
		if got := join(ctx, nil, ups(&n, err, nil), nil); !errors.As(got, &r) || n != 1 || RateLimited(err) {
			t.Errorf("%q: %v after %d", said, got, n)
		}
	}
	if !RateLimited(limited) || RateLimited(refused) || RateLimited(nil) {
		t.Error("RateLimited")
	}
	// Without end, until the caller's, which names what it waited through.
	n = 0
	cctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	begun := time.Now()
	err := join(cctx, nil, ups(&n, limited), nil)
	if err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), "rate limited") || n != 2 || time.Since(begun) > 10*time.Second {
		t.Errorf("limited without end: %v after %d in %v", err, n, time.Since(begun))
	}
	// A closed node's join ends.
	closed := make(chan struct{})
	close(closed)
	n = 0
	if err := join(ctx, closed, ups(&n, local), nil); !errors.Is(err, errNodeClosed) {
		t.Errorf("closed: %v", err)
	}
}

// A control server's answer that repeats the auth key: no error or log line
// of the node has it.
func TestARefusalNeverRepeatsTheAuthKey(t *testing.T) {
	secret := strings.ToLower(rand.Text())
	bare := "ts" + "key-auth-" + secret
	for _, key := range []string{bare, bare + "?ephemeral=false", secret, secret + "?preauthorized=true"} {
		sent, _, _ := strings.Cut(key, "?")
		control := startControl(t)
		control.MaybeRejectRequest = func(r *http.Request) (int, string, string) {
			if r.URL.Path == "/machine/register" {
				return http.StatusOK, "", `{"Error":"the key ` + key + ` (` + sent + `) is not valid"}`
			}
			return 0, "", ""
		}
		var mu sync.Mutex
		var log strings.Builder
		n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"},
			Logf: func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				fmt.Fprintf(&log, format+"\n", args...)
			}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err = n.Up(ctx)
		cancel()
		_ = n.Close()
		var refused *RefusedError
		if !errors.As(err, &refused) || !strings.Contains(err.Error(), "is not valid") || strings.Contains(err.Error(), secret) {
			t.Errorf("the refusal of %d characters: not a refusal, or with the key in it", len(key))
		}
		mu.Lock()
		said := log.String()
		mu.Unlock()
		if !strings.Contains(said, "is not valid") || strings.Contains(said, secret) {
			t.Error("the node's log does not say the refusal, or has the key in it")
		}
	}
	if got := withoutKey("a wrapped "+bare+" and "+bare+"--TLabc-def", bare+"--TLabc-def"); strings.Contains(got, secret) {
		t.Error("a wrapped key is not taken out")
	}
	if got := withoutKey("nothing of a key", bare); got != "nothing of a key" {
		t.Error(got)
	}
}

// tsnet's own words for a control server's answers, which passing goes by:
// a rate limit is waited through, and a refusal is not.
func TestANodeJoinsOnceItsControlServerLetsIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, c := range []struct {
		status     int
		retryAfter string
	}{{http.StatusTooManyRequests, "1"}, {http.StatusServiceUnavailable, "1"}} {
		control := startControl(t)
		var left atomic.Int32
		left.Store(2)
		control.MaybeRejectRequest = func(r *http.Request) (int, string, string) {
			if r.URL.Path == "/machine/register" && left.Add(-1) >= 0 {
				return c.status, c.retryAfter, "slow down"
			}
			return 0, "", ""
		}
		n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), Tags: []string{"tag:varlatch"}})
		if err != nil {
			t.Fatal(err)
		}
		var heard atomic.Int32
		err = n.Join(ctx, func(err error) {
			if !RateLimited(err) {
				t.Errorf("heard %v", err)
			}
			heard.Add(1)
		})
		_ = n.Close()
		if err != nil || heard.Load() == 0 {
			t.Errorf("%d twice, then yes: %v, heard %d", c.status, err, heard.Load())
		}
	}

	control := startControl(t)
	control.RequireAuthKey = "another"
	n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: "hermetic", Tags: []string{"tag:varlatch"}})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	var refused *RefusedError
	if err := n.Up(ctx); !errors.As(err, &refused) || !strings.Contains(err.Error(), "invalid authkey") {
		t.Errorf("an auth key the control server does not take: %v", err)
	}
}

// A node somebody must log in is told from one whose control server does not
// answer.
func TestANodeThatNeedsLogin(t *testing.T) {
	look := func(auth bool) Status {
		control := startControl(t)
		control.RequireAuth = auth
		if !auth {
			control.MaybeRejectRequest = func(*http.Request) (int, string, string) { return http.StatusInternalServerError, "", "down" }
		}
		n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), Tags: []string{"tag:varlatch"}})
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		st, _, err := n.AwaitStatus(context.Background(), 4*time.Second, func(st Status) bool { return st.AuthNeeded })
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := look(true); !st.AuthNeeded {
		t.Errorf("a node that needs a login: %+v", st)
	}
	if st := look(false); st.AuthNeeded {
		t.Errorf("a control server that does not answer: %+v", st)
	}
}

// Why a node has not joined: what it waits for ends when a check finds it on
// its tailnet; a refusal does not, whatever a check finds and whatever else
// closes access.
func TestWhyANodeHasNotJoined(t *testing.T) {
	on := &statusNode{st: Status{BackendState: "Running", SelfID: "nA", DNSName: "varlatch." + testSuffix, Suffix: testSuffix}}
	for _, c := range []struct {
		what   string
		pin    *Pin
		reason string
		before string // Closed before a check finds the node on its tailnet
		after  string
	}{
		{"waiting", &Pin{Suffix: testSuffix}, WaitingForControl, WaitingForControl, ""},
		{"a login needed, enrolling", &Pin{Enrolling: true}, LoginNeeded, LoginNeeded, ""},
		{"waiting, the pin closed", &Pin{Suffix: testSuffix, Closed: &Closure{Reason: PinSuffix}}, WaitingForControl, PinSuffix, PinSuffix},
		{"refused", &Pin{Suffix: testSuffix}, JoinRefused, JoinRefused, JoinRefused},
		{"refused, the pin closed", &Pin{Suffix: testSuffix, Closed: &Closure{Reason: PinSuffix}}, JoinRefused, JoinRefused, JoinRefused},
		{"refused, no pin", nil, JoinRefused, JoinRefused, JoinRefused},
	} {
		dir := t.TempDir()
		if c.pin != nil {
			if err := SavePin(filepath.Join(dir, PinFile), c.pin); err != nil {
				t.Fatal(err)
			}
		}
		m, err := NewManager(on, "", dir, 8687, slog.New(slog.DiscardHandler), nil)
		if err != nil {
			t.Fatal(err)
		}
		// Tags that differ are said too, but never in place of the restart.
		m.RequireTags([]string{"tag:varlatch"})
		m.SetJoin(c.reason, "why")
		if got := m.Closed(); got != c.before {
			t.Errorf("%s: %q", c.what, got)
		}
		m.Check(context.Background())
		m.SetJoin("", "")
		m.RequireTags(nil)
		detail, _ := m.Explain()
		if c.reason == JoinRefused != (detail == "why") {
			t.Errorf("%s: after a check, the detail %q", c.what, detail)
		}
		m.Check(context.Background())
		if got := m.Closed(); got != c.after {
			t.Errorf("%s: after a check, %q", c.what, got)
		}
	}
}
