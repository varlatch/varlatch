// SPDX-License-Identifier: AGPL-3.0-or-later

package tailnet

import (
	"context"
	"errors"
	"net/http"
	"strings"
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
	if err := join(ctx, nil, ups(&n, refused, nil), nil); !errors.As(err, &r) || n != 1 || !errors.Is(err, refused) {
		t.Errorf("refused: %v after %d", err, n)
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
