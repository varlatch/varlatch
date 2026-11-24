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
	"slices"
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
	if err := join(ctx, nil, ups(&n, refused, nil), nil); !errors.As(err, &r) || n != 1 || err.Error() != refusedText || RateLimited(err) {
		t.Errorf("refused: %v after %d", err, n)
	}
	// tsnet's own words for a tailnet that requires logs are told apart.
	n = 0
	if err := join(ctx, nil, ups(&n, errors.New(backendError+logsRequired)), nil); !errors.As(err, &r) || !strings.Contains(err.Error(), "requires its nodes to log") {
		t.Errorf("logs required: %v", err)
	}
	// Refused as its time ends: the fixed text all the same.
	ectx, end := context.WithCancel(ctx)
	if err := join(ectx, nil, func(context.Context) error { end(); return refused }, nil); !errors.As(err, &r) || err.Error() != refusedText {
		t.Errorf("refused as its time ends: %v", err)
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

// spellings are a key as an answer may write it.
func spellings(key string) map[string]string {
	escaped := func(s, format string, every int) string {
		var b strings.Builder
		for i := range len(s) {
			if i%every == 0 {
				fmt.Fprintf(&b, format, s[i])
			} else {
				b.WriteByte(s[i])
			}
		}
		return b.String()
	}
	fully := escaped(key, "%%%02X", 1)
	mixed := ""
	for i := range len(key) {
		mixed += fmt.Sprintf([]string{"%%%02x", "%%%02X"}[i%2], key[i])
	}
	again := func(s string) string { return strings.ReplaceAll(s, "%", "%25") }
	return map[string]string{
		"literal": key, "fully escaped": fully, "partially escaped": escaped(key, "%%%02X", 3), "mixed-case hex": mixed,
		"double-escaped": again(fully), "partially, double-escaped": again(escaped(key, "%%%02x", 4)), "triple-escaped": again(again(fully)),
		"escaped deeper than is looked through":      again(again(again(fully))),
		"beside a percent sign that escapes nothing": "100% %zz%" + escaped(key, "%%%02x", 2) + "%4",
	}
}

func TestAKeyIsFoundHoweverItIsEscaped(t *testing.T) {
	secret := strings.ToLower(rand.Text())
	key := "ts" + "key-auth-kABC11CNTRL-" + secret
	for what, as := range map[string]string{"a key": key, "its secret part": secret, "another key": "hs" + "key-auth-" + strings.ToLower(rand.Text())} {
		for how, said := range spellings(as) {
			if got := withoutKey("the key "+said+" is not valid\nand more", key); got != keyTaken {
				t.Errorf("%s, %s: shown", what, how)
			}
			if err := keyless(errors.New("x: "+said), key); err.Error() != keyTaken {
				t.Errorf("%s, %s: an error with it", what, how)
			}
		}
	}
	// Without parameters, wrapped, and one with no shape (an old Headscale's).
	for full, said := range map[string]string{key + "?ephemeral=false": key, key + "--TLabcdefgh-ijklmnop": key, secret: secret, secret + "?a=b": secret} {
		for how, as := range spellings(said) {
			if withoutKey(as, full) != keyTaken {
				t.Errorf("a part of it, %s: shown", how)
			}
		}
	}
	for _, text := range []string{"", "nothing of a key", "100% of %41 %zz %", "three layers, %252541, of nothing", "a key- and tskey", "register request: http 403: no"} {
		if got := withoutKey(text, key); got != text {
			t.Errorf("%q: %q", text, got)
		}
		if got := withoutKey(text, ""); got != text {
			t.Errorf("%q without a key: %q", text, got)
		}
	}
	if err := errors.New("plain"); keyless(err, key) != err || keyless(nil, key) != nil {
		t.Error("an error without the key")
	}
}

// A control server's answer that repeats the auth key: no error or log line
// of the node, or of a probe, has it.
func TestARefusalNeverRepeatsTheAuthKey(t *testing.T) {
	secret := strings.ToLower(rand.Text())
	key := "ts" + "key-auth-" + secret
	for how, said := range spellings(key) {
		control := startControl(t)
		control.MaybeRejectRequest = func(r *http.Request) (int, string, string) {
			if r.URL.Path == "/machine/register" {
				return http.StatusOK, "", `{"Error":"the key ` + said + ` is not valid"}`
			}
			return 0, "", ""
		}
		var mu sync.Mutex
		var log []string
		n, err := StartNode(NodeConfig{Dir: t.TempDir(), Hostname: "varlatch", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"},
			Logf: func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				log = append(log, fmt.Sprintf(format, args...))
			}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err = n.Up(ctx)
		_ = n.Close()
		var refused *RefusedError
		if !errors.As(err, &refused) || err.Error() != refusedText {
			t.Errorf("%s: the refusal is not the fixed text", how)
		}
		if how == "literal" || how == "partially escaped" {
			_, err = ProbeName(ctx, ProbeConfig{Dir: t.TempDir(), Hostname: "vault", ControlURL: control.BaseURL(), AuthKey: key, Tags: []string{"tag:varlatch"}})
			if !errors.As(err, &refused) || !strings.HasSuffix(err.Error(), refusedText) {
				t.Errorf("%s: the probe's refusal is not the fixed text", how)
			}
		}
		cancel()
		mu.Lock()
		if !slices.Contains(log, keyTaken) {
			t.Errorf("%s: the node's log never had the refusal: this shows nothing", how)
		}
		for _, line := range log {
			if strings.Contains(line, "is not valid") || hasKey(line, key) {
				t.Errorf("%s: a line of the node's log has the refusal's words", how)
			}
		}
		mu.Unlock()
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
	if err := n.Up(ctx); !errors.As(err, &refused) || err.Error() != refusedText {
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
	if st := look(true); !st.AuthNeeded || st.HaveNodeKey {
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
		if m.NeverJoined() {
			t.Errorf("%s: never joined, before it is known", c.what)
		}
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

// Only a node no control server ever registered, with no tailnet ever pinned,
// never joined.
func TestANodeThatNeverJoined(t *testing.T) {
	for _, c := range []struct {
		what string
		pin  *Pin
		st   Status
		err  error
		want bool
	}{
		{"a first enrolment refused", &Pin{Enrolling: true}, Status{BackendState: "NeedsLogin"}, nil, true},
		{"registered, not pinned yet", &Pin{Enrolling: true}, Status{BackendState: "Starting", HaveNodeKey: true}, nil, false},
		{"a StableID, not pinned yet", &Pin{Enrolling: true}, Status{BackendState: "NeedsLogin", SelfID: "nA"}, nil, false},
		{"pinned", &Pin{Suffix: testSuffix}, Status{BackendState: "NeedsLogin"}, nil, false},
		{"no pin", nil, Status{BackendState: "NeedsLogin"}, nil, false},
		{"not known", &Pin{Enrolling: true}, Status{}, errors.New("no status"), false},
	} {
		dir := t.TempDir()
		if c.pin != nil {
			if err := SavePin(filepath.Join(dir, PinFile), c.pin); err != nil {
				t.Fatal(err)
			}
		}
		m, err := NewManager(&statusNode{st: c.st, err: c.err}, "", dir, 8687, slog.New(slog.DiscardHandler), nil)
		if err != nil {
			t.Fatal(err)
		}
		m.Check(context.Background())
		if got := m.NeverJoined(); got != c.want {
			t.Errorf("%s: %v", c.what, got)
		}
	}
}
