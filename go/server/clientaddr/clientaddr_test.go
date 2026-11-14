// SPDX-License-Identifier: AGPL-3.0-or-later

package clientaddr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Ported from services/varlatchd/test/client-address.test.ts.

const (
	nginx   = "10.0.0.2"
	ingress = "10.0.0.3"
)

func trusted(addresses ...string) func(string) bool {
	return func(a string) bool { return slices.Contains(addresses, a) }
}

func TestOf(t *testing.T) {
	cases := []struct {
		peer, xff string
		trusts    func(string) bool
		want      string
	}{
		// The socket peer, ignoring X-Forwarded-For, when the peer is not trusted.
		{"198.51.100.9", "192.0.2.1", trusted(nginx), "198.51.100.9"},
		{"::ffff:198.51.100.9", "192.0.2.1, 10.0.0.2", trusted(nginx), "198.51.100.9"},
		// From the right through trusted proxies.
		{nginx, "192.0.2.10", trusted(nginx), "192.0.2.10"},
		{nginx, "192.0.2.10, " + ingress, trusted(nginx, ingress), "192.0.2.10"},
		// An untrusted ingress is the client.
		{nginx, "192.0.2.10, " + ingress, trusted(nginx), ingress},
		// The last good address on a malformed entry, or when every hop is trusted.
		{nginx, "not-an-ip", trusted(nginx), nginx},
		{nginx, ingress, trusted(nginx, ingress), ingress},
		{nginx, "", trusted(nginx), nginx},
		// Go's RemoteAddr carries the port.
		{"127.0.0.1:52811", "", nil, "127.0.0.1"},
		{"[::1]:52811", "1.2.3.4", nil, "::1"},
	}
	for _, c := range cases {
		if got := Of(c.peer, c.xff, c.trusts); got != c.want {
			t.Errorf("Of(%q, %q) = %q, want %q", c.peer, c.xff, got, c.want)
		}
	}
	for _, forged := range []string{"1.1.1.1", "1.1.1.1, 2.2.2.2", "garbage", ingress, "::1"} {
		if got := Of(nginx, forged+", 192.0.2.10, "+ingress, trusted(nginx, ingress)); got != "192.0.2.10" {
			t.Errorf("forged %q reached: %q", forged, got)
		}
		if got := Of(nginx, forged+", 198.51.100.7", trusted(nginx, ingress)); got != "198.51.100.7" {
			t.Errorf("forged %q directly to nginx reached: %q", forged, got)
		}
	}
	chain := strings.Repeat(ingress+", ", 29) + ingress
	if got := Of(nginx, "192.0.2.10, "+chain, trusted(nginx, ingress)); got != ingress {
		t.Errorf("more than %d hops read: %q", MaxHops, got)
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"[2001:DB8::1]:443": "2001:db8::1",
		"192.0.2.1:8080":    "192.0.2.1",
		"fe80::1%eth0":      "fe80::1",
		"::ffff:192.0.2.1":  "192.0.2.1",
		"unknown":           "",
		"01.2.3.4":          "",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies("varlatch-web, caddy,10.0.0.2, 172.18.0.0/16, 2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	var shown []string
	for _, e := range got {
		if e.Name != "" {
			shown = append(shown, "name "+e.Name)
		} else {
			shown = append(shown, e.Prefix.String())
		}
	}
	want := []string{"name varlatch-web", "name caddy", "10.0.0.2/32", "172.18.0.0/16", "2001:db8::/32"}
	if !slices.Equal(shown, want) {
		t.Errorf("got %q, want %q", shown, want)
	}
	for _, bad := range []string{"10.0.0.0/33", "under_score", "http://proxy", "*"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

func (l *logs) matching(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, s) {
			n++
		}
	}
	return n
}

var errNotFound = errors.New("lookup: no such host")

func TestTrustedProxiesResolveAndFollow(t *testing.T) {
	web := []string{"172.18.0.4"}
	var mu sync.Mutex
	l := &logs{}
	tp, err := NewTrustedProxies("varlatch-web, coolify-proxy, 10.9.0.0/24", func(_ context.Context, name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if name == "varlatch-web" {
			return web, nil
		}
		return nil, errNotFound
	}, slog.New(slog.NewTextHandler(l, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tp.Start(ctx, time.Minute)
	for addr, want := range map[string]bool{"172.18.0.4": true, "::ffff:172.18.0.4": true, "10.9.0.77": true, "172.18.0.1": false} {
		if tp.Trusts(addr) != want {
			t.Errorf("Trusts(%s) = %v", addr, !want)
		}
	}
	if l.matching("coolify-proxy does not resolve") != 1 {
		t.Errorf("no warning for coolify-proxy: %q", l.lines)
	}
	mu.Lock()
	web = []string{"172.18.0.9"}
	mu.Unlock()
	tp.Refresh(ctx)
	if !tp.Trusts("172.18.0.9") || tp.Trusts("172.18.0.4") {
		t.Error("the recreated container's address was not followed")
	}
}

func TestTrustedProxiesDropOnFailure(t *testing.T) {
	var answer []string = []string{"172.18.0.4"}
	failing := false
	l := &logs{}
	tp, _ := NewTrustedProxies("varlatch-web, 10.9.0.0/24", func(context.Context, string) ([]string, error) {
		if failing {
			return nil, errNotFound
		}
		return answer, nil
	}, slog.New(slog.NewTextHandler(l, nil)), nil)
	ctx := context.Background()
	tp.Start(ctx, time.Minute)
	if got := Of("172.18.0.4", "198.51.100.99", tp.Trusts); got != "198.51.100.99" {
		t.Fatalf("got %s", got)
	}
	failing = true
	tp.Refresh(ctx)
	if tp.Trusts("172.18.0.4") || Of("172.18.0.4", "198.51.100.99", tp.Trusts) != "172.18.0.4" {
		t.Error("a name that no longer resolves is still trusted")
	}
	if l.matching("varlatch-web no longer resolves") != 1 || !tp.Trusts("10.9.0.5") {
		t.Errorf("logs %q", l.lines)
	}
	tp.Refresh(ctx)
	if n := l.matching("resolve"); n != 1 {
		t.Errorf("a continuing failure was logged %d times", n)
	}
	failing, answer = false, []string{"172.18.0.11"}
	tp.Refresh(ctx)
	if Of("172.18.0.11", "198.51.100.99", tp.Trusts) != "198.51.100.99" || tp.Trusts("172.18.0.4") {
		t.Error("the new address is not trusted, or the old one still is")
	}
	if l.matching("varlatch-web is 172.18.0.11") != 1 {
		t.Errorf("logs %q", l.lines)
	}
}

func TestTrustedProxiesStaleResolution(t *testing.T) {
	clock := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	stall := make(chan struct{})
	stalled := false
	tp, _ := NewTrustedProxies("varlatch-web", func(ctx context.Context, _ string) ([]string, error) {
		mu.Lock()
		s := stalled
		mu.Unlock()
		if s {
			select {
			case <-stall:
			case <-ctx.Done():
			}
			return nil, ctx.Err()
		}
		return []string{"172.18.0.4"}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tp.Start(ctx, 10*time.Second)
	if !tp.Trusts("172.18.0.4") {
		t.Fatal("not trusted after start")
	}
	mu.Lock()
	stalled = true
	mu.Unlock()
	go tp.Refresh(ctx)
	mu.Lock()
	clock = clock.Add(29 * time.Second)
	mu.Unlock()
	if !tp.Trusts("172.18.0.4") {
		t.Error("a resolution 29 s old is not trusted")
	}
	mu.Lock()
	clock = clock.Add(2 * time.Second)
	mu.Unlock()
	if tp.Trusts("172.18.0.4") {
		t.Error("a resolution older than three periods is still trusted")
	}
	close(stall)
}
