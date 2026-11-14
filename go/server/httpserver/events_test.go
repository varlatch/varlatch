// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/realtime"
)

// eventsServer is varlatchd's handler with live updates, served by a real
// http.Server (a stream is a long response) with a short ReadTimeout, and
// a browser enrolled in it.
func eventsServer(t *testing.T, opts realtime.Options) (*httptest.Server, *testBrowser, *testAuth, *realtime.Hub) {
	t.Helper()
	var hub *realtime.Hub
	s, ta := browserServer(t, browserOrigin)
	opts.Store = ta.store
	if opts.Poll == 0 {
		opts.Poll = 20 * time.Millisecond
	}
	hub = realtime.New(opts)
	s.opts.Realtime = hub
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = hub.Run(ctx) }()
	srv := httptest.NewUnstartedServer(s)
	// Like varlatchd's (the http-timeouts change): a stream must outlive it.
	srv.Config.ReadTimeout = 200 * time.Millisecond
	srv.Config.ConnContext = ConnContext
	srv.Config.RegisterOnShutdown(hub.Close)
	srv.Start()
	t.Cleanup(func() {
		hub.Close()
		srv.Close()
		cancel()
		<-done
	})
	b := newBrowser(t, s, browserOrigin)
	enrollOver(t, b, ta)
	return srv, b, ta, hub
}

type sse struct {
	resp   *http.Response
	events chan [2]string
}

// open starts a stream with the browser's cookies and reads its events.
func open(t *testing.T, srv *httptest.Server, b *testBrowser) *sse {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/auth/events", nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	s := &sse{resp: resp, events: make(chan [2]string, 64)}
	if resp.StatusCode != 200 {
		return s
	}
	go func() {
		defer close(s.events)
		r := bufio.NewReader(resp.Body)
		var name string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				s.events <- [2]string{name, strings.TrimPrefix(line, "data: ")}
			case strings.HasPrefix(line, "id:"):
				s.events <- [2]string{"id", line}
			}
		}
	}()
	return s
}

func (s *sse) next(t *testing.T, within time.Duration) [2]string {
	t.Helper()
	select {
	case e, ok := <-s.events:
		if !ok {
			t.Fatal("the stream ended")
		}
		return e
	case <-time.After(within):
		t.Fatal("no event")
	}
	return [2]string{}
}

// until skips events until one satisfies ok (a stream may first carry the
// signals of what happened just before it opened).
func (s *sse) until(t *testing.T, within time.Duration, ok func(e [2]string) bool) [2]string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		e := s.next(t, time.Until(deadline))
		if ok(e) {
			return e
		}
	}
}

func (s *sse) ends(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case _, ok := <-s.events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the stream did not end")
		}
	}
}

func TestEventsNeedASession(t *testing.T) {
	srv, b, _, _ := eventsServer(t, realtime.Options{})
	anonymous := newBrowser(t, b.s, browserOrigin)
	s := open(t, srv, anonymous)
	body := make([]byte, 512)
	n, _ := s.resp.Body.Read(body)
	if s.resp.StatusCode != 401 || !strings.Contains(string(body[:n]), `"code":"AUTHENTICATION_REQUIRED"`) {
		t.Fatalf("%d %s", s.resp.StatusCode, body[:n])
	}
	if w := b.send("POST", "/auth/events", nil, map[string]string{"Origin": browserOrigin}); w.Code != 405 && w.Code != 403 && w.Code != 404 {
		t.Fatalf("POST /auth/events: %d", w.Code)
	}
}

// The stream outlives the server's ReadTimeout, and carries the session's
// identity's signals, with no event ids (nothing is replayed).
func TestEventsStreamOutlivesReadTimeout(t *testing.T) {
	srv, b, _, _ := eventsServer(t, realtime.Options{})
	s := open(t, srv, b)
	if s.resp.StatusCode != 200 || s.resp.Header.Get("Content-Type") != "text/event-stream" || s.resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", s.resp.StatusCode, s.resp.Header)
	}
	if e := s.next(t, 2*time.Second); e[0] != "ready" || !strings.Contains(e[1], `"identityId":"idn_`) {
		t.Fatalf("first event %v", e)
	}
	time.Sleep(4 * srv.Config.ReadTimeout)
	// Minting a bearer records credential.issued, actor this identity.
	if w := b.post("/auth/varlatch-token", nil); w.Code != 200 {
		t.Fatalf("mint %d", w.Code)
	}
	e := s.until(t, 3*time.Second, func(e [2]string) bool { return strings.Contains(e[1], `"credential"`) })
	if e[0] != "identity" || !strings.Contains(e[1], `"domains":["credential"]`) {
		t.Fatalf("got %v", e)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(e[1]), &data); err != nil || len(data) != 3 || data["lastEventId"] == nil || data["occurredAt"] == nil {
		t.Fatalf("data %s", e[1])
	}
}

// Signing out closes the session's stream, with its reason.
func TestEventsSignOutClosesStream(t *testing.T) {
	srv, b, _, hub := eventsServer(t, realtime.Options{})
	s := open(t, srv, b)
	s.next(t, 2*time.Second)
	if w := b.post("/auth/sign-out", nil); w.Code != 204 {
		t.Fatalf("sign-out %d", w.Code)
	}
	if e := s.until(t, 3*time.Second, func(e [2]string) bool { return e[0] == "close" }); e[1] != `{"reason":"session-ended"}` {
		t.Fatalf("close %s", e[1])
	}
	s.ends(t, 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for hub.Streams() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := hub.Streams(); n != 0 {
		t.Fatalf("%d streams left", n)
	}
}

// Stopping the server ends its streams: Shutdown does not wait for them.
func TestEventsEndOnShutdown(t *testing.T) {
	srv, b, _, _ := eventsServer(t, realtime.Options{})
	s := open(t, srv, b)
	s.next(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Config.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown waited for the stream: %v", err)
	}
	if e := s.until(t, time.Second, func(e [2]string) bool { return e[0] == "close" }); e[1] != `{"reason":"shutdown"}` {
		t.Fatalf("got %v", e)
	}
}

func TestMetaListsRealtimeSSE(t *testing.T) {
	meta := func(s http.Handler) []string {
		var m api.Meta
		w := do(s, "GET", "/v1/meta", "", nil)
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m.Capabilities
	}
	without, _ := browserServer(t, browserOrigin)
	if caps := meta(without); !slices.Contains(caps, "auth.session") || slices.Contains(caps, "realtime.sse") {
		t.Fatalf("without a hub: %v", caps)
	}
	_, b, _, _ := eventsServer(t, realtime.Options{})
	if caps := meta(b.s); !slices.Contains(caps, "realtime.sse") || caps[len(caps)-1] != "realtime.sse" {
		t.Fatalf("with a hub: %v", caps)
	}
}
