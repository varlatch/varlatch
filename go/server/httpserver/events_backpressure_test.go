// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/realtime"
)

// gatedWriter is a client under controlled backpressure: it takes `allow`
// writes, then each write blocks until released or until its write
// deadline passes, as a connection's would. A write that missed its
// deadline breaks it, as it breaks a real response.
type gatedWriter struct {
	mu       sync.Mutex
	header   http.Header
	out      bytes.Buffer
	allow    int
	deadline time.Time
	broken   bool
	blocked  chan struct{}
}

func newGatedWriter(allow int) *gatedWriter {
	return &gatedWriter{header: http.Header{}, allow: allow, blocked: make(chan struct{}, 1)}
}

func (g *gatedWriter) Header() http.Header { return g.header }
func (g *gatedWriter) WriteHeader(int)     {}
func (g *gatedWriter) Flush()              {}

func (g *gatedWriter) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		if g.broken {
			return 0, os.ErrDeadlineExceeded
		}
		if g.allow != 0 {
			if g.allow > 0 {
				g.allow--
			}
			g.out.Write(p)
			return len(p), nil
		}
		if !g.deadline.IsZero() && !time.Now().Before(g.deadline) {
			g.broken = true
			continue
		}
		select {
		case g.blocked <- struct{}{}:
		default:
		}
		g.mu.Unlock()
		time.Sleep(time.Millisecond)
		g.mu.Lock()
	}
}

func (g *gatedWriter) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deadline = t
	return nil
}

func (g *gatedWriter) SetReadDeadline(time.Time) error { return nil }

// release lets every write through from now on.
func (g *gatedWriter) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allow = -1
}

// events are the complete events written so far, as "name data".
func (g *gatedWriter) events() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, block := range strings.Split(g.out.String(), "\n\n") {
		var name, data string
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				name = v
			} else if v, ok := strings.CutPrefix(line, "data: "); ok {
				data = v
			}
		}
		if name != "" {
			out = append(out, name+" "+data)
		}
	}
	return out
}

// streamWorld is an installation with one person (idn_parity) in two
// Organizations, browser sessions of theirs, and a running hub.
type streamWorld struct {
	t     *testing.T
	s     *Server
	store *storage.DB
	hub   *realtime.Hub
	n     int
}

func newStreamWorld(t *testing.T, opts realtime.Options) *streamWorld {
	t.Helper()
	s, ta := browserServer(t, browserOrigin)
	opts.Store = ta.store
	opts.Poll = 10 * time.Millisecond
	if opts.Validate == 0 {
		opts.Validate = 20 * time.Millisecond
	}
	hub := realtime.New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = hub.Run(ctx) }()
	t.Cleanup(func() { hub.Close(); cancel(); <-done })
	w := &streamWorld{t: t, s: s, store: ta.store, hub: hub}
	w.exec(`INSERT INTO auth_users (id, name, email) VALUES ('usr_parity', 'Parity', 'parity@example.com')`)
	w.exec(`INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('usr_parity', 'idn_parity')`)
	for _, org := range []string{"org_a", "org_b"} {
		w.exec(`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, ?, ?, '{}')`, org, org, org)
		w.exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_parity', 'member')`, org)
	}
	return w
}

func (w *streamWorld) exec(stmt string, args ...any) {
	w.t.Helper()
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), stmt, args...)
		return err
	}); err != nil {
		w.t.Fatalf("%s: %v", stmt, err)
	}
}

func (w *streamWorld) session() string {
	w.n++
	id := fmt.Sprintf("ses_bp%d", w.n)
	w.exec(`INSERT INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES (?, ?, ?, 'usr_parity')`, id, time.Now().Add(time.Hour).UnixMicro(), "h_"+id)
	return id
}

// event commits audit events of an Organization ("" for none), one per
// type, in one commit; it returns their ids.
func (w *streamWorld) event(org string, types ...string) []string {
	w.t.Helper()
	var ids []string
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		ids = ids[:0]
		for _, typ := range types {
			w.n++
			id := fmt.Sprintf("evt_bp%05d", w.n)
			var o any
			if org != "" {
				o = org
			}
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO audit_events (id, event_type, decision, organization_id, actor_identity_id) VALUES (?, ?, 'info', ?, 'idn_parity')`, id, typ, o); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	}); err != nil {
		w.t.Fatal(err)
	}
	return ids
}

// serve runs a stream for session into gw; the channel closes when
// serveStream returns.
func (w *streamWorld) serve(session string, gw *gatedWriter) (*realtime.Stream, chan struct{}) {
	w.t.Helper()
	st, err := w.hub.Subscribe(context.Background(), session, "idn_parity")
	if err != nil {
		w.t.Fatal(err)
	}
	done := make(chan struct{})
	r := httptest.NewRequest("GET", "/auth/events", nil)
	go func() {
		defer close(done)
		defer w.hub.Unsubscribe(st)
		w.s.serveStream(gw, r, st, "idn_parity")
	}()
	return st, done
}

func within(t *testing.T, done <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: not within %s", what, d)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func contains(events []string, id string) bool {
	for _, e := range events {
		if strings.Contains(e, id) {
			return true
		}
	}
	return false
}

// A security closure while the client is not reading: the write in
// progress is cut at once (not after WriteTimeout), and nothing published
// before the closure (that write, or the queue behind it) is written
// after it, even once the client reads again.
func TestStreamClosureUnderBackpressureWritesNothingQueued(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		close        func(w *streamWorld, session string)
	}{
		{"sign-out", realtime.ReasonSessionEnded, func(w *streamWorld, session string) {
			w.exec(`DELETE FROM auth_sessions WHERE id = ?`, session)
		}},
		{"removal", realtime.ReasonMembershipRemoved, func(w *streamWorld, _ string) {
			w.exec(`UPDATE org_memberships SET removed_at = 1 WHERE organization_id = 'org_b' AND identity_id = 'idn_parity'`)
			if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
				_, err := tx.ExecContext(context.Background(), `INSERT INTO audit_events (id, event_type, decision, organization_id, resource) VALUES ('evt_removal', 'membership.removed', 'info', 'org_b', '{"identityId":"idn_parity"}')`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newStreamWorld(t, realtime.Options{})
			session := w.session()
			gw := newGatedWriter(1) // "ready", then the client stops reading
			st, done := w.serve(session, gw)
			waitFor(t, 2*time.Second, "ready", func() bool { return len(gw.events()) == 1 })
			first := w.event("org_a", "project.created")
			<-gw.blocked // the first publication's write is blocked
			queued := w.event("org_b", "grant.created")
			queued = append(queued, w.event("org_a", "value.updated")...)
			time.Sleep(100 * time.Millisecond) // published, behind the blocked write
			start := time.Now()
			tc.close(w, session)
			within(t, done, 2*time.Second, "the stream to end")
			if took := time.Since(start); took >= WriteTimeout/2 {
				t.Fatalf("the blocked write was not cut at once: %s", took)
			}
			if r, _ := st.Ending(); r != tc.reason {
				t.Fatalf("reason %q", r)
			}
			gw.release()
			time.Sleep(50 * time.Millisecond)
			got := gw.events()
			for _, id := range append(first, queued...) {
				if contains(got, id) {
					t.Fatalf("%s, published before the closure, was written after it: %v", id, got)
				}
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], "ready ") {
				t.Fatalf("written: %v", got)
			}
		})
	}
}

// A removal with the client reading: the identitySignal that tells it and
// the close event are written, nothing else of that publication (another
// Organization's change in the same commit).
func TestRemovalSendsOnlyItsNotification(t *testing.T) {
	w := newStreamWorld(t, realtime.Options{})
	gw := newGatedWriter(-1)
	_, done := w.serve(w.session(), gw)
	waitFor(t, 2*time.Second, "ready", func() bool { return len(gw.events()) == 1 })
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		for _, stmt := range []string{
			`UPDATE org_memberships SET removed_at = 1 WHERE organization_id = 'org_b' AND identity_id = 'idn_parity'`,
			`INSERT INTO audit_events (id, event_type, decision, organization_id, resource) VALUES ('evt_removal', 'membership.removed', 'info', 'org_b', '{"identityId":"idn_parity"}')`,
			`INSERT INTO audit_events (id, event_type, decision, organization_id) VALUES ('evt_other_org', 'project.created', 'info', 'org_a')`,
		} {
			if _, err := tx.ExecContext(context.Background(), stmt); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	within(t, done, 3*time.Second, "the stream to end")
	got := gw.events()
	if len(got) != 3 || !strings.HasPrefix(got[1], `identity {"lastEventId":"evt_removal"`) || !strings.Contains(got[1], `"membership"`) ||
		got[2] != `close {"reason":"membership-removed"}` {
		t.Fatalf("written: %v", got)
	}
}

// A slow client is cut off when its buffer of publications fills; its
// blocked write is cut at once; another stream of the same person gets
// every publication meanwhile. Barriers, not timing: the slow client's
// write of the first publication is seen blocked, each publication is
// seen by the other stream before the next, and the cut is awaited after
// the fourth (one taken, two buffered, the fourth overflows).
func TestSlowClientCutOffUnderControlledBackpressure(t *testing.T) {
	w := newStreamWorld(t, realtime.Options{Buffer: 2})
	slow := newGatedWriter(1)
	fast := newGatedWriter(-1)
	slowStream, slowDone := w.serve(w.session(), slow)
	_, fastDone := w.serve(w.session(), fast)
	waitFor(t, 2*time.Second, "ready", func() bool { return len(slow.events()) == 1 && len(fast.events()) == 1 })
	var sent []string
	publish := func(n int) {
		ids := w.event("org_a", "project.created")
		sent = append(sent, ids...)
		waitFor(t, 2*time.Second, fmt.Sprintf("the other stream's publication %d", n), func() bool { return contains(fast.events(), ids[0]) })
	}
	publish(1)
	select {
	case <-slow.blocked: // the slow client's writer took publication 1 and is stuck on it
	case <-time.After(2 * time.Second):
		t.Fatal("the slow client's write of publication 1 never blocked")
	}
	publish(2)
	publish(3)
	if r, _ := slowStream.Ending(); r != "" {
		t.Fatalf("ended %q with one publication taken and two buffered", r)
	}
	publish(4)
	within(t, slowDone, 2*time.Second, "the slow stream to end after publication 4")
	if r, _ := slowStream.Ending(); r != realtime.ReasonSlowClient {
		t.Fatalf("ended %q", r)
	}
	slow.release()
	if got := slow.events(); len(got) != 1 {
		t.Fatalf("written to the slow client after its cut: %v", got)
	}
	select {
	case <-fastDone:
		t.Fatal("the other stream ended")
	default:
	}
	for _, id := range sent {
		if !contains(fast.events(), id) {
			t.Fatalf("the other stream missed %s", id)
		}
	}
}

// A stream request that declares a body is refused at once, and its
// connection closed, without reading the body: with an incomplete
// fixed-length body, and with an incomplete chunked one.
func TestEventsRefuseARequestBody(t *testing.T) {
	srv, b, _, hub := eventsServer(t, realtime.Options{})
	var cookies []string
	for _, k := range b.cookies {
		cookies = append(cookies, k.Name+"="+k.Value)
	}
	addr := strings.TrimPrefix(srv.URL, "http://")
	for name, framing := range map[string]string{
		"fixed length": "Content-Length: 1\r\n\r\n",
		"chunked":      "Transfer-Encoding: chunked\r\n\r\n5\r\nab",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(c, "GET /auth/events HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n%s", addr, strings.Join(cookies, "; "), framing)
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			body := new(bytes.Buffer)
			if _, err := body.ReadFrom(resp.Body); err != nil {
				t.Fatalf("reading the refusal: %v", err)
			}
			if resp.StatusCode != 400 || !resp.Close || !strings.Contains(body.String(), `"code":"VALIDATION_FAILED"`) {
				t.Fatalf("%d close=%v %s", resp.StatusCode, resp.Close, body)
			}
			// The server closed the connection.
			if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
				t.Fatalf("the connection stayed open: %d %v", n, err)
			}
			if hub.Streams() != 0 {
				t.Fatal("a stream was opened")
			}
		})
	}
}
