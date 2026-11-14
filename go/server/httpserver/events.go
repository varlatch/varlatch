// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/server/api/browser"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/realtime"
)

// The dashboard's live updates (ADR-0059 Decision 4; GET /auth/events):
// server-sent events, dashboard-internal and outside /v1. The browser's
// session authenticates the stream and go/server/realtime decides what it
// receives: its identity's Organizations' changeSignals and its own
// identitySignal, checked as each is sent.
//
// The wire format (the OpenAPI document's /auth/events):
//
//	event: ready      data {"identityId": ...}, once, first
//	event: change     data {"organizationId", "lastEventId", "occurredAt", "domains"}
//	event: identity   data {"lastEventId", "occurredAt", "domains"}
//	: keepalive       a comment, every KeepAlive
//	event: close      data {"reason": ...}, as the server ends the stream
//
// No event has an id: nothing is replayed, so a browser's Last-Event-ID
// would mean nothing. A dashboard that reconnects refreshes from /v1.
//
// A stream lives longer than any request: http.Server's ReadTimeout would
// close it, so its read deadline is cleared, and each write has a deadline
// of its own (WriteTimeout), so a client that stops reading cannot hold a
// stream: its writes time out, or its buffer in the hub fills and the hub
// disconnects it. The connection's kernel send buffer is kept small
// (SendBuffer) so that a stuck client is found after little data.
const (
	KeepAlive    = 15 * time.Second
	WriteTimeout = 10 * time.Second
	SendBuffer   = 16 << 10
)

type connKey struct{}

// ConnContext is http.Server's ConnContext: it keeps the connection in the
// request's context, so a stream can size its send buffer.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// eventsReply answers GET /auth/events: its visit writes the response,
// the whole stream included.
type eventsReply struct {
	visit func(w http.ResponseWriter) error
}

func (r eventsReply) VisitStreamBrowserEventsResponse(w http.ResponseWriter) error { return r.visit(w) }

// StreamBrowserEvents is GET /auth/events.
func (o *browserOps) StreamBrowserEvents(ctx context.Context, _ browser.StreamBrowserEventsRequestObject) (browser.StreamBrowserEventsResponseObject, error) {
	hub := o.s.opts.Realtime
	if hub == nil {
		// Not served: /v1/meta does not list realtime.sse.
		return eventsReply{func(w http.ResponseWriter) error { writeNotFound(w); return nil }}, nil
	}
	r := httpRequestOf(ctx)
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		// A stream clears its read deadline, and net/http reads an unread
		// request body before it writes the response: a body that never
		// arrives would hold the stream's goroutine and connection for
		// good. The request is refused without reading it.
		return eventsReply{func(w http.ResponseWriter) error { refuseBody(w, r); return nil }}, nil
	}
	session, err := o.session(ctx)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, domainerr.New("AUTHENTICATION_REQUIRED", "No authenticated session")
	}
	stream, err := hub.Subscribe(ctx, session.ID, session.IdentityID)
	if errors.Is(err, realtime.ErrNotLive) {
		return nil, domainerr.New("AUTHENTICATION_REQUIRED", "No authenticated session")
	}
	if errors.Is(err, realtime.ErrClosed) {
		return nil, domainerr.New("MAINTENANCE", "The server is stopping")
	}
	if err != nil {
		return nil, err
	}
	return eventsReply{func(w http.ResponseWriter) error {
		defer hub.Unsubscribe(stream)
		o.s.serveStream(w, r, stream, session.IdentityID)
		return nil
	}}, nil
}

// refuseBody answers 400 to a stream request that declares a body, and
// closes the connection without reading the body: the read deadline is
// moved to now, so net/http's own attempt to read it fails at once.
func refuseBody(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	w.Header().Set("Connection", "close")
	writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", "GET /auth/events takes no request body")
}

// CloseTimeout bounds what a stream still writes once it must end: a
// removal's identitySignal and the close event.
const CloseTimeout = 2 * time.Second

// serveStream writes a stream until it ends: the hub ends it, the client
// goes, or a write fails.
//
// Once the hub ends the stream (a sign-out, an expired or revoked
// session, a disabled identity, a removal, a slow client, a shutdown),
// nothing it had queued is written: a write in progress is interrupted at
// once (its deadline moved to now, which breaks the response), the queue
// is dropped, and the end is checked again before each event. A removal's
// identitySignal and the close event are then written, within
// CloseTimeout, when the response is still whole.
func (s *Server) serveStream(w http.ResponseWriter, r *http.Request, stream *realtime.Stream, identity string) {
	rc := http.NewResponseController(w)
	// The server's ReadTimeout would end the stream; nothing more is read
	// (the request has no body: StreamBrowserEvents refused one).
	_ = rc.SetReadDeadline(time.Time{})
	if c, ok := r.Context().Value(connKey{}).(*net.TCPConn); ok {
		_ = c.SetWriteBuffer(SendBuffer)
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // a proxy in front must not buffer it
	w.WriteHeader(http.StatusOK)

	var mu sync.Mutex
	writing, broken := false, false
	finished := make(chan struct{})
	defer close(finished)
	interrupted := make(chan struct{})
	go func() {
		defer close(interrupted)
		select {
		case <-stream.Done():
			mu.Lock()
			if writing {
				_ = rc.SetWriteDeadline(time.Now())
			}
			mu.Unlock()
		case <-finished:
		}
	}()
	// write writes one chunk by deadline. Unless final, it writes nothing
	// once the stream has ended.
	write := func(chunk string, deadline time.Time, final bool) bool {
		mu.Lock()
		if broken || !final && stream.Ended() {
			mu.Unlock()
			return false
		}
		if err := rc.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			broken = true
			mu.Unlock()
			return false
		}
		writing = true
		mu.Unlock()
		_, err := io.WriteString(w, chunk)
		if err == nil {
			err = rc.Flush()
		}
		mu.Lock()
		writing = false
		if err != nil {
			broken = true
		}
		mu.Unlock()
		return err == nil
	}
	event := func(name string, data []byte, deadline time.Time, final bool) bool {
		return write(fmt.Sprintf("event: %s\ndata: %s\n\n", name, data), deadline, final)
	}
	next := func() time.Time { return time.Now().Add(WriteTimeout) }

	ready, _ := json.Marshal(map[string]string{"identityId": identity})
	if !event("ready", ready, next(), false) {
		s.endStream(stream, interrupted, event)
		return
	}
	keepAlive := time.NewTicker(KeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case batch := <-stream.Messages():
			for _, m := range batch {
				if !event(m.Event, m.Data, next(), false) {
					s.endStream(stream, interrupted, event)
					return
				}
			}
		case <-keepAlive.C:
			if !write(": keepalive\n\n", next(), false) {
				s.endStream(stream, interrupted, event)
				return
			}
		case <-r.Context().Done():
			return
		case <-stream.Done():
			s.endStream(stream, interrupted, event)
			return
		}
	}
}

// endStream writes what an ended stream still sends, if it has ended and
// its response is whole: a removal's identitySignal, then the close event,
// all within CloseTimeout. A slow client gets nothing more.
func (s *Server) endStream(stream *realtime.Stream, interrupted <-chan struct{}, event func(string, []byte, time.Time, bool) bool) {
	if !stream.Ended() {
		return // a write failed: the client is gone
	}
	<-interrupted // a write in progress at the end was cut first
	reason, final := stream.Ending()
	if reason == "" || reason == realtime.ReasonSlowClient {
		return
	}
	deadline := time.Now().Add(CloseTimeout)
	for _, m := range final {
		if !event(m.Event, m.Data, deadline, true) {
			return
		}
	}
	data, _ := json.Marshal(map[string]string{"reason": reason})
	event("close", data, deadline, true)
}
