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
	r := httpRequestOf(ctx)
	return eventsReply{func(w http.ResponseWriter) error {
		defer hub.Unsubscribe(stream)
		o.s.serveStream(w, r, stream, session.IdentityID)
		return nil
	}}, nil
}

// serveStream writes a stream until it ends: the hub ends it, the client
// goes, or a write fails.
func (s *Server) serveStream(w http.ResponseWriter, r *http.Request, stream *realtime.Stream, identity string) {
	rc := http.NewResponseController(w)
	// The server's ReadTimeout would end the stream; nothing more is read.
	_ = rc.SetReadDeadline(time.Time{})
	if c, ok := r.Context().Value(connKey{}).(*net.TCPConn); ok {
		_ = c.SetWriteBuffer(SendBuffer)
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // a proxy in front must not buffer it
	w.WriteHeader(http.StatusOK)
	// A client the hub cut off for being slow may have a write blocked on
	// it: the deadline is moved to now, which ends that write at once.
	var mu sync.Mutex
	cut := false
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-stream.Done():
			if reason, _ := stream.Ending(); reason == realtime.ReasonSlowClient {
				mu.Lock()
				cut = true
				_ = rc.SetWriteDeadline(time.Now())
				mu.Unlock()
			}
		case <-finished:
		}
	}()
	write := func(chunk string) bool {
		mu.Lock()
		if cut {
			mu.Unlock()
			return false
		}
		err := rc.SetWriteDeadline(time.Now().Add(WriteTimeout))
		mu.Unlock()
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := io.WriteString(w, chunk); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	event := func(name string, data []byte) bool {
		return write(fmt.Sprintf("event: %s\ndata: %s\n\n", name, data))
	}
	ready, _ := json.Marshal(map[string]string{"identityId": identity})
	if !event("ready", ready) {
		return
	}
	keepAlive := time.NewTicker(KeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case batch := <-stream.Messages():
			for _, m := range batch {
				if !event(m.Event, m.Data) {
					return
				}
			}
		case <-keepAlive.C:
			if !write(": keepalive\n\n") {
				return
			}
		case <-r.Context().Done():
			return
		case <-stream.Done():
			reason, drain := stream.Ending()
			if reason == realtime.ReasonSlowClient {
				// Nothing more is written to a client that does not read.
				return
			}
			for drain {
				select {
				case batch := <-stream.Messages():
					for _, m := range batch {
						if !event(m.Event, m.Data) {
							return
						}
					}
				default:
					drain = false
				}
			}
			if reason != "" {
				data, _ := json.Marshal(map[string]string{"reason": reason})
				event("close", data)
			}
			return
		}
	}
}
