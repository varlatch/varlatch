// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"strconv"
	"sync"
	"time"
)

// The request window, as the TypeScript server keeps it (http/app.ts): at
// most WindowLimit requests per client address in a fixed window of
// WindowLength that starts with the client's first request, and at most
// MaxWindows clients with an open window. It bounds per-process work before
// authentication or audit writes. The limit is per client address, not per
// credential, and stays in force for the conformance harness and G9a.
const (
	WindowLimit  = 600
	WindowLength = 60 * time.Second
	MaxWindows   = 10_000
)

// RateExceededMessage is the 429's message; its code is PERMISSION_DENIED,
// one of the two known differences decision 4 keeps (not RATE_LIMITED).
const RateExceededMessage = "Request rate exceeded"

type window struct {
	until time.Time
	count int
}

// requestWindow counts requests per client address.
type requestWindow struct {
	mu      sync.Mutex
	windows map[string]*window
	now     func() time.Time
}

func newRequestWindow(now func() time.Time) *requestWindow {
	if now == nil {
		now = time.Now
	}
	return &requestWindow{windows: map[string]*window{}, now: now}
}

// admit counts one request from peer. When the request is refused it
// returns false and the Retry-After value in seconds.
func (rw *requestWindow) admit(peer string) (ok bool, retryAfter string) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	now := rw.now()
	w := rw.windows[peer]
	if w == nil || !w.until.After(now) {
		for k, v := range rw.windows {
			if !v.until.After(now) {
				delete(rw.windows, k)
			}
		}
		if _, has := rw.windows[peer]; len(rw.windows) >= MaxWindows && !has {
			return false, "60"
		}
		w = &window{until: now.Add(WindowLength)}
		rw.windows[peer] = w
	}
	w.count++
	if w.count > WindowLimit {
		// Math.max(1, Math.ceil((until - now) / 1000)) over milliseconds.
		ms := w.until.Sub(now).Milliseconds()
		return false, strconv.FormatInt(max(1, (ms+999)/1000), 10)
	}
	return true, ""
}
