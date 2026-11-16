// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"sync"
	"testing"
)

// fakeAdmission is a maintenance admission the test opens and closes.
type fakeAdmission struct {
	mu      sync.Mutex
	closed  bool
	entered int
	left    int
}

func (f *fakeAdmission) Enter() (func(), bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, false
	}
	f.entered++
	return func() { f.mu.Lock(); f.left++; f.mu.Unlock() }, true
}

// The 503 MAINTENANCE admission, as http/app.ts answers it: /healthz
// always, /readyz not ready, every other API route MAINTENANCE with
// Retry-After, before the body limit; the dashboard's own files are
// served, so it can show its maintenance screen. An admitted request
// leaves when it ends.
func TestMaintenanceAdmission(t *testing.T) {
	gate := &fakeAdmission{closed: true}
	s, _, _, _ := newTestServer(t, func(o *Options) { o.Maintenance = gate })
	if w := do(s, "GET", "/healthz", "", nil); w.Code != 200 || w.Body.String() != `{"status":"ok"}` {
		t.Errorf("healthz: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "GET", "/readyz", "", nil); w.Code != 503 || w.Body.String() != `{"ready":false,"checks":{"maintenance":false}}` {
		t.Errorf("readyz: %d %s", w.Code, w.Body.String())
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/v1/meta", ""},
		{"GET", "/v1/installation/backups", ""},
		{"POST", "/v1/organizations", string(make([]byte, MaxBody+1))},
		{"GET", "/v1/nothing", ""},
	} {
		w := do(s, c.method, c.path, c.body, nil)
		e := decode(t, w)
		if w.Code != 503 || e.Error.Code != "MAINTENANCE" || e.Error.Message != MaintenanceMessage || w.Header().Get("Retry-After") != "5" ||
			!requestIDPattern.MatchString(e.Error.RequestID) || w.Header().Get("X-Request-Id") != e.Error.RequestID {
			t.Errorf("%s %s: %d %v %s", c.method, c.path, w.Code, w.Header(), w.Body.String())
		}
	}
	for _, p := range []string{"/", "/o/acme/projects", "/assets/app-1234.js"} {
		if w := do(s, "GET", p, "", nil); w.Code != 200 {
			t.Errorf("dashboard %s: %d", p, w.Code)
		}
	}
	if gate.entered != 0 {
		t.Errorf("%d requests admitted while closed", gate.entered)
	}

	gate.mu.Lock()
	gate.closed = false
	gate.mu.Unlock()
	if w := do(s, "GET", "/readyz", "", nil); w.Code != 200 {
		t.Errorf("readyz once open: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "GET", "/v1/meta", "", nil); w.Code != 200 {
		t.Errorf("meta once open: %d %s", w.Code, w.Body.String())
	}
	if gate.entered != 2 || gate.left != 2 {
		t.Errorf("entered %d, left %d", gate.entered, gate.left)
	}
}
