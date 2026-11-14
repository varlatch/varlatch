// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/known-differences.json holds the answers the Go server must give
// exactly as the TypeScript server does; services/varlatchd/test/
// go-parity.test.ts runs the same table against the TypeScript app.
type parityTable struct {
	UnknownRoutes []struct {
		Method, Path, Credential, Code, Text string
		Status                               int
		GoUntilStep34                        *struct {
			Status int
			Code   string
			Text   string
		} `json:"goUntilStep3_4"`
	} `json:"unknownRoutes"`
	ForwardedFor []struct {
		Peer    string
		Trusted []string
		Lines   []string
		Client  string
	} `json:"forwardedFor"`
	RequestWindow struct {
		Path              string
		Allowed, Status   int
		Code, Message     string
		RetryAfterAtStart string
	} `json:"requestWindow"`
}

func loadParity(t *testing.T) parityTable {
	t.Helper()
	b, err := os.ReadFile("testdata/known-differences.json")
	if err != nil {
		t.Fatal(err)
	}
	var p parityTable
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.UnknownRoutes) == 0 || len(p.ForwardedFor) == 0 || p.RequestWindow.Allowed != WindowLimit {
		t.Fatalf("the table is incomplete: %+v", p)
	}
	return p
}

// Unknown /v1 routes: authentication first (401 AUTHENTICATION_REQUIRED
// without a bearer), the plain-text 404 after it or on /v1/meta's path.
func TestParityUnknownRoutes(t *testing.T) {
	s, b, _, _ := newTestServer(t, nil)
	for _, c := range loadParity(t).UnknownRoutes {
		want := struct {
			Status     int
			Code, Text string
		}{c.Status, c.Code, c.Text}
		if c.GoUntilStep34 != nil {
			want.Status, want.Code, want.Text = c.GoUntilStep34.Status, c.GoUntilStep34.Code, c.GoUntilStep34.Text
		}
		header := map[string]string{}
		switch c.Credential {
		case "valid", "invalid":
			header["Authorization"] = "Bearer vlt_cli_" + c.Credential
		case "basic":
			header["Authorization"] = "Basic dXNlcjpwYXNz"
		}
		r := httptest.NewRequest(c.Method, "http://varlatch.test/", nil)
		r.URL.Path = c.Path // as sent, not cleaned
		r.RequestURI = c.Path
		r.RemoteAddr = "192.0.2.10:40000"
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		name := fmt.Sprintf("%s %s (%s)", c.Method, c.Path, c.Credential)
		if w.Code != want.Status {
			t.Errorf("%s: %d, want %d: %s", name, w.Code, want.Status, w.Body.String())
			continue
		}
		if want.Text != "" {
			if w.Body.String() != want.Text || w.Header().Get("Content-Type") != "text/plain; charset=UTF-8" {
				t.Errorf("%s: %q %q", name, w.Header().Get("Content-Type"), w.Body.String())
			}
		} else if e := decode(t, w); e.Error.Code != want.Code || w.Header().Get("Content-Type") != "application/json" ||
			(want.Code == "AUTHENTICATION_REQUIRED" && e.Error.Message != "Provide a Varlatch bearer credential") {
			t.Errorf("%s: %s", name, w.Body.String())
		}
	}
	if b.installationCalls != 0 || b.readies != 0 {
		t.Error("an unknown route reached the backend")
	}
}

// X-Forwarded-For in several lines: every line counts, joined as Node
// joins them, and read from the right through trusted proxies.
func TestParityForwardedForLines(t *testing.T) {
	for _, c := range loadParity(t).ForwardedFor {
		trusted := c.Trusted
		s, _, _, logBuf := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return slices.Contains(trusted, a) } })
		r := httptest.NewRequest("GET", "/v1/meta", nil)
		r.RemoteAddr = c.Peer + ":5555"
		for _, line := range c.Lines {
			r.Header.Add("X-Forwarded-For", line)
		}
		s.ServeHTTP(httptest.NewRecorder(), r)
		var rec AccessRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(logBuf.String())), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Client != c.Client {
			t.Errorf("lines %q from %s: client %s, want %s", c.Lines, c.Peer, rec.Client, c.Client)
		}
		if rec.ForwardedFor == nil || *rec.ForwardedFor != strings.Join(c.Lines, ", ") {
			t.Errorf("lines %q: forwardedFor %v", c.Lines, rec.ForwardedFor)
		}
	}
}

// A forged first line cannot take another client's window: Sol's
// reproduction, a trusted proxy adding the observed client as a second
// line.
func TestForwardedForSecondLineWindow(t *testing.T) {
	s, _, _, _ := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return a == "10.0.0.2" } })
	send := func(forged string) int {
		r := httptest.NewRequest("GET", "/v1/meta", nil)
		r.RemoteAddr = "10.0.0.2:5555"
		r.Header.Add("X-Forwarded-For", forged)
		r.Header.Add("X-Forwarded-For", "203.0.113.7")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < WindowLimit; i++ {
		send(fmt.Sprintf("198.51.100.%d", i%250))
	}
	if code := send("198.51.100.99"); code != http.StatusTooManyRequests {
		t.Errorf("a forged first line evaded the window: %d", code)
	}
}

func TestParityRequestWindow(t *testing.T) {
	w := loadParity(t).RequestWindow
	s, _, _, _ := newTestServer(t, nil)
	for i := 0; i < w.Allowed; i++ {
		if got := do(s, "GET", w.Path, "", nil); got.Code != 200 {
			t.Fatalf("request %d: %d", i+1, got.Code)
		}
	}
	got := do(s, "GET", w.Path, "", nil)
	e := decode(t, got)
	if got.Code != w.Status || got.Header().Get("Retry-After") != w.RetryAfterAtStart || e.Error.Code != w.Code || e.Error.Message != w.Message {
		t.Errorf("%d %q %s", got.Code, got.Header().Get("Retry-After"), got.Body.String())
	}
}
