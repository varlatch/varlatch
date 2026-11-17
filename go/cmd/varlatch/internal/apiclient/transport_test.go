// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// What fetch does that the transcripts cannot show from one local server:
// cross-origin redirects, failures to connect, timeouts, trust. Node.js's
// behaviour for each was checked by hand with fetch in Node 26.

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []string
}

func (s *seen) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r)
	s.body = append(s.body, string(b))
}

func TestHeadersAsFetchSends(t *testing.T) {
	var s seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.add(r); w.WriteHeader(204) }))
	defer srv.Close()
	c := New(Options{Server: srv.URL + "//", Token: "vlt_cli_x", UserAgent: "ua/1", Approval: "apr_1"})
	if _, err := c.Request(context.Background(), "PUT", "/v1/x?y=1", jsjson.Object{{Key: "value", Value: "v"}}, IdempotencyKey("key-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Meta(context.Background()); err != nil {
		t.Fatal(err)
	}
	put, get := s.reqs[0], s.reqs[1]
	for name, want := range map[string]string{"Authorization": "Bearer vlt_cli_x", "User-Agent": "ua/1", "Content-Type": "application/json", "Accept": "*/*", "Idempotency-Key": "key-1", ApprovalHeader: "apr_1"} {
		if got := put.Header.Get(name); got != want {
			t.Errorf("PUT %s: %q, want %q", name, got, want)
		}
	}
	if put.URL.RequestURI() != "/v1/x?y=1" || s.body[0] != `{"value":"v"}` {
		t.Errorf("PUT %s with %s", put.URL.RequestURI(), s.body[0])
	}
	// A GET carries neither a body's Content-Type nor the approval.
	if get.Header.Get("Content-Type") != "" || get.Header.Get(ApprovalHeader) != "" || get.Header.Get("Idempotency-Key") != "" {
		t.Errorf("GET headers %v", get.Header)
	}
}

func TestRedirectsAsFetchFollows(t *testing.T) {
	var other seen
	otherSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.add(r); w.WriteHeader(204) }))
	defer otherSrv.Close()
	var same seen
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		same.add(r)
		switch r.URL.Path {
		case "/302":
			w.Header().Set("Location", "/target")
			w.WriteHeader(302)
		case "/307":
			w.Header().Set("Location", "target")
			w.WriteHeader(307)
		case "/303-put":
			w.Header().Set("Location", "/target")
			w.WriteHeader(303)
		case "/301-put":
			w.Header().Set("Location", "/target")
			w.WriteHeader(301)
		case "/cross":
			w.Header().Set("Location", strings.Replace(otherSrv.URL, "127.0.0.1", "localhost", 1)+"/x")
			w.WriteHeader(302)
		case "/loop":
			w.Header().Set("Location", "/loop")
			w.WriteHeader(302)
		case "/ftp":
			w.Header().Set("Location", "ftp://example.invalid/")
			w.WriteHeader(302)
		case "/no-location":
			w.WriteHeader(302)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	c := New(Options{Server: srv.URL, Token: "vlt_cli_x"})
	ctx := context.Background()
	body := jsjson.Object{{Key: "a", Value: 1.0}}

	// 302 after a POST: a GET, without the body or its headers; same origin keeps the credential.
	if _, err := c.Request(ctx, "POST", "/302", body, nil); err != nil {
		t.Fatal(err)
	}
	r := same.reqs[len(same.reqs)-1]
	if r.Method != "GET" || r.URL.Path != "/target" || same.body[len(same.body)-1] != "" || r.Header.Get("Content-Type") != "" || r.Header.Get("Authorization") == "" {
		t.Errorf("after 302: %s %s %q %v", r.Method, r.URL.Path, same.body[len(same.body)-1], r.Header)
	}
	// 307: the same method and body again, relative Location resolved.
	if _, err := c.Request(ctx, "POST", "/307", body, nil); err != nil {
		t.Fatal(err)
	}
	r = same.reqs[len(same.reqs)-1]
	if r.Method != "POST" || r.URL.Path != "/target" || same.body[len(same.body)-1] != `{"a":1}` {
		t.Errorf("after 307: %s %s %q", r.Method, r.URL.Path, same.body[len(same.body)-1])
	}
	// 303 makes any method a GET; 301 keeps a PUT (fetch, unlike Go's client).
	if _, err := c.Request(ctx, "PUT", "/303-put", body, nil); err != nil {
		t.Fatal(err)
	}
	if r = same.reqs[len(same.reqs)-1]; r.Method != "GET" {
		t.Errorf("after 303: %s", r.Method)
	}
	if _, err := c.Request(ctx, "PUT", "/301-put", body, nil); err != nil {
		t.Fatal(err)
	}
	if r = same.reqs[len(same.reqs)-1]; r.Method != "PUT" || same.body[len(same.body)-1] != `{"a":1}` {
		t.Errorf("after 301: %s %q", r.Method, same.body[len(same.body)-1])
	}
	// Another origin (localhost is not 127.0.0.1): the credential is dropped.
	if _, err := c.Request(ctx, "GET", "/cross", NoBody, nil); err != nil {
		t.Fatal(err)
	}
	if len(other.reqs) != 1 || other.reqs[0].Header.Get("Authorization") != "" {
		t.Errorf("cross-origin redirect: %d requests, Authorization %q", len(other.reqs), other.reqs[0].Header.Get("Authorization"))
	}
	// A 302 without a Location is the answer.
	if _, err := c.Request(ctx, "GET", "/no-location", NoBody, nil); err == nil || err.(*APIError).Message != "HTTP 302" {
		t.Errorf("302 without Location: %v", err)
	}
	// More than 20 redirects, and a redirect to another scheme: a network error.
	for _, path := range []string{"/loop", "/ftp"} {
		before := len(same.reqs)
		_, err := c.Request(ctx, "GET", path, NoBody, nil)
		if NetworkFailure(err) != "network error" || err.Error() != "fetch failed" {
			t.Errorf("%s: %v (%q)", path, err, NetworkFailure(err))
		}
		if path == "/loop" && len(same.reqs)-before != 21 {
			t.Errorf("/loop: %d requests, want 21", len(same.reqs)-before)
		}
	}
}

func TestFailuresToConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "http://" + ln.Addr().String()
	ln.Close()
	closing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer closing.Close()
	for _, c := range []struct{ server, message, code string }{
		{refused, "fetch failed", "ECONNREFUSED"},
		{"http://127.0.0.1:1", "fetch failed", "network error"}, // a bad port: never connected to
		{"http://127.0.0.1:6000", "fetch failed", "network error"},
		{"ftp://127.0.0.1:2", "fetch failed", "network error"},
		{"file:///tmp", "fetch failed", "network error"},
		{closing.URL, "fetch failed", "UND_ERR_SOCKET"},
		{"not a url", "Failed to parse URL from not a url/v1/meta", ""},
		{"http://u:p@127.0.0.1:2", "Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:2/v1/meta", ""},
		{"http://user:hunter2@[::1", "Failed to parse URL from http://[redacted]@[::1/v1/meta", ""},
		{"http:/user:hunter2@[::1", "Failed to parse URL from http:/[redacted]@[::1/v1/meta", ""},
		{"HTTP:\\user:hunter2@[::1", "Failed to parse URL from HTTP:\\[redacted]@[::1/v1/meta", ""},
	} {
		_, err := New(Options{Server: c.server}).Meta(context.Background())
		var f *FetchError
		if !errors.As(err, &f) || f.Message != c.message || NetworkFailure(err) != c.code {
			t.Errorf("%s: %v (%q), want %q (%q)", c.server, err, NetworkFailure(err), c.message, c.code)
		}
	}
}

func TestTimeouts(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/slow-body" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"a":`))
			w.(http.Flusher).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	c := New(Options{Server: srv.URL})
	c.transport = newTransport("", 200*time.Millisecond, 200*time.Millisecond)
	// No headers in time: undici's UND_ERR_HEADERS_TIMEOUT, which exitCodes.ts calls a network error.
	if _, err := c.Meta(context.Background()); NetworkFailure(err) != "network error" {
		t.Errorf("headers timeout: %v (%q)", err, NetworkFailure(err))
	}
	// No body chunk in time: "terminated", not a network failure.
	_, err := c.Request(context.Background(), "GET", "/v1/slow-body", NoBody, nil)
	var b *BodyError
	if !errors.As(err, &b) || b.Message != "terminated" || NetworkFailure(err) != "" {
		t.Errorf("body timeout: %v", err)
	}
}

type mapEnv map[string]string

func (m mapEnv) LookupEnv(k string) (string, bool) { v, ok := m[k]; return v, ok }

func TestNodeExtraCACerts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "extra.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// Without it the private CA is not trusted: fetch failed, a network error.
	if _, err := New(Options{Server: srv.URL, Env: mapEnv{}}).Meta(context.Background()); NetworkFailure(err) != "network error" {
		t.Errorf("untrusted: %v", err)
	}
	if _, err := New(Options{Server: srv.URL, Env: mapEnv{"NODE_EXTRA_CA_CERTS": file}}).Meta(context.Background()); err != nil {
		t.Errorf("with NODE_EXTRA_CA_CERTS: %v", err)
	}
	// A file that cannot be read adds nothing, and nothing fails because of it.
	if _, err := New(Options{Server: srv.URL, Env: mapEnv{"NODE_EXTRA_CA_CERTS": file + ".missing"}}).Meta(context.Background()); NetworkFailure(err) != "network error" {
		t.Errorf("missing file: %v", err)
	}
}

func TestNoProxyFromTheEnvironment(t *testing.T) {
	ht := newTransport("", time.Second, time.Second).client.Transport.(*http.Transport)
	if ht.Proxy != nil {
		t.Error("the transport reads a proxy; fetch reads none")
	}
}

func TestStepUpAndStaleCapture(t *testing.T) {
	var s seen
	answers := []string{
		`{"error":{"code":"STEP_UP_REQUIRED","message":"approve","details":{"approval":{"id":"apr_9"}}}}`,
		`{"error":{"code":"STATE_CHANGED","message":"stale","details":{"reason":"stale-capture"}}}`,
		`{"error":{"code":"STATE_CHANGED","message":"stale","details":{"reason":"stale-capture"}}}`,
		`{"done":true}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		next := answers[0]
		answers = answers[1:]
		if strings.Contains(next, "error") {
			w.WriteHeader(403)
		}
		_, _ = w.Write([]byte(next))
	}))
	defer srv.Close()
	var asked any
	c := New(Options{Server: srv.URL, OnStepUp: func(a any) (bool, error) { asked = a; return true, nil }})
	v, err := c.Request(context.Background(), "POST", "/v1/x", jsjson.Object{}, nil)
	if err != nil || string(jsjson.Stringify(v)) != `{"done":true}` {
		t.Fatalf("%v %v", v, err)
	}
	if asked == nil || len(s.reqs) != 4 || s.reqs[0].Header.Get(ApprovalHeader) != "" || s.reqs[3].Header.Get(ApprovalHeader) != "apr_9" {
		t.Errorf("approval %v; %d requests", asked, len(s.reqs))
	}
}

func TestCredentialExpiresHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(CredentialExpiresHeader, "2026-11-20T00:00:00Z")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"INVALID_CREDENTIAL","message":"no"}}`))
	}))
	defer srv.Close()
	var got []string
	c := New(Options{Server: srv.URL, OnCredentialExpires: func(at string) { got = append(got, at) }})
	_, _ = c.Meta(context.Background())
	_, _ = c.Meta(context.Background())
	if len(got) != 2 || got[0] != "2026-11-20T00:00:00Z" {
		t.Errorf("OnCredentialExpires calls: %q", got)
	}
}

func TestHTTP1Only(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proto":"` + r.Proto + `"}`))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "extra.pem")
	_ = os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	v, err := New(Options{Server: srv.URL, Env: mapEnv{"NODE_EXTRA_CA_CERTS": file}}).Meta(context.Background())
	if err != nil || string(jsjson.Stringify(v)) != `{"proto":"HTTP/1.1"}` {
		t.Errorf("%s %v", jsjson.Stringify(v), err)
	}
}

// Diagnostics never print credential values: a header value fetch refuses
// is named by its header, a URL by its host, and nothing is sent.
func TestRefusalsNeverShowCredentials(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests++; w.WriteHeader(204) }))
	defer srv.Close()
	const secret = "vlt_cli_secretAAAA"
	for _, c := range []struct {
		opts    Options
		headers []Header
		message string
	}{
		{Options{Token: secret + "\nextra"}, nil, "the credential contains a character that is not allowed in an HTTP header"},
		{Options{Token: secret + "\x00"}, nil, "the credential contains a character that is not allowed in an HTTP header"},
		{Options{Token: secret + "\u0100"}, nil, "the credential contains a character that is not allowed in an HTTP header"},
		{Options{Token: secret, UserAgent: "ua\r" + secret}, nil, "the User-Agent header contains a character that is not allowed in an HTTP header"},
		{Options{Token: secret, Approval: "apr_" + secret + "\n1"}, nil, "the Varlatch-Approval header contains a character that is not allowed in an HTTP header"},
		{Options{Token: secret}, IdempotencyKey(secret + "\u4e2d"), "the Idempotency-Key header contains a character that is not allowed in an HTTP header"},
	} {
		c.opts.Server = srv.URL
		_, err := New(c.opts).Request(context.Background(), "POST", "/v1/x", jsjson.Object{}, c.headers)
		var f *FetchError
		if !errors.As(err, &f) || f.Message != c.message || NetworkFailure(err) != "" || strings.Contains(err.Error(), "secretAAAA") {
			t.Errorf("%v, want %q", err, c.message)
		}
	}
	if requests != 0 {
		t.Errorf("%d requests sent", requests)
	}
}

// fetch refuses to follow a redirect to a URL with credentials, before
// sending anything there (Node 26: "fetch failed", "cross origin not
// allowed for request mode cors").
func TestRedirectWithCredentialsRefused(t *testing.T) {
	var s seen
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		host := strings.TrimPrefix(srv.URL, "http://")
		switch r.URL.Path {
		case "/userpass":
			w.Header().Set("Location", "http://user:hunter2@"+host+"/target")
			w.WriteHeader(302)
		case "/user":
			w.Header().Set("Location", "//user@"+host+"/target")
			w.WriteHeader(307)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	c := New(Options{Server: srv.URL, Token: "vlt_cli_x"})
	for _, path := range []string{"/userpass", "/user"} {
		before := len(s.reqs)
		_, err := c.Request(context.Background(), "GET", path, NoBody, nil)
		if err == nil || err.Error() != "fetch failed" || NetworkFailure(err) != "network error" || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: %v (%q)", path, err, NetworkFailure(err))
		}
		if len(s.reqs)-before != 1 {
			t.Errorf("%s: %d requests, want only the first", path, len(s.reqs)-before)
		}
	}
}
