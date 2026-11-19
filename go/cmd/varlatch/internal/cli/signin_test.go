// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// syncBuffer is a buffer two goroutines can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var printedCallback = regexp.MustCompile(`callback=(\S+)\n`)

// TestBrowserCallbackTakesOnlyItsPath: the loopback listener is on
// 127.0.0.1 only; a POST to any path but its random one, or to it under
// another Host (DNS rebinding), is refused (404); a GET (405) or a preflight
// OPTIONS (204) on its path is answered; none of them ends the sign-in or
// uses up the callback; the sign-in's own POST delivers the bearer; and the
// listener takes no connection after it (single use).
func TestBrowserCallbackTakesOnlyItsPath(t *testing.T) {
	var stdout syncBuffer
	r := &Run{IO: IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &syncBuffer{}}, Env: MapEnv{"VARLATCH_NO_BROWSER": "1"}, Secrets: &Secrets{}}
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		token, err := r.browserLogin("https://varlatch.example")
		done <- result{token, err}
	}()
	var callback string
	for i := 0; i < 200 && callback == ""; i++ {
		if m := printedCallback.FindStringSubmatch(stdout.String()); m != nil {
			callback, _ = url.QueryUnescape(m[1])
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, err := url.Parse(callback)
	if err != nil || u.Hostname() != "127.0.0.1" || len(strings.TrimPrefix(u.Path, "/")) != 32 {
		t.Fatalf("callback %q: not on 127.0.0.1 with a random path", callback)
	}
	send := func(method, target, host, body string) int {
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
		req, err := http.NewRequest(method, target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		res, err := client.Do(req)
		if err != nil {
			return 0 // refused
		}
		res.Body.Close()
		return res.StatusCode
	}
	post := func(target, body string) int { return send("POST", target, "", body) }
	port := u.Port()
	for _, c := range []struct {
		method, host string
		want         int
	}{
		{"POST", "rebound.example:" + port, http.StatusNotFound},
		{"POST", "127.0.0.1:1", http.StatusNotFound},
		{"GET", "", http.StatusMethodNotAllowed},
		{"OPTIONS", "", http.StatusNoContent},
		{"GET", "localhost:" + port, http.StatusMethodNotAllowed},
	} {
		if got := send(c.method, callback, c.host, `{"token":"vlt_web_forged"}`); got != c.want {
			t.Errorf("%s with Host %q got %d, want %d", c.method, c.host, got, c.want)
		}
	}
	if got := post("http://"+u.Host+"/", `{"token":"vlt_web_forged"}`); got != http.StatusNotFound {
		t.Errorf("a POST to / got %d, want 404", got)
	}
	if got := post("http://"+u.Host+"/"+strings.Repeat("A", 32), `{"token":"vlt_web_forged"}`); got != http.StatusNotFound {
		t.Errorf("a POST to another path got %d, want 404", got)
	}
	select {
	case r := <-done:
		t.Fatalf("a POST elsewhere ended the sign-in: %q, %v", r.token, r.err)
	default:
	}
	if got := post(callback, `{"token":"vlt_web_handoff","identityId":"idn_1"}`); got != http.StatusOK {
		t.Errorf("the sign-in's POST got %d, want 200", got)
	}
	got := <-done
	if got.err != nil || got.token != "vlt_web_handoff" {
		t.Fatalf("got %q, %v", got.token, got.err)
	}
	if status := post(callback, `{"token":"vlt_web_again"}`); status != 0 {
		t.Errorf("a second POST got %d, want refused", status)
	}
}

func TestSetSearchParam(t *testing.T) {
	for _, c := range []struct{ query, want string }{
		{"", "audience=varlatch+ci"},
		{"api-version=2.0", "api-version=2.0&audience=varlatch+ci"},
		{"audience=old&x=1&audience=older", "audience=varlatch+ci&x=1"},
		{"a=b%20c&d", "a=b+c&d=&audience=varlatch+ci"},
	} {
		if got := setSearchParam(c.query, "audience", "varlatch ci"); got != c.want {
			t.Errorf("setSearchParam(%q) = %q, want %q", c.query, got, c.want)
		}
	}
}

// TestShellWords: a server in a suggested command is one shell word; an
// IPv6 address's brackets and anything else a shell would read are quoted.
func TestShellWords(t *testing.T) {
	for in, want := range map[string]string{
		"https://varlatch.example.com": "https://varlatch.example.com",
		"http://127.0.0.1:8080/base":   "http://127.0.0.1:8080/base",
		"http://[::1]:8080":            "'http://[::1]:8080'",
		"it's":                         `'it'\''s'`,
	} {
		if got := shellWord(in); got != want {
			t.Errorf("shellWord(%q) = %q, want %q", in, got, want)
		}
	}
	if got := commandServer("https://u:p@h.example/?x=1"); got != "'https://h.example/?[redacted]'" {
		t.Errorf("commandServer = %q", got)
	}
}

// TestInFlightSecretsNeverShow: a secret the run handles (a device code, a
// hand-off bearer, an OIDC token) is redacted wherever it would show: a
// stdout line, a --json document and a diagnostic, whatever its form.
func TestInFlightSecretsNeverShow(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Run{IO: IO{Stdout: &stdout, Stderr: &stderr}, Env: MapEnv{}, Secrets: &Secrets{}}
	r.holdSecret("dc_canary_short")
	r.holdSecret("eyJ.oidc.canary")
	_ = r.println("code dc_canary_short and eyJ.oidc.canary")
	_ = r.printJSON(jsjson.Object{{Key: "deviceCode", Value: "dc_canary_short"}, {Key: "nested", Value: []any{"x eyJ.oidc.canary"}}})
	_ = r.warn("refused dc_canary_short")
	r.finish(Fail("failed with eyJ.oidc.canary", ExitFailure))
	out := stdout.String() + stderr.String()
	if strings.Contains(out, "canary") || strings.Count(out, Redacted) != 6 {
		t.Errorf("in-flight secrets shown:\n%s", out)
	}
}

// TestResumeWaitsBeforeTheFirstChange: with --approval, reads go out at
// once; the first change request waits until the approval is approved and
// then carries it; later changes do not wait again.
func TestResumeWaitsBeforeTheFirstChange(t *testing.T) {
	var polls atomic.Int32
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		seen = append(seen, req.Method+" "+req.URL.Path+" "+req.Header.Get(apiclient.ApprovalHeader))
		mu.Unlock()
		if req.URL.Path == "/v1/me/approvals/apr_1" {
			state := "pending"
			if polls.Add(1) > 1 {
				state = "approved"
			}
			_, _ = w.Write([]byte(`{"id":"apr_1","state":"` + state + `","interval":1,"expiresAt":"2100-01-01T00:00:00.000Z","url":null,"summary":{"title":"t","changes":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	var stderr bytes.Buffer
	r := &Run{IO: IO{Stdout: &bytes.Buffer{}, Stderr: &stderr}, Env: MapEnv{}, Secrets: &Secrets{}, Approval: "apr_1"}
	polling := func() *apiclient.Client { return r.plainClient(srv.URL, "vlt_cli_x") }
	api := apiclient.New(apiclient.Options{Server: srv.URL, Token: "vlt_cli_x", Approval: "apr_1", Ready: r.resumeReady("apr_1", polling)})
	ctx := context.Background()
	if _, err := api.Request(ctx, "GET", "/v1/read", apiclient.NoBody, nil); err != nil || polls.Load() != 0 {
		t.Fatalf("a read waited or failed: %v, %d polls", err, polls.Load())
	}
	if _, err := api.Request(ctx, "POST", "/v1/change", jsjson.Object{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Request(ctx, "POST", "/v1/change", jsjson.Object{}, nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"GET /v1/read ", "GET /v1/me/approvals/apr_1 ", "GET /v1/me/approvals/apr_1 ", "POST /v1/change apr_1", "POST /v1/change apr_1"}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Errorf("requests %q, want %q", seen, want)
	}
	if !strings.Contains(stderr.String(), approvalWaiting) {
		t.Errorf("no waiting line:\n%s", stderr.String())
	}
}

func TestRerunCommand(t *testing.T) {
	if got := rerunCommand([]string{"values", "set", "API KEY"}, "apr_1", true); got != "varlatch --assisted --approval apr_1 values set 'API KEY'" {
		t.Errorf("got %q", got)
	}
	if got := rerunCommand([]string{"--assisted", "org", "freeze"}, "apr_1", true); got != "varlatch --approval apr_1 --assisted org freeze" {
		t.Errorf("--assisted twice: %q", got)
	}
}

// TestSecondCtrlCExitsAtOnce: after a first Ctrl-C the CLI cancels the
// approval (up to cancelBudget); a second Ctrl-C during that cancel exits
// 130 at once, as TypeScript's handler does.
func TestSecondCtrlCExitsAtOnce(t *testing.T) {
	cancelSeen := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/cancel") {
			close(cancelSeen)
			<-release // the cancel hangs
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	defer close(release)
	signals := make(chan os.Signal, 2)
	exited := make(chan int, 2)
	savedInterrupts, savedExit := interrupts, exitNow
	interrupts = func() (<-chan os.Signal, func()) { return signals, func() {} }
	exitNow = func(code int) { exited <- code }
	defer func() { interrupts, exitNow = savedInterrupts, savedExit }()

	r := &Run{IO: IO{Stdout: &bytes.Buffer{}, Stderr: &syncBuffer{}}, Env: MapEnv{}, Secrets: &Secrets{}}
	approval, _ := jsjson.Parse([]byte(`{"id":"apr_1","state":"pending","interval":30,"expiresAt":"2100-01-01T00:00:00.000Z"}`))
	go func() { _, _ = r.waitInterruptibly(r.plainClient(srv.URL, "vlt_cli_x"), approval, nil) }()
	signals <- os.Interrupt
	select {
	case <-cancelSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("the first Ctrl-C did not cancel the approval")
	}
	signals <- os.Interrupt
	select {
	case code := <-exited:
		if code != ExitInterrupted {
			t.Errorf("exited %d, want 130", code)
		}
	case <-time.After(time.Second):
		t.Fatal("the second Ctrl-C did not exit at once")
	}
}
