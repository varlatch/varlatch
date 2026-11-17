// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

// The Coolify adapter's live checks (ADR-0059 step 4.9e), the Go
// replacements of scripts/test-coolify-live.mjs and
// scripts/test-coolify-live-expands.mjs: against the lab Coolify only,
// never in CI (the coolifylive build tag), run by hand:
//
//	cd robotsson-monorepo/scripts && varlatch run -- sh -c '
//	  COOLIFY_LIVE_TOKEN=$COOLIFY_LAB_ROOT_TOKEN \
//	  COOLIFY_LIVE_URL=https://coolify-lab.private.robotsson.be \
//	  COOLIFY_LIVE_SERVER=<the lab server uuid> COOLIFY_LIVE_RUN=<a new dir> \
//	  go test -tags coolifylive -count=1 -v -run <test> ./lib/sync'
//
// TestCoolifyLivePreflight only reads (the instance's version and its
// servers' names and uuids). TestCoolifyLiveServices and
// TestCoolifyLiveExpands (FIXTURE_REF, FIXTURE_SHA) create throwaway
// resources and delete them. COOLIFY_LIVE_CLEANUP=<a run dir> deletes what
// an interrupted run recorded (TestCoolifyLiveCleanup).
//
// The guard: every request refuses unless COOLIFY_LIVE_URL's origin is
// exactly the lab's (labOrigin, normalised), and before any change the
// instance must list the server COOLIFY_LIVE_SERVER exactly once. Every
// name carries the run's prefix (VARLATCH_CANARY_<RUN>_, projects
// varlatch-coolify-…-<run>); every created resource is recorded in
// COOLIFY_LIVE_RUN/ids.env before anything else, and cleanup deletes the
// shared variables first, then the resources, then checks that nothing
// with the prefix is left. Answers are never printed (the token reads
// sensitive values): only statuses and named fields.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// labOrigin is the lab Coolify, normalised (scheme://host:port, lower
// case). The production Coolify (https://coolify.private.robotsson.be) and
// anything else are refused.
const labOrigin = "https://coolify-lab.private.robotsson.be:443"

// normalOrigin is raw's scheme://host:port, lower case, with the default
// port spelled out; "" if raw is not a URL with a host.
func normalOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	host, port := strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port
}

// live is one live run: the lab, its token, the run's prefix and record.
type live struct {
	t      *testing.T
	base   string // COOLIFY_LIVE_URL without a trailing slash
	token  string
	server string // the lab server's uuid
	run    string // the run id, 8 lower-case hex
	dir    string // COOLIFY_LIVE_RUN
	client *http.Client

	mu      sync.Mutex
	created []liveResource
	checks  []string
	failed  int
}

// liveResource is one thing a run created: its kind, the API path that
// deletes it, and how to tell it is gone.
type liveResource struct {
	Kind string `json:"kind"` // project, service, application, shared-team, shared-server, shared-project, shared-environment
	UUID string `json:"uuid"`
	// Delete is the path DELETE is sent to; Gone the path a GET answers
	// 404 on once it is deleted ("" when only a listing shows it).
	Delete, Gone string
}

// newLive checks the environment and the guard, and makes the run's
// record. Without the environment it skips: these checks run by hand only.
func newLive(t *testing.T) *live {
	t.Helper()
	base := strings.TrimRight(os.Getenv("COOLIFY_LIVE_URL"), "/")
	token := os.Getenv("COOLIFY_LIVE_TOKEN")
	if base == "" || token == "" {
		t.Skip("COOLIFY_LIVE_URL and COOLIFY_LIVE_TOKEN are not set: the live checks run by hand against the lab Coolify")
	}
	if got := normalOrigin(base); got != labOrigin {
		t.Fatalf("refused: COOLIFY_LIVE_URL is %q, not the lab Coolify (%s); nothing was sent", got, labOrigin)
	}
	l := &live{t: t, base: base, token: token, server: os.Getenv("COOLIFY_LIVE_SERVER"), dir: os.Getenv("COOLIFY_LIVE_RUN"),
		client: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return l
}

// begin is the guard before any change, then the run's id and record.
func (l *live) begin() {
	l.t.Helper()
	if l.server == "" || l.dir == "" {
		l.t.Fatal("COOLIFY_LIVE_SERVER (the lab server's uuid, from TestCoolifyLivePreflight) and COOLIFY_LIVE_RUN (a new directory) are required before any change")
	}
	l.instance()
	if _, err := os.Stat(filepath.Join(l.dir, "ids.env")); err == nil {
		l.t.Fatalf("%s already holds a run: clean it up (COOLIFY_LIVE_CLEANUP) or use a new directory", l.dir)
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		l.t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		l.t.Fatal(err)
	}
	l.run = hex.EncodeToString(b)
	l.record("RUN", l.run, "", "")
	l.t.Logf("run %s, record %s", l.run, filepath.Join(l.dir, "ids.env"))
}

// instance: this is the lab Coolify, by what its API says: the lab server
// is among its servers, exactly once. Anything else stops before any change.
func (l *live) instance() {
	l.t.Helper()
	var servers []struct{ UUID, Name string }
	if code := l.json("GET", "/servers", nil, &servers); code != 200 {
		l.t.Fatalf("listing the servers: HTTP %d; nothing changed", code)
	}
	n := 0
	for _, s := range servers {
		if s.UUID == l.server {
			n++
		}
	}
	if n != 1 {
		l.t.Fatalf("not the lab Coolify: server %s is listed %d times; nothing changed", l.server, n)
	}
}

// name is a variable name with the run's prefix.
func (l *live) name(n string) string { return "VARLATCH_CANARY_" + strings.ToUpper(l.run) + "_" + n }

// record appends a created resource to the run's ids.env (before anything
// else uses it) and keeps it for cleanup.
func (l *live) record(kind, uuid, del, gone string) {
	l.t.Helper()
	f, err := os.OpenFile(filepath.Join(l.dir, "ids.env"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.t.Fatal(err)
	}
	line, _ := json.Marshal(liveResource{Kind: kind, UUID: uuid, Delete: del, Gone: gone})
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		l.t.Fatal(err)
	}
	if kind != "RUN" {
		l.mu.Lock()
		l.created = append(l.created, liveResource{Kind: kind, UUID: uuid, Delete: del, Gone: gone})
		l.mu.Unlock()
	}
}

// do sends one request to the lab and answers its status and body; a
// transport error fails the test. The body is never printed.
func (l *live) do(method, path string, body any) (int, []byte) {
	l.t.Helper()
	code, b, err := l.send(method, path, body)
	if err != nil {
		l.t.Fatalf("%s %s: %v", method, path, err)
	}
	return code, b
}

// try is do for cleanup: a transport error is logged and answered as
// status 0, so that cleanup goes on with the next resource.
func (l *live) try(method, path string) int {
	code, _, err := l.send(method, path, nil)
	if err != nil {
		l.t.Logf("%s %s: %v", method, path, err)
		return 0
	}
	return code
}

// send is one request to the lab, refused unless the origin is the lab's.
// A transport error may name the URL, never the token.
func (l *live) send(method, path string, body any) (int, []byte, error) {
	if normalOrigin(l.base) != labOrigin {
		return 0, nil, fmt.Errorf("refused: not the lab Coolify")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, l.base+"/api/v1"+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	res, err := l.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	return res.StatusCode, b, nil
}

// json sends a request and decodes its answer into out (when 2xx).
func (l *live) json(method, path string, body, out any) int {
	l.t.Helper()
	code, b := l.do(method, path, body)
	if out != nil && code/100 == 2 {
		_ = json.Unmarshal(b, out)
	}
	return code
}

// check records one check, as the TypeScript scripts print them.
func (l *live) check(name string, ok bool, detail string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := "PASS"
	if !ok {
		status = "FAIL"
		l.failed++
	}
	line := status + " " + name
	if detail != "" {
		line += ": " + detail
	}
	l.checks = append(l.checks, line)
	l.t.Log(line)
}

// req is the adapter's request for a destination.
func (l *live) req(dest Fields, usage *UsageReport) *Request {
	base, err := coolify{}.CanonicalizeBaseIdentity(l.base)
	if err != nil {
		l.t.Fatalf("the lab's base identity: %v", err)
	}
	return &Request{BaseIdentity: base, Destination: dest, Credential: l.token, Client: l.client, Usage: usage}
}

// finish cleans up (shared variables first), checks that nothing with
// the run's prefix is left, and fails the test on any failed check.
func (l *live) finish() {
	l.t.Helper()
	l.cleanup(l.created)
	if l.failed > 0 {
		l.t.Errorf("%d of %d checks failed", l.failed, len(l.checks))
	} else {
		l.t.Logf("%d/%d checks passed", len(l.checks), len(l.checks))
	}
}

// cleanup deletes rs, shared variables first, each until a GET says it is
// gone (or, for a shared variable, until its scope's listing no longer has
// the run's names), then lists every scope for the prefix.
func (l *live) cleanup(rs []liveResource) {
	l.t.Helper()
	order := map[string]int{"shared-team": 0, "shared-server": 1, "shared-environment": 2, "shared-project": 3, "application": 4, "service": 5, "project": 6}
	sorted := append([]liveResource(nil), rs...)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if order[sorted[j].Kind] < order[sorted[i].Kind] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, r := range sorted {
		ok := false
		for i := 0; i < 24 && !ok; i++ {
			code := l.try("DELETE", r.Delete)
			if code == 200 || code == 204 || code == 404 {
				ok = r.Gone == "" || l.gone(r.Gone)
			}
			if !ok {
				time.Sleep(5 * time.Second)
			}
		}
		l.t.Logf("cleanup %s %s: %v", r.Kind, r.UUID, ok)
		if !ok {
			l.t.Errorf("cleanup: %s %s is not gone; its record is in %s", r.Kind, r.UUID, filepath.Join(l.dir, "ids.env"))
		}
	}
	if left := l.leftovers(); len(left) > 0 {
		l.t.Errorf("cleanup: left with the run's prefix: %s", strings.Join(left, ", "))
		return
	}
	if l.run != "" {
		l.record("CLEANED", l.run, "", "")
	}
}

func (l *live) gone(path string) bool { return l.try("GET", path) == 404 }

// leftovers lists what still carries the run's prefix: projects by name,
// shared variables of the team, the server and every project by key.
func (l *live) leftovers() []string {
	if l.run == "" {
		return nil
	}
	var left []string
	read := func(path string, out any) int {
		code, b, err := l.send("GET", path, nil)
		if err != nil {
			return 0
		}
		if code == 200 {
			_ = json.Unmarshal(b, out)
		}
		return code
	}
	var projects []struct{ UUID, Name string }
	if code := read("/projects", &projects); code != 200 {
		return []string{fmt.Sprintf("(projects unreadable: HTTP %d)", code)}
	}
	for _, p := range projects {
		if strings.Contains(p.Name, l.run) {
			left = append(left, "project "+p.Name)
		}
	}
	prefix := l.name("")
	for _, path := range []string{"/team/envs", "/servers/" + l.server + "/envs"} {
		var envs []struct{ Key string }
		if code := read(path, &envs); code != 200 {
			left = append(left, fmt.Sprintf("(%s unreadable: HTTP %d)", path, code))
			continue
		}
		for _, e := range envs {
			if strings.HasPrefix(e.Key, prefix) {
				left = append(left, path+" "+e.Key)
			}
		}
	}
	return left
}

// TestCoolifyLivePreflight only reads: the instance's version and its
// servers' names and uuids (for COOLIFY_LIVE_SERVER). The guard on the
// origin applies; nothing is changed.
func TestCoolifyLivePreflight(t *testing.T) {
	l := newLive(t)
	code, b := l.do("GET", "/version", nil)
	t.Logf("version: HTTP %d %s", code, strings.TrimSpace(string(b)))
	var servers []struct {
		UUID, Name string
		Settings   struct {
			IsReachable bool `json:"is_reachable"`
		}
	}
	if code := l.json("GET", "/servers", nil, &servers); code != 200 {
		t.Fatalf("servers: HTTP %d", code)
	}
	for _, s := range servers {
		t.Logf("server %s %q reachable=%v", s.UUID, s.Name, s.Settings.IsReachable)
	}
}

// TestCoolifyLiveCleanup deletes what the run in COOLIFY_LIVE_CLEANUP
// recorded and did not clean up (an interrupted run).
func TestCoolifyLiveCleanup(t *testing.T) {
	dir := os.Getenv("COOLIFY_LIVE_CLEANUP")
	if dir == "" {
		t.Skip("COOLIFY_LIVE_CLEANUP (a run's directory) is not set")
	}
	l := newLive(t)
	l.dir = dir
	l.instance()
	b, err := os.ReadFile(filepath.Join(dir, "ids.env"))
	if err != nil {
		t.Fatal(err)
	}
	var rs []liveResource
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r liveResource
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		switch r.Kind {
		case "RUN":
			l.run = r.UUID
		case "CLEANED":
			t.Logf("run %s was cleaned up already", r.UUID)
		default:
			rs = append(rs, r)
		}
	}
	l.cleanup(rs)
}

// liveCtx is the checks' context: each call is bounded by the client's
// timeout.
func liveCtx() context.Context { return context.Background() }
