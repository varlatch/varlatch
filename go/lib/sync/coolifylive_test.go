// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

// The Coolify adapter's live checks (ADR-0059 step 4.9e), the Go
// replacements of scripts/test-coolify-live.mjs and
// scripts/test-coolify-live-expands.mjs: against the lab Coolify only,
// never in CI (the coolifylive build tag), run by hand:
//
//	cd robotsson-monorepo/scripts && varlatch run -- sh -c '
//	  COOLIFY_LIVE_URL=https://coolify-lab.private.robotsson.be \
//	  COOLIFY_LIVE_SERVER=<the lab server uuid> COOLIFY_LIVE_RUN=<a new dir> \
//	  go test -tags coolifylive -count=1 -v -run <test> ./lib/sync'
//
// The token is COOLIFY_LAB_ROOT_TOKEN, as varlatch run gives it (the lab's
// root-team token), and no other variable.
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
// name carries the run's id (variables VARLATCH_CANARY_<RUN>_…, projects,
// services and applications …-<run>); every creation is recorded in
// COOLIFY_LIVE_RUN/ids.env before it is sent (and its uuid once known).
// Cleanup does not rely on that record: it lists every scope (projects,
// services, applications, the team's, the server's and each run project's
// and environment's shared variables) for the run's id, deletes what it
// finds (shared variables first), and records CLEANED only once every
// listing was read and none holds the run's id. Answers are never printed
// (the token reads sensitive values): only statuses and named fields.

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
	"regexp"
	"strconv"
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
	token := os.Getenv("COOLIFY_LAB_ROOT_TOKEN")
	if base == "" || token == "" {
		t.Skip("COOLIFY_LIVE_URL and COOLIFY_LAB_ROOT_TOKEN (from varlatch run) are not set: the live checks run by hand against the lab Coolify")
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

// intend appends what is about to be created to the run's ids.env, before
// the request that creates it: its kind, its name (with the run's id) and
// where it is created.
func (l *live) intend(kind, name, where string) {
	l.t.Helper()
	l.appendRecord(map[string]string{"intent": kind, "name": name, "where": where})
}

func (l *live) appendRecord(v any) {
	l.t.Helper()
	f, err := os.OpenFile(filepath.Join(l.dir, "ids.env"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.t.Fatal(err)
	}
	line, _ := json.Marshal(v)
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		l.t.Fatal(err)
	}
}

// record appends a created resource to the run's ids.env (before anything
// else uses it) and keeps it for cleanup's first round.
func (l *live) record(kind, uuid, del, gone string) {
	l.t.Helper()
	l.appendRecord(liveResource{Kind: kind, UUID: uuid, Delete: del, Gone: gone})
	if kind != "RUN" && kind != "CLEANED" {
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

// finish cleans up and fails the test on any failed check (after the
// cleanup, which runs first whatever happened).
func (l *live) finish() {
	l.t.Helper()
	l.cleanup()
	if l.failed > 0 {
		l.t.Errorf("%d of %d checks failed", l.failed, len(l.checks))
	} else {
		l.t.Logf("%d/%d checks passed", len(l.checks), len(l.checks))
	}
}

// found is something the run left: its kind, a label (a name with the
// run's id, or a uuid; never a value) and the path that deletes it.
type found struct{ kind, label, del string }

// survey lists every scope for what carries the run's id: projects,
// services and applications by name; the team's, the server's and each
// run project's and its environment's shared variables by key. complete
// is false when a listing could not be read or decoded, or an item has no
// id to delete it by: then nothing is confirmed.
func (l *live) survey() (left []found, complete bool) {
	complete = true
	list := func(path string) ([]map[string]any, bool) {
		code, b, err := l.send("GET", path, nil)
		if err != nil || code != 200 {
			return nil, false
		}
		return decodeListing(b)
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	idOf := func(m map[string]any) string {
		switch v := m["id"].(type) {
		case float64:
			return strconv.FormatInt(int64(v), 10)
		case string:
			if v != "" {
				return v
			}
		}
		return str(m, "uuid")
	}
	prefix := l.name("")
	shared := func(scope, path string) {
		rows, ok := list(path)
		if !ok {
			complete = false
			return
		}
		for _, r := range rows {
			if key := str(r, "key"); strings.HasPrefix(key, prefix) {
				if id := idOf(r); id != "" {
					left = append(left, found{"shared-" + scope, key, path + "/" + id})
				} else {
					complete = false
				}
			}
		}
	}
	shared("team", "/team/envs")
	shared("server", "/servers/"+l.server+"/envs")
	projects, ok := list("/projects")
	if !ok {
		complete = false
	}
	var runProjects []string
	for _, p := range projects {
		if strings.Contains(str(p, "name"), l.run) {
			if uuid := str(p, "uuid"); uuid != "" {
				runProjects = append(runProjects, uuid)
			} else {
				complete = false
			}
		}
	}
	for _, uuid := range runProjects {
		shared("project", "/projects/"+uuid+"/envs")
		shared("environment", "/projects/"+uuid+"/environments/production/envs")
	}
	for _, kind := range []string{"application", "service"} {
		rows, ok := list("/" + kind + "s")
		if !ok {
			complete = false
			continue
		}
		for _, r := range rows {
			if name := str(r, "name"); strings.Contains(name, l.run) {
				if uuid := str(r, "uuid"); uuid != "" {
					left = append(left, found{kind, name, "/" + kind + "s/" + uuid + "?delete_configurations=true&delete_volumes=true&docker_cleanup=true&delete_connected_networks=true"})
				} else {
					complete = false
				}
			}
		}
	}
	for _, uuid := range runProjects {
		left = append(left, found{"project", uuid, "/projects/" + uuid})
	}
	return left, complete
}

// decodeListing is a listing's rows, and whether the answer was a JSON
// array: null, an object or anything else is not a listing, and confirms
// nothing (null decodes to a nil slice, an empty array to an empty one).
func decodeListing(b []byte) ([]map[string]any, bool) {
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil || rows == nil {
		return nil, false
	}
	return rows, true
}

// cleanup deletes what the run left, recorded or not: first the shared
// variables it recorded, then whatever the survey finds, shared variables
// first, round after round (two minutes at most), until every listing is
// read and none holds the run's id; only then is CLEANED recorded.
// Otherwise the test fails naming what is left, and TestCoolifyLiveCleanup
// can finish it.
func (l *live) cleanup() {
	l.t.Helper()
	if l.run == "" {
		return
	}
	for _, r := range l.created {
		if strings.HasPrefix(r.Kind, "shared-") {
			l.t.Logf("cleanup %s %s: HTTP %d", r.Kind, r.UUID, l.try("DELETE", r.Delete))
		}
	}
	var left []found
	complete := false
	for round := 0; round < 24; round++ {
		if left, complete = l.survey(); complete && len(left) == 0 {
			l.record("CLEANED", l.run, "", "")
			l.t.Logf("cleanup: every scope listed, nothing with run %s left", l.run)
			return
		}
		for _, f := range left {
			l.t.Logf("cleanup %s %s: HTTP %d", f.kind, f.label, l.try("DELETE", f.del))
		}
		time.Sleep(5 * time.Second)
	}
	var labels []string
	for _, f := range left {
		labels = append(labels, f.kind+" "+f.label)
	}
	if !complete {
		labels = append(labels, "(a listing could not be read: nothing is confirmed)")
	}
	l.t.Errorf("cleanup not confirmed for run %s (record %s): %s", l.run, filepath.Join(l.dir, "ids.env"), strings.Join(labels, ", "))
}

// version is the instance's version, if its answer is one (a version
// string, quoted or not); nothing else of the answer is shown.
func (l *live) version() string {
	code, b := l.do("GET", "/version", nil)
	v := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if code != 200 || !versionText.MatchString(v) {
		return fmt.Sprintf("(HTTP %d, not a version)", code)
	}
	return v
}

var versionText = regexp.MustCompile(`^v?[0-9]+([.][0-9]+){1,3}([-.][A-Za-z0-9.]+)?$`)

// TestCoolifyLivePreflight only reads: the instance's version and its
// servers' names and uuids (for COOLIFY_LIVE_SERVER). The guard on the
// origin applies; nothing is changed.
func TestCoolifyLivePreflight(t *testing.T) {
	l := newLive(t)
	t.Logf("version: %s", l.version())
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

// TestCoolifyLiveCleanup finishes the cleanup of the run in
// COOLIFY_LIVE_CLEANUP (a run's directory: its ids.env names the run's id),
// by the same survey: everything with the run's id, recorded or not.
func TestCoolifyLiveCleanup(t *testing.T) {
	dir := os.Getenv("COOLIFY_LIVE_CLEANUP")
	if dir == "" {
		t.Skip("COOLIFY_LIVE_CLEANUP (a run's directory) is not set")
	}
	l := newLive(t)
	l.dir = dir
	if l.server == "" {
		t.Fatal("COOLIFY_LIVE_SERVER is required")
	}
	l.instance()
	b, err := os.ReadFile(filepath.Join(dir, "ids.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r liveResource
		if json.Unmarshal([]byte(line), &r) == nil && r.Kind == "RUN" {
			l.run = r.UUID
		}
	}
	if l.run == "" {
		t.Fatal("ids.env names no run")
	}
	l.cleanup()
}

// liveCtx is the checks' context: each call is bounded by the client's
// timeout.
func liveCtx() context.Context { return context.Background() }
