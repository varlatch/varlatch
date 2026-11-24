// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// migrated is an installation the seeded migration made: the seed's bundle
// imported, the journal open.
func migrated(t *testing.T) (install, migrationtest.Source) {
	t.Helper()
	s := migrationtest.Load(t)
	path := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(path, migrationtest.Bundle(t, s, migrationtest.Options{}), 0o600); err != nil {
		t.Fatal(err)
	}
	// sync = off: the seed's Sync Targets (the TypeScript server's test
	// fixtures) name hosts no test reaches, so a sync pass in flight can
	// outlast a barrier's 5 s drain, and the barrier then stays, as it
	// must (not a fault of the server: of the fixture).
	in := newInstall(t, "backup_interval = off\nsync = off\n")
	if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(s.RootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "migrate", "import", "--in", path, "--config", in.conf); code != ExitOK {
		t.Fatalf("import: %q", errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "open"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	return in, s
}

func lastEvent(t *testing.T, conf string) int64 {
	t.Helper()
	cfg, err := config.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openReadOnly(cfg)
	if err != nil || db == nil {
		t.Fatalf("the database: %v", err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow("SELECT coalesce(max(event_order), 0) FROM audit_events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func httpStatus(t *testing.T, r *running, method, path string) int {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+r.addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}

// decide is the TypeScript evaluator's decision table at its export of
// the rebuilt installation, stood in for: the rebuild's rows imported into
// a scratch directory (beside the running varlatchd), and its tuples
// evaluated there.
func decide(t *testing.T, conf string, rebuilt migrationtest.Source) []bundle.Decision {
	t.Helper()
	plain := filepath.Join(t.TempDir(), "rows.jsonl")
	if err := os.WriteFile(plain, migrationtest.Bundle(t, rebuilt, migrationtest.Options{}), 0o600); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(t.TempDir(), "scratch")
	if code, _, errOut := migrateWith(t, conf, nil, "import", "--in", plain, "--scratch", scratch); code != ExitOK {
		t.Fatalf("a scratch import beside varlatchd: %q", errOut)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(scratch, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []bundle.Decision
	for _, d := range migrationtest.Tuples(t, db, 8) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got)
	}
	if len(out) == 0 {
		t.Fatal("no decision")
	}
	return out
}

// tableSections is a bundle's table sections: its lines from the first
// table's to the digest section's.
func tableSections(t *testing.T, b []byte) []byte {
	t.Helper()
	start := bytes.IndexByte(b, '\n') + 1
	end := bytes.Index(b, []byte("\n{\"digests\":"))
	if start <= 0 || end < start {
		t.Fatal("not a bundle")
	}
	return b[start : end+1]
}

// liveUpdates is one /auth/events stream of a browser's session.
type liveUpdates struct {
	res   *http.Response
	lines *bufio.Scanner
}

func (b *browser) liveUpdates(t *testing.T) (*liveUpdates, int, string) {
	t.Helper()
	c := *b.c
	c.Timeout = 0
	res, err := c.Get(b.origin + "/auth/events")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, res.StatusCode, res.Header.Get("Retry-After") + " " + string(raw)
	}
	t.Cleanup(func() { res.Body.Close() })
	return &liveUpdates{res: res, lines: bufio.NewScanner(res.Body)}, res.StatusCode, ""
}

// next is the stream's next event and its data; "" at its end.
func (l *liveUpdates) next() (event, data string) {
	for l.lines.Scan() {
		switch line := l.lines.Text(); {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			return event, strings.TrimPrefix(line, "data: ")
		}
	}
	return "", ""
}

// A dashboard's live updates are a request admitted before the barrier, which
// never ends by itself: the barrier ends every open one, with what the server
// sends as it stops, and drains at once. One asked for behind it is refused as
// maintenance, not as signed out; after the release the same session opens it
// again. Dashboards that reconnect all the while, as they do, open none that
// holds the barrier.
func TestTheBarrierEndsOpenDashboards(t *testing.T) {
	in, _ := migrated(t)
	const origin = "http://localhost:18999"
	f, err := os.OpenFile(in.conf, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("public_url = " + origin + "\n")
	if cerr := f.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	r := start(t, in)
	jar, _ := cookiejar.New(nil)
	b := &browser{origin: origin, c: &http.Client{Jar: jar, Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, r.addr)
		}}}}
	code, out, errOut := runAdmin(t, "bootstrap-status", "--config", in.conf)
	var st struct {
		Admins []struct {
			ID      string
			Enabled bool
		}
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil || len(st.Admins) == 0 {
		t.Fatalf("bootstrap-status: %d %q %q", code, out, errOut)
	}
	admin := st.Admins[slices.IndexFunc(st.Admins, func(a struct {
		ID      string
		Enabled bool
	}) bool {
		return a.Enabled
	})].ID
	code, out, errOut = runAdmin(t, "recover", "--identity", admin, "--config", in.conf)
	m := enrollToken.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("recover: %d %q %q", code, out, errOut)
	}
	b.enroll(t, m[1], authtest.New(t))

	var open []*liveUpdates
	for range 3 {
		l, status, body := b.liveUpdates(t)
		if l == nil {
			t.Fatalf("the live updates: %d %s", status, body)
		}
		if event, _ := l.next(); event != "ready" {
			t.Fatalf("the stream's first event: %q", event)
		}
		open = append(open, l)
	}
	// Dashboards that reconnect at once, whatever they are answered.
	stop, done := make(chan struct{}), make(chan int)
	go func() {
		n := 0
		defer func() { done <- n }()
		c := *b.c
		c.Timeout = 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			res, err := c.Get(origin + "/auth/events")
			if err != nil {
				continue
			}
			n++
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	}()

	began := time.Now()
	code, out, errOut = runAdmin(t, "migrate", "barrier", "--id", migA, "--drain-seconds", "5", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"phase":"paused"`) {
		t.Fatalf("the barrier with dashboards open: %d %q %q", code, out, errOut)
	}
	if took := time.Since(began); took > 4*time.Second {
		t.Errorf("the barrier took %s", took)
	}
	for i, l := range open {
		var event, data string
		for event != "close" {
			if event, data = l.next(); event == "" {
				break
			}
		}
		if event != "close" || data != `{"reason":"shutdown"}` {
			t.Errorf("stream %d ended with %q %q", i, event, data)
		}
		if event, _ := l.next(); event != "" {
			t.Errorf("stream %d goes on: %q", i, event)
		}
	}
	if l, status, body := b.liveUpdates(t); l != nil || status != http.StatusServiceUnavailable || !strings.HasPrefix(body, "5 ") || !strings.Contains(body, `"code":"MAINTENANCE"`) {
		t.Errorf("the live updates behind the barrier: %d %s", status, body)
	}
	close(stop)
	if n := <-done; n == 0 {
		t.Error("no dashboard reconnected")
	}

	if code, _, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatalf("the release: %q", errOut)
	}
	l, status, body := b.liveUpdates(t)
	if l == nil {
		t.Fatalf("the live updates after the release: %d %s", status, body)
	}
	if event, _ := l.next(); event != "ready" {
		t.Errorf("after the release the stream's first event is %q", event)
	}
	// A barrier again: the streams of the second time end too.
	if code, out, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--drain-seconds", "5", "--config", in.conf); code != ExitOK {
		t.Fatalf("the barrier a second time: %d %q %q", code, out, errOut)
	}
	if event, _ := l.next(); event != "close" {
		t.Errorf("the second time: %q", event)
	}
	if code, _, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatalf("the second release: %q", errOut)
	}
}

// The reverse's varlatchd half, beside a running varlatchd (slice 7.6a):
//   - the barrier, through the control socket: isolated at once (GET
//     /v1/meta only), drained, the frozen copy made at the frozen point,
//     the gate paused; again, the same answer; another migration's, or one
//     of a migration not open, refused;
//   - the reverse export beside it, from the frozen copy, the transformed
//     copy kept; the live database untouched;
//   - the stand-in TypeScript import loads the reverse bundle verbatim, and
//     its export of the rebuilt database (its digests under the run key,
//     its evaluator's decisions) passes the reverse checks against the
//     kept copy, beside the running varlatchd; a rebuild that lost a row,
//     or whose plaintext differs, fails them; the forward checks do not
//     take the reverse's state;
//   - a restart stays behind the barrier; the release reopens varlatchd and
//     removes the frozen copy; without a barrier the export beside a
//     running varlatchd is refused, as before.
func TestTheReverseBarrier(t *testing.T) {
	in, s := migrated(t)
	r := start(t, in)
	if httpStatus(t, r, "GET", "/v1/whoami") == http.StatusServiceUnavailable {
		t.Fatal("isolated before the barrier")
	}
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migB, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not "+migB) {
		t.Fatalf("another migration's barrier: %d %q", code, errOut)
	}
	if g, _ := backup.ReadGate(in.data); g != nil {
		t.Fatalf("a refused barrier left a gate: %+v", g)
	}
	code, out, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--drain-seconds", "5", "--config", in.conf)
	var rec barrierRecord
	if code != ExitOK || json.Unmarshal([]byte(out), &rec) != nil {
		t.Fatalf("the barrier: %d %q %q", code, out, errOut)
	}
	// Behind the barrier the database stays where it froze (varlatchd's
	// own background passes wrote events before it).
	before := lastEvent(t, in.conf)
	time.Sleep(300 * time.Millisecond)
	if lastEvent(t, in.conf) != before {
		t.Fatal("the database moved behind the barrier")
	}
	if rec.Gate.ID != migA || rec.Gate.Kind != "migration" || rec.Gate.Phase != "paused" || rec.Frozen.AuditPosition != strconv.FormatInt(before, 10) || rec.Frozen.Copy != FrozenCopyName(migA) {
		t.Fatalf("the barrier's record: %+v (last event %d)", rec, before)
	}
	frozen := filepath.Join(in.data, FrozenCopyName(migA))
	if st, err := os.Stat(frozen); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the frozen copy: %v %v", st, err)
	}
	for _, sfx := range []string{"-wal", "-shm", ".partial", ".partial-wal", ".partial-shm", ".partial-journal"} {
		if _, err := os.Stat(frozen + sfx); !os.IsNotExist(err) {
			t.Errorf("%s beside the frozen copy: %v", sfx, err)
		}
	}
	if g, err := backup.ReadGate(in.data); err != nil || g == nil || g.Phase != "paused" || g.FrozenPosition == nil || *g.FrozenPosition != rec.Frozen.AuditPosition {
		t.Fatalf("the gate: %+v %v", g, err)
	}
	if c := httpStatus(t, r, "GET", "/v1/meta"); c != http.StatusOK {
		t.Errorf("/v1/meta behind the barrier: %d", c)
	}
	for _, p := range []string{"/v1/whoami", "/v1/orgs", "/readyz"} {
		if c := httpStatus(t, r, "GET", p); c != http.StatusServiceUnavailable {
			t.Errorf("%s behind the barrier: %d", p, c)
		}
	}
	if c := httpStatus(t, r, "POST", "/v1/meta"); c != http.StatusServiceUnavailable && c != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/meta behind the barrier: %d", c)
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"migrationGate":false`) || !strings.Contains(out, `"barrier":"paused"`) || !strings.Contains(out, `"running":true`) {
		t.Errorf("the state behind the barrier: %q", out)
	}
	if code, _, errOut := runAdmin(t, "maintenance", "begin", "--ttl", "1m", "--config", in.conf); code == ExitOK {
		t.Fatalf("a lease behind the barrier: %q", errOut)
	}
	again, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf)
	if again != ExitOK {
		t.Fatalf("the barrier again: %q", errOut)
	}

	// The export beside it, the transformed copy kept.
	keep := filepath.Join(t.TempDir(), "keep")
	revPath := filepath.Join(t.TempDir(), "reverse.jsonl")
	entries := func() []string {
		var names []string
		des, _ := os.ReadDir(in.data)
		for _, d := range des {
			names = append(names, d.Name())
		}
		return names
	}
	was := entries()
	code, out, errOut = runAdmin(t, "migrate", "export", "--reverse", "--out", revPath, "--keep", keep, "--json", "--config", in.conf)
	var res struct {
		Tables           int   `json:"tables"`
		MigratedPosition int64 `json:"migratedPosition"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil || res.Tables == 0 || res.MigratedPosition != before+1 {
		t.Fatalf("the export beside the barrier: %d %q %q", code, out, errOut)
	}
	if now := entries(); strings.Join(now, ",") != strings.Join(was, ",") {
		t.Errorf("the export changed the data directory: %v, was %v", now, was)
	}
	if lastEvent(t, in.conf) != before {
		t.Error("the export changed the database")
	}
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", filepath.Join(t.TempDir(), "r.jsonl"), "--keep", keep, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not empty") {
		t.Errorf("a second export into the kept copy's directory: %d %q", code, errOut)
	}
	rev, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatal(err)
	}

	// The stand-in TypeScript import, and its export of what it rebuilt.
	rebuilt := migrationtest.FromReverse(t, rev, s.RootKEK)
	if got, want := tableSections(t, migrationtest.Bundle(t, rebuilt, migrationtest.Options{})), tableSections(t, rev); !bytes.Equal(got, want) {
		t.Fatal("the rebuilt installation's rows are not the reverse bundle's")
	}
	runKey := make([]byte, 32)
	_, _ = rand.Read(runKey)
	keyText := []byte(hex.EncodeToString(runKey) + "\n")
	decisions := decide(t, in.conf, rebuilt)
	reexport := func(src migrationtest.Source) string {
		p := filepath.Join(t.TempDir(), "rebuilt.jsonl")
		b := migrationtest.Bundle(t, src, migrationtest.Options{Sections: &migrationtest.Sections{
			Digests: migrationtest.Digests(t, src, runKey), Decisions: decisions, At: time.Now().UnixMicro()}})
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	f2 := reexport(rebuilt)
	code, out, errOut = migrateWith(t, in.conf, keyText, "check", "--reverse", "--in", f2, "--scratch", keep)
	if code != ExitOK || !strings.Contains(out, "The reverse checks passed") {
		t.Fatalf("the reverse checks: %d\n%s%s", code, out, errOut)
	}
	for _, sec := range s.Secrets {
		if len(sec) >= 8 && (strings.Contains(out+errOut, string(sec)) || strings.Contains(out+errOut, hex.EncodeToString(sec))) {
			t.Fatal("the report holds a secret")
		}
	}
	// The forward checks do not take the reverse's state.
	if code, out, _ := migrateWith(t, in.conf, keyText, "check", "--in", f2, "--scratch", keep); code != ExitFailure || !strings.Contains(out, "audit: FAILED") {
		t.Errorf("the forward checks of the kept copy: %d\n%s", code, out)
	}
	// A rebuild that lost a row, or holds another plaintext, fails.
	lost := rebuilt
	for _, table := range []string{"webhooks", "grants"} {
		if len(rebuilt.Rows[table]) == 0 {
			t.Fatalf("the seed holds no %s", table)
		}
		lost.Rows = maps.Clone(rebuilt.Rows)
		lost.Rows[table] = rebuilt.Rows[table][1:]
		if code, out, _ := migrateWith(t, in.conf, keyText, "check", "--reverse", "--in", reexport(lost), "--scratch", keep); code != ExitFailure || !strings.Contains(out, "rows: FAILED") {
			t.Errorf("a rebuild missing one of its %s: %d\n%s", table, code, out)
		}
	}
	other := filepath.Join(t.TempDir(), "other.jsonl")
	// Another run key: its first byte flipped, never the same key (a key
	// whose first byte is already 1 would be with {1} put in its place).
	otherKey := append([]byte{runKey[0] ^ 0xff}, runKey[1:]...)
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{
		Digests: migrationtest.Digests(t, rebuilt, otherKey), Decisions: decisions, At: 1}})
	if err := os.WriteFile(other, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := migrateWith(t, in.conf, keyText, "check", "--reverse", "--in", other, "--scratch", keep); code != ExitFailure || !strings.Contains(out, "encryption-classes: FAILED") {
		t.Errorf("a rebuild whose digests differ: %d\n%s", code, out)
	}

	// A restart stays behind the barrier.
	r.stop(t)
	r = start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c != http.StatusServiceUnavailable {
		t.Fatalf("after a restart behind the barrier: %d", c)
	}
	if c := httpStatus(t, r, "GET", "/v1/meta"); c != http.StatusOK {
		t.Fatalf("/v1/meta after a restart behind the barrier: %d", c)
	}
	// The release: another migration's refused; then varlatchd serves.
	if code, _, _ := runAdmin(t, "migrate", "release", "--id", migB, "--config", in.conf); code != ExitFailure {
		t.Fatal("another migration released the barrier")
	}
	if code, out, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf); code != ExitOK || !strings.Contains(out, `"released":true`) {
		t.Fatalf("the release: %d %q %q", code, out, errOut)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Fatal("isolated after the release")
	}
	if _, err := os.Stat(frozen); !os.IsNotExist(err) {
		t.Fatalf("the frozen copy after the release: %v", err)
	}
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", filepath.Join(t.TempDir(), "r2.jsonl"), "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "frozen copy its migration barrier makes") {
		t.Fatalf("an export beside varlatchd without a barrier: %d %q", code, errOut)
	}
	r.stop(t)
}

// The barrier offline, on a stopped varlatchd's data directory: made the
// same (varlatchd then starts behind it), released the same. A barrier of
// a migration not open, or without one, is refused.
func TestTheReverseBarrierOffline(t *testing.T) {
	in, _ := migrated(t)
	before := lastEvent(t, in.conf)
	code, out, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf)
	var rec barrierRecord
	if code != ExitOK || json.Unmarshal([]byte(out), &rec) != nil || rec.Gate.Phase != "paused" || rec.Frozen.AuditPosition != strconv.FormatInt(before, 10) {
		t.Fatalf("the offline barrier: %d %q %q", code, out, errOut)
	}
	r := start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c != http.StatusServiceUnavailable {
		t.Fatalf("started behind the offline barrier: %d", c)
	}
	r.stop(t)
	if code, _, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatalf("the offline release: %q", errOut)
	}
	if g, err := backup.ReadGate(in.data); g != nil || err != nil {
		t.Fatalf("the gate after the offline release: %+v %v", g, err)
	}
	// Not open: refused.
	for _, phase := range []string{"switched"} {
		in2 := newInstall(t, "backup_interval = off\n")
		for _, p := range []string{"started", "transfer", phase} {
			if code, _, errOut := migrateWith(t, in2.conf, journalText(migA, p), "state", "--write"); code != ExitOK {
				t.Fatal(errOut)
			}
		}
		if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in2.conf); code != ExitFailure || !strings.Contains(errOut, "in phase "+phase) {
			t.Errorf("a barrier in phase %s: %d %q", phase, code, errOut)
		}
	}
	// No migration: refused.
	in3 := newInstall(t, "backup_interval = off\n")
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in3.conf); code != ExitFailure || !strings.Contains(errOut, "holds no migration") {
		t.Errorf("a barrier without a migration: %d %q", code, errOut)
	}
	// Usage.
	for _, args := range [][]string{{"migrate", "barrier"}, {"migrate", "barrier", "--id", migA, "--drain-seconds", "0"}, {"migrate", "barrier", "--id", migA, "--drain-seconds", "3601"},
		{"migrate", "release"}, {"migrate", "release", "--id", migA, "--json"}, {"migrate", "check", "--in", "x", "--reverse"}, {"migrate", "export", "--reverse", "--out", "x", "--keep", "rel"}} {
		if code, _, _ := runAdmin(t, append(args, "--config", in.conf)...); code != 64 {
			t.Errorf("%q: %d, want 64", args, code)
		}
	}
}

// A drain that does not end: what was admitted still runs past the drain;
// the barrier fails and stays (draining), the export refuses a draining
// barrier, and the barrier again, once that work ended, freezes.
func TestABarrierThatDoesNotDrain(t *testing.T) {
	in, _ := migrated(t)
	cfg, err := config.Load(in.conf)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: cfg.DatabasePath()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	env := &hostEnv{cfg: cfg, store: store, admission: maintenance.Open(cfg.DataDir, nil), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	leave, ok := env.admission.Enter()
	if !ok {
		t.Fatal("not admitted")
	}
	var out, errOut bytes.Buffer
	if code := runMigrateBarrier(context.Background(), env, []string{"barrier", "--id", migA, "--drain-seconds", "1"}, &out, &errOut); code != ExitFailure || !strings.Contains(errOut.String(), "still ran after 1s") {
		t.Fatalf("an undrained barrier: %d %q", code, errOut.String())
	}
	if g, err := backup.ReadGate(in.data); err != nil || g == nil || g.Phase != "draining" {
		t.Fatalf("the gate: %+v %v", g, err)
	}
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", filepath.Join(t.TempDir(), "r.jsonl"), "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "still draining") {
		t.Fatalf("an export behind a draining barrier: %d %q", code, errOut)
	}
	leave()
	out.Reset()
	errOut.Reset()
	if code := runMigrateBarrier(context.Background(), env, []string{"barrier", "--id", migA, "--drain-seconds", "1"}, &out, &errOut); code != ExitOK || !strings.Contains(out.String(), `"phase":"paused"`) {
		t.Fatalf("the barrier again: %d %q %q", code, out.String(), errOut.String())
	}
}

// The reverse's journal (go-step7 decision 16, slice 7.6a), written by
// varlatch migrate in the data directory as in the source's directory:
//   - beside the running varlatchd: from open into the reverse's phases,
//     on through them, and back to open (the reverse undone), each the
//     journal's word alone; going back within them, released, or rolled
//     back (which keeps varlatchd from starting) are not;
//   - at start: reversing, varlatchd serves (isolated by the barrier once
//     it stands); past the export it starts behind its barrier only;
//     rolled back, never.
func TestTheReverseJournal(t *testing.T) {
	in, _ := migrated(t)
	r := start(t, in)
	write := func(phase string) (int, string) {
		code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write")
		return code, errOut
	}
	if code, errOut := write("rollback"); code != ExitOK {
		t.Fatalf("rollback beside the running varlatchd: %q", errOut)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Fatal("isolated before the barrier")
	}
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatalf("the barrier in phase rollback: %q", errOut)
	}
	for _, phase := range []string{"rollback-exported", "rollback-imported", "rollback-checked", "rollback-transfer"} {
		if code, errOut := write(phase); code != ExitOK {
			t.Fatalf("%s beside the running varlatchd: %q", phase, errOut)
		}
	}
	for _, phase := range []string{"rollback-exported", "released", "switched", "rolled-back"} {
		if code, errOut := write(phase); code != ExitFailure {
			t.Errorf("%s beside the running varlatchd, from rollback-transfer: %d %q", phase, code, errOut)
		}
	}
	if code, out, _ := migrateWith(t, in.conf, journalText(migB, "rollback"), "state", "--write"); code != ExitFailure {
		t.Errorf("another migration's reverse: %q", out)
	}
	// Undone: back to open, beside it; the barrier is released after.
	if code, errOut := write("open"); code != ExitOK {
		t.Fatalf("the reverse undone beside the running varlatchd: %q", errOut)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c != http.StatusServiceUnavailable {
		t.Fatalf("the barrier lifted by a journal write: %d", c)
	}
	if code, _, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatal(errOut)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Fatal("isolated after the release")
	}
	r.stop(t)

	// At start.
	starts := func() (bool, string) {
		var errOut syncBuffer
		sig := make(chan os.Signal, 1)
		done := make(chan int, 1)
		ready := make(chan struct{}, 1)
		go func() {
			done <- Serve(Options{ConfigPath: in.conf, Stderr: &errOut, Signals: sig, Ready: func(net.Addr) { ready <- struct{}{} }})
		}()
		select {
		case <-ready:
			sig <- syscall.SIGTERM
			<-done
			return true, ""
		case code := <-done:
			_ = code
			return false, errOut.String()
		case <-time.After(30 * time.Second):
			t.Fatal("varlatchd neither started nor refused")
		}
		return false, ""
	}
	if code, errOut := write("rollback"); code != ExitOK {
		t.Fatal(errOut)
	}
	if ok, why := starts(); !ok {
		t.Errorf("reversing, before the barrier: refused (%s)", why)
	}
	if code, errOut := write("rollback-exported"); code != ExitOK {
		t.Fatal(errOut)
	}
	if ok, why := starts(); ok || !strings.Contains(why, "holds no barrier of it") {
		t.Errorf("past the export without the barrier: %v %q", ok, why)
	}
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatal(errOut)
	}
	r = start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c != http.StatusServiceUnavailable {
		t.Errorf("past the export, behind the barrier: %d", c)
	}
	r.stop(t)
	for _, phase := range []string{"rollback-transfer", "rolled-back"} {
		if code, errOut := write(phase); code != ExitOK {
			t.Fatalf("%s, stopped: %q", phase, errOut)
		}
	}
	if ok, why := starts(); ok || !strings.Contains(why, "was reversed") {
		t.Errorf("rolled back: %v %q", ok, why)
	}
	for _, phase := range []string{"open", "rollback", "released"} {
		if code, errOut := write(phase); code != ExitFailure {
			t.Errorf("%s after rolled back: %d %q", phase, code, errOut)
		}
	}
}

// Two barrier commands at once, through the running varlatchd: one at a
// time makes the frozen copy (they never share its temporary name); both
// answer paused at the same frozen point, nothing left beside the copy; a
// release beside a barrier waits for it.
func TestConcurrentBarriers(t *testing.T) {
	in, _ := migrated(t)
	r := start(t, in)
	defer r.stop(t)
	type answer struct {
		code     int
		out, err string
	}
	answers := make(chan answer, 2)
	for range 2 {
		go func() {
			code, out, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--drain-seconds", "5", "--config", in.conf)
			answers <- answer{code, out, errOut}
		}()
	}
	var positions []string
	for range 2 {
		a := <-answers
		var rec barrierRecord
		if a.code != ExitOK || json.Unmarshal([]byte(a.out), &rec) != nil || rec.Gate.Phase != "paused" {
			t.Fatalf("a concurrent barrier: %d %q %q", a.code, a.out, a.err)
		}
		positions = append(positions, rec.Frozen.AuditPosition)
	}
	if positions[0] != positions[1] {
		t.Errorf("two frozen points: %v", positions)
	}
	frozen := filepath.Join(in.data, FrozenCopyName(migA))
	for _, sfx := range []string{".partial", ".partial-wal", ".partial-shm", ".partial-journal", "-wal", "-shm"} {
		if _, err := os.Stat(frozen + sfx); !os.IsNotExist(err) {
			t.Errorf("%s beside the frozen copy: %v", sfx, err)
		}
	}
	if pos, _, err := frozenOf(frozen); err != nil || strconv.FormatInt(pos, 10) != positions[0] {
		t.Errorf("the frozen copy: %d %v, want %s", pos, err, positions[0])
	}
	done := make(chan answer, 2)
	go func() {
		code, out, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf)
		done <- answer{code, out, errOut}
	}()
	go func() {
		code, out, errOut := runAdmin(t, "migrate", "release", "--id", migA, "--config", in.conf)
		done <- answer{code, out, errOut}
	}()
	for range 2 {
		if a := <-done; a.code != ExitOK {
			t.Fatalf("a barrier beside a release: %d %q %q", a.code, a.out, a.err)
		}
	}
	// Whichever came last decided: a barrier paused with its copy, or none
	// and no copy; never a gate without its copy.
	g, err := backup.ReadGate(in.data)
	_, cerr := os.Stat(frozen)
	if err != nil || (g == nil) != os.IsNotExist(cerr) {
		t.Fatalf("after a barrier beside a release: gate %+v %v, copy %v", g, err, cerr)
	}
}
