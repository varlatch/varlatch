// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// G5's reverse half (internal docs/design/go-step7.md §7.6, slice 7.6a,
// decision 16), through the binary, with the TypeScript side's stand-in
// (migrationtest.FromReverse: the last TypeScript release's `admin
// migration import` loading the reverse bundle verbatim, and its export of
// what it rebuilt, its digests under the run key and its evaluator's
// decisions; the release job of 7.6b runs the published image instead):
//
//   - Go's barrier freezes the installation; the reverse export reads the
//     frozen copy and keeps the transformed one;
//   - the rebuilt installation's rows are the reverse bundle's, byte for
//     byte, and the reverse checks pass against the kept copy: every row,
//     every encrypted item's plaintext (the TypeScript side's digests), the
//     audit log and its cursors, every decision of the TypeScript
//     evaluator's table, the authentication state;
//   - nothing is lost: a second forward migration, from the rebuilt
//     installation, passes the forward checks, and reproduces the state:
//     its reverse bundle is the first one's, but for the two
//     installation.migrated events the round trip appended;
//   - a credential revoked, or a browser session ended, stays so in either
//     direction: revoked at the same moment, never live again.

const migR = "mig_rrrrrrrrrrrrrrrrrrrrrrrrrr"

// journalOpen writes in's journal: the migration migR, open.
func (g *gate) journalOpen(t *testing.T, conf string) {
	t.Helper()
	j := []byte(`{"format":1,"id":"` + migR + `","phase":"open","source":{"dir":"/srv/old"},"history":[]}`)
	if code, _, errOut := g.run(t, j, "admin", "migrate", "state", "--write", "--config", conf); code != 0 {
		t.Fatalf("the journal: %q", errOut)
	}
}

// roundTrip is one reverse migration and the second forward one, from the
// Go installation conf, under rootKEK: what each step made.
type roundTrip struct {
	reverse  []byte               // the reverse bundle
	keep     string               // the transformed copy's directory
	rebuilt  migrationtest.Source // the TypeScript installation rebuilt
	rexport  string               // its export, with its sections
	second   install              // the second forward migration's Go installation
	reverse2 []byte               // the second installation's reverse bundle
}

// reverseAndBack runs the reverse migration's data path from the Go
// installation in, and a second forward migration into a new one.
func (g *gate) reverseAndBack(t *testing.T, in install, rootKEK []byte) roundTrip {
	t.Helper()
	var rt roundTrip
	// Go's barrier, offline here (beside a running varlatchd in
	// server/daemon's TestTheReverseBarrier).
	code, out, errOut := g.run(t, nil, "admin", "migrate", "barrier", "--id", migR, "--config", in.conf)
	var rec struct {
		Gate   struct{ Phase string } `json:"gate"`
		Frozen struct {
			AuditPosition string `json:"auditPosition"`
		} `json:"frozen"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &rec) != nil || rec.Gate.Phase != "paused" {
		t.Fatalf("the barrier: %d %q %q", code, out, errOut)
	}
	rt.keep = filepath.Join(t.TempDir(), "keep")
	revPath := filepath.Join(t.TempDir(), "reverse.jsonl")
	if code, out, errOut := g.run(t, nil, "admin", "migrate", "export", "--reverse", "--out", revPath, "--keep", rt.keep, "--config", in.conf); code != 0 {
		t.Fatalf("the reverse export: %d %q %q", code, out, errOut)
	}
	var err error
	if rt.reverse, err = os.ReadFile(revPath); err != nil {
		t.Fatal(err)
	}
	// The TypeScript import, and its export of what it rebuilt.
	rt.rebuilt = migrationtest.FromReverse(t, rt.reverse, rootKEK)
	if !bytes.Equal(tables(t, migrationtest.Bundle(t, rt.rebuilt, migrationtest.Options{})), tables(t, rt.reverse)) {
		t.Fatal("the rebuilt installation's rows are not the reverse bundle's")
	}
	runKey := make([]byte, 32)
	_, _ = rand.Read(runKey)
	g.secrets = append(g.secrets, runKey)
	g.secrets = append(g.secrets, rt.rebuilt.Secrets...)
	digests := migrationtest.Digests(t, rt.rebuilt, runKey)
	for _, d := range digests {
		g.secrets = append(g.secrets, []byte(d.HMAC))
	}
	rt.rexport = writeBundle(t, migrationtest.Bundle(t, rt.rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{
		Digests: digests, Decisions: g.decide(t, in, rt.rebuilt), At: time.Now().UnixMicro()}}))
	key := []byte(hex.EncodeToString(runKey) + "\n")
	code, out, errOut = g.run(t, key, "admin", "migrate", "check", "--reverse", "--in", rt.rexport, "--scratch", rt.keep, "--json", "--config", in.conf)
	var rep check.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || !rep.Passed || !rep.Reverse {
		t.Fatalf("the reverse checks: %d %s %q", code, out, errOut)
	}
	for _, c := range rep.Checks {
		if c.Checked == 0 {
			t.Errorf("the reverse check %s checked nothing", c.Name)
		}
	}
	// The second forward migration, from the rebuilt installation.
	rt.second = newInstall(t, rootKEK)
	if code, errOut := g.importInto(t, rt.second, rt.rexport); code != 0 {
		t.Fatalf("the second forward import: %q", errOut)
	}
	code, out, errOut = g.run(t, key, "admin", "migrate", "check", "--in", rt.rexport, "--config", rt.second.conf)
	if code != 0 || !strings.HasPrefix(out, "The migration's checks passed") {
		t.Fatalf("the second forward migration's checks: %d %q %q", code, out, errOut)
	}
	// Its reverse bundle, to hold against the first.
	g.journalOpen(t, rt.second.conf)
	if code, out, errOut := g.run(t, nil, "admin", "migrate", "export", "--reverse", "--out", filepath.Join(rt.second.data, "..", "reverse2.jsonl"), "--config", rt.second.conf); code != 0 {
		t.Fatalf("the second reverse export: %d %q %q", code, out, errOut)
	}
	if rt.reverse2, err = os.ReadFile(filepath.Join(rt.second.data, "..", "reverse2.jsonl")); err != nil {
		t.Fatal(err)
	}
	return rt
}

// decide is the TypeScript evaluator's decision table at its export,
// stood in for: the rebuilt installation's rows imported into a scratch
// directory, and every tuple evaluated there.
func (g *gate) decide(t *testing.T, in install, rebuilt migrationtest.Source) []bundle.Decision {
	t.Helper()
	plain := writeBundle(t, migrationtest.Bundle(t, rebuilt, migrationtest.Options{}))
	scratch := filepath.Join(t.TempDir(), "scratch")
	if code, _, errOut := g.run(t, nil, "admin", "migrate", "import", "--in", plain, "--scratch", scratch, "--config", in.conf); code != 0 {
		t.Fatalf("the stand-in's evaluation import: %q", errOut)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(scratch, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []bundle.Decision
	for _, d := range migrationtest.Tuples(t, db, 2) {
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

// tables is a bundle's table sections: from its first table's line to its
// digest section's.
func tables(t *testing.T, b []byte) []byte {
	t.Helper()
	start := bytes.IndexByte(b, '\n') + 1
	end := bytes.Index(b, []byte("\n{\"digests\":"))
	if start <= 0 || end < start {
		t.Fatal("not a bundle")
	}
	return b[start : end+1]
}

// tableRows is a bundle's rows by table, each row's canonical line.
func tableRows(t *testing.T, b []byte) map[string][]string {
	t.Helper()
	m := migrationtest.Manifest(t)
	r, err := bundle.NewReader(bytes.NewReader(b), m)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for range bundle.Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		out[tb.Source] = []string{}
		for range n {
			row, err := r.Row()
			if err != nil {
				t.Fatal(err)
			}
			out[tb.Source] = append(out[tb.Source], string(row))
		}
	}
	return out
}

// reproduces holds the second installation's reverse bundle against the
// first's: every table's rows the same, byte for byte, but the audit log,
// which holds the first's events and, after them, the two the round trip
// appended: the second forward migration's installation.migrated, and the
// second reverse export's.
func (rt roundTrip) reproduces(t *testing.T) {
	t.Helper()
	for _, d := range differences(tableRows(t, rt.reverse), tableRows(t, rt.reverse2)) {
		t.Error(d)
	}
}

// differences are the second bundle's rows held against the first's, as
// reproduces holds them: one line per table that differs.
func differences(first, second map[string][]string) []string {
	var out []string
	for table, rows := range first {
		got := second[table]
		if table == "audit_events" {
			if len(got) != len(rows)+2 {
				out = append(out, fmt.Sprintf("audit_events: %d events, want the first's %d and two", len(got), len(rows)))
				continue
			}
			for i, r := range rows {
				if got[i] != r {
					out = append(out, fmt.Sprintf("audit_events: event %d differs", i+1))
				}
			}
			for _, extra := range got[len(rows):] {
				if !strings.Contains(extra, `"installation.migrated"`) {
					out = append(out, "audit_events: an event after the first's that is not installation.migrated")
				}
			}
			continue
		}
		if strings.Join(got, "\n") != strings.Join(rows, "\n") {
			out = append(out, fmt.Sprintf("%s: the second migration's rows differ from the first's (%d rows, %d)", table, len(got), len(rows)))
		}
	}
	slices.Sort(out)
	return out
}

// stayRevoked holds that every credential revoked in the first reverse
// bundle (the TypeScript side's state) is revoked, at the same moment, in
// the second (Go's after the second forward migration), and that neither
// holds a session.
func (rt roundTrip) stayRevoked(t *testing.T, mustBe ...string) {
	t.Helper()
	creds := migrationtest.ManifestTable(t, "credentials")
	idCol, revCol := -1, -1
	for i, c := range creds.Columns {
		switch c.Source {
		case "id":
			idCol = i
		case "revoked_at":
			revCol = i
		}
	}
	revoked := func(b []byte) map[string]any {
		out := map[string]any{}
		for _, line := range tableRows(t, b)["credentials"] {
			v, err := bundle.Decode(creds, []byte(line))
			if err != nil {
				t.Fatal(err)
			}
			if v[revCol] != nil {
				out[v[idCol].(string)] = v[revCol]
			}
		}
		return out
	}
	first, second := revoked(rt.reverse), revoked(rt.reverse2)
	for id, at := range first {
		if second[id] != at {
			t.Errorf("credential %s, revoked in the TypeScript side's state, is %v after the second forward migration", id, second[id])
		}
	}
	for _, id := range mustBe {
		if first[id] == nil {
			t.Errorf("credential %s is not revoked in the reverse bundle", id)
		}
	}
	for _, b := range [][]byte{rt.reverse, rt.reverse2} {
		if n := len(tableRows(t, b)["session"]); n != 0 {
			t.Errorf("a reverse bundle holds %d sessions", n)
		}
	}
}

// The seeded installation, migrated forward from the TypeScript release's
// rows: the reverse loses nothing of it, and the second forward migration
// reproduces it; the seed's browser credential, revoked when the forward
// migration ended its session, stays revoked.
func TestG5Reverse(t *testing.T) {
	g := setUp(t)
	in := withDatabase(t, g.source.RootKEK, g.clean)
	g.journalOpen(t, in.conf)
	rt := g.reverseAndBack(t, in, g.source.RootKEK)
	rt.reproduces(t)
	rt.stayRevoked(t, "crd_migration_browser")
	// The comparison fails on a loss: one grant dropped from the second
	// migration's rows, or one of its events.
	first, second := tableRows(t, rt.reverse), tableRows(t, rt.reverse2)
	if len(second["grants"]) == 0 {
		t.Fatal("the seed holds no grant")
	}
	lost := maps.Clone(second)
	lost["grants"] = second["grants"][1:]
	if d := differences(first, lost); len(d) != 1 || !strings.HasPrefix(d[0], "grants: ") {
		t.Errorf("a grant lost: %q", d)
	}
	lost = maps.Clone(second)
	lost["audit_events"] = slices.Delete(slices.Clone(second["audit_events"]), 3, 4)
	if d := differences(first, lost); len(d) == 0 || !strings.HasPrefix(d[0], "audit_events: ") {
		t.Errorf("an event lost: %q", d)
	}
	// The barrier's frozen copy stays with the Go installation, which the
	// reverse leaves isolated behind its barrier; the release reopens it.
	if code, _, errOut := g.run(t, nil, "admin", "migrate", "release", "--id", migR, "--config", in.conf); code != 0 {
		t.Fatalf("the release: %q", errOut)
	}
}

// rootKEKOf reads an installation's Root KEK from its configuration's file.
func rootKEKOf(t *testing.T, conf string) []byte {
	t.Helper()
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "root_kek_file" {
			raw, err := os.ReadFile(strings.TrimSpace(v))
			if err != nil {
				t.Fatal(err)
			}
			key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			return key
		}
	}
	t.Fatal("no root_kek_file")
	return nil
}

// holds reports whether a reverse bundle's table holds a row naming id.
func holds(t *testing.T, b []byte, table, id string) bool {
	t.Helper()
	for _, row := range tableRows(t, b)[table] {
		if strings.Contains(row, `"`+id+`"`) {
			return true
		}
	}
	return false
}

// After each kind of change made on Go (kinds_test.go: a new value, a
// rotation, a new passkey and its browser session, a revoked credential, a
// grant change, a Sync Target run, a webhook delivery, an audit export
// batch), on an installation Go made, the reverse migration runs beside
// the running varlatchd (its barrier through the control socket, the
// export from the frozen copy, the reverse checks of the kept copy): it
// loses nothing of any of them, and a second forward migration reproduces
// the state. The browser session ends in the reverse: its credential,
// revoked then, stays revoked, and its bearer is refused by the second
// installation, while the admin's CLI credential, never revoked, still
// answers.
func TestG5ReverseAfterEachKind(t *testing.T) {
	g := &gate{bin: build(t)}
	w := newKindsWorld(t)
	in := freshInstall(t, g.bin, w)
	g.secrets = append(g.secrets, []byte(in.Admin))
	g.journalOpen(t, in.Conf)
	svc := startKinds(t, g.bin, w, in)
	made := applyKinds(t, w, g.bin, in)
	g.secrets = append(g.secrets, []byte(made.BrowserToken))
	rootKEK := rootKEKOf(t, in.Conf)
	g.secrets = append(g.secrets, rootKEK)
	rt := g.reverseAndBack(t, install{conf: in.Conf, data: in.Data}, rootKEK)
	// Behind the barrier the Go installation still runs, isolated.
	if status, _ := (kindsClient{t: t, base: in.Base, token: in.Admin}).call("GET", "/v1/me", nil); status != http.StatusServiceUnavailable {
		t.Errorf("the Go installation behind its barrier answers /v1/me with %d", status)
	}
	svc.stop(t)
	rt.reproduces(t)
	rt.stayRevoked(t, made.RevokedCredential, made.BrowserCredential)
	for _, k := range []struct{ table, id string }{
		{"value_versions", made.ValueVersion}, {"value_versions", made.RotationVersion}, {"value_versions", made.RetiringVersion},
		{"passkey", made.Passkey}, {"credentials", made.BrowserCredential}, {"credentials", made.RevokedCredential},
		{"grants", made.Grant}, {"sync_targets", made.SyncTarget}, {"webhooks", made.Webhook}, {"audit_exports", made.AuditExport},
	} {
		for _, b := range [][]byte{rt.reverse, rt.reverse2} {
			if !holds(t, b, k.table, k.id) {
				t.Errorf("%s %s is missing from a reverse bundle", k.table, k.id)
			}
		}
	}
	// The second forward migration's installation, serving: the ended
	// session's bearer is refused, the admin's CLI credential answers.
	second := freshInstall(t, g.bin, w)
	if err := os.RemoveAll(second.Data); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second.Data, 0o700); err != nil {
		t.Fatal(err)
	}
	kek := strings.TrimSpace(func() string {
		b, _ := os.ReadFile(second.Conf)
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "root_kek_file" {
				return v
			}
		}
		return ""
	}())
	if err := os.WriteFile(kek, []byte(hex.EncodeToString(rootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, errOut := g.importInto(t, install{conf: second.Conf, data: second.Data}, rt.rexport); code != 0 {
		t.Fatalf("the second forward import: %q", errOut)
	}
	svc2 := startKinds(t, g.bin, w, second)
	if status, _ := (kindsClient{t: t, base: second.Base, token: made.BrowserToken}).call("GET", "/v1/me", nil); status != http.StatusUnauthorized {
		t.Errorf("the ended session's browser credential after the round trip: %d", status)
	}
	if status, _ := (kindsClient{t: t, base: second.Base, token: in.Admin}).call("GET", "/v1/me", nil); status != http.StatusOK {
		t.Errorf("the admin's CLI credential after the round trip: %d", status)
	}
	svc2.stop(t)
}
