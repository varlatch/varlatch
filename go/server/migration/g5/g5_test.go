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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"

	_ "github.com/varlatch/varlatch/go/lib/storage" // the sqlite driver
)

// The gate's state: the varlatchd binary, the seed, its bundle, and the
// database a clean import made.
type gate struct {
	bin     string
	source  migrationtest.Source
	runKey  []byte
	bundle  []byte
	path    string // the bundle's file
	clean   string // the clean import's varlatch.db
	secrets [][]byte
}

// build builds varlatchd from this checkout, as the release does (no cgo).
func build(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "varlatchd")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/varlatchd")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/varlatchd: %v\n%s", err, out)
	}
	return bin
}

// install is a varlatchd installation: its configuration, its Root KEK
// file, its data directory.
type install struct {
	conf, data string
}

func newInstall(t *testing.T, rootKEK []byte) install {
	t.Helper()
	dir := t.TempDir()
	in := install{conf: filepath.Join(dir, "varlatchd.conf"), data: filepath.Join(dir, "data")}
	kek := filepath.Join(dir, "root-kek")
	if err := os.Mkdir(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kek, []byte(hex.EncodeToString(rootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\nbackup_interval = off\n",
		in.data, kek, filepath.Join(dir, "access.log"))
	if err := os.WriteFile(in.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return in
}

// withDatabase is a new installation holding a copy of the database at db.
func withDatabase(t *testing.T, rootKEK []byte, db string) install {
	t.Helper()
	in := newInstall(t, rootKEK)
	b, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.data, "varlatch.db"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return in
}

// run runs varlatchd with stdin, and fails the test if what it printed
// holds a secret.
func (g *gate) run(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(g.bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	g.noSecrets(t, append(stdout.Bytes(), stderr.Bytes()...))
	return code, stdout.String(), stderr.String()
}

func (g *gate) noSecrets(t *testing.T, out []byte) {
	t.Helper()
	for _, s := range g.secrets {
		if len(s) < 8 {
			continue
		}
		for _, form := range migrationtest.Forms(s) {
			if bytes.Contains(out, form) {
				t.Fatal("varlatchd printed a secret")
			}
		}
	}
}

func (g *gate) importInto(t *testing.T, in install, bundlePath string) (int, string) {
	t.Helper()
	code, _, errOut := g.run(t, nil, "admin", "migrate", "import", "--in", bundlePath, "--config", in.conf)
	return code, errOut
}

// checkJSON runs the checks, key on a pipe, and reads the JSON report.
func (g *gate) checkJSON(t *testing.T, in install, bundlePath string, runKey []byte) (int, check.Report) {
	t.Helper()
	code, stdout, errOut := g.run(t, []byte(hex.EncodeToString(runKey)+"\n"), "admin", "migrate", "check", "--in", bundlePath, "--json", "--config", in.conf)
	var rep check.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("check --json: %d %q %q", code, stdout, errOut)
	}
	return code, rep
}

func writeBundle(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// setUp builds the binary and the seeded migration: the bundle's decision
// table evaluated on a first, in-process import (the TypeScript
// evaluator's arrives with its export), then the bundle imported through
// the binary.
func setUp(t *testing.T) *gate {
	t.Helper()
	g := &gate{bin: build(t), source: migrationtest.Load(t)}
	g.runKey = make([]byte, 32)
	_, _ = rand.Read(g.runKey)
	digests := migrationtest.Digests(t, g.source, g.runKey)
	plain := migrationtest.Bundle(t, g.source, migrationtest.Options{Sections: &migrationtest.Sections{Digests: digests}})
	first := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(plain), migrate.Options{DataDir: first, RootKEK: g.source.RootKEK, Release: "0.50.0-g5"}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(first, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var decisions []bundle.Decision
	for _, d := range migrationtest.Tuples(t, db, 2) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	db.Close()
	g.bundle = migrationtest.Bundle(t, g.source, migrationtest.Options{Sections: &migrationtest.Sections{Digests: digests, Decisions: decisions, At: time.Now().UnixMicro()}})
	g.path = writeBundle(t, g.bundle)
	g.secrets = append(slices.Clone(g.source.Secrets), g.runKey)
	for _, d := range digests {
		g.secrets = append(g.secrets, []byte(d.HMAC))
	}
	in := newInstall(t, g.source.RootKEK)
	if code, errOut := g.importInto(t, in, g.path); code != 0 {
		t.Fatalf("the clean import: %d %q", code, errOut)
	}
	g.clean = filepath.Join(in.data, "varlatch.db")
	return g
}

// G5: the seeded migration passes through the binary; each damage of the
// bundle stream is refused by the import, naming it, with nothing kept;
// each damage of the bundle's check sections and of the imported database
// fails the checks at its own check, naming its table or class; a killed
// import leaves nothing a second import does not clear; nothing secret is
// ever printed.
func TestG5(t *testing.T) {
	g := setUp(t)
	t.Run("the seeded migration passes", func(t *testing.T) { g.passes(t) })
	t.Run("the bundle stream damaged", func(t *testing.T) { g.streamDamage(t) })
	t.Run("the check sections damaged", func(t *testing.T) { g.sectionDamage(t) })
	t.Run("the imported database damaged", func(t *testing.T) { g.targetDamage(t) })
	t.Run("the wrong keys", func(t *testing.T) { g.wrongKeys(t) })
	t.Run("a killed import", func(t *testing.T) { g.killedImport(t) })
}

func (g *gate) passes(t *testing.T) {
	in := withDatabase(t, g.source.RootKEK, g.clean)
	code, stdout, errOut := g.run(t, []byte(hex.EncodeToString(g.runKey)+"\n"), "admin", "migrate", "check", "--in", g.path, "--config", in.conf)
	if code != 0 || !strings.HasPrefix(stdout, "The migration's checks passed") {
		t.Fatalf("check: %d %q %q", code, stdout, errOut)
	}
	t.Logf("\n%s", stdout)
	code, rep := g.checkJSON(t, in, g.path, g.runKey)
	if code != 0 || !rep.Passed || len(rep.Checks) != len(check.Names) {
		t.Fatalf("check --json: %d %+v", code, rep)
	}
	for _, c := range rep.Checks {
		if c.Checked == 0 {
			t.Errorf("%s checked nothing", c.Name)
		}
	}
}

// lines is a bundle's lines, each with its \n.
func lines(b []byte) [][]byte {
	return bytes.SplitAfter(b, []byte("\n"))[:bytes.Count(b, []byte("\n"))]
}

func index(ls [][]byte, prefix string) int {
	for i, l := range ls {
		if bytes.HasPrefix(l, []byte(prefix)) {
			return i
		}
	}
	return -1
}

// setCount replaces a member's count in line ("digests":n), by delta.
func setCount(t *testing.T, line []byte, member string, delta int) []byte {
	t.Helper()
	key := []byte(`"` + member + `":`)
	i := bytes.Index(line, key)
	if i < 0 {
		t.Fatalf("no %s in %s", member, line)
	}
	i += len(key)
	j := i
	for j < len(line) && line[j] >= '0' && line[j] <= '9' {
		j++
	}
	n, _ := strconv.Atoi(string(line[i:j]))
	return slices.Concat(line[:i], []byte(strconv.Itoa(n+delta)), line[j:])
}

func (g *gate) streamDamage(t *testing.T) {
	ls := lines(g.bundle)
	end := len(ls) - 1
	digests := index(ls, `{"digests":`)
	decisions := index(ls, `{"decisions":`)
	instRow := index(ls, `{"table":"installation",`) + 1
	join := func(ls [][]byte) []byte { return bytes.Join(ls, nil) }
	with := func(i int, l []byte) [][]byte {
		out := slices.Clone(ls)
		out[i] = l
		return out
	}
	reseal := func(ls [][]byte) []byte { return migrationtest.Reseal(t, join(ls)) }
	changed := slices.Clone(g.bundle)
	changed[len(join(ls[:instRow]))+3] ^= 1
	// The source with its session's token carried.
	carried := migrationtest.Source{RootKEK: g.source.RootKEK, AuditPosition: g.source.AuditPosition, Rows: map[string][]jsvalue.Object{}}
	for k, v := range g.source.Rows {
		carried.Rows[k] = v
	}
	session := slices.Clone(g.source.Rows["session"][0]).Set("token", "a token the export never carries")
	carried.Rows["session"] = []jsvalue.Object{session}
	for _, c := range []struct {
		name   string
		bundle []byte
		why    string
	}{
		{"a changed row byte", changed, "damaged"},
		{"cut short", join(ls[:end/2]), "cut short"},
		{"no end line", join(ls[:end]), "cut short"},
		{"an end line's digest changed", join(with(end, otherDigit(ls[end], bytes.Index(ls[end], []byte(`"sha256":"`))+len(`"sha256":"`)))), "damaged"},
		{"an end line counting another row", reseal(with(end, setCount(t, ls[end], "rows", 1))), "the end line counts"},
		{"an end line counting another digest", reseal(with(end, setCount(t, ls[end], "digests", 1))), "the end line counts"},
		{"digests out of order", reseal(slices.Concat(ls[:digests+1], [][]byte{ls[digests+2], ls[digests+1]}, ls[digests+3:])), "out of order"},
		{"a decision line not in canonical form", reseal(with(decisions+1, bytes.Replace(ls[decisions+1], []byte(`"state":`), []byte(`"state": `), 1))), "not in canonical form"},
		{"a session token carried", migrationtest.Bundle(t, carried, migrationtest.Options{}), "session.token holds a value"},
		{"a sequence", migrationtest.Bundle(t, g.source, migrationtest.Options{Sequences: true}), "sequences"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := newInstall(t, g.source.RootKEK)
			code, errOut := g.importInto(t, in, writeBundle(t, c.bundle))
			if code != 1 || !strings.Contains(errOut, c.why) || !strings.Contains(errOut, "nothing was kept") {
				t.Fatalf("import: %d %q, want %q", code, errOut, c.why)
			}
			entries, _ := os.ReadDir(in.data)
			for _, e := range entries {
				if e.Name() != "varlatchd.lock" {
					t.Errorf("the data directory kept %s", e.Name())
				}
			}
		})
	}
}

// sectionDamage: a bundle whose rows are intact but whose check sections
// were changed imports (the import holds nothing against them), and the
// checks fail at the right check.
func (g *gate) sectionDamage(t *testing.T) {
	ls := lines(g.bundle)
	end := len(ls) - 1
	digests := index(ls, `{"digests":`)
	decisions := index(ls, `{"decisions":`)
	allowed := -1
	for i := decisions + 1; i < end; i++ {
		if bytes.Contains(ls[i], []byte(`"allowed":true,"code":null`)) {
			allowed = i
			break
		}
	}
	if allowed < 0 {
		t.Fatal("no allowed decision")
	}
	var d struct {
		Class string `json:"class"`
	}
	_ = json.Unmarshal(ls[digests+1], &d)
	hmacAt := bytes.Index(ls[digests+1], []byte(`"hmac":"`)) + len(`"hmac":"`)
	otherHMAC := slices.Clone(ls[digests+1])
	if otherHMAC[hmacAt] == '0' {
		otherHMAC[hmacAt] = '1'
	} else {
		otherHMAC[hmacAt] = '0'
	}
	without := slices.Concat(ls[:digests], [][]byte{setCount(t, ls[digests], "digests", -1)}, ls[digests+2:end], [][]byte{setCount(t, ls[end], "digests", -1)})
	for _, c := range []struct {
		name, check, class, says string
		bundle                   [][]byte
	}{
		{"a digest that is not the source's", check.Classes, d.Class, "its plaintext is not the source's", slices.Concat(ls[:digests+1], [][]byte{otherHMAC}, ls[digests+2:])},
		{"a digest missing", check.Classes, d.Class, "an item the source does not have", without},
		{"a decision answered otherwise", check.Authorization, "", "the source denies (PERMISSION_DENIED), the target allows",
			slices.Concat(ls[:allowed], [][]byte{bytes.Replace(ls[allowed], []byte(`"allowed":true,"code":null`), []byte(`"allowed":false,"code":"PERMISSION_DENIED"`), 1)}, ls[allowed+1:])},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := writeBundle(t, migrationtest.Reseal(t, bytes.Join(c.bundle, nil)))
			in := newInstall(t, g.source.RootKEK)
			if code, errOut := g.importInto(t, in, b); code != 0 {
				t.Fatalf("import: %d %q", code, errOut)
			}
			code, rep := g.checkJSON(t, in, b, g.runKey)
			g.failsAt(t, code, rep, c.check, "", c.class, c.says)
		})
	}
}

// failsAt holds a report to failing (exit 1) at the named check, with a
// fault naming table or class (each when given) that says says.
func (g *gate) failsAt(t *testing.T, code int, rep check.Report, name, table, class, says string) {
	t.Helper()
	r := rep.Result(name)
	if code != 1 || rep.Passed || r.Passed {
		t.Fatalf("exit %d: the %s check did not fail: %+v", code, name, rep)
	}
	for _, f := range r.Failures {
		where := f.Table
		if f.Class != "" {
			where = f.Class
		}
		text := f.What
		if where != "" {
			text = where + ": " + f.What
		}
		if (table == "" || f.Table == table) && (class == "" || f.Class == class) && strings.Contains(text, says) {
			return
		}
	}
	t.Fatalf("the %s check does not name %s%s with %q: %+v", name, table, class, says, r.Failures)
}

func (g *gate) targetDamage(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+g.clean+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	decisions := readDecisions(t, g.bundle)
	grant := migrationtest.AskedGrant(t, db, decisions)
	db.Close()
	for _, f := range append(migrationtest.ClassFaults(), migrationtest.TargetFaults(grant)...) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			in := withDatabase(t, g.source.RootKEK, g.clean)
			f.Apply(t, filepath.Join(in.data, "varlatch.db"))
			code, rep := g.checkJSON(t, in, g.path, g.runKey)
			g.failsAt(t, code, rep, f.Check, f.Table, f.Class, f.Says)
		})
	}
}

func readDecisions(t *testing.T, b []byte) []bundle.Decision {
	t.Helper()
	ls := lines(b)
	var out []bundle.Decision
	for i := index(ls, `{"decisions":`) + 1; i < len(ls)-1; i++ {
		var d struct {
			Credential string `json:"credential"`
		}
		if err := json.Unmarshal(ls[i], &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, bundle.Decision{Credential: d.Credential})
	}
	return out
}

// wrongKeys: another run key fails the class check alone; another Root
// KEK fails the class check (nothing opens), and the import refuses it.
func (g *gate) wrongKeys(t *testing.T) {
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	g.secrets = append(g.secrets, other)
	in := withDatabase(t, g.source.RootKEK, g.clean)
	code, rep := g.checkJSON(t, in, g.path, other)
	g.failsAt(t, code, rep, check.Classes, "", "", "its plaintext is not the source's")
	for _, c := range rep.Checks {
		if c.Name != check.Classes && !c.Passed {
			t.Errorf("another run key failed %s", c.Name)
		}
	}
	wrong := withDatabase(t, other, g.clean)
	code, rep = g.checkJSON(t, wrong, g.path, g.runKey)
	g.failsAt(t, code, rep, check.Classes, "installation", "kek-canary", "does not open")
	fresh := newInstall(t, other)
	if code, errOut := g.importInto(t, fresh, g.path); code != 1 || !strings.Contains(errOut, "does not open the installation's canary") {
		t.Fatalf("an import with another Root KEK: %d %q", code, errOut)
	}
}

// killedImport: an import killed while it writes leaves no varlatch.db,
// only its temporary name; the next import clears it and builds the
// database, which passes the checks.
func (g *gate) killedImport(t *testing.T) {
	// A larger bundle, so the kill lands in the write: 50,000 more audit
	// events after the source's.
	m := migrationtest.ManifestTable(t, "audit_events")
	var extra [][]any
	first := g.source.AuditPosition + 1
	for i := range 50000 {
		row := make([]any, len(m.Columns))
		for j, c := range m.Columns {
			switch c.Source {
			case "id":
				row[j] = fmt.Sprintf("evt_g5%020d", i)
			case "schema_version":
				row[j] = int64(1)
			case "event_type":
				row[j] = "organization.read"
			case "occurred_at":
				row[j] = int64(1795000000000000 + i)
			case "decision":
				row[j] = "info"
			case "event_order":
				row[j] = first + int64(i)
			}
		}
		extra = append(extra, row)
	}
	b := migrationtest.Bundle(t, g.source, migrationtest.Options{Extra: map[string][][]any{"audit_events": extra},
		AuditPosition: first + 49999, Sections: g.sections(t)})
	path := writeBundle(t, b)
	in := newInstall(t, g.source.RootKEK)
	cmd := exec.Command(g.bin, "admin", "migrate", "import", "--in", path, "--config", in.conf)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if left, _ := filepath.Glob(filepath.Join(in.data, ".migrate-import-*.db")); len(left) > 0 {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			killed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if !killed || !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("the import was not killed while it wrote: killed %v, %v", killed, err)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a killed import left varlatch.db: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(in.data, ".migrate-import-*")); len(left) == 0 {
		t.Fatal("the killed import left nothing under its temporary name: it was not mid-write")
	}
	if code, errOut := g.importInto(t, in, path); code != 0 {
		t.Fatalf("the import after a killed one: %d %q", code, errOut)
	}
	entries, _ := os.ReadDir(in.data)
	for _, e := range entries {
		if e.Name() != "varlatch.db" && e.Name() != "varlatchd.lock" {
			t.Errorf("after the second import, the data directory holds %s", e.Name())
		}
	}
	code, rep := g.checkJSON(t, in, path, g.runKey)
	if code != 0 || !rep.Passed {
		t.Fatalf("the checks after a killed import: %d %+v", code, rep)
	}
}

// sections are the seeded bundle's check sections, read back.
func (g *gate) sections(t *testing.T) *migrationtest.Sections {
	t.Helper()
	m := migrationtest.Manifest(t)
	r, err := bundle.NewReader(bytes.NewReader(g.bundle), m)
	if err != nil {
		t.Fatal(err)
	}
	for range bundle.Tables(m) {
		_, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		for range n {
			if _, err := r.Row(); err != nil {
				t.Fatal(err)
			}
		}
	}
	var s migrationtest.Sections
	n, err := r.Digests()
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		d, err := r.Digest()
		if err != nil {
			t.Fatal(err)
		}
		s.Digests = append(s.Digests, d)
	}
	n, s.At, err = r.Decisions()
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		d, err := r.Decision()
		if err != nil {
			t.Fatal(err)
		}
		s.Decisions = append(s.Decisions, d)
	}
	return &s
}

// otherDigit is line with its hex digit at i changed.
func otherDigit(line []byte, i int) []byte {
	out := slices.Clone(line)
	if out[i] == '0' {
		out[i] = '1'
	} else {
		out[i] = '0'
	}
	return out
}
