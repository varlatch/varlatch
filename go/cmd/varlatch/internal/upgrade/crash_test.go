// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// The upgrade's crash safety, tried at every point of it: a host whose
// releases are stand-ins (text files) and whose databases are small text
// files, so that thousands of interrupted upgrades run in a minute. A run is
// killed after each change it makes (or the power is cut: what was not
// synced is lost), the host reboots, and the next run finishes or undoes
// it. Whatever happened, one whole database of known identity is served at
// the end, with every write a client was told was stored.
//
// A database is a file of lines: "db <identity>", "schema <n>" and a
// "write <n>" for each client's write; its log, "wal <identity>" and more
// writes.

const (
	standFrom, standTo = "0.50.0-rc.4", "0.50.0-rc.5"
	oldFrom            = "0.50.0-rc.3" // reads no journal
)

type standHost struct {
	t              *testing.T
	dir, bin, data string
	conf           string
	from, to       string
	badTo          bool // To fails its health checks
	badFrom        bool // From does, once it is not the first installed
	keeps          bool // To is rollback-safe: From opens its database
	crash          func(string) bool
	// The writes the pre-upgrade snapshot holds, and those made when a
	// rollback restored it.
	snapshot, rolled int
	svc              *standService
	boots            int
	shadow           *shadow
}

// standIn is a release's varlatchd: its version and schema, and what it
// answers as its status.
func standIn(version string, schema int, status string) string {
	return fmt.Sprintf("release %s schema %d\n%s", version, schema, status)
}

// run is a stand-in run: what its varlatchd admin would do.
func (h *standHost) run(binary string, args ...string) ([]byte, error) {
	var version string
	var schema int
	head, status, _ := strings.Cut(h.read(binary), "\n")
	if n, _ := fmt.Sscanf(head, "release %s schema %d", &version, &schema); n != 2 {
		return nil, fmt.Errorf("%s is no varlatchd: %q", binary, head)
	}
	switch strings.Join(args[1:3], " ") {
	case "backup run":
		archive := filepath.Join(h.data, "backups", "a.vltbak")
		if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
			return nil, err
		}
		h.put(archive, h.database(), 0o600)
		h.snapshot = h.svc.writes + 1
		return fmt.Appendf(nil, `{"path":%q,"createdAt":"2026-11-24T00:00:00Z","archiveId":"archive-1","capture":{"dumpBytes":100}}`, archive), nil
	case "backup restore":
		return nil, h.restore(args)
	case "changes --since":
		return fmt.Appendf(nil, `{"since":%q,"total":%d,"byType":{},"latest":[],"revocationsTotal":0,"revocations":[]}`, args[3], strings.Count(h.database(), "write ")), nil
	case "schema status":
		content, database := h.database(), "null"
		n := 0
		if _, err := fmt.Sscanf(content, "db original\nschema %d\n", &n); err == nil {
			database = fmt.Sprintf(`{"schemaVersion":%d}`, n)
		}
		return fmt.Appendf(nil, `{"opens":%v,"dataDir":%q,"database":%s}`, n == schema || h.keeps || n == 0, h.data, database), nil
	case "schema upgrade":
		f := args[len(args)-1]
		content, log := h.read(f), h.read(f+walSuffix)
		if log != "" {
			if !strings.HasPrefix(log, walHead(content)) {
				h.svc.fault("a copy with another's log: %q beside %q", log, content)
			}
			content += log[strings.Index(log, "\n")+1:]
			_ = os.Remove(f + walSuffix)
		}
		h.put(f, strings.Replace(content, "schema 1\n", fmt.Sprintf("schema %d\n", schema), 1), 0o600)
		return fmt.Appendf(nil, `{"to":%d}`, schema), nil
	case "status --json":
		if h.svc.running != version {
			return nil, errors.New("it is not running")
		}
		return []byte(status), nil
	}
	return nil, fmt.Errorf("no stand-in for %q", args)
}

// database is the database with what its log holds.
func (h *standHost) database() string {
	content, log := h.read(filepath.Join(h.data, databaseFile)), h.read(filepath.Join(h.data, databaseFile+walSuffix))
	return content + log[strings.Index(log, "\n")+1:]
}

// restore is `admin backup restore` as varlatchd does it: a gate, the log
// removed, the database replaced by one rename, the hold, the gate removed;
// killed and cut at each.
func (h *standHost) restore(args []string) error {
	archive := h.read(args[len(args)-1])
	if !strings.HasPrefix(archive, "db original\n") {
		return fmt.Errorf("not an archive: %q", archive)
	}
	if slices.Contains(args, "--check") {
		return nil
	}
	if h.svc.running != "" {
		return errors.New("varlatchd is running")
	}
	db := filepath.Join(h.data, databaseFile)
	for _, step := range []struct {
		name string
		do   func()
	}{
		{"gate", func() {
			h.put(filepath.Join(h.data, "maintenance.json"), `{"id":"x","kind":"restore","phase":"paused","archiveId":"archive-1"}`, 0o600)
			h.shadow.stored(h.data, filepath.Join(h.data, "maintenance.json"))
		}},
		{"opened", func() {
			_ = os.Mkdir(filepath.Join(h.data, ".restore-work"), 0o700)
			h.put(filepath.Join(h.data, ".restore-work", "database"), archive, 0o600)
			h.shadow.entries(h.data)
		}},
		{"staged", func() {
			h.put(db+".restore", archive, 0o600)
			h.shadow.stored(h.data, db+".restore")
		}},
		{"log", func() {
			_ = os.Remove(db + walSuffix)
			h.shadow.stored(h.data, db+walSuffix)
		}},
		{"renamed", func() {
			h.rolled = h.svc.writes + 1
			_ = os.Rename(db+".restore", db)
			h.shadow.stored(h.data, db)
			h.shadow.stored(h.data, db+".restore")
		}},
		{"reconciled", func() { h.svc.log("restored\n") }},
		{"held", func() {
			h.put(filepath.Join(h.data, holdFile), `{"archiveId":"archive-1","restoredAt":"t"}`, 0o600)
			h.shadow.stored(h.data, filepath.Join(h.data, holdFile))
		}},
		{"done", func() {
			_ = os.RemoveAll(filepath.Join(h.data, ".restore-work"))
			_ = os.Remove(filepath.Join(h.data, "maintenance.json"))
			h.shadow.entries(h.data)
		}},
	} {
		step.do()
		if h.crash != nil && h.crash("restore:"+step.name) {
			return errKilled
		}
	}
	return nil
}

func standStatus(version string, schema int) string {
	return fmt.Sprintf(`{"version":"%s","schemaVersion":%d,"serving":true,"ready":{"schema":true,"rootKek":true,"installation":true}}`, version, schema)
}

func newStandHost(t *testing.T, from string, badTo, wal bool) *standHost {
	t.Helper()
	// In memory where there is one: thousands of syncs.
	base := "/dev/shm"
	dir, err := os.MkdirTemp(base, "vl-upgrade-")
	if err != nil {
		if dir, err = os.MkdirTemp("", "vl-upgrade-"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &standHost{t: t, keeps: true, dir: dir, bin: filepath.Join(dir, "usr", "bin"), data: filepath.Join(dir, "data"), conf: filepath.Join(dir, "etc", "varlatchd.conf"), from: from, to: standTo, badTo: badTo, boots: 1}
	for _, d := range []string{h.bin, h.data, filepath.Dir(h.conf)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.put(h.conf, "data_dir = "+h.data+"\n", 0o600)
	h.put(filepath.Join(h.bin, "varlatchd"), standIn(from, 1, standStatus(from, 1)), 0o755)
	h.put(filepath.Join(h.bin, "varlatch"), "varlatch "+from, 0o755)
	h.put(filepath.Join(h.data, lockFile), "", 0o600)
	h.put(filepath.Join(h.data, databaseFile), "db original\nschema 1\nwrite 1\n", 0o600)
	h.svc = &standService{h: h, killed: wal}
	if err := h.svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.svc.write()
	h.shadow = newShadow(t, h.dir)
	return h
}

func (h *standHost) put(path, content string, mode os.FileMode) {
	h.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *standHost) read(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func (h *standHost) release() Release {
	d := release.Declaration{SchemaVersion: 2, CompatibleFrom: 2, Previous: &release.Previous{Version: h.from, SchemaVersion: 1}, ReversibleTo: &reversible}
	if h.keeps {
		d.CompatibleFrom, d.RollbackSafe = 1, true
	}
	m, err := release.NewManifest(standTo, d)
	if err != nil {
		h.t.Fatal(err)
	}
	status := standStatus(standTo, 2)
	if h.badTo {
		status = strings.Replace(status, `"rootKek":true`, `"rootKek":false`, 1)
	}
	return Release{Version: standTo, Varlatch: []byte("varlatch " + standTo), Varlatchd: []byte(standIn(standTo, 2, status)), Manifest: m}
}

func (h *standHost) installed() Installed {
	return Installed{Version: h.from, Schema: 1, DataDir: h.data}
}

func (h *standHost) upgrader(crash func(string) bool) *Upgrader {
	// A client writes all the while, as it can.
	point := func(p string) bool {
		h.svc.write()
		return crash != nil && crash(p)
	}
	h.crash = point
	return &Upgrader{BinDir: h.bin, ConfigPath: h.conf, Service: h.svc, HealthTimeout: time.Nanosecond, Crash: point,
		trace: h.shadow.event, run: h.run, free: func(string) (uint64, uint64, error) { return 1 << 40, 1, nil }, boot: func() string { return fmt.Sprint("boot", h.boots) }}
}

func (h *standHost) journal() *journal.Journal {
	j, err := journal.Read(filepath.Dir(h.conf))
	if err != nil {
		h.t.Fatal(err)
	}
	return j
}

// standService is the unit: it starts what is in place, as serve would.
type standService struct {
	h       *standHost
	running string // the release that runs, "" for none
	writes  int    // clients' writes accepted
	killed  bool   // a stop kills: the log stays
	hold    bool   // it was started held
	faults  []string
}

func (s *standService) fault(format string, a ...any) {
	s.faults = append(s.faults, fmt.Sprintf(format, a...))
}

// refusal is why varlatchd of version does not start: the upgrade journal
// (slice A3), for a release that reads it.
func (s *standService) refusal(version string) error {
	s.hold = false
	if order, _ := release.CompareVersions(version, journal.FormatSince); order < 0 {
		return nil
	}
	j, boot := s.h.journal(), fmt.Sprint("boot", s.h.boots)
	if !j.Holds() || j.Settled(boot) {
		return nil
	}
	formatOne := j.Format == journal.FormatOne && j.State == journal.InProgress && j.To == version && (j.Step == journal.Swapped || j.Step == journal.Started || j.Step == journal.Checked)
	if !j.Allows(version, boot) && !formatOne {
		return errors.New("an upgrade is not over")
	}
	s.hold = true
	return nil
}

// held is whether the running varlatchd answers 503: started as the journal
// allows, which is not over (as far as it can see: a name may not be durable).
func (s *standService) held() bool {
	if s.hold && !s.h.journal().Holds() {
		s.hold = false
	}
	return s.hold
}

func (s *standService) Start(context.Context) error {
	if s.running != "" {
		return nil
	}
	var version string
	var schema int
	if n, _ := fmt.Sscanf(s.h.read(filepath.Join(s.h.bin, "varlatchd")), "release %s schema %d", &version, &schema); n != 2 {
		s.fault("no varlatchd in place")
		return errors.New("no varlatchd")
	}
	if err := s.refusal(version); err != nil {
		return err
	}
	db, wal := filepath.Join(s.h.data, databaseFile), filepath.Join(s.h.data, databaseFile+walSuffix)
	content := s.h.read(db)
	if content == "" {
		s.fault("%s started without a database: it would make an empty one", version)
		return errors.New("no database")
	}
	if !strings.HasPrefix(content, "db original\n") || !strings.HasSuffix(content, "\n") {
		s.fault("%s started on a database that is not the installation's: %q", version, content)
	}
	if log := s.h.read(wal); log != "" && !strings.HasPrefix(log, walHead(content)) {
		s.fault("%s started on a database with another's log: %q beside %q", version, log, content)
	}
	if !strings.Contains(content, fmt.Sprintf("schema %d\n", schema)) && !(schema == 1 && s.h.keeps) {
		return errors.New("the schema is not this release's")
	}
	s.running = version
	// What a server writes as it starts, held or not.
	s.log("started " + version + "\n")
	return nil
}

// write is a client's write, stored in the log, when it is accepted.
func (s *standService) write() {
	if s.running == "" || s.held() {
		return
	}
	s.writes++
	s.log(fmt.Sprintf("write %d\n", s.writes+1))
}

// log adds a line to the database's log, whose head says which database it
// is of.
func (s *standService) log(line string) {
	wal := filepath.Join(s.h.data, databaseFile+walSuffix)
	log := s.h.read(wal)
	if log == "" {
		log = walHead(s.h.read(filepath.Join(s.h.data, databaseFile)))
	}
	s.h.put(wal, log+line, 0o600)
	if s.h.shadow != nil {
		s.h.shadow.stored(s.h.data, wal)
	}
}

// walHead is the head of the log of a database of this content.
func walHead(database string) string {
	schema := "none"
	if i := strings.Index(database, "schema "); i >= 0 {
		schema, _, _ = strings.Cut(database[i+len("schema "):], "\n")
	}
	return fmt.Sprintf("wal original %d %s\n", strings.Count(database, "\n"), schema)
}

func (s *standService) Stop(context.Context) error {
	if s.running == "" {
		return nil
	}
	s.running = ""
	db, wal := filepath.Join(s.h.data, databaseFile), filepath.Join(s.h.data, databaseFile+walSuffix)
	if log := s.h.read(wal); log != "" && !s.killed {
		// Stopped, it writes its log back, in place, and removes it.
		f, err := os.OpenFile(db, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, _ = f.WriteString(log[strings.Index(log, "\n")+1:])
		f.Close()
		_ = os.Remove(wal)
		if s.h.shadow != nil {
			s.h.shadow.keep(db)
			s.h.shadow.stored(s.h.data, wal)
		}
	}
	return nil
}

// canGoOn fails when an upgrade is not over and the varlatch installed, the
// one an operator runs, could not read its journal.
func (h *standHost) canGoOn(what string) {
	h.t.Helper()
	j := h.journal()
	version := strings.TrimPrefix(h.read(filepath.Join(h.bin, "varlatch")), "varlatch ")
	if order, _ := release.CompareVersions(version, journal.FormatSince); j.Pending() && j.Format != journal.FormatOne && order < 0 {
		h.t.Fatalf("%s: varlatch %s is installed, and cannot read the journal\n%s", what, version, h.tree())
	}
}

// reboot is the power coming back: nothing runs, and the enabled unit
// starts what it may.
func (h *standHost) reboot() {
	h.boots++
	h.svc.running = ""
	_ = h.svc.Start(context.Background())
	h.svc.write()
}

// ends checks that the host ended as it must: want's release serving the
// installation's one whole database, with every accepted write.
func (h *standHost) ends(what string) {
	h.t.Helper()
	fail := func(format string, a ...any) {
		h.t.Helper()
		h.t.Fatalf("%s: %s\njournal %+v\nfaults %q\n%s", what, fmt.Sprintf(format, a...), h.journal(), h.svc.faults, h.tree())
	}
	if len(h.svc.faults) > 0 {
		fail("the server met what it must not")
	}
	h.svc.write()
	j := h.journal()
	version, schema := h.from, 1
	if j != nil && j.State == journal.Done && j.Kind == journal.Upgrade || j != nil && j.State == journal.Done && j.RollbackSafe {
		version, schema = h.to, 2
	}
	// What a rollback that restored the snapshot lost.
	lost := func(int) bool { return false }
	if j != nil && j.Kind == journal.Rollback {
		version = j.To
		if !j.RollbackSafe {
			lost = func(n int) bool { return n > h.snapshot && n <= h.rolled }
		}
		if got := exists(filepath.Join(h.data, holdFile)); got == j.RollbackSafe {
			fail("held: %v", got)
		}
	} else if exists(filepath.Join(h.data, holdFile)) {
		fail("held")
	}
	if j.Pending() {
		fail("not over")
	}
	for _, name := range []string{"maintenance.json", ".restore-work", databaseFile + ".restore"} {
		if exists(filepath.Join(h.data, name)) {
			fail("%s is left", name)
		}
	}
	if h.svc.running != version {
		fail("%q serves, not %s", h.svc.running, version)
	}
	content := h.read(filepath.Join(h.data, databaseFile)) + h.read(filepath.Join(h.data, databaseFile+walSuffix))
	if !strings.HasPrefix(content, fmt.Sprintf("db original\nschema %d\n", schema)) {
		fail("the database is %q", content)
	}
	for n := 1; n <= h.svc.writes+1; n++ {
		if want := map[bool]int{false: 1}[lost(n)]; strings.Count(content, fmt.Sprintf("write %d\n", n)) != want {
			fail("write %d of %d is not there once: %q", n, h.svc.writes+1, content)
		}
	}
	// An undo to a release that reads no journal ends with the journal set
	// aside: what it tidies after, and the older varlatch, are not missed.
	if j == nil && h.from == oldFrom {
		return
	}
	if j != nil && j.State == journal.Undone && h.from == oldFrom && j.Format != journal.FormatOne {
		fail("%s's varlatch could not read the journal left", h.from)
	}
	if got := h.read(filepath.Join(h.bin, "varlatch")); got != "varlatch "+version {
		fail("varlatch is %q", got)
	}
	for _, name := range workDirs {
		left, _ := filepath.Glob(filepath.Join(h.data, "upgrades", "*", name))
		if j != nil && j.Kind == journal.Rollback && !j.RollbackSafe && name == originalDir {
			// The database it replaced.
			if len(left) != 1 || left[0] != filepath.Join(j.Work, originalDir) {
				fail("kept: %q", left)
			}
			continue
		}
		if len(left) > 0 {
			fail("%s is left", left)
		}
	}
}

func (h *standHost) tree() string {
	var b strings.Builder
	_ = filepath.WalkDir(h.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.Contains(p, "/usr/") {
			fmt.Fprintf(&b, "  %s: %.120q\n", strings.TrimPrefix(p, h.dir), h.read(p))
		}
		return nil
	})
	return b.String()
}

// shadow is what of the data directory a power cut would leave: the
// entries of each directory as last synced, and the content of each file as
// last synced.
type shadow struct {
	t       *testing.T
	root    string
	ids     map[uint64]int // a live inode's identity here
	next    int
	dirs    map[int]map[string]int
	content map[int]string
	isDir   map[int]bool
}

func newShadow(t *testing.T, root string) *shadow {
	s := &shadow{t: t, root: root, ids: map[uint64]int{}, dirs: map[int]map[string]int{}, content: map[int]string{}, isDir: map[int]bool{}}
	s.absorb()
	return s
}

func inode(path string) (uint64, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false
	}
	return info.Sys().(*syscall.Stat_t).Ino, true
}

func (s *shadow) id(path string) int {
	ino, ok := inode(path)
	if !ok {
		return -1
	}
	id, ok := s.ids[ino]
	if !ok {
		s.next++
		id = s.next
		s.ids[ino] = id
		info, _ := os.Lstat(path)
		s.isDir[id] = info.IsDir()
	}
	return id
}

// absorb takes the whole directory as it is now as durable.
func (s *shadow) absorb() {
	_ = filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			s.entries(p)
		} else {
			s.keep(p)
		}
		return nil
	})
}

func (s *shadow) entries(dir string) {
	m := map[string]int{}
	list, _ := os.ReadDir(dir)
	for _, e := range list {
		m[e.Name()] = s.id(filepath.Join(dir, e.Name()))
	}
	s.dirs[s.id(dir)] = m
}

func (s *shadow) keep(path string) {
	b, _ := os.ReadFile(path)
	s.content[s.id(path)] = string(b)
}

// stored is what a server stored in a file of the data directory: its
// content, and its name, or that it is gone. Nothing else's name.
func (s *shadow) stored(dir string, path string) {
	s.gone()
	m := s.dirs[s.id(dir)]
	if id := s.id(path); id >= 0 {
		s.keep(path)
		m[filepath.Base(path)] = id
	} else {
		delete(m, filepath.Base(path))
	}
}

// gone forgets the inodes that are no more: their numbers are given again.
func (s *shadow) gone() {
	live := map[uint64]bool{}
	_ = filepath.WalkDir(s.root, func(p string, _ fs.DirEntry, err error) error {
		if ino, ok := inode(p); err == nil && ok {
			live[ino] = true
		}
		return nil
	})
	for ino := range s.ids {
		if !live[ino] {
			delete(s.ids, ino)
		}
	}
}

func (s *shadow) event(e fsEvent) {
	if !strings.HasPrefix(e.path, s.root) && !strings.HasPrefix(e.to, s.root) {
		return
	}
	switch e.op {
	case "remove", "remove-all", "rename":
		s.gone()
	case "create", "mkdir":
		if ino, ok := inode(e.path); ok {
			delete(s.ids, ino)
			s.id(e.path)
		}
	case "sync":
		s.keep(e.path)
	case "sync-dir":
		s.entries(e.path)
	}
}

// cut is the power going: the directory becomes what was durable.
func (s *shadow) cut() {
	s.t.Helper()
	root := s.id(s.root)
	list, _ := os.ReadDir(s.root)
	dirs, content, isDir := s.dirs, s.content, s.isDir
	for _, e := range list {
		_ = os.RemoveAll(filepath.Join(s.root, e.Name()))
	}
	made := map[int]string{}
	var build func(dir string, id int)
	build = func(dir string, id int) {
		names := make([]string, 0, len(dirs[id]))
		for name := range dirs[id] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child, path := dirs[id][name], filepath.Join(dir, name)
			switch {
			case isDir[child]:
				_ = os.Mkdir(path, 0o700)
				build(path, child)
			case made[child] != "":
				_ = os.Link(made[child], path)
			default:
				_ = os.WriteFile(path, []byte(content[child]), 0o600)
				made[child] = path
			}
		}
	}
	build(s.root, root)
	s.ids, s.dirs, s.content, s.isDir = map[uint64]int{}, map[int]map[string]int{}, map[int]string{}, map[int]bool{}
	s.absorb()
}

// interrupted runs work with a kill after its nth point (counted over the
// run), and returns the point, "" when it ended before.
func interrupted(n int, work func(crash func(string) bool)) string {
	i, at := 0, ""
	work(func(p string) bool {
		if at != "" {
			return true
		}
		if i++; i == n {
			at = p
			return true
		}
		return false
	})
	return at
}

// Every point of an upgrade, and of its undo, killed and cut, with the
// reboot before the next run and without: the next run finishes or undoes
// it.
func TestAnUpgradeInterruptedAnywhere(t *testing.T) {
	for _, c := range []struct {
		name       string
		from       string
		badTo, wal bool
	}{
		{"done", standFrom, false, false},
		{"done, the old server killed", standFrom, false, true},
		{"undone", standFrom, true, false},
		{"undone, the servers killed", standFrom, true, true},
		{"from a release that reads no journal", oldFrom, false, false},
		{"from one, the old server killed", oldFrom, false, true},
		{"from one, undone", oldFrom, true, false},
		{"from one, undone, the servers killed", oldFrom, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for _, how := range []struct {
				name        string
				cut, reboot bool
			}{{"killed", false, false}, {"killed, rebooted", false, true}, {"cut", true, true}} {
				points := 0
				for n := 1; ; n++ {
					h := newStandHost(t, c.from, c.badTo, c.wal)
					at := interrupted(n, func(crash func(string) bool) {
						_, _ = h.upgrader(crash).Run(context.Background(), h.installed(), h.release())
					})
					if at == "" {
						// No such point: the run ended by itself.
						h.ends(how.name + ", not interrupted")
						if want := "varlatch " + map[bool]string{true: c.from, false: h.to}[c.badTo]; h.read(filepath.Join(h.bin, "varlatch")) != want {
							t.Fatalf("%s: not %s\n%s", how.name, want, h.tree())
						}
						break
					}
					points++
					what := fmt.Sprintf("%s at point %d (%s)", how.name, n, at)
					h.svc.write()
					if how.cut {
						h.shadow.cut()
					}
					if how.reboot {
						h.reboot()
					}
					h.canGoOn(what)
					// Read back after a reboot, Checked is for good: it serves.
					if j := h.journal(); how.reboot && j.Pending() && j.Reached(journal.Checked) && (h.svc.running != h.to || h.svc.held()) {
						t.Fatalf("%s: %q runs, held %v", what, h.svc.running, h.svc.held())
					}
					if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
						t.Fatalf("%s: %v\nfaults %q\n%s", what, err, h.svc.faults, h.tree())
					}
					h.ends(what)
					os.RemoveAll(h.dir)
				}
				if points < 25 {
					h := newStandHost(t, c.from, c.badTo, c.wal)
					_, err := h.upgrader(nil).Run(context.Background(), h.installed(), h.release())
					t.Fatalf("%s: only %d points; a run: %v", how.name, points, err)
				}
			}
		})
	}
}

// Interrupted, and the recovery interrupted too, at random points, up to
// four times.
func TestARecoveryInterruptedAnywhere(t *testing.T) {
	seed := time.Now().UnixNano()
	if testing.Short() {
		seed = 1
	}
	for w := range 4 {
		t.Run(fmt.Sprint(w), func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewSource(seed + int64(w)))
			for range 400 {
				h := newStandHost(t, []string{standFrom, oldFrom}[r.Intn(2)], r.Intn(2) == 0, r.Intn(2) == 0)
				var story []string
				again := func(work func(crash func(string) bool)) bool {
					at := interrupted(1+r.Intn(45), work)
					story = append(story, at)
					h.svc.write()
					if at != "" && r.Intn(2) == 0 {
						story = append(story, "cut")
						h.shadow.cut()
						h.reboot()
					} else if at != "" && r.Intn(2) == 0 {
						story = append(story, "reboot")
						h.reboot()
					}
					h.canGoOn(fmt.Sprintf("seed %d, %q", seed+int64(w), story))
					return at != ""
				}
				for i := 0; again(func(crash func(string) bool) {
					if i == 0 {
						_, _ = h.upgrader(crash).Run(context.Background(), h.installed(), h.release())
					} else {
						_, _ = h.upgrader(crash).Recover(context.Background())
					}
				}) && i < 3; i++ {
				}
				if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
					t.Fatalf("seed %d, %q: %v\nfaults %q\n%s", seed+int64(w), story, err, h.svc.faults, h.tree())
				}
				h.ends(fmt.Sprintf("seed %d, %q", seed+int64(w), story))
				os.RemoveAll(h.dir)
			}
		})
	}
}

// Where the file system has no hard links, the original's set is a synced
// copy, and what is put back too.
func TestAnUpgradeWithoutHardLinks(t *testing.T) {
	defer func(f func(fsys, string, string) error) { linkFile = f }(linkFile)
	linkFile = func(fsys, string, string) error {
		return &os.LinkError{Op: "link", Err: syscall.EPERM}
	}
	for _, c := range []struct {
		from  string
		badTo bool
	}{{standFrom, false}, {standFrom, true}, {oldFrom, false}, {oldFrom, true}} {
		for n := 1; ; n++ {
			h := newStandHost(t, c.from, c.badTo, true)
			at := interrupted(n, func(crash func(string) bool) {
				_, _ = h.upgrader(crash).Run(context.Background(), h.installed(), h.release())
			})
			if at != "" {
				h.shadow.cut()
				h.reboot()
				if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
					t.Fatalf("at %s: %v\n%s", at, err, h.tree())
				}
			}
			h.ends("without hard links, cut at " + at)
			os.RemoveAll(h.dir)
			if at == "" {
				break
			}
		}
	}
}

// The original's set gone when it must be there: nothing is put in its
// place, nothing is started, and the operator is told; with the set back,
// the next run undoes.
func TestAnUndoWithoutItsOriginal(t *testing.T) {
	h := newStandHost(t, standFrom, true, false)
	_ = interrupted(1, func(crash func(string) bool) {
		_, _ = h.upgrader(func(p string) bool { return p == "swapped" }).Run(context.Background(), h.installed(), h.release())
	})
	sets, _ := filepath.Glob(filepath.Join(h.data, "upgrades", "*", originalDir))
	if len(sets) != 1 {
		t.Fatalf("sets %q", sets)
	}
	aside := filepath.Join(h.dir, "aside")
	if err := os.Rename(sets[0], aside); err != nil {
		t.Fatal(err)
	}
	database := h.read(filepath.Join(h.data, databaseFile))
	j, err := h.upgrader(nil).Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Nothing was put in its place") || !strings.Contains(err.Error(), "Put the original database's files back into "+sets[0]) || j.State != journal.Failed {
		t.Fatalf("%+v, %v", j, err)
	}
	if h.svc.running != "" || h.read(filepath.Join(h.data, databaseFile)) != database {
		t.Fatalf("%s runs", h.svc.running)
	}
	h.reboot()
	if h.svc.running != "" {
		t.Fatalf("%s started on a database that is not its", h.svc.running)
	}
	if err := os.Rename(aside, sets[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.ends("with its original back")
}

// A restore made since is not undone over: the journal stays, and nothing
// changes.
func TestARestoreIsNotUndoneOver(t *testing.T) {
	for _, point := range []string{"stopped", "kept", "swapped"} {
		h := newStandHost(t, standFrom, false, false)
		_, _ = h.upgrader(func(p string) bool { return p == point }).Run(context.Background(), h.installed(), h.release())
		h.put(filepath.Join(h.data, holdFile), "{}", 0o644)
		before := h.tree()
		step := h.journal().Step
		j, err := h.upgrader(nil).Recover(context.Background())
		if point == "swapped" && (err == nil || !strings.Contains(err.Error(), "was restored from an archive") || !strings.Contains(err.Error(), "Nothing was changed")) {
			t.Fatalf("%s: %+v, %v", point, j, err)
		}
		if point == "swapped" && (!h.journal().Pending() || h.journal().Step != step || before != h.tree()) {
			t.Fatalf("%s: something changed:\n%s\n%s", point, before, h.tree())
		}
	}
}

// The start allowed is for its one start: an undo, whatever stopped it,
// leaves none allowed.
func TestAStartIsAllowedOnce(t *testing.T) {
	for point, want := range map[string]bool{"start:" + standTo: true, "started": true, "checked": true, "undo:stopped": false, "undo:files-back": false, "undo:binaries-back": false, "start:" + standFrom: true} {
		h := newStandHost(t, standFrom, point != "checked", false)
		_, err := h.upgrader(func(p string) bool { return p == point }).Run(context.Background(), h.installed(), h.release())
		if !errors.Is(err, errKilled) {
			t.Fatalf("%s: %v", point, err)
		}
		j := h.journal()
		if (j.Start != nil) != want || want && !j.Allows(strings.TrimPrefix(strings.NewReplacer("started", standTo, "checked", standTo).Replace(point), "start:"), "boot1") {
			t.Errorf("%s: %+v", point, j.Start)
		}
		if j.Allows(standTo, "boot2") || j.Allows(standFrom, "boot2") {
			t.Errorf("%s: a start after a reboot", point)
		}
	}
}

// Kept binaries that are not the ones recorded are neither run nor put in
// place; a cached one that is not the release's is replaced when staged.
func TestKeptBinariesAreTheRecordedOnes(t *testing.T) {
	h := newStandHost(t, standFrom, true, false)
	u := h.upgrader(nil)
	cached := filepath.Join(u.Releases(), standFrom, "varlatchd")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		t.Fatal(err)
	}
	h.put(cached, "another", 0o755)
	_, _ = h.upgrader(func(p string) bool { return p == "swapped" }).Run(context.Background(), h.installed(), h.release())
	if got := h.read(cached); got != standIn(standFrom, 1, standStatus(standFrom, 1)) {
		t.Fatalf("the cached binary stayed: %q", got)
	}
	h.put(cached, "another", 0o755)
	j, err := h.upgrader(nil).Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not the one the upgrade recorded") || j.State != journal.Failed || strings.Contains(h.read(filepath.Join(h.bin, "varlatchd")), "another") {
		t.Fatalf("%+v, %v", j, err)
	}
	if h.svc.running != "" {
		t.Fatalf("%s runs", h.svc.running)
	}
}

// A directory of binaries others may write is refused before anything.
func TestBinariesOthersMayWriteAreRefused(t *testing.T) {
	for _, what := range []string{"bin", "releases"} {
		h := newStandHost(t, standFrom, false, false)
		dir := h.bin
		if what == "releases" {
			dir = h.upgrader(nil).Releases()
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := h.upgrader(nil).Run(context.Background(), h.installed(), h.release()); err == nil || !strings.Contains(err.Error(), "may be written by others") || !strings.Contains(err.Error(), "nothing was changed") || h.journal() != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
}

// A journal that cannot be made durable is an error; at Checked, whose
// record is there, the upgrade is finished, never undone.
func TestAnUpgradeItsEndCannotBeRecorded(t *testing.T) {
	for _, point := range []string{"started", "checked"} {
		h := newStandHost(t, standFrom, false, false)
		armed := false
		u := h.upgrader(func(p string) bool {
			armed = armed || p == point
			return false
		})
		u.Fault = func(path string) error {
			if armed && filepath.Base(path) == journal.File {
				return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
			}
			return nil
		}
		j, err := u.Run(context.Background(), h.installed(), h.release())
		if point == "checked" {
			if err == nil || !strings.Contains(err.Error(), "its end could not be recorded") && !strings.Contains(err.Error(), "end could not be recorded") || j.State != journal.InProgress {
				t.Fatalf("%s: %+v, %v", point, j, err)
			}
			if h.svc.running != standTo {
				t.Fatalf("%s runs", h.svc.running)
			}
		}
		if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.ends(point)
	}
}

// A directory's sync that fails, each of them in turn, in an upgrade and in
// its undo (a name in place that a power cut may take back), then nothing, a
// reboot, or the cut: the next run finishes or undoes it.
func TestAnUpgradeWhoseSyncsFail(t *testing.T) {
	for _, c := range []struct {
		from  string
		badTo bool
	}{{standFrom, false}, {standFrom, true}, {oldFrom, false}, {oldFrom, true}} {
		for _, how := range []string{"left", "reboot", "cut"} {
			t.Run(fmt.Sprint(c.from, " undone ", c.badTo, " ", how), func(t *testing.T) {
				t.Parallel()
				for n := 1; ; n++ {
					h := newStandHost(t, c.from, c.badTo, true)
					syncs, at := 0, ""
					u := h.upgrader(nil)
					u.Fault = func(path string) error {
						if !strings.HasSuffix(path, "/") {
							return nil
						}
						if syncs++; syncs == n {
							at = strings.TrimPrefix(path, h.dir)
							return syscall.EIO
						}
						return nil
					}
					_, err := u.Run(context.Background(), h.installed(), h.release())
					if at == "" {
						break
					}
					what := fmt.Sprintf("sync %d (%s), %v", n, at, err)
					h.svc.write()
					switch how {
					case "cut":
						h.shadow.cut()
						h.reboot()
					case "reboot":
						h.reboot()
					}
					h.canGoOn(what)
					if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
						t.Fatalf("%s: %v\nfaults %q\n%s", what, err, h.svc.faults, h.tree())
					}
					h.ends(what)
					os.RemoveAll(h.dir)
				}
			})
		}
	}
}

// A record that is not known to be durable ends the run there: no step that
// relies on it, nor its undo, until it is.
func TestARecordThatIsNotDurableEndsTheRun(t *testing.T) {
	for _, step := range []journal.Step{journal.Stopping, journal.Kept, journal.Installed, journal.Swapped, journal.Started} {
		h := newStandHost(t, standFrom, false, true)
		u := h.upgrader(nil)
		armed := false
		u.Fault = func(path string) error {
			if path == filepath.Dir(h.conf)+"/" && h.journal() != nil && h.journal().Step == step {
				armed = true
			}
			if armed && path == filepath.Dir(h.conf)+"/" {
				return syscall.EIO
			}
			return nil
		}
		database := ""
		j, err := u.Run(context.Background(), h.installed(), h.release())
		if err == nil || !strings.Contains(err.Error(), "could not be made durable") || !strings.Contains(err.Error(), "run sudo varlatch upgrade") || j.Reached(step) {
			t.Fatalf("%s: %+v, %v", step, j, err)
		}
		// Nothing of an undo either: what is in place is what the run had put
		// there, and the record is the one it made.
		schema := map[bool]string{true: "schema 2\n", false: "schema 1\n"}[step == journal.Swapped || step == journal.Started]
		if !strings.Contains(h.read(filepath.Join(h.data, databaseFile)), schema) || h.journal().Step != step || h.journal().Undo != journal.UndoNone {
			t.Fatalf("%s: %+v\n%s", step, h.journal(), h.tree())
		}
		database = h.read(filepath.Join(h.data, databaseFile)) + h.read(filepath.Join(h.data, databaseFile+walSuffix))
		// Nor does a recovery, until it can make it durable.
		u = h.upgrader(nil)
		u.Fault = func(path string) error {
			if path == filepath.Dir(h.conf)+"/" {
				return syscall.EIO
			}
			return nil
		}
		if _, err := u.Recover(context.Background()); err == nil || !strings.Contains(err.Error(), "could not be made durable") {
			t.Fatalf("%s: a recovery: %v", step, err)
		}
		if now := h.read(filepath.Join(h.data, databaseFile)) + h.read(filepath.Join(h.data, databaseFile+walSuffix)); !strings.HasPrefix(now, database) || step != journal.Stopping && now != database {
			// (A server that was not stopped yet takes writes.)
			t.Fatalf("%s: the database changed: %q, %q", step, database, now)
		}
		if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		h.ends(string(step))
	}
}

// What a killed run started holds the upgrade lock until it has ended: no
// recovery goes on beside it.
func TestWhatAKilledRunStartedHoldsTheLock(t *testing.T) {
	h := newStandHost(t, standFrom, false, false)
	u := &Upgrader{BinDir: h.bin, ConfigPath: h.conf}
	programs := t.TempDir() // /dev/shm may run none
	program := func(name, text string) string {
		p := filepath.Join(programs, name)
		h.put(p, "#!/bin/sh\n"+text, 0o755)
		return p
	}
	if _, err := u.hold(); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(filepath.Dir(h.conf), "upgrade.lock")
	end := filepath.Join(h.dir, "end")
	cmd := exec.Command(program("slow", "while [ ! -e "+end+" ]; do sleep 0.02; done\n"))
	u.bind(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// So does a varlatchd (the data directory's child is bound as this is).
	out, err := u.admin(context.Background(), program("varlatchd", "readlink /proc/self/fd/3\n"), "admin")
	if err != nil || strings.TrimSpace(string(out)) != locked {
		t.Fatalf("%q, %v", out, err)
	}
	// The run is killed: its own descriptor goes.
	u.held.Close()
	if _, err := lock(filepath.Dir(h.conf)); err == nil || !strings.Contains(err.Error(), "a command that a killed one started") {
		t.Fatalf("the lock is free: %v", err)
	}
	h.put(end, "", 0o600)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	f, err := lock(filepath.Dir(h.conf))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// Nothing is run, and nothing made, where another than root could have
// changed what it is.
func TestNothingIsRunThatOthersMayChange(t *testing.T) {
	for _, c := range []struct {
		name string
		make func(h *standHost)
	}{
		{"varlatchd is a link to what others may replace", func(h *standHost) {
			open := filepath.Join(h.dir, "open")
			if err := os.Mkdir(open, 0o700); err != nil {
				t.Fatal(err)
			}
			h.put(filepath.Join(open, "varlatchd"), "#!/bin/sh\n: >"+filepath.Join(h.dir, "ran")+"\n", 0o755)
			if err := os.Chmod(open, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(h.bin, "varlatchd")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(open, "varlatchd"), filepath.Join(h.bin, "varlatchd")); err != nil {
				t.Fatal(err)
			}
		}},
		{"varlatchd may be written by others", func(h *standHost) { _ = os.Chmod(filepath.Join(h.bin, "varlatchd"), 0o777) }},
		{"the releases' parent may be", func(h *standHost) {
			_ = os.Mkdir(filepath.Join(h.dir, "usr", "lib"), 0o700)
			_ = os.Chmod(filepath.Join(h.dir, "usr", "lib"), 0o777)
		}},
		{"the journal's directory may be", func(h *standHost) { _ = os.Chmod(filepath.Dir(h.conf), 0o777) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newStandHost(t, standFrom, false, false)
			c.make(h)
			before := h.tree()
			for what, run := range map[string]func(u *Upgrader) error{
				"inspect": func(u *Upgrader) error { _, err := u.Inspect(context.Background()); return err },
				"run":     func(u *Upgrader) error { _, err := u.Run(context.Background(), h.installed(), h.release()); return err },
				"recover": func(u *Upgrader) error { _, err := u.Recover(context.Background()); return err },
			} {
				u := h.upgrader(nil)
				u.run = nil
				if err := run(u); err == nil || !strings.Contains(err.Error(), "may be written by others") {
					t.Errorf("%s: %v", what, err)
				}
			}
			if after := h.tree(); after != before || exists(filepath.Join(h.dir, "ran")) || exists(filepath.Join(h.dir, "usr", "lib", "varlatch")) || exists(filepath.Join(filepath.Dir(h.conf), "upgrade.lock")) {
				t.Errorf("something was run or made:\n%s", after)
			}
		})
	}
}

// An upgrade an earlier release's varlatch left pending (format 1), at each
// place its swap could have stopped: undone while the original is in its
// place, and, once another database is, which that engine's start may have
// had serve, finished.
func TestAPendingUpgradeOfFormatOne(t *testing.T) {
	copyOf := "db original\nschema 2\nwrite 1\nwrite 2\n"
	aside := func(h *standHost, work string, names ...string) {
		_ = os.MkdirAll(filepath.Join(work, "original"), 0o700)
		for _, n := range names {
			_ = os.Rename(filepath.Join(h.data, n), filepath.Join(work, "original", n))
		}
	}
	swapped := func(h *standHost, work string) {
		aside(h, work, databaseFile, databaseFile+walSuffix)
		h.put(filepath.Join(h.data, databaseFile), copyOf, 0o600)
	}
	installed := func(h *standHost) {
		h.put(filepath.Join(h.bin, "varlatchd"), standIn(h.to, 2, standStatus(h.to, 2)), 0o755)
		h.put(filepath.Join(h.bin, "varlatch"), "varlatch "+h.to, 0o755)
	}
	for _, c := range []struct {
		name string
		step journal.Step
		make func(h *standHost, work string)
		done bool
	}{
		{"stopped", journal.Stopped, func(*standHost, string) {}, false},
		{"prepared", journal.Prepared, func(h *standHost, work string) {
			_ = os.MkdirAll(filepath.Join(work, "db"), 0o700)
			h.put(filepath.Join(work, "db", databaseFile), copyOf, 0o600)
		}, false},
		{"the database aside, its log not", journal.Prepared, func(h *standHost, work string) { aside(h, work, databaseFile) }, false},
		{"both aside", journal.Prepared, func(h *standHost, work string) { aside(h, work, databaseFile, databaseFile+walSuffix) }, false},
		{"a move left with both names", journal.Prepared, func(h *standHost, work string) {
			aside(h, work, databaseFile, databaseFile+walSuffix)
			for _, n := range []string{databaseFile, databaseFile + walSuffix} {
				_ = os.Link(filepath.Join(work, "original", n), filepath.Join(h.data, n))
			}
		}, false},
		{"an undo stopped after the database", journal.Started, func(h *standHost, work string) {
			aside(h, work, databaseFile+walSuffix)
			installed(h)
		}, false},
		{"swapped, not recorded, the old binaries in place", journal.Prepared, swapped, true},
		{"swapped, not recorded, one binary in place", journal.Prepared, func(h *standHost, work string) {
			swapped(h, work)
			h.put(filepath.Join(h.bin, "varlatchd"), standIn(h.to, 2, standStatus(h.to, 2)), 0o755)
		}, true},
		{"swapped", journal.Swapped, func(h *standHost, work string) { swapped(h, work); installed(h) }, true},
		{"started, writes taken, the server killed", journal.Started, func(h *standHost, work string) {
			swapped(h, work)
			installed(h)
			_ = h.svc.Start(context.Background())
			h.svc.write()
			h.svc.write()
			h.svc.running = ""
		}, true},
		{"started, writes taken, the server stopped", journal.Started, func(h *standHost, work string) {
			swapped(h, work)
			installed(h)
			_ = h.svc.Start(context.Background())
			h.svc.write()
			h.svc.killed = false
			_ = h.svc.Stop(context.Background())
		}, true},
		{"started and serving", journal.Started, func(h *standHost, work string) {
			swapped(h, work)
			installed(h)
			_ = h.svc.Start(context.Background())
			h.svc.write()
		}, true},
	} {
		// To a release that holds still for the journal, and to one that does
		// not (it takes writes whenever it runs).
		for _, to := range []string{standTo, oldFrom} {
			t.Run(c.name+", to "+to, func(t *testing.T) {
				from := "0.50.0-rc.2"
				build := func() (*standHost, string) {
					h := newStandHost(t, from, false, true)
					h.to = to
					_ = h.svc.Stop(context.Background())
					u := h.upgrader(nil)
					work := filepath.Join(h.data, "upgrades", "0011223344556677")
					if err := os.MkdirAll(work, 0o700); err != nil {
						t.Fatal(err)
					}
					for v, schema := range map[string]int{from: 1, to: 2} {
						kept := filepath.Join(u.Releases(), v)
						if err := os.MkdirAll(kept, 0o755); err != nil {
							t.Fatal(err)
						}
						h.put(filepath.Join(kept, "varlatchd"), standIn(v, schema, standStatus(v, schema)), 0o755)
						h.put(filepath.Join(kept, "varlatch"), "varlatch "+v, 0o755)
					}
					if err := journal.Write(filepath.Dir(h.conf), &journal.Journal{Format: journal.FormatOne, ID: "0011223344556677", From: from, To: to, FromSchema: 1, ToSchema: 2,
						State: journal.InProgress, Step: c.step, StartedAt: "2026-11-24T10:00:00Z", BinDir: h.bin, Releases: u.Releases(), DataDir: h.data, Work: work, Snapshot: "/s"}); err != nil {
						t.Fatal(err)
					}
					c.make(h, work)
					h.shadow.absorb()
					return h, work
				}
				// Recovered, at once and with the recovery interrupted
				// anywhere, killed or cut.
				for n := 0; ; n++ {
					h, _ := build()
					at := ""
					if n > 0 {
						if at = interrupted(n, func(crash func(string) bool) { _, _ = h.upgrader(crash).Recover(context.Background()) }); at == "" {
							break
						}
						if n%2 == 0 {
							h.shadow.cut()
						}
						// (That release makes an empty database where it finds
						// none: there is one in its place then.)
						if exists(filepath.Join(h.data, databaseFile)) {
							h.reboot()
						}
					}
					j, err := h.upgrader(nil).Recover(context.Background())
					if err != nil {
						t.Fatalf("at %s: %+v, %v\n%s", at, j, err, h.tree())
					}
					if on := h.journal(); on.Format != journal.FormatOne || (on.State == journal.Done) != c.done {
						t.Fatalf("at %s: %+v", at, on)
					}
					h.ends("at " + at)
					os.RemoveAll(h.dir)
				}
				if !c.done {
					return
				}
				// A new release that does not serve: nothing of either database
				// goes, and the way back, by hand, is the one printed.
				h, work := build()
				bad := standIn(to, 2, strings.Replace(standStatus(to, 2), `"rootKek":true`, `"rootKek":false`, 1))
				h.put(filepath.Join(h.upgrader(nil).Releases(), to, "varlatchd"), bad, 0o755)
				h.put(filepath.Join(h.bin, "varlatchd"), bad, 0o755)
				_ = h.svc.Stop(context.Background())
				inPlace, original := h.database(), h.read(filepath.Join(work, "original", databaseFile))+h.read(filepath.Join(work, "original", databaseFile+walSuffix))
				for range 2 {
					j, err := h.upgrader(nil).Recover(context.Background())
					if err == nil || j.State != journal.Failed || !strings.Contains(err.Error(), "Both databases are kept") || !strings.Contains(err.Error(), "sudo systemctl start varlatchd") {
						t.Fatalf("%+v, %v", j, err)
					}
					if !strings.HasPrefix(h.database(), inPlace) || h.read(filepath.Join(work, "original", databaseFile))+h.read(filepath.Join(work, "original", databaseFile+walSuffix)) != original {
						t.Fatalf("a database changed: %q\n%s", inPlace, h.tree())
					}
					if h.svc.running != "" {
						t.Fatalf("%s runs", h.svc.running)
					}
				}
				for _, line := range h.upgrader(nil).backByHand(h.journal()) {
					line = strings.TrimPrefix(line, "sudo ")
					if !strings.HasPrefix(line, "systemctl ") {
						if out, err := exec.Command("sh", "-c", line).CombinedOutput(); err != nil {
							t.Fatalf("%s: %v %s", line, err, out)
						}
					}
				}
				if h.journal() != nil || h.read(filepath.Join(h.data, databaseFile))+h.read(filepath.Join(h.data, databaseFile+walSuffix)) != original {
					t.Fatalf("by hand:\n%s", h.tree())
				}
				if err := h.svc.Start(context.Background()); err != nil || h.svc.running != from {
					t.Fatalf("%v, %s runs", err, h.svc.running)
				}
			})
		}
	}
}

// newUpgradedHost is a host upgraded from standFrom to standTo, with a
// write after it.
func newUpgradedHost(t *testing.T, keeps, badFrom, wal bool) *standHost {
	t.Helper()
	h := newStandHost(t, standFrom, false, wal)
	h.keeps = keeps
	if badFrom {
		// What it answers is asked for the first time after its rollback.
		_ = h.svc.Stop(context.Background())
		h.put(filepath.Join(h.bin, "varlatchd"), standIn(standFrom, 1, strings.Replace(standStatus(standFrom, 1), `"rootKek":true`, `"rootKek":false`, 1)), 0o755)
		_ = h.svc.Start(context.Background())
		h.shadow.absorb()
	}
	if j, err := h.upgrader(nil).Run(context.Background(), h.installed(), h.release()); err != nil || j.State != journal.Done {
		t.Fatalf("the upgrade: %+v, %v\n%s", j, err, h.tree())
	}
	h.svc.write()
	// Long ago, to a power cut now.
	h.shadow.absorb()
	return h
}

// rollback plans and runs a rollback.
func (h *standHost) rollback(crash func(string) bool) (*journal.Journal, error) {
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		return nil, err
	}
	if plan.Safe != h.keeps {
		h.t.Fatalf("plan %+v", plan)
	}
	// More writes than the plan lists are made before the stop, as a rule.
	return h.upgrader(crash).Rollback(context.Background(), plan, func(*Changes) (bool, error) { return true, nil })
}

// Every point of a rollback, and of its undo, killed and cut, with the
// reboot before the next run and without: the next run finishes or undoes
// it, and an undone one can be run again.
func TestARollbackInterruptedAnywhere(t *testing.T) {
	for _, c := range []struct {
		name                string
		keeps, badFrom, wal bool
	}{
		{"the database kept", true, false, false},
		{"the database kept, the servers killed", true, false, true},
		{"the database kept, undone", true, true, true},
		{"the snapshot restored", false, false, false},
		{"the snapshot restored, the servers killed", false, false, true},
		{"the snapshot restored, undone", false, true, false},
		{"the snapshot restored, undone, the servers killed", false, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for _, how := range []struct {
				name        string
				cut, reboot bool
			}{{"killed", false, false}, {"killed, rebooted", false, true}, {"cut", true, true}} {
				points := 0
				for n := 1; ; n++ {
					h := newUpgradedHost(t, c.keeps, c.badFrom, c.wal)
					at := interrupted(n, func(crash func(string) bool) {
						if j, err := h.rollback(crash); err != nil && !errors.Is(err, errKilled) && !c.badFrom {
							t.Fatalf("%+v, %v\n%s", j, err, h.tree())
						}
					})
					if at == "" {
						h.ends(how.name + ", not interrupted")
						if undone := h.journal().Kind == journal.Upgrade; undone != c.badFrom {
							t.Fatalf("%s: %+v", how.name, h.journal())
						}
						break
					}
					points++
					what := fmt.Sprintf("%s at point %d (%s)", how.name, n, at)
					h.svc.write()
					if how.cut {
						h.shadow.cut()
					}
					if how.reboot {
						h.reboot()
					}
					h.canGoOn(what)
					if j := h.journal(); how.reboot && j.Pending() && j.Reached(journal.Checked) && (h.svc.running != j.To || h.svc.held()) {
						t.Fatalf("%s: %q runs, held %v", what, h.svc.running, h.svc.held())
					}
					if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
						t.Fatalf("%s: %v\nfaults %q\n%s", what, err, h.svc.faults, h.tree())
					}
					h.ends(what)
					if j := h.journal(); j.Kind == journal.Upgrade && !c.badFrom {
						if j, err := h.rollback(nil); err != nil || j.State != journal.Done {
							t.Fatalf("%s: again: %+v, %v\n%s", what, j, err, h.tree())
						}
						h.ends(what + ", again")
					}
					os.RemoveAll(h.dir)
				}
				if least := map[bool]int{true: 12, false: 26}[c.keeps]; points < least {
					t.Fatalf("%s: only %d points", how.name, points)
				}
			}
		})
	}
}

// Interrupted, and the recovery interrupted too, at random points, then
// rolled back again.
func TestARollbacksRecoveryInterruptedAnywhere(t *testing.T) {
	seed := time.Now().UnixNano()
	if testing.Short() {
		seed = 1
	}
	for w := range 4 {
		t.Run(fmt.Sprint(w), func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewSource(seed + int64(w)))
			for range 300 {
				bad := r.Intn(2) == 0
				h := newUpgradedHost(t, r.Intn(3) == 0, bad, r.Intn(2) == 0)
				var story []string
				for i := 0; i < 4; i++ {
					at := interrupted(1+r.Intn(50), func(crash func(string) bool) {
						if j := h.journal(); j.Kind == journal.Upgrade && j.State == journal.Done {
							_, _ = h.rollback(crash)
						} else {
							_, _ = h.upgrader(crash).Recover(context.Background())
						}
					})
					story = append(story, at)
					h.svc.write()
					if at != "" && r.Intn(2) == 0 {
						story = append(story, "cut")
						h.shadow.cut()
						h.reboot()
					} else if at != "" && r.Intn(2) == 0 {
						story = append(story, "reboot")
						h.reboot()
					}
				}
				if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
					t.Fatalf("seed %d, %q: %v\nfaults %q\n%s", seed+int64(w), story, err, h.svc.faults, h.tree())
				}
				h.ends(fmt.Sprintf("seed %d, %q", seed+int64(w), story))
				os.RemoveAll(h.dir)
			}
		})
	}
}

// A rollback whose stop cannot be recorded stops nothing, and leaves the
// upgrade's record.
func TestARollbackThatCannotRecordTheStopChangesNothing(t *testing.T) {
	h := newUpgradedHost(t, false, false, false)
	plan, err := h.upgrader(nil).PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u := h.upgrader(nil)
	u.Fault = func(path string) error {
		if filepath.Base(path) == journal.File {
			return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
		}
		return nil
	}
	if _, err := u.Rollback(context.Background(), plan, nil); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatal(err)
	}
	if h.svc.running != standTo || h.journal().ID != plan.Last.ID || h.journal().LastRollback != nil {
		t.Fatalf("%s runs, %+v", h.svc.running, h.journal())
	}
	h.ends("a stop that cannot be recorded")
}

// A directory's sync that fails in a rollback, or in its undo, each in turn.
func TestARollbackWhoseSyncsFail(t *testing.T) {
	for _, c := range []struct{ keeps, badFrom bool }{{true, false}, {true, true}, {false, false}, {false, true}} {
		for _, how := range []string{"left", "reboot", "cut"} {
			t.Run(fmt.Sprint("keeps ", c.keeps, " undone ", c.badFrom, " ", how), func(t *testing.T) {
				t.Parallel()
				for n := 1; ; n++ {
					h := newUpgradedHost(t, c.keeps, c.badFrom, true)
					plan, err := h.upgrader(nil).PlanRollback(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					syncs, at := 0, ""
					u := h.upgrader(nil)
					u.Fault = func(path string) error {
						if !strings.HasSuffix(path, "/") {
							return nil
						}
						if syncs++; syncs == n {
							at = strings.TrimPrefix(path, h.dir)
							return syscall.EIO
						}
						return nil
					}
					_, err = u.Rollback(context.Background(), plan, func(*Changes) (bool, error) { return true, nil })
					if at == "" {
						break
					}
					what := fmt.Sprintf("sync %d (%s), %v", n, at, err)
					h.svc.write()
					switch how {
					case "cut":
						h.shadow.cut()
						h.reboot()
					case "reboot":
						h.reboot()
					}
					h.canGoOn(what)
					if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
						t.Fatalf("%s: %v\nfaults %q\n%s", what, err, h.svc.faults, h.tree())
					}
					h.ends(what)
					os.RemoveAll(h.dir)
				}
			})
		}
	}
}
