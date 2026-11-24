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
	"path/filepath"
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
	from           string
	badTo          bool // To fails its health checks
	svc            *standService
	boots          int
	shadow         *shadow
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
		h.put(archive, h.read(filepath.Join(h.data, databaseFile)), 0o600)
		return fmt.Appendf(nil, `{"path":%q,"createdAt":"2026-11-24T00:00:00Z"}`, archive), nil
	case "schema upgrade":
		f := args[len(args)-1]
		content, log := h.read(f), h.read(f+walSuffix)
		if log != "" {
			if !strings.HasPrefix(log, "wal original "+fmt.Sprint(strings.Count(content, "write"))+"\n") {
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

func standStatus(version string, schema int) string {
	return fmt.Sprintf(`{"version":"%s","schemaVersion":%d,"serving":true,"ready":{"schema":true,"rootKek":true,"installation":true}}`, version, schema)
}

func newStandHost(t *testing.T, from string, badTo, wal bool) *standHost {
	t.Helper()
	dir, err := os.MkdirTemp("", "vl-upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &standHost{t: t, dir: dir, bin: filepath.Join(dir, "usr", "bin"), data: filepath.Join(dir, "data"), conf: filepath.Join(dir, "etc", "varlatchd.conf"), from: from, badTo: badTo, boots: 1}
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
	h.shadow = newShadow(t, h.data)
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
	m, err := release.NewManifest(standTo, release.Declaration{SchemaVersion: 2, CompatibleFrom: 1, RollbackSafe: true,
		Previous: &release.Previous{Version: h.from, SchemaVersion: 1}, ReversibleTo: &reversible})
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
	return &Upgrader{BinDir: h.bin, ConfigPath: h.conf, Service: h.svc, HealthTimeout: time.Nanosecond, Crash: crash,
		trace: h.shadow.event, run: h.run, boot: func() string { return fmt.Sprint("boot", h.boots) }}
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
	faults  []string
}

func (s *standService) fault(format string, a ...any) {
	s.faults = append(s.faults, fmt.Sprintf(format, a...))
}

// refusal is why varlatchd of version does not start: the upgrade journal
// (slice A3), for a release that reads it.
func (s *standService) refusal(version string) error {
	if order, _ := release.CompareVersions(version, journal.FormatSince); order < 0 {
		return nil
	}
	j := s.h.journal()
	if j.Holds() && !j.Allows(version, fmt.Sprint("boot", s.h.boots)) {
		return errors.New("an upgrade is not over")
	}
	return nil
}

// held is whether the running varlatchd answers 503: started as the journal
// allows, not yet checked.
func (s *standService) held() bool {
	if order, _ := release.CompareVersions(s.running, journal.FormatSince); order < 0 {
		return false
	}
	return s.h.journal().Holds()
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
	if log := s.h.read(wal); log != "" && !strings.HasPrefix(log, "wal original "+fmt.Sprint(strings.Count(content, "write"))+"\n") {
		s.fault("%s started on a database with another's log: %q beside %q", version, log, content)
	}
	if !strings.Contains(content, fmt.Sprintf("schema %d\n", schema)) {
		return errors.New("the schema is not this release's")
	}
	s.running = version
	return nil
}

// write is a client's write, stored in the log, when it is accepted.
func (s *standService) write() {
	if s.running == "" || s.held() {
		return
	}
	s.writes++
	wal := filepath.Join(s.h.data, databaseFile+walSuffix)
	log := s.h.read(wal)
	if log == "" {
		log = fmt.Sprintf("wal original %d\n", strings.Count(s.h.read(filepath.Join(s.h.data, databaseFile)), "write"))
	}
	s.h.put(wal, log+fmt.Sprintf("write %d\n", s.writes+1), 0o600)
	if s.h.shadow != nil {
		s.h.shadow.stored(s.h.data, wal)
	}
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
			s.h.shadow.stored(s.h.data, db)
		}
	}
	return nil
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
	if j != nil && j.State == journal.Done {
		version, schema = standTo, 2
	}
	if j.Pending() {
		fail("not over")
	}
	if h.svc.running != version {
		fail("%q serves, not %s", h.svc.running, version)
	}
	content := h.read(filepath.Join(h.data, databaseFile)) + h.read(filepath.Join(h.data, databaseFile+walSuffix))
	if !strings.HasPrefix(content, fmt.Sprintf("db original\nschema %d\n", schema)) {
		fail("the database is %q", content)
	}
	for n := 1; n <= h.svc.writes+1; n++ {
		if strings.Count(content, fmt.Sprintf("write %d\n", n)) != 1 {
			fail("write %d of %d is not there once: %q", n, h.svc.writes+1, content)
		}
	}
	// An undo to a release that reads no journal ends with the journal set
	// aside: what it tidies after, and the older varlatch, are not missed.
	if j == nil && h.from == oldFrom {
		return
	}
	if got := h.read(filepath.Join(h.bin, "varlatch")); got != "varlatch "+version {
		fail("varlatch is %q", got)
	}
	for _, name := range []string{copyDir, originalDir, copyDir + makingDir, originalDir + makingDir} {
		if left, _ := filepath.Glob(filepath.Join(h.data, "upgrades", "*", name)); len(left) > 0 {
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

// stored is what a server stored: its files' content, and its names.
func (s *shadow) stored(dir string, path string) {
	s.gone()
	s.keep(path)
	m := s.dirs[s.id(dir)]
	for _, name := range []string{databaseFile, databaseFile + walSuffix} {
		if id := s.id(filepath.Join(dir, name)); id >= 0 {
			m[name] = id
		} else {
			delete(m, name)
		}
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
					if _, err := h.upgrader(nil).Recover(context.Background()); err != nil {
						t.Fatalf("%s: %v\nfaults %q\n%s", what, err, h.svc.faults, h.tree())
					}
					h.ends(what)
					os.RemoveAll(h.dir)
				}
				if points < 25 {
					t.Fatalf("%s: only %d points", how.name, points)
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
			for range 60 {
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
