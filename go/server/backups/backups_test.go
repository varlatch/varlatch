// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/maintenance"
)

type fixture struct {
	dir     string
	cfg     *config.Config
	store   *storage.DB
	rootKEK []byte
	bek     []byte
	inst    string
	now     time.Time
	mu      sync.Mutex
}

func (f *fixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) add(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureIn(t, t.TempDir())
}

// newFixtureIn is newFixture with its data directory at dir.
func newFixtureIn(t *testing.T, dir string) *fixture {
	t.Helper()
	f := &fixture{dir: dir, rootKEK: envelope.GenerateKey(), bek: envelope.GenerateKey(), inst: ids.New(ids.Installation), now: time.Now().UTC().Truncate(time.Millisecond)}
	keyFile := filepath.Join(dir, "bek")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(f.bek)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.cfg = &config.Config{Listen: "127.0.0.1:8686", DataDir: dir, AccessLog: "off", Sync: true, BackupKeyFile: keyFile,
		BackupInterval: 24 * time.Hour, BackupKeep: 2, BackupDestination: "offsite"}
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: f.cfg.DatabasePath()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = store
	if _, err := db.Init(ctx, store, "0.50.0-test"); err != nil {
		t.Fatal(err)
	}
	canary, err := envelope.NewCanary(f.rootKEK, f.inst)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(canary)
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		return query.New(tx).CreateInstallation(ctx, query.CreateInstallationParams{ID: f.inst, KekCanary: string(raw)})
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) service(mod func(*Options)) *Service {
	o := Options{Config: f.cfg, Store: f.store, RootKEK: f.rootKEK, Now: f.clock, SealRate: -1,
		Snapshot: storage.SnapshotOptions{StepPages: 64, Pause: time.Millisecond}, Log: slog.New(slog.DiscardHandler)}
	if mod != nil {
		mod(&o)
	}
	return New(o)
}

func (f *fixture) exec(t *testing.T, stmt string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := f.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, stmt, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// One run: the archive is a format-3 archive of the snapshot and the
// configuration, sealed with the BEK; it opens, its canary opens with the
// Root KEK, the snapshot is the database, and its status record says it
// was checked. Its temporary files are gone.
func TestRun(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE marker (v TEXT) STRICT")
	f.exec(t, "INSERT INTO marker VALUES ('before the snapshot')")
	s := f.service(nil)
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != filepath.Join(f.dir, Dir, res.ArchiveID+".vltbak") || res.Delivery != nil || res.UploadError != "" || len(res.Removed) != 0 {
		t.Errorf("%+v", res)
	}
	if !res.Verification.Integrity || !res.Verification.Compatibility || !res.Verification.KeyMatch || res.Verification.TargetRelease != buildinfo.Version {
		t.Errorf("verification %+v", res.Verification)
	}
	if res.Capture.Mode != "online" || res.Capture.DumpBytes == 0 {
		t.Errorf("capture %+v", res.Capture)
	}
	bek, _ := backup.KeyBEK(f.bek)
	o, err := backup.Open(res.Path, bek, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	m := o.Manifest
	r, _ := m.GoRelease()
	if m.FormatVersion != backup.FormatGo || m.ArchiveID != res.ArchiveID || m.InstallationID != f.inst || m.CreatedAt != res.CreatedAt ||
		r != (backup.GoRelease{Version: buildinfo.Version, APIMajor: 1, DatabaseSchema: db.SchemaVersion}) || len(m.RequiredKeyVersions) != 1 || m.RequiredKeyVersions[0] != 1 {
		t.Errorf("manifest %s", o.ManifestJSON)
	}
	if !backup.CheckKeys(m, map[int][]byte{1: f.rootKEK}) {
		t.Error("the canary does not open with the Root KEK")
	}
	snap, err := sql.Open("sqlite", fileURI(o.Path(backup.ComponentDatabase))+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var v string
	if err := snap.QueryRow("SELECT v FROM marker").Scan(&v); err != nil || v != "before the snapshot" {
		t.Errorf("the snapshot: %q %v", v, err)
	}
	snap.Close()
	var conf Configuration
	raw, _ := os.ReadFile(o.Path(backup.ComponentConfiguration))
	if err := json.Unmarshal(raw, &conf); err != nil || conf.FormatVersion != 1 || conf.Settings["listen"] != "127.0.0.1:8686" || conf.Settings["backup_keep"] != "2" {
		t.Errorf("configuration %s", raw)
	}
	for _, leak := range []string{f.dir, "bek", "root_kek", "data_dir", hex.EncodeToString(f.bek)} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("the configuration holds %q: %s", leak, raw)
		}
	}
	st, err := s.Status()
	if err != nil || len(st.Archives) != 1 || st.Archives[0].ArchiveID != res.ArchiveID || st.Archives[0].Release != buildinfo.Version {
		t.Fatalf("%+v %v", st, err)
	}
	// Checked, but not delivered: no destination is configured.
	if strings.Join(st.Warnings, "|") != "Newest archive "+res.ArchiveID+" has not been delivered to a destination" {
		t.Errorf("warnings %q", st.Warnings)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dir, Dir))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != res.ArchiveID+".json "+res.ArchiveID+".vltbak" {
		t.Errorf("the backups directory holds %v", names)
	}
	if info, _ := os.Stat(res.Path); info.Mode().Perm() != 0o600 {
		t.Errorf("archive mode %v", info.Mode())
	}
	js, err := s.StatusJSON()
	if err != nil || !bytes.HasPrefix(js, []byte(`{"archives":[{"archiveId":"`+res.ArchiveID+`","installationId":"`+f.inst+`"`)) {
		t.Errorf("status JSON %s %v", js, err)
	}
}

// Local retention keeps the newest backup_keep archives; the status
// records stay.
func TestRetention(t *testing.T) {
	f := newFixture(t)
	s := f.service(nil)
	var ids []string
	for i := 0; i < 4; i++ {
		res, err := s.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, res.ArchiveID)
		if want := max(0, i+1-2); len(res.Removed) != min(1, want) {
			t.Errorf("run %d removed %v", i, res.Removed)
		}
		f.add(time.Hour)
	}
	for i, id := range ids {
		_, err := os.Stat(filepath.Join(f.dir, Dir, id+".vltbak"))
		if kept := i >= 2; kept != (err == nil) {
			t.Errorf("archive %d: kept %t, %v", i, kept, err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, Dir, id+".json")); err != nil {
			t.Errorf("archive %d's status record: %v", i, err)
		}
	}
	if st, _ := s.Status(); len(st.Archives) != 4 || st.Archives[0].ArchiveID != ids[3] {
		t.Errorf("%+v", st.Archives)
	}
}

// What a run refuses before it writes anything.
func TestRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	empty := func(t *testing.T) {
		t.Helper()
		entries, _ := os.ReadDir(filepath.Join(f.dir, Dir))
		if len(entries) != 0 {
			t.Errorf("a refused run left %d files", len(entries))
		}
	}
	noKey := *f.cfg
	noKey.BackupKeyFile = ""
	if _, err := New(Options{Config: &noKey, Store: f.store, RootKEK: f.rootKEK}).Run(ctx); !errors.Is(err, ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
	same := filepath.Join(f.dir, "same")
	os.WriteFile(same, []byte(hex.EncodeToString(f.rootKEK)), 0o600)
	sameKey := *f.cfg
	sameKey.BackupKeyFile = same
	if _, err := New(Options{Config: &sameKey, Store: f.store, RootKEK: f.rootKEK}).Run(ctx); err == nil {
		t.Error("a BEK that is the Root KEK was used")
	}
	empty(t)

	a := maintenance.Open(f.dir, nil)
	g, err := a.Begin(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service(func(o *Options) { o.Admission = a }).Run(ctx); !errors.Is(err, ErrMaintenance) {
		t.Errorf("during maintenance: %v", err)
	}
	a.End(g.ID)

	var space *SpaceError
	if _, err := f.service(func(o *Options) { o.FreeSpace = func(string) (int64, error) { return 1 << 20, nil } }).Run(ctx); !errors.As(err, &space) || space.Available != 1<<20 || space.Need < spaceMargin {
		t.Errorf("no room: %v", err)
	}
	empty(t)

	f.exec(t, "UPDATE installation SET key_rotation_state = 'rewrapping'")
	if _, err := f.service(nil).Run(ctx); !errors.Is(err, ErrRotation) {
		t.Errorf("during a rotation: %v", err)
	}
	f.exec(t, "UPDATE installation SET key_rotation_state = 'idle'")
	f.exec(t, "INSERT INTO organizations (id, slug, name, wrapped_org_kek, root_kek_version) VALUES ('org_1', 'acme', 'Acme', '{}', 2)")
	if _, err := f.service(nil).Run(ctx); !errors.Is(err, ErrRewraps) {
		t.Errorf("with an Organization on another key version: %v", err)
	}
	f.exec(t, "DELETE FROM organizations")
	if _, err := f.service(func(o *Options) { o.RootKEK = envelope.GenerateKey() }).Run(ctx); err == nil {
		t.Error("a Root KEK that does not open the canary")
	}
	empty(t)

	// A killed run's files go; nothing else does.
	backups := filepath.Join(f.dir, Dir)
	os.MkdirAll(filepath.Join(backups, ".work-dead"), 0o700)
	os.WriteFile(filepath.Join(backups, ".work-dead", "varlatch.db"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(backups, "a.vltbak.0011223344556677.partial"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(backups, "operator-notes.txt"), []byte("x"), 0o600)
	if _, err := f.service(nil).Run(ctx); err != nil {
		t.Fatal(err)
	}
	for name, kept := range map[string]bool{".work-dead": false, "a.vltbak.0011223344556677.partial": false, "operator-notes.txt": true} {
		if _, err := os.Stat(filepath.Join(backups, name)); kept != (err == nil) {
			t.Errorf("%s: kept %t, %v", name, kept, err)
		}
	}
}

// One run at a time, and a stop ends a run without leaving an archive.
func TestConcurrencyAndStop(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE filler (v BLOB) STRICT")
	for i := 0; i < 8; i++ {
		f.exec(t, "INSERT INTO filler VALUES (randomblob(1048576))")
	}
	ctx, cancel := context.WithCancel(context.Background())
	sealing := make(chan struct{})
	s := f.service(func(o *Options) { o.SealRate = 1 << 20 })
	go func() {
		// Sealing 8 MiB at 1 MiB/s: stop it while it runs.
		for {
			if m, _ := filepath.Glob(filepath.Join(f.dir, Dir, "*.partial")); len(m) > 0 {
				close(sealing)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	done := make(chan error, 1)
	go func() { _, err := s.Run(ctx); done <- err }()
	<-sealing
	if _, err := s.Run(context.Background()); !errors.Is(err, ErrRunning) {
		t.Errorf("a second run: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("stopped run: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, Dir)); len(entries) != 0 {
		t.Errorf("a stopped run left %v", entries)
	}
}

// fakeS3 takes PutObject requests.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	fail    bool
}

func (s *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		w.WriteHeader(403)
		io.WriteString(w, `<?xml version="1.0"?><Error><Code>AccessDenied</Code><Message>no</Message></Error>`)
		return
	}
	if r.Method != http.MethodPut || r.URL.RawQuery != "" && !strings.HasPrefix(r.URL.RawQuery, "x-id=PutObject") {
		w.WriteHeader(400)
		return
	}
	b, _ := io.ReadAll(r.Body)
	s.objects[r.URL.Path] = b
	w.Header().Set("ETag", `"etag"`)
	w.WriteHeader(200)
}

// With a destination, the archive is uploaded under the prefix and the
// delivery recorded; a failed upload keeps the archive and its record.
func TestUpload(t *testing.T) {
	f := newFixture(t)
	fake := &fakeS3{objects: map[string][]byte{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	conf := filepath.Join(f.dir, "conf")
	os.Mkdir(conf, 0o700)
	os.WriteFile(filepath.Join(conf, "destinations.json"), []byte(`{"offsite":{"endpoint":"`+srv.URL+`","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`), 0o600)
	os.WriteFile(filepath.Join(conf, "write.json"), []byte(`{"accessKeyId":"AKIDTEST","secretAccessKey":"not-a-secret"}`), 0o600)
	f.cfg.BackupDestinationsFile = filepath.Join(conf, "destinations.json")
	s := f.service(nil)
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	local, _ := os.ReadFile(res.Path)
	if got := fake.objects["/b/varlatch/"+res.ArchiveID+".vltbak"]; !bytes.Equal(got, local) {
		t.Errorf("uploaded %d bytes, archive %d: %v", len(got), len(local), keys(fake.objects))
	}
	if res.Delivery == nil || res.Delivery.Destination != "offsite" {
		t.Errorf("%+v", res)
	}
	st, _ := s.Status()
	if d := st.Archives[0].Delivery; d == nil || d.UploadedAt != res.Delivery.UploadedAt || len(st.Warnings) != 1 || !strings.HasPrefix(st.Warnings[0], "No remote copy has passed") {
		t.Errorf("%+v %q", d, st.Warnings)
	}

	fake.fail = true
	f.add(time.Hour)
	res, err = s.Run(context.Background())
	if err == nil || res.ArchiveID == "" || res.Delivery != nil || !strings.Contains(err.Error(), "Destination upload failed") || !strings.Contains(err.Error(), "local archive remains available") {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("the archive went with the failed upload: %v", err)
	}
	st, _ = s.Status()
	if st.Archives[0].ArchiveID != res.ArchiveID || st.Archives[0].Delivery != nil || !strings.Contains(strings.Join(st.Warnings, "|"), "has not been delivered") {
		t.Errorf("%+v %q", st.Archives[0], st.Warnings)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The schedule: a backup at once when there is none, then one when the
// newest is backup_interval old; an hour after a failure; a minute while
// maintenance holds it back.
func TestSchedule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a := maintenance.Open(f.dir, f.clock)
	s := f.service(func(o *Options) { o.Admission = a })
	if wait := s.tick(ctx); wait != 24*time.Hour {
		t.Fatalf("first tick: %s", wait)
	}
	f.add(10 * time.Hour)
	if wait := s.tick(ctx); wait != 14*time.Hour {
		t.Errorf("not due: %s", wait)
	}
	f.add(14 * time.Hour)
	g, _ := a.Begin(time.Hour)
	if wait := s.tick(ctx); wait != MaintenanceRetry {
		t.Errorf("during maintenance: %s", wait)
	}
	a.End(g.ID)
	f.cfg.BackupKeyFile = filepath.Join(f.dir, "missing")
	if wait := s.tick(ctx); wait != RetryAfter {
		t.Errorf("after a failure: %s", wait)
	}
	if st, _ := s.Status(); len(st.Archives) != 1 {
		t.Errorf("%d archives", len(st.Archives))
	}
}

// A run is admitted as a request is, in one step: a gate that opens while
// it runs sees it in Busy until it ends, and a run while the gate is open
// is refused.
func TestRunIsAdmitted(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "CREATE TABLE filler (v BLOB) STRICT")
	for i := 0; i < 4; i++ {
		f.exec(t, "INSERT INTO filler VALUES (randomblob(1048576))")
	}
	a := maintenance.Open(f.dir, nil)
	s := f.service(func(o *Options) { o.Admission = a; o.SealRate = 2 << 20 })
	done := make(chan error, 1)
	go func() { _, err := s.Run(context.Background()); done <- err }()
	deadline := time.Now().Add(10 * time.Second)
	for a.Busy() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the run was never admitted")
		}
		time.Sleep(time.Millisecond)
	}
	g, err := a.Begin(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.Busy() != 1 {
		t.Errorf("busy %d while the run continues under the gate", a.Busy())
	}
	if _, err := f.service(func(o *Options) { o.Admission = a }).Run(context.Background()); !errors.Is(err, ErrMaintenance) {
		t.Errorf("a run under the gate: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a.Busy() != 0 {
		t.Errorf("busy %d after the run", a.Busy())
	}
	a.End(g.ID)
}

// The schedule while its timer is armed and the wall clock changes: every
// wait is at most Recheck, so a clock moved forward makes the overdue
// backup at the next look, within an hour; a clock moved back makes the
// newest archive look dated in the future, and a backup is taken at once,
// not when the clock catches up with it.
func TestScheduleUnderClockChanges(t *testing.T) {
	f := newFixture(t)
	timers := make(chan time.Duration, 1)
	fire := make(chan time.Time)
	s := f.service(func(o *Options) {
		o.StartDelay = 5 * time.Second
		o.After = func(d time.Duration) <-chan time.Time { timers <- d; return fire }
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Loop(ctx) }()
	defer func() { cancel(); <-done }()
	armed := func(want time.Duration) {
		t.Helper()
		select {
		case d := <-timers:
			if d != want {
				t.Fatalf("the timer was armed for %s, want %s", d, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the timer was not armed")
		}
	}
	archives := func() int {
		t.Helper()
		st, err := s.Status()
		if err != nil {
			t.Fatal(err)
		}
		return len(st.Archives)
	}

	armed(5 * time.Second)
	fire <- time.Time{} // the first look: no archive, one is taken
	armed(Recheck)
	if archives() != 1 {
		t.Fatalf("%d archives after the first look", archives())
	}
	// Armed for an hour; the clock moves 30 hours forward meanwhile.
	f.add(30 * time.Hour)
	fire <- time.Time{}
	armed(Recheck)
	if archives() != 2 {
		t.Fatalf("%d archives after the clock moved forward", archives())
	}
	// Not due: the next look is still within the hour.
	f.add(time.Hour)
	fire <- time.Time{}
	armed(Recheck)
	if archives() != 2 {
		t.Fatalf("%d archives an hour later", archives())
	}
	// The clock moves three days back while the timer is armed.
	f.add(-72 * time.Hour)
	fire <- time.Time{}
	armed(Recheck)
	if archives() != 3 {
		t.Fatalf("%d archives after the clock moved back", archives())
	}
	// And from there the schedule goes on by the new archive's age.
	f.add(time.Hour)
	fire <- time.Time{}
	armed(Recheck)
	if archives() != 3 {
		t.Fatalf("%d archives an hour after", archives())
	}
}

// heldS3 holds a bucket test's upload until release is closed; everything
// else it stores and serves.
type heldS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	held    chan struct{}
	release chan struct{}
}

func (s *heldS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/bucket-test/") {
		close(s.held)
		<-s.release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		s.objects[r.URL.Path] = b
		w.Header().Set("ETag", `"etag"`)
	case http.MethodGet:
		w.Write(s.objects[r.URL.Path])
	}
}

// A backup run while a bucket test is uploading leaves the test's files
// alone (a run removes only a killed test's), and the test still gets its
// archive back; a bucket test while a maintenance gate is open is refused.
func TestBucketTestBesideARun(t *testing.T) {
	f := newFixture(t)
	fake := &heldS3{objects: map[string][]byte{}, held: make(chan struct{}), release: make(chan struct{})}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	conf := filepath.Join(f.dir, "conf")
	os.Mkdir(conf, 0o700)
	os.WriteFile(filepath.Join(conf, "destinations.json"), []byte(`{"offsite":{"endpoint":"`+srv.URL+`","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`), 0o600)
	os.WriteFile(filepath.Join(conf, "write.json"), []byte(`{"accessKeyId":"AKIDTEST","secretAccessKey":"not-a-secret"}`), 0o600)
	f.cfg.BackupDestinationsFile = filepath.Join(conf, "destinations.json")
	a := maintenance.Open(f.dir, nil)
	s := f.service(func(o *Options) { o.Admission = a })

	// A killed test's directory, which the run removes.
	os.MkdirAll(filepath.Join(f.dir, Dir, bucketTestPrefix+"dead"), 0o700)
	type outcome struct {
		r   backup.BucketReport
		err error
	}
	done := make(chan outcome, 1)
	// The first run cleans up before the test starts.
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, Dir, bucketTestPrefix+"dead")); !os.IsNotExist(err) {
		t.Errorf("a killed test's directory stayed: %v", err)
	}
	go func() { r, err := s.TestBucket(context.Background()); done <- outcome{r, err} }()
	<-fake.held
	dirs, _ := filepath.Glob(filepath.Join(f.dir, Dir, bucketTestPrefix+"*"))
	if len(dirs) != 1 {
		t.Fatalf("the test's directory: %v", dirs)
	}
	f.add(time.Hour)
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatalf("a run during the test: %v", err)
	}
	if _, err := os.Stat(dirs[0]); err != nil {
		t.Fatalf("the run removed the running test's directory: %v", err)
	}
	close(fake.release)
	o := <-done
	if o.err != nil || !o.r.Delivery.OK || !o.r.Recoverability.OK {
		t.Fatalf("%+v %v", o.r, o.err)
	}
	if _, err := os.Stat(dirs[0]); !os.IsNotExist(err) {
		t.Errorf("the test left its directory: %v", err)
	}

	g, err := a.Begin(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.TestBucket(context.Background()); !errors.Is(err, ErrMaintenance) {
		t.Errorf("a bucket test during maintenance: %v", err)
	}
	a.End(g.ID)
}
