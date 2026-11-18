// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/bench/g9a"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/stages"
)

// settingsLog collects what serving reports as its effective settings.
type settingsLog struct {
	mu sync.Mutex
	s  []storage.Settings
}

func (l *settingsLog) observe(t *testing.T) {
	t.Helper()
	observeSettings = func(s storage.Settings) {
		l.mu.Lock()
		l.s = append(l.s, s)
		l.mu.Unlock()
	}
	t.Cleanup(func() { observeSettings = nil })
}

func (l *settingsLog) last(t *testing.T) storage.Settings {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.s) == 0 {
		t.Fatal("no settings reported")
	}
	return l.s[len(l.s)-1]
}

// benchRun serves a G9a run in-process with plan p until fn returns, then
// stops it with POST /run/stop. It returns the output directory.
func benchRun(t *testing.T, p g9a.Plan, fn func(base string, manifest []g9a.ManifestEntry)) string {
	t.Helper()
	return benchRunTo(t, p, benchDestination{}, fn)
}

// benchRunTo is benchRun with the backups uploading to dest.
func benchRunTo(t *testing.T, p g9a.Plan, dest benchDestination, fn func(base string, manifest []g9a.ManifestEntry)) string {
	t.Helper()
	data, out := t.TempDir(), t.TempDir()
	coolify, err := startBenchCoolify(benchProjects * benchEnvsPer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(coolify.close)
	conf, err := benchInstallation(data, out, "127.0.0.1:0", coolify.Port(), dest)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	done := make(chan int, 1)
	var stderr syncBuffer
	go func() {
		done <- benchServe(Options{ConfigPath: conf, Stderr: &stderr, Signals: make(chan os.Signal), Ready: func(a net.Addr) { ready <- a.String() }}, p, data, out, 30*time.Second, coolify)
	}()
	var base string
	select {
	case a := <-ready:
		base = "http://" + a
	case code := <-done:
		t.Fatalf("exited %d: %s", code, stderr.String())
	case <-time.After(3 * time.Minute):
		t.Fatalf("not serving: %s", stderr.String())
	}
	var manifest []g9a.ManifestEntry
	b, err := os.ReadFile(filepath.Join(out, g9a.FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	fn(base, manifest)
	resp, err := http.Post(base+"/run/stop", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("exited %d: %s", code, stderr.String())
		}
	case <-time.After(time.Minute):
		t.Fatal("did not stop")
	}
	return out
}

func quickPlan() g9a.Plan {
	p := g9a.DefaultPlan()
	p.IdleProbeSeconds = 3
	return p
}

func readSystem(t *testing.T, out string) g9a.System {
	t.Helper()
	var sys g9a.System
	b, err := os.ReadFile(filepath.Join(out, g9a.FileSystem))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &sys); err != nil {
		t.Fatal(err)
	}
	return sys
}

// ADR-0059 varlatchd-core decision 7: the g9a build's effective storage
// settings (pragmas, WAL bound, batch size, checkpoint period, snapshot
// pacing) are the production build's, and it reports them; a smoke plan's
// WAL bound is the only thing a plan may change, and the report says so.
func TestBenchSettingsAreProduction(t *testing.T) {
	var log settingsLog
	log.observe(t)

	// The production path: varlatchd serve.
	r := start(t, newInstall(t, ""))
	r.stop(t)
	production := log.last(t)
	if production.WALBound != storage.DefaultWALBound || production.MaxBatch != storage.DefaultMaxBatch ||
		production.Pragmas["writer"]["synchronous"] != "2" || production.Pragmas["reader"]["journal_mode"] != "wal" {
		t.Fatalf("production settings: %+v", production)
	}
	if !strings.Contains(r.stderr.String(), `msg="storage settings"`) {
		t.Errorf("serve does not report its settings:\n%s", r.stderr.String())
	}

	// The g9a build with the G9a profile.
	out := benchRun(t, quickPlan(), func(string, []g9a.ManifestEntry) {})
	bench := log.last(t)
	if !reflect.DeepEqual(bench, production) {
		t.Fatalf("the g9a build's settings %+v, production %+v", bench, production)
	}
	if sys := readSystem(t, out); !sys.Production || sys.SettingsNote != "" || !reflect.DeepEqual(sys.Settings, production) || sys.Target != g9a.TargetVarlatchd || sys.Build.SHA256 == "" {
		t.Fatalf("system.json: %+v", sys)
	}

	// A smoke plan's bound: only the WAL bound differs.
	p := quickPlan()
	p.WALBound = 512 << 10
	out = benchRun(t, p, func(string, []g9a.ManifestEntry) {})
	smoke := log.last(t)
	if smoke.WALBound != p.WALBound {
		t.Fatalf("smoke WAL bound %d", smoke.WALBound)
	}
	smoke.WALBound = production.WALBound
	if !reflect.DeepEqual(smoke, production) {
		t.Fatalf("the smoke run's settings differ beyond the WAL bound: %+v, production %+v", smoke, production)
	}
	if sys := readSystem(t, out); !sys.Production || !strings.Contains(sys.SettingsNote, "WAL bound 524288 bytes (production 67108864)") {
		t.Fatalf("system.json: %+v", sys)
	}
}

// A short run: W1 seeded in the production tables, a disclosure with the
// manifest's credential, and converge runs on the real engine against the
// run's Coolify: before each, k values changed in every Target's
// environment; each Target's run writes them and reports its commits and
// the WAL bytes they wrote.
func TestBenchRun(t *testing.T) {
	p := quickPlan()
	// One converge run, at 3 s (the next would be after the load), with a
	// provider call of 5 ms so that it ends in time.
	p.Phases = []g9a.Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 4}}
	p.Backups = []g9a.Backup{{Phase: "p", AtSeconds: 1}}
	p.ConvergeEverySeconds = 3
	p.ChangesPerRun = 3
	p.ProviderDelayMs = 5
	out := benchRun(t, p, func(base string, manifest []g9a.ManifestEntry) {
		if len(manifest) != 20 {
			t.Fatalf("%d manifest entries", len(manifest))
		}
		seen := map[string]bool{}
		for i, m := range manifest {
			if m.Address != BenchAddresses[i] || seen[m.Identity] || len(m.Keys) != benchSecretsPer {
				t.Fatalf("manifest entry %d: %+v", i, m)
			}
			seen[m.Identity] = true
			// Each entry's credential reveals its Secrets (a person's by
			// membership, a service identity's by its Grant).
			req, _ := http.NewRequest("POST", base+"/v1/organizations/"+m.Org+"/projects/"+m.Project+"/environments/"+m.Env+"/disclosures",
				strings.NewReader(`{"items":["`+m.Keys[i]+`"]}`))
			req.Header.Set("Authorization", "Bearer "+m.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), `"value":"`) {
				t.Fatalf("disclosure for %s: %d %s", m.Address, resp.StatusCode, body)
			}
		}
		// Each disclosure's stages (step 4 decision 7), and a CPU profile.
		var sums []stages.Summary
		if code := getJSON(t, base+"/run/stages", &sums); code != 200 || len(sums) != len(stages.Names) {
			t.Fatalf("/run/stages: %d %+v", code, sums)
		}
		for i, sm := range sums {
			if sm.Stage != stages.Names[i] || sm.Count < 20 || sm.P50Ms <= 0 || sm.P99Ms < sm.P50Ms {
				t.Errorf("stage %+v", sm)
			}
		}
		prof, err := http.Get(base + "/run/profile?seconds=1")
		if err != nil {
			t.Fatal(err)
		}
		pb, _ := io.ReadAll(prof.Body)
		prof.Body.Close()
		if prof.StatusCode != 200 || len(pb) < 2 || pb[0] != 0x1f || pb[1] != 0x8b {
			t.Errorf("/run/profile: %d, %d bytes", prof.StatusCode, len(pb))
		}
		resp, err := http.Post(base+"/run/start", "", nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("/run/start: %v %v", err, resp)
		}
		resp.Body.Close()
		time.Sleep(5 * time.Second) // stopping waits for the converge run
	})
	// The load's CPU profile, from POST /run/start to the run's end, and
	// when it ran.
	if b, err := os.ReadFile(filepath.Join(out, g9a.FileCPUProfile)); err != nil || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Errorf("%s: %v, %d bytes", g9a.FileCPUProfile, err, len(b))
	}
	var window g9a.ProfileSpan
	if b, err := os.ReadFile(filepath.Join(out, g9a.FileCPUWindow)); err != nil || json.Unmarshal(b, &window) != nil || window.StartUs <= 0 || window.EndUs <= window.StartUs {
		t.Errorf("%s: %v %+v", g9a.FileCPUWindow, err, window)
	}
	var final []stages.Summary
	if b, err := os.ReadFile(filepath.Join(out, g9a.FileStages)); err != nil || json.Unmarshal(b, &final) != nil || len(final) != len(stages.Names) {
		t.Errorf("%s: %v %s", g9a.FileStages, err, b)
	}
	events, err := g9a.ReadEvents(filepath.Join(out, g9a.FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	for _, e := range events {
		switch e.Ev {
		case g9a.EvConvergeEnd:
			// Each Target's k values written, a call each after reading
			// its variables; the engine's commits and their WAL bytes.
			if e.Err != "" || e.Targets != 20 || e.Values != 20*p.ChangesPerRun || e.Calls < int64(20*(p.ChangesPerRun+1)) ||
				e.Commits < 20*p.ChangesPerRun || e.WALBytes <= 0 || e.EngineUs <= 0 {
				t.Fatalf("converge: %+v", e)
			}
			// The provider stand-in's observed latency of every call of
			// the run (amendment 6), each at least the plan's delay.
			if int64(len(e.ProviderCallsUs)) != e.Calls || slices.Min(e.ProviderCallsUs) < int64(p.ProviderDelayMs)*1000 {
				t.Fatalf("provider timings: %d for %d calls, min %v", len(e.ProviderCallsUs), e.Calls, e.ProviderCallsUs)
			}
			runs++
		case g9a.EvBackupEnd:
			// A real backup: its snapshot, and the archive it sealed.
			if e.Err != "" || e.Pages == 0 || e.ArchiveBytes == 0 {
				t.Fatalf("backup: %+v", e)
			}
		case g9a.EvError:
			t.Fatalf("error: %s", e.Err)
		case g9a.EvRunEnd:
			if e.Requests != 20 || e.Errors != 0 {
				t.Fatalf("run_end: %+v", e)
			}
		}
	}
	if runs == 0 {
		t.Fatal("no converge run")
	}
	// converge.jsonl: each run's Targets, every commit with its time and
	// its batch's WAL bytes.
	lines, err := g9a.ReadConverge(filepath.Join(out, g9a.FileConverge))
	if err != nil || len(lines) != runs {
		t.Fatalf("%s: %d lines, %d runs: %v", g9a.FileConverge, len(lines), runs, err)
	}
	// The successful path's commits, 2k + 7, in order (CONVERGE.md).
	want := []string{"lease", "values-decrypted", "push-attempted"}
	for range p.ChangesPerRun {
		want = append(want, "intent-write")
	}
	for range p.ChangesPerRun {
		want = append(want, "write-outcome")
	}
	want = append(want, "push-result", "result", "lease-release", "run-row")
	for _, l := range lines {
		if len(l.Runs) != 20 {
			t.Fatalf("a run of %d Targets", len(l.Runs))
		}
		for _, r := range l.Runs {
			if r.Commits != len(r.Jobs) || r.Commits != 2*p.ChangesPerRun+7 || r.WALBytes <= 0 || r.DurationUs <= 0 {
				t.Fatalf("Target run %+v", r)
			}
			var points []string
			var inJobs, completion int64
			for _, j := range r.Jobs {
				points = append(points, j.Point)
				inJobs += j.InJobUs
				completion += j.CompletionUs
				// A job's body and its wait for its batch, apart.
				if j.InJobUs < 0 || j.CompletionUs < 0 || j.QueuedUs < 0 {
					t.Fatalf("commit times %+v of %s", j, r.Target)
				}
			}
			// Each job's time is rounded to the microsecond, the run's total once.
			near := func(a, b int64) bool { return max(a-b, b-a) <= int64(len(r.Jobs)) }
			if !reflect.DeepEqual(points, want) || !near(inJobs, r.InJobsUs) || !near(completion, r.CompletionUs) {
				t.Fatalf("Target run %s: commits %v (want %v), in jobs %d of %d, completion %d of %d", r.Target, points, want, inJobs, r.InJobsUs, completion, r.CompletionUs)
			}
			for _, j := range r.Jobs {
				// A commit may write no page (an update that changed no
				// row): its WAL bytes may be 0, never less.
				if j.Point == "" || j.BatchJobs < 1 || j.WALBytes < 0 {
					t.Fatalf("commit %+v of %s", j, r.Target)
				}
			}
		}
	}

	// The database the run left: what the converge runs wrote.
	conf, err := config.Load(filepath.Join(out, g9a.FileConfig))
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: conf.DatabasePath()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count := func(q string, args ...any) int {
		var n int
		if err := store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct {
		q    string
		want int
	}{
		// The seed's versions and each run's changes.
		{`SELECT count(*) FROM value_versions`, 5000 + 20*p.ChangesPerRun*runs},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'value.written'`, 20 * p.ChangesPerRun * runs},
		{`SELECT count(*) FROM identities`, 50},
		// Every Target converged and released: the first pass (every
		// value) and each run.
		{`SELECT count(*) FROM sync_targets WHERE failure_count = 0 AND last_result IS NOT NULL AND lease_expires_at IS NULL`, 20},
		{`SELECT count(*) FROM sync_runs`, 0},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.values_decrypted'`, 20 * (runs + 1)},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.push_attempted'`, 20 * (runs + 1)},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.push_result'`, 20 * (runs + 1)},
		{`SELECT count(*) FROM sync_ledger WHERE state = 'written'`, 20 * benchSecretsPer},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'secret.disclosed'`, 20},
	} {
		if got := count(c.q); got != c.want {
			t.Errorf("%s: %d, want %d", c.q, got, c.want)
		}
	}
}

// ADR-0059 amendment 6: G9's backups are the shipped backup path, writing
// to an S3-compatible server on the same host. With -backup-destinations,
// each of the run's backups uploads its archive there (backup_end names
// the destination), and a failed upload is a failed backup, which the
// report fails. Against s3fake: once with the server up, once down.
func TestBenchBackupUploads(t *testing.T) {
	for _, down := range []bool{false, true} {
		t.Run(map[bool]string{false: "uploaded", true: "upload-fails"}[down], func(t *testing.T) {
			srv := s3fake.New()
			t.Cleanup(srv.Close)
			srv.SetDown(down)
			dir := t.TempDir()
			creds := filepath.Join(dir, "credentials.json")
			if err := os.WriteFile(creds, []byte(`{"accessKeyId":"`+s3fake.KeyGood+`","secretAccessKey":"fixture-secret"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			dests := filepath.Join(dir, "destinations.json")
			if err := os.WriteFile(dests, []byte(`{"local":{"endpoint":"`+srv.URL+`","region":"us-east-1","bucket":"`+s3fake.BucketLocked+`","prefix":"g9a/","writeCredentialsFile":"`+creds+`"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			p := quickPlan()
			p.Phases = []g9a.Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 3}}
			p.Backups = []g9a.Backup{{Phase: "p", AtSeconds: 1}}
			p.ConvergeEverySeconds = 600
			p.ProviderDelayMs = 5
			out := benchRunTo(t, p, benchDestination{File: dests, Name: "local"}, func(base string, _ []g9a.ManifestEntry) {
				resp, err := http.Post(base+"/run/start", "", nil)
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("/run/start: %v %v", err, resp)
				}
				resp.Body.Close()
				time.Sleep(5 * time.Second)
			})
			conf, err := os.ReadFile(filepath.Join(out, g9a.FileConfig))
			if err != nil || !strings.Contains(string(conf), "backup_destinations_file = "+dests+"\nbackup_destination = local\n") {
				t.Fatalf("%s: %v\n%s", g9a.FileConfig, err, conf)
			}
			events, err := g9a.ReadEvents(filepath.Join(out, g9a.FileEvents))
			if err != nil {
				t.Fatal(err)
			}
			ends := 0
			for _, e := range events {
				if e.Ev != g9a.EvBackupEnd {
					continue
				}
				ends++
				if down {
					if e.Err == "" || e.UploadedTo != "" {
						t.Errorf("backup with the destination down: %+v", e)
					}
				} else if e.Err != "" || e.UploadedTo != "local" || e.ArchiveBytes == 0 {
					t.Errorf("backup: %+v", e)
				}
			}
			if ends != 1 {
				t.Fatalf("%d backup_end events", ends)
			}
			keys := srv.Keys(s3fake.BucketLocked)
			if down != (len(keys) == 0) || !down && (len(keys) != 1 || !strings.HasPrefix(keys[0], "g9a/") || !strings.HasSuffix(keys[0], ".vltbak")) {
				t.Fatalf("objects in the bucket: %v", keys)
			}
		})
	}
}

// The two destination flags go together, the file is an absolute path,
// and it must name the destination: a run that names one never falls back
// to local archives. Each is refused before anything is seeded.
func TestBenchDestinationFlags(t *testing.T) {
	dir := t.TempDir()
	dests := filepath.Join(dir, "destinations.json")
	if err := os.WriteFile(dests, []byte(`{"other":{"endpoint":"http://127.0.0.1:9","region":"us-east-1","bucket":"b-1","writeCredentialsFile":"c.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-backup-destinations", "/x.json"}, 64, "go together"},
		{[]string{"-backup-destination", "local"}, 64, "go together"},
		{[]string{"-backup-destinations", "destinations.json", "-backup-destination", "other"}, 64, "not an absolute path"},
		{[]string{"-backup-destinations", dests, "-backup-destination", "local"}, ExitConfig, "No destination named local"},
		{[]string{"-backup-destinations", filepath.Join(dir, "missing.json"), "-backup-destination", "local"}, ExitConfig, "missing.json"},
	} {
		var stderr strings.Builder
		args := append([]string{"-plan", filepath.Join(dir, "plan.json"), "-data", data, "-out", filepath.Join(dir, "out")}, c.args...)
		if code := runBench(args, &stderr); code != c.code || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: exit %d: %s", c.args, code, stderr.String())
		}
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Errorf("the data directory was made: %v", err)
	}
}

// A bound run (writeScale above 1): the server makes the added writes in
// W1's mix, in-process, through the production paths: disclosures by the
// load's identities, and value writes into an environment of the bound
// run's own, which no Sync Target reads. Every planned write is made, none
// fails, and the requests of the load are only k6's.
func TestBenchBoundRun(t *testing.T) {
	p := quickPlan()
	p.Phases = []g9a.Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 4, Seconds: 3}}
	p.Backups = nil
	p.ConvergeEverySeconds = 600 // no converge run; 1 × 5 × 20 / 600 value writes a second
	p.ProviderDelayMs = 5
	p.WriteScale = 2     // + 4 disclosures a second in p, 1 in the warm-up
	p.ChangesPerRun = 30 // 1 × 30 × 20 / 600 = 1 value write a second
	out := benchRun(t, p, func(base string, manifest []g9a.ManifestEntry) {
		resp, err := http.Post(base+"/run/start", "", nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("/run/start: %v %v", err, resp)
		}
		resp.Body.Close()
		time.Sleep(6 * time.Second)
	})
	events, err := g9a.ReadEvents(filepath.Join(out, g9a.FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	ends := map[string]g9a.Event{}
	for _, e := range events {
		switch e.Ev {
		case g9a.EvWriteLoadEnd:
			ends[e.Kind] = e
		case g9a.EvError:
			t.Fatalf("error: %s", e.Err)
		case g9a.EvRunEnd:
			if e.Requests != 0 {
				t.Fatalf("the added writes counted as requests of the load: %+v", e)
			}
		}
	}
	d, v := ends[string(g9a.WriteDisclose)], ends[string(g9a.WriteValue)]
	if d.Planned != 13 || d.Writes != d.Planned || d.WritesFailed != 0 || d.WritesBusy != 0 || d.WritesLate != 0 {
		t.Errorf("disclosures: %+v", d)
	}
	if v.Planned != 4 || v.Writes != v.Planned || v.WritesFailed != 0 || v.WritesLate != 0 {
		t.Errorf("value writes: %+v", v)
	}
}
