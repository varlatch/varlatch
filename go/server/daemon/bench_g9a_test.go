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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/bench/g9a"
	"github.com/varlatch/varlatch/go/lib/storage"
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
	data, out := t.TempDir(), t.TempDir()
	conf, err := benchInstallation(data, out, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	done := make(chan int, 1)
	var stderr syncBuffer
	go func() {
		done <- benchServe(Options{ConfigPath: conf, Stderr: &stderr, Signals: make(chan os.Signal), Ready: func(a net.Addr) { ready <- a.String() }}, p, data, out)
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
// manifest's credential, and converge runs whose writes are reconcileTarget's
// successful path (2k + 7 commits per Target: k written ledger entries, the
// three sync.* events, the lease released and the run's row deleted).
func TestBenchRun(t *testing.T) {
	p := quickPlan()
	// One converge run, at 3 s (the next would be after the load): over 20
	// Targets one takes a few seconds, each Target's provider call 200 ms.
	p.Phases = []g9a.Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 4}}
	p.Backups = []g9a.Backup{{Phase: "p", AtSeconds: 1}}
	p.ConvergeEverySeconds = 3
	p.ChangesPerRun = 3
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
			if e.Err != "" || e.Targets != 20 || e.Values != 20*p.ChangesPerRun {
				t.Fatalf("converge: %+v", e)
			}
			runs++
		case g9a.EvBackupEnd:
			if e.Err != "" || e.Pages == 0 {
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
		{`SELECT count(*) FROM value_versions`, 5000},
		{`SELECT count(*) FROM identities`, 50},
		{`SELECT count(*) FROM sync_targets WHERE last_result = 'ok' AND lease_expires_at IS NULL AND generation = ?`, 20},
		{`SELECT count(*) FROM sync_runs`, 0},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.values_decrypted'`, 20 * runs},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.push_attempted'`, 20 * runs},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'sync.push_result'`, 20 * runs},
		{`SELECT count(*) FROM sync_ledger WHERE state = 'written'`, 20 * min(runs*p.ChangesPerRun, benchSecretsPer)},
		{`SELECT count(*) FROM audit_events WHERE event_type = 'secret.disclosed'`, 20},
	} {
		args := []any{}
		if strings.Contains(c.q, "?") {
			args = append(args, runs)
		}
		if got := count(c.q, args...); got != c.want {
			t.Errorf("%s: %d, want %d", c.q, got, c.want)
		}
	}
}
