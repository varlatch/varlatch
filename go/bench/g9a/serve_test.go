// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The server end to end, without k6: seed, a handful of retrievals (one
// denied), a converge run and a backup, then the event log and the files.
func TestServe(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds W1 and probes the disk for a few seconds")
	}
	p := DefaultPlan()
	p.Phases = []Phase{{Name: "warmup", Rate: 1, Seconds: 1, Warmup: true}, {Name: "p", Rate: 1, Seconds: 5}}
	p.Backups = []Backup{{Phase: "p", AtSeconds: 1}}
	p.ConvergeEverySeconds = 1.5
	p.Targets = 3
	p.IdleProbeSeconds = 3
	p.WALBound = 64 << 10
	out, data := t.TempDir(), t.TempDir()

	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), ServeOptions{DataDir: data, OutDir: out, Plan: p, Listen: "127.0.0.1:0", Ready: func(a string) { ready <- a }, Tail: time.Minute})
	}()
	var base string
	select {
	case a := <-ready:
		base = "http://" + a
	case err := <-done:
		t.Fatal(err)
	case <-time.After(2 * time.Minute):
		t.Fatal("not ready")
	}

	var manifest []Credential
	b, err := os.ReadFile(filepath.Join(out, FileManifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil || len(manifest) != 3*w1SecretsPerEnv {
		t.Fatalf("manifest: %v, %d entries", err, len(manifest))
	}

	post := func(path string, want int) {
		t.Helper()
		resp, err := http.Post(base+path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("POST %s: %d", path, resp.StatusCode)
		}
	}
	get := func(c Credential) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", base+"/v1/retrieve/"+c.Env+"/"+c.Key, nil)
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	post("/run/start", 200)
	post("/run/start", 409)
	for i := range 20 {
		if code, body := get(manifest[i*17%len(manifest)]); code != 200 || !strings.Contains(body, `"value":"`) {
			t.Fatalf("retrieval: %d %s", code, body)
		}
	}
	bad := manifest[0]
	bad.Token = "vl_g9a_wrong"
	if code, _ := get(bad); code != 403 {
		t.Fatalf("a wrong token: %d", code)
	}
	time.Sleep(4 * time.Second) // a converge run and the backup
	post("/run/stop", 200)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(filepath.Join(out, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	var end Event
	for _, e := range events {
		seen[e.Ev]++
		if e.Ev == EvCheckpoint {
			seen["checkpoint "+e.Trigger]++
		}
		if e.Ev == EvFsync && e.Idle {
			seen["fsync idle"]++
		}
		if e.Ev == EvConvergeEnd && e.Err != "" {
			t.Errorf("converge: %s", e.Err)
		}
		if e.Ev == EvBackupEnd && (e.Err != "" || e.Pages == 0) {
			t.Errorf("backup: %+v", e)
		}
		if e.Ev == EvError {
			t.Errorf("server error: %s", e.Err)
		}
		if e.Ev == EvRunEnd {
			end = e
		}
	}
	for _, want := range []string{EvRunStart, EvRunEnd, EvWAL, EvMemory, EvBackupStart, EvBackupEnd, EvConvergeEnd,
		"checkpoint interval", "checkpoint snapshot", "checkpoint close", "fsync idle"} {
		if seen[want] == 0 {
			t.Errorf("no %s event (saw %v)", want, seen)
		}
	}
	if end.Requests != 21 || end.Errors != 1 || end.BusyErrs != 0 {
		t.Errorf("run_end: %+v", end)
	}
	var sys System
	b, _ = os.ReadFile(filepath.Join(out, FileSystem))
	if err := json.Unmarshal(b, &sys); err != nil || sys.Target != StandInTarget || sys.IdleSync == "" {
		t.Fatalf("system.json: %v %+v", err, sys)
	}
	if _, err := os.Stat(filepath.Join(data, "backups", "snapshot-0.db")); !os.IsNotExist(err) {
		t.Errorf("the backup snapshot was kept: %v", err)
	}

	// A second run into the same directories is refused.
	err = Serve(context.Background(), ServeOptions{DataDir: data, OutDir: t.TempDir(), Plan: p, Listen: "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "fresh database") {
		t.Fatalf("reused database: %v", err)
	}
}
