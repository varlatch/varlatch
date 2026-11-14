// SPDX-License-Identifier: AGPL-3.0-or-later

// G7 runs varlatchd as a process and fills a small filesystem (statfs):
// Linux and macOS only; varlatchd itself only ships for Linux.

//go:build !windows

package daemon

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/values/valuestest"
)

// G7 against the server (ADR-0059 step 3.6): durability of the read path
// of values, whose audit row must be committed before a value leaves.
//
//   - Killing varlatchd (SIGKILL) during disclosures loses no committed
//     audit row: every disclosure a client received has its
//     secret.disclosed event after a restart.
//   - A full disk refuses writes, keeps reads, and writing resumes when
//     space returns.
//   - A disk-full error in a group-commit batch of disclosures answers
//     every one of them with an error, and none returns a value.
//
// The kill at controlled points inside a commit, a WAL write and a
// checkpoint is crashpoint_test.go (go test -tags crashpoint). The two
// disk tests fill a small filesystem: they run when
// VARLATCH_G7_SMALL_FS names a directory on one (a tmpfs of 16 to 64 MiB:
// docker run --tmpfs, or mount -t tmpfs on a disposable CI runner), and
// VARLATCH_REQUIRE_G7_DISK=1 makes them fail instead of skipping without
// it (go.yml). Nothing here needs privileges of its own.

const g7Fixture = "values-v0.22.0.json"

// g7Install is an installation whose database holds the read path's
// fixture, in dir.
func g7Install(t *testing.T, dir string) (install, valuestest.Fixture) {
	t.Helper()
	f, err := valuestest.Read(valuestest.Path(g7Fixture))
	if err != nil {
		t.Fatal(err)
	}
	in := install{dir: dir, conf: filepath.Join(dir, "varlatchd.conf"), kekFile: filepath.Join(dir, "root-kek"),
		data: filepath.Join(dir, "data"), accessLog: filepath.Join(dir, "access.log")}
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.kekFile, []byte(f.RootKEK+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, "")
	if err := valuestest.Prepare(filepath.Join(in.data, config.DatabaseFile), f); err != nil {
		t.Fatal(err)
	}
	return in, f
}

const disclosurePath = "/v1/organizations/acme/projects/api/environments/development/disclosures"

// disclose asks for every Secret alice may reveal: the status, the
// request's id and the body.
func disclose(client *http.Client, base, token string) (int, string, string, error) {
	req, _ := http.NewRequest("POST", base+disclosurePath, strings.NewReader(`{"scope":"all-authorized-secrets"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, "", "", err
	}
	return res.StatusCode, res.Header.Get("X-Request-Id"), string(b), nil
}

// TestKillDuringDisclosuresLosesNoAuditRow: varlatchd runs as a process of
// its own (this test binary, serving); clients ask for disclosures until
// hundreds were answered, and the parent kills it with SIGKILL in the
// middle of more. Every disclosure a client received carried values, so
// its audit event had committed: after the kill each one's
// secret.disclosed event is in the database, which is consistent.
func TestKillDuringDisclosuresLosesNoAuditRow(t *testing.T) {
	if conf := os.Getenv("G7_SERVE_CONF"); conf != "" {
		os.Exit(Serve(Options{ConfigPath: conf, Stderr: os.Stderr, Ready: func(a net.Addr) {
			fmt.Println("ready", a.String())
		}}))
	}
	in, f := g7Install(t, t.TempDir())
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillDuringDisclosuresLosesNoAuditRow$")
	cmd.Env = append(os.Environ(), "G7_SERVE_CONF="+in.conf)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	defer func() {
		if !killed {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if a, ok := strings.CutPrefix(sc.Text(), "ready "); ok {
				addr <- a
			}
		}
	}()
	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case <-time.After(30 * time.Second):
		t.Fatalf("varlatchd did not serve: %s", stderr.String())
	}

	// 8 clients; the request window allows 600 a minute from one address.
	const target = 300
	var mu sync.Mutex
	var disclosed []string
	var answered atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				status, id, body, err := disclose(client, base, f.Tokens["alice"])
				if err != nil {
					return // the server is gone
				}
				if status == 200 {
					if !strings.Contains(body, "hunter2-hunter2") {
						t.Errorf("a disclosure without its value: %s", body)
						return
					}
					mu.Lock()
					disclosed = append(disclosed, id)
					mu.Unlock()
					answered.Add(1)
				} else if status != 429 {
					t.Errorf("disclosure answered %d: %s", status, body)
					return
				}
			}
		}()
	}
	deadline := time.Now().Add(60 * time.Second)
	for answered.Load() < target && time.Now().Before(deadline) && !t.Failed() {
		time.Sleep(5 * time.Millisecond)
	}
	// Kill while the clients are still asking.
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	killed = true
	close(stop)
	wg.Wait()
	if n := answered.Load(); n < target {
		t.Fatalf("only %d disclosures answered before the kill: %s", n, stderr.String())
	}

	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := store.Reader()
	var check string
	if err := r.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}
	var events, last int64
	if err := r.QueryRow(`SELECT count(*), coalesce(max(event_order), 0) FROM audit_events`).Scan(&events, &last); err != nil {
		t.Fatal(err)
	}
	if events != last {
		t.Fatalf("%d audit events, the last at position %d: positions have a gap", events, last)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range disclosed {
		var n int
		if err := r.QueryRow(`SELECT count(*) FROM audit_events WHERE request_id = ? AND event_type = 'secret.disclosed'`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("request %s received its values, but its secret.disclosed event is missing after the kill", id)
		}
	}
	t.Logf("%d disclosures answered before the kill, each with its audit event; %d events in all", len(disclosed), events)
}

// smallFS is a directory on a small filesystem the disk tests may fill.
func smallFS(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("VARLATCH_G7_SMALL_FS")
	if dir == "" {
		if os.Getenv("VARLATCH_REQUIRE_G7_DISK") == "1" {
			t.Fatal("VARLATCH_G7_SMALL_FS is not set, and VARLATCH_REQUIRE_G7_DISK requires the disk tests")
		}
		t.Skip("VARLATCH_G7_SMALL_FS names no small filesystem to fill")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if size := int64(st.Blocks) * int64(st.Bsize); size > 256<<20 {
		t.Fatalf("%s is %d MiB: the disk tests fill it, so it must be a small filesystem of its own", dir, size>>20)
	}
	sub, err := os.MkdirTemp(dir, "g7-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sub) })
	return sub
}

// fill writes a file until the filesystem has no room left, and returns a
// function that removes it.
func fill(t *testing.T, dir string) func() {
	t.Helper()
	path := filepath.Join(dir, "filler")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for size := len(chunk); size >= 512; {
		if _, err := f.Write(chunk[:size]); err != nil {
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatal(err)
			}
			size /= 2
		}
	}
	_ = f.Sync()
	_ = f.Close()
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

const effectivePath = "/v1/organizations/acme/projects/api/environments/development/effective-configuration"

func get(client *http.Client, url, token string) (int, string) {
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// TestFullDiskRefusesWritesKeepsReads: varlatchd on a filesystem with no
// room left answers reads that write nothing (a metadata read of the
// effective configuration, /readyz), refuses what must write (a
// disclosure's audit event) with an error and no value, keeps running, and
// writes again once space is free.
func TestFullDiskRefusesWritesKeepsReads(t *testing.T) {
	dir := smallFS(t)
	in, f := g7Install(t, dir)
	// Checkpoints every 200 ms, so that one is tried while the disk is full
	// and one after space returns; every attempt is recorded.
	var checkpoints checkpointLog
	r := startWith(t, in, &hooks{storage: func(o *storage.Options) {
		o.PassiveEvery = 200 * time.Millisecond
		o.OnCheckpoint = checkpoints.add
	}})
	stopped := false
	defer func() {
		if !stopped {
			r.stop(t)
		}
	}()
	base := "http://" + r.addr
	client := &http.Client{Timeout: 30 * time.Second}
	token := f.Tokens["alice"]
	// Before: every kind works (and the credential's last use is written,
	// so later requests write nothing to authenticate).
	if status, _, body, err := disclose(client, base, token); err != nil || status != 200 {
		t.Fatalf("before: %d %v %s", status, err, body)
	}

	// A burst of disclosures leaves WAL frames that need the database file
	// to grow, and the disk is filled at once, before the next checkpoint
	// copies them: that checkpoint must fail. When a checkpoint wins the
	// race and copies them first, space is freed and the burst repeated.
	var refused, served []string
	var free func()
	for attempt := 1; ; attempt++ {
		for range 10 {
			status, id, body, err := disclose(client, base, token)
			if err != nil || status != 200 {
				t.Fatalf("a disclosure before the disk is full: %d %v %s", status, err, body)
			}
			served = append(served, id)
		}
		free = fill(t, dir)
		filledAt := time.Now()
		// A full disk refuses writes. The WAL may still have room a
		// checkpoint left in it, so a few disclosures may commit first;
		// every one that returns a value had its audit event committed
		// (checked below).
		n := len(refused)
		for i := 0; i < 200 && len(refused) < n+3; i++ {
			status, id, body, err := disclose(client, base, token)
			if err != nil {
				t.Fatal(err)
			}
			switch status {
			case 200:
				served = append(served, id)
			case 500:
				if strings.Contains(body, "hunter2") {
					t.Fatalf("a refused disclosure carries a value: %s", body)
				}
				refused = append(refused, id)
			default:
				t.Fatalf("disclosure on a full disk: %d %s", status, body)
			}
		}
		if len(refused) == n {
			t.Fatal("200 disclosures on a full disk all committed: the disk was not full")
		}
		if failed, ok := checkpoints.wait(filledAt, 5*time.Second, func(c checkpointAttempt) bool { return c.err != nil }); ok {
			t.Logf("on the full disk: %d disclosures refused; a %s checkpoint failed: %v", len(refused)-n, failed.r.Mode, failed.err)
			break
		}
		if attempt == 5 {
			t.Fatal("five times a checkpoint copied the burst before the disk was full: no checkpoint was seen failing")
		}
		free()
	}
	if !strings.Contains(r.stderr.String(), "the disk is full") {
		t.Errorf("the log does not say the disk is full:\n%s", r.stderr.String())
	}
	// Reads keep working.
	for _, p := range []string{effectivePath, "/readyz"} {
		tok := token
		if p == "/readyz" {
			tok = ""
		}
		if status, body := get(client, base+p, tok); status != 200 {
			t.Fatalf("read %s on a full disk: %d %s", p, status, body)
		}
	}

	// Space returns: a checkpoint copies what the full disk held back, and
	// writing resumes (the next batch opens a new writer).
	free()
	freedAt := time.Now()
	if copied, ok := checkpoints.wait(freedAt, 5*time.Second, func(c checkpointAttempt) bool { return c.err == nil && c.r.Checkpointed > 0 }); ok {
		t.Logf("after space returned: a %s checkpoint copied %d frames", copied.r.Mode, copied.r.Checkpointed)
	} else {
		t.Fatal("no checkpoint succeeded within 5 s of space returning")
	}
	var resumed string
	for i := 0; i < 50 && resumed == ""; i++ {
		status, id, body, err := disclose(client, base, token)
		if err != nil {
			t.Fatal(err)
		}
		if status == 200 && strings.Contains(body, "hunter2-hunter2") {
			resumed = id
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resumed == "" {
		t.Fatal("writing did not resume once space was free")
	}
	served = append(served, resumed)
	r.stop(t)
	stopped = true

	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	count := func(id string) int {
		var n int
		if err := store.Reader().QueryRow(`SELECT count(*) FROM audit_events WHERE request_id = ? AND event_type = 'secret.disclosed'`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, id := range served {
		if count(id) != 1 {
			t.Fatalf("disclosure %s returned values without its audit event", id)
		}
	}
	for _, id := range refused {
		if count(id) != 0 {
			t.Fatalf("refused disclosure %s left an audit event", id)
		}
	}
}

// TestDiskFullBatchAnswersEveryDisclosure: disclosures queue behind a job
// that holds the single writer, the disk fills, and the writer goes on: the
// batch holding every queued audit event fails on the full disk, so each
// disclosure in it answers an error and none returns a value; nothing of
// the batch is committed. The writer's next batch, once space is free,
// commits.
func TestDiskFullBatchAnswersEveryDisclosure(t *testing.T) {
	dir := smallFS(t)
	f, err := valuestest.Read(valuestest.Path(g7Fixture))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "varlatchd.db")
	if err := valuestest.Prepare(path, f); err != nil {
		t.Fatal(err)
	}
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	open := func() (*storage.DB, http.Handler) {
		store, err := storage.Open(ctx, storage.Options{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		h, err := httpserver.New(httpserver.Options{Version: "test", Backend: &backend{store: store, rootKEK: rootKEK}, Log: log,
			Auth: auth.New(store, auth.Options{Log: log, RootKEK: rootKEK}), Values: values.New(store, rootKEK, values.Options{Log: log})})
		if err != nil {
			t.Fatal(err)
		}
		return store, h
	}
	// Each credential's last use is written once, before: within the next
	// minute authenticating them writes nothing, so the queued jobs are the
	// disclosures' audit events alone. Closing truncates the WAL, so the
	// batch below must grow it.
	store, h := open()
	people := []string{"alice", "bob", "dave", "erin"}
	for _, p := range people {
		if rec := serveRequest(h, "POST", disclosurePath, f.Tokens[p]); rec.Code != 200 {
			t.Fatalf("%s before: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, h = open()
	defer store.Close()
	before := store.Metrics()
	var events int
	if err := store.Reader().QueryRow(`SELECT count(*) FROM audit_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}

	hold, held := make(chan struct{}), make(chan struct{})
	// Released at most once, and before the database closes (deferred
	// after its Close), whichever way the test ends: a failure before the
	// release would otherwise leave Close waiting on the held writer.
	release := sync.OnceFunc(func() { close(hold) })
	defer release()
	holder := make(chan error, 1)
	go func() {
		holder <- store.Write(ctx, func(*storage.Tx) error {
			close(held)
			<-hold
			return nil
		})
	}()
	<-held
	const n = 12
	type answer struct {
		code int
		body string
	}
	answers := make(chan answer, n)
	for i := range n {
		go func() {
			rec := serveRequest(h, "POST", disclosurePath, f.Tokens[people[i%len(people)]])
			answers <- answer{rec.Code, rec.Body.String()}
		}()
	}
	// The disclosures read their snapshot and queue their audit jobs behind
	// the held writer.
	deadline := time.Now().Add(10 * time.Second)
	for store.Metrics().Queued < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if q := store.Metrics().Queued; q < n {
		t.Fatalf("%d jobs queued, want %d", q, n)
	}
	free := fill(t, dir)
	release()
	if err := <-holder; err != nil {
		t.Fatalf("the holding job: %v", err)
	}
	for range n {
		a := <-answers
		if a.code != 500 || strings.Contains(a.body, "hunter2") || strings.Contains(a.body, "preview-pass") {
			t.Fatalf("a disclosure in the failed batch answered %d: %s", a.code, a.body)
		}
	}
	// The engine answers a batch's jobs before it counts the batch: wait,
	// bounded, for the counters.
	var m storage.Metrics
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if m = store.Metrics(); (m.FailedBatches == before.FailedBatches+1 && m.MaxBatch >= n) || time.Now().After(deadline) {
			break
		}
	}
	if m.FailedBatches != before.FailedBatches+1 || m.MaxBatch < n {
		t.Fatalf("failed batches %d (was %d), largest batch %d: the disclosures did not fail as one batch", m.FailedBatches, before.FailedBatches, m.MaxBatch)
	}
	t.Logf("%d disclosures in one failed batch (largest batch %d, failed batches %d)", n, m.MaxBatch, m.FailedBatches-before.FailedBatches)
	var after int
	if err := store.Reader().QueryRow(`SELECT count(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != events {
		t.Fatalf("%d audit events committed from the failed batch", after-events)
	}
	free()
	if rec := serveRequest(h, "POST", disclosurePath, f.Tokens["alice"]); rec.Code != 200 || !strings.Contains(rec.Body.String(), "hunter2-hunter2") {
		t.Fatalf("after space returned: %d %s", rec.Code, rec.Body.String())
	}
}

func serveRequest(h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"scope":"all-authorized-secrets"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// startWith serves in with hooks, as start serves with none.
func startWith(t *testing.T, in install, h *hooks) *running {
	t.Helper()
	r := &running{signals: make(chan os.Signal, 1), done: make(chan int, 1), stderr: &syncBuffer{}}
	ready := make(chan string, 1)
	go func() {
		r.done <- serve(Options{ConfigPath: in.conf, Stderr: r.stderr, Signals: r.signals, Ready: func(a net.Addr) { ready <- a.String() }}, h)
	}()
	select {
	case r.addr = <-ready:
	case code := <-r.done:
		t.Fatalf("exited %d before serving: %s", code, r.stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("not serving after 30 s")
	}
	return r
}

type checkpointAttempt struct {
	at  time.Time
	r   storage.CheckpointResult
	err error
}

// checkpointLog records every checkpoint the engine reports.
type checkpointLog struct {
	mu sync.Mutex
	cs []checkpointAttempt
}

func (l *checkpointLog) add(r storage.CheckpointResult, err error) {
	l.mu.Lock()
	l.cs = append(l.cs, checkpointAttempt{time.Now(), r, err})
	l.mu.Unlock()
}

// wait returns the first checkpoint after since that matches, waiting up
// to timeout for one.
func (l *checkpointLog) wait(since time.Time, timeout time.Duration, match func(checkpointAttempt) bool) (checkpointAttempt, bool) {
	for deadline := time.Now().Add(timeout); ; time.Sleep(10 * time.Millisecond) {
		l.mu.Lock()
		for _, c := range l.cs {
			if c.at.After(since) && !c.r.Deferred && match(c) {
				l.mu.Unlock()
				return c, true
			}
		}
		l.mu.Unlock()
		if time.Now().After(deadline) {
			return checkpointAttempt{}, false
		}
	}
}
