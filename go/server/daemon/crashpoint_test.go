// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint

package daemon

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/values/valuestest"
)

// G7 against the server at controlled crash points (go test -tags
// crashpoint; lib/storage/crashpoint.go): varlatchd runs as a process of
// its own while clients ask for disclosures, and is killed with SIGKILL
//
//   - inside a commit: paused in SQLite's commit of a write batch, before
//     its WAL frames are written;
//   - during a WAL write: while a large batch's frames are being written to
//     the WAL (its size seen growing, its COMMIT not returned);
//   - during a checkpoint: while a checkpoint copies those frames into the
//     database file (its size seen growing, the checkpoint not returned).
//
// After each kill, every disclosure a client received has its
// secret.disclosed event, audit positions have no gap, the database is
// consistent, and the large batch is there whole or not at all.

const ballastBytes = 48 << 20

type crashRun struct {
	t        *testing.T
	in       install
	f        valuestest.Fixture
	cmd      *exec.Cmd
	stderr   syncBuffer
	log, arm string
	base     string

	mu       sync.Mutex
	answered []string
	stop     chan struct{}
	wg       sync.WaitGroup
}

func (c *crashRun) path(name string) string { return filepath.Join(c.in.data, name) }

func startCrashRun(t *testing.T, env ...string) *crashRun {
	t.Helper()
	in, f := g7Install(t, t.TempDir())
	c := &crashRun{t: t, in: in, f: f, log: filepath.Join(in.dir, "crashpoints.log"), arm: filepath.Join(in.dir, "arm"), stop: make(chan struct{})}
	c.cmd = exec.Command(os.Args[0], "-test.run=^TestKillDuringDisclosuresLosesNoAuditRow$")
	c.cmd.Env = append(os.Environ(), append([]string{"G7_SERVE_CONF=" + in.conf, "VARLATCH_CRASHPOINT_LOG=" + c.log, "VARLATCH_CRASHPOINT_ARM=" + c.arm}, env...)...)
	out, err := c.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.cmd.Stderr = &c.stderr
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	})
	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if a, ok := strings.CutPrefix(sc.Text(), "ready "); ok {
				addr <- a
			}
		}
	}()
	select {
	case a := <-addr:
		c.base = "http://" + a
	case <-time.After(30 * time.Second):
		t.Fatalf("varlatchd did not serve: %s", c.stderr.String())
	}
	// Clients ask for disclosures until the process is gone.
	client := &http.Client{Timeout: 30 * time.Second}
	for range 6 {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for {
				select {
				case <-c.stop:
					return
				default:
				}
				status, id, body, err := disclose(client, c.base, f.Tokens["alice"])
				if err != nil {
					return
				}
				if status == 200 && strings.Contains(body, "hunter2-hunter2") {
					c.mu.Lock()
					c.answered = append(c.answered, id)
					c.mu.Unlock()
				}
			}
		}()
	}
	c.waitFor("50 disclosures answered", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.answered) >= 50 })
	return c
}

func (c *crashRun) waitFor(what string, ok func() bool) {
	c.t.Helper()
	for deadline := time.Now().Add(60 * time.Second); !ok(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for %s: %s", what, c.stderr.String())
		}
	}
}

// lines are the crash points logged so far.
func (c *crashRun) lines() []string {
	b, _ := os.ReadFile(c.log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (c *crashRun) logged(line string) bool {
	for _, l := range c.lines() {
		if l == line {
			return true
		}
	}
	return false
}

func (c *crashRun) armNow() {
	if err := os.WriteFile(c.arm, nil, 0o600); err != nil {
		c.t.Fatal(err)
	}
}

func size(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// kill sends SIGKILL, waits for the process and the clients.
func (c *crashRun) kill() {
	if err := c.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		c.t.Fatal(err)
	}
	_ = c.cmd.Wait()
	close(c.stop)
	c.wg.Wait()
}

// verify opens the database the killed process left and checks it.
func (c *crashRun) verify() {
	t := c.t
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{Path: c.path(config.DatabaseFile)})
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
		t.Fatalf("%d audit events, the last at position %d: a gap", events, last)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range c.answered {
		var n int
		if err := r.QueryRow(`SELECT count(*) FROM audit_events WHERE request_id = ? AND event_type = 'secret.disclosed'`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("request %s received its values, but its secret.disclosed event is missing after the kill", id)
		}
	}
	var tables int
	if err := r.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name = 'crashpoint_ballast'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables == 1 {
		var rows int
		if err := r.QueryRow(`SELECT count(*) FROM crashpoint_ballast`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 0 && rows != ballastBytes>>20 {
			t.Fatalf("%d of the large batch's %d rows survived: not atomic", rows, ballastBytes>>20)
		}
		t.Logf("the large batch: %d rows after recovery", rows)
	}
	t.Logf("%d disclosures answered before the kill, each with its audit event; %d events", len(c.answered), events)
}

func TestKillAtCrashPoints(t *testing.T) {
	// Inside a commit: the next batch after arming pauses in SQLite's
	// commit hook, before any of its WAL frames is written.
	t.Run("inside a commit", func(t *testing.T) {
		c := startCrashRun(t, "VARLATCH_CRASHPOINT_PAUSE=commit")
		c.armNow()
		c.waitFor("a paused commit", func() bool { return c.logged("paused commit") })
		time.Sleep(100 * time.Millisecond) // more disclosures queue behind it
		c.kill()
		c.verify()
	})

	// During a WAL write: the large batch's frames go to the WAL while its
	// job runs and at its commit; the kill comes once the WAL has grown by
	// 8 MiB and before its COMMIT returned. Retried when the batch wins the
	// race.
	t.Run("during a WAL write", func(t *testing.T) {
		for attempt := 1; ; attempt++ {
			c := startCrashRun(t, "VARLATCH_CRASHPOINT_BALLAST="+strconv.Itoa(ballastBytes))
			c.armNow()
			c.waitFor("the large batch", func() bool { return c.logged("ballast-start") })
			start := size(c.path(config.DatabaseFile) + "-wal")
			c.waitFor("the WAL to grow", func() bool {
				return size(c.path(config.DatabaseFile)+"-wal") >= start+8<<20 || c.logged("ballast-committed")
			})
			c.kill()
			if c.logged("ballast-committed") {
				if attempt == 3 {
					t.Fatal("three times the large batch committed before the kill")
				}
				continue
			}
			t.Logf("killed with the WAL at %d bytes (%d at the batch's start), the batch not committed", size(c.path(config.DatabaseFile)+"-wal"), start)
			c.verify()
			return
		}
	})

	// During a checkpoint: once the large batch committed, the next
	// checkpoint copies its frames into the database file; the kill comes
	// once that file has grown by 4 MiB and before the checkpoint returned.
	t.Run("during a checkpoint", func(t *testing.T) {
		for attempt := 1; ; attempt++ {
			c := startCrashRun(t, "VARLATCH_CRASHPOINT_BALLAST="+strconv.Itoa(ballastBytes))
			c.armNow()
			c.waitFor("the large batch to commit", func() bool { return c.logged("ballast-committed") })
			db := c.path(config.DatabaseFile)
			start := size(db)
			// A checkpoint started after the batch committed, not yet returned.
			inCheckpoint := func() bool {
				l := c.lines()
				after := false
				open := false
				for _, x := range l {
					switch {
					case x == "ballast-committed":
						after = true
					case after && x == "checkpoint":
						open = true
					case after && x == "checkpointed":
						open = false
					}
				}
				return open
			}
			c.waitFor("the database file to grow in a checkpoint", func() bool { return size(db) >= start+4<<20 && inCheckpoint() || size(db) >= start+ballastBytes })
			copying := inCheckpoint()
			c.kill()
			if !copying || !inCheckpoint() {
				if attempt == 3 {
					t.Fatal("three times the checkpoint finished before the kill")
				}
				continue
			}
			t.Logf("killed in a checkpoint with the database file at %d bytes (%d before)", size(db), start)
			c.verify()
			return
		}
	})
}
