// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build crashpoint && !windows

package daemon

import (
	"bufio"
	"context"
	"io"
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
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/values/valuestest"
)

// G7 against the server at controlled crash points (go test -tags
// crashpoint; lib/storage/crashpoint.go): varlatchd runs as a process of
// its own while clients ask for disclosures, and is killed with SIGKILL
//
//   - inside a commit: paused in SQLite's commit of a write batch, before
//     its WAL frames are written;
//   - during a WAL write: while a large batch's frames are being written to
//     the WAL (its size seen growing), before its commit began;
//   - during a checkpoint: while a checkpoint copies that batch, committed,
//     into the database file (its size seen growing, the checkpoint not
//     returned).
//
// Other clients exercise a Capability of a Broker the run adds (step 4.6):
// its answer carries the Secret, so its capability.exercised event had
// committed.
//
// After each kill, every disclosure a client received has its
// secret.disclosed event, every exercise its capability.exercised event,
// audit positions have no gap and the database is consistent; the large batch has none of its rows after the kill in its
// WAL write, and all of them after the kill in a checkpoint.

const ballastBytes = 48 << 20

type crashRun struct {
	t        *testing.T
	in       install
	f        valuestest.Fixture
	cmd      *exec.Cmd
	stderr   syncBuffer
	log, arm string
	base     string

	mu        sync.Mutex
	answered  []string
	exercised []string
	stop      chan struct{}
	wg        sync.WaitGroup
}

func (c *crashRun) path(name string) string { return filepath.Join(c.in.data, name) }

func startCrashRun(t *testing.T, env ...string) *crashRun {
	t.Helper()
	in, f := g7Install(t, t.TempDir())
	broker := addBroker(t, in, f)
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
	// Clients ask for disclosures, and exercise the Capability, until the
	// process is gone.
	client := &http.Client{Timeout: 30 * time.Second}
	for i := range 8 {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for {
				select {
				case <-c.stop:
					return
				default:
				}
				ask, into := func() (int, string, string, error) { return disclose(client, c.base, f.Tokens["alice"]) }, &c.answered
				if i%4 == 3 {
					ask, into = func() (int, string, string, error) { return exercise(client, c.base, broker) }, &c.exercised
				}
				status, id, body, err := ask()
				if err != nil {
					return
				}
				if status == 200 && strings.Contains(body, "hunter2-hunter2") {
					c.mu.Lock()
					*into = append(*into, id)
					c.mu.Unlock()
				}
			}
		}()
	}
	c.waitFor("50 disclosures and 10 exercises answered", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.answered) >= 50 && len(c.exercised) >= 10
	})
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

// verify opens the database the killed process left and checks it;
// ballastRows is how many rows of the large batch must be there (-1: the
// scenario wrote none).
func (c *crashRun) verify(ballastRows int) {
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
	for event, ids := range map[string][]string{"secret.disclosed": c.answered, "capability.exercised": c.exercised} {
		for _, id := range ids {
			var n int
			if err := r.QueryRow(`SELECT count(*) FROM audit_events WHERE request_id = ? AND event_type = ?`, id, event).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Fatalf("request %s received its values, but its %s event is missing after the kill", id, event)
			}
		}
	}
	if ballastRows >= 0 {
		var rows int
		if err := r.QueryRow(`SELECT count(*) FROM crashpoint_ballast`).Scan(&rows); err != nil {
			t.Fatalf("the large batch's table: %v", err)
		}
		if rows != ballastRows {
			t.Fatalf("%d of the large batch's %d rows after recovery, want %d", rows, ballastBytes>>20, ballastRows)
		}
		t.Logf("the large batch: %d rows after recovery, as required", rows)
	}
	t.Logf("%d disclosures and %d exercises answered before the kill, each with its audit event; %d events", len(c.answered), len(c.exercised), events)
}

// The Broker addBroker adds: its token and the Capability's path.
type g7Broker struct{ token, path string }

const g7CapabilitySecret = "vlt_cap_g7"

// addBroker adds to the install's database a Broker with a credential, an
// Agent with secret.use in acme, and a Capability of DB_PASS in acme/api's
// development (hunter2-hunter2).
func addBroker(t *testing.T, in install, f valuestest.Fixture) g7Broker {
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	org := f.Slugged("organizations", "acme", "")
	project := f.Slugged("projects", "api", org)
	var env string
	for _, e := range f.Rows["environments"] {
		if e["project_id"] == project && e["name"] == "development" {
			env, _ = e["id"].(string)
		}
	}
	broker, agent, capability := ids.New(ids.Identity), ids.New(ids.Identity), ids.New(ids.Capability)
	var token string
	err = store.Write(context.Background(), func(tx *storage.Tx) error {
		for _, x := range []struct{ id, kind string }{{broker, "broker"}, {agent, "agent"}} {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO identities (id, kind, name, organization_id) VALUES (?, ?, ?, ?)`, x.id, x.kind, "g7-"+x.kind, org); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions) VALUES (?, ?, ?, '{"kind":"organization"}', '["secret.use"]')`,
			ids.New(ids.Grant), org, agent); err != nil {
			return err
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id,
			items, destinations, targets, secret_hash, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, '["DB_PASS"]', '["api.example.com:443"]',
			'{"DB_PASS":["header:authorization"]}', ?, ?, ?)`,
			capability, org, broker, agent, project, env, values.HashSecret(g7CapabilitySecret), time.Now().Add(24*time.Hour).UnixMicro(), broker); err != nil {
			return err
		}
		issued, err := auth.IssueCredential(context.Background(), tx, time.Now().UnixMicro(), auth.Issue{IdentityID: broker, Kind: "service"})
		token = issued.Token
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return g7Broker{token: token, path: "/v1/organizations/acme/projects/api/environments/development/capabilities/" + capability + "/exercises"}
}

// exercise exercises the Broker's Capability: the status, the request's id
// and the body.
func exercise(client *http.Client, base string, b g7Broker) (int, string, string, error) {
	req, _ := http.NewRequest("POST", base+b.path, strings.NewReader(
		`{"capabilitySecret":"`+g7CapabilitySecret+`","destination":{"host":"api.example.com","port":443},"placements":[{"item":"DB_PASS","target":"header:authorization"}]}`))
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, "", "", err
	}
	return res.StatusCode, res.Header.Get("X-Request-Id"), string(body), nil
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
		c.verify(-1)
	})

	// During a WAL write: the large batch's job writes its frames to the
	// WAL as its inserts spill, before its commit begins. The kill comes once
	// the WAL has grown 8 MiB; an attempt in which the batch's commit had
	// begun by then ("ballast-commit", from the commit hook, before the
	// commit's own frames) is retried, since its outcome may be either. So an
	// accepted kill is inside the WAL write of an uncommitted batch, and
	// none of its rows may survive.
	t.Run("during a WAL write", func(t *testing.T) {
		for attempt := 1; ; attempt++ {
			c := startCrashRun(t, "VARLATCH_CRASHPOINT_BALLAST="+strconv.Itoa(ballastBytes))
			wal := c.path(config.DatabaseFile) + "-wal"
			c.armNow()
			c.waitFor("the large batch", func() bool { return c.logged("ballast-start") })
			start := size(wal)
			c.waitFor("the WAL to grow", func() bool { return size(wal) >= start+8<<20 || c.logged("ballast-commit") })
			c.kill()
			if c.logged("ballast-commit") {
				if attempt == 5 {
					t.Fatal("five times the large batch's commit began before the kill")
				}
				continue
			}
			t.Logf("killed with the WAL at %d bytes (%d at the batch's start), its commit not begun (attempt %d)", size(wal), start, attempt)
			c.verify(0)
			return
		}
	})

	// During a checkpoint: once the large batch committed ("ballast-durable",
	// its COMMIT returned), a checkpoint copies its frames into the database
	// file. The baseline is the file's size when the batch was queued, before
	// any of its frames could be checkpointed. The kill comes once the file
	// has grown 4 MiB in a checkpoint that started after the commit and has
	// not returned; an attempt in which a checkpoint copied the batch and
	// returned first is retried. The batch committed, so all its rows must
	// survive.
	t.Run("during a checkpoint", func(t *testing.T) {
		for attempt := 1; ; attempt++ {
			c := startCrashRun(t, "VARLATCH_CRASHPOINT_BALLAST="+strconv.Itoa(ballastBytes))
			db := c.path(config.DatabaseFile)
			c.armNow()
			c.waitFor("the large batch", func() bool { return c.logged("ballast-start") })
			base := size(db)
			// After the commit: whether a checkpoint is running, and
			// whether one has finished.
			state := func() (running, finished bool) {
				after := false
				for _, x := range c.lines() {
					switch {
					case x == "ballast-durable":
						after = true
					case after && x == "checkpoint":
						running = true
					case after && x == "checkpointed" && running:
						running, finished = false, true
					}
				}
				return
			}
			copied := func() bool { return size(db) >= base+ballastBytes*3/4 }
			c.waitFor("a checkpoint copying the batch", func() bool {
				running, finished := state()
				return running && size(db) >= base+4<<20 || finished && copied()
			})
			c.kill()
			if running, _ := state(); !running || size(db) < base+4<<20 {
				if attempt == 5 {
					t.Fatal("five times a checkpoint copied the batch and returned before the kill")
				}
				continue
			}
			t.Logf("killed in a checkpoint with the database file at %d bytes (%d before the batch; attempt %d)", size(db), base, attempt)
			c.verify(ballastBytes >> 20)
			return
		}
	})
}
