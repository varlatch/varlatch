// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

// helperArgs is the environment variable that makes this test binary run
// one `varlatchd admin` command and exit with its status (TestAdminHelper):
// the "other process" of decision 11's test.
const helperArgs = "VARLATCH_TEST_ADMIN_ARGS"

// TestAdminHelper is not a test: run by TestOperatorCommandsWaitForAnEffect
// as a process of its own, it runs the admin command its environment names.
func TestAdminHelper(t *testing.T) {
	raw := os.Getenv(helperArgs)
	if raw == "" {
		t.Skip("run as a process by TestOperatorCommandsWaitForAnEffect")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		os.Exit(70)
	}
	os.Exit(admin(args, os.Stdout, os.Stderr))
}

type adminProcess struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	done           chan error
}

func spawnAdmin(t *testing.T, args ...string) *adminProcess {
	t.Helper()
	raw, _ := json.Marshal(args)
	p := &adminProcess{cmd: exec.Command(os.Args[0], "-test.run=^TestAdminHelper$", "-test.count=1"), done: make(chan error, 1)}
	p.cmd.Env = append(os.Environ(), helperArgs+"="+string(raw))
	p.cmd.Stdout, p.cmd.Stderr = &p.stdout, &p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	return p
}

// Feature-parity decision 11: with the daemon holding an external effect
// of an Organization open (a test-only effect against a blocking fake),
// `admin security reset` and `admin unfreeze`, run from other processes,
// reach the daemon through its socket, take its Organization gate, wait,
// and commit only after the effect ended, as the TypeScript commands wait
// on the Organization row the effect holds.
func TestOperatorCommandsWaitForAnEffect(t *testing.T) {
	in := newInstall(t, "")
	writers := make(chan *write.Writer, 1)
	r := startWith(t, in, &hooks{writer: func(w *write.Writer) { writers <- w }})
	w := <-writers
	ctx := context.Background()

	material, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	rootKEK, err := envelope.ParseRootKEK(string(material))
	if err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_controls (organization_id, control, mode, version) VALUES (?, 'admin-step-up', 'enforce', 2)`, org.ID)

	// The effect, inside the daemon: its call blocks until released.
	called, release := make(chan struct{}), make(chan struct{})
	effectDone := make(chan error, 1)
	go func() {
		_, _, err := write.RunEffect(ctx, w, write.Effect[int, int]{
			OrganizationID: org.ID,
			Call:           func(context.Context) (int, error) { close(called); <-release; return 0, nil },
			Final:          func(context.Context, *storage.Tx, int) (int, error) { return 0, nil },
		})
		effectDone <- err
	}()
	<-called
	// A freeze to lift. Freezing through the daemon would wait for the
	// effect too, so its row is written straight to the database.
	exec(`INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_aaaaaaaaaaaaaaaaaaaaaaaaaa', ?, 'idn_a', ?, 'drill')`,
		org.ID, time.Now().UnixMicro())

	reset := spawnAdmin(t, "security", "reset", "--org", "acme", "--all", "--config", in.conf)
	unfreeze := spawnAdmin(t, "unfreeze", "--org", "acme", "--confirm", "acme", "--json", "--config", in.conf)
	// Both reach the daemon and wait on its gate.
	deadline := time.Now().Add(20 * time.Second)
	for waiting := 0; waiting < 2; {
		waiting = 0
		for _, g := range w.Gates.Waiting() {
			if g.Level == write.LevelOrganization && g.Key == org.ID && g.Mode == write.Exclusive {
				waiting++
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the commands did not reach the daemon's gate: %s %s", reset.stderr.String(), unfreeze.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-reset.done:
		t.Fatalf("reset finished during the effect: %v %s", err, reset.stderr.String())
	case err := <-unfreeze.done:
		t.Fatalf("unfreeze finished during the effect: %v %s", err, unfreeze.stderr.String())
	case <-time.After(300 * time.Millisecond):
	}
	rows := func(q string, args ...any) int {
		var n int
		if err := w.Store.Reader().QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rows(`SELECT count(*) FROM security_controls WHERE organization_id = ? AND mode = 'enforce'`, org.ID) != 1 ||
		rows(`SELECT count(*) FROM organization_freezes WHERE organization_id = ? AND lifted_at IS NULL`, org.ID) != 1 {
		t.Fatal("a command wrote during the effect")
	}

	released := time.Now()
	close(release)
	// The effect's final job finds the freeze written meanwhile and keeps
	// nothing; what matters is that it ended before the commands ran.
	if err := <-effectDone; err != nil && !strings.Contains(err.Error(), "ORGANIZATION_FROZEN") {
		t.Fatal(err)
	}
	for name, p := range map[string]*adminProcess{"reset": reset, "unfreeze": unfreeze} {
		select {
		case err := <-p.done:
			if err != nil {
				t.Fatalf("%s: %v %s", name, err, p.stderr.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s did not finish after the effect", name)
		}
	}
	if !strings.Contains(reset.stdout.String(), "  admin-step-up: enforce -> off (version 3)") {
		t.Errorf("reset printed %q", reset.stdout.String())
	}
	var lifted struct {
		Freeze struct {
			LiftMethod string `json:"liftMethod"`
		} `json:"freeze"`
	}
	if err := json.Unmarshal(unfreeze.stdout.Bytes(), &lifted); err != nil || lifted.Freeze.LiftMethod != "operator" {
		t.Errorf("unfreeze printed %q: %v", unfreeze.stdout.String(), err)
	}
	// Both committed after the release.
	if n := rows(`SELECT count(*) FROM audit_events WHERE organization_id = ? AND event_type IN ('security_control.reset', 'organization.unfrozen') AND occurred_at >= ?`,
		org.ID, released.UnixMilli()*1000); n != 5 {
		t.Errorf("%d events after the release, want 4 resets and 1 lift", n)
	}

	// Offline, under the lock, once the daemon stopped: the same commands.
	r.stop(t)
	if code, out, errOut := runAdmin(t, "security", "reset", "--org", "acme", "--control", "admin-step-up", "--config", in.conf); code != ExitOK ||
		!strings.Contains(out, "  admin-step-up: already off\n") {
		t.Errorf("reset offline: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runAdmin(t, "unfreeze", "--org", "acme", "--confirm", "acme", "--config", in.conf); code != ExitFailure ||
		errOut != "varlatchd admin unfreeze: STATE_CHANGED: acme is not frozen\n" {
		t.Errorf("unfreeze offline, not frozen: %d %q", code, errOut)
	}
	// A usage error never reaches the daemon or the database.
	if code, _, errOut := runAdmin(t, "security", "reset", "--org", "acme", "--config", in.conf); code != 64 || !strings.HasPrefix(errOut, "Usage: varlatchd admin security reset") {
		t.Errorf("usage: %d %q", code, errOut)
	}
}
