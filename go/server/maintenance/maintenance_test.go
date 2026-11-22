// SPDX-License-Identifier: AGPL-3.0-or-later

package maintenance

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestLease(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	a := Open(dir, c.now)
	leave, ok := a.Enter()
	if !ok || a.Busy() != 1 {
		t.Fatal("not admitted without a gate")
	}
	leave()
	leave()
	if a.Busy() != 0 {
		t.Errorf("busy %d after leaving twice", a.Busy())
	}
	for _, ttl := range []time.Duration{0, 999 * time.Millisecond, 24*time.Hour + time.Millisecond} {
		if _, err := a.Begin(ttl); err == nil {
			t.Errorf("a lease of %s was opened", ttl)
		}
	}
	g, err := a.Begin(time.Minute)
	if err != nil || g.Kind != "capture" || g.Phase != "draining" || *g.ExpiresAt != c.now().Add(time.Minute).UnixMilli() || g.ArchiveID != nil || len(g.ID) != 36 {
		t.Fatalf("%+v %v", g, err)
	}
	// The TypeScript server's maintenance.json, which holds across a
	// restart.
	raw, err := os.ReadFile(filepath.Join(dir, backup.GateFile))
	var onDisk map[string]any
	if err != nil || json.Unmarshal(raw, &onDisk) != nil || len(onDisk) != 5 || onDisk["archiveId"] != nil || onDisk["kind"] != "capture" {
		t.Fatalf("%s %v", raw, err)
	}
	if _, ok := a.Enter(); ok || !a.Isolated() {
		t.Error("admitted during the lease")
	}
	if _, err := a.Begin(time.Minute); !errors.Is(err, ErrOpen) {
		t.Errorf("a second lease: %v", err)
	}
	if again := Open(dir, c.now); !again.Isolated() {
		t.Error("the lease did not hold across a restart")
	}
	if err := a.End("another"); err == nil {
		t.Error("another lease's id ended it")
	}
	if err := a.End(g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, backup.GateFile)); !os.IsNotExist(err) || a.Isolated() {
		t.Errorf("the lease outlived its end: %v", err)
	}
	// A lease ends by itself, and its file goes; its id no longer ends
	// anything.
	expired, err := a.Begin(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.add(time.Second)
	if err := a.End(expired.ID); err == nil {
		t.Error("an expired lease's id ended it")
	}
	if _, ok := a.Enter(); !ok {
		t.Error("not admitted after the lease expired")
	}
	if _, err := os.Stat(filepath.Join(dir, backup.GateFile)); !os.IsNotExist(err) {
		t.Errorf("the expired lease's file stayed: %v", err)
	}
	// One that expired while varlatchd was stopped: its id ends neither
	// it nor the lease opened after it.
	stale, err := a.Begin(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	b := Open(dir, c.now)
	if b.Isolated() {
		t.Error("an expired lease isolated a restart")
	}
	if err := b.End(stale.ID); err == nil {
		t.Error("an expired lease's id ended it after a restart")
	}
	next, err := b.Begin(time.Minute)
	if err != nil {
		t.Fatalf("a lease after an expired one: %v", err)
	}
	if err := b.End(stale.ID); err == nil || !b.Isolated() {
		t.Errorf("an expired lease's id ended the next lease: %v", err)
	}
	if err := b.End(next.ID); err != nil || b.Isolated() {
		t.Errorf("the next lease's own id: %v", err)
	}
}

// A gate that cannot be read keeps the installation isolated, and a
// restore's gate is not a lease.
func TestUnreadableAndRestoreGates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, backup.GateFile)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Open(dir, nil)
	if _, ok := a.Enter(); ok || !a.Isolated() {
		t.Error("admitted with an unreadable gate")
	}
	if _, err := a.Gate(); !errors.Is(err, backup.ErrGateUnreadable) {
		t.Errorf("gate: %v", err)
	}
	if _, err := a.Begin(time.Minute); !errors.Is(err, backup.ErrGateUnreadable) {
		t.Errorf("begin: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"id":"r1","kind":"restore","phase":"paused","expiresAt":null,"archiveId":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a = Open(dir, nil)
	if g, err := a.Gate(); err != nil || g == nil || g.Kind != "restore" {
		t.Fatalf("%+v %v", g, err)
	}
	if err := a.End("r1"); err == nil || a.Isolated() == false {
		t.Errorf("a restore gate ended as a lease: %v", err)
	}
}

// The reverse migration's barrier (go-step7 decision 6, Go's half): opened
// draining, nothing admitted from then but what ran; the same migration's
// barrier continued, another gate refused; paused with its frozen point;
// a restart stays behind it; released by its migration only, never by a
// lease's end or the transfer's open.
func TestMigrationBarrier(t *testing.T) {
	const id, other = "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", "mig_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	dir := t.TempDir()
	a := Open(dir, nil)
	leave, ok := a.Enter()
	if !ok {
		t.Fatal("not admitted")
	}
	g, err := a.BeginBarrier(id)
	if err != nil || g.Kind != "migration" || g.Phase != "draining" || g.ID != id || g.ExpiresAt != nil || g.FrozenPosition != nil {
		t.Fatalf("the barrier: %+v %v", g, err)
	}
	if _, ok := a.Enter(); ok {
		t.Fatal("admitted behind the barrier")
	}
	if a.Busy() != 1 || !a.AdmitsMeta() {
		t.Fatalf("busy %d, meta %v", a.Busy(), a.AdmitsMeta())
	}
	leave()
	if g, err := a.BeginBarrier(id); err != nil || g.Phase != "draining" {
		t.Fatalf("the same barrier again: %+v %v", g, err)
	}
	if _, err := a.BeginBarrier(other); !errors.Is(err, ErrBarrier) {
		t.Fatalf("another migration's barrier: %v", err)
	}
	if _, err := a.Begin(time.Minute); !errors.Is(err, ErrOpen) {
		t.Fatalf("a lease behind the barrier: %v", err)
	}
	if err := a.End(id); err == nil {
		t.Fatal("the barrier ended as a lease")
	}
	if err := a.EndMigration(id); err == nil {
		t.Fatal("the barrier ended as the transfer's gate")
	}
	if _, err := a.PauseBarrier(other, 7); err == nil {
		t.Fatal("another migration paused the barrier")
	}
	g, err = a.PauseBarrier(id, 42)
	if err != nil || g.Phase != "paused" || g.FrozenPosition == nil || *g.FrozenPosition != "42" {
		t.Fatalf("paused: %+v %v", g, err)
	}
	// On disk, as a restart reads it.
	b := Open(dir, nil)
	if got, err := b.Gate(); err != nil || got == nil || got.Phase != "paused" || *got.FrozenPosition != "42" || !b.Isolated() {
		t.Fatalf("after a restart: %+v %v", got, err)
	}
	if g, err := b.BeginBarrier(id); err != nil || g.Phase != "paused" {
		t.Fatalf("a paused barrier continued: %+v %v", g, err)
	}
	if err := b.ReleaseBarrier(other); err == nil {
		t.Fatal("another migration released the barrier")
	}
	if err := b.ReleaseBarrier(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Enter(); !ok {
		t.Fatal("not admitted after the release")
	}
	if _, err := os.Stat(filepath.Join(dir, backup.GateFile)); !os.IsNotExist(err) {
		t.Fatalf("the gate file after the release: %v", err)
	}
	if err := b.ReleaseBarrier(id); err != nil {
		t.Fatalf("a second release: %v", err)
	}
	// The transfer's gate is not a barrier: neither released nor
	// continued as one.
	transfer, _ := json.Marshal(backup.Gate{ID: id, Kind: "migration", Phase: "transfer"})
	if err := os.WriteFile(filepath.Join(dir, backup.GateFile), transfer, 0o600); err != nil {
		t.Fatal(err)
	}
	c := Open(dir, nil)
	if err := c.ReleaseBarrier(id); err == nil {
		t.Fatal("the transfer's gate released as a barrier")
	}
	if _, err := c.BeginBarrier(id); !errors.Is(err, ErrBarrier) {
		t.Fatalf("a barrier over the transfer's gate: %v", err)
	}
}

// A migration gate is read in its forms only: a transfer, a draining
// barrier, a paused one with its frozen point; any other is unreadable,
// and isolates.
func TestMigrationGateForms(t *testing.T) {
	for _, c := range []struct {
		json string
		ok   bool
	}{
		{`{"id":"m","kind":"migration","phase":"transfer","expiresAt":null,"archiveId":null}`, true},
		{`{"id":"m","kind":"migration","phase":"draining","expiresAt":null,"archiveId":null}`, true},
		{`{"id":"m","kind":"migration","phase":"paused","expiresAt":null,"archiveId":null,"frozenPosition":"17"}`, true},
		{`{"id":"m","kind":"migration","phase":"paused","expiresAt":null,"archiveId":null}`, false},
		{`{"id":"m","kind":"migration","phase":"paused","expiresAt":null,"archiveId":null,"frozenPosition":"-1"}`, false},
		{`{"id":"m","kind":"migration","phase":"paused","expiresAt":null,"archiveId":null,"frozenPosition":"017"}`, false},
		{`{"id":"m","kind":"migration","phase":"draining","expiresAt":null,"archiveId":null,"frozenPosition":"3"}`, false},
		{`{"id":"m","kind":"migration","phase":"draining","expiresAt":5,"archiveId":null}`, false},
		{`{"id":"m","kind":"migration","phase":"reconciling","expiresAt":null,"archiveId":null}`, false},
		{`{"id":"m","kind":"capture","phase":"draining","expiresAt":5,"archiveId":null,"frozenPosition":"3"}`, false},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, backup.GateFile), []byte(c.json), 0o600); err != nil {
			t.Fatal(err)
		}
		g, err := backup.ReadGate(dir)
		if c.ok != (err == nil && g != nil) {
			t.Errorf("%s: %+v %v", c.json, g, err)
		}
		if !c.ok && !Open(dir, nil).Isolated() {
			t.Errorf("%s: not isolated", c.json)
		}
	}
}
