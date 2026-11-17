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
