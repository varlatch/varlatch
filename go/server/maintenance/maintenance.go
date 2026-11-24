// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maintenance is the installation's maintenance admission
// (ADR-0036 D6; ADR-0059 step 4.14): while a gate is open, varlatchd admits
// no API work and answers 503 MAINTENANCE, which the dashboard and the CLI
// wait out. A restore opens a gate until it completes; an operator, and
// step 6's upgrade, open a lease that ends by itself. The gate is the
// TypeScript server's maintenance.json (lib/backup Gate), kept in the data
// directory so it holds across a restart, and one that cannot be read keeps
// the installation isolated.
package maintenance

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/server/ids"
)

// MaxLease bounds a lease, as the TypeScript capture deadline.
const (
	MinLease = time.Second
	MaxLease = 24 * time.Hour
)

// Admission is the gate as varlatchd holds it, and the requests it admitted
// that are still running.
type Admission struct {
	dir  string
	now  func() time.Time
	mu   sync.Mutex
	gate *backup.Gate
	// unreadable: the gate file exists but cannot be read; nothing is
	// admitted until an operator repairs it.
	unreadable bool
	// upgrading: an upgrade is checking this varlatchd (HoldForUpgrade);
	// upgradeNote is why it is still held.
	upgrading   bool
	upgradeNote string
	busy        int
}

// Open reads the gate in dir, the data directory.
func Open(dir string, now func() time.Time) *Admission {
	if now == nil {
		now = time.Now
	}
	a := &Admission{dir: dir, now: now}
	g, err := backup.ReadGate(dir)
	a.gate, a.unreadable = g, err != nil
	return a
}

// active is the open gate, or nil; an expired lease is removed. Called
// with mu held.
func (a *Admission) active() *backup.Gate {
	if a.gate != nil && !a.gate.Active(a.now()) {
		_ = os.Remove(filepath.Join(a.dir, backup.GateFile))
		a.gate = nil
	}
	return a.gate
}

// closed is whether nothing is admitted. Called with mu held.
func (a *Admission) closed() bool { return a.unreadable || a.upgrading || a.active() != nil }

// Isolated reports whether a gate is open (or unreadable), or an upgrade
// holds this varlatchd.
func (a *Admission) Isolated() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed()
}

// HoldForUpgrade admits nothing until EndUpgrade, beside whatever gate is
// open: this process's only, never written. It begins before anything asks
// to be admitted.
func (a *Admission) HoldForUpgrade() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upgrading, a.upgradeNote = true, UpgradeHeld
}

// Why an upgrade holds this varlatchd: it is not over; or its journal, which
// says when it is, is gone, or cannot be read.
const (
	UpgradeHeld              = "held"
	UpgradeJournalMissing    = "journal-missing"
	UpgradeJournalUnreadable = "journal-unreadable"
)

// NoteUpgrade says why the upgrade's hold stands.
func (a *Admission) NoteUpgrade(note string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upgradeNote = note
}

// UpgradeHold is why an upgrade holds this varlatchd, "" when none does.
func (a *Admission) UpgradeHold() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.upgrading {
		return ""
	}
	return a.upgradeNote
}

// EndUpgrade ends HoldForUpgrade's hold. A gate stays as it is.
func (a *Admission) EndUpgrade() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.upgrading = false
}

// Enter admits one request: false while isolated. leave ends it.
func (a *Admission) Enter() (leave func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed() {
		return nil, false
	}
	a.busy++
	done := false
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if !done {
			done = true
			a.busy--
		}
	}, true
}

// AdmitsMeta reports whether the open gate is a migration's, under which
// GET /v1/meta still answers (httpserver.MetaAdmission).
func (a *Admission) AdmitsMeta() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.active()
	return !a.unreadable && !a.upgrading && g != nil && g.Kind == "migration"
}

// EndMigration ends the migration's gate id (go-step7 decision 12, the
// live open): the gate is removed, and the API admitted again. No gate is
// nothing to do; another gate is refused.
func (a *Admission) EndMigration(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return backup.ErrGateUnreadable
	}
	g := a.active()
	if g == nil {
		return nil
	}
	if g.Kind != "migration" || g.ID != id || g.Phase != "transfer" {
		return fmt.Errorf("the open gate is a %s gate (%s, %s), not the migration %s's transfer", g.Kind, g.ID, g.Phase, id)
	}
	if err := os.Remove(filepath.Join(a.dir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	a.gate = nil
	return nil
}

// ErrBarrier refuses a barrier while another gate is open.
var ErrBarrier = errors.New("another maintenance operation owns this installation; the migration barrier was not opened")

// BeginBarrier opens the migration barrier of the migration id (go-step7
// decision 6, the reverse): a migration gate in phase draining, with no
// expiry, written durably. From here nothing new is admitted: no request
// but GET /v1/meta, no background pass, no host command that writes; the
// caller waits for what was admitted (Busy) to end. The same migration's
// barrier already open (draining, or paused) is returned as it is, so an
// interrupted barrier is continued; any other gate is refused.
func (a *Admission) BeginBarrier(id string) (backup.Gate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return backup.Gate{}, backup.ErrGateUnreadable
	}
	if g := a.active(); g != nil {
		if g.Kind == "migration" && g.ID == id && (g.Phase == "draining" || g.Phase == "paused") {
			return *g, nil
		}
		return backup.Gate{}, ErrBarrier
	}
	// A lease that expired while varlatchd was stopped.
	if err := os.Remove(filepath.Join(a.dir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return backup.Gate{}, err
	}
	g := backup.Gate{ID: id, Kind: "migration", Phase: "draining"}
	if err := backup.DurableJSON(filepath.Join(a.dir, backup.GateFile), g, true); err != nil {
		return backup.Gate{}, err
	}
	a.gate = &g
	return g, nil
}

// PauseBarrier records the drained barrier's frozen point: phase paused,
// the last audit position.
func (a *Admission) PauseBarrier(id string, position int64) (backup.Gate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return backup.Gate{}, backup.ErrGateUnreadable
	}
	g := a.active()
	if g == nil || g.Kind != "migration" || g.ID != id || (g.Phase != "draining" && g.Phase != "paused") {
		return backup.Gate{}, fmt.Errorf("the migration %s's barrier is not open", id)
	}
	frozen := strconv.FormatInt(position, 10)
	next := backup.Gate{ID: id, Kind: "migration", Phase: "paused", FrozenPosition: &frozen}
	if err := backup.DurableJSON(filepath.Join(a.dir, backup.GateFile), next, false); err != nil {
		return backup.Gate{}, err
	}
	a.gate = &next
	return next, nil
}

// ReleaseBarrier lifts the migration barrier of the migration id (the
// reverse undone): the gate removed, the API admitted again. No gate is
// nothing to do; another gate, a transfer's included, is refused.
func (a *Admission) ReleaseBarrier(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return backup.ErrGateUnreadable
	}
	g := a.active()
	if g == nil {
		return nil
	}
	if g.Kind != "migration" || g.ID != id || (g.Phase != "draining" && g.Phase != "paused") {
		return fmt.Errorf("the open gate is a %s gate (%s, %s), not the migration %s's barrier", g.Kind, g.ID, g.Phase, id)
	}
	if err := os.Remove(filepath.Join(a.dir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	a.gate = nil
	return nil
}

// Busy is how many admitted requests are still running.
func (a *Admission) Busy() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.busy
}

// Gate is the open gate, or nil.
func (a *Admission) Gate() (*backup.Gate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return nil, backup.ErrGateUnreadable
	}
	if g := a.active(); g != nil {
		c := *g
		return &c, nil
	}
	return nil, nil
}

// ErrOpen refuses a lease while another gate is open.
var ErrOpen = errors.New("Installation maintenance is already active")

// Begin opens a lease of ttl (the TypeScript capture gate's form: kind
// capture, its expiry in Unix milliseconds), written exclusively.
func (a *Admission) Begin(ttl time.Duration) (backup.Gate, error) {
	if ttl < MinLease || ttl > MaxLease {
		return backup.Gate{}, fmt.Errorf("the lease must be between %s and %s", MinLease, MaxLease)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unreadable {
		return backup.Gate{}, backup.ErrGateUnreadable
	}
	if a.active() != nil {
		return backup.Gate{}, ErrOpen
	}
	// A lease that expired while varlatchd was stopped.
	if err := os.Remove(filepath.Join(a.dir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return backup.Gate{}, err
	}
	expires := a.now().Add(ttl).UnixMilli()
	g := backup.Gate{ID: ids.UUID(), Kind: "capture", Phase: "draining", ExpiresAt: &expires}
	if err := backup.DurableJSON(filepath.Join(a.dir, backup.GateFile), g, true); err != nil {
		return backup.Gate{}, err
	}
	a.gate = &g
	c := g
	return c, nil
}

// End closes the lease id early. A restore's gate is not a lease.
func (a *Admission) End(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.active()
	if g == nil || g.ID != id {
		return errors.New("Maintenance ownership lost; no such lease is open")
	}
	if g.Kind != "capture" {
		return errors.New("Restore isolation cannot expire or be released as a lease")
	}
	if err := os.Remove(filepath.Join(a.dir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	a.gate = nil
	return nil
}
