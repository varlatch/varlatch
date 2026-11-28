// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The target's side of `varlatch migrate` (internal docs/design/
// go-step7.md decisions 9 and 14, slice 7.4a): the migration journal in
// the data directory, the target's key files, and the discarding of the
// database a migration undone before its switch leaves.
//
// The journal (JournalFile) is `varlatch migrate`'s: varlatchd writes it
// as given and reads two members of it, its id and its phase. Until the
// phase is "open", varlatchd does not start on that data directory
// (migrationGate): the old installation may still reopen, so the new one
// must not serve.

// JournalFile is the migration journal's name in the data directory.
const JournalFile = "migration.json"

// The journal's phases, in order (`varlatch migrate`'s
// internal/migrate.Phase); "released" is a migration undone. After them,
// the reverse migration's (go-step7 decision 16, slice 7.6a): reversing
// (Go behind its barrier, or being put there), then the reverse bundle
// exported, imported by the TypeScript release onto a fresh database,
// checked, the address moving back; "rolled-back" is the reverse done,
// the TypeScript release the installation again. A reverse undone goes
// back to "open". "finished" is an open migration whose rollback window
// `varlatch migrate --finish` ended (decision 17): Go is the installation
// for good, and no reverse starts from it.
var journalPhases = []string{"started", "preflight", "dry-run", "barrier", "copied", "checked", "transfer", "switched", "open", "released",
	"rollback", "rollback-exported", "rollback-imported", "rollback-checked", "rollback-transfer", "rolled-back", "finished"}

// reversing are the reverse migration's phases before it is done: Go
// still the installation, behind its barrier once it froze.
var reversing = []string{"rollback", "rollback-exported", "rollback-imported", "rollback-checked", "rollback-transfer"}

// beforeBarrier are the phases a migration is redone from its start in.
var beforeBarrier = []string{"started", "preflight", "dry-run"}

// undoable are the phases before the switch: the target's database may be
// discarded then.
var undoable = []string{"started", "preflight", "dry-run", "barrier", "copied", "checked", "transfer", "released"}

var journalID = regexp.MustCompile(`^mig_[a-z2-7]{26}$`)

// journalHead is what varlatchd reads of a journal.
type journalHead struct {
	Format int    `json:"format"`
	ID     string `json:"id"`
	Phase  string `json:"phase"`
	// WindowEnded is an upgrade's record that it ended the migration's
	// rollback window (decision 17): no reverse starts after it.
	WindowEnded *struct {
		Release string `json:"release"`
	} `json:"windowEnded"`
	// History is the phases reached and when, for the rollback window's
	// start (the switch).
	History []struct {
		Phase string `json:"phase"`
		At    string `json:"at"`
	} `json:"history"`
}

// migrationRollbackWindow is `varlatch migrate`'s RollbackWindow: how long
// after its switch an open migration can still be reversed (decision 17).
const migrationRollbackWindow = 30 * 24 * time.Hour

// migrationWindowOpen is whether dataDir's migration is in its rollback
// window at now, as `varlatch migrate`'s RollbackWindowOpen says it: open,
// switched no more than 30 days ago and not ended by an upgrade, or a
// reverse under way. No migration is not.
func migrationWindowOpen(dataDir string, now time.Time) (bool, error) {
	h, ok, err := readJournal(dataDir)
	if err != nil || !ok {
		return false, err
	}
	if slices.Contains(reversing, h.Phase) {
		return true, nil
	}
	if h.Phase != "open" || h.WindowEnded != nil {
		return false, nil
	}
	for _, s := range h.History {
		if s.Phase == "switched" {
			at, err := time.Parse(time.RFC3339Nano, s.At)
			return err == nil && now.Sub(at) <= migrationRollbackWindow, nil
		}
	}
	return false, nil
}

func parseJournal(b []byte) (journalHead, error) {
	var h journalHead
	if err := json.Unmarshal(b, &h); err != nil {
		return h, fmt.Errorf("the migration journal is not JSON: %v", err)
	}
	switch {
	case h.Format != 1:
		return h, fmt.Errorf("the migration journal's format is %d; this varlatchd reads format 1", h.Format)
	case !journalID.MatchString(h.ID):
		return h, errors.New("the migration journal has no valid id")
	case !slices.Contains(journalPhases, h.Phase):
		return h, fmt.Errorf("the migration journal's phase %q is not one varlatchd knows", h.Phase)
	}
	return h, nil
}

// readJournal reads dir's journal; ok is false when it has none.
func readJournal(dir string) (h journalHead, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if errors.Is(err, fs.ErrNotExist) {
		return h, false, nil
	}
	if err != nil {
		return h, false, err
	}
	h, err = parseJournal(b)
	return h, true, err
}

// migrationGate refuses to serve a data directory mid-migration: its
// journal's phase is not "open" (decision 14). An unreadable journal
// refuses too.
func migrationGate(dataDir string) error {
	h, ok, err := readJournal(dataDir)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %v; varlatchd does not start on a data directory whose migration it cannot read", filepath.Join(dataDir, JournalFile), err)
	case !ok || h.Phase == "open" || h.Phase == "finished":
		return nil
	case h.Phase == "transfer":
		// The address transfer (decision 12): varlatchd serves, isolated
		// by the migration's own gate, so the public URL can be checked;
		// without that gate it does not start.
		g, err := backup.ReadGate(dataDir)
		if err != nil || g == nil || g.Kind != "migration" || g.ID != h.ID {
			return fmt.Errorf("the migration %s is transferring its address, but the data directory holds no gate of it; varlatchd starts isolated by it only (varlatch migrate --status)", h.ID)
		}
		return nil
	case h.Phase == "released":
		return fmt.Errorf("the migration %s into this data directory was undone; its database is the old installation's copy, not to serve (varlatch migrate --status)", h.ID)
	case h.Phase == "rollback":
		// Reversing, Go is still the installation: it serves, isolated by
		// its barrier once that stands (an interrupted reverse leaves Go
		// running, decision 17).
		return nil
	case slices.Contains(reversing, h.Phase):
		// Past the frozen point the rebuilt TypeScript installation holds
		// Go's state as the barrier froze it: varlatchd serves behind
		// that barrier only, never taking a write the rebuild lacks.
		g, err := backup.ReadGate(dataDir)
		if err != nil || g == nil || g.Kind != "migration" || g.ID != h.ID || g.Phase == "transfer" {
			return fmt.Errorf("the migration %s is being reversed (phase %s), but the data directory holds no barrier of it; varlatchd starts behind it only (varlatch migrate --status)", h.ID, h.Phase)
		}
		return nil
	case h.Phase == "rolled-back":
		return fmt.Errorf("the migration %s was reversed: the TypeScript release is the installation again, and this data directory is Go's copy as it was, not to serve (varlatch migrate --status; varlatch migrate --finish removes it)", h.ID)
	}
	return fmt.Errorf("the migration %s into this data directory is in phase %s; varlatchd starts once varlatch migrate opens it (varlatch migrate --status)", h.ID, h.Phase)
}

// writeDurably writes b to path through a temporary name in its
// directory, mode 0600, owned by uid when uid >= 0, synced, renamed, the
// directory synced.
func writeDurably(path string, b []byte, uid int) error {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(suffix)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil && uid >= 0 {
		err = f.Chown(uid, -1)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncFile(filepath.Dir(path))
}

// readLimited reads at most n bytes of stdin, refusing a terminal (what
// comes here is a key or the journal, from `varlatch migrate`'s pipe).
func readLimited(stdin io.Reader, n int64, what string) ([]byte, error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return nil, fmt.Errorf("%s comes on a pipe; standard input is a terminal", what)
	}
	b, err := io.ReadAll(io.LimitReader(stdin, n+1))
	if err != nil {
		clear(b)
		return nil, fmt.Errorf("cannot read %s from standard input: %v", what, err)
	}
	if int64(len(b)) > n {
		clear(b)
		return nil, fmt.Errorf("%s on standard input is larger than %d bytes", what, n)
	}
	return b, nil
}

// runMigrateState is `admin migrate state`: the data directory's journal
// as JSON ({"journal": <it> or null, "database": whether varlatch.db is
// there}); with --write, the journal on stdin written in its place. A
// journal of another migration is replaced only once that one was undone
// (released).
func runMigrateState(cfg *config.Config, a migrateArgs, b []byte, stdout io.Writer, fail func(int, string, ...any) int) int {
	if a.write {
		h, err := parseJournal(b)
		if err != nil {
			return fail(ExitFailure, "%v; nothing was written", err)
		}
		old, ok, err := readJournal(cfg.DataDir)
		if err != nil {
			return fail(ExitFailure, "the data directory's journal: %v; nothing was written", err)
		}
		// The window's end is the Go side's record: checked, never changed
		// once written, and kept when a journal of the same migration
		// comes without it (migrate's source journal does not carry it).
		next, err := journalWindow(b)
		if err != nil {
			return fail(ExitFailure, "%v; nothing was written", errWindowRecord)
		}
		if ok && old.ID == h.ID {
			oldRaw, err := os.ReadFile(filepath.Join(cfg.DataDir, JournalFile))
			if err != nil {
				return fail(ExitFailure, "the data directory's journal: %v; nothing was written", err)
			}
			prev, err := journalWindow(oldRaw)
			if err != nil {
				return fail(ExitFailure, "the data directory's journal: %v; nothing was written", errWindowRecord)
			}
			switch {
			case prev != nil && next == nil:
				if b, err = withWindow(b, *prev); err != nil {
					return fail(ExitFailure, "%v; nothing was written", err)
				}
			case prev != nil && *next != *prev:
				return fail(ExitFailure, "the migration %s's rollback window ended already, with varlatchd %s: that record does not change; nothing was written", h.ID, prev.Release)
			}
		}
		// Another migration's journal is replaced once that one was undone
		// (released), or reversed and its database discarded (rolled back,
		// then finished with its old data deleted).
		_, dbErr := os.Stat(cfg.DatabasePath())
		replaceable := old.Phase == "released" || old.Phase == "rolled-back" && errors.Is(dbErr, fs.ErrNotExist)
		if ok && old.ID != h.ID && !replaceable {
			return fail(ExitFailure, "the data directory holds the migration %s, in phase %s; it is not replaced by %s; nothing was written", old.ID, old.Phase, h.ID)
		}
		// A journal goes forward, but for a migration redone from its
		// start before its barrier, or undone before its switch.
		back := slices.Index(journalPhases, h.Phase) < slices.Index(journalPhases, old.Phase)
		redone := h.Phase == "started" && slices.Contains(beforeBarrier, old.Phase)
		// A reverse undone goes back to open, and to nothing else.
		reverseUndone := h.Phase == "open" && slices.Contains(reversing, old.Phase)
		if ok && old.ID == h.ID && slices.Contains(append(slices.Clone(reversing), "rolled-back"), old.Phase) && !slices.Contains(append(slices.Clone(reversing), "open", "rolled-back"), h.Phase) {
			return fail(ExitFailure, "the migration %s is in phase %s; its journal goes on to the reverse's phases, or back to open, not to %s; nothing was written", h.ID, old.Phase, h.Phase)
		}
		// Finished is the migration's last phase: never undone (released),
		// running or not.
		if ok && old.ID == h.ID && old.Phase == "finished" && h.Phase != "finished" {
			return fail(ExitFailure, "the migration %s is finished: its rollback window ended, and its journal stays finished, not %s; nothing was written", h.ID, h.Phase)
		}
		if ok && old.ID == h.ID && back && h.Phase != "released" && !redone && !reverseUndone {
			return fail(ExitFailure, "the migration %s is in phase %s; its journal does not go back to %s; nothing was written", h.ID, old.Phase, h.Phase)
		}
		if ok && old.ID == h.ID && (old.Phase == "switched" || old.Phase == "open") && h.Phase == "released" {
			return fail(ExitFailure, "the migration %s was switched; it is not undone here; nothing was written", h.ID)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, b); err != nil {
			return fail(ExitFailure, "%v; nothing was written", err)
		}
		owner := -1
		if st, err := os.Stat(cfg.DataDir); err == nil {
			owner = statOwner(st)
		}
		// The transfer's gate: written before the journal says transfer,
		// removed before it says open or released, so a journal never
		// says either while the gate stands (writeTransferGate).
		if h.Phase == "transfer" {
			if err := writeTransferGate(cfg.DataDir, h.ID, owner); err != nil {
				return fail(ExitFailure, "%v; nothing was written", err)
			}
		}
		if h.Phase == "open" || h.Phase == "released" {
			prior := old.Phase
			if !ok {
				prior = "nothing"
			}
			if err := removeTransferGate(cfg.DataDir, h.ID); err != nil {
				return fail(ExitFailure, "the transfer's gate %s could not be removed (%v), so the journal still says %s; remove that file by hand (it is the migration's gate, nothing else), then run varlatch migrate --resume",
					filepath.Join(cfg.DataDir, backup.GateFile), err, prior)
			}
		}
		if err := writeDurably(filepath.Join(cfg.DataDir, JournalFile), append(compact.Bytes(), '\n'), owner); err != nil {
			return fail(ExitFailure, "%v", err)
		}
	}
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, JournalFile))
	var journal json.RawMessage = []byte("null")
	switch {
	case err == nil:
		if _, perr := parseJournal(b); perr != nil {
			return fail(ExitFailure, "%v", perr)
		}
		journal = bytes.TrimSpace(b)
	case !errors.Is(err, fs.ErrNotExist):
		return fail(ExitFailure, "%v", err)
	}
	_, dbErr := os.Stat(cfg.DatabasePath())
	public := ""
	if cfg.PublicURL != nil {
		public = cfg.PublicURL.String()
	}
	https := ""
	if cfg.PublicHTTPS != nil {
		https = cfg.PublicHTTPS.Listen
	}
	gate, gerr := backup.ReadGate(cfg.DataDir)
	running := false
	if controlAnswers(cfg.DataDir, 2*time.Second) {
		running = true
	}
	out, _ := json.Marshal(struct {
		Journal     json.RawMessage `json:"journal"`
		Database    bool            `json:"database"`
		DataDir     string          `json:"dataDir"`
		Release     string          `json:"release"`
		PublicURL   string          `json:"publicUrl"`
		Listen      string          `json:"listen"`
		ListenHTTPS string          `json:"listenHttps"`
		// OutboundAllow is the configuration's outbound_allow, as written
		// ("" for none): what migrate compares with the source's.
		OutboundAllow string `json:"outboundAllow"`
		// MigrationGate is whether the transfer's gate stands (an
		// unreadable gate counts: it isolates as well); Barrier a reverse
		// migration's barrier's phase (draining, paused), when one
		// stands; Running whether a varlatchd answers on the data
		// directory's control socket.
		MigrationGate bool   `json:"migrationGate"`
		Barrier       string `json:"barrier,omitempty"`
		Running       bool   `json:"running"`
		// Tailnet is the tailnet listener's settings and its node's handoff
		// state (go-step7 decision 11), null when tailnet = off.
		Tailnet *tailnetState `json:"tailnet"`
		// ImportRefusal is why an import into the data directory would be
		// refused now (importableDataDir, the import's own check), empty
		// when it would not: varlatch migrate's preflight refuses it before
		// the barrier.
		ImportRefusal string `json:"importRefusal,omitempty"`
	}{journal, dbErr == nil, cfg.DataDir, buildinfo.Version, public, cfg.Listen, https, cfg.OutboundAllow,
		gerr != nil || (gate != nil && gate.Kind == "migration" && gate.Phase == "transfer"), barrierPhase(gate), running, readTailnetState(cfg), importRefusal(cfg.DataDir)})
	fmt.Fprintln(stdout, string(out))
	return ExitOK
}

func importRefusal(dataDir string) string {
	if err := importableDataDir(dataDir); err != nil {
		return err.Error()
	}
	return ""
}

// tailnetState is `admin migrate state`'s tailnet: what `varlatch migrate`
// plans the handoff from. Never the auth key, only whether its file holds
// one.
type tailnetState struct {
	Hostname   string   `json:"hostname"`
	Tags       []string `json:"tags"`
	HTTPSPort  int      `json:"httpsPort"`
	AuthKey    bool     `json:"authKey"`
	Enrolled   bool     `json:"enrolled"`
	HeldAs     string   `json:"heldAs"`
	PinnedTo   string   `json:"pinnedTo"`
	HoldBroken bool     `json:"holdBroken,omitempty"`
	// ControlURL is tailnet_control_url, canonical; "" is Tailscale's.
	ControlURL string `json:"controlUrl,omitempty"`
}

func readTailnetState(cfg *config.Config) *tailnetState {
	t := cfg.Tailnet
	if t == nil {
		return nil
	}
	st := &tailnetState{Hostname: t.Hostname, Tags: t.Tags, HTTPSPort: t.HTTPSPort, ControlURL: t.ControlURL}
	if t.AuthKeyFile != "" {
		if b, err := preread.ReadFile(t.AuthKeyFile); err == nil {
			st.AuthKey = len(bytes.TrimSpace(b)) > 0
			clear(b)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, tailnet.StateDir, "tailscaled.state")); err == nil {
		st.Enrolled = true
	}
	if h, err := tailnet.LoadHold(cfg.DataDir); err != nil {
		st.HoldBroken = true
	} else if h != nil {
		st.HeldAs = h.Hostname
	}
	if p, err := tailnet.LoadPin(filepath.Join(cfg.DataDir, tailnet.PinFile)); err == nil && p != nil && !p.Enrolling {
		st.PinnedTo = p.Suffix
	}
	return st
}

// barrierPhase is a reverse migration's barrier's phase, "" for none.
func barrierPhase(g *backup.Gate) string {
	if g != nil && g.Kind == "migration" && g.Phase != "transfer" {
		return g.Phase
	}
	return ""
}

// writeTransferGate writes the migration's gate (maintenance.json, kind
// migration, phase transfer, no expiry): varlatchd then starts isolated,
// answering GET /v1/meta only (httpserver.MetaAdmission). Another gate
// (a lease, a restore) is refused, never replaced.
func writeTransferGate(dataDir, id string, owner int) error {
	g, err := backup.ReadGate(dataDir)
	switch {
	case err != nil:
		return fmt.Errorf("the data directory's maintenance gate: %w", err)
	case g != nil && (g.Kind != "migration" || g.ID != id):
		return fmt.Errorf("the data directory holds a %s gate (%s); the transfer's is not written over it", g.Kind, g.ID)
	case g != nil:
		return nil
	}
	b, err := json.Marshal(backup.Gate{ID: id, Kind: "migration", Phase: "transfer"})
	if err != nil {
		return err
	}
	return writeDurably(filepath.Join(dataDir, backup.GateFile), b, owner)
}

// windowEnded is a journal's record that an upgrade ended the migration's
// rollback window (varlatch upgrade, go-step7 decision 17).
type windowEnded struct {
	Release string `json:"release"`
	At      string `json:"at"`
}

// errWindowRecord is a windowEnded that is not a release and a time; the
// record's text is never repeated.
var errWindowRecord = errors.New("the journal's windowEnded is not a release version and a time")

// journalWindow is b's windowEnded, checked: nil when it has none.
func journalWindow(b []byte) (*windowEnded, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	v, ok := raw["windowEnded"]
	if !ok || string(v) == "null" {
		return nil, nil
	}
	var w windowEnded
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || !release.ValidVersion(w.Release) {
		return nil, errWindowRecord
	}
	if _, err := time.Parse(time.RFC3339Nano, w.At); err != nil {
		return nil, errWindowRecord
	}
	return &w, nil
}

// sameButWindow is whether two journals are the same document but for
// windowEnded (compared as JSON values, not bytes).
func sameButWindow(a, b []byte) bool {
	var x, y map[string]any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	if da.Decode(&x) != nil || db.Decode(&y) != nil {
		return false
	}
	delete(x, "windowEnded")
	delete(y, "windowEnded")
	return reflect.DeepEqual(x, y)
}

// onlyEndsWindow is whether next is old with a valid windowEnded added, and
// nothing else changed: the one write of an open journal that is the
// journal's word alone beside the running varlatchd (an upgrade ending the
// rollback window).
func onlyEndsWindow(old, next []byte) bool {
	ow, oerr := journalWindow(old)
	nw, nerr := journalWindow(next)
	return oerr == nil && nerr == nil && ow == nil && nw != nil && sameButWindow(old, next)
}

// transferGateStands is whether the migration id's transfer gate stands
// in dataDir; an unreadable gate counts as standing.
func transferGateStands(dataDir, id string) bool {
	g, err := backup.ReadGate(dataDir)
	return err != nil || g != nil && g.Kind == "migration" && g.ID == id && g.Phase == "transfer"
}

// withWindow is the journal b with windowEnded set to w.
func withWindow(b []byte, w windowEnded) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	v, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	raw["windowEnded"] = v
	return json.Marshal(raw)
}

// removeTransferGate removes the migration's gate, when it is this one's.
func removeTransferGate(dataDir, id string) error {
	g, err := backup.ReadGate(dataDir)
	if err != nil || g == nil || g.Kind != "migration" || g.ID != id || g.Phase != "transfer" {
		// A reverse's barrier is its own commands' (barrier, release).
		return err
	}
	if err := os.Remove(filepath.Join(dataDir, backup.GateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncFile(dataDir)
}

// runMigrateDiscard is `admin migrate discard --id <migration>`: the
// database a migration built in the data directory, removed, when the
// journal names that migration and it was not switched (decision 14:
// interrupted before the switch, the new data directory is discarded).
// The journal stays.
func runMigrateDiscard(cfg *config.Config, a migrateArgs, stdout io.Writer, fail func(int, string, ...any) int) int {
	h, ok, err := readJournal(cfg.DataDir)
	switch {
	case err != nil:
		return fail(ExitFailure, "%v; nothing was removed", err)
	case !ok:
		return fail(ExitFailure, "the data directory %s has no migration journal: its database is not a migration's to discard; nothing was removed", cfg.DataDir)
	case h.ID != a.id:
		return fail(ExitFailure, "the data directory's journal is the migration %s, not %s; nothing was removed", h.ID, a.id)
	case !slices.Contains(undoable, h.Phase) && h.Phase != "rolled-back":
		return fail(ExitFailure, "the migration %s is in phase %s, past its switch: its database is the installation's; nothing was removed", h.ID, h.Phase)
	}
	// Rolled back, the database is Go's copy, the TypeScript release the
	// installation again: varlatch migrate --finish --delete-old-data
	// discards it (and the reverse's frozen copy) once its final archive
	// is verified.
	frozen := FrozenCopyName(h.ID)
	entries, err := os.ReadDir(cfg.DataDir)
	if err != nil {
		return fail(ExitFailure, "%v", err)
	}
	removed := []string{}
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() && n != backup.HoldFile {
			continue
		}
		db := n == config.DatabaseFile || n == config.DatabaseFile+"-wal" || n == config.DatabaseFile+"-shm" || n == config.DatabaseFile+"-journal"
		if h.Phase == "rolled-back" && strings.HasPrefix(n, frozen) {
			db = true
		}
		// A restore's hold is the database's: none is left without one.
		db = db || n == backup.HoldFile
		if !db && !migrate.IsLeftover(n) {
			continue
		}
		if err := os.Remove(filepath.Join(cfg.DataDir, n)); err != nil {
			return fail(ExitFailure, "%v", err)
		}
		removed = append(removed, n)
	}
	if err := syncFile(cfg.DataDir); err != nil {
		return fail(ExitFailure, "%v", err)
	}
	out, _ := json.Marshal(struct {
		Removed []string `json:"removed"`
	}{removed})
	fmt.Fprintln(stdout, string(out))
	return ExitOK
}

// runMigrateKeys is `admin migrate keys`: the source's Root KEK, and its
// Backup Encryption Key when given, written to the target's key files
// (root_kek_file, backup_key_file; mode 0600, owned by the caller), on
// stdin as {"rootKek": "<the file's bytes, base64>", "bek": "<the same>"}
// (decision 9: the same keys, never a rotation), and the new tailnet node's
// auth key when given ("tailnetAuthKey", into tailnet_auth_key_file: the
// handoff enrols the node with it). Each is checked first: a
// Root KEK as varlatchd reads one, a BEK as its backups read one, distinct
// from the Root KEK. A key file that is already there must hold the same
// key; another is refused. Nothing of a key is printed.
func runMigrateKeys(cfg *config.Config, stdin io.Reader, stdout io.Writer, fail func(int, string, ...any) int) int {
	raw, err := readLimited(stdin, 64<<10, "the keys")
	if err != nil {
		return fail(64, "%v", err)
	}
	defer clear(raw)
	var in struct {
		RootKEK        []byte `json:"rootKek"`
		BEK            []byte `json:"bek"`
		TailnetAuthKey []byte `json:"tailnetAuthKey"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(in.RootKEK) == 0 {
		return fail(64, "standard input does not hold the keys: {\"rootKek\": <base64>, \"bek\": <base64>}")
	}
	defer clear(in.RootKEK)
	defer clear(in.BEK)
	defer clear(in.TailnetAuthKey)
	if len(in.TailnetAuthKey) > 0 && (cfg.Tailnet == nil || cfg.Tailnet.AuthKeyFile == "") {
		return fail(ExitConfig, "a tailnet auth key was given and the configuration names no tailnet_auth_key_file (tailnet = on); nothing was written")
	}
	kek, err := envelope.ParseRootKEK(string(in.RootKEK))
	if err != nil {
		return fail(ExitFailure, "the source's Root KEK is not one varlatchd reads: %v; nothing was written", err)
	}
	defer clear(kek)
	var bekMaterial []byte
	if len(in.BEK) > 0 {
		if cfg.BackupKeyFile == "" {
			// Under its unit varlatchd reads the backup-key credential
			// beside the Root KEK's when it is there (config.Parse): a
			// target setup's way, whose keys this writes, gets it there.
			if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && cfg.RootKEKFile == filepath.Join(dir, "root-kek") {
				cfg.BackupKeyFile = filepath.Join(dir, "backup-key")
			}
		}
		if cfg.BackupKeyFile == "" {
			return fail(ExitConfig, "a Backup Encryption Key was given and the configuration names no backup_key_file; nothing was written")
		}
		bekMaterial, err = backup.ParseKey(string(in.BEK))
		if err != nil {
			return fail(ExitFailure, "the source's Backup Encryption Key: %v; nothing was written", err)
		}
		defer clear(bekMaterial)
		bek, err := backup.KeyBEK(bekMaterial)
		if err != nil {
			return fail(ExitFailure, "the source's Backup Encryption Key: %v; nothing was written", err)
		}
		err = backup.DistinctKeys(bek, kek)
		bek.Clear()
		if err != nil {
			return fail(ExitFailure, "%v; nothing was written", err)
		}
	}
	// Both are checked against what is there before either is written.
	kekState, err := keyFileState(cfg.RootKEKFile, kek, func(s string) ([]byte, error) { return envelope.ParseRootKEK(s) })
	if err != nil {
		return fail(ExitFailure, "the target's Root KEK file %s: %v; nothing was written", cfg.RootKEKFile, err)
	}
	bekState := "absent"
	if bekMaterial != nil {
		if bekState, err = keyFileState(cfg.BackupKeyFile, bekMaterial, backup.ParseKey); err != nil {
			return fail(ExitFailure, "the target's Backup Encryption Key file %s: %v; nothing was written", cfg.BackupKeyFile, err)
		}
	}
	// Said only when one was given: the answer is as before otherwise.
	tailnetKeyState := ""
	if len(in.TailnetAuthKey) > 0 {
		trimmed := bytes.TrimSpace(in.TailnetAuthKey)
		if tailnetKeyState, err = keyFileState(cfg.Tailnet.AuthKeyFile, trimmed, func(s string) ([]byte, error) {
			if v := strings.TrimSpace(s); v != "" {
				return []byte(v), nil
			}
			return nil, errors.New("empty")
		}); err != nil {
			return fail(ExitFailure, "the target's tailnet auth key file %s: %v; nothing was written", cfg.Tailnet.AuthKeyFile, err)
		}
	}
	if kekState == "written" {
		if err := writeKeyFile(cfg.RootKEKFile, in.RootKEK); err != nil {
			return fail(ExitFailure, "the target's Root KEK file %s: %v", cfg.RootKEKFile, err)
		}
	}
	if bekState == "written" {
		if err := writeKeyFile(cfg.BackupKeyFile, in.BEK); err != nil {
			return fail(ExitFailure, "the target's Backup Encryption Key file %s: %v", cfg.BackupKeyFile, err)
		}
	}
	if tailnetKeyState == "written" {
		if err := writeKeyFile(cfg.Tailnet.AuthKeyFile, append(bytes.TrimSpace(in.TailnetAuthKey), '\n')); err != nil {
			return fail(ExitFailure, "the target's tailnet auth key file %s: %v", cfg.Tailnet.AuthKeyFile, err)
		}
	}
	out, _ := json.Marshal(struct {
		RootKEK    string `json:"rootKek"`
		BEK        string `json:"bek"`
		TailnetKey string `json:"tailnetAuthKey,omitempty"`
	}{kekState, bekState, tailnetKeyState})
	fmt.Fprintln(stdout, string(out))
	return ExitOK
}

// keyFileState is "written" when path does not exist yet, "unchanged" when
// it holds the same key; another key, or a file that holds none, is the
// error.
func keyFileState(path string, want []byte, parse func(string) ([]byte, error)) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "written", nil
	}
	if err != nil {
		return "", err
	}
	have, err := parse(string(b))
	clear(b)
	if err != nil {
		return "", errors.New("it holds no key; a migration writes the source's key only into an absent file")
	}
	defer clear(have)
	if subtle.ConstantTimeCompare(have, want) != 1 {
		return "", errors.New("it holds another key; a migration keeps the source's keys (go-step7 decision 9), so the target's must be absent or the same")
	}
	return "unchanged", nil
}

// writeKeyFile writes a key file anew: mode 0600, the caller's, synced.
func writeKeyFile(path string, key []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncFile(filepath.Dir(path))
}

// runMigrateOpen is `admin migrate open --id <migration>`, the live open
// (decision 12): in the running varlatchd, through its control socket (or
// offline on the data directory), the migration's gate ended, then its
// journal written open (its phase, and the step in its history). The
// journal must name the migration and be switched (or open already: then
// nothing changes but a gate left over). The gate first, as `state
// --write`: the journal never says open while the gate stands.
func runMigrateOpen(env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	fail := func(status int, format string, args ...any) int {
		fmt.Fprintf(stderr, "varlatchd admin migrate open: "+format+"\n", args...)
		return status
	}
	a, msg := parseMigrate(rest)
	if msg != "" || a.sub != "open" {
		fmt.Fprintln(stderr, migrateUsage)
		return 64
	}
	dir := env.cfg.DataDir
	raw, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if err != nil {
		return fail(ExitFailure, "the data directory's journal: %v", err)
	}
	h, err := parseJournal(raw)
	switch {
	case err != nil:
		return fail(ExitFailure, "%v", err)
	case h.ID != a.id:
		return fail(ExitFailure, "the data directory's journal is the migration %s, not %s", h.ID, a.id)
	case h.Phase != "switched" && h.Phase != "open":
		return fail(ExitFailure, "the migration %s is in phase %s; it opens once switched", h.ID, h.Phase)
	}
	// What the transfer brought in was never repaired: Capabilities wait
	// for the repair before the API opens (capabilities.Repair).
	env.capabilityRepair.Invalidate()
	if err := env.admission.EndMigration(h.ID); err != nil {
		return fail(ExitFailure, "the transfer's gate %s could not be ended (%v), so the journal still says %s; remove that file by hand, then run varlatch migrate --resume",
			filepath.Join(dir, backup.GateFile), err, h.Phase)
	}
	if h.Phase == "switched" {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fail(ExitFailure, "%v", err)
		}
		var history []json.RawMessage
		_ = json.Unmarshal(doc["history"], &history)
		step, _ := json.Marshal(map[string]string{"phase": "open", "at": time.Now().UTC().Format(time.RFC3339Nano)})
		history = append(history, step)
		doc["phase"], _ = json.Marshal("open")
		doc["history"], _ = json.Marshal(history)
		b, err := json.Marshal(doc)
		if err != nil {
			return fail(ExitFailure, "%v", err)
		}
		owner := -1
		if st, err := os.Stat(dir); err == nil {
			owner = statOwner(st)
		}
		if err := writeDurably(filepath.Join(dir, JournalFile), append(b, '\n'), owner); err != nil {
			return fail(ExitFailure, "the gate is ended, but the journal could not say open: %v; varlatch migrate --resume finishes it", err)
		}
	}
	fmt.Fprintln(stdout, `{"opened":true}`)
	return ExitOK
}
