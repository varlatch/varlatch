// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// proxyAnswers are what a migration derives from an own-proxy source.
func proxyAnswers() Answers {
	return Answers{Ingress: Proxy, PublicURL: "https://varlatch.example.test", Listen: "127.0.0.1:8787", Backups: "host"}
}

// A migration's target made on an empty host: the user, /etc/varlatch,
// the data directory, the configuration (the source's answers), the unit
// enabled and not started; each item named before it is made, in order;
// no key, no setup journal. Undone, exactly those go, and the host is as
// it was.
func TestPrepareTargetOnAnEmptyHost(t *testing.T) {
	skipOffUnix(t)
	h, said := newFakeHost(t), &recorder{}
	// /var/lib is every host's.
	if err := os.MkdirAll(filepath.Dir(h.Path(DataDir)), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, h.root)
	var made []string
	a, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers(), Say: said.say}, func(item string) error {
		made = append(made, item)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{MadeUser, MadeEtcDir, MadeDataDir, MadeUnitEnabled, MadeConfig}; !slices.Equal(made, want) {
		t.Fatalf("made %v, want %v", made, want)
	}
	if a.PublicURL != "https://varlatch.example.test" || a.Listen != "127.0.0.1:8787" {
		t.Errorf("the answers: %+v", a)
	}
	conf, err := os.ReadFile(h.Path(ConfigFile))
	if err != nil || !strings.Contains(string(conf), "public_url = https://varlatch.example.test\n") || !strings.Contains(string(conf), "listen = 127.0.0.1:8787\n") ||
		!strings.Contains(string(conf), "data_dir = "+h.Path(DataDir)+"\n") {
		t.Fatalf("the configuration: %s %v", conf, err)
	}
	if !h.enabled || h.active {
		t.Errorf("the unit: enabled %v, active %v; want enabled, not started", h.enabled, h.active)
	}
	for _, p := range []string{RootKEK, BackupKey, Journal} {
		if _, err := os.Stat(h.Path(p)); !os.IsNotExist(err) {
			t.Errorf("%s: %v; a target's keys are the source's, installed later", p, err)
		}
	}
	if st, err := os.Stat(h.Path(DataDir)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("the data directory: %v %v", st, err)
	}
	if err := UndoTarget(h, made, said.say); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.users[User]; ok || h.enabled {
		t.Errorf("after the undo: user %v, unit enabled %v", ok, h.enabled)
	}
	after := snapshot(t, h.root)
	if len(after) != len(before) {
		t.Errorf("the host after the undo:\n%v\nbefore:\n%v", after, before)
	}
	// Done again harmlessly.
	if err := UndoTarget(h, made, said.say); err != nil {
		t.Errorf("a second undo: %v", err)
	}
}

// What was there already is used as it is and never named, so never
// removed: an existing system user, /etc/varlatch (root:root 0755, open
// to the user: not setup's root:varlatch 0750, and kept so) holding the
// operator's file, an empty data directory (varlatch's 0700),
// the unit enabled; neither directory is chmodded or chowned. The undo
// then removes only the configuration, and keeps /etc/varlatch with the
// operator's file.
func TestPrepareTargetUsesWhatIsThere(t *testing.T) {
	skipOffUnix(t)
	h, said := newFakeHost(t), &recorder{}
	h.users[User], h.shells[User] = [2]int{985, 985}, "/usr/sbin/nologin"
	h.enabled = true
	for d, mode := range map[string]os.FileMode{EtcDir: 0o755, DataDir: 0o700} {
		if err := os.MkdirAll(h.Path(d), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(h.Path(d), mode); err != nil {
			t.Fatal(err)
		}
	}
	// Their owners, as the fake's Owner reads them (and its Chown would
	// change them).
	h.chowns[EtcDir], h.chowns[DataDir] = [2]int{0, 0}, [2]int{985, 985}
	notes := filepath.Join(h.Path(EtcDir), "notes.txt")
	if err := os.WriteFile(notes, []byte("the operator's"), 0o600); err != nil {
		t.Fatal(err)
	}
	var made []string
	if _, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers(), Say: said.say}, func(item string) error {
		made = append(made, item)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(made, []string{MadeConfig}) {
		t.Fatalf("made %v, want the configuration only", made)
	}
	for d, want := range map[string]os.FileMode{EtcDir: 0o755, DataDir: 0o700} {
		if st, err := os.Stat(h.Path(d)); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s was chmodded: %v %v", d, st, err)
		}
	}
	if h.chowns[EtcDir] != [2]int{0, 0} || h.chowns[DataDir] != [2]int{985, 985} {
		t.Errorf("a directory that was there was chowned: %v", h.chowns)
	}
	if err := UndoTarget(h, append(made, MadeEtcDir), said.say); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(notes); err != nil {
		t.Errorf("the operator's file: %v", err)
	}
	if !strings.Contains(strings.Join(said.lines, "\n"), "Kept /etc/varlatch: it holds files migrate did not make.") {
		t.Errorf("not said: %q", said.lines)
	}
	if _, ok := h.users[User]; !ok || !h.enabled {
		t.Error("the user or the unit, not migrate's, was removed")
	}
}

// Refusals before anything is made: a configuration there already (a
// prepared target is used as it is, not made); an existing user that is
// no system account, or in a group beyond its own (#329's rule), unless
// --accept-existing-user; a data directory holding a database; a running
// unit; a missing unit file; a missing answer. A refusal's items made so
// far are named first, so an undo removes them.
func TestPrepareTargetRefusals(t *testing.T) {
	skipOffUnix(t)
	run := func(h *fakeHost, o Options) ([]string, error) {
		var made []string
		o.Host = h
		if o.Given == (Answers{}) {
			o.Given = proxyAnswers()
		}
		_, err := PrepareTarget(context.Background(), o, func(item string) error {
			made = append(made, item)
			return nil
		})
		return made, err
	}
	h := newFakeHost(t)
	if err := os.MkdirAll(h.Path(EtcDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.Path(ConfigFile), []byte("listen = 127.0.0.1:1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "the target is there already") || len(made) != 0 {
		t.Errorf("a configuration there already: %v %v", made, err)
	}
	h = newFakeHost(t)
	h.users[User], h.shells[User], h.groups[User] = [2]int{985, 985}, "/usr/sbin/nologin", []string{"docker"}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "it is in the groups docker") || len(made) != 0 {
		t.Errorf("a user in docker's group: %v %v", made, err)
	}
	if _, err := run(h, Options{AcceptExistingUser: true}); err != nil {
		t.Errorf("accepted: %v", err)
	}
	h = newFakeHost(t)
	if err := os.MkdirAll(h.Path(DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.Path(DataDir), "varlatch.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "holds a database") || slices.Contains(made, MadeConfig) {
		t.Errorf("a data directory holding a database: %v %v", made, err)
	}
	h = newFakeHost(t)
	h.active = true
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "is running") || len(made) != 0 {
		t.Errorf("a running unit, refused before anything is made: %v %v", made, err)
	}
	// Directories there already, not as a target needs them: refused, and
	// left as they were (no chmod, no chown), before anything is made.
	h = newFakeHost(t)
	h.users[User], h.shells[User] = [2]int{985, 985}, "/usr/sbin/nologin"
	if err := os.MkdirAll(h.Path(EtcDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.Path(EtcDir), 0o775); err != nil {
		t.Fatal(err)
	}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "/etc/varlatch is there, and not as a migration's target needs it") || len(made) != 0 {
		t.Errorf("a group-writable /etc/varlatch: %v %v", made, err)
	}
	if st, _ := os.Stat(h.Path(EtcDir)); st.Mode().Perm() != 0o775 || len(h.chowns) != 0 {
		t.Errorf("the /etc/varlatch that was there was changed: %v %v", st.Mode().Perm(), h.chowns)
	}
	h = newFakeHost(t)
	h.users[User], h.shells[User] = [2]int{985, 985}, "/usr/sbin/nologin"
	if err := os.MkdirAll(h.Path(DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "/var/lib/varlatch is there, and not as a migration's target needs it") || len(made) != 0 {
		t.Errorf("a data directory that is root's: %v %v", made, err)
	}
	if len(h.chowns) != 0 {
		t.Errorf("the data directory that was there was chowned: %v", h.chowns)
	}
	h = newFakeHost(t)
	if err := os.MkdirAll(h.Path(DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "/var/lib/varlatch is there") || len(made) != 0 {
		t.Errorf("a data directory and no varlatch user: %v %v", made, err)
	}
	h = newFakeHost(t)
	_ = os.Remove(h.Path(UnitFile))
	if _, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "install.sh --server") {
		t.Errorf("no unit file: %v", err)
	}
	h = newFakeHost(t)
	if made, err := run(h, Options{Given: Answers{Ingress: Proxy}}); err == nil || len(made) != 0 {
		t.Errorf("a missing answer: %v %v", made, err)
	}
}

// The configuration is made last: a run stopped at any item before it
// leaves no configuration, so migrate finds the target missing and makes
// the rest again (Ours: what the stopped run made is migrate's, made again
// where needed), and the unit ends enabled.
func TestPrepareTargetWritesItsConfigurationLast(t *testing.T) {
	skipOffUnix(t)
	for _, stop := range []string{MadeUser, MadeEtcDir, MadeDataDir, MadeUnitEnabled, MadeConfig} {
		t.Run("stopped at "+stop, func(t *testing.T) {
			h := newFakeHost(t)
			if err := os.MkdirAll(filepath.Dir(h.Path(DataDir)), 0o755); err != nil {
				t.Fatal(err)
			}
			var made []string
			_, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers()}, func(item string) error {
				made = append(made, item)
				if item == stop {
					return errStopped
				}
				return nil
			})
			if err != errStopped {
				t.Fatalf("not stopped: %v", err)
			}
			if _, err := os.Stat(h.Path(ConfigFile)); !os.IsNotExist(err) {
				t.Fatalf("the configuration is there before the target is ready: %v", err)
			}
			if _, err := PrepareTarget(context.Background(), Options{Host: h, Given: proxyAnswers(), Ours: made}, func(item string) error {
				if !slices.Contains(made, item) {
					made = append(made, item)
				}
				return nil
			}); err != nil {
				t.Fatalf("made again: %v", err)
			}
			if _, err := os.Stat(h.Path(ConfigFile)); err != nil || !h.enabled {
				t.Errorf("after: configuration %v, unit enabled %v", err, h.enabled)
			}
			if h.chowns[EtcDir] != [2]int{0, 990} || h.chowns[DataDir] != [2]int{990, 990} {
				t.Errorf("the directories: %v", h.chowns)
			}
		})
	}
}

var errStopped = errors.New("stopped")
