// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
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
	if want := []string{MadeUser, MadeEtcDir, MadeDataDir, MadeConfig, MadeUnitEnabled}; !slices.Equal(made, want) {
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

// What was there already is used and never named, so never removed: an
// existing system user, /etc/varlatch holding the operator's file, an
// empty data directory, the unit enabled. The undo then removes only the
// configuration, and keeps /etc/varlatch with the operator's file.
func TestPrepareTargetUsesWhatIsThere(t *testing.T) {
	skipOffUnix(t)
	h, said := newFakeHost(t), &recorder{}
	h.users[User], h.shells[User] = [2]int{985, 985}, "/usr/sbin/nologin"
	h.enabled = true
	for _, d := range []string{EtcDir, DataDir} {
		if err := os.MkdirAll(h.Path(d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
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
	if made, err := run(h, Options{}); err == nil || !strings.Contains(err.Error(), "is running") || slices.Contains(made, MadeUnitEnabled) {
		t.Errorf("a running unit: %v %v", made, err)
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
