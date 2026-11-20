// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
)

// fakeHost is a host under a temporary root: users, chowns and systemctl
// recorded, the unit's state kept, the probe's answer and the
// configuration's check chosen by the test.
type fakeHost struct {
	root      string
	users     map[string][2]int
	chowns    map[string][2]int
	systemctl []string
	active    bool
	probe     diskprobe.Result
	probeErr  error
	checkMsg  string
	readyErr  error
	failUnit  bool
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{root: t.TempDir(), users: map[string][2]int{}, chowns: map[string][2]int{}}
	s := diskprobe.Stats{Samples: 250, P50: time.Millisecond, P99: 3 * time.Millisecond}
	h.probe = diskprobe.Result{Append: s, Rewrite: s, Limit: diskprobe.DefaultLimit, Pass: true}
	if err := os.MkdirAll(filepath.Dir(h.Path(UnitFile)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.Path(UnitFile), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *fakeHost) Path(p string) string { return filepath.Join(h.root, p) }
func (h *fakeHost) LookupUser(name string) (int, int, bool, error) {
	ids, ok := h.users[name]
	return ids[0], ids[1], ok, nil
}
func (h *fakeHost) CreateUser(name string) error { h.users[name] = [2]int{990, 990}; return nil }
func (h *fakeHost) Chown(path string, uid, gid int) error {
	rel, _ := filepath.Rel(h.root, path)
	h.chowns["/"+rel] = [2]int{uid, gid}
	return nil
}
func (h *fakeHost) Systemctl(args ...string) (string, error) {
	h.systemctl = append(h.systemctl, strings.Join(args, " "))
	switch args[0] {
	case "is-active":
		if h.active {
			return "active\n", nil
		}
		return "inactive\n", errors.New("exit status 3")
	case "enable":
		if h.failUnit {
			return "Job failed", errors.New("exit status 1")
		}
		h.active = true
	}
	return "", nil
}
func (h *fakeHost) Probe(context.Context, string) (diskprobe.Result, error) {
	return h.probe, h.probeErr
}
func (h *fakeHost) CheckConfig(string) (string, error)  { return h.checkMsg, nil }
func (h *fakeHost) Ready(context.Context, string) error { return h.readyErr }

// recorder collects what setup says.
type recorder struct{ lines []string }

func (r *recorder) say(s string) error { r.lines = append(r.lines, s); return nil }

func localhostAnswers() Answers { return Answers{Ingress: Localhost, Backups: "host"} }

func options(h *fakeHost, said *recorder, out string) Options {
	return Options{Host: h, Given: localhostAnswers(), Say: said.say, RootKEKOut: filepath.Join(out, "root-kek.copy"), BackupKeyOut: filepath.Join(out, "backup-key.copy"),
		Now: func() time.Time { return time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) }}
}

// snapshot is every file under the host's root: mode and content digest.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		rel, _ := filepath.Rel(root, p)
		v := info.Mode().String()
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			v += " " + hex.EncodeToString(sum[:8])
		}
		out[rel] = v
		return nil
	})
	return out
}

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func skipOffUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes and links")
	}
}

// TestNonInteractiveSetup: from an empty host, a run without a terminal
// with every answer given: the user, the data directory (0700, the
// user's), the keys (root, 0600) and their copies (0600) holding the same
// keys, varlatchd.conf (0640, root:varlatch) naming no key, the journal
// (0600) holding every step and no key, the unit enabled and started, and
// readiness awaited.
func TestNonInteractiveSetup(t *testing.T) {
	skipOffUnix(t)
	h, said, out := newFakeHost(t), &recorder{}, t.TempDir()
	if err := Run(context.Background(), options(h, said, out)); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.users[User]; !ok {
		t.Error("no varlatch user")
	}
	for p, want := range map[string]fs.FileMode{DataDir: 0o700, RootKEK: 0o600, BackupKey: 0o600, Journal: 0o600, ConfigFile: 0o640, EtcDir: 0o750} {
		if got := mode(t, h.Path(p)); got != want {
			t.Errorf("%s: %04o, want %04o", p, got, want)
		}
	}
	if h.chowns[DataDir] != [2]int{990, 990} || h.chowns[EtcDir] != [2]int{0, 990} {
		t.Errorf("owners %v", h.chowns)
	}
	keys := map[string]string{}
	for name, p := range map[string]string{"kek": RootKEK, "bek": BackupKey} {
		b, _ := os.ReadFile(h.Path(p))
		k := strings.TrimSpace(string(b))
		if len(k) != 64 {
			t.Fatalf("%s: %d hex digits", p, len(k))
		}
		keys[name] = k
	}
	if keys["kek"] == keys["bek"] {
		t.Error("the two keys are the same")
	}
	for name, p := range map[string]string{"kek": "root-kek.copy", "bek": "backup-key.copy"} {
		b, _ := os.ReadFile(filepath.Join(out, p))
		if strings.TrimSpace(string(b)) != keys[name] || mode(t, filepath.Join(out, p)) != 0o600 {
			t.Errorf("%s: not the key, or not 0600", p)
		}
	}
	conf, _ := os.ReadFile(h.Path(ConfigFile))
	if string(conf) != string(RenderConfig(Answers{Ingress: Localhost, Backups: "host", Listen: DefaultListen, PublicURL: DefaultLocalhostURL})) ||
		!strings.Contains(string(conf), "public_url = http://localhost:8686\n") || strings.Contains(string(conf), "key_file") {
		t.Errorf("config:\n%s", conf)
	}
	var j JournalDoc
	raw, _ := os.ReadFile(h.Path(Journal))
	if err := json.Unmarshal(raw, &j); err != nil || len(j.Done) != len(Steps) || j.Probe == nil || !j.Probe.Pass {
		t.Errorf("journal %s", raw)
	}
	if !slices.Contains(h.systemctl, "enable --now varlatchd.service") {
		t.Errorf("systemctl %q", h.systemctl)
	}
	// Keys: only in their files and their copies.
	everything := strings.Join(said.lines, "\n") + string(raw) + string(conf)
	for _, k := range keys {
		if strings.Contains(everything, k) {
			t.Error("a key in setup's output, its journal or the configuration")
		}
	}
	_ = filepath.WalkDir(h.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(h.root, p)
		for name, k := range keys {
			if strings.Contains(string(b), k) && "/"+rel != map[string]string{"kek": RootKEK, "bek": BackupKey}[name] {
				t.Errorf("%s holds a key", rel)
			}
		}
		return nil
	})
}

// TestRerunChangesNothing: a second run with the same answers writes no
// file, starts nothing (the unit is active), and keeps the keys.
func TestRerunChangesNothing(t *testing.T) {
	skipOffUnix(t)
	h, said, out := newFakeHost(t), &recorder{}, t.TempDir()
	if err := Run(context.Background(), options(h, said, out)); err != nil {
		t.Fatal(err)
	}
	before, beforeOut := snapshot(t, h.root), snapshot(t, out)
	h.systemctl = nil
	if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, h.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("the host changed:\n%v\n%v", before, after)
	}
	if fmt.Sprint(snapshot(t, out)) != fmt.Sprint(beforeOut) {
		t.Error("the copies changed")
	}
	if !slices.Equal(h.systemctl, []string{"is-active varlatchd.service"}) {
		t.Errorf("systemctl on a rerun: %q", h.systemctl)
	}
}

// TestInterruptedAtEachStep: stopped after each step, then run again,
// setup ends where an uninterrupted run ends: the same files (the keys
// made once, at the step that makes them), every step journaled.
func TestInterruptedAtEachStep(t *testing.T) {
	skipOffUnix(t)
	for _, stop := range Steps[:len(Steps)-1] {
		t.Run(stop, func(t *testing.T) {
			h, out := newFakeHost(t), t.TempDir()
			o := options(h, &recorder{}, out)
			o.StopAfter = stop
			if err := Run(context.Background(), o); !errors.Is(err, ErrStopped) {
				t.Fatalf("stopped: %v", err)
			}
			var kek []byte
			if slices.Index(Steps, stop) >= slices.Index(Steps, "keys") {
				kek, _ = os.ReadFile(h.Path(RootKEK))
			}
			if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil {
				t.Fatalf("resumed: %v", err)
			}
			if got, _ := os.ReadFile(h.Path(RootKEK)); kek != nil && string(got) != string(kek) {
				t.Error("the Root KEK was made again")
			}
			var j JournalDoc
			raw, _ := os.ReadFile(h.Path(Journal))
			if json.Unmarshal(raw, &j) != nil || len(j.Done) != len(Steps) || !h.active {
				t.Errorf("after resuming: %s, active %v", raw, h.active)
			}
		})
	}
}

// TestFailureThenResume: a step that fails (the unit does not start) ends
// the run with what to do; once fixed, a rerun finishes.
func TestFailureThenResume(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	h.failUnit = true
	err := Run(context.Background(), options(h, &recorder{}, out))
	if err == nil || !strings.Contains(err.Error(), "journalctl -u varlatchd") {
		t.Fatalf("the unit's failure: %v", err)
	}
	h.failUnit = false
	if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil || !h.active {
		t.Fatalf("resumed: %v", err)
	}
}

// TestAnswersAreFinal: once journaled, an answer given differently is
// refused (a move is not setup's), and nothing changes.
func TestAnswersAreFinal(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, h.root)
	o := options(h, &recorder{}, out)
	o.Given = Answers{Ingress: Proxy, PublicURL: "https://vault.example.com", Backups: "host"}
	var usage *UsageError
	if err := Run(context.Background(), o); !errors.As(err, &usage) || !strings.Contains(err.Error(), "--ingress, --public-url") || !strings.Contains(err.Error(), "varlatch move") {
		t.Fatalf("%v", err)
	}
	if fmt.Sprint(snapshot(t, h.root)) != fmt.Sprint(before) {
		t.Error("a refused rerun changed the host")
	}
}

// TestMissingAnswers: without a terminal, the first missing answer is
// named with its flag and the answers file's name, before anything is
// changed; so are the keys' copies.
func TestMissingAnswers(t *testing.T) {
	skipOffUnix(t)
	h := newFakeHost(t)
	o := options(h, &recorder{}, t.TempDir())
	o.Given = Answers{Ingress: Proxy, Backups: "host"}
	if err := Run(context.Background(), o); !errors.Is(err, ErrNotAnswered) || !strings.Contains(err.Error(), "--public-url") || !strings.Contains(err.Error(), `"publicUrl"`) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(h.Path(EtcDir)); err == nil {
		t.Error("something was written before every answer was in")
	}
	o = options(h, &recorder{}, t.TempDir())
	o.RootKEKOut, o.BackupKeyOut = "", ""
	if err := Run(context.Background(), o); !errors.Is(err, ErrNotAnswered) || !strings.Contains(err.Error(), "--root-kek-out") {
		t.Fatalf("no copies: %v", err)
	}
	if _, err := os.Stat(h.Path(EtcDir)); err == nil {
		t.Error("something was written before the copies' files were named")
	}
	for _, c := range []struct {
		a   Answers
		has string
	}{
		{Answers{Ingress: "dmz", Backups: "host"}, "--ingress"},
		{Answers{Ingress: Public, PublicURL: "https://192.0.2.1", Backups: "host"}, "DNS name"},
		{Answers{Ingress: Proxy, PublicURL: "http://vault.example.com", Backups: "host"}, "must be https"},
		{Answers{Ingress: Proxy, PublicURL: "https://u:p@vault.example.com", Backups: "host"}, "without a user name, password"},
		{Answers{Ingress: Localhost, Backups: "hosted"}, "not available yet"},
		{Answers{Ingress: Localhost, Backups: "host", ACMEEmail: "a@b.c"}, "for --ingress public"},
	} {
		o := options(newFakeHost(t), &recorder{}, t.TempDir())
		o.Given = c.a
		var usage *UsageError
		if err := Run(context.Background(), o); !errors.As(err, &usage) || !strings.Contains(err.Error(), c.has) || strings.Contains(err.Error(), "u:p") {
			t.Errorf("%+v: %v", c.a, err)
		}
	}
}

// TestSlowDisk: the probe's measure is said before the database is placed
// (no key, no configuration yet); without --accept-slow-disk setup stops,
// and a rerun accepting it continues; on a terminal the operator decides.
func TestSlowDisk(t *testing.T) {
	skipOffUnix(t)
	slow := diskprobe.Stats{Samples: 250, P50: 20 * time.Millisecond, P99: 80 * time.Millisecond}
	h, said, out := newFakeHost(t), &recorder{}, t.TempDir()
	h.probe = diskprobe.Result{Append: slow, Rewrite: slow, Limit: diskprobe.DefaultLimit}
	err := Run(context.Background(), options(h, said, out))
	if err == nil || !strings.Contains(err.Error(), "--accept-slow-disk") || !strings.Contains(strings.Join(said.lines, "\n"), "p99 80.0 ms") {
		t.Fatalf("%v %q", err, said.lines)
	}
	for _, p := range []string{RootKEK, ConfigFile} {
		if _, err := os.Stat(h.Path(p)); err == nil {
			t.Errorf("%s exists after a refused slow disk", p)
		}
	}
	o := options(h, &recorder{}, out)
	o.AcceptSlowDisk = true
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(h.Path(Journal))
	if !strings.Contains(string(raw), `"accepted": true`) {
		t.Errorf("journal %s", raw)
	}
	// On a terminal: asked, and "no" stops.
	h2 := newFakeHost(t)
	h2.probe = diskprobe.Result{Append: slow, Rewrite: slow, Limit: diskprobe.DefaultLimit}
	o = options(h2, &recorder{}, t.TempDir())
	ask := &fakeAsker{confirm: false}
	o.Ask, o.ShowKeys = ask, func([]byte, []byte) error { return nil }
	if err := Run(context.Background(), o); err == nil || !slices.Contains(ask.asked, "Continue on this disk anyway?") {
		t.Errorf("declined: %v %q", err, ask.asked)
	}
}

// TestKeysNeverReplaced: a key setup made that is gone stops setup; a
// copy's file holding something else is never written over.
func TestKeysNeverReplaced(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.Path(BackupKey)); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), options(h, &recorder{}, out)); err == nil || !strings.Contains(err.Error(), "is gone") {
		t.Errorf("a lost key: %v", err)
	}
	if _, err := os.Stat(h.Path(BackupKey)); err == nil {
		t.Error("a lost key was made again")
	}
	// A copy's file holding something else.
	h2, out2 := newFakeHost(t), t.TempDir()
	if err := os.WriteFile(filepath.Join(out2, "root-kek.copy"), []byte("something else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), options(h2, &recorder{}, out2)); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("a copy over another file: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(out2, "root-kek.copy")); string(b) != "something else\n" {
		t.Error("the operator's file was written over")
	}
}

// TestADatabaseIsARestore: a data directory with a database setup did not
// make is refused, before anything else.
func TestADatabaseIsARestore(t *testing.T) {
	skipOffUnix(t)
	h := newFakeHost(t)
	if err := os.MkdirAll(h.Path(DataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.Path(DataDir), "varlatch.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), options(h, &recorder{}, t.TempDir())); err == nil || !strings.Contains(err.Error(), "setup --restore") {
		t.Errorf("%v", err)
	}
	if _, err := os.Stat(h.Path(RootKEK)); err == nil {
		t.Error("keys made over an existing installation")
	}
}

// fakeAsker answers questions: the first option, the default text, and
// confirm.
type fakeAsker struct {
	asked   []string
	confirm bool
	texts   map[string]string
}

func (a *fakeAsker) Choose(q string, _ []string, pre int) (int, error) {
	a.asked = append(a.asked, q)
	return pre, nil
}
func (a *fakeAsker) Confirm(q string, _ bool) (bool, error) {
	a.asked = append(a.asked, q)
	return a.confirm, nil
}
func (a *fakeAsker) Text(q, d string) (string, error) {
	a.asked = append(a.asked, q)
	for k, v := range a.texts {
		if strings.Contains(q, k) {
			return v, nil
		}
	}
	return d, nil
}

// TestInteractiveSetup: on a terminal, the missing answers are asked (the
// ingress, its address, the backups), the keys shown once, and no copy
// written; a rerun shows nothing again.
func TestInteractiveSetup(t *testing.T) {
	skipOffUnix(t)
	h := newFakeHost(t)
	ask := &fakeAsker{texts: map[string]string{"address people open": "https://vault.example.com"}}
	shown := 0
	o := Options{Host: h, Ask: ask, Say: (&recorder{}).say, ShowKeys: func(kek, bek []byte) error {
		shown++
		if len(kek) != 64 || len(bek) != 64 {
			t.Errorf("keys %d %d", len(kek), len(bek))
		}
		return nil
	}}
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if shown != 1 || !slices.Contains(ask.asked, "How do people reach Varlatch?") || !slices.Contains(ask.asked, "Where do backups go?") {
		t.Errorf("shown %d, asked %q", shown, ask.asked)
	}
	conf, _ := os.ReadFile(h.Path(ConfigFile))
	if !strings.Contains(string(conf), "public_url = https://vault.example.com\nlisten_https = :443\n") {
		t.Errorf("config:\n%s", conf)
	}
	if err := Run(context.Background(), o); err != nil || shown != 1 {
		t.Errorf("rerun: %v, shown %d", err, shown)
	}
}

// TestRenderConfigByIngress: each ingress mode's configuration names what
// it needs and nothing else.
func TestRenderConfigByIngress(t *testing.T) {
	for _, c := range []struct {
		a          Answers
		has, lacks []string
	}{
		{Answers{Ingress: Public, PublicURL: "https://vault.example.com", ACMEEmail: "ops@example.com", Backups: "host"},
			[]string{"listen = 127.0.0.1:8686", "listen_https = :443", "acme_email = ops@example.com"}, []string{"trusted_proxies", "tailnet"}},
		{Answers{Ingress: Proxy, PublicURL: "https://vault.example.com", Backups: "bucket", BackupDestinationsFile: "/etc/varlatch/destinations.json"},
			[]string{"trusted_proxies = 127.0.0.1,::1", "backup_destinations_file = /etc/varlatch/destinations.json", "backup_destination = offsite"}, []string{"listen_https", "acme"}},
		{Answers{Ingress: Localhost, Backups: "host"}, []string{"public_url = http://localhost:8686"}, []string{"listen_https", "trusted_proxies", "backup_destination"}},
		{Answers{Ingress: Tailnet, TailnetAuthKeyFile: "/etc/varlatch/tailnet-auth-key", Backups: "host"},
			[]string{"tailnet = on", "tailnet_hostname = varlatch", "tailnet_tags = tag:varlatch", "tailnet_port = 8687", "tailnet_auth_key_file = /etc/varlatch/tailnet-auth-key"}, []string{"listen_https"}},
	} {
		a := c.a
		a.Defaults()
		if err := a.Check(); err != nil {
			t.Errorf("%s: %v", a.Ingress, err)
			continue
		}
		conf := string(RenderConfig(a))
		for _, s := range c.has {
			if !strings.Contains(conf, s+"\n") {
				t.Errorf("%s lacks %q:\n%s", a.Ingress, s, conf)
			}
		}
		for _, s := range c.lacks {
			if strings.Contains(conf, s) {
				t.Errorf("%s has %q:\n%s", a.Ingress, s, conf)
			}
		}
	}
}
