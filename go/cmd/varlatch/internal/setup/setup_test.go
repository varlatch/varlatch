// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"crypto/rand"
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
	root   string
	users  map[string][2]int
	shells map[string]string
	groups map[string][]string
	chowns map[string][2]int
	// leftGroups are groups there without their user.
	leftGroups map[string]bool
	// unknownState: is-enabled prints no state (an error on stderr only).
	unknownState bool
	systemctl    []string
	enabled      bool
	active       bool
	probe        diskprobe.Result
	probeErr     error
	checkMsg     string
	readyErr     error
	failUnit     bool
	// The fake varlatchd's admin commands: the first administrator, the
	// links issued, the attestations, the backups.
	admin                 string
	bootstrapped, passkey bool
	manualEnroll          bool // a link is not enrolled at once
	links                 []string
	attested              map[string]bool
	backups               int
	backupUnverified      bool
	adminCalls            []string
	// restoreURL is the restored archive's public_url.
	restoreURL string
	// The tailnet probe's findings.
	probeSeen      []string
	probeSingleUse bool
	// The restored certificate issuance count for the public host.
	issued int
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{root: t.TempDir(), users: map[string][2]int{}, shells: map[string]string{}, groups: map[string][]string{}, chowns: map[string][2]int{}, leftGroups: map[string]bool{}}
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
func (h *fakeHost) CreateUser(name string) error {
	h.users[name] = [2]int{990, 990}
	h.shells[name] = "/usr/sbin/nologin"
	return nil
}
func (h *fakeHost) DeleteUser(name string) error {
	delete(h.users, name)
	delete(h.shells, name)
	return nil
}
func (h *fakeHost) LoginShell(name string) (string, error) { return h.shells[name], nil }
func (h *fakeHost) SupplementaryGroups(name string) ([]string, error) {
	return h.groups[name], nil
}
func (h *fakeHost) SysUIDMax() int { return 999 }
func (h *fakeHost) Chown(path string, uid, gid int) error {
	rel, _ := filepath.Rel(h.root, path)
	h.chowns["/"+rel] = [2]int{uid, gid}
	return nil
}

func (h *fakeHost) SystemctlStdout(args ...string) (string, error) { return h.Systemctl(args...) }

// LookupGroup: a user's own group is there while the user is, or while
// the test leaves it (leftGroups).
func (h *fakeHost) LookupGroup(name string) (bool, error) {
	_, ok := h.users[name]
	return ok || h.leftGroups[name], nil
}

// Owner is what Chown made it, else root's.
func (h *fakeHost) Owner(path string) (int, int, error) {
	rel, _ := filepath.Rel(h.root, path)
	ids := h.chowns["/"+rel]
	return ids[0], ids[1], nil
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
		h.enabled = true
		if slices.Contains(args, "--now") {
			h.active = true
		}
	case "disable":
		// systemctl refuses a unit whose file is gone.
		if _, err := os.Stat(h.Path(UnitFile)); err != nil {
			return "Failed to disable unit: Unit file " + Unit + " does not exist.", errors.New("exit status 1")
		}
		h.enabled = false
	case "is-enabled":
		if h.unknownState {
			return "", errors.New("exit status 1")
		}
		if h.enabled {
			return "enabled\n", nil
		}
		return "disabled\n", errors.New("exit status 1")
	}
	return "", nil
}
func (h *fakeHost) Probe(context.Context, string) (diskprobe.Result, error) {
	return h.probe, h.probeErr
}
func (h *fakeHost) CheckConfig(string) (string, error) { return h.checkMsg, nil }

// Admin is a fake varlatchd's admin commands. A link issued is enrolled at
// once (the operator's browser), unless manualEnroll.
func (h *fakeHost) Admin(_ context.Context, args ...string) ([]byte, error) {
	h.adminCalls = append(h.adminCalls, strings.Join(args, " "))
	if args[0] == "backup" && args[1] == "restore" {
		// Offline, before the unit: the restored installation's database,
		// its administrator with a passkey and its attestations.
		if err := os.WriteFile(h.Path(DataDir+"/varlatch.db"), []byte("restored"), 0o600); err != nil {
			return nil, err
		}
		h.admin, h.bootstrapped, h.passkey = "idn_restored", true, true
		h.attested = map[string]bool{"root-kek": true, "backup-key": true}
		return []byte("Restore completed for inst_old from archive bak_old (created 2026-11-01T00:00:00.000Z): the database is restored and its canary verified.\n" +
			"The archive's settings, to compare with this host's varlatchd.conf:\n  backup_interval = 24h\n  public_url = " + h.restoreURL + "\n" +
			"Next: start varlatchd, then take and check a fresh archive (`varlatchd admin backup run`).\n"), nil
	}
	if args[0] == "certificate" && args[1] == "issuances" {
		// Offline, before the unit: the restored records' count.
		until := `,"until":"2026-11-25T08:00:00Z"`
		if h.issued == 0 {
			until = ""
		}
		return []byte(fmt.Sprintf(`{"name":"vault.example.com","limit":5,"window":"169h0m0s","attempts":%d%s,"full":%t}`, h.issued, until, h.issued >= 5)), nil
	}
	if args[0] == "tailnet" && args[1] == "probe-name" {
		// Offline, before the unit: the probe's findings, as JSON.
		seen, _ := json.Marshal(append([]string{}, h.probeSeen...))
		second := ""
		if h.probeSingleUse {
			second = `,"secondJoin":"invalid authkey"`
		}
		return []byte(fmt.Sprintf(`{"seen":%s,"reusable":%t%s}`, seen, !h.probeSingleUse, second)), nil
	}
	if !h.active {
		return nil, errors.New("varlatchd is not running")
	}
	link := func() []byte {
		h.links = append(h.links, fmt.Sprintf("http://localhost:8686/enroll#link-%d", len(h.links)+1))
		if !h.manualEnroll {
			h.enroll()
		}
		return []byte("Open this one-time enrollment URL in your browser to create\nthe first Installation Admin's passkey (ADR-0006):\n  " +
			h.links[len(h.links)-1] + "\nExpires: 2026-11-20T12:15:00.000Z. If it lapses, run bootstrap again.\n")
	}
	switch args[0] {
	case "bootstrap-status":
		admins := "[]"
		if h.admin != "" {
			admins = fmt.Sprintf(`[{"id":%q,"enabled":true,"hasPasskey":%t}]`, h.admin, h.passkey)
		}
		return []byte(fmt.Sprintf(`{"initialized":true,"bootstrapped":%t,"admins":%s}`, h.bootstrapped, admins)), nil
	case "bootstrap": // with --revoke-unused, as setup asks
		if h.bootstrapped {
			return nil, errors.New("Installation is already bootstrapped; use recovery instead.")
		}
		return link(), nil
	case "recover":
		return link(), nil
	case "custody":
		if args[1] == "status" {
			at := func(k string) string {
				if h.attested[k] {
					return `{"key":"` + k + `","method":"copy","at":"2026-11-20T12:00:00.000Z","keyVersion":null}`
				}
				return "null"
			}
			return []byte(`{"rootKekVersion":1,"attestations":{"root-kek":` + at("root-kek") + `,"backup-key":` + at("backup-key") + `}}`), nil
		}
		if h.attested == nil {
			h.attested = map[string]bool{}
		}
		h.attested[args[3]] = true
		return []byte("{}"), nil
	case "backup":
		h.backups++
		ok := !h.backupUnverified
		return []byte(fmt.Sprintf(`{"archiveId":"bak_%d","path":"/var/lib/varlatch/backups/x","verification":{"integrity":%t,"compatibility":true,"keyMatch":true},"removed":[]}`, h.backups, ok)), nil
	}
	return nil, fmt.Errorf("unknown admin command %q", args)
}

// enroll is the operator's browser enrolling a passkey from the last link.
func (h *fakeHost) enroll() {
	if h.admin == "" {
		h.admin = "idn_first"
	}
	h.bootstrapped, h.passkey = true, true
}
func (h *fakeHost) Ready(context.Context, string) error { return h.readyErr }

// recorder collects what setup says.
type recorder struct{ lines []string }

func (r *recorder) say(s string) error { r.lines = append(r.lines, s); return nil }

func localhostAnswers() Answers { return Answers{Ingress: Localhost, Backups: "host"} }

func options(h *fakeHost, said *recorder, out string) Options {
	return Options{Host: h, Given: localhostAnswers(), Say: said.say, RootKEKOut: filepath.Join(out, "root-kek.copy"), BackupKeyOut: filepath.Join(out, "backup-key.copy"),
		AdminLinkOut: filepath.Join(out, "enroll-link"), AdminWait: time.Second, PollEvery: time.Millisecond, Attest: true,
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
	// The first administrator: the link in its file only (0600), the
	// custody attested, the first backup verified and journaled.
	// The link's file is removed once the passkey is in.
	if _, err := os.Stat(filepath.Join(out, "enroll-link")); err == nil || len(h.links) != 1 || !slices.Contains(said.lines, "Removed the used enrollment link's file "+filepath.Join(out, "enroll-link")+".") {
		t.Errorf("the link's file after the passkey: %v, links %q, said %q", err, h.links, said.lines)
	}
	if strings.Contains(strings.Join(said.lines, "\n"), "#link-") || strings.Contains(string(raw), "#link-") {
		t.Error("the enrollment link in setup's output or its journal")
	}
	if want := []string{"bootstrap-status", "bootstrap --revoke-unused", "bootstrap-status", "custody status", "custody attest --key root-kek --method copy", "custody attest --key backup-key --method copy", "backup run --json"}; !slices.Equal(h.adminCalls, want) {
		t.Errorf("admin calls %q, want %q", h.adminCalls, want)
	}
	if j.FirstBackup != "bak_1" {
		t.Errorf("first backup %q", j.FirstBackup)
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
		{Answers{Ingress: Localhost, Backups: "host", Listen: "0.0.0.0:8686"}, "--listen: with ingress localhost"},
		{Answers{Ingress: Localhost, Backups: "host", Listen: ":8686"}, "--listen: with ingress localhost"},
		{Answers{Ingress: Localhost, Backups: "host", Listen: "192.0.2.7:8686"}, "--listen: with ingress localhost"},
		{Answers{Ingress: Localhost, Backups: "host", TrustedProxies: "127.0.0.1"}, "--trusted-proxies"},
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

// TestAnExistingUserMustBeASystemAccount: a varlatch user that exists is
// used when it is a system account; one with a login shell or a person's
// uid is refused, saying what was found, unless --accept-existing-user;
// root's uid always is. A rerun after an accepted run asks no more.
func TestAnExistingUserMustBeASystemAccount(t *testing.T) {
	skipOffUnix(t)
	for _, c := range []struct {
		name   string
		uid    int
		shell  string
		groups []string
		refuse []string
	}{
		{"system account", 985, "/usr/sbin/nologin", nil, nil},
		{"false shell", 985, "/bin/false", nil, nil},
		{"login shell", 985, "/bin/bash", nil, []string{"its login shell is /bin/bash"}},
		{"no shell", 985, "", nil, []string{"no login shell set"}},
		{"a person's uid", 1001, "/usr/bin/nologin", nil, []string{"its uid 1001 is above", "SYS_UID_MAX 999"}},
		{"both", 1001, "/bin/sh", nil, []string{"its login shell is /bin/sh", "its uid 1001"}},
		{"in docker's group", 985, "/usr/sbin/nologin", []string{"docker"}, []string{"it is in the groups docker, which varlatchd would run with"}},
		{"in groups", 985, "/usr/sbin/nologin", []string{"wheel", "adm"}, []string{"it is in the groups wheel, adm"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, said := newFakeHost(t), &recorder{}
			h.users[User], h.shells[User], h.groups[User] = [2]int{c.uid, c.uid}, c.shell, c.groups
			err := Run(context.Background(), options(h, said, t.TempDir()))
			if c.refuse == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "--accept-existing-user") {
				t.Fatalf("not refused: %v", err)
			}
			for _, want := range c.refuse {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%q does not say %q", err, want)
				}
			}
			if _, err := os.Stat(h.Path(DataDir)); err == nil {
				t.Error("the data directory was made for a refused user")
			}
			o := options(h, said, t.TempDir())
			o.AcceptExistingUser = true
			if err := Run(context.Background(), o); err != nil {
				t.Fatalf("accepted: %v", err)
			}
			if !strings.Contains(strings.Join(said.lines, "\n"), "Using the existing user varlatch as --accept-existing-user says") {
				t.Errorf("the acceptance was not said: %q", said.lines)
			}
			for _, want := range c.refuse {
				if !strings.Contains(strings.Join(said.lines, "\n"), want) {
					t.Errorf("the acceptance does not say %q: %q", want, said.lines)
				}
			}
			if err := Run(context.Background(), options(h, &recorder{}, t.TempDir())); err != nil {
				t.Errorf("a rerun after an accepted run: %v", err)
			}
		})
	}
	h := newFakeHost(t)
	h.users[User], h.shells[User] = [2]int{0, 0}, "/usr/sbin/nologin"
	o := options(h, &recorder{}, t.TempDir())
	o.AcceptExistingUser = true
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "uid 0") {
		t.Errorf("root's uid: %v", err)
	}
}

// TestLeftoversOfAnInterruptedRun: a key file no journal knows of is kept
// and said; the temporary files a run that ended mid-write left in
// /etc/varlatch are removed and counted, and nothing else there is
// touched.
func TestLeftoversOfAnInterruptedRun(t *testing.T) {
	skipOffUnix(t)
	h, said := newFakeHost(t), &recorder{}
	etc := h.Path(EtcDir)
	if err := os.MkdirAll(etc, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.Path(RootKEK), []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var leftovers []string
	for _, p := range []string{RootKEK, BackupKey, Journal} {
		name, err := stagedName(h.Path(p))
		if err != nil {
			t.Fatal(err)
		}
		leftovers = append(leftovers, name)
	}
	// The configuration's staged copy a run killed before its rename left.
	leftovers = append(leftovers, h.Path(ConfigFile)+".setup")
	kept := []string{".root-kek.tmp", ".root-kek.0123456789ab.tmp.bak", ".other.0123456789ab.tmp", "notes.txt", ".backup-key.0123456789AB.tmp"}
	for _, p := range leftovers {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range kept {
		if err := os.WriteFile(filepath.Join(etc, n), []byte("not setup's"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory and a link with a leftover's name are not files setup left.
	dirName := filepath.Join(etc, ".setup.json.aaaaaaaaaaaa.tmp")
	if err := os.Mkdir(dirName, 0o700); err != nil {
		t.Fatal(err)
	}
	linkName := filepath.Join(etc, ".backup-key.bbbbbbbbbbbb.tmp")
	if err := os.Symlink(filepath.Join(etc, "notes.txt"), linkName); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), options(h, said, t.TempDir())); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(said.lines, "\n")
	if !strings.Contains(all, "Removed 4 temporary files an interrupted run left in /etc/varlatch.") {
		t.Errorf("the count was not said: %q", said.lines)
	}
	if !strings.Contains(all, "Kept the existing Root KEK at /etc/varlatch/root-kek.") || strings.Contains(all, "Kept the existing backup key") {
		t.Errorf("the kept key was not said, or the made one was: %q", said.lines)
	}
	if b, _ := os.ReadFile(h.Path(RootKEK)); string(b) != strings.Repeat("ab", 32)+"\n" {
		t.Error("the existing Root KEK was replaced")
	}
	for _, p := range leftovers {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s is still there", filepath.Base(p))
		}
	}
	for _, p := range append([]string{dirName, linkName}, func() (out []string) {
		for _, n := range kept {
			out = append(out, filepath.Join(etc, n))
		}
		return
	}()...) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was touched: %v", filepath.Base(p), err)
		}
	}
	// A rerun: nothing to remove, the keys the journal's.
	said = &recorder{}
	if err := Run(context.Background(), options(h, said, t.TempDir())); err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(said.lines, "\n"); strings.Contains(all, "Removed") || strings.Contains(all, "Kept the existing") {
		t.Errorf("a rerun said %q", said.lines)
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
	// secret answers a hidden prompt (the paste-back).
	secret func(q string) []byte
}

func (a *fakeAsker) Secret(q string) ([]byte, error) {
	a.asked = append(a.asked, q)
	if a.secret == nil {
		return nil, errors.New("no hidden answer")
	}
	return a.secret(q), nil
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
	ask := &fakeAsker{texts: map[string]string{"address people open": "https://vault.example.com"}, confirm: true, secret: pasteFrom(h)}
	shown, links := 0, 0
	o := Options{Host: h, Ask: ask, Say: (&recorder{}).say, ShowKeys: func(kek, bek []byte) error {
		shown++
		if len(kek) != 64 || len(bek) != 64 {
			t.Errorf("keys %d %d", len(kek), len(bek))
		}
		return nil
	}, ShowLink: func(link, expires string) error {
		links++
		if link != h.links[len(h.links)-1] || expires != "2026-11-20T12:15:00.000Z" {
			t.Errorf("link %q expires %q", link, expires)
		}
		return nil
	}, AdminWait: time.Second, PollEvery: time.Millisecond}
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
	if err := Run(context.Background(), o); err != nil || shown != 1 || links != 1 {
		t.Errorf("rerun: %v, shown %d, links %d", err, shown, links)
	}
	if !h.attested["root-kek"] || !h.attested["backup-key"] || h.backups != 1 {
		t.Errorf("attested %v, backups %d", h.attested, h.backups)
	}
}

// pasteFrom pastes back the key the prompt names, as stored.
func pasteFrom(h *fakeHost) func(q string) []byte {
	return func(q string) []byte {
		p := BackupKey
		if strings.Contains(q, "Root KEK") {
			p = RootKEK
		}
		b, _ := os.ReadFile(h.Path(p))
		return b
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

// TestFirstAdministrator: without a terminal the link goes to its file and
// setup waits for the passkey; with no wait it stops (ErrPending) and a
// rerun issues a new link into the same file; an administrator made but
// never enrolled gets a recovery link; a wait that ends without a passkey
// stops; the link's file is never another file or a link.
func TestFirstAdministrator(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	h.manualEnroll = true
	o := options(h, &recorder{}, out)
	o.AdminWait = 0
	if err := Run(context.Background(), o); !errors.Is(err, ErrPending) || !strings.Contains(err.Error(), "run setup again") {
		t.Fatalf("no wait: %v", err)
	}
	linkFile := filepath.Join(out, "enroll-link")
	if b, _ := os.ReadFile(linkFile); string(b) != h.links[0]+"\n" || mode(t, linkFile) != 0o600 {
		t.Errorf("the first link's file %q", b)
	}
	if _, err := os.Stat(filepath.Join(out, "root-kek.copy")); err == nil {
		t.Error("the keys' copies were written before the first administrator")
	}
	if err := Run(context.Background(), o); !errors.Is(err, ErrPending) || len(h.links) != 2 {
		t.Fatalf("a rerun: %v, links %q", err, h.links)
	}
	if b, _ := os.ReadFile(linkFile); string(b) != h.links[1]+"\n" {
		t.Errorf("the rerun's link's file %q", b)
	}
	// A wait that ends without a passkey.
	o.AdminWait = 20 * time.Millisecond
	if err := Run(context.Background(), o); !errors.Is(err, ErrPending) || !strings.Contains(err.Error(), "no passkey was enrolled") {
		t.Errorf("a wait without a passkey: %v", err)
	}
	h.enroll()
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("after enrolling: %v", err)
	}
	if _, err := os.Stat(linkFile); err == nil {
		t.Error("the used link's file is still there")
	}
	for _, c := range h.adminCalls {
		if (strings.HasPrefix(c, "bootstrap ") || strings.HasPrefix(c, "recover ")) && !strings.HasSuffix(c, " --revoke-unused") {
			t.Errorf("%q does not revoke the earlier links", c)
		}
	}

	// Bootstrapped headless: a recovery link for that administrator.
	h2, out2 := newFakeHost(t), t.TempDir()
	h2.admin, h2.bootstrapped = "idn_headless", true
	if err := Run(context.Background(), options(h2, &recorder{}, out2)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h2.adminCalls, "recover --identity idn_headless --revoke-unused") || slices.ContainsFunc(h2.adminCalls, func(c string) bool { return strings.HasPrefix(c, "bootstrap ") }) {
		t.Errorf("admin calls %q", h2.adminCalls)
	}

	// The link's file: never another file, never through a link.
	for name, prepare := range map[string]func(p string){
		"another file": func(p string) { _ = os.WriteFile(p, []byte("notes\n"), 0o600) },
		"a link":       func(p string) { _ = os.Symlink(filepath.Join(filepath.Dir(p), "elsewhere"), p) },
	} {
		h3, out3 := newFakeHost(t), t.TempDir()
		o3 := options(h3, &recorder{}, out3)
		prepare(o3.AdminLinkOut)
		if err := Run(context.Background(), o3); err == nil || !strings.Contains(err.Error(), "nothing was written there") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(out3, "elsewhere")); err == nil {
			t.Errorf("%s: written through the link", name)
		}
	}
}

// TestPasteBack: on a terminal the keys are shown once, then each is pasted
// back: a wrong copy is refused (never echoed) and asked again; three wrong
// ones stop setup before custody, and a rerun shows the keys again.
func TestPasteBack(t *testing.T) {
	skipOffUnix(t)
	h := newFakeHost(t)
	wrong := 2
	paste := pasteFrom(h)
	ask := &fakeAsker{confirm: true, secret: func(q string) []byte {
		if strings.Contains(q, "Root KEK") && wrong > 0 {
			wrong--
			return []byte("not-the-key-at-all")
		}
		return paste(q)
	}}
	said := &recorder{}
	shown := 0
	o := Options{Host: h, Ask: ask, Given: localhostAnswers(), Say: said.say, AdminWait: time.Second, PollEvery: time.Millisecond,
		ShowKeys: func(kek, bek []byte) error { shown++; return nil }, ShowLink: func(string, string) error { return nil }}
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(said.lines, "\n")
	if strings.Count(all, "That is not the Root KEK") != 2 || strings.Contains(all, "not-the-key-at-all") || !strings.Contains(all, "The backup key you stored matches.") {
		t.Errorf("said %q", said.lines)
	}

	// Three wrong pastes: stopped, nothing attested; a rerun shows the keys again.
	h2 := newFakeHost(t)
	ask2 := &fakeAsker{confirm: true, secret: func(string) []byte { return []byte("wrong") }}
	shown2 := 0
	o2 := Options{Host: h2, Ask: ask2, Given: localhostAnswers(), Say: (&recorder{}).say, AdminWait: time.Second, PollEvery: time.Millisecond,
		ShowKeys: func(kek, bek []byte) error { shown2++; return nil }, ShowLink: func(string, string) error { return nil }}
	if err := Run(context.Background(), o2); err == nil || !strings.Contains(err.Error(), "did not match three times") {
		t.Fatalf("three wrong pastes: %v", err)
	}
	if len(h2.attested) != 0 || h2.backups != 0 {
		t.Errorf("attested %v, backups %d after a refused paste-back", h2.attested, h2.backups)
	}
	ask2.secret = pasteFrom(h2)
	if err := Run(context.Background(), o2); err != nil || shown2 != 2 {
		t.Errorf("rerun: %v, shown %d", err, shown2)
	}
}

// TestCustodyAttestation: without a terminal the attestation needs
// --attest (setup stops before it, and before the backup); on a terminal
// it is asked; once recorded, a rerun records nothing more.
func TestCustodyAttestation(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	o := options(h, &recorder{}, out)
	o.Attest = false
	if err := Run(context.Background(), o); !errors.Is(err, ErrPending) || !strings.Contains(err.Error(), "--attest") || !strings.Contains(err.Error(), "root-kek.copy") {
		t.Fatalf("without --attest: %v", err)
	}
	if len(h.attested) != 0 || h.backups != 0 {
		t.Errorf("attested %v, backups %d", h.attested, h.backups)
	}
	// A rerun without the copies' names (written by the run before):
	// the keys' own files are named.
	o.RootKEKOut, o.BackupKeyOut = "", ""
	if err := Run(context.Background(), o); !errors.Is(err, ErrPending) || !strings.Contains(err.Error(), "copies of "+RootKEK+" and "+BackupKey) {
		t.Fatalf("without --attest, copies written before: %v", err)
	}
	o.Attest = true
	if err := Run(context.Background(), o); err != nil || !h.attested["root-kek"] || !h.attested["backup-key"] {
		t.Fatalf("with --attest: %v %v", err, h.attested)
	}
	calls := len(h.adminCalls)
	if err := Run(context.Background(), o); err != nil || slices.ContainsFunc(h.adminCalls[calls:], func(c string) bool { return strings.HasPrefix(c, "custody attest") || strings.HasPrefix(c, "backup") }) {
		t.Errorf("a rerun: %v %q", err, h.adminCalls[calls:])
	}
	// On a terminal, a "no" stops for a rerun.
	h2 := newFakeHost(t)
	o2 := Options{Host: h2, Ask: &fakeAsker{secret: pasteFrom(h2)}, Given: localhostAnswers(), Say: (&recorder{}).say, AdminWait: time.Second, PollEvery: time.Millisecond,
		ShowKeys: func(kek, bek []byte) error { return nil }, ShowLink: func(string, string) error { return nil }}
	if err := Run(context.Background(), o2); !errors.Is(err, ErrPending) || len(h2.attested) != 0 {
		t.Errorf("a no: %v %v", err, h2.attested)
	}
}

// TestFirstBackup: a backup that does not verify stops setup, and a rerun
// makes another; a verified one is made once; with a bucket, one not
// delivered stops setup.
func TestFirstBackup(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	h.backupUnverified = true
	o := options(h, &recorder{}, out)
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("unverified: %v", err)
	}
	h.backupUnverified = false
	if err := Run(context.Background(), o); err != nil || h.backups != 2 {
		t.Fatalf("verified: %v, backups %d", err, h.backups)
	}
	if err := Run(context.Background(), o); err != nil || h.backups != 2 {
		t.Errorf("a rerun: %v, backups %d", err, h.backups)
	}
	h2, out2 := newFakeHost(t), t.TempDir()
	o2 := options(h2, &recorder{}, out2)
	o2.Given = Answers{Ingress: Localhost, Backups: "bucket", BackupDestinationsFile: "/etc/varlatch/destinations.json"}
	if err := Run(context.Background(), o2); err == nil || !strings.Contains(err.Error(), "not delivered") {
		t.Errorf("a bucket without delivery: %v", err)
	}
}

// TestDoctorStep: setup ends with doctor's report; a mandatory check that
// fails ends the run with ErrDoctor, everything else done, and a rerun runs
// doctor again only.
func TestDoctorStep(t *testing.T) {
	skipOffUnix(t)
	h, out := newFakeHost(t), t.TempDir()
	o := options(h, &recorder{}, out)
	runs, ok := 0, false
	o.Doctor = func(context.Context) (bool, error) { runs++; return ok, nil }
	if err := Run(context.Background(), o); !errors.Is(err, ErrDoctor) {
		t.Fatalf("a failing doctor: %v", err)
	}
	ok = true
	calls := len(h.adminCalls)
	if err := Run(context.Background(), o); err != nil || runs != 2 || h.backups != 1 {
		t.Errorf("a rerun: %v, doctor %d, backups %d", err, runs, h.backups)
	}
	if slices.ContainsFunc(h.adminCalls[calls:], func(c string) bool {
		return strings.HasPrefix(c, "bootstrap ") || strings.HasPrefix(c, "custody attest")
	}) {
		t.Errorf("a rerun repeated %q", h.adminCalls[calls:])
	}
}

// operatorKeys writes two key files as an operator keeps them, made at
// run time.
func operatorKeys(t *testing.T, dir string) (kek, bek string) {
	t.Helper()
	write := func(name string) string {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("my-root-kek"), write("my-backup-key")
}

// TestRestore: setup --restore on a fresh host installs the operator's
// keys (root, 0600, never shown, copied or said), restores the archive
// before the unit first starts, makes the restored files the unit's, issues
// no enrollment link (the restored administrator has a passkey), and
// verifies a first backup; a rerun without --restore continues it.
func TestRestore(t *testing.T) {
	skipOffUnix(t)
	h, said, out := newFakeHost(t), &recorder{}, t.TempDir()
	h.restoreURL = "http://localhost:8686"
	kek, bek := operatorKeys(t, out)
	o := options(h, said, out)
	o.RootKEKOut, o.BackupKeyOut = "", ""
	o.Restore, o.RootKEKIn, o.BackupKeyIn = "/srv/backups/old.vltbak", kek, bek
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for in, p := range map[string]string{kek: RootKEK, bek: BackupKey} {
		want, _ := os.ReadFile(in)
		got, _ := os.ReadFile(h.Path(p))
		if string(got) != string(want) || mode(t, h.Path(p)) != 0o600 {
			t.Errorf("%s: not the operator's key, or mode %v", p, mode(t, h.Path(p)))
		}
		for _, line := range said.lines {
			if strings.Contains(line, strings.TrimSpace(string(want))) {
				t.Error("a key in setup's output")
			}
		}
	}
	restoreAt := slices.Index(h.adminCalls, "backup restore --in /srv/backups/old.vltbak --backup-key-file "+BackupKey)
	if restoreAt != 0 || len(h.links) != 0 || h.backups != 1 || !slices.Contains(h.adminCalls, "bootstrap-status") {
		t.Errorf("admin calls %q, links %q, backups %d", h.adminCalls, h.links, h.backups)
	}
	if h.chowns["/var/lib/varlatch/varlatch.db"] != [2]int{990, 990} {
		t.Errorf("the restored database is not the unit's: %v", h.chowns)
	}
	if _, err := os.Stat(filepath.Join(out, "root-kek.copy")); err == nil {
		t.Error("a restore wrote a key copy")
	}
	var j JournalDoc
	raw, _ := os.ReadFile(h.Path(Journal))
	if json.Unmarshal(raw, &j) != nil || j.Restore == nil || j.Restore.ArchiveID != "bak_old" || j.Restore.InstallationID != "inst_old" {
		t.Errorf("journal %s", raw)
	}
	// A rerun without --restore continues the restore's installation.
	o2 := options(h, &recorder{}, out)
	o2.RootKEKOut, o2.BackupKeyOut = "", ""
	calls := len(h.adminCalls)
	if err := Run(context.Background(), o2); err != nil || slices.ContainsFunc(h.adminCalls[calls:], func(c string) bool { return strings.HasPrefix(c, "backup") }) {
		t.Errorf("a rerun: %v %q", err, h.adminCalls[calls:])
	}
}

// TestRestoreRefusals: a restore is refused onto a host already set up,
// over another key, with the same key twice, with keys that are not keys,
// and at another address than the archive's (before the unit starts).
func TestRestoreRefusals(t *testing.T) {
	skipOffUnix(t)
	restoreOpts := func(h *fakeHost, out string) Options {
		kek, bek := operatorKeys(t, out)
		o := options(h, &recorder{}, out)
		o.RootKEKOut, o.BackupKeyOut = "", ""
		o.Restore, o.RootKEKIn, o.BackupKeyIn = "/srv/backups/old.vltbak", kek, bek
		return o
	}
	// A host already set up.
	h, out := newFakeHost(t), t.TempDir()
	if err := Run(context.Background(), options(h, &recorder{}, out)); err != nil {
		t.Fatal(err)
	}
	var usage *UsageError
	if err := Run(context.Background(), restoreOpts(h, t.TempDir())); !errors.As(err, &usage) || !strings.Contains(err.Error(), "a restore goes onto a fresh host") {
		t.Errorf("onto a host set up: %v", err)
	}
	// Another key already there.
	h2 := newFakeHost(t)
	if err := os.MkdirAll(h2.Path(EtcDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h2.Path(RootKEK), []byte(strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), restoreOpts(h2, t.TempDir())); err == nil || !strings.Contains(err.Error(), "already holds another Root KEK") {
		t.Errorf("over another key: %v", err)
	}
	// The same key twice; and a file that holds no key.
	h3, out3 := newFakeHost(t), t.TempDir()
	o3 := restoreOpts(h3, out3)
	o3.BackupKeyIn = o3.RootKEKIn
	if err := Run(context.Background(), o3); !errors.As(err, &usage) || !strings.Contains(err.Error(), "hold the same key") {
		t.Errorf("the same key twice: %v", err)
	}
	h4, out4 := newFakeHost(t), t.TempDir()
	o4 := restoreOpts(h4, out4)
	if err := os.WriteFile(o4.BackupKeyIn, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), o4); !errors.As(err, &usage) || !strings.Contains(err.Error(), "does not hold a key") || strings.Contains(err.Error(), "not a key\n") {
		t.Errorf("not a key: %v", err)
	}
	// Another address than the archive's: refused before the unit starts.
	h5, out5 := newFakeHost(t), t.TempDir()
	h5.restoreURL = "https://vault.example.com"
	if err := Run(context.Background(), restoreOpts(h5, out5)); !errors.As(err, &usage) || !strings.Contains(err.Error(), "--public-url https://vault.example.com") {
		t.Errorf("another address: %v", err)
	}
	if slices.Contains(h5.systemctl, "enable --now varlatchd.service") {
		t.Error("the unit started at another address than the archive's")
	}
}

// TestRestoreChecksTheTailnetName: a restore with tailnet ingress probes
// the name before the restored node first enrols: a name still held, or a
// single-use key (the probe spent it), stops setup before the unit starts,
// saying what to do; a name not seen goes on, and a rerun probes no more.
// A restore with public HTTPS reads the restored records' certificate
// issuance count before varlatchd first asks Let's Encrypt (decision 16):
// at its five per name per week, it is refused before the unit starts and
// says when to run setup again; with room, it goes on.
func TestRestoreChecksTheIssuanceCount(t *testing.T) {
	skipOffUnix(t)
	h := newFakeHost(t)
	h.restoreURL, h.issued = "https://vault.example.com", 5
	out := t.TempDir()
	kek, bek := operatorKeys(t, out)
	o := options(h, &recorder{}, out)
	o.RootKEKOut, o.BackupKeyOut = "", ""
	o.Restore, o.RootKEKIn, o.BackupKeyIn = "/srv/backups/old.vltbak", kek, bek
	o.Given = Answers{Ingress: Public, PublicURL: "https://vault.example.com", ACMEEmail: "ops@example.com", Backups: "host"}
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "5 certificate requests for vault.example.com in the last 7 days and an hour, Let's Encrypt's limit of 5") ||
		!strings.Contains(err.Error(), "Nothing has asked; the restored data stays. Run setup again after 2026-11-25T08:00:00Z") {
		t.Fatalf("a full count: %v", err)
	}
	if slices.Contains(h.systemctl, "enable --now varlatchd.service") {
		t.Error("the unit started with the count full")
	}
	// A week on, the count has room: setup goes on, the restore not done
	// again.
	h.issued = 3
	said := &recorder{}
	o.Say = said.say
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	restores := len(slices.DeleteFunc(slices.Clone(h.adminCalls), func(c string) bool { return !strings.HasPrefix(c, "backup restore ") }))
	if restores != 1 || !slices.Contains(h.systemctl, "enable --now varlatchd.service") || !slices.Contains(said.lines, "Certificate requests for vault.example.com in the last 7 days and an hour, by the restored records: 3 of Let's Encrypt's 5.") {
		t.Errorf("restores %d, systemctl %q, said %q", restores, h.systemctl, said.lines)
	}
	// Without public HTTPS, there is nothing to count.
	h2 := newFakeHost(t)
	h2.restoreURL, h2.issued = "http://localhost:8686", 5
	o2 := options(h2, &recorder{}, t.TempDir())
	o2.RootKEKOut, o2.BackupKeyOut = "", ""
	o2.Restore, o2.RootKEKIn, o2.BackupKeyIn = "/srv/backups/old.vltbak", kek, bek
	if err := Run(context.Background(), o2); err != nil || slices.Contains(h2.adminCalls, "certificate issuances --json") {
		t.Errorf("a localhost restore: %v %q", err, h2.adminCalls)
	}
}

func TestRestoreChecksTheTailnetName(t *testing.T) {
	skipOffUnix(t)
	tailnetRestore := func(h *fakeHost) Options {
		out := t.TempDir()
		kek, bek := operatorKeys(t, out)
		o := options(h, &recorder{}, out)
		o.RootKEKOut, o.BackupKeyOut = "", ""
		o.Restore, o.RootKEKIn, o.BackupKeyIn = "/srv/backups/old.vltbak", kek, bek
		o.Given = Answers{Ingress: Tailnet, TailnetHostname: "varlatch", TailnetPort: "8687", TailnetTags: "tag:varlatch",
			TailnetAuthKeyFile: "/etc/varlatch/tailnet-auth-key", Backups: "host"}
		return o
	}
	h := newFakeHost(t)
	h.probeSeen = []string{"varlatch.corp.ts.net"}
	if err := Run(context.Background(), tailnetRestore(h)); err == nil || !strings.Contains(err.Error(), "still held by varlatch.corp.ts.net") {
		t.Fatalf("a held name: %v", err)
	}
	if slices.Contains(h.systemctl, "enable --now varlatchd.service") {
		t.Error("the unit started with the name held")
	}
	h2 := newFakeHost(t)
	h2.probeSingleUse = true
	o := tailnetRestore(h2)
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "single-use") || !strings.Contains(err.Error(), "Reusable, with those tags") ||
		!strings.Contains(err.Error(), "tag:varlatch") || !strings.Contains(err.Error(), "/etc/varlatch/tailnet-auth-key") {
		t.Fatalf("a single-use key: %v", err)
	}
	if slices.Contains(h2.systemctl, "enable --now varlatchd.service") {
		t.Error("the unit started with a spent key")
	}
	// Freed (the old node deleted) and a reusable key: setup goes on.
	h2.probeSingleUse = false
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	probes := func() int {
		return len(slices.DeleteFunc(slices.Clone(h2.adminCalls), func(c string) bool { return c != "tailnet probe-name --json" }))
	}
	if probes() != 2 || !slices.Contains(h2.systemctl, "enable --now varlatchd.service") {
		t.Errorf("probes %d, systemctl %q", probes(), h2.systemctl)
	}
	if err := Run(context.Background(), o); err != nil || probes() != 2 {
		t.Errorf("a rerun: %v, probes %d", err, probes())
	}
	// Without tailnet ingress, a restore probes nothing.
	h3 := newFakeHost(t)
	h3.restoreURL = "http://localhost:8686"
	o3 := tailnetRestore(h3)
	o3.Given = localhostAnswers()
	if err := Run(context.Background(), o3); err != nil || slices.Contains(h3.adminCalls, "tailnet probe-name --json") {
		t.Errorf("a localhost restore: %v %q", err, h3.adminCalls)
	}
}
