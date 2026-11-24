// SPDX-License-Identifier: AGPL-3.0-or-later

package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/custody"
)

// fixture is a healthy installation's files, configuration and live
// state, with the host's functions faked: every check passes.
type fixture struct {
	dir, conf string
	cfg       *config.Config
	in        Inputs
	now       time.Time
}

func newFixture(t *testing.T, extra string) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installation's modes are Unix modes")
	}
	f := &fixture{dir: t.TempDir(), now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	data := filepath.Join(f.dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root-kek", "backup-key"} {
		// Files standing for the keys: doctor only looks at their modes.
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.dir, "destinations.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.conf = filepath.Join(f.dir, "varlatchd.conf")
	conf := fmt.Sprintf("public_url = https://vault.example.com\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_destinations_file = %s\n%s",
		data, filepath.Join(f.dir, "root-kek"), filepath.Join(f.dir, "backup-key"), filepath.Join(f.dir, "destinations.json"), extra)
	if err := os.WriteFile(f.conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(f.conf)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	// One archive from an hour ago: verified, delivered, its remote copy
	// checked.
	iso := func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
	hour := iso(f.now.Add(-time.Hour))
	verified := &backup.Verification{Integrity: true, Compatibility: true, KeyMatch: true, TargetRelease: "0.50.0", CheckedAt: hour}
	if err := backup.SaveStatus(data, backup.StatusRecord{ArchiveID: "0f0e0d0c-0b0a-4908-8706-050403020100", InstallationID: "inst_test", CreatedAt: hour,
		Release: "0.50.0", RequiredKeyVersions: []int{1}, Verification: verified,
		Delivery: &backup.Delivery{Destination: "offsite", UploadedAt: hour, RemoteVerification: verified}}); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(-24 * time.Hour).Format(time.RFC3339Nano)
	v := int64(1)
	f.in = Inputs{
		Config: cfg, ConfigPath: f.conf, Now: func() time.Time { return f.now },
		Live: &Live{Schema: true, KEK: true, Installation: true, InstallationID: "inst_test",
			Storage:  storage.Metrics{WALBytes: 4 << 20, Truncates: 3, LastTruncate: storage.CheckpointResult{Duration: 30 * time.Millisecond, Trigger: "size"}, MaxTruncate: 40 * time.Millisecond},
			WALBound: 64 << 20,
			Custody: &custody.Status{RootKEKVersion: 1, Attestations: map[string]*custody.Attestation{
				"root-kek": {Key: "root-kek", Method: "printed", At: at, KeyVersion: &v}, "backup-key": {Key: "backup-key", Method: "printed", At: at}}}},
		Probe: func(context.Context, string) (diskprobe.Result, error) {
			s := diskprobe.Stats{Samples: 200, P50: time.Millisecond, P95: 2 * time.Millisecond, P99: 3 * time.Millisecond, Max: 4 * time.Millisecond}
			return diskprobe.Result{Append: s, Rewrite: s, Limit: diskprobe.DefaultLimit, Pass: true}, nil
		},
		Free:  func(string) (uint64, error) { return 50 << 30, nil },
		Clock: func() (bool, bool) { return true, true },
	}
	return f
}

func (f *fixture) run(t *testing.T) Report {
	t.Helper()
	return Run(context.Background(), f.in)
}

func checkOf(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s in %+v", id, r.Checks)
	return Check{}
}

// TestHealthyInstallation: every check of a healthy installation passes,
// except the release check, unknown until step 6.6; doctor does not fail.
func TestHealthyInstallation(t *testing.T) {
	f := newFixture(t, "")
	r := f.run(t)
	for _, c := range r.Checks {
		want := Pass
		if c.ID == "release.latest" || c.ID == "realtime.browser" {
			want = Unknown
		}
		if c.Status != want {
			t.Errorf("%s: %s %q", c.ID, c.Status, c.Detail)
		}
	}
	if r.Failed() || r.Via != "daemon" || r.Facts.PublicURL == nil || *r.Facts.PublicURL != "https://vault.example.com" || r.Facts.InstallationID == nil {
		t.Errorf("report %+v", r)
	}
}

// TestFailingChecks: each failing check, with its status, class, what it
// says and its remedy (step 6.5's acceptance list).
func TestFailingChecks(t *testing.T) {
	for _, c := range []struct {
		name, id, class string
		extra           string
		change          func(f *fixture)
		detail, remedy  string
	}{
		{"a slow disk (the probe's seam)", "disk.fsync", Advisory, "", func(f *fixture) {
			f.in.Probe = func(context.Context, string) (diskprobe.Result, error) {
				slow := diskprobe.Stats{Samples: 200, P50: 20 * time.Millisecond, P95: 40 * time.Millisecond, P99: 80 * time.Millisecond, Max: 300 * time.Millisecond, Over100ms: 3}
				return diskprobe.Result{Append: slow, Rewrite: slow, Limit: diskprobe.DefaultLimit}, nil
			}
		}, "p99 80.0 ms", "local disk"},
		{"a disk too slow for the probe's samples", "disk.fsync", Advisory, "", func(f *fixture) {
			f.in.Probe = func(context.Context, string) (diskprobe.Result, error) {
				return diskprobe.Result{}, fmt.Errorf("%w: only 40 append samples in 5s", diskprobe.ErrTooFewSamples)
			}
		}, "only 40 append samples", "local disk"},
		{"a full disk", "disk.free", Mandatory, "", func(f *fixture) {
			f.in.Free = func(string) (uint64, error) { return 10 << 20, nil }
		}, "10.0 MiB free", "Free space"},
		{"a missing Root KEK file", "files.keys", Mandatory, "", func(f *fixture) {
			_ = os.Remove(filepath.Join(f.dir, "root-kek"))
		}, "the Root KEK file " + "@@DIR@@/root-kek is missing", "kek restore"},
		{"a missing backup key file", "files.keys", Mandatory, "", func(f *fixture) {
			_ = os.Remove(filepath.Join(f.dir, "backup-key"))
		}, "the backup key file @@DIR@@/backup-key is missing", "backup key back"},
		{"a key file others can read", "files.keys", Mandatory, "", func(f *fixture) {
			_ = os.Chmod(filepath.Join(f.dir, "root-kek"), 0o644)
		}, "readable by its group or others (mode 0644)", "chmod 0600"},
		{"a data directory others can enter", "files.data-dir", Mandatory, "", func(f *fixture) {
			_ = os.Chmod(f.cfg.DataDir, 0o755)
		}, "open to its group or others (mode 0755)", "chmod 0700"},
		{"a configuration others can write", "files.config", Advisory, "", func(f *fixture) {
			_ = os.Chmod(f.conf, 0o666)
		}, "writable by its group or others", "chmod 0644"},
		{"an expired certificate", "public.certificate", Mandatory, "listen_https = :443\n", func(f *fixture) {
			f.in.Live.Public = json.RawMessage(`{"status":"expired","certificate":{"notBefore":"2026-08-01T00:00:00.000Z","notAfter":"2026-10-30T00:00:00.000Z","renewAfter":"2026-10-01T00:00:00.000Z","issuer":"Test CA"},` +
				`"lastError":"connection refused","failures":4,"nextAttempt":"2026-11-20T12:20:00.000Z"}`)
		}, "expired: nothing is served over HTTPS; valid until 2026-10-30T00:00:00.000Z (Test CA), renewal from 2026-10-01T00:00:00.000Z; 4 failed attempts in a row, the last: connection refused; next attempt 2026-11-20T12:20:00.000Z", "ports 80 and 443"},
		{"no certificate after failures", "public.certificate", Mandatory, "listen_https = :443\n", func(f *fixture) {
			f.in.Live.Public = json.RawMessage(`{"status":"pending","certificate":null,"lastError":"no such host","failures":1,"nextAttempt":"2026-11-20T12:01:00.000Z"}`)
		}, "no certificate for vault.example.com yet", "resolves to this host"},
		{"no backup key: unprotected", "backups.status", Advisory, "", func(f *fixture) {
			f.in.Config.BackupKeyFile = ""
		}, "no backup_key_file: varlatchd makes no scheduled backup", "backup_key_file"},
		{"no destination: archives on this host only", "backups.status", Advisory, "", func(f *fixture) {
			f.in.Config.BackupDestinationsFile = ""
		}, "no destination: archives stay on this host", "backup_destinations_file"},
		{"no recent archive", "backups.status", Advisory, "", func(f *fixture) {
			f.now = f.now.Add(72 * time.Hour)
		}, "No archive created within the last 48 hours", "backup status"},
		{"only an earlier database's archive (a migration made again)", "backups.status", Advisory, "", func(f *fixture) {
			// The live database was made after the archive: an import's.
			f.in.Live.DatabaseCreatedAt = f.now.Add(-30 * time.Minute).Format(time.RFC3339Nano)
		}, "No archive created within the last 48 hours", "backup status"},
		{"only another installation's archive", "backups.status", Advisory, "", func(f *fixture) {
			f.in.Live.InstallationID = "inst_other"
		}, "No archive created within the last 48 hours", "backup status"},
		{"a closed tailnet pin", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed = true, "suffix-changed"
		}, "tailnet access is closed: suffix-changed", "varlatch tailnet repin"},
		{"the node's tags not tailnet_tags", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = https://192.0.2.10\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed = true, "tags-differ"
			f.in.Live.TailnetDetail = "The node's tags (none) are not tailnet_tags (tag:varlatch): on a self-hosted control server they are its pre-auth key's."
		}, "tailnet access is closed: The node's tags (none) are not tailnet_tags (tag:varlatch)", "headscale nodes tag"},
		{"a node waiting for its control server", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed = true, "waiting-for-control"
			f.in.Live.TailnetDetail = "The node is waiting for control: its control server has not answered since varlatchd started."
		}, "tailnet access is closed: The node is waiting for control: its control server has not answered since varlatchd started.", "After 5 minutes of this, the control server may also be refusing the node: check the auth key"},
		{"a node that must be logged in", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed = true, "login-needed"
			f.in.Live.TailnetDetail = "The node must be logged in or approved at its control server."
		}, "tailnet access is closed: The node must be logged in or approved at its control server.", "admin console"},
		{"a node its control server refused", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed = true, "join-refused"
			f.in.Live.TailnetDetail = "The node's control server refused it."
		}, "tailnet access is closed: The node's control server refused it.", "put it right, then restart varlatchd. Keep <data_dir>/tailnet"},
		{"a node its control server refused, enrolling", "tailnet.pin", Mandatory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n", func(f *fixture) {
			f.in.Live.Tailnet, f.in.Live.TailnetClosed, f.in.Live.TailnetNeverJoined = true, "join-refused", true
			f.in.Live.TailnetDetail = "The node's control server refused it."
		}, "tailnet access is closed: The node's control server refused it.", "The node never joined: a new auth key (tailnet_auth_key_file) is read only while it has no state, so stop varlatchd, move <data_dir>/tailnet away"},
		{"Tailscale's DERP servers in a self-hosted DERP map", "tailnet.control", Advisory, "tailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_control_url = https://192.0.2.10\n", func(f *fixture) {
			f.in.Live.Tailnet = true
			f.in.Live.TailnetWarnings = []string{"The control server's DERP map lists Tailscale's DERP servers (derp1f.tailscale.com)."}
		}, "lists Tailscale's DERP servers (derp1f.tailscale.com)", "derp.urls"},
		{"a WAL past its bound", "storage.wal", Mandatory, "", func(f *fixture) {
			f.in.Live.Storage.WALBytes, f.in.Live.Storage.TruncatesDelayed = 200<<20, 2
		}, "the WAL is 200.0 MiB; its bound is 64.0 MiB (more than 2 times", "long reader"},
		{"a slow TRUNCATE checkpoint", "storage.checkpoints", Advisory, "", func(f *fixture) {
			f.in.Live.Storage.LastTruncate.Duration, f.in.Live.Storage.MaxTruncate = 3*time.Second, 3*time.Second
		}, "the last took 3s (size), the slowest 3s: slower than 1s", "fsync check"},
		{"a busy TRUNCATE", "storage.checkpoints", Advisory, "", func(f *fixture) {
			f.in.Live.Storage.TruncatesBusy = 2
		}, "2 returned busy", "fsync check"},
		{"a maintenance gate", "secret-plane.ready", Mandatory, "", func(f *fixture) {
			f.in.Live.Maintenance = true
		}, "a maintenance gate holds the installation", "maintenance status"},
		{"the wrong Root KEK", "secret-plane.ready", Mandatory, "", func(f *fixture) {
			f.in.Live.KEK = false
		}, "does not open this installation's canary", "off-host copy"},
		{"an unsynchronized clock", "clock.sync", Advisory, "", func(f *fixture) {
			f.in.Clock = func() (bool, bool) { return false, true }
		}, "not synchronized", "timedatectl set-ntp true"},
		{"no public URL", "config.public-url", Mandatory, "", func(f *fixture) {
			f.in.Config.PublicURL = nil
		}, "public_url is not set", "public_url"},
		{"an attestation too old", "custody.attestations", Advisory, "", func(f *fixture) {
			f.in.Live.Custody.Attestations["root-kek"].At = f.now.Add(-200 * 24 * time.Hour).Format(time.RFC3339Nano)
		}, "root-kek attested 200 days ago", "custody attest"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.extra)
			c.change(f)
			r := f.run(t)
			got := checkOf(t, r, c.id)
			detail := strings.ReplaceAll(c.detail, "@@DIR@@", f.dir)
			if got.Status != Fail || got.Class != c.class || !strings.Contains(got.Detail, detail) || !strings.Contains(got.Remedy, c.remedy) {
				t.Errorf("%s: %+v\nwant detail containing %q, remedy containing %q", c.id, got, detail, c.remedy)
			}
			if r.Failed() != (c.class == Mandatory) {
				t.Errorf("doctor failed %v with a %s failure", r.Failed(), c.class)
			}
			// Every other check still passes (the release check aside).
			for _, other := range r.Checks {
				if other.ID != c.id && other.ID != "release.latest" && other.ID != "realtime.browser" && other.Status != Pass {
					t.Errorf("%s also %s: %q", other.ID, other.Status, other.Detail)
				}
			}
		})
	}
}

// TestWithoutARunningVarlatchd: the server's checks are unknown (never a
// pass, never a guess), with how to start it; the host's are still made.
func TestWithoutARunningVarlatchd(t *testing.T) {
	f := newFixture(t, "listen_https = :443\ntailnet = on\ntailnet_hostname = varlatch\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\n")
	f.in.Live = nil
	r := f.run(t)
	if r.Via != "offline" || r.Facts.InstallationID != nil {
		t.Errorf("report %+v", r)
	}
	for _, id := range []string{"secret-plane.ready", "storage.wal", "storage.checkpoints", "public.certificate", "tailnet.pin", "custody.attestations"} {
		if c := checkOf(t, r, id); c.Status != Unknown {
			t.Errorf("%s: %s", id, c.Status)
		}
	}
	for _, id := range []string{"config.public-url", "files.data-dir", "files.keys", "disk.free", "disk.fsync", "backups.status"} {
		if c := checkOf(t, r, id); c.Status != Pass {
			t.Errorf("%s: %s %q", id, c.Status, c.Detail)
		}
	}
	if r.Failed() {
		t.Error("unknown failed doctor")
	}
}

// TestUnknownWhenItCannotLook: a systemd credential seen from outside the
// unit, a file this user may not look at, a probe it may not run, an
// unreadable clock: unknown, with what to do, never a failure.
func TestUnknownWhenItCannotLook(t *testing.T) {
	f := newFixture(t, "")
	f.in.Config.RootKEKFile = "/run/credentials/varlatchd.service/root-kek"
	stat := os.Stat
	f.in.Stat = func(p string) (fs.FileInfo, error) {
		if p == f.in.Config.RootKEKFile {
			return nil, fs.ErrPermission // the unit's credential directory, root's
		}
		return stat(p)
	}
	f.in.Probe = func(context.Context, string) (diskprobe.Result, error) { return diskprobe.Result{}, os.ErrPermission }
	f.in.Clock = func() (bool, bool) { return false, false }
	r := f.run(t)
	for id, want := range map[string]string{"files.keys": "systemd credential", "disk.fsync": "sudo varlatch doctor", "clock.sync": "cannot be read"} {
		c := checkOf(t, r, id)
		if c.Status != Unknown || !strings.Contains(c.Detail+" "+c.Remedy, want) {
			t.Errorf("%s: %+v", id, c)
		}
	}
	f.in.Probe = func(context.Context, string) (diskprobe.Result, error) {
		return diskprobe.Result{}, diskprobe.ErrUnnamed
	}
	if c := checkOf(t, f.run(t), "disk.fsync"); c.Status != Unknown || !errors.Is(diskprobe.ErrUnnamed, diskprobe.ErrUnnamed) {
		t.Errorf("no unnamed file: %+v", c)
	}
}

// TestNoURLCredentialInTheReport: a URL's user name and password in what
// a CA or a network error said are masked in every check.
func TestNoURLCredentialInTheReport(t *testing.T) {
	f := newFixture(t, "listen_https = :443\n")
	f.in.Live.Public = json.RawMessage(`{"status":"expired","certificate":null,"lastError":"fetching https://ops:hunter2@ca.example/directory: refused","failures":1,"nextAttempt":null}`)
	c := checkOf(t, f.run(t), "public.certificate")
	if strings.Contains(c.Detail, "hunter2") || strings.Contains(c.Detail, "ops:") || !strings.Contains(c.Detail, "https://[redacted]@ca.example/directory") {
		t.Errorf("detail %q", c.Detail)
	}
}

// TestUnaskedIsNotStopped (#328 review): a varlatchd this user could not
// ask (its data directory or socket refused) is never reported stopped:
// the server's checks are unknown, saying why, with a run-as remedy.
func TestUnaskedIsNotStopped(t *testing.T) {
	f := newFixture(t, "")
	f.in.Live, f.in.Unasked = nil, "the data directory /var/lib/varlatch is owned by uid 990, not by you (uid 1000)"
	r := f.run(t)
	if r.Via != "unasked" || r.Failed() {
		t.Fatalf("report %+v", r)
	}
	for _, id := range []string{"secret-plane.ready", "storage.wal", "storage.checkpoints"} {
		c := checkOf(t, r, id)
		if c.Status != Unknown || !strings.Contains(c.Detail, "could not be asked (the data directory /var/lib/varlatch is owned by uid 990") || !strings.Contains(c.Remedy, "sudo varlatch doctor") {
			t.Errorf("%s: %+v", id, c)
		}
	}
}

// TestOneLineCutsOnACharacter: a long line is cut before a character,
// never inside one.
func TestOneLineCutsOnACharacter(t *testing.T) {
	s := oneLine("a" + strings.Repeat("€", 120))
	if !utf8.ValidString(s) || !strings.HasSuffix(s, "€…") || len(s) > 304 {
		t.Errorf("%q (%d bytes)", s, len(s))
	}
}

// TestCredentialMissingOrHidden (#328 review): a systemd credential that
// does not exist is missing (the unit is not running, or does not load
// it); one this user may not look at is unknown, with a run-as remedy.
func TestCredentialMissingOrHidden(t *testing.T) {
	const cred = "/run/credentials/varlatchd.service/root-kek"
	f := newFixture(t, "")
	f.in.Config.RootKEKFile = cred
	stat := os.Stat
	for _, c := range []struct {
		err            error
		status, detail string
		remedy         string
	}{
		{fs.ErrNotExist, Fail, cred + " is missing: the unit is not running, or does not load that credential", "LoadCredential="},
		{fs.ErrPermission, Unknown, "is a systemd credential, visible to the unit (and root) only", "sudo varlatch doctor"},
	} {
		f.in.Stat = func(p string) (fs.FileInfo, error) {
			if p == cred {
				return nil, c.err
			}
			return stat(p)
		}
		got := checkOf(t, f.run(t), "files.keys")
		if got.Status != c.status || !strings.Contains(got.Detail, c.detail) || !strings.Contains(got.Remedy, c.remedy) {
			t.Errorf("%v: %+v", c.err, got)
		}
	}
}
