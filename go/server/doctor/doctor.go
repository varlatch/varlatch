// SPDX-License-Identifier: AGPL-3.0-or-later

// Package doctor is a Go installation's health report (ADR-0059 Decision
// 8; internal docs/design/go-step6.md, decision 8 and slice 6.5): what
// `varlatchd admin doctor` reports and `varlatch doctor` fronts.
//
// Doctor reads, never writes. The host's part is read here, by the
// process the operator runs: the configuration, the data directory's and
// the key files' modes (stat only: a key file is never opened), free
// space, the clock, the backups' status files, and a short fsync probe
// whose file has no name (it never appears in the data directory). The
// server's part (readiness, the WAL and its checkpoints, the public
// certificate, the tailnet pin, custody attestations) is what the running
// varlatchd says through its control socket (Live); without a running
// varlatchd it is unknown, and nothing opens the database or takes its
// lock.
//
// Each check is pass, fail or unknown, mandatory or advisory, with what
// was seen and, when it does not pass, what to do. A mandatory failure is
// exit status 1; unknown never fails.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/diskprobe"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/custody"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/tailnet/closed"
)

// Status of a check.
const (
	Pass    = "pass"
	Fail    = "fail"
	Unknown = "unknown"
)

// Class of a check: a mandatory failure fails doctor (exit 1).
const (
	Mandatory = "mandatory"
	Advisory  = "advisory"
)

// Check is one result, as the TypeScript doctor's (apps/cli/src/doctor.ts).
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
	Remedy string `json:"remedy,omitempty"`
}

// Facts describe the installation.
type Facts struct {
	ServerVersion  string    `json:"serverVersion"`
	SchemaVersion  int       `json:"schemaVersion"`
	DataDir        string    `json:"dataDir"`
	PublicURL      *string   `json:"publicUrl"`
	InstallationID *string   `json:"installationId"`
	Listeners      Listeners `json:"listeners"`
}

// Listeners are the listeners the configuration opens.
type Listeners struct {
	Plain          string  `json:"plain"`
	HTTPS          *string `json:"https"`
	HTTPRedirect   *string `json:"httpRedirect"`
	TailnetPort    *int    `json:"tailnetPort"`
	TailnetBrowser *int    `json:"tailnetBrowserPort"`
}

// Report is doctor's answer. Via is "daemon" when the running varlatchd
// answered on its control socket, "offline" when none did, "unasked" when
// this user could not ask it (the data directory or its socket refused).
type Report struct {
	Via    string  `json:"via"`
	Facts  Facts   `json:"facts"`
	Checks []Check `json:"checks"`
}

// Failed reports whether a mandatory check failed.
func (r Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Class == Mandatory && c.Status == Fail {
			return true
		}
	}
	return false
}

// Live is what only the running varlatchd knows, sent over its control
// socket (`varlatchd admin doctor --live`).
type Live struct {
	Schema         bool   `json:"schema"`
	KEK            bool   `json:"kek"`
	Installation   bool   `json:"installation"`
	InstallationID string `json:"installationId,omitempty"`
	// DatabaseCreatedAt is when the live database was made (schema_version;
	// a migration's import makes it then): the backups' check counts only
	// this database's archives (backup.Lifecycle).
	DatabaseCreatedAt string `json:"databaseCreatedAt,omitempty"`
	// Maintenance: a maintenance gate holds the installation.
	Maintenance bool `json:"maintenance"`
	// UpgradeHold is why an upgrade holds varlatchd (server/maintenance), ""
	// when none does.
	UpgradeHold string `json:"upgradeHold,omitempty"`
	// Storage is the engine's metrics (ADR-0059 Decision 2) and WALBound
	// its bound.
	Storage  storage.Metrics `json:"storage"`
	WALBound int64           `json:"walBound"`
	// Public is public HTTPS's report (publictls.Manager.Report); null
	// when it is off.
	Public json.RawMessage `json:"public,omitempty"`
	// Tailnet: whether the tailnet listener runs, and why its pin closes
	// tailnet access ("" when it is open).
	Tailnet       bool   `json:"tailnet"`
	TailnetClosed string `json:"tailnetClosed,omitempty"`
	// TailnetDetail says why the node's tags close access (TailnetClosed
	// tags-differ: both sets named); TailnetWarnings what the last check
	// found that closes nothing (a self-hosted control server's DERP map
	// listing Tailscale's DERP servers).
	TailnetDetail   string   `json:"tailnetDetail,omitempty"`
	TailnetWarnings []string `json:"tailnetWarnings,omitempty"`
	// Custody is the attestations, CustodyError why they could not be read.
	Custody      *custody.Status `json:"custody,omitempty"`
	CustodyError string          `json:"custodyError,omitempty"`
}

// Thresholds.
const (
	// WALFactor: the WAL is past its bound above this many times the bound
	// (the checkpointer resets it at the bound; G9a judges a peak under
	// twice the bound).
	WALFactor = 2
	// SlowTruncate: a TRUNCATE checkpoint slower than this is reported
	// (ADR-0059 Decision 2 measured each under 50 ms on a VPS disk).
	SlowTruncate = time.Second
	// FreeMargin is the free space kept beyond a snapshot's.
	FreeMargin = 64 << 20
	// CustodyMaxAge is how old an attestation may be (the TypeScript
	// doctor's CUSTODY_MAX_AGE_DAYS).
	CustodyMaxAge = 180 * 24 * time.Hour
	// ProbeDuration is the fsync probe's length: diskprobe's default, 250
	// samples of each kind on a disk that keeps up.
	ProbeDuration = 5 * time.Second
)

// Inputs are what Run reads; the functions are the host's, and tests
// replace them.
type Inputs struct {
	Config     *config.Config
	ConfigPath string
	// Live is nil when no varlatchd answered; Unasked then says why this
	// user could not ask one ("" when none listens).
	Live    *Live
	Unasked string
	Now     func() time.Time
	// Probe measures the data directory's disk (diskprobe.Run, with an
	// unnamed file).
	Probe func(ctx context.Context, dir string) (diskprobe.Result, error)
	// Free is the space left on dir's filesystem for this process.
	Free func(dir string) (uint64, error)
	// Clock reports whether the system clock is synchronized (known false
	// when it cannot tell).
	Clock func() (synced, known bool)
	// Stat is os.Stat; Owner the file's owner (false when unknown).
	Stat func(path string) (fs.FileInfo, error)
}

func (in *Inputs) defaults() {
	if in.Now == nil {
		in.Now = time.Now
	}
	if in.Probe == nil {
		in.Probe = func(ctx context.Context, dir string) (diskprobe.Result, error) {
			return diskprobe.Run(ctx, diskprobe.Options{Dir: dir, Duration: ProbeDuration, Unnamed: true})
		}
	}
	if in.Free == nil {
		in.Free = freeSpace
	}
	if in.Clock == nil {
		in.Clock = clockSynced
	}
	if in.Stat == nil {
		in.Stat = os.Stat
	}
}

// Run makes the report.
func Run(ctx context.Context, in Inputs) Report {
	in.defaults()
	cfg := in.Config
	r := Report{Via: "offline", Facts: facts(cfg, in.Live)}
	switch {
	case in.Live != nil:
		r.Via = "daemon"
	case in.Unasked != "":
		r.Via = "unasked"
	}
	add := func(c Check) {
		// Without the running varlatchd's answer: why, and what to do.
		if in.Live == nil && c.Detail == notRunning && in.Unasked != "" {
			c.Detail, c.Remedy = "varlatchd could not be asked ("+oneLine(in.Unasked)+"), so this is unknown", runAs
		}
		r.Checks = append(r.Checks, c)
	}
	add(readiness(in.Live))
	add(publicURL(cfg))
	add(dataDir(in))
	add(keyFiles(in))
	add(configFile(in))
	add(diskFree(in))
	add(fsyncProbe(ctx, in))
	add(clock(in))
	add(wal(in.Live))
	add(checkpoints(in.Live))
	if cfg.PublicHTTPS != nil {
		add(certificate(cfg, in.Live))
	}
	if cfg.Tailnet != nil {
		add(tailnetPin(in.Live))
		add(tailnetControl(in))
	}
	add(backupsStatus(in))
	add(custodyCheck(in))
	add(Check{ID: "realtime.browser", Title: "Live updates reach browsers", Status: Unknown, Class: Mandatory,
		Detail: "only a browser sees whether live updates reach it: open the dashboard and watch a change arrive"})
	add(Check{ID: "release.latest", Title: "Newer release check", Status: Unknown, Class: Advisory,
		Detail: "no release check is recorded: `varlatch upgrade --check` comes with step 6.6"})
	// What a CA, a network error or a file said may name a URL: never its
	// user name and password.
	for i := range r.Checks {
		r.Checks[i].Detail = maskUserinfo(r.Checks[i].Detail)
		r.Checks[i].Remedy = maskUserinfo(r.Checks[i].Remedy)
	}
	return r
}

// userinfo is a URL's user name and password: scheme://user[:password]@.
var userinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@\s]*@`)

// maskUserinfo masks every URL's user name and password in s.
func maskUserinfo(s string) string { return userinfo.ReplaceAllString(s, "${1}[redacted]@") }

func facts(cfg *config.Config, live *Live) Facts {
	f := Facts{ServerVersion: buildinfo.Version, SchemaVersion: db.SchemaVersion, DataDir: cfg.DataDir, Listeners: Listeners{Plain: cfg.Listen}}
	if cfg.PublicURL != nil {
		s := origin(cfg.PublicURL)
		f.PublicURL = &s
	}
	if live != nil && live.InstallationID != "" {
		id := live.InstallationID
		f.InstallationID = &id
	}
	if p := cfg.PublicHTTPS; p != nil {
		f.Listeners.HTTPS = &p.Listen
		if p.RedirectListen != "" {
			f.Listeners.HTTPRedirect = &p.RedirectListen
		}
	}
	if t := cfg.Tailnet; t != nil {
		f.Listeners.TailnetPort = &t.Port
		if t.HTTPSPort != 0 {
			f.Listeners.TailnetBrowser = &t.HTTPSPort
		}
	}
	return f
}

// origin is u's scheme, host and port: never a path, a query or userinfo.
func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

const notRunning = "varlatchd did not answer on its control socket, so this is unknown"
const startIt = "Start varlatchd (sudo systemctl start varlatchd; journalctl -u varlatchd says why it stopped), then run doctor again"
const runAs = "Run doctor as root (sudo varlatch doctor), or as the user varlatchd runs as where the configuration names root_kek_file"

func readiness(live *Live) Check {
	c := Check{ID: "secret-plane.ready", Title: "Server readiness (schema, Root KEK, installation)", Class: Mandatory}
	switch {
	case live == nil:
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
	case live.UpgradeHold == maintenance.UpgradeJournalMissing:
		c.Status, c.Detail = Fail, "an upgrade holds varlatchd, and its journal, which says when it is over, is gone: nothing but /healthz is served"
		c.Remedy = "Once no varlatch upgrade runs: sudo systemctl restart varlatchd (it serves the database in place)"
	case live.UpgradeHold == maintenance.UpgradeJournalUnreadable:
		c.Status, c.Detail = Fail, "an upgrade holds varlatchd, and its journal, which says when it is over, cannot be read: nothing but /healthz is served"
		c.Remedy = "Run sudo varlatch upgrade: it says what to do with the journal"
	case live.UpgradeHold != "":
		c.Status, c.Detail = Fail, "an upgrade that is not over holds varlatchd: nothing but /healthz is served"
		c.Remedy = "When no varlatch upgrade runs: sudo varlatch upgrade finishes or undoes it"
	case live.Maintenance:
		c.Status, c.Detail = Fail, "a maintenance gate holds the installation: nothing but /healthz is served"
		c.Remedy = "Wait for the backup or upgrade holding it, or end it: `varlatchd admin maintenance status`, then `end <lease id>`"
	case !live.Installation:
		c.Status, c.Detail, c.Remedy = Fail, "the installation is not initialized", "Run `varlatch setup` on this host"
	case !live.Schema:
		c.Status, c.Detail = Fail, fmt.Sprintf("the database's schema is not one this varlatchd (schema %d) can serve", db.SchemaVersion)
		c.Remedy = "Run the varlatchd release that matches the database, or restore a backup"
	case !live.KEK:
		c.Status, c.Detail = Fail, "the Root KEK does not open this installation's canary"
		c.Remedy = "root_kek_file must hold this installation's Root KEK: restore it from its off-host copy"
	default:
		c.Status, c.Detail = Pass, "schema, Root KEK and installation are ready"
	}
	return c
}

func publicURL(cfg *config.Config) Check {
	c := Check{ID: "config.public-url", Title: "Public URL", Class: Mandatory}
	if cfg.PublicURL == nil {
		c.Status, c.Detail = Fail, "public_url is not set: enrollment links and the dashboard's passkeys need it"
		c.Remedy = "Set public_url in varlatchd.conf to the exact origin people reach Varlatch at, such as https://varlatch.example.com"
		return c
	}
	c.Status, c.Detail = Pass, origin(cfg.PublicURL)
	return c
}

// statFailure is a check's answer to a stat it could not make.
func statFailure(c Check, what, path string, err error) Check {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.Status, c.Detail = Fail, what+" "+path+" is missing"
	case errors.Is(err, fs.ErrPermission):
		c.Status, c.Detail, c.Remedy = Unknown, what+" "+path+" cannot be looked at by this user", "Run doctor as root: sudo varlatch doctor"
	default:
		c.Status, c.Detail = Unknown, what+" "+path+": "+err.Error()
	}
	return c
}

func dataDir(in Inputs) Check {
	dir := in.Config.DataDir
	c := Check{ID: "files.data-dir", Title: "Data directory", Class: Mandatory}
	info, err := in.Stat(dir)
	if err != nil {
		c = statFailure(c, "the data directory", dir, err)
		if c.Status == Fail {
			c.Remedy = "Set data_dir to the installation's data directory, or restore it from a backup (varlatch setup --restore)"
		}
		return c
	}
	switch {
	case !info.IsDir():
		c.Status, c.Detail, c.Remedy = Fail, dir+" is not a directory", "Set data_dir to the installation's data directory"
	case info.Mode().Perm()&0o077 != 0:
		c.Status, c.Detail = Fail, fmt.Sprintf("%s is open to its group or others (mode %04o): it holds the database", dir, info.Mode().Perm())
		c.Remedy = "chmod 0700 " + dir
	default:
		c.Status, c.Detail = Pass, fmt.Sprintf("%s (mode %04o)", dir, info.Mode().Perm())
	}
	return c
}

// keyFile is one key file doctor looks at.
type keyFile struct{ what, path, remedy string }

func keyFiles(in Inputs) Check {
	cfg := in.Config
	c := Check{ID: "files.keys", Title: "Key files (Root KEK, backup key)", Class: Mandatory}
	files := []keyFile{{"the Root KEK file", cfg.RootKEKFile, "Put the Root KEK back from its off-host copy (varlatchd admin kek restore), mode 0600, owned by the service"}}
	if cfg.BackupKeyFile != "" {
		files = append(files, keyFile{"the backup key file", cfg.BackupKeyFile, "Put the backup key back from its off-host copy, mode 0600, or set backup_key_file to where it is"})
	}
	var seen, unknown, failed []string
	var remedies []string
	for _, f := range files {
		if credential(f.path) {
			// A systemd credential: its directory is the unit's, open to
			// root, and there only while the unit runs and loads it.
			_, err := in.Stat(f.path)
			switch {
			case errors.Is(err, fs.ErrPermission):
				unknown = append(unknown, f.what+" is a systemd credential, visible to the unit (and root) only")
				remedies = append(remedies, "Run doctor as root: sudo varlatch doctor")
				continue
			case errors.Is(err, fs.ErrNotExist):
				failed = append(failed, f.what+" "+f.path+" is missing: the unit is not running, or does not load that credential")
				remedies = append(remedies, "Check the unit's LoadCredential= (systemctl cat varlatchd) and start it")
				continue
			}
		}
		info, err := in.Stat(f.path)
		if err != nil {
			s := statFailure(Check{}, f.what, f.path, err)
			if s.Status == Fail {
				failed = append(failed, s.Detail)
				remedies = append(remedies, f.remedy)
			} else {
				unknown = append(unknown, s.Detail)
				if s.Remedy != "" {
					remedies = append(remedies, s.Remedy)
				}
			}
			continue
		}
		switch {
		case !info.Mode().IsRegular():
			failed = append(failed, f.what+" "+f.path+" is not a regular file")
			remedies = append(remedies, f.remedy)
		case info.Mode().Perm()&0o077 != 0:
			failed = append(failed, fmt.Sprintf("%s %s is readable by its group or others (mode %04o)", f.what, f.path, info.Mode().Perm()))
			remedies = append(remedies, "chmod 0600 "+f.path)
		default:
			seen = append(seen, fmt.Sprintf("%s (mode %04o)", f.path, info.Mode().Perm()))
		}
	}
	switch {
	case len(failed) > 0:
		c.Status, c.Detail = Fail, strings.Join(failed, "; ")
	case len(unknown) > 0:
		c.Status, c.Detail = Unknown, strings.Join(append(unknown, seen...), "; ")
	default:
		c.Status, c.Detail = Pass, strings.Join(seen, ", ")
	}
	c.Remedy = strings.Join(unique(remedies), "; ")
	return c
}

// credential is whether path is a systemd credential (the unit's own).
func credential(path string) bool {
	return strings.HasPrefix(path, "/run/credentials/") || strings.Contains(path, "/credentials/")
}

func unique(in []string) []string {
	var out []string
	for _, s := range in {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func configFile(in Inputs) Check {
	c := Check{ID: "files.config", Title: "Configuration file", Class: Advisory}
	if in.ConfigPath == "" {
		c.Status, c.Detail = Unknown, "the configuration file's path is not known"
		return c
	}
	info, err := in.Stat(in.ConfigPath)
	if err != nil {
		return statFailure(c, "the configuration file", in.ConfigPath, err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		c.Status, c.Detail = Fail, fmt.Sprintf("%s is writable by its group or others (mode %04o): whoever can change it chooses the server's keys and listeners", in.ConfigPath, info.Mode().Perm())
		c.Remedy = "chmod 0644 " + in.ConfigPath + " (owned by root)"
		return c
	}
	c.Status, c.Detail = Pass, fmt.Sprintf("%s (mode %04o)", in.ConfigPath, info.Mode().Perm())
	return c
}

// databaseBytes is the database's size with its WAL: what a snapshot
// copies.
func databaseBytes(in Inputs) int64 {
	var n int64
	for _, suffix := range []string{"", "-wal"} {
		if info, err := in.Stat(in.Config.DatabasePath() + suffix); err == nil {
			n += info.Size()
		}
	}
	return n
}

func diskFree(in Inputs) Check {
	c := Check{ID: "disk.free", Title: "Free space for a snapshot", Class: Mandatory}
	free, err := in.Free(in.Config.DataDir)
	if err != nil {
		c.Status, c.Detail = Unknown, "the data directory's free space cannot be read: "+err.Error()
		return c
	}
	need := uint64(databaseBytes(in)) + FreeMargin
	detail := fmt.Sprintf("%s free; the database is %s, and a snapshot needs as much again (plus %s)", size(free), size(uint64(databaseBytes(in))), size(FreeMargin))
	if free < need {
		c.Status, c.Detail = Fail, detail
		c.Remedy = "Free space on the data directory's filesystem, or grow it: a backup's snapshot, and the WAL, need room"
		return c
	}
	c.Status, c.Detail = Pass, detail
	return c
}

func size(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", n>>10)
	}
}

func fsyncProbe(ctx context.Context, in Inputs) Check {
	c := Check{ID: "disk.fsync", Title: "Disk fsync latency (p99 under 10 ms)", Class: Advisory}
	res, err := in.Probe(ctx, in.Config.DataDir)
	switch {
	case errors.Is(err, fs.ErrPermission):
		c.Status, c.Detail, c.Remedy = Unknown, "the probe cannot write a temporary file in the data directory as this user", "Run doctor as root: sudo varlatch doctor"
	case errors.Is(err, diskprobe.ErrTooFewSamples):
		// A disk that cannot sync 100 times of each kind in the probe's
		// time is slow by any measure.
		c.Status, c.Detail = Fail, oneLine(err.Error())
		c.Remedy = "Every write waits for this disk's fsync: put the data directory on a local disk (network block storage is not supported until G9a passes on it), or expect slow writes"
	case err != nil:
		c.Status, c.Detail = Unknown, "the fsync probe did not run: "+err.Error()
	case !res.Pass:
		c.Status, c.Detail = Fail, res.String()
		c.Remedy = "Every write waits for this disk's fsync: put the data directory on a local disk (network block storage is not supported until G9a passes on it), or expect slow writes"
	default:
		c.Status, c.Detail = Pass, res.String()
	}
	return c
}

func clock(in Inputs) Check {
	c := Check{ID: "clock.sync", Title: "System clock synchronized", Class: Advisory}
	synced, known := in.Clock()
	switch {
	case !known:
		c.Status, c.Detail = Unknown, "the clock's synchronization cannot be read on this system"
	case !synced:
		c.Status, c.Detail = Fail, "the system clock is not synchronized: credential lifetimes, approvals and audit times rely on it"
		c.Remedy = "Turn time synchronization on: sudo timedatectl set-ntp true"
	default:
		c.Status, c.Detail = Pass, "synchronized"
	}
	return c
}

func wal(live *Live) Check {
	c := Check{ID: "storage.wal", Title: "Write-ahead log within its bound", Class: Mandatory}
	if live == nil {
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
		return c
	}
	detail := fmt.Sprintf("the WAL is %s; its bound is %s", size(uint64(live.Storage.WALBytes)), size(uint64(live.WALBound)))
	if live.WALBound > 0 && live.Storage.WALBytes > WALFactor*live.WALBound {
		c.Status, c.Detail = Fail, detail+fmt.Sprintf(" (more than %d times: checkpoints cannot reset it)", WALFactor)
		if live.Storage.TruncatesDelayed > 0 {
			c.Detail += "; a snapshot held a checkpoint off"
		}
		c.Remedy = "A long reader holds the WAL: let a running backup finish (varlatchd admin backup status), then look at the checkpoint check; restart varlatchd if it stays"
		return c
	}
	c.Status, c.Detail = Pass, detail
	return c
}

func checkpoints(live *Live) Check {
	c := Check{ID: "storage.checkpoints", Title: "TRUNCATE checkpoints", Class: Advisory}
	if live == nil {
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
		return c
	}
	m := live.Storage
	if m.Truncates == 0 && m.CheckpointErrors == 0 {
		c.Status, c.Detail = Pass, "none since varlatchd started"
		return c
	}
	detail := fmt.Sprintf("%d since start; the last took %s (%s), the slowest %s", m.Truncates, m.LastTruncate.Duration.Round(time.Millisecond),
		m.LastTruncate.Trigger, m.MaxTruncate.Round(time.Millisecond))
	var problems []string
	if m.LastTruncate.Duration > SlowTruncate || m.MaxTruncate > SlowTruncate {
		problems = append(problems, fmt.Sprintf("slower than %s", SlowTruncate))
	}
	if m.TruncatesBusy > 0 {
		problems = append(problems, fmt.Sprintf("%d returned busy (the WAL was not reset)", m.TruncatesBusy))
	}
	if m.CheckpointErrors > 0 {
		problems = append(problems, fmt.Sprintf("%d failed (last: %s)", m.CheckpointErrors, oneLine(m.LastCheckpointErr)))
	}
	if len(problems) > 0 {
		c.Status, c.Detail = Fail, detail+": "+strings.Join(problems, "; ")
		c.Remedy = "Every TRUNCATE waits for the disk: compare with the fsync check; a slow disk makes every write wait"
		return c
	}
	c.Status, c.Detail = Pass, detail
	return c
}

// publicReport is the part of publictls's report doctor reads.
type publicReport struct {
	Status      string `json:"status"`
	Certificate *struct {
		NotAfter   string `json:"notAfter"`
		RenewAfter string `json:"renewAfter"`
		Issuer     string `json:"issuer"`
	} `json:"certificate"`
	LastError   *string `json:"lastError"`
	Failures    int     `json:"failures"`
	NextAttempt *string `json:"nextAttempt"`
}

func certificate(cfg *config.Config, live *Live) Check {
	host := cfg.PublicHTTPS.Host
	c := Check{ID: "public.certificate", Title: "Public HTTPS certificate", Class: Mandatory}
	if live == nil {
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
		return c
	}
	var p publicReport
	if len(live.Public) == 0 || json.Unmarshal(live.Public, &p) != nil {
		c.Status, c.Detail = Unknown, "varlatchd did not report its certificate"
		return c
	}
	remedy := fmt.Sprintf("Check that %s resolves to this host and that ports 80 and 443 reach varlatchd (listen_https, listen_http_redirect); varlatchd tries again by itself", host)
	var parts []string
	if p.Certificate != nil {
		parts = append(parts, fmt.Sprintf("valid until %s (%s), renewal from %s", p.Certificate.NotAfter, p.Certificate.Issuer, p.Certificate.RenewAfter))
	}
	if p.Failures > 0 {
		s := fmt.Sprintf("%d failed attempts in a row", p.Failures)
		if p.LastError != nil {
			s += ", the last: " + oneLine(*p.LastError)
		}
		if p.NextAttempt != nil {
			s += "; next attempt " + *p.NextAttempt
		}
		parts = append(parts, s)
	}
	switch {
	case p.Status == "expired":
		c.Status = Fail
		parts = append([]string{"the certificate for " + host + " expired: nothing is served over HTTPS"}, parts...)
		c.Remedy = remedy
	case p.Status == "pending" && p.Failures > 0:
		c.Status = Fail
		parts = append([]string{"no certificate for " + host + " yet: nothing is served over HTTPS"}, parts...)
		c.Remedy = remedy
	case p.Status == "pending":
		c.Status = Unknown
		parts = append([]string{"the first certificate for " + host + " is being obtained"}, parts...)
	case p.Status == "renewal-due" && p.Failures > 0:
		c.Status, c.Remedy = Fail, remedy
	default:
		c.Status = Pass
	}
	c.Detail = strings.Join(parts, "; ")
	return c
}

func tailnetPin(live *Live) Check {
	c := Check{ID: "tailnet.pin", Title: "Tailnet pin", Class: Mandatory}
	switch {
	case live == nil:
		c.Status, c.Detail, c.Remedy = Unknown, notRunning, startIt
	case !live.Tailnet:
		c.Status, c.Detail = Unknown, "varlatchd runs no tailnet listener"
	case live.TailnetClosed == closed.TagsDiffer:
		// The node's tags, not its pin: a self-hosted control server's
		// pre-auth key gave it others than tailnet_tags.
		c.Status, c.Detail = Fail, "tailnet access is closed: "+live.TailnetDetail
		c.Remedy = "Give the node exactly tailnet_tags in Headscale (headscale nodes tag -i <node id> -t <tailnet_tags>), or enrol it again with a pre-auth key tagged with them; access reopens at the next check"
	case live.TailnetClosed != "":
		c.Status, c.Detail = Fail, "tailnet access is closed: "+live.TailnetClosed
		c.Remedy = "Run `sudo varlatch tailnet repin` on this host: it shows the pinned and the observed tailnet, and offers what can be re-pinned"
	default:
		c.Status, c.Detail = Pass, "the node is on its pinned tailnet"
	}
	return c
}

// tailnetControl is the coordination server's: Tailscale's, or a
// self-hosted one (tailnet_control_url), whose DERP map should list only
// its own DERP servers (ADR-0059 amendment 11): one listing Tailscale's is
// said, as the operator's to change; nothing closes for it.
func tailnetControl(in Inputs) Check {
	c := Check{ID: "tailnet.control", Title: "Tailnet control server", Class: Advisory}
	t := in.Config.Tailnet
	switch {
	case t.ControlURL == "":
		c.Status, c.Detail = Pass, "Tailscale's coordination server"
	case in.Live == nil:
		c.Status, c.Detail, c.Remedy = Unknown, "a self-hosted control server ("+t.ControlURL+"); "+notRunning, startIt
	case len(in.Live.TailnetWarnings) > 0:
		c.Status, c.Detail = Fail, strings.Join(in.Live.TailnetWarnings, " ")
		c.Remedy = "Set Headscale's derp.urls and derp.paths to your own DERP servers only (its embedded DERP server, or yours), then restart Headscale"
	default:
		c.Status, c.Detail = Pass, "a self-hosted control server ("+t.ControlURL+"), its DERP map naming none of Tailscale's DERP servers"
	}
	return c
}

func backupsStatus(in Inputs) Check {
	cfg := in.Config
	c := Check{ID: "backups.status", Title: "Backups", Class: Advisory}
	remedy := "Set backup_key_file, backup_interval and a destination (backup_destinations_file): `varlatch setup`'s backup step"
	switch {
	case cfg.BackupKeyFile == "":
		c.Status, c.Detail, c.Remedy = Fail, "no backup_key_file: varlatchd makes no scheduled backup, so nothing protects this installation's data", remedy
		return c
	case cfg.BackupInterval == 0:
		c.Status, c.Detail, c.Remedy = Fail, "backup_interval = off: no scheduled backup", remedy
		return c
	}
	// This database's archives only, when a varlatchd says which it is:
	// an earlier one's (a migration rolled back, then made again) neither
	// makes the backups recent nor stands for the newest.
	var life backup.Lifecycle
	if in.Live != nil && in.Live.InstallationID != "" {
		life.InstallationID = in.Live.InstallationID
		if t, err := time.Parse(time.RFC3339Nano, in.Live.DatabaseCreatedAt); err == nil {
			life.Since = t
		}
	}
	st, err := backup.ReadStatusFor(cfg.DataDir, in.Now(), life)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			c.Status, c.Detail, c.Remedy = Unknown, "the backups' status cannot be read by this user", "Run doctor as root: sudo varlatch doctor"
			return c
		}
		c.Status, c.Detail = Unknown, "the backups' status cannot be read: "+oneLine(err.Error())
		return c
	}
	var problems []string
	if cfg.BackupDestinationsFile == "" {
		problems = append(problems, "no destination: archives stay on this host, lost with it")
	}
	problems = append(problems, st.Warnings...)
	if len(problems) > 0 {
		c.Status, c.Detail, c.Remedy = Fail, strings.Join(problems, "; "), "See `varlatchd admin backup status`; "+remedy
		return c
	}
	if n := len(st.Archives); n > 0 {
		newest := st.Archives[0] // newest first
		for _, a := range st.Archives {
			if life.At(in.Now()).Holds(a) {
				newest = a
				break
			}
		}
		c.Status, c.Detail = Pass, fmt.Sprintf("%d archives; the newest %s, %s", n, newest.ArchiveID, newest.CreatedAt)
		return c
	}
	c.Status, c.Detail = Pass, "no archive yet"
	return c
}

func custodyCheck(in Inputs) Check {
	c := Check{ID: "custody.attestations", Title: "Off-host recovery key copies (operator attestation)", Class: Advisory}
	remedy := "Store the Root KEK and the backup key off this host, then record it: `varlatchd admin custody attest --key <root-kek|backup-key> --method <how>`"
	live := in.Live
	switch {
	case live == nil:
		c.Status, c.Detail = Unknown, notRunning
		return c
	case live.Custody == nil:
		c.Status, c.Detail = Unknown, "attestations could not be read"
		if live.CustodyError != "" {
			c.Detail += ": " + oneLine(live.CustodyError)
		}
		return c
	}
	var problems, claims []string
	for _, key := range custody.Keys {
		a := live.Custody.Attestations[key]
		if a == nil {
			if key == "root-kek" {
				problems = append(problems, fmt.Sprintf("no attestation for Root KEK version %d", live.Custody.RootKEKVersion))
			} else {
				problems = append(problems, "no attestation for the backup key")
			}
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, a.At)
		if err == nil && in.Now().Sub(at) > CustodyMaxAge {
			problems = append(problems, fmt.Sprintf("%s attested %d days ago (%s): confirm again", key, int(in.Now().Sub(at).Hours()/24), a.Method))
			continue
		}
		claims = append(claims, fmt.Sprintf("%s attested %s (%s)", key, firstN(a.At, 10), a.Method))
	}
	if len(problems) > 0 {
		c.Status, c.Detail, c.Remedy = Fail, strings.Join(append(problems, claims...), "; "), remedy
		return c
	}
	c.Status, c.Detail = Pass, strings.Join(claims, "; ")
	return c
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// oneLine is s as one line of at most 300 bytes.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		cut := 300
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut-- // never inside a character
		}
		s = s[:cut] + "…"
	}
	return s
}
