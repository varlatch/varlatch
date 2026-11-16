// SPDX-License-Identifier: AGPL-3.0-or-later

// Package backups takes the installation's backups inside varlatchd
// (ADR-0059 Decision 7, step 4.14): on a schedule, and on demand through
// the control socket (`varlatchd admin backup run`).
//
// One run:
//
//  1. checks that no maintenance gate is open, that the Backup Encryption
//     Key is configured and is not the Root KEK, and that the data
//     directory has room for the run's temporary files (RequiredSpace);
//  2. snapshots the database on the writer's connection, paced, followed by
//     a TRUNCATE checkpoint (lib/storage Snapshot);
//  3. reads the archive's metadata from the snapshot itself, so it
//     describes exactly what was copied: the installation, its Root KEK
//     version and canary, and the schema version. It refuses a snapshot
//     taken during an incomplete Root KEK rotation, and one whose canary
//     the loaded Root KEK does not open;
//  4. seals the snapshot and the non-key configuration into a format-3
//     archive, paced (SealRate), as backups/<archive id>.vltbak;
//  5. opens it again and records the verification (integrity,
//     compatibility with this release, the Root KEK match) in
//     backups/<archive id>.json, the TypeScript server's status record;
//  6. uploads it to the configured destination, when there is one, and
//     records the delivery;
//  7. keeps the newest backup_keep archives in the data directory and
//     removes older ones; their status records stay, as the TypeScript
//     host backup keeps them, since a delivered archive still exists in
//     the bucket and its Root KEK version must be kept.
//
// The run's temporary files are in backups/.work-<archive id>, removed
// when it ends; one left by a run that was killed is removed by the next.
package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/maintenance"
)

// Dir is the backups' directory in the data directory.
const Dir = "backups"

// DefaultSealRate is how fast sealing reads the snapshot: 32 MiB/s, so a
// backup never takes the disk from the requests.
const DefaultSealRate = 32 << 20

// APIMajor is the /v1 API's major version, recorded in an archive.
const APIMajor = 1

// Options configure a Service.
type Options struct {
	Config    *config.Config
	Store     *storage.DB
	RootKEK   []byte
	Admission *maintenance.Admission
	Log       *slog.Logger
	// Now is the clock (time.Now).
	Now func() time.Time
	// SealRate is sealing's pace in bytes per second: 0 is
	// DefaultSealRate, below 0 unpaced (tests).
	SealRate int64
	// Snapshot paces the snapshot (zero: lib/storage's defaults).
	Snapshot storage.SnapshotOptions
	// HTTPClient uploads (nil: lib/backup's default).
	HTTPClient *http.Client
	// FreeSpace reports the bytes available under a directory (nil: the
	// file system's; tests).
	FreeSpace func(dir string) (int64, error)
	// StartDelay is how long the schedule waits after varlatchd starts
	// before its first look (DefaultStartDelay).
	StartDelay time.Duration
	// After arms the schedule's timer (nil: a time.Timer; tests).
	After func(time.Duration) <-chan time.Time
}

// The schedule's waits.
const (
	// DefaultStartDelay lets varlatchd settle before a backup that is due.
	DefaultStartDelay = time.Minute
	// RetryAfter is the wait after a run that made no archive.
	RetryAfter = time.Hour
	// MaintenanceRetry is the wait while a maintenance gate is open.
	MaintenanceRetry = time.Minute
	// Recheck bounds every wait: the schedule looks at the clock again at
	// least this often, so a clock moved forward is noticed within it.
	Recheck = time.Hour
	// clockSkew is how far in the future the newest archive may be dated
	// before the schedule takes the clock to have moved back.
	clockSkew = time.Minute
)

// Service runs backups, one at a time.
type Service struct {
	o   Options
	dir string
	// running is held for a whole run; a second run is refused.
	running sync.Mutex
}

// New makes the service for the data directory in o.Config.
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.SealRate == 0 {
		o.SealRate = DefaultSealRate
	}
	if o.FreeSpace == nil {
		o.FreeSpace = freeSpace
	}
	if o.StartDelay == 0 {
		o.StartDelay = DefaultStartDelay
	}
	return &Service{o: o, dir: o.Config.DataDir}
}

// Status is the backup status (backupStatus): the archives' records,
// newest first, and the warnings.
func (s *Service) Status() (backup.Status, error) {
	return backup.ReadStatus(s.dir, s.o.Now())
}

// StatusJSON is Status as JSON, for getInstallationBackups.
func (s *Service) StatusJSON() ([]byte, error) {
	st, err := s.Status()
	if err != nil {
		return nil, err
	}
	return json.Marshal(st)
}

// Result is what a run did.
type Result struct {
	ArchiveID    string               `json:"archiveId"`
	Path         string               `json:"path"`
	Bytes        int64                `json:"bytes"`
	CreatedAt    string               `json:"createdAt"`
	Verification *backup.Verification `json:"verification"`
	Capture      backup.CaptureStats  `json:"capture"`
	// Delivery is the upload, nil when no destination is configured or
	// the upload failed (UploadError then says why).
	Delivery    *backup.Delivery `json:"delivery,omitempty"`
	UploadError string           `json:"uploadError,omitempty"`
	// Removed are the archives local retention removed.
	Removed []string `json:"removed"`
	// Snapshot is the snapshot's own account (the g9a build reports it).
	Snapshot storage.SnapshotStats `json:"-"`
}

// Errors a run refuses with before it writes anything.
var (
	ErrRunning     = errors.New("Another backup is running")
	ErrMaintenance = errors.New("Installation maintenance is active; no backup was taken")
	ErrNoKey       = errors.New("No Backup Encryption Key is configured (backup_key_file); no backup was taken")
	ErrRotation    = errors.New("Root KEK rotation is incomplete")
	ErrRewraps     = errors.New("Key rotation has unverified rewraps outstanding")
	ErrCanary      = errors.New("The loaded Root KEK does not open the snapshot's canary")
)

// SpaceError is a data directory without room for a run.
type SpaceError struct {
	Need, Available int64
}

func (e *SpaceError) Error() string {
	return fmt.Sprintf("The data directory has %s free and a backup needs %s (the snapshot, the archive and its check); no backup was taken", size(e.Available), size(e.Need))
}

func size(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// spaceMargin is the room a run leaves beyond its temporary files.
const spaceMargin = 64 << 20

// RequiredSpace is the free space a run needs beside a database of
// dbBytes (the file and its WAL): the snapshot, a temporary file the size
// of the database, then the archive and, while it is checked, its
// unpacked copy, plus a margin. Setup and doctor (step 6) count it too.
func RequiredSpace(dbBytes int64) int64 { return 3*dbBytes + spaceMargin }

// Run takes one backup now.
func (s *Service) Run(ctx context.Context) (Result, error) {
	if !s.running.TryLock() {
		return Result{}, ErrRunning
	}
	defer s.running.Unlock()
	// Admitted for the whole run, as a request is: a gate that opens
	// meanwhile sees it in Busy until it ends.
	if s.o.Admission != nil {
		leave, ok := s.o.Admission.Enter()
		if !ok {
			return Result{}, ErrMaintenance
		}
		defer leave()
	}
	cfg := s.o.Config
	bek, err := s.bek()
	if err != nil {
		return Result{}, err
	}
	defer bek.Clear()

	backups := filepath.Join(s.dir, Dir)
	if err := os.MkdirAll(backups, 0o700); err != nil {
		return Result{}, err
	}
	s.clean(backups)
	if err := s.checkSpace(backups); err != nil {
		return Result{}, err
	}

	id := ids.UUID()
	work := filepath.Join(backups, ".work-"+id)
	if err := os.Mkdir(work, 0o700); err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(work)

	// The snapshot, then its metadata, read from the copy itself.
	snapshot := filepath.Join(work, backup.ComponentDatabase)
	st, err := s.o.Store.Snapshot(ctx, snapshot, s.o.Snapshot)
	if err != nil {
		return Result{}, fmt.Errorf("the snapshot failed: %w", err)
	}
	createdAt := iso(s.o.Now())
	meta, err := readMetadata(ctx, snapshot)
	if err != nil {
		return Result{}, err
	}
	if !envelope.VerifyCanary(s.o.RootKEK, meta.canary, meta.installationID) {
		return Result{}, ErrCanary
	}
	configuration := filepath.Join(work, backup.ComponentConfiguration)
	if err := writeConfiguration(configuration, cfg); err != nil {
		return Result{}, err
	}
	manifest, err := s.manifest(id, createdAt, meta, snapshot, configuration)
	if err != nil {
		return Result{}, err
	}

	// Paced sealing.
	archive := filepath.Join(backups, id+".vltbak")
	sealStart := time.Now()
	if err := backup.Seal(archive, manifest, []string{snapshot, configuration}, bek, backup.SealOptions{Pace: s.pace(ctx, sealStart)}); err != nil {
		var linked *backup.LinkedError
		if !errors.As(err, &linked) {
			return Result{}, fmt.Errorf("sealing the archive failed: %w", err)
		}
		s.o.Log.Warn("backup: the archive was written but its directory could not be synced", "archiveId", id, "error", err)
	}
	snapInfo, err := os.Stat(snapshot)
	if err != nil {
		return Result{}, err
	}
	stats := backup.CaptureStats{
		Mode:           "online",
		SnapshotHeldMs: st.Duration.Milliseconds(),
		DumpMs:         time.Since(sealStart).Milliseconds(),
		DumpBytes:      snapInfo.Size(),
	}
	// The snapshot is not needed any more: free its room before the check.
	_ = os.Remove(snapshot)

	verification := s.verify(archive, bek, work)
	record := backup.StatusRecord{
		ArchiveID: id, InstallationID: meta.installationID, CreatedAt: createdAt, Release: buildinfo.Version,
		RequiredKeyVersions: []int{meta.keyVersion}, Verification: &verification, Capture: &stats,
	}
	if err := backup.SaveStatus(s.dir, record); err != nil {
		return Result{}, fmt.Errorf("the archive %s was written, but its status could not be recorded: %w", id, err)
	}
	info, err := os.Stat(archive)
	if err != nil {
		return Result{}, err
	}
	res := Result{ArchiveID: id, Path: archive, Bytes: info.Size(), CreatedAt: createdAt, Verification: &verification, Capture: stats, Removed: []string{}, Snapshot: st}
	if !verification.Integrity || !verification.Compatibility || !verification.KeyMatch {
		return res, fmt.Errorf("the archive %s failed its check (integrity %t, compatibility %t, Root KEK match %t)", id, verification.Integrity, verification.Compatibility, verification.KeyMatch)
	}

	if cfg.BackupDestinationsFile != "" {
		delivery, err := s.upload(ctx, id, archive)
		if err != nil {
			res.UploadError = err.Error()
		} else {
			record.Delivery = delivery
			if err := backup.SaveStatus(s.dir, record); err != nil {
				return res, fmt.Errorf("the archive %s was uploaded, but its delivery could not be recorded: %w", id, err)
			}
			res.Delivery = delivery
		}
	}
	res.Removed = s.retain(backups)
	if res.UploadError != "" {
		return res, errors.New(res.UploadError)
	}
	return res, nil
}

// bek reads the Backup Encryption Key, which must not be the Root KEK.
func (s *Service) bek() (backup.BEK, error) {
	if s.o.Config.BackupKeyFile == "" {
		return backup.BEK{}, ErrNoKey
	}
	raw, err := os.ReadFile(s.o.Config.BackupKeyFile)
	if err != nil {
		return backup.BEK{}, fmt.Errorf("cannot read the Backup Encryption Key file: %w", err)
	}
	material, err := backup.ParseKey(string(raw))
	clear(raw)
	if err != nil {
		return backup.BEK{}, err
	}
	bek, err := backup.KeyBEK(material)
	clear(material)
	if err != nil {
		return backup.BEK{}, err
	}
	if err := backup.DistinctKeys(bek, s.o.RootKEK); err != nil {
		bek.Clear()
		return backup.BEK{}, err
	}
	return bek, nil
}

// clean removes what a killed run left: its work directory and a partial
// archive. Nothing else in the directory is touched.
func (s *Service) clean(backups string) {
	entries, _ := os.ReadDir(backups)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".work-") || strings.HasSuffix(name, ".partial") && strings.Contains(name, ".vltbak.") {
			if err := os.RemoveAll(filepath.Join(backups, name)); err != nil {
				s.o.Log.Warn("backup: cannot remove a killed run's file", "file", name, "error", err)
			}
		}
	}
}

func (s *Service) checkSpace(backups string) error {
	var dbBytes int64
	for _, suffix := range []string{"", "-wal"} {
		if st, err := os.Stat(s.o.Config.DatabasePath() + suffix); err == nil {
			dbBytes += st.Size()
		}
	}
	avail, err := s.o.FreeSpace(backups)
	if err != nil {
		return fmt.Errorf("cannot read the data directory's free space: %w", err)
	}
	if need := RequiredSpace(dbBytes); avail < need {
		return &SpaceError{Need: need, Available: avail}
	}
	return nil
}

// pace keeps sealing at SealRate, and ends it when ctx ends.
func (s *Service) pace(ctx context.Context, start time.Time) func(int64) error {
	return func(sealed int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.o.SealRate < 0 {
			return nil
		}
		due := start.Add(time.Duration(float64(sealed) / float64(s.o.SealRate) * float64(time.Second)))
		if wait := time.Until(due); wait > 0 {
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
		return nil
	}
}

// metadata is what the snapshot says about itself.
type metadata struct {
	installationID string
	canary         envelope.Envelope
	keyVersion     int
	schemaVersion  int
}

// readMetadata reads the snapshot (read-only): the installation, its Root
// KEK version and canary, refusing an incomplete rotation as
// archiveMetadata does, and the schema version.
func readMetadata(ctx context.Context, path string) (metadata, error) {
	var m metadata
	conn, err := sql.Open("sqlite", fileURI(path)+"?mode=ro&immutable=1")
	if err != nil {
		return m, err
	}
	defer conn.Close()
	var canary, state string
	if err := conn.QueryRowContext(ctx, "SELECT id, kek_canary, root_kek_version, key_rotation_state FROM installation").Scan(&m.installationID, &canary, &m.keyVersion, &state); err != nil {
		return m, fmt.Errorf("the snapshot has no installation: %w", err)
	}
	if state != "idle" {
		return m, ErrRotation
	}
	var outstanding int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM organizations WHERE root_kek_version <> ? OR key_rotation_state <> 'idle'", m.keyVersion).Scan(&outstanding); err != nil {
		return m, err
	}
	if outstanding > 0 {
		return m, ErrRewraps
	}
	if err := json.Unmarshal([]byte(canary), &m.canary); err != nil {
		return m, fmt.Errorf("the snapshot's canary is not an envelope: %w", err)
	}
	if err := conn.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&m.schemaVersion); err != nil {
		return m, fmt.Errorf("the snapshot has no schema version: %w", err)
	}
	return m, nil
}

// Configuration is an archive's configuration.json: the installation's
// non-key settings, as varlatchd.conf names them. Paths on this host (the
// data directory, the key files, the destinations file) are left out: a
// restore names its own.
type Configuration struct {
	FormatVersion int               `json:"formatVersion"`
	Settings      map[string]string `json:"settings"`
}

func writeConfiguration(path string, cfg *config.Config) error {
	settings := map[string]string{
		"listen":     cfg.Listen,
		"access_log": cfg.AccessLog,
		"sync":       map[bool]string{true: "on", false: "off"}[cfg.Sync],
		"backup_interval": func() string {
			if cfg.BackupInterval == 0 {
				return "off"
			}
			return cfg.BackupInterval.String()
		}(),
		"backup_keep":        fmt.Sprint(cfg.BackupKeep),
		"backup_destination": cfg.BackupDestination,
	}
	if cfg.PublicURL != nil {
		settings["public_url"] = cfg.PublicURL.String()
	}
	if cfg.TrustedProxies != "" {
		settings["trusted_proxies"] = cfg.TrustedProxies
	}
	if cfg.SyncAdapters != nil {
		settings["sync_adapters"] = strings.Join(cfg.SyncAdapters, ",")
	}
	b, err := json.Marshal(Configuration{FormatVersion: 1, Settings: settings})
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) manifest(id, createdAt string, meta metadata, snapshot, configuration string) ([]byte, error) {
	release, err := json.Marshal(backup.GoRelease{Version: buildinfo.Version, APIMajor: APIMajor, DatabaseSchema: meta.schemaVersion})
	if err != nil {
		return nil, err
	}
	var components []backup.Component
	for _, c := range []struct{ name, path string }{{backup.ComponentDatabase, snapshot}, {backup.ComponentConfiguration, configuration}} {
		d, err := backup.Describe(c.name, c.path)
		if err != nil {
			return nil, err
		}
		components = append(components, d)
	}
	return json.Marshal(backup.Manifest{
		FormatVersion: backup.FormatGo, ArchiveID: id, InstallationID: meta.installationID, CreatedAt: createdAt,
		Release: release, RequiredKeyVersions: []int{meta.keyVersion},
		Canaries: []backup.Canary{backup.CanaryOf(meta.keyVersion, meta.canary)}, Components: components,
	})
}

// Compatible is whether this release restores an archive: a Go archive
// of this API major whose schema this release opens. The TypeScript
// server's archives are converted by step 7, not restored.
func Compatible(m backup.Manifest) bool {
	r, err := m.GoRelease()
	return err == nil && r.APIMajor == APIMajor && r.DatabaseSchema == db.SchemaVersion
}

// verify opens the archive again (its integrity), and checks this release
// restores it and the Root KEK opens its canaries.
func (s *Service) verify(archive string, bek backup.BEK, scratch string) backup.Verification {
	v := backup.Verification{TargetRelease: buildinfo.Version}
	o, err := backup.Open(archive, bek, scratch)
	if err != nil {
		s.o.Log.Warn("backup: the archive does not open", "archive", archive, "error", err)
	} else {
		v.Integrity = true
		v.Compatibility = Compatible(o.Manifest)
		candidates := map[int][]byte{}
		for _, version := range o.Manifest.RequiredKeyVersions {
			candidates[version] = s.o.RootKEK
		}
		v.KeyMatch = backup.CheckKeys(o.Manifest, candidates)
		_ = o.Close()
	}
	v.CheckedAt = iso(s.o.Now())
	return v
}

// client is the configured destination's client, with its write key.
func (s *Service) client() (*backup.Client, backup.Destination, error) {
	cfg := s.o.Config
	d, err := backup.ReadDestination(cfg.BackupDestinationsFile, cfg.BackupDestination)
	if err != nil {
		return nil, d, err
	}
	credentials := d.WriteCredentialsFile
	if !filepath.IsAbs(credentials) {
		credentials = filepath.Join(filepath.Dir(cfg.BackupDestinationsFile), credentials)
	}
	c, err := backup.ReadCredentials(credentials)
	if err != nil {
		return nil, d, err
	}
	return backup.NewClient(d, c, s.o.HTTPClient), d, nil
}

func (s *Service) upload(ctx context.Context, id, archive string) (*backup.Delivery, error) {
	cfg := s.o.Config
	client, d, err := s.client()
	if err != nil {
		return nil, fmt.Errorf("Destination upload failed: %w; local archive remains available", err)
	}
	key, err := backup.ObjectKey(d, id)
	if err != nil {
		return nil, err
	}
	if err := client.Upload(ctx, key, archive); err != nil {
		return nil, err
	}
	return &backup.Delivery{Destination: cfg.BackupDestination, UploadedAt: iso(s.o.Now())}, nil
}

// retain keeps the newest backup_keep archives (by their status record's
// creation time, else the file's), and removes the others' files.
func (s *Service) retain(backups string) []string {
	type local struct {
		id string
		at time.Time
	}
	var archives []local
	entries, _ := os.ReadDir(backups)
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".vltbak")
		if !ok || !e.Type().IsRegular() || len(id) != 36 {
			continue
		}
		at := time.Time{}
		if info, err := e.Info(); err == nil {
			at = info.ModTime()
		}
		if raw, err := os.ReadFile(filepath.Join(backups, id+".json")); err == nil {
			var r struct {
				CreatedAt string `json:"createdAt"`
			}
			if json.Unmarshal(raw, &r) == nil {
				if t, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err == nil {
					at = t
				}
			}
		}
		archives = append(archives, local{id, at})
	}
	slices.SortStableFunc(archives, func(a, b local) int { return b.at.Compare(a.at) })
	removed := []string{}
	for _, a := range archives[min(len(archives), s.o.Config.BackupKeep):] {
		if err := os.Remove(filepath.Join(backups, a.id+".vltbak")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.o.Log.Warn("backup: cannot remove an archive beyond backup_keep", "archiveId", a.id, "error", err)
			continue
		}
		removed = append(removed, a.id)
	}
	return removed
}

// fileURI is path as an SQLite file: URI.
func fileURI(path string) string {
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '%', '?', '#':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Loop runs the scheduled backups until ctx ends: one when the newest
// archive is backup_interval old (at once when there is none), an hour
// after a run that made no archive, and a minute after a maintenance gate
// held one back. It goes by the archives' age, not a calendar time (the
// TypeScript host backup's systemd timer runs at 03:30 UTC), and looks at
// the wall clock again at least every Recheck: a clock moved forward is
// noticed within an hour, and after a clock moved back the newest archive
// not dated in the future decides (with none recent, a backup at once). With backup_interval off or no
// backup_key_file, it does nothing.
func (s *Service) Loop(ctx context.Context) {
	cfg := s.o.Config
	if cfg.BackupInterval == 0 {
		s.o.Log.Info("scheduled backups are off (backup_interval)")
		return
	}
	if cfg.BackupKeyFile == "" {
		s.o.Log.Info("scheduled backups are off: no backup_key_file is configured")
		return
	}
	wait := s.o.StartDelay
	for {
		if s.o.After != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.o.After(wait):
			}
		} else {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		wait = min(s.tick(ctx), Recheck)
	}
}

// tick takes a backup if one is due, and says how long to wait for the
// next look.
func (s *Service) tick(ctx context.Context) time.Duration {
	interval := s.o.Config.BackupInterval
	now := s.o.Now()
	if st, err := s.Status(); err != nil {
		s.o.Log.Warn("backup: the status records cannot be read; taking a backup", "error", err)
	} else {
		// The newest archive not dated in the future decides. One from the
		// future means the clock moved back: its age says nothing, so with
		// no other recent archive a backup is taken now, not once the clock
		// has caught up with it.
		for _, a := range st.Archives {
			created, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
			if err != nil {
				continue
			}
			if created.After(now.Add(clockSkew)) {
				continue
			}
			if due := created.Add(interval); now.Before(due) {
				return due.Sub(now)
			}
			break
		}
	}
	res, err := s.Run(ctx)
	switch {
	case err == nil:
		s.o.Log.Info("backup created", "archiveId", res.ArchiveID, "bytes", res.Bytes, "delivered", res.Delivery != nil, "removed", len(res.Removed))
		return interval
	case ctx.Err() != nil:
		return 0
	case errors.Is(err, ErrMaintenance) || errors.Is(err, ErrRunning):
		return MaintenanceRetry
	case res.ArchiveID != "":
		// The archive exists; its check or upload failed. The status
		// warnings say so; the next run is at the interval.
		s.o.Log.Error("backup: the archive was made, but a later step failed", "archiveId", res.ArchiveID, "error", err)
		return interval
	default:
		s.o.Log.Error("backup failed; retrying in an hour", "error", err)
		return min(RetryAfter, interval)
	}
}

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
