// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/custody"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/doctor"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
	"github.com/varlatch/varlatch/go/server/upgraderequests"
	"github.com/varlatch/varlatch/go/server/write"
)

// Upgrading from the web app, phase 1 (ADR-0065): the Release tab's
// pre-flight reads what this varlatchd knows of its host (upgradeHost), and
// an upgrade the host made is recorded as installation.upgraded, from root's
// journal, in the database that serves after it (recordUpgraded). Neither
// gives varlatchd any new power: it reads, and writes an audit event.

// upgradeHost is the pre-flight's view of the host, read at each request:
// how varlatchd runs, the backups and their delivery, the Custody
// Attestations, the data directory's free space, root's upgrade journal in
// configDir, a restore's hold, a maintenance gate and a migration's
// rollback window.
func upgradeHost(env *hostEnv, configDir string) func(ctx context.Context) upgradecheck.Host {
	return func(ctx context.Context) upgradecheck.Host {
		h := upgradecheck.Host{Deployment: upgradecheck.Systemd, Schema: db.SchemaVersion}
		if inImage() {
			h.Deployment = upgradecheck.Image
		}
		installation, _ := (&backend{store: env.store, rootKEK: env.rootKEK}).InstallationID(ctx)
		if env.backups.HasDestination() {
			h.Backups.Destination = env.cfg.BackupDestination
		}
		if st, err := env.backups.Status(); err != nil {
			h.Backups.Err = err
		} else {
			// The newest archive of this installation (an earlier
			// database's are listed too) and its delivery.
			for _, a := range st.Archives {
				at, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
				if err != nil || installation != "" && a.InstallationID != installation || !at.After(h.Backups.Last) {
					continue
				}
				h.Backups.Last, h.Backups.Delivered = at, time.Time{}
				if d := a.Delivery; d != nil {
					if up, err := time.Parse(time.RFC3339Nano, d.UploadedAt); err == nil {
						h.Backups.Delivered = up
					}
				}
			}
		}
		if cs, err := custody.StatusOf(ctx, env.store.Reader()); err != nil {
			h.Custody.Err = err
		} else {
			h.Custody.RootKEKVersion = cs.RootKEKVersion
			h.Custody.RootKEK, h.Custody.BackupKey = cs.Attestations["root-kek"] != nil, cs.Attestations["backup-key"] != nil
		}
		h.Disk.Free, h.Disk.Err = doctor.FreeSpace(env.cfg.DataDir)
		for _, suffix := range []string{"", "-wal"} {
			if info, err := os.Stat(env.cfg.DatabasePath() + suffix); err == nil {
				h.Disk.Database += info.Size()
			}
		}
		h.Upgrade, h.UpgradeErr = readUpgrade(configDir)
		h.RestoreHeld = env.admission.Held()
		if g, err := env.admission.Gate(); err != nil || g != nil {
			h.Maintenance = true
		}
		h.WindowOpen, h.WindowErr = migrationWindowOpen(env.cfg.DataDir, time.Now())
		// The host helper's record of itself (phase 2): display state.
		if rec, err := upgraderequest.ReadHelper(env.cfg.DataDir); err != nil {
			h.Helper.Err = err
		} else if rec != nil {
			h.Helper = upgradecheck.Helper{Present: true, Enabled: rec.Enabled, Version: rec.Version, At: rec.Heartbeat(), Problem: rec.Problem}
		}
		return h
	}
}

// preflightOf is the Release tab's judgement now, as GET
// /v1/installation/release makes it: the upgrade request's route offers
// only what it offers.
func preflightOf(env *hostEnv, configDir string, version string) func(ctx context.Context) upgradecheck.Report {
	host := upgradeHost(env, configDir)
	return func(ctx context.Context) upgradecheck.Report {
		in := upgradecheck.Input{Now: time.Now(), Running: version, Host: host(ctx)}
		if check, err := release.ReadReleaseCheck(env.cfg.DataDir); err == nil {
			in.Check = check
		}
		in.Target, in.TargetErr = release.ReadReleaseTarget(env.cfg.DataDir)
		return upgradecheck.Judge(in)
	}
}

// UpgradedEvent is the audit event of an upgrade the host made (ADR-0065
// Decision 7), recorded by the release it upgraded to.
const UpgradedEvent = "installation.upgraded"

// recordUpgraded records installation.upgraded for root's journal j, once
// per journal id: when it is an upgrade's (not a rollback's), done, to this
// release (version), of this installation. The journal is root's
// (/etc/varlatch/upgrade.json, which varlatchd cannot write), so what it
// says (the releases, the binaries' SHA-256 as the signed SHA256SUMS gave
// them, the snapshot's archive, the times) is root's; there is no actor: an
// upgrade from the terminal is the host's (source host). Whether this
// journal id was recorded is read in the same write job, from the events
// themselves, so a restored database that lacks the event gets it again.
// requestID is the web request whose helper ran this journal (its status
// record names the journal id), "" for an upgrade from the terminal: then
// source is host, else web (phase 2).
func recordUpgraded(ctx context.Context, w *write.Writer, j *upgradejournal.Journal, version, installation, requestID string) (bool, error) {
	if j == nil || j.Kind != upgradejournal.Upgrade || j.State != upgradejournal.Done || j.To != version ||
		installation == "" || j.Installation != "" && j.Installation != installation {
		return false, nil
	}
	recorded := false
	err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.journalId') = ?`, UpgradedEvent, j.ID).Scan(&n); err != nil || n > 0 {
			return err
		}
		var cli, server any
		if b := j.Binaries; b != nil {
			cli, server = b.To.Varlatch, b.To.Varlatchd
		}
		orNil := func(s string) any {
			if s == "" {
				return nil
			}
			return s
		}
		meta := jsvalue.Object{
			{Key: "from", Value: j.From}, {Key: "to", Value: j.To}, {Key: "journalId", Value: j.ID},
			{Key: "varlatchSha256", Value: cli}, {Key: "varlatchdSha256", Value: server}, {Key: "snapshotArchiveId", Value: orNil(j.SnapshotArchive)},
			{Key: "startedAt", Value: orNil(j.StartedAt)}, {Key: "finishedAt", Value: orNil(j.UpdatedAt)},
		}
		meta = append(meta, sourceOf(requestID)...)
		if _, err := audit.Record(ctx, tx, audit.Event{Type: UpgradedEvent, Decision: audit.Info, Metadata: meta}); err != nil {
			return err
		}
		recorded = true
		return nil
	})
	return recorded, err
}

// sourceOf is an event's source and request: web and its id, or host.
func sourceOf(requestID string) jsvalue.Object {
	if requestID == "" {
		return jsvalue.Object{{Key: "source", Value: "host"}, {Key: "requestId", Value: nil}}
	}
	return jsvalue.Object{{Key: "source", Value: "web"}, {Key: "requestId", Value: requestID}}
}

// recordUndone records installation.upgrade_undone for root's journal j,
// once per journal id (ADR-0065 Decision 7): an upgrade's, undone after
// it stopped varlatchd (a check failed, or a step after the stop), from
// this release (version), which serves again, of this installation. The
// reason is the journal's (the failing check), root's. An upgrade undone
// before the stop (its snapshot or upload failed) never restarted
// anything and records none.
func recordUndone(ctx context.Context, w *write.Writer, j *upgradejournal.Journal, version, installation, requestID string) (bool, error) {
	if j == nil || j.Kind != upgradejournal.Upgrade || j.State != upgradejournal.Undone || j.From != version || !j.Reached(upgradejournal.Stopping) ||
		installation == "" || j.Installation != "" && j.Installation != installation {
		return false, nil
	}
	recorded := false
	err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.journalId') = ?`, upgraderequests.UndoneEvent, j.ID).Scan(&n); err != nil || n > 0 {
			return err
		}
		meta := jsvalue.Object{{Key: "from", Value: j.From}, {Key: "to", Value: j.To}, {Key: "journalId", Value: j.ID}, {Key: "reason", Value: j.Reason}}
		meta = append(meta, sourceOf(requestID)...)
		if _, err := audit.Record(ctx, tx, audit.Event{Type: upgraderequests.UndoneEvent, Decision: audit.Info, Metadata: meta}); err != nil {
			return err
		}
		recorded = true
		return nil
	})
	return recorded, err
}

// noteJournal records what root's journal j says ended (installation.
// upgraded on the release upgraded to, installation.upgrade_undone on the
// one it went back to), with the web request whose helper ran it, logged: a
// failure to record leaves the event to the next start.
func noteJournal(ctx context.Context, w *write.Writer, j *upgradejournal.Journal, dataDir, version, installation string, log *slog.Logger) {
	if j == nil {
		return
	}
	request := upgraderequests.RequestOf(dataDir, j.ID)
	for _, e := range []struct {
		event  string
		record func(context.Context, *write.Writer, *upgradejournal.Journal, string, string, string) (bool, error)
	}{{UpgradedEvent, recordUpgraded}, {upgraderequests.UndoneEvent, recordUndone}} {
		recorded, err := e.record(ctx, w, j, version, installation, request)
		switch {
		case err != nil:
			log.Warn("the upgrade could not be recorded in the audit log; the next start records it", "event", e.event, "journal", j.ID, "error", err)
		case recorded:
			log.Info("recorded the upgrade in the audit log", "event", e.event, "from", j.From, "to", j.To, "journal", j.ID)
		}
	}
}

// noteUpgraded is noteJournal for the journal in configDir as it is now.
func noteUpgraded(ctx context.Context, w *write.Writer, configDir, dataDir, version, installation string, log *slog.Logger) {
	j, err := readUpgrade(configDir)
	if err != nil {
		return
	}
	noteJournal(ctx, w, j, dataDir, version, installation, log)
}
