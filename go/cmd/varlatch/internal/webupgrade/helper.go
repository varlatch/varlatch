// SPDX-License-Identifier: Apache-2.0

// Package webupgrade is the host helper of an upgrade the web app asks for
// (ADR-0065): `varlatch upgrade --from-request`, which a root path unit runs
// when varlatchd has written a request, and `--enable-web` / `--disable-web`,
// which install and remove that unit, its service, the boot recovery and the
// daily release check.
//
// The web app asks; the host acts. varlatchd can only write a request that
// names a version. The helper takes it, treats its bytes as untrusted,
// finds the latest release itself, verifies it from scratch, judges it with
// the same rules as `sudo varlatch upgrade <version> --yes` and refuses
// what that would not do without an override flag, then runs the same
// engine (cmd/varlatch/internal/upgrade), with its snapshot checked off the
// host first. What it did goes back to the dashboard as status records,
// written through varlatchd as the data directory's owner.
package webupgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/selfupdate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/upgrade"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/release"
	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// TakenDir is where the helper takes requests to: root's alone (0700), on
// the file system of varlatchd's state directory. Its parent is root's too.
const TakenDir = "/var/lib/varlatch-upgrade/taken"

// ErrNoRequest is a run that found no request: it was cancelled, or taken.
var ErrNoRequest = errors.New("there is no upgrade request")

// ErrInvalid is a taken file that is not a request.
var ErrInvalid = errors.New("the taken file is not an upgrade request")

// ErrNotTaken is a run that could not take the request, which stays in
// request.json: the path unit runs the helper again.
var ErrNotTaken = errors.New("the upgrade request could not be taken")

// RetryDelay is how long a run that could not take a request waits, its
// lock released, before it fails. The request stays, so the path unit
// starts the service again at once: waiting keeps that to one run a
// minute, far under the start limit of the service's unit, until the
// cause is put right (then the next run takes it) or varlatchd removes the
// request at its expiry (then the path unit stops). Without the wait the
// runs would follow each other until systemd's start limit failed the
// units for good.
const RetryDelay = time.Minute

// noDestination is how varlatchd refuses --verify-remote without a backup
// destination (server/backups ErrNoDestination).
const noDestination = "No backup destination is configured"

// Helper takes and acts on one request. Every field but NoticeWait and Log
// is required; the CLI sets them to the engine's and the host's, the tests
// to their own.
type Helper struct {
	// ConfigDir is varlatchd.conf's directory: the journal and
	// web-upgrade.conf are there.
	ConfigDir string
	// TakenDir is TakenDir but in the tests, owned by TakenOwner (root).
	TakenDir   string
	TakenOwner uint32
	Now        func() time.Time
	// DataDir is the data directory varlatchd's configuration names.
	DataDir func(ctx context.Context) (string, error)
	// Inspect is the installed release (upgrade.Upgrader.Inspect).
	Inspect func(ctx context.Context) (upgrade.Installed, error)
	// Newest is the newest release that is not a prerelease, asked of
	// GitHub now (selfupdate.Newest).
	Newest func(ctx context.Context) (string, error)
	// Fetch downloads and verifies a release (upgrade.Fetch).
	Fetch func(ctx context.Context, version string) (upgrade.Release, error)
	// WindowEnds is whether upgrading to version, whose manifest ends a
	// migration's rollback window when ends, would end an open one.
	WindowEnds func(dataDir, version string, ends bool) (bool, error)
	// Run runs the engine, its snapshot verified off the host, telling
	// onStep each step it records.
	Run func(ctx context.Context, inst upgrade.Installed, rel upgrade.Release, onStep func(*journal.Journal, journal.Step)) (*journal.Journal, error)
	// Record writes a status record: `varlatchd admin upgrade-request
	// record` with these arguments.
	Record func(ctx context.Context, args ...string) error
	// NoticeWait is how long the helper waits, before the stop, once it has
	// recorded that varlatchd restarts: the dashboards' notice goes out.
	NoticeWait time.Duration
	Log        func(line string)
	// Version is the helper's release, for the heartbeat that records a
	// problem.
	Version string
	// Lock, when set, takes the helper's run lock, waiting for it, until
	// the function it returns: --enable-web and --disable-web hold it while
	// they change the host, so no run takes a request meanwhile, and
	// --disable-web refuses while a run holds it.
	Lock func(ctx context.Context) (unlock func(), err error)
	// RetryDelay is RetryDelay but in the tests.
	RetryDelay time.Duration
}

// Outcome is what a run did with a request.
type Outcome struct {
	Request   upgraderequest.Request
	Phase     upgraderequest.Phase
	Reason    string
	JournalID string
}

func (h *Helper) logf(format string, a ...any) {
	if h.Log != nil {
		h.Log(fmt.Sprintf(format, a...))
	}
}

// FromRequest takes the pending request and acts on it. ErrNoRequest when
// there is none. ErrNotTaken when it could not take it: the request stays,
// the helper's heartbeat says why (where varlatchd can still write it), and
// the run fails after RetryDelay. Any other error is one it could not
// record: the request is taken, and the dashboard says the host did not
// answer.
func (h *Helper) FromRequest(ctx context.Context) (Outcome, error) {
	unlock := func() {}
	if h.Lock != nil {
		u, err := h.Lock(ctx)
		if err != nil {
			return Outcome{}, h.notTaken(ctx, unlock, "take", fmt.Errorf("the helper's lock: %w", err))
		}
		unlock = sync.OnceFunc(u)
	}
	defer func() { unlock() }()
	dataDir, err := h.DataDir(ctx)
	if err != nil {
		return Outcome{}, h.notTaken(ctx, unlock, "data-directory", fmt.Errorf("the data directory: %w", err))
	}
	raw, taken, err := take(dataDir, h.TakenDir, h.TakenOwner)
	if err != nil && taken == "" && !errors.Is(err, ErrNoRequest) {
		// Before the take's rename: request.json is where it was.
		return Outcome{}, h.notTaken(ctx, unlock, "take", err)
	}
	if err != nil {
		return Outcome{}, err
	}
	req, err := upgraderequest.ParseRequest(raw)
	if err != nil {
		// No id to record it under: the file stays in the taken directory.
		return Outcome{}, fmt.Errorf("%w (%v): kept as %s", ErrInvalid, err, taken)
	}
	// For the record: the request's own name, now that it has one.
	if named := filepath.Join(h.TakenDir, req.ID+".json"); os.Rename(taken, named) == nil {
		taken = named
	}
	h.logf("Took the upgrade request %s for %s (%s).", req.ID, req.Version, taken)
	o := Outcome{Request: req}
	record := func(p upgraderequest.Phase, reason, journalID string) error {
		o.Phase, o.Reason, o.JournalID = p, reason, journalID
		args := []string{"record", "--request", req.ID, "--version", req.Version, "--phase", string(p)}
		if reason != "" {
			args = append(args, "--reason", reason)
		}
		if journalID != "" {
			args = append(args, "--journal", journalID)
		}
		return h.Record(ctx, args...)
	}
	refuse := func(reason string) (Outcome, error) {
		h.logf("Refused the upgrade request %s for %s: %s.", req.ID, req.Version, reason)
		return o, record(upgraderequest.Refused, reason, "")
	}
	if !req.Current(h.Now()) {
		// Expired, or dated ahead of this host's clock, which varlatchd
		// shares: the lifetime bounds it either way.
		return refuse("expired")
	}
	if accept, err := upgraderequest.Accepting(h.ConfigDir); err != nil || !accept {
		return refuse("disabled")
	}
	if err := record(upgraderequest.Taken, "", ""); err != nil {
		return o, err
	}
	reason, inst, err := h.refusal(ctx, req, dataDir)
	if err != nil {
		h.logf("The upgrade request %s could not be judged: %v.", req.ID, err)
		return o, errors.Join(err, record(upgraderequest.Failed, "error", ""))
	}
	if reason != "" {
		return refuse(reason)
	}
	if err := record(upgraderequest.Verifying, "", ""); err != nil {
		return o, err
	}
	rel, reason, err := h.verified(ctx, req.Version, inst, dataDir)
	switch {
	case err != nil:
		h.logf("The upgrade request %s: %s did not verify: %v.", req.ID, req.Version, err)
		return o, errors.Join(err, record(upgraderequest.Failed, "verification", ""))
	case reason != "":
		return refuse(reason)
	}
	var recordErr error
	onStep := func(j *journal.Journal, s journal.Step) {
		var err error
		switch s {
		case journal.Verified:
			err = record(upgraderequest.BackingUp, "", j.ID)
		case journal.Snapshot:
			// Before the stop: every dashboard is told, then it stops.
			err = record(upgraderequest.Restart, "", j.ID)
			if err == nil && h.NoticeWait > 0 {
				time.Sleep(h.NoticeWait)
			}
		case journal.Started:
			err = record(upgraderequest.Checking, "", j.ID)
		}
		recordErr = errors.Join(recordErr, err)
	}
	h.logf("Upgrading %s to %s for the request %s.", inst.Version, req.Version, req.ID)
	j, err := h.Run(ctx, inst, rel, onStep)
	id := ""
	if j != nil {
		id = j.ID
	}
	switch {
	case err == nil:
		return o, errors.Join(recordErr, record(upgraderequest.Done, "", id))
	case j != nil && j.State == journal.Undone && j.Reached(journal.Stopping):
		return o, errors.Join(err, record(upgraderequest.Undone, "health", id))
	case j != nil && j.State == journal.Failed:
		return o, errors.Join(err, record(upgraderequest.Failed, "undo", id))
	case strings.Contains(err.Error(), noDestination):
		return o, record(upgraderequest.Refused, "no-backup-destination", id)
	case j != nil && !j.Reached(journal.Snapshot):
		return o, errors.Join(err, record(upgraderequest.Failed, "backup", id))
	}
	return o, errors.Join(err, record(upgraderequest.Failed, "error", id))
}

// notTaken is a run that could not take the request (problem, one of
// upgraderequest.HelperProblems, for cause): logged, recorded in the
// helper's heartbeat so that the dashboard's helper line says so, the lock
// released, and RetryDelay waited before the run fails. The heartbeat is
// written through varlatchd as any record is; when even that fails (the
// upgrade-request directory itself is not one), the journal of the
// service's unit says why, and `varlatch doctor` that the unit failed.
func (h *Helper) notTaken(ctx context.Context, unlock func(), problem string, cause error) error {
	h.logf("The upgrade request could not be taken (%s): %v. It stays in place; the helper tries again in %s, until varlatchd removes it at its expiry.", problem, cause, h.RetryDelay)
	var said error
	if h.Version != "" {
		accept, _ := upgraderequest.Accepting(h.ConfigDir)
		if err := h.Record(ctx, "heartbeat", "--helper-version", h.Version, "--enabled", strconv.FormatBool(accept), "--problem", problem); err != nil {
			said = fmt.Errorf("the dashboard was not told: %w", err)
		}
	}
	unlock()
	if h.RetryDelay > 0 {
		wait := time.NewTimer(h.RetryDelay)
		select {
		case <-ctx.Done():
		case <-wait.C:
		}
		wait.Stop()
	}
	return errors.Join(fmt.Errorf("%w: %w", ErrNotTaken, cause), said)
}

// refusal is Decision 1's refusals that need no download: a version that is
// a prerelease or not newer; another upgrade or rollback not over; a hold
// after a restore; a maintenance gate; a version root's journal says was
// undone, or rolled back from.
func (h *Helper) refusal(ctx context.Context, req upgraderequest.Request, dataDir string) (string, upgrade.Installed, error) {
	if release.Prerelease(req.Version) {
		return "prerelease", upgrade.Installed{}, nil
	}
	j, err := journal.Read(h.ConfigDir)
	if err != nil {
		return "", upgrade.Installed{}, err
	}
	if j.Pending() {
		return "pending", upgrade.Installed{}, nil
	}
	if hold, err := backup.ReadHold(dataDir); err != nil || hold != nil {
		return "held", upgrade.Installed{}, nil
	}
	if _, err := os.Lstat(filepath.Join(dataDir, backup.GateFile)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "maintenance", upgrade.Installed{}, nil
	}
	inst, err := h.Inspect(ctx)
	if err != nil {
		return "", inst, err
	}
	if order, ok := release.CompareVersions(req.Version, inst.Version); !ok || order <= 0 {
		return "not-newer", inst, nil
	}
	// Root's journal, by the rule the pre-flight offers by (Decision 6).
	if j.Undid(req.Version) {
		return "undone", inst, nil
	}
	return "", inst, nil
}

// verified finds the newest release again, from GitHub, and refuses a
// version that is not it; then downloads and verifies it and judges it as
// `varlatch upgrade <version> --yes` would without an override: rollback-
// safe for the installed release, not below the database's schema, not
// ending an open migration's rollback window. An error is a release that
// did not verify.
func (h *Helper) verified(ctx context.Context, version string, inst upgrade.Installed, dataDir string) (upgrade.Release, string, error) {
	newest, err := h.Newest(ctx)
	if err != nil {
		// GitHub did not say (unreachable, rate-limited, an answer that is
		// not one): nothing is upgraded on what varlatchd's record says.
		return upgrade.Release{}, "unreachable", nil
	}
	if newest != version {
		if order, ok := release.CompareVersions(newest, version); ok && order > 0 {
			return upgrade.Release{}, "superseded", nil
		}
		return upgrade.Release{}, "not-latest", nil
	}
	rel, err := h.Fetch(ctx, version)
	if err != nil {
		var se *selfupdate.Error
		if errors.As(err, &se) && se.Unreachable {
			return upgrade.Release{}, "unreachable", nil
		}
		return upgrade.Release{}, "", err
	}
	if upgrade.SchemaRefusal(inst, rel.Version, rel.Manifest) != nil {
		return rel, "schema", nil
	}
	if !upgrade.RollbackSafe(rel.Manifest, inst) {
		return rel, "not-rollback-safe", nil
	}
	ends, err := h.WindowEnds(dataDir, rel.Version, rel.Manifest.EndsRollbackWindow())
	if err != nil || ends {
		return rel, "ends-rollback-window", nil
	}
	return rel, "", nil
}
