// SPDX-License-Identifier: AGPL-3.0-or-later

// Package upgraderequests is the web app's side of an upgrade the host
// helper makes (ADR-0065 phase 2): an Installation Admin files a request
// for the release the pre-flight offers, with a step-up approval bound to
// it; varlatchd writes the request into its data directory and reads back
// what the helper did with it; an admin may cancel it until the helper has
// taken it. varlatchd gains no other power: the helper decides and acts.
//
// The files (go/lib/upgraderequest) are display state, and so is what this
// answers, but for root's upgrade journal, which says whether an upgrade
// the helper ran is done or undone. The audit events say who asked through
// a working server: they are as trustworthy as varlatchd.
package upgraderequests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
	"github.com/varlatch/varlatch/go/server/write"
)

// The audit events (Decision 7). installation.upgraded is daemon's, from
// root's journal; it names the request when the status does.
const (
	RequestedEvent = "installation.upgrade_requested"
	CancelledEvent = "installation.upgrade_cancelled"
	TooLateEvent   = "installation.upgrade_cancel_too_late"
	RefusedEvent   = "installation.upgrade_refused"
	UndoneEvent    = "installation.upgrade_undone"
)

// Operation is the step-up approval's operation.
const Operation = "installation.upgrade"

// NoAnswer is how long the host may take to take a request, or to say what
// it does, before the dashboard says it did not answer (Decision 8).
const NoAnswer = 2 * time.Minute

// Stalled is how long a step may stay unchanged before the request counts
// as interrupted: a whole upgrade's bound and some.
const Stalled = 45 * time.Minute

// lastFile is varlatchd's record of the last request it filed, and how it
// ended when varlatchd ended it (cancelled, expired).
const lastFile = "last.json"

// Last is that record.
type Last struct {
	ID          string `json:"id"`
	From        string `json:"from"`
	Version     string `json:"version"`
	RequestedBy string `json:"requestedBy"`
	RequestedAt string `json:"requestedAt"`
	ExpiresAt   string `json:"expiresAt"`
	// Ended is "cancelled" or "expired" when varlatchd removed it.
	Ended string `json:"ended"`
}

// Service files, reads and cancels requests.
type Service struct {
	DataDir, ConfigDir string
	// Version is the running release.
	Version   string
	Writer    *write.Writer
	Approvals *auth.Service
	// Installation is the installation's id.
	Installation func(ctx context.Context) (string, error)
	// Preflight is the Release tab's judgement now.
	Preflight func(ctx context.Context) upgradecheck.Report
	// Announce, when set, tells every dashboard (realtime.Hub.Announce).
	Announce func(*realtime.Notice)
	Now      func() time.Time
	Log      *slog.Logger

	mu sync.Mutex
	// seen is the state last acted on (Watch), announced the request whose
	// restart was announced.
	seen, announced string
	// warned is, by file, the error last logged for a file that cannot be
	// read: Watch logs it once, not at each look.
	warned map[string]string
}

// The records of the upgrade-request directory a State can say cannot be
// read.
const (
	unreadableLast    = lastFile
	unreadableStatus  = upgraderequest.StatusFile
	unreadableRequest = upgraderequest.RequestFile
)

// warnOnce logs that file cannot be read (err), once per error; a nil err
// forgets it, so the next failure is logged again.
func (s *Service) warnOnce(file string, err error) {
	if s.warned == nil {
		s.warned = map[string]string{}
	}
	if err == nil {
		delete(s.warned, file)
		return
	}
	if s.warned[file] == err.Error() {
		return
	}
	s.warned[file] = err.Error()
	if s.Log != nil {
		s.Log.Warn("the upgrade request's record cannot be read; the dashboard says so until it is replaced", "file", file, "error", err)
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) dir() string { return filepath.Join(s.DataDir, upgraderequest.Dir) }

func (s *Service) readLast() (*Last, error) {
	if err := upgraderequest.CheckDir(s.DataDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir(), lastFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var l Last
	if err := json.Unmarshal(b, &l); err != nil || !upgraderequest.ValidRequestID(l.ID) {
		return nil, fmt.Errorf("%s is not a request's record", lastFile)
	}
	return &l, nil
}

// restoreLast puts back the last.json a failed request replaced: prev, or
// none.
func (s *Service) restoreLast(prev *Last) error {
	if prev != nil {
		return s.writeLast(*prev)
	}
	if err := upgraderequest.CheckDir(s.DataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir(), lastFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Service) writeLast(l Last) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := upgraderequest.MakeDir(s.DataDir); err != nil {
		return err
	}
	if err := release.WriteDurably(filepath.Join(s.dir(), lastFile), append(b, '\n'), 0o600); err != nil && !errors.Is(err, release.ErrNotDurable) {
		return err
	}
	return nil
}

// State is the last request and how far the host got with it, as GET
// /v1/installation/upgrade-request answers it.
type State struct {
	Request   *Last
	State     string
	Reason    string
	JournalID string
	UpdatedAt string
	NoAnswer  bool
	// Unreadable are the records that are there but cannot be read
	// (last.json, status.json, request.json): the state is what the rest
	// says, and a new request may replace them.
	Unreadable []string
	// Cancelled is a cancel's outcome; nil elsewhere.
	Cancelled *bool
}

// JS is the answer.
func (st State) JS() jsvalue.Object {
	orNil := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	var req any
	if r := st.Request; r != nil {
		req = jsvalue.Object{{Key: "id", Value: r.ID}, {Key: "from", Value: r.From}, {Key: "version", Value: r.Version}, {Key: "requestedBy", Value: orNil(r.RequestedBy)},
			{Key: "requestedAt", Value: r.RequestedAt}, {Key: "expiresAt", Value: r.ExpiresAt}}
	}
	unreadable := append([]string{}, st.Unreadable...)
	o := jsvalue.Object{{Key: "request", Value: req}, {Key: "state", Value: st.State}, {Key: "reason", Value: orNil(st.Reason)},
		{Key: "journalId", Value: orNil(st.JournalID)}, {Key: "updatedAt", Value: orNil(st.UpdatedAt)}, {Key: "noAnswer", Value: st.NoAnswer},
		{Key: "unreadable", Value: unreadable}}
	if st.Cancelled != nil {
		o = append(o, jsvalue.Member{Key: "cancelled", Value: *st.Cancelled})
	}
	return o
}

// Final is whether the state ends the request.
func (st State) Final() bool {
	switch st.State {
	case "none", "done", "refused", "failed", "undone", "interrupted", "cancelled", "expired":
		return true
	}
	return false
}

// Read is the state now. Its records are display state, so one that is
// there but cannot be read is not an error: the state is what the rest
// says, with Unreadable naming it, as the pre-flight's helper line treats
// helper.json.
func (s *Service) Read(ctx context.Context) (State, error) {
	st, _ := s.read()
	return st, nil
}

// errs are the read errors of the files Unreadable names, for warnOnce.
type errs map[string]error

func (s *Service) read() (State, errs) {
	bad := errs{}
	now := s.now()
	pending, err := upgraderequest.ReadRequest(s.DataDir)
	if err != nil {
		bad[unreadableRequest] = err
	}
	status, err := upgraderequest.ReadStatus(s.DataDir)
	if err != nil {
		bad[unreadableStatus], status = err, nil
	}
	last, err := s.readLast()
	if err != nil {
		bad[unreadableLast] = err
	}
	if last == nil {
		st := State{State: "none"}
		if err != nil {
			// Which request it was is not known. A file the host has not
			// taken, or a step it reports that still moves, is not over:
			// no new request until it is; else one may replace it.
			switch {
			case pending != nil || bad[unreadableRequest] != nil:
				st.State = "waiting"
			case status != nil && !status.Phase.Final():
				if at, err := time.Parse(upgraderequest.TimeLayout, status.UpdatedAt); err == nil && now.Sub(at) <= Stalled {
					st.State, st.JournalID, st.UpdatedAt = string(status.Phase), status.JournalID, status.UpdatedAt
				}
			}
		}
		st.Unreadable = bad.names()
		return st, bad
	}
	st := s.readOf(last, pending, bad[unreadableRequest] != nil, status, now)
	st.Unreadable = bad.names()
	return st, bad
}

func (e errs) names() []string {
	var out []string
	for _, f := range []string{unreadableLast, unreadableStatus, unreadableRequest} {
		if e[f] != nil {
			out = append(out, f)
		}
	}
	return out
}

// readOf is the state of the last request, from the pending request (or
// one that cannot be read, unreadablePending), the helper's status and
// root's journal.
func (s *Service) readOf(last *Last, pending *upgraderequest.Request, unreadablePending bool, status *upgraderequest.Status, now time.Time) State {
	st := State{Request: last}
	asked, _ := time.Parse(upgraderequest.TimeLayout, last.RequestedAt)
	switch {
	case last.Ended != "":
		st.State = last.Ended
		return st
	case pending != nil && pending.ID == last.ID || pending == nil && unreadablePending:
		// A request.json that cannot be read is still one the host has
		// not taken.
		st.State, st.NoAnswer = "waiting", now.Sub(asked) > NoAnswer
		return st
	}
	if status == nil || status.RequestID != last.ID {
		// Taken (the file is gone), and nothing said yet. Past the
		// request's expiry the host never will (its helper stopped, or
		// the file was no request): over, so another may be filed.
		st.State, st.NoAnswer = "taken", now.Sub(asked) > NoAnswer
		if until, err := time.Parse(upgraderequest.TimeLayout, last.ExpiresAt); err == nil && !now.Before(until) {
			st.State, st.NoAnswer = "interrupted", false
		}
		return st
	}
	st.State, st.Reason, st.JournalID, st.UpdatedAt = string(status.Phase), status.Reason, status.JournalID, status.UpdatedAt
	if status.Phase.Final() {
		return st
	}
	// Not over by the helper's word: root's journal says how its upgrade
	// ended, and a step that has not moved for long was interrupted.
	if status.JournalID != "" {
		if j, err := upgradejournal.ReadWith(readFile, s.ConfigDir); err == nil && j != nil && j.ID == status.JournalID && j.Kind == upgradejournal.Upgrade {
			switch j.State {
			case upgradejournal.Done:
				st.State, st.Reason = "done", ""
				return st
			case upgradejournal.Undone:
				st.State, st.Reason = "undone", "health"
				if !j.Reached(upgradejournal.Stopping) {
					st.State, st.Reason = "failed", "backup"
				}
				return st
			case upgradejournal.Failed:
				st.State, st.Reason = "failed", "undo"
				return st
			}
		}
	}
	at, _ := time.Parse(upgraderequest.TimeLayout, status.UpdatedAt)
	switch {
	case now.Sub(at) > Stalled:
		st.State = "interrupted"
	case status.Phase == upgraderequest.Taken && now.Sub(at) > NoAnswer:
		st.NoAnswer = true
	}
	return st
}

// readFile reads root's journal (0644, in a directory varlatchd may read).
var readFile = os.ReadFile

// stateChanged refuses a request with a reason.
func stateChanged(reason, msg string, details ...jsvalue.Member) error {
	return &domainerr.Error{Code: "STATE_CHANGED", Message: msg, Details: append(jsvalue.Object{{Key: "reason", Value: reason}}, details...)}
}

// Binding is the step-up approval for one request (Decision 2): this
// installation, from the running release, to the version, this request id.
func Binding(installation, from, to, requestID string) auth.Binding {
	return auth.Binding{
		Operation: Operation, Target: map[string]string{"installationId": installation},
		Body:  jsvalue.Object{{Key: "from", Value: from}, {Key: "to", Value: to}, {Key: "requestId", Value: requestID}},
		Query: map[string]string{},
		Summary: auth.ApprovalSummary{
			Title:   "Upgrade Varlatch from " + from + " to " + to + ": the host verifies the release, backs up, and restarts Varlatch (unavailable for about a minute). Request " + requestID,
			Changes: []auth.ApprovalChange{{Field: "version", From: &from, To: &to}},
		},
	}
}

// Request files a request for version, with requestID, by the requester,
// consuming approvalID ("" asks for one: STEP_UP_REQUIRED). The caller has
// checked that the requester is an Installation Admin on a dashboard
// session.
func (s *Service) Request(ctx context.Context, req auth.Requester, version, requestID, approvalID string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !upgraderequest.ValidRequestID(requestID) || !release.ValidVersion(version) {
		return State{}, &domainerr.Error{Code: "VALIDATION_FAILED", Message: "requestId must be a fresh upr_ id and version a release version"}
	}
	installation, err := s.Installation(ctx)
	if err != nil {
		return State{}, err
	}
	// One at a time: none waiting, none the host is on.
	cur, _ := s.read()
	if !cur.Final() {
		return State{}, stateChanged("pending", "Another upgrade request is pending or running: wait for it, or cancel it before the host takes it")
	} else if cur.Request != nil && cur.Request.ID == requestID {
		return State{}, stateChanged("request-id-used", "This request id was used: start again for a new one")
	}
	// Offered only as the pre-flight offers it, now (Decisions 4 and 8).
	r := s.Preflight(ctx)
	if !r.All() || r.Target.Version != version {
		return State{}, stateChanged("not-offered", "An upgrade to "+version+" is not offered from the web now: every line of the Release tab's pre-flight must pass for it; the tab shows the commands")
	}
	b := Binding(installation, s.Version, version, requestID)
	if approvalID == "" {
		return State{}, s.Approvals.StepUpRequired(ctx, req, b)
	}
	now := s.now()
	file := upgraderequest.NewRequest(requestID, version, req.IdentityID, now)
	last := Last{ID: requestID, From: s.Version, Version: version, RequestedBy: req.IdentityID, RequestedAt: file.RequestedAt, ExpiresAt: file.ExpiresAt}
	lastWritten, written := false, false
	err = s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		var used int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.requestId') = ?`, RequestedEvent, requestID).Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			return stateChanged("request-id-used", "This request id was used: start again for a new one")
		}
		approval, err := s.Approvals.ConsumeApproval(ctx, tx, req, approvalID, b)
		if err != nil {
			return err
		}
		actor := req.IdentityID
		if _, err := audit.Record(ctx, tx, audit.Event{Type: RequestedEvent, Decision: audit.Info, ActorIdentityID: &actor, Metadata: jsvalue.Object{
			{Key: "from", Value: s.Version}, {Key: "to", Value: version}, {Key: "requestId", Value: requestID}, {Key: "expiresAt", Value: file.ExpiresAt},
			{Key: "approvalId", Value: approval.ID}, {Key: "passkeyId", Value: approval.PasskeyID}, {Key: "userVerified", Value: approval.UserVerified},
		}}); err != nil {
			return err
		}
		// The files last, inside the job: last.json, then the request.
		// A job that fails after them (its commit) takes both back below,
		// unless the host took the request first.
		if err := s.writeLast(last); err != nil {
			return err
		}
		lastWritten = true
		if err := upgraderequest.WriteRequest(s.DataDir, file); err != nil {
			if errors.Is(err, upgraderequest.ErrPending) {
				return stateChanged("pending", "Another upgrade request is pending")
			}
			return err
		}
		written = true
		return nil
	})
	if err != nil {
		s.takeBack(requestID, cur.Request, lastWritten, written)
		return State{}, err
	}
	return s.Read(ctx)
}

// takeBack undoes the files of a request whose job failed: the request
// when it was written, and last.json when the request is gone (prev is the
// record it replaced). When the host took the request first, it acts on
// it, and last.json keeps naming it so that its status is shown; so it
// does when the request could not be removed.
func (s *Service) takeBack(requestID string, prev *Last, lastWritten, written bool) {
	if written {
		switch err := upgraderequest.CancelRequest(s.DataDir, requestID); {
		case errors.Is(err, upgraderequest.ErrTaken):
			return
		case err != nil:
			// It may still be there: last.json keeps naming it.
			if s.Log != nil {
				s.Log.Warn("an upgrade request whose filing failed could not be taken back", "request", requestID, "error", err)
			}
			return
		}
	}
	if lastWritten {
		if err := s.restoreLast(prev); err != nil && s.Log != nil {
			s.Log.Warn("the record of an upgrade request whose filing failed could not be taken back", "request", requestID, "error", err)
		}
	}
}

// Cancel removes the pending request, or finds it taken (too late), and
// records which, by the requester.
func (s *Service) Cancel(ctx context.Context, req auth.Requester, requestID string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A last.json that cannot be read names no request to cancel: a
	// pending one expires.
	last, _ := s.readLast()
	if last == nil || last.ID != requestID {
		return State{}, domainerr.NotFound("Upgrade request")
	}
	if last.Ended != "" {
		st, err := s.Read(ctx)
		no := false
		st.Cancelled = &no
		return st, err
	}
	actor := req.IdentityID
	cancelled := false
	err := upgraderequest.CancelRequest(s.DataDir, requestID)
	switch {
	case err == nil:
		cancelled = true
		last.Ended = "cancelled"
		werr := s.writeLast(*last)
		err = s.record(ctx, audit.Event{Type: CancelledEvent, Decision: audit.Info, ActorIdentityID: &actor,
			Metadata: jsvalue.Object{{Key: "requestId", Value: requestID}, {Key: "to", Value: last.Version}, {Key: "reason", Value: "cancelled"}}})
		if err == nil {
			err = werr
		}
	case errors.Is(err, upgraderequest.ErrTaken):
		err = s.record(ctx, audit.Event{Type: TooLateEvent, Decision: audit.Info, ActorIdentityID: &actor,
			Metadata: jsvalue.Object{{Key: "requestId", Value: requestID}, {Key: "to", Value: last.Version}}})
	}
	if err != nil {
		return State{}, err
	}
	st, err := s.Read(ctx)
	st.Cancelled = &cancelled
	return st, err
}

func (s *Service) record(ctx context.Context, events ...audit.Event) error {
	return s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, events...)
		return err
	})
}

// recordOnce records e unless an event of its type names its request.
func (s *Service) recordOnce(ctx context.Context, requestID string, e audit.Event) (bool, error) {
	recorded := false
	err := s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.requestId') = ?`, e.Type, requestID).Scan(&n); err != nil || n > 0 {
			return err
		}
		if _, err := audit.Record(ctx, tx, e); err != nil {
			return err
		}
		recorded = true
		return nil
	})
	return recorded, err
}

// WatchEvery is how often Watch looks.
const WatchEvery = time.Second

// Watch runs until ctx ends, each WatchEvery: a request past its expiry is
// removed (installation.upgrade_cancelled, expired); a refusal the helper
// recorded is audited once (installation.upgrade_refused); and when the
// helper says it restarts varlatchd, every dashboard is told, until the
// request ends without the restart. Each look waits for admit (the
// maintenance admission): nothing is written while it is closed.
func (s *Service) Watch(ctx context.Context, admit func() (leave func(), ok bool)) {
	tick := time.NewTicker(WatchEvery)
	defer tick.Stop()
	for {
		if leave, ok := admit(); ok {
			if err := s.Pass(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
				s.Log.Warn("the upgrade request's watch", "error", err)
			}
			leave()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Pass is one look of Watch.
func (s *Service) Pass(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A pending request past its expiry is removed, whether last.json names
	// it, is missing, or cannot be read.
	last, _ := s.readLast()
	if r, err := upgraderequest.ReadRequest(s.DataDir); err == nil && r != nil && !s.now().Before(r.Expires()) {
		switch err := upgraderequest.CancelRequest(s.DataDir, r.ID); {
		case err == nil:
			// Once the request is gone, audit its expiry even if last.json
			// cannot be updated, and update last.json only when it still
			// names this open request.
			var writeErr error
			if last != nil && last.ID == r.ID && last.Ended == "" {
				last.Ended = "expired"
				writeErr = s.writeLast(*last)
			}
			if _, recErr := s.recordOnce(ctx, r.ID, audit.Event{Type: CancelledEvent, Decision: audit.Info,
				Metadata: jsvalue.Object{{Key: "requestId", Value: r.ID}, {Key: "to", Value: r.Version}, {Key: "reason", Value: "expired"}}}); recErr != nil {
				return recErr
			}
			if writeErr != nil {
				return writeErr
			}
		case !errors.Is(err, upgraderequest.ErrTaken):
			return err
		}
	}
	st, bad := s.read()
	for _, f := range []string{unreadableLast, unreadableStatus, unreadableRequest} {
		s.warnOnce(f, bad[f])
	}
	if st.Request == nil {
		// None, or a last.json that cannot be read: no request to follow.
		// A restart announced for one that no record names now stands no
		// more.
		s.withdraw("")
		return nil
	}
	id := st.Request.ID
	key := id + "/" + st.State + "/" + st.UpdatedAt
	if key == s.seen {
		return nil
	}
	s.seen = key
	switch {
	case st.State == string(upgraderequest.Restart) && s.announced != id:
		s.announced = id
		if s.Announce != nil {
			s.Announce(&realtime.Notice{Kind: realtime.NoticeUpgradeRestarting, Version: st.Request.Version})
		}
	case st.Final():
		// Over by the helper's word, root's journal, or as interrupted (a
		// step that has not moved for Stalled), and this release still
		// serves: no restart stands.
		s.withdraw(id)
	}
	if st.State == string(upgraderequest.Refused) {
		_, err := s.recordOnce(ctx, id, audit.Event{Type: RefusedEvent, Decision: audit.Info,
			Metadata: jsvalue.Object{{Key: "requestId", Value: id}, {Key: "to", Value: st.Request.Version}, {Key: "reason", Value: st.Reason}}})
		return err
	}
	return nil
}

// withdraw withdraws the restart notice announced for the request id, or
// for any request when id is "".
func (s *Service) withdraw(id string) {
	if s.announced == "" || id != "" && s.announced != id {
		return
	}
	s.announced = ""
	if s.Announce != nil {
		s.Announce(nil)
	}
}

// RequestOf is the request a status record names for root's journal id,
// "" when none does: installation.upgraded and installation.upgrade_undone
// then carry it, with source web.
func RequestOf(dataDir, journalID string) string {
	st, err := upgraderequest.ReadStatus(dataDir)
	if err != nil || st == nil || journalID == "" || st.JournalID != journalID {
		return ""
	}
	return st.RequestID
}
