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
	// seen is the status last acted on (Watch), announced the request whose
	// restart was announced.
	seen, announced string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) dir() string { return filepath.Join(s.DataDir, upgraderequest.Dir) }

func (s *Service) readLast() (*Last, error) {
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
	o := jsvalue.Object{{Key: "request", Value: req}, {Key: "state", Value: st.State}, {Key: "reason", Value: orNil(st.Reason)},
		{Key: "journalId", Value: orNil(st.JournalID)}, {Key: "updatedAt", Value: orNil(st.UpdatedAt)}, {Key: "noAnswer", Value: st.NoAnswer}}
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

// Read is the state now.
func (s *Service) Read(ctx context.Context) (State, error) {
	last, err := s.readLast()
	if err != nil || last == nil {
		return State{State: "none"}, err
	}
	st := State{Request: last}
	now := s.now()
	asked, _ := time.Parse(upgraderequest.TimeLayout, last.RequestedAt)
	pending, err := upgraderequest.ReadRequest(s.DataDir)
	if err != nil {
		return st, err
	}
	switch {
	case last.Ended != "":
		st.State = last.Ended
		return st, nil
	case pending != nil && pending.ID == last.ID:
		st.State, st.NoAnswer = "waiting", now.Sub(asked) > NoAnswer
		return st, nil
	}
	status, err := upgraderequest.ReadStatus(s.DataDir)
	if err != nil {
		return st, err
	}
	if status == nil || status.RequestID != last.ID {
		// Taken (the file is gone), and nothing said yet. Past the
		// request's expiry the host never will (its helper stopped, or
		// the file was no request): over, so another may be filed.
		st.State, st.NoAnswer = "taken", now.Sub(asked) > NoAnswer
		if until, err := time.Parse(upgraderequest.TimeLayout, last.ExpiresAt); err == nil && !now.Before(until) {
			st.State, st.NoAnswer = "interrupted", false
		}
		return st, nil
	}
	st.State, st.Reason, st.JournalID, st.UpdatedAt = string(status.Phase), status.Reason, status.JournalID, status.UpdatedAt
	if status.Phase.Final() {
		return st, nil
	}
	// Not over by the helper's word: root's journal says how its upgrade
	// ended, and a step that has not moved for long was interrupted.
	if status.JournalID != "" {
		if j, err := upgradejournal.ReadWith(readFile, s.ConfigDir); err == nil && j != nil && j.ID == status.JournalID && j.Kind == upgradejournal.Upgrade {
			switch j.State {
			case upgradejournal.Done:
				st.State, st.Reason = "done", ""
				return st, nil
			case upgradejournal.Undone:
				st.State, st.Reason = "undone", "health"
				if !j.Reached(upgradejournal.Stopping) {
					st.State, st.Reason = "failed", "backup"
				}
				return st, nil
			case upgradejournal.Failed:
				st.State, st.Reason = "failed", "undo"
				return st, nil
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
	return st, nil
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
	if cur, err := s.Read(ctx); err != nil {
		return State{}, err
	} else if !cur.Final() {
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
	written := false
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
		// The request last, inside the job: a commit that fails takes it
		// back below.
		if err := s.writeLast(last); err != nil {
			return err
		}
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
		if written {
			_ = upgraderequest.CancelRequest(s.DataDir, requestID)
		}
		return State{}, err
	}
	return s.Read(ctx)
}

// Cancel removes the pending request, or finds it taken (too late), and
// records which, by the requester.
func (s *Service) Cancel(ctx context.Context, req auth.Requester, requestID string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, err := s.readLast()
	if err != nil {
		return State{}, err
	}
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
	err = upgraderequest.CancelRequest(s.DataDir, requestID)
	switch {
	case err == nil:
		cancelled = true
		last.Ended = "cancelled"
		if werr := s.writeLast(*last); werr != nil {
			return State{}, werr
		}
		err = s.record(ctx, audit.Event{Type: CancelledEvent, Decision: audit.Info, ActorIdentityID: &actor,
			Metadata: jsvalue.Object{{Key: "requestId", Value: requestID}, {Key: "to", Value: last.Version}, {Key: "reason", Value: "cancelled"}}})
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
	last, err := s.readLast()
	if err != nil || last == nil {
		return err
	}
	if last.Ended == "" {
		if r, err := upgraderequest.ReadRequest(s.DataDir); err == nil && r != nil && r.ID == last.ID && !s.now().Before(r.Expires()) {
			if err := upgraderequest.CancelRequest(s.DataDir, r.ID); err == nil {
				last.Ended = "expired"
				if err := s.writeLast(*last); err != nil {
					return err
				}
				if err := s.record(ctx, audit.Event{Type: CancelledEvent, Decision: audit.Info,
					Metadata: jsvalue.Object{{Key: "requestId", Value: r.ID}, {Key: "to", Value: r.Version}, {Key: "reason", Value: "expired"}}}); err != nil {
					return err
				}
			}
		}
	}
	status, err := upgraderequest.ReadStatus(s.DataDir)
	if err != nil || status == nil || status.RequestID != last.ID {
		return err
	}
	key := status.RequestID + "/" + string(status.Phase) + "/" + status.UpdatedAt
	if key == s.seen {
		return nil
	}
	s.seen = key
	switch {
	case status.Phase == upgraderequest.Restart && s.announced != status.RequestID:
		s.announced = status.RequestID
		if s.Announce != nil {
			s.Announce(&realtime.Notice{Kind: realtime.NoticeUpgradeRestarting, Version: last.Version})
		}
	case status.Phase.Final() && s.announced == status.RequestID:
		// Over, and this release still serves: no restart stands.
		s.announced = ""
		if s.Announce != nil {
			s.Announce(nil)
		}
	}
	if status.Phase == upgraderequest.Refused {
		_, err := s.recordOnce(ctx, status.RequestID, audit.Event{Type: RefusedEvent, Decision: audit.Info,
			Metadata: jsvalue.Object{{Key: "requestId", Value: status.RequestID}, {Key: "to", Value: last.Version}, {Key: "reason", Value: status.Reason}}})
		return err
	}
	return nil
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
