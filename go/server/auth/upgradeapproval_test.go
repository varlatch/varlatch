// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
	"github.com/varlatch/varlatch/go/server/upgraderequests"
	"github.com/varlatch/varlatch/go/server/write"
)

// An upgrade request from the web app (ADR-0065 phase 2, server/
// upgraderequests), with the real approvals: here, beside the auth test kit.

type upgradeWorld struct {
	e         *env
	svc       *upgraderequests.Service
	me        signedIn
	key       *softKey
	data, etc string
	offered   bool
	notices   []*realtime.Notice
}

func newUpgradeWorld(t *testing.T) *upgradeWorld {
	e := newEnv(t)
	k := newSoftKey(t)
	w := &upgradeWorld{e: e, key: k, me: e.dashboard(k), data: t.TempDir(), etc: t.TempDir(), offered: true}
	w.svc = &upgraderequests.Service{
		DataDir: w.data, ConfigDir: w.etc, Version: "0.51.0",
		Writer: &write.Writer{Store: e.store, Gates: write.NewGates()}, Approvals: e.svc,
		Installation: func(context.Context) (string, error) { return "inst_test", nil },
		Preflight: func(context.Context) upgradecheck.Report {
			status := upgradecheck.Pass
			if !w.offered {
				status = upgradecheck.Fail
			}
			return upgradecheck.Report{Target: &release.Target{Version: "0.52.0", Verified: &release.VerifiedTarget{}},
				Lines: []upgradecheck.Line{{ID: upgradecheck.LineBackup, Status: status}, {ID: upgradecheck.LineHelper, Status: upgradecheck.Pass}}}
		},
		Announce: func(n *realtime.Notice) { w.notices = append(w.notices, n) },
		Now:      e.clock.now,
	}
	return w
}

func (w *upgradeWorld) req() auth.Requester { return auth.RequesterOf(w.me.principal) }

func requestID(c string) string { return "upr_" + strings.Repeat(c, 26) }

// ask files without an approval: the approval asked for, its id.
func (w *upgradeWorld) ask(t *testing.T, id string) string {
	t.Helper()
	_, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", id, "")
	approval, view := approvalOf(t, err)
	if get(view, "operation") != upgraderequests.Operation {
		t.Fatalf("%s", jsvalue.Stringify(view))
	}
	return approval
}

// approve approves it with k.
func (w *upgradeWorld) approve(t *testing.T, approval string, k *softKey) error {
	t.Helper()
	o, err := w.e.svc.StartApproval(w.e.ctx, w.me.identityID, w.me.session.ID, approval)
	if err != nil {
		return err
	}
	_, err = w.e.svc.ApproveApproval(w.e.ctx, w.me.identityID, w.me.session.ID, approval, k.Assert(t, o, origin), "req_u")
	return err
}

func (w *upgradeWorld) events(typ string) int {
	return w.e.count(`SELECT count(*) FROM audit_events WHERE event_type = ?`, typ)
}

// The step-up: always asked for, bound to this installation, from, to and
// the request id, approved with a trusted passkey and user verification,
// used once and within its 2 minutes.
func TestAnUpgradeRequestNeedsItsOwnApproval(t *testing.T) {
	w := newUpgradeWorld(t)
	approval := w.ask(t, requestID("a"))
	if n := w.e.count(`SELECT count(*) FROM approval_intents WHERE id = ? AND expires_at - created_at = ?`, approval, (2 * time.Minute).Microseconds()); n != 1 {
		t.Fatal("not a 2-minute intent")
	}
	if _, err := upgraderequest.ReadRequest(w.data); err != nil || w.events(upgraderequests.RequestedEvent) != 0 {
		t.Fatal("filed without an approval")
	}
	// Not approved yet.
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("a"), approval); reasonOf(err) != "pending" {
		t.Fatalf("pending: %v", err)
	}
	// An unconfirmed passkey (added by the session) cannot approve.
	added := newSoftKey(t)
	ro, err := w.e.svc.RegistrationOptions(w.e.ctx, auth.CSRFBinding(browserCSRF), "", w.me.session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.svc.Register(w.e.ctx, auth.CSRFBinding(browserCSRF), w.me.session, added.Register(t, ro, origin), "Laptop", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := w.approve(t, approval, added); codeOf(err) != "PERMISSION_DENIED" {
		t.Fatalf("an unconfirmed passkey: %v", err)
	}
	// Nor a trusted one without user verification.
	w.key.NoUV = true
	if err := w.approve(t, approval, w.key); reasonOf(err) != "user-verification-required" {
		t.Fatalf("no user verification: %v", err)
	}
	w.key.NoUV = false
	if err := w.approve(t, approval, w.key); err != nil {
		t.Fatal(err)
	}
	// Bound to the request id: another one does not fit.
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("b"), approval); reasonOf(err) != "mismatch" {
		t.Fatalf("another request id: %v", err)
	}
	st, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("a"), approval)
	if err != nil || st.State != "waiting" || st.Request.ID != requestID("a") || st.Request.From != "0.51.0" {
		t.Fatalf("%+v %v", st, err)
	}
	r, err := upgraderequest.ReadRequest(w.data)
	if err != nil || r == nil || r.Version != "0.52.0" || r.RequestedBy != w.me.identityID || !r.Expires().Equal(w.e.clock.now().Add(10*time.Minute).Truncate(time.Millisecond)) {
		t.Fatalf("the request file: %+v %v", r, err)
	}
	if n := w.e.count(`SELECT count(*) FROM audit_events WHERE event_type = ? AND actor_identity_id = ? AND json_extract(metadata, '$.userVerified') = 1 AND json_extract(metadata, '$.passkeyId') != '' AND json_extract(metadata, '$.to') = '0.52.0'`,
		upgraderequests.RequestedEvent, w.me.identityID); n != 1 {
		t.Fatal("installation.upgrade_requested not recorded with its approval")
	}
	// One at a time.
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("c"), ""); reasonOf(err) != "pending" {
		t.Fatalf("a second request: %v", err)
	}
	// Cancelled, then the same approval replayed: used once.
	if st, err := w.svc.Cancel(w.e.ctx, w.req(), requestID("a")); err != nil || st.Cancelled == nil || !*st.Cancelled || st.State != "cancelled" {
		t.Fatalf("cancel: %+v %v", st, err)
	}
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("a"), approval); reasonOf(err) != "request-id-used" {
		t.Fatalf("the same request again: %v", err)
	}
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("d"), approval); reasonOf(err) != "mismatch" && reasonOf(err) != "consumed" {
		t.Fatalf("a replayed approval: %v", err)
	}
	// Expired: approved, then past its 2 minutes.
	approval = w.ask(t, requestID("e"))
	if err := w.approve(t, approval, w.key); err != nil {
		t.Fatal(err)
	}
	w.e.clock.add(121 * time.Second)
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("e"), approval); reasonOf(err) != "expired" {
		t.Fatalf("an expired approval: %v", err)
	}
	if r, _ := upgraderequest.ReadRequest(w.data); r != nil {
		t.Fatal("filed with a refused approval")
	}
	// Not offered (a pre-flight line fails): no approval is even asked for.
	w.offered = false
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("f"), ""); reasonOf(err) != "not-offered" {
		t.Fatalf("not offered: %v", err)
	}
	w.offered = true
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.1", requestID("f"), ""); reasonOf(err) != "not-offered" {
		t.Fatalf("another version: %v", err)
	}
}

// file files request id with a fresh approval.
func (w *upgradeWorld) file(t *testing.T, id string) {
	t.Helper()
	approval := w.ask(t, id)
	if err := w.approve(t, approval, w.key); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", id, approval); err != nil {
		t.Fatal(err)
	}
}

// take does what the helper's take does: request.json moved away.
func (w *upgradeWorld) take(t *testing.T) {
	t.Helper()
	if err := os.Rename(filepath.Join(w.data, upgraderequest.Dir, upgraderequest.RequestFile), filepath.Join(w.data, "taken.json")); err != nil {
		t.Fatal(err)
	}
}

func (w *upgradeWorld) status(t *testing.T, id string, p upgraderequest.Phase, reason, journal string) {
	t.Helper()
	if err := upgraderequest.WriteStatus(w.data, upgraderequest.Status{Format: upgraderequest.Format, RequestID: id, Version: "0.52.0", Phase: p, Reason: reason, JournalID: journal,
		UpdatedAt: w.e.clock.now().UTC().Format(upgraderequest.TimeLayout)}); err != nil {
		t.Fatal(err)
	}
}

// A cancel after the take finds nothing: too late, recorded, the request's
// state shown; the host goes on.
func TestACancelAfterTheTakeIsTooLate(t *testing.T) {
	w := newUpgradeWorld(t)
	w.file(t, requestID("a"))
	w.take(t)
	st, err := w.svc.Cancel(w.e.ctx, w.req(), requestID("a"))
	if err != nil || st.Cancelled == nil || *st.Cancelled || st.State != "taken" || w.events(upgraderequests.TooLateEvent) != 1 || w.events(upgraderequests.CancelledEvent) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := w.svc.Cancel(w.e.ctx, w.req(), requestID("z")); codeOf(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("another request: %v", err)
	}
	// Taken, no word from the host for 2 minutes: it did not answer.
	w.e.clock.add(3 * time.Minute)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "taken" || !st.NoAnswer {
		t.Fatalf("%+v", st)
	}
	// Past its expiry with no word at all: over, and another may be filed.
	w.e.clock.add(8 * time.Minute)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "interrupted" || !st.Final() {
		t.Fatalf("never answered: %+v", st)
	}
	w.file(t, requestID("b"))
}

// The watch: an expired request is removed and recorded once; a refusal
// the helper recorded is audited once; a restart is announced to every
// dashboard once, and withdrawn when the request ends with this release
// still serving.
func TestTheWatch(t *testing.T) {
	w := newUpgradeWorld(t)
	w.file(t, requestID("a"))
	if st, _ := w.svc.Read(w.e.ctx); st.State != "waiting" || st.NoAnswer {
		t.Fatalf("%+v", st)
	}
	w.e.clock.add(3 * time.Minute)
	if st, _ := w.svc.Read(w.e.ctx); !st.NoAnswer {
		t.Fatal("the host did not answer, and the state does not say so")
	}
	w.e.clock.add(8 * time.Minute)
	for i := 0; i < 2; i++ {
		if err := w.svc.Pass(w.e.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := w.svc.Read(w.e.ctx); st.State != "expired" {
		t.Fatalf("%+v", st)
	}
	if n := w.e.count(`SELECT count(*) FROM audit_events WHERE event_type = ? AND actor_identity_id IS NULL AND json_extract(metadata, '$.reason') = 'expired'`, upgraderequests.CancelledEvent); n != 1 {
		t.Fatalf("%d expiry events", n)
	}

	w.file(t, requestID("b"))
	w.take(t)
	w.status(t, requestID("b"), upgraderequest.Taken, "", "")
	w.status(t, requestID("b"), upgraderequest.Refused, "undone", "")
	for i := 0; i < 2; i++ {
		_ = w.svc.Pass(w.e.ctx)
	}
	if n := w.e.count(`SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.reason') = 'undone'`, upgraderequests.RefusedEvent); n != 1 {
		t.Fatalf("%d refusal events", n)
	}
	if st, _ := w.svc.Read(w.e.ctx); st.State != "refused" || st.Reason != "undone" || !st.Final() {
		t.Fatalf("%+v", st)
	}

	w.file(t, requestID("c"))
	w.take(t)
	w.status(t, requestID("c"), upgraderequest.Restart, "", "0123456789abcdef")
	_ = w.svc.Pass(w.e.ctx)
	_ = w.svc.Pass(w.e.ctx)
	if len(w.notices) != 1 || w.notices[0] == nil || w.notices[0].Kind != realtime.NoticeUpgradeRestarting || w.notices[0].Version != "0.52.0" {
		t.Fatalf("the notice: %+v", w.notices)
	}
	w.e.clock.add(time.Second)
	w.status(t, requestID("c"), upgraderequest.Failed, "error", "0123456789abcdef")
	_ = w.svc.Pass(w.e.ctx)
	if len(w.notices) != 2 || w.notices[1] != nil {
		t.Fatalf("not withdrawn: %+v", w.notices)
	}

	// A restart whose step never moves again (the helper died before the
	// stop): once interrupted, the notice is withdrawn too.
	w.file(t, requestID("d"))
	w.take(t)
	w.status(t, requestID("d"), upgraderequest.Restart, "", "0123456789abcdef")
	_ = w.svc.Pass(w.e.ctx)
	if len(w.notices) != 3 || w.notices[2] == nil {
		t.Fatalf("the second notice: %+v", w.notices)
	}
	w.e.clock.add(upgraderequests.Stalled - time.Minute)
	_ = w.svc.Pass(w.e.ctx)
	if len(w.notices) != 3 {
		t.Fatalf("withdrawn before the stall: %+v", w.notices)
	}
	w.e.clock.add(2 * time.Minute)
	_ = w.svc.Pass(w.e.ctx)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "interrupted" || len(w.notices) != 4 || w.notices[3] != nil {
		t.Fatalf("interrupted, not withdrawn: %+v %+v", st, w.notices)
	}
}

// The records are display state: one that is there but cannot be read is
// said (unreadable), never an error; the watch logs it once, not at each
// look; a new request replaces it once nothing waits or runs.
func TestUnreadableRecords(t *testing.T) {
	w := newUpgradeWorld(t)
	var logged strings.Builder
	w.svc.Log = slog.New(slog.NewTextHandler(&logged, nil))
	dir := filepath.Join(w.data, upgraderequest.Dir)
	w.file(t, requestID("a"))
	w.take(t)
	if err := os.WriteFile(filepath.Join(dir, upgraderequest.StatusFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := w.svc.Read(w.e.ctx)
	if err != nil || st.State != "taken" || !slices.Equal(st.Unreadable, []string{"status.json"}) || st.Request == nil {
		t.Fatalf("status.json: %+v %v", st, err)
	}
	for i := 0; i < 3; i++ {
		if err := w.svc.Pass(w.e.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logged.String(), "cannot be read"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, logged.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "last.json"), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = w.svc.Read(w.e.ctx)
	if err != nil || st.State != "none" || st.Request != nil || !slices.Equal(st.Unreadable, []string{"last.json", "status.json"}) {
		t.Fatalf("last.json: %+v %v", st, err)
	}
	if !strings.Contains(string(jsvalue.Stringify(st.JS())), `"unreadable":["last.json","status.json"]`) {
		t.Fatalf("the answer: %s", jsvalue.Stringify(st.JS()))
	}
	// Nothing waits or runs (the status cannot say so): a new request
	// replaces both records' word.
	w.file(t, requestID("b"))
	if st, err := w.svc.Read(w.e.ctx); err != nil || st.State != "waiting" || st.Request == nil || st.Request.ID != requestID("b") || !slices.Equal(st.Unreadable, []string{"status.json"}) {
		t.Fatalf("after a new request: %+v %v", st, err)
	}
	// With last.json unreadable while a request waits, none is filed over
	// it, and it still expires.
	_ = os.WriteFile(filepath.Join(dir, "last.json"), []byte("[]"), 0o600)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "waiting" || st.Final() {
		t.Fatalf("a request waits: %+v", st)
	}
	w.e.clock.add(11 * time.Minute)
	_ = w.svc.Pass(w.e.ctx)
	if r, _ := upgraderequest.ReadRequest(w.data); r != nil {
		t.Fatal("the request did not expire")
	}
}

// A filing whose job fails after it wrote last.json (here the request
// file: another is there) takes last.json back: the state stays the
// previous request's, never a phantom request "taken".
func TestAFailedFilingLeavesNoRecord(t *testing.T) {
	w := newUpgradeWorld(t)
	w.file(t, requestID("a"))
	if _, err := w.svc.Cancel(w.e.ctx, w.req(), requestID("a")); err != nil {
		t.Fatal(err)
	}
	stray := upgraderequest.NewRequest(requestID("z"), "0.52.0", "idn_"+strings.Repeat("b", 26), w.e.clock.now())
	if err := upgraderequest.WriteRequest(w.data, stray); err != nil {
		t.Fatal(err)
	}
	approval := w.ask(t, requestID("b"))
	if err := w.approve(t, approval, w.key); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Request(w.e.ctx, w.req(), "0.52.0", requestID("b"), approval); reasonOf(err) != "pending" {
		t.Fatalf("over another request: %v", err)
	}
	if st, _ := w.svc.Read(w.e.ctx); st.Request == nil || st.Request.ID != requestID("a") || st.State != "cancelled" {
		t.Fatalf("the state after the failed filing: %+v", st)
	}
	if w.e.count(`SELECT count(*) FROM audit_events WHERE event_type = ? AND json_extract(metadata, '$.requestId') = ?`, upgraderequests.RequestedEvent, requestID("b")) != 0 {
		t.Fatal("the failed filing was audited")
	}
}

// What the state says once the host runs the engine: root's journal says
// done or undone when the helper could not (the release changed under
// it); a step that does not move is interrupted.
func TestTheStateFollowsRootsJournal(t *testing.T) {
	w := newUpgradeWorld(t)
	w.file(t, requestID("a"))
	w.take(t)
	w.status(t, requestID("a"), upgraderequest.Checking, "", "0123456789abcdef")
	if st, _ := w.svc.Read(w.e.ctx); st.State != "checking" || st.JournalID != "0123456789abcdef" {
		t.Fatalf("%+v", st)
	}
	j := &upgradejournal.Journal{Format: upgradejournal.Format, ID: "0123456789abcdef", From: "0.51.0", To: "0.52.0", State: upgradejournal.Undone, Step: upgradejournal.Started}
	if err := upgradejournal.Write(w.etc, j); err != nil {
		t.Fatal(err)
	}
	if st, _ := w.svc.Read(w.e.ctx); st.State != "undone" || st.Reason != "health" {
		t.Fatalf("undone: %+v", st)
	}
	j.State = upgradejournal.Done
	_ = upgradejournal.Write(w.etc, j)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "done" {
		t.Fatalf("done: %+v", st)
	}
	// Another journal (an upgrade by hand since): the step is the helper's
	// last word, then interrupted once it has not moved for long.
	j.ID = "fedcba9876543210"
	_ = upgradejournal.Write(w.etc, j)
	w.e.clock.add(46 * time.Minute)
	if st, _ := w.svc.Read(w.e.ctx); st.State != "interrupted" {
		t.Fatalf("interrupted: %+v", st)
	}
	if upgraderequests.RequestOf(w.data, "0123456789abcdef") != requestID("a") || upgraderequests.RequestOf(w.data, "fedcba9876543210") != "" {
		t.Fatal("RequestOf")
	}
}
