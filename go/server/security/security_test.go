// SPDX-License-Identifier: AGPL-3.0-or-later

package security_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

type world struct {
	t         *testing.T
	store     *storage.DB
	w         *write.Writer
	approvals *auth.Service
	org       string
}

// newWorld: alice, a person with a CLI credential, admin of acme; a
// service identity of acme with a credential of its own.
func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	wd := &world{t: t, store: store, w: &write.Writer{Store: store, Gates: write.NewGates()}}
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = org.ID
	wd.exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_m', 'service', 'deploy', ?)`, org.ID)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_m', 'idn_m', 'service', 'h_m')`)
	public, _ := url.Parse("http://127.0.0.1:8686")
	wd.approvals = auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK})
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) setControl(control, mode, config string, version int) {
	wd.t.Helper()
	var cfg any
	if config != "" {
		cfg = config
	}
	wd.exec(`INSERT INTO security_controls (organization_id, control, mode, config, version) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (organization_id, control) DO UPDATE SET mode = excluded.mode, config = excluded.config, version = excluded.version`,
		wd.org, control, mode, cfg, version)
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

func machine(org string) *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_m", Kind: "service", OrganizationID: &org}, Credential: auth.Credential{ID: "crd_m", Kind: "service"}}
}

func ptr[T any](v T) *T { return &v }

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func detail(err error, key string) any {
	var de *domainerr.Error
	if !errors.As(err, &de) {
		return nil
	}
	v, _ := de.Details.Get(key)
	return v
}

func (wd *world) change(in security.ChangeInput) (security.Change, error) {
	if in.Principal == nil {
		in.Principal = alice()
	}
	if in.Config == (security.ConfigChange{}) && in.Control != security.CredentialLifetime {
		in.Config.Keep = true
	}
	in.OrganizationID, in.RequestID = wd.org, "req_test"
	return security.WithApproval(context.Background(), wd.approvals, auth.RequesterOf(in.Principal), func() (security.Change, error) {
		c, _, err := security.ChangeControl(context.Background(), wd.w, wd.approvals, in, time.Now)
		return c, err
	})
}

// approve marks an approval approved, as the dashboard's ceremony leaves it.
func (wd *world) approve(err error) string {
	wd.t.Helper()
	view, _ := detail(err, "approval").(jsvalue.Object)
	id, _ := view.Get("id")
	s, _ := id.(string)
	if s == "" {
		wd.t.Fatalf("no approval in %v", err)
	}
	wd.exec(`UPDATE approval_intents SET approved_at = ?, approved_with_passkey_id = 'pk_1', approval_user_verified = 1 WHERE id = ?`, time.Now().UnixMicro(), s)
	return s
}

func TestClassifyChange(t *testing.T) {
	l := func(d, m int64) *security.Lifetime { return &security.Lifetime{DefaultTTLSeconds: d, MaxTTLSeconds: m} }
	for _, c := range []struct {
		name              string
		fromMode, toMode  string
		from, to          *security.Lifetime
		changes, loosened string
	}{
		{"off to report", "off", "report", nil, nil, "mode", ""},
		{"enforce to report", "enforce", "report", nil, nil, "mode", "mode"},
		{"a lifetime set", "report", "report", nil, l(60, 120), "defaultTtlSeconds,maxTtlSeconds", ""},
		{"a lifetime cleared", "off", "off", l(60, 120), nil, "defaultTtlSeconds,maxTtlSeconds", "defaultTtlSeconds,maxTtlSeconds"},
		{"the maximum grown, the mode tightened", "report", "enforce", l(60, 120), l(60, 240), "mode,maxTtlSeconds", "maxTtlSeconds"},
		{"both shrunk", "enforce", "enforce", l(60, 120), l(30, 90), "defaultTtlSeconds,maxTtlSeconds", ""},
		{"nothing", "report", "report", l(60, 120), l(60, 120), "", ""},
	} {
		changes, loosened := security.ClassifyChange(c.fromMode, c.from, c.toMode, c.to)
		var fields []string
		for _, ch := range changes {
			fields = append(fields, ch.Field)
		}
		if strings.Join(fields, ",") != c.changes || strings.Join(loosened, ",") != c.loosened {
			t.Errorf("%s: changes %v loosened %v, want %s and %s", c.name, fields, loosened, c.changes, c.loosened)
		}
	}
}

// A control change takes the Organization's gate exclusive (decision 4):
// it waits for an external effect of the Organization, which holds the
// gate shared across its call, and commits once the effect ended.
func TestChangeWaitsForAnEffect(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	called, release := make(chan struct{}), make(chan struct{})
	effectDone := make(chan error, 1)
	go func() {
		_, _, err := write.RunEffect(ctx, wd.w, write.Effect[int, int]{
			OrganizationID: wd.org,
			Call:           func(context.Context) (int, error) { close(called); <-release; return 0, nil },
			Final:          func(context.Context, *storage.Tx, int) (int, error) { return 0, nil },
		})
		effectDone <- err
	}()
	<-called
	waiting := make(chan struct{})
	var once sync.Once
	wd.w.Gates.Observe(func(event string, g write.Gate) {
		if event == "waiting" && g.Level == write.LevelOrganization && g.Mode == write.Exclusive {
			once.Do(func() { close(waiting) })
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Report)})
		done <- err
	}()
	<-waiting
	select {
	case err := <-done:
		t.Fatalf("the change finished during the effect's call: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-effectDone; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st, err := security.Read(ctx, wd.store.Reader(), wd.org, security.AdminStepUp)
	if err != nil || st.Mode != security.Report || st.Version != 1 {
		t.Fatalf("%+v %v", st, err)
	}
}

// The gates a change takes: the Organization exclusive, the requester
// shared, or exclusive when the request carries an approval it may
// consume; never inside the job.
func TestChangeGates(t *testing.T) {
	wd := newWorld(t)
	var mu sync.Mutex
	var got []string
	wd.w.Gates.Observe(func(event string, g write.Gate) {
		if event == "acquired" {
			mu.Lock()
			got = append(got, g.String())
			mu.Unlock()
		}
	})
	if _, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Report)}); err != nil {
		t.Fatal(err)
	}
	_, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Report), ExpectedVersion: 1, ApprovalID: "apr_aaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2:organization:" + wd.org + "(exclusive)", "3:person:idn_a(shared)", "2:organization:" + wd.org + "(exclusive)", "3:person:idn_a(exclusive)"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("gates %v, want %v", got, want)
	}
}

// Loosening needs a step-up approval for exactly that change: without one
// the answer is STEP_UP_REQUIRED and nothing changes; with the approved
// intent the change is made and records the approval; the approval cannot
// be used again, and one for another body does not fit.
func TestLooseningConsumesItsApproval(t *testing.T) {
	wd := newWorld(t)
	if _, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Enforce)}); err != nil {
		t.Fatal(err)
	}
	loosen := security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Off), ExpectedVersion: 1}
	_, err := wd.change(loosen)
	if code(err) != "STEP_UP_REQUIRED" {
		t.Fatalf("%v", err)
	}
	id := wd.approve(err)
	// Expired (the fixture cannot hold one: the TypeScript sweep deletes
	// intents a day past their expiry, which fixed times cannot stay short of).
	wd.exec(`UPDATE approval_intents SET created_at = ?, expires_at = ? WHERE id = ?`, time.Now().Add(-time.Minute).UnixMicro(), time.Now().Add(-time.Second).UnixMicro(), id)
	if _, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Off), ExpectedVersion: 1, ApprovalID: id}); code(err) != "APPROVAL_INVALID" || detail(err, "reason") != "expired" {
		t.Fatalf("expired: %v", err)
	}
	wd.exec(`UPDATE approval_intents SET expires_at = ? WHERE id = ?`, time.Now().Add(time.Hour).UnixMicro(), id)
	other := security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Report), ExpectedVersion: 1, ApprovalID: id}
	if _, err := wd.change(other); code(err) != "APPROVAL_INVALID" || detail(err, "reason") != "mismatch" {
		t.Fatalf("another body: %v", err)
	}
	loosen.ApprovalID = id
	c, err := wd.change(loosen)
	if err != nil || !c.Changed || !c.Loosened || c.Control.Mode != security.Off || c.Control.Version != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	ev := paritytest.Rows(t, wd.store, `SELECT json_extract(metadata, '$.approvalId') AS id, json_extract(metadata, '$.approvalPasskeyId') AS pk,
		json_extract(metadata, '$.loosenedFields') AS fields FROM audit_events WHERE event_type = 'security_control.changed' ORDER BY event_order DESC LIMIT 1`)
	if ev[0]["id"] != id || ev[0]["pk"] != "pk_1" || ev[0]["fields"] != "mode" {
		t.Fatalf("audit %v", ev[0])
	}
	if _, err := wd.change(security.ChangeInput{Control: security.RequirementProtection, Mode: ptr(security.Off), ApprovalID: id}); err != nil {
		t.Fatalf("requirement-protection off to off needs nothing: %v", err)
	}
	wd.setControl(security.RequirementProtection, security.Report, "", 1)
	if _, err := wd.change(security.ChangeInput{Control: security.RequirementProtection, Mode: ptr(security.Off), ExpectedVersion: 1, ApprovalID: id}); code(err) != "APPROVAL_INVALID" || detail(err, "reason") != "consumed" {
		t.Fatalf("used again: %v", err)
	}
}

// A machine credential never gets an approval created.
func TestNoIntentForAMachine(t *testing.T) {
	wd := newWorld(t)
	wd.setControl(security.AdminStepUp, security.Report, "", 1)
	_, err := wd.change(security.ChangeInput{Control: security.AdminStepUp, Mode: ptr(security.Off), ExpectedVersion: 1, Principal: machine(wd.org)})
	if code(err) == "STEP_UP_REQUIRED" || err == nil {
		t.Fatalf("%v", err)
	}
	if n := paritytest.Rows(t, wd.store, `SELECT count(*) AS n FROM approval_intents`)[0]["n"]; n != int64(0) {
		t.Fatalf("%v intents", n)
	}
}

// The protected-operation framework (protected.ts): the controls' modes
// decide, in the operation's job.
func TestPrepare(t *testing.T) {
	ctx := context.Background()
	op := func(org string, ttl *int64, binding bool) security.Protected {
		return security.Protected{
			Scope: write.Scope{OrganizationID: org},
			Checks: []security.Check{
				{Control: security.AdminStepUp, Operation: "credential.issue"},
				{Control: security.CredentialLifetime, Operation: "credential.issue", TTLSeconds: ttl},
			},
			Binding: func(context.Context, query.DBTX, *int64) (*auth.Binding, error) {
				if !binding {
					return nil, nil
				}
				return &auth.Binding{Operation: "credential.issue", OrganizationID: &org, Target: map[string]string{"identityId": "idn_m"}, Query: map[string]string{}}, nil
			},
		}
	}
	run := func(wd *world, r security.Request, p security.Protected, count bool) (*security.Prepared, error) {
		var out *security.Prepared
		err := wd.w.Job(ctx, r.Gates(wd.org), func(ctx context.Context, tx *storage.Tx) error {
			var err error
			if out, err = security.Prepare(ctx, tx, r, p, time.Now); err != nil {
				return err
			}
			if count {
				return out.Count(ctx, tx)
			}
			return nil
		})
		return out, err
	}
	person := security.Request{Principal: alice()}

	wd := newWorld(t)
	p, err := run(wd, person, op(wd.org, ptr[int64](30), true), false)
	if err != nil || p.Approval != nil || len(p.Reports) != 0 || *p.EffectiveTTL != 30 {
		t.Fatalf("every control off: %+v %v", p, err)
	}

	wd.setControl(security.AdminStepUp, security.Report, "", 2)
	wd.setControl(security.CredentialLifetime, security.Report, `{"defaultTtlSeconds":600,"maxTtlSeconds":7200}`, 3)
	if p, err = run(wd, person, op(wd.org, nil, true), true); err != nil || len(p.Reports) != 2 || p.Reports[0].Reason != "no-approval" || p.Reports[1].Reason != "would-default" || p.EffectiveTTL != nil {
		t.Fatalf("report: %+v %v", p, err)
	}
	if p, err = run(wd, security.Request{Principal: machine(wd.org)}, op(wd.org, ptr[int64](9000), true), true); err != nil ||
		len(p.Reports) != 2 || p.Reports[0].Reason != "machine-credential" || p.Reports[1].Reason != "would-refuse" {
		t.Fatalf("report, a machine: %+v %v", p, err)
	}
	counted := paritytest.Rows(t, wd.store, `SELECT control, config_version AS v, reason, count FROM security_control_counters ORDER BY control, reason`)
	if len(counted) != 4 || counted[0]["reason"] != "machine-credential" || counted[0]["v"] != int64(2) || counted[3]["reason"] != "would-refuse" || counted[3]["v"] != int64(3) {
		t.Fatalf("counters %v", counted)
	}

	wd.setControl(security.AdminStepUp, security.Enforce, "", 4)
	wd.setControl(security.CredentialLifetime, security.Enforce, `{"defaultTtlSeconds":600,"maxTtlSeconds":7200}`, 5)
	if _, err := run(wd, person, op(wd.org, ptr[int64](9000), true), false); code(err) != "CREDENTIAL_LIFETIME_EXCEEDED" {
		t.Fatalf("above the maximum, before any approval: %v", err)
	}
	if _, err := run(wd, person, op(wd.org, ptr[int64](0), true), false); code(err) != "VALIDATION_FAILED" {
		t.Fatalf("a zero lifetime: %v", err)
	}
	var needed *auth.ApprovalNeeded
	if _, err := run(wd, person, op(wd.org, nil, true), false); !errors.As(err, &needed) {
		t.Fatalf("enforce without an approval: %v", err)
	}
	if p, err = run(wd, person, op(wd.org, nil, false), false); err != nil || p.Binding != nil || *p.EffectiveTTL != 600 || !p.TTLDefaulted {
		t.Fatalf("a request that changes nothing needs no approval; the default lifetime: %+v %v", p, err)
	}
	m := security.Request{Principal: machine(wd.org)}
	if _, err := run(wd, m, op(wd.org, nil, true), false); code(err) != "PERMISSION_DENIED" || detail(err, "reason") != "machine-credential" {
		t.Fatalf("a machine under enforce: %v", err)
	}
	if err := security.RefuseMachineUnderEnforce(ctx, wd.store.Reader(), machine(wd.org), wd.org, op(wd.org, nil, true).Checks); code(err) != "PERMISSION_DENIED" {
		t.Fatalf("early refusal: %v", err)
	}
	if err := security.RefuseMachineUnderEnforce(ctx, wd.store.Reader(), alice(), wd.org, op(wd.org, nil, true).Checks); err != nil {
		t.Fatalf("a person is never refused early: %v", err)
	}

	// With the approval: STEP_UP_REQUIRED creates it, the approved intent
	// is consumed in the job, once.
	_, err = security.WithApproval(ctx, wd.approvals, auth.RequesterOf(alice()), func() (*security.Prepared, error) {
		return run(wd, person, op(wd.org, nil, true), false)
	})
	id := wd.approve(err)
	with := security.Request{Principal: alice(), ApprovalID: id, Approvals: wd.approvals}
	if p, err = run(wd, with, op(wd.org, nil, true), false); err != nil || p.Approval == nil || p.Approval.ID != id || !p.Approval.UserVerified {
		t.Fatalf("consumed: %+v %v", p, err)
	}
	if _, err := run(wd, with, op(wd.org, nil, true), false); code(err) != "APPROVAL_INVALID" {
		t.Fatalf("consumed again: %v", err)
	}
}

// The summary worker, on an injected clock: a bucket is summarized once
// its hour has been over for 10 minutes, once; an increment that arrives
// after its bucket was summarized counts in the current hour; counter rows
// go 35 days after their summary, and a deleted Organization's at once,
// never summarized.
func TestSummaries(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	var now time.Time
	clock := func() time.Time { return now }
	count := func(at time.Time) {
		t.Helper()
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
			return security.CountWouldBlock(ctx, tx, wd.org, []security.WouldBlock{{Control: "admin-step-up", ConfigVersion: 1, Operation: "grant.create", ActorIdentityID: "idn_a", Reason: "no-approval"}}, at.UnixMicro(), clock)
		}); err != nil {
			t.Fatal(err)
		}
	}
	work := func(wantEmitted, wantDeleted int) {
		t.Helper()
		e, d, err := security.RunWorker(ctx, wd.w, clock)
		if err != nil || e != wantEmitted || d != wantDeleted {
			t.Fatalf("at %s: emitted %d deleted %d (%v), want %d and %d", now, e, d, err, wantEmitted, wantDeleted)
		}
	}
	ten := time.Date(2026, 3, 1, 10, 20, 0, 0, time.UTC)
	now = ten
	count(ten)
	count(ten)
	now = ten.Add(45 * time.Minute) // 11:05: the 10:00 hour is not 10 minutes over yet
	work(0, 0)
	now = ten.Add(50 * time.Minute) // 11:10
	work(1, 0)
	work(0, 0)
	ev := paritytest.Rows(t, wd.store, `SELECT json_extract(metadata, '$.bucketHour') AS hour, json_extract(metadata, '$.count') AS n, credential_id, actor_identity_id
		FROM audit_events WHERE event_type = 'security_control.would_block'`)
	if len(ev) != 1 || ev[0]["hour"] != "2026-03-01T10:00:00.000Z" || ev[0]["n"] != int64(2) || ev[0]["credential_id"] != nil || ev[0]["actor_identity_id"] != "idn_a" {
		t.Fatalf("summaries %v", ev)
	}
	// Late: decided at 10:20, counted at 11:15, after its hour's summary.
	now = ten.Add(55 * time.Minute)
	count(ten)
	hours := paritytest.Rows(t, wd.store, `SELECT bucket_hour, count, emitted_at IS NOT NULL AS emitted FROM security_control_counters ORDER BY bucket_hour`)
	if len(hours) != 2 || hours[0]["count"] != int64(2) || hours[1]["bucket_hour"] != time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC).UnixMicro() || hours[1]["count"] != int64(1) || hours[1]["emitted"] != int64(0) {
		t.Fatalf("buckets %v", hours)
	}
	now = ten.Add(110 * time.Minute) // 12:10
	work(1, 0)
	now = ten.Add(50*time.Minute + security.Retention) // 35 days after the first summary
	work(0, 1)
	// A deleted Organization's counts are never summarized, and go at once.
	count(now)
	wd.exec(`UPDATE organizations SET deleted_at = ? WHERE id = ?`, now.UnixMicro(), wd.org)
	now = now.Add(3 * time.Hour)
	work(0, 2)
}

// The report: the window's counts per control, the current hour's and the
// ones not summarized yet, entries by count, and the window bounded.
func TestControlReport(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 10, 12, 30, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	wd.setControl(security.AdminStepUp, security.Report, "", 1)
	add := func(at time.Time, operation string, n int) {
		var attempts []security.WouldBlock
		for range n {
			attempts = append(attempts, security.WouldBlock{Control: "admin-step-up", ConfigVersion: 1, Operation: operation, ActorIdentityID: "idn_a", Reason: "no-approval"})
		}
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
			return security.CountWouldBlock(ctx, tx, wd.org, attempts, at.UnixMicro(), func() time.Time { return at })
		}); err != nil {
			t.Fatal(err)
		}
	}
	add(now.Add(-26*time.Hour), "grant.create", 1)
	add(now.Add(-3*time.Hour), "grant.create", 1)
	add(now.Add(-2*time.Hour), "role.create", 1)
	add(now, "role.create", 3)
	if _, _, err := security.RunWorker(ctx, wd.w, clock); err != nil {
		t.Fatal(err)
	}
	report, err := security.ControlReportOf(ctx, wd.store.Reader(), wd.org, 1, clock)
	if err != nil {
		t.Fatal(err)
	}
	got := string(jsvalue.Stringify(report))
	for _, want := range []string{
		`"days":1,"since":"2026-03-09T12:00:00.000Z","generatedAt":"2026-03-10T12:30:00.000Z","summaryDelayMinutes":10`,
		`{"control":"admin-step-up","mode":"report","version":1,"total":5,"currentHour":3,"pending":3,"entries":[{"configVersion":1,"operation":"role.create","reason":"no-approval","actor":{"id":"idn_a","name":"Alice","kind":"human"},"count":4,`,
		`{"configVersion":1,"operation":"grant.create","reason":"no-approval","actor":{"id":"idn_a","name":"Alice","kind":"human"},"count":1,"firstSeen":"2026-03-10T09:30:00.000Z"`,
		`{"control":"credential-lifetime","mode":"off","version":0,"total":0,"currentHour":0,"pending":0,"entries":[]}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %s\n%s", want, got)
		}
	}
	for _, days := range []int64{0, 31} {
		if _, err := security.ControlReportOf(ctx, wd.store.Reader(), wd.org, days, clock); code(err) != "VALIDATION_FAILED" {
			t.Errorf("days %d: %v", days, err)
		}
	}
}

// The worker writes in several jobs (a batch of summaries each, then
// retention): a pass stopped after any job (a crash, a stop) leaves rows
// the next pass finishes, each summary written once, as each TypeScript
// batch is its own transaction.
func TestSummariesResumeAfterAnyJob(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 10, 20, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	for i, op := range []string{"grant.create", "role.create", "team.create"} {
		at := now.Add(time.Duration(i) * time.Minute)
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
			return security.CountWouldBlock(ctx, tx, wd.org, []security.WouldBlock{{Control: "admin-step-up", ConfigVersion: 1, Operation: op, ActorIdentityID: "idn_a", Reason: "no-approval"}}, at.UnixMicro(), clock)
		}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Hour)
	// One job of one row, then the process stops.
	if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
		n, err := security.EmitDueSummaries(ctx, tx, 1, clock)
		if err == nil && n != 1 {
			t.Errorf("first job emitted %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if e, _, err := security.RunWorker(ctx, wd.w, clock); err != nil || e != 2 {
		t.Fatalf("the next pass emitted %d (%v), want the other 2", e, err)
	}
	ev := paritytest.Rows(t, wd.store, `SELECT json_extract(metadata, '$.operation') AS op FROM audit_events WHERE event_type = 'security_control.would_block' ORDER BY event_order`)
	if len(ev) != 3 || ev[0]["op"] != "grant.create" || ev[1]["op"] != "role.create" || ev[2]["op"] != "team.create" {
		t.Fatalf("summaries %v", ev)
	}
}

// A clock moved back across an hour the worker already summarized loses no
// count (the TypeScript server drops it): the count goes to the hour after
// the last summarized one, and the summaries together carry every count.
func TestCountsSurviveAClockMovedBack(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	var now time.Time
	clock := func() time.Time { return now }
	count := func() {
		t.Helper()
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
			return security.CountWouldBlock(ctx, tx, wd.org, []security.WouldBlock{{Control: "admin-step-up", ConfigVersion: 1, Operation: "grant.create", ActorIdentityID: "idn_a", Reason: "no-approval"}}, now.UnixMicro(), clock)
		}); err != nil {
			t.Fatal(err)
		}
	}
	total := func() int64 {
		return paritytest.Rows(t, wd.store, `SELECT sum(count) AS n FROM security_control_counters`)[0]["n"].(int64)
	}
	ten := time.Date(2026, 3, 1, 10, 20, 0, 0, time.UTC)
	now = ten
	count()
	now = ten.Add(50 * time.Minute) // 11:10: the 10:00 hour is summarized
	if e, _, err := security.RunWorker(ctx, wd.w, clock); err != nil || e != 1 {
		t.Fatalf("emitted %d: %v", e, err)
	}
	now = ten // the clock moves back
	count()
	if got := total(); got != 2 {
		t.Fatalf("total %d after counting into a summarized hour, want 2", got)
	}
	// Further back, across two summarized hours: still kept.
	now = ten.Add(3 * time.Hour) // 13:20: 11:00 summarized
	if _, _, err := security.RunWorker(ctx, wd.w, clock); err != nil {
		t.Fatal(err)
	}
	now = ten.Add(time.Hour) // 11:20, in the summarized 11:00 hour
	count()
	hours := paritytest.Rows(t, wd.store, `SELECT bucket_hour, emitted_at IS NULL AS open FROM security_control_counters ORDER BY bucket_hour`)
	if len(hours) != 3 || hours[2]["bucket_hour"] != ten.Add(100*time.Minute).UnixMicro() || hours[2]["open"] != int64(1) {
		t.Fatalf("buckets %v: the count belongs in the open 12:00 hour", hours)
	}
	if got := total(); got != 3 {
		t.Fatalf("total %d, want 3", got)
	}
	now = ten.Add(6 * time.Hour)
	if _, _, err := security.RunWorker(ctx, wd.w, clock); err != nil {
		t.Fatal(err)
	}
	sum := paritytest.Rows(t, wd.store, `SELECT sum(json_extract(metadata, '$.count')) AS n, count(*) AS events FROM audit_events WHERE event_type = 'security_control.would_block'`)
	if sum[0]["n"] != int64(3) {
		t.Fatalf("the summaries carry %v counts in %v events, want 3", sum[0]["n"], sum[0]["events"])
	}
}
