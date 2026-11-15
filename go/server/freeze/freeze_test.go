// SPDX-License-Identifier: AGPL-3.0-or-later

package freeze_test

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
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/freeze"
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
	public, _ := url.Parse("http://127.0.0.1:8686")
	wd.approvals = auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK, PersonGate: wd.w.Gates.PersonGate})
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func get(o jsvalue.Object, key string) any { v, _ := o.Get(key); return v }

func (wd *world) freeze(reason string) (jsvalue.Object, error) {
	out, _, err := freeze.Freeze(context.Background(), wd.w, wd.approvals, freeze.FreezeInput{OrganizationID: wd.org, Principal: alice(), Reason: reason, RequestID: "req_f"}, time.Now)
	return out, err
}

func (wd *world) lift(id, approval string) (jsvalue.Object, error) {
	return security.WithApproval(context.Background(), wd.approvals, auth.RequesterOf(alice()), func() (jsvalue.Object, error) {
		out, _, err := freeze.Lift(context.Background(), wd.w, wd.approvals, freeze.LiftInput{OrganizationID: wd.org, FreezeID: id, Principal: alice(), ApprovalID: approval, RequestID: "req_l"}, time.Now)
		return out, err
	})
}

func (wd *world) intents(where string) int64 {
	return paritytest.Rows(wd.t, wd.store, `SELECT count(*) AS n FROM approval_intents WHERE `+where)[0]["n"].(int64)
}

// Freezing, then lifting with the approval bound to that freeze: the
// freeze closes every open intent, a second freeze is STATE_CHANGED, the
// reason is trimmed and bounded, a machine never freezes; the lift needs
// its approval, then lifts once.
func TestFreezeAndLift(t *testing.T) {
	wd := newWorld(t)
	org := wd.org
	// An open intent of the Organization, closed by the freeze.
	if err := wd.approvals.StepUpRequired(context.Background(), auth.RequesterOf(alice()), auth.Binding{Operation: "grant.create", OrganizationID: &org,
		Target: map[string]string{}, Query: map[string]string{}, Summary: auth.ApprovalSummary{Title: "x"}}); code(err) != "STEP_UP_REQUIRED" {
		t.Fatal(err)
	}
	if _, err := wd.freeze("   "); code(err) != "VALIDATION_FAILED" {
		t.Fatalf("blank reason: %v", err)
	}
	if _, err := wd.freeze(strings.Repeat("😀", 101)); code(err) != "VALIDATION_FAILED" {
		t.Fatalf("201 UTF-16 units: %v", err)
	}
	m := &auth.Principal{Identity: auth.Identity{ID: "idn_m", Kind: "service", OrganizationID: &org}, Credential: auth.Credential{ID: "crd_m", Kind: "service"}}
	if _, _, err := freeze.Freeze(context.Background(), wd.w, wd.approvals, freeze.FreezeInput{OrganizationID: org, Principal: m, Reason: "x"}, time.Now); code(err) != "PERMISSION_DENIED" {
		t.Fatalf("a machine: %v", err)
	}
	f, err := wd.freeze("  incident drill  ")
	if err != nil {
		t.Fatal(err)
	}
	if get(f, "reason") != "incident drill" || get(f, "liftedAt") != nil {
		t.Fatalf("freeze %s", jsvalue.Stringify(f))
	}
	if wd.intents(`closed_at IS NOT NULL AND close_reason = 'frozen'`) != 1 {
		t.Fatal("the open intent was not closed")
	}
	if _, err := wd.freeze("again"); code(err) != "STATE_CHANGED" {
		t.Fatalf("frozen twice: %v", err)
	}
	id := get(f, "id").(string)
	if _, err := wd.lift("ofz_nope", ""); code(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("unknown freeze: %v", err)
	}
	_, err = wd.lift(id, "")
	if code(err) != "STEP_UP_REQUIRED" {
		t.Fatalf("no approval: %v", err)
	}
	var de *domainerr.Error
	errors.As(err, &de)
	approval := get(get(de.Details, "approval").(jsvalue.Object), "id").(string)
	wd.exec(`UPDATE approval_intents SET approved_at = ?, approved_with_passkey_id = 'pk_1', approval_user_verified = 1 WHERE id = ?`, time.Now().UnixMicro(), approval)
	out, err := wd.lift(id, approval)
	if err != nil {
		t.Fatal(err)
	}
	if lifted := get(out, "freeze").(jsvalue.Object); get(lifted, "liftMethod") != "approval" || get(out, "resumingTargets") != nil {
		t.Fatalf("lift %s", jsvalue.Stringify(out))
	}
	if _, err := wd.lift(id, approval); code(err) != "STATE_CHANGED" {
		t.Fatalf("lifted twice: %v", err)
	}
}

// The host operator's lift and reset: --confirm repeats the slug; a lift
// closes the open lift intents only; the reset turns the named controls
// off, closes their intents and says the freeze stays.
func TestOperatorUnfreezeAndReset(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	if _, err := freeze.OperatorUnfreeze(ctx, wd.w, wd.approvals, "acme", "acme", time.Now); code(err) != "STATE_CHANGED" {
		t.Fatalf("not frozen: %v", err)
	}
	f, err := wd.freeze("drill")
	if err != nil {
		t.Fatal(err)
	}
	wd.exec(`INSERT INTO security_controls (organization_id, control, mode, version) VALUES (?, 'admin-step-up', 'enforce', 4), (?, 'requirement-protection', 'report', 2)`, wd.org, wd.org)
	if _, err := wd.lift(get(f, "id").(string), ""); code(err) != "STEP_UP_REQUIRED" {
		t.Fatal(err)
	}
	reset, err := security.ResetControls(ctx, wd.w, wd.approvals, wd.org, []string{"admin-step-up", "credential-lifetime"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reset.Lines(), "\n"); !strings.Contains(got, "  admin-step-up: enforce -> off (version 5)\n  credential-lifetime: already off\nOpen approvals closed: 0.") ||
		!strings.Contains(got, "acme is still frozen for an incident") {
		t.Fatalf("reset:\n%s", got)
	}
	if st, _ := security.Read(ctx, wd.store.Reader(), wd.org, "requirement-protection"); st.Mode != "report" {
		t.Fatalf("an unnamed control changed: %+v", st)
	}
	if _, err := freeze.OperatorUnfreeze(ctx, wd.w, wd.approvals, wd.org, "wrong", time.Now); code(err) != "VALIDATION_FAILED" {
		t.Fatalf("confirm: %v", err)
	}
	out, err := freeze.OperatorUnfreeze(ctx, wd.w, wd.approvals, "acme", "acme", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if out.ApprovalsClosed != 1 || get(out.Freeze, "liftMethod") != "operator" || !strings.Contains(strings.Join(out.Lines(), "\n"), "No Sync Target resumes pushing.") {
		t.Fatalf("unfreeze %+v", out)
	}
	ev := paritytest.Rows(t, wd.store, `SELECT actor_identity_id AS actor, json_extract(metadata, '$.method') AS method FROM audit_events WHERE event_type = 'organization.unfrozen'`)
	if len(ev) != 1 || ev[0]["actor"] != nil || ev[0]["method"] != "operator" {
		t.Fatalf("audit %v", ev)
	}
}

// The Organization's exclusive takers (decision 4), each against an
// external effect holding the Organization across its call: freezing,
// lifting, the operator's lift and reset, and a control change all wait,
// and run once the effect ended.
func TestOrganizationTakersWaitForAnEffect(t *testing.T) {
	for name, run := range map[string]func(wd *world, freezeID string) error{
		"freeze": func(wd *world, _ string) error {
			_, err := wd.freeze("drill")
			return err
		},
		"lift": func(wd *world, id string) error {
			_, err := wd.lift(id, "")
			if code(err) == "STEP_UP_REQUIRED" {
				return nil
			}
			return err
		},
		"operator unfreeze": func(wd *world, _ string) error {
			_, err := freeze.OperatorUnfreeze(context.Background(), wd.w, wd.approvals, "acme", "acme", time.Now)
			return err
		},
		"reset": func(wd *world, _ string) error {
			_, err := security.ResetControls(context.Background(), wd.w, wd.approvals, "acme", nil, time.Now)
			return err
		},
		"control change": func(wd *world, _ string) error {
			mode := security.Report
			_, _, err := security.ChangeControl(context.Background(), wd.w, wd.approvals, security.ChangeInput{
				OrganizationID: wd.org, Control: security.RequirementProtection, Mode: &mode, Config: security.ConfigChange{Keep: true},
				Principal: alice(), RequestID: "req_c",
			}, time.Now)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
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
			select {
			case <-called:
			case err := <-effectDone:
				t.Fatalf("the effect did not reach its call: %v", err)
			}
			// The lifts need a freeze to lift. One cannot start while the
			// effect holds the Organization (a freeze waits for it), so its row
			// is written straight to the database here.
			freezeID := "ofz_aaaaaaaaaaaaaaaaaaaaaaaaaa"
			if freezeWritten(name) {
				wd.exec(`INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES (?, ?, 'idn_a', ?, 'drill')`,
					freezeID, wd.org, time.Now().UnixMicro())
			}
			f := jsvalue.Object{{Key: "id", Value: freezeID}}
			waiting := make(chan struct{})
			var once sync.Once
			wd.w.Gates.Observe(func(event string, g write.Gate) {
				if event == "waiting" && g.Level == write.LevelOrganization && g.Mode == write.Exclusive {
					once.Do(func() { close(waiting) })
				}
			})
			done := make(chan error, 1)
			go func() { done <- run(wd, get(f, "id").(string)) }()
			<-waiting
			select {
			case err := <-done:
				t.Fatalf("finished during the effect's call: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			// With the freeze written meanwhile, the effect's final job refuses,
			// as it would after any freeze: nothing of it is kept.
			if err := <-effectDone; err != nil && !(freezeWritten(name) && code(err) == "ORGANIZATION_FROZEN") {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func freezeWritten(name string) bool { return name == "lift" || name == "operator unfreeze" }
