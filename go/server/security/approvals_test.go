// SPDX-License-Identifier: AGPL-3.0-or-later

package security_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/write"
)

// stepUp asks for an approval of b as alice's CLI credential: its id.
func (wd *world) stepUp(b auth.Binding) string {
	wd.t.Helper()
	err := wd.approvals.StepUpRequired(context.Background(), auth.RequesterOf(alice()), b)
	view, _ := detail(err, "approval").(jsvalue.Object)
	id, _ := view.Get("id")
	if code(err) != "STEP_UP_REQUIRED" || id == nil {
		wd.t.Fatalf("%v", err)
	}
	return id.(string)
}

func (wd *world) binding(operation string, target map[string]string) auth.Binding {
	org := wd.org
	return auth.Binding{Operation: operation, OrganizationID: &org, Target: target, Query: map[string]string{}, Summary: auth.ApprovalSummary{Title: operation}}
}

// The account writers the TypeScript code runs under the person's row FOR
// UPDATE take the person's gate exclusive (decision 4): starting,
// approving and cancelling an approval, confirming and removing a passkey.
// Each waits while an external effect holds the person across its call,
// and runs once the effect ended.
func TestAccountWritersWaitForAnEffectHoldingThePerson(t *testing.T) {
	for name, run := range map[string]func(wd *world, id string) error{
		"cancel an approval": func(wd *world, id string) error {
			_, err := wd.approvals.CancelApproval(context.Background(), "idn_a", id)
			return err
		},
		"remove a passkey": func(wd *world, _ string) error {
			err := wd.approvals.RemoveOwnPasskey(context.Background(), auth.RequesterOf(alice()), "pk_missing", "")
			if code(err) == "RESOURCE_NOT_FOUND" {
				return nil
			}
			return err
		},
		"start a confirmation": func(wd *world, _ string) error {
			_, err := wd.approvals.StartConfirmation(context.Background(), "idn_a", "ses_1", "pk_missing")
			if err != nil {
				return nil // refused, after the gate: no relying party, or no such passkey
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			wd := newWorld(t)
			id := wd.stepUp(wd.binding("grant.create", map[string]string{"grantId": "grt_1"}))
			ctx := context.Background()
			called, release := make(chan struct{}), make(chan struct{})
			effectDone := make(chan error, 1)
			go func() {
				_, _, err := write.RunEffect(ctx, wd.w, write.Effect[int, int]{
					OrganizationID: wd.org, People: []write.Gate{write.Person("idn_a", write.Shared)},
					Call:  func(context.Context) (int, error) { close(called); <-release; return 0, nil },
					Final: func(context.Context, *storage.Tx, int) (int, error) { return 0, nil },
				})
				effectDone <- err
			}()
			<-called
			waiting := make(chan struct{})
			var once sync.Once
			wd.w.Gates.Observe(func(event string, g write.Gate) {
				if event == "waiting" && g.Level == write.LevelPerson && g.Mode == write.Exclusive {
					once.Do(func() { close(waiting) })
				}
			})
			done := make(chan error, 1)
			go func() { done <- run(wd, id) }()
			<-waiting
			select {
			case err := <-done:
				t.Fatalf("finished during the effect's call: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			if err := <-effectDone; err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// precheckApproval finds an approved intent for exactly the request
// without consuming it; closeOpenApprovals closes the intents its filter
// selects: a control's changes and the operations it asks approvals for.
func TestPrecheckAndCloseApprovals(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	req := auth.RequesterOf(alice())
	grant := wd.binding("grant.create", map[string]string{"grantId": "grt_1"})
	id := wd.stepUp(grant)
	if err := wd.approvals.PrecheckApproval(ctx, wd.store.Reader(), req, id, grant); code(err) != "APPROVAL_INVALID" || detail(err, "reason") != "pending" {
		t.Fatalf("pending: %v", err)
	}
	wd.exec(`UPDATE approval_intents SET approved_at = ?, approved_with_passkey_id = 'pk_1', approval_user_verified = 1 WHERE id = ?`, time.Now().UnixMicro(), id)
	if err := wd.approvals.PrecheckApproval(ctx, wd.store.Reader(), req, id, grant); err != nil {
		t.Fatalf("approved: %v", err)
	}
	if err := wd.approvals.PrecheckApproval(ctx, wd.store.Reader(), req, id, wd.binding("grant.create", map[string]string{"grantId": "grt_2"})); code(err) != "APPROVAL_INVALID" || detail(err, "reason") != "mismatch" {
		t.Fatalf("another target: %v", err)
	}
	var used auth.UsedApproval
	if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
		var err error
		used, err = wd.approvals.ConsumeApproval(ctx, tx, req, id, grant)
		return err
	}); err != nil || used.ID != id {
		t.Fatalf("the precheck consumed nothing: %v", err)
	}

	stepUp := wd.stepUp(wd.binding("security_control.change", map[string]string{"control": "admin-step-up"}))
	requirement := wd.stepUp(wd.binding("security_control.change", map[string]string{"control": "requirement-protection"}))
	gated := wd.stepUp(wd.binding("role.create", map[string]string{}))
	revoke := wd.stepUp(wd.binding("requirement.revoke", map[string]string{"requirementId": "req_1"}))
	closeWith := func(controls, operations []string) int {
		var n int
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
			var err error
			n, err = wd.approvals.CloseOpenApprovals(ctx, tx, wd.org, auth.CloseReset, controls, operations)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := closeWith([]string{"admin-step-up"}, nil); n != 2 {
		t.Fatalf("closed %d, want admin-step-up's change and role.create", n)
	}
	if n := closeWith(nil, []string{"requirement.revoke"}); n != 1 {
		t.Fatalf("closed %d by operation", n)
	}
	state := map[string]any{}
	for _, r := range paritytest.Rows(t, wd.store, `SELECT id, close_reason FROM approval_intents`) {
		state[r["id"].(string)] = r["close_reason"]
	}
	if state[stepUp] != "reset" || state[gated] != "reset" || state[revoke] != "reset" || state[requirement] != nil || state[id] != nil {
		t.Fatalf("intents %v", state)
	}
}
