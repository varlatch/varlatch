// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/projects"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// target is the route's view of an environment of acme/api, read now.
func (wd *world) target(env string) values.Target {
	wd.t.Helper()
	ctx := context.Background()
	project, err := projects.Get(ctx, wd.store.Reader(), wd.org, "api")
	if err != nil {
		wd.t.Fatal(err)
	}
	e, err := environments.Get(ctx, wd.store.Reader(), project.ID, env)
	if err != nil {
		wd.t.Fatal(err)
	}
	return values.Target{OrganizationID: wd.org, Project: project, Env: e}
}

// rotationState is an item's value row and its current version's
// predecessor.
type rotationState struct {
	current, retiring, previous sql.NullString
	deadline, started           sql.NullInt64
}

func (wd *world) rotationState(item string) rotationState {
	wd.t.Helper()
	var s rotationState
	if err := wd.store.Reader().QueryRow(`SELECT v.current_version_id, v.retiring_version_id, v.rotation_deadline, v.rotation_started_at, vv.previous_version_id
		FROM env_values v JOIN value_versions vv ON vv.id = v.current_version_id
		JOIN environments e ON e.id = v.environment_id WHERE e.name = 'dev' AND v.item_name = ?`, item).
		Scan(&s.current, &s.retiring, &s.deadline, &s.started, &s.previous); err != nil {
		wd.t.Fatal(err)
	}
	return s
}

// The states domain/values.ts allows a value row: no rotation (the
// retiring version, deadline and start all empty), or one in flight (all
// three set, the retiring version the current one's predecessor, the
// deadline after the start).
func allowed(s rotationState) bool {
	none := !s.retiring.Valid && !s.deadline.Valid && !s.started.Valid
	flight := s.retiring.Valid && s.deadline.Valid && s.started.Valid && s.previous.Valid &&
		s.retiring.String == s.previous.String && s.deadline.Int64 > s.started.Int64
	return none || flight
}

// Begin, complete and a plain write racing on one item: whatever order the
// single writer commits them in, the row is always in a state the
// TypeScript code allows, a begin succeeds only when no rotation is in
// flight (else ROTATION_IN_PROGRESS), and the committed events replayed in
// order give the final row: the last of value.rotation_started,
// value.rotation_completed and value.written decides whether a rotation
// is in flight.
func TestRotationRaces(t *testing.T) {
	wd := newWorld(t)
	wd.set("dev", "TOKEN", "v0")
	tgt := wd.target("dev")
	ctx := context.Background()
	const rounds = 30
	var refused, begun, completed, written int
	for round := range rounds {
		var wg sync.WaitGroup
		results := make([]error, 3)
		ops := []func() error{
			func() error {
				_, _, err := values.BeginRotation(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.RotationInput{Value: "rotated"}, time.Now)
				return err
			},
			func() error {
				_, _, err := values.CompleteRotation(ctx, wd.w, alice(), tgt, "TOKEN", time.Now)
				return err
			},
			func() error {
				_, _, _, err := values.SetValue(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.SetInput{Value: "plain"}, write.Claim{IdentityID: "idn_a"}, time.Now)
				return err
			},
		}
		// Rotate first in odd rounds (after ending any rotation the last
		// round left), so some begins meet a rotation in flight.
		if round%2 == 1 {
			if _, _, err := values.CompleteRotation(ctx, wd.w, alice(), tgt, "TOKEN", time.Now); err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			if _, _, err := values.BeginRotation(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.RotationInput{Value: "first"}, time.Now); err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		// The launch order varies by round; the writer's commit order is
		// whatever the race gives.
		for k := range ops {
			i := (k + round) % len(ops)
			wg.Add(1)
			go func() { defer wg.Done(); results[i] = ops[i]() }()
		}
		wg.Wait()
		var de *domainerr.Error
		switch err := results[0]; {
		case err == nil:
			begun++
		case errors.As(err, &de) && de.Code == "ROTATION_IN_PROGRESS":
			refused++
		default:
			t.Fatalf("round %d: begin: %v", round, err)
		}
		if results[1] != nil || results[2] != nil {
			t.Fatalf("round %d: complete %v, write %v", round, results[1], results[2])
		}
		completed++
		written++
		if s := wd.rotationState("TOKEN"); !allowed(s) {
			t.Fatalf("round %d: a state the TypeScript code does not allow: %+v", round, s)
		}
	}
	if begun == 0 {
		t.Fatal("no begin ever committed")
	}

	// Replay the committed events, in commit order, against the rules.
	rows, err := wd.store.Reader().Query(`SELECT event_type, resource FROM audit_events
		WHERE event_type IN ('value.written', 'value.rotation_started', 'value.rotation_completed') ORDER BY event_order`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	inFlight, current := false, ""
	for rows.Next() {
		var typ, resource string
		if err := rows.Scan(&typ, &resource); err != nil {
			t.Fatal(err)
		}
		var r struct{ VersionID, PreviousVersionID string }
		if err := json.Unmarshal([]byte(resource), &r); err != nil {
			t.Fatal(err)
		}
		switch typ {
		case "value.written":
			inFlight, current = false, r.VersionID
		case "value.rotation_started":
			if inFlight {
				t.Fatalf("a rotation began while one was in flight: %s", resource)
			}
			if r.PreviousVersionID != current {
				t.Fatalf("a rotation retired %s, the current version was %s", r.PreviousVersionID, current)
			}
			inFlight, current = true, r.VersionID
		case "value.rotation_completed":
			if !inFlight || r.VersionID != current {
				t.Fatalf("a completion with no rotation in flight, or of another version: %s", resource)
			}
			inFlight = false
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	s := wd.rotationState("TOKEN")
	if s.current.String != current || s.retiring.Valid != inFlight {
		t.Fatalf("the row %+v is not what the events give (current %s, in flight %v)", s, current, inFlight)
	}
	t.Logf("%d begins, %d refused, %d completions, %d writes", begun, refused, completed, written)
}

// A begin during a rotation in flight is refused and changes nothing; one
// past its deadline is over: another may begin; completing one clears the
// pinned version, and completing again changes nothing.
func TestRotationInFlightAndPastItsWindow(t *testing.T) {
	wd := newWorld(t)
	wd.set("dev", "TOKEN", "v0")
	tgt := wd.target("dev")
	ctx := context.Background()
	if _, _, err := values.BeginRotation(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.RotationInput{Value: "v1"}, time.Now); err != nil {
		t.Fatal(err)
	}
	// In flight: another begin is refused, and changes nothing.
	before := wd.rotationState("TOKEN")
	var de *domainerr.Error
	if _, _, err := values.BeginRotation(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.RotationInput{Value: "v1b"}, time.Now); !errors.As(err, &de) || de.Code != "ROTATION_IN_PROGRESS" {
		t.Fatalf("a begin during a rotation: %v", err)
	}
	if after := wd.rotationState("TOKEN"); after != before {
		t.Fatalf("a refused begin changed the row: %+v, before %+v", after, before)
	}
	if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE env_values SET rotation_started_at = 500000, rotation_deadline = 1000000 WHERE item_name = 'TOKEN'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !allowed(wd.rotationState("TOKEN")) {
		t.Fatal("the past rotation is not an allowed state")
	}
	if _, _, err := values.BeginRotation(ctx, wd.w, wd.rootKEK, alice(), tgt, "TOKEN", values.RotationInput{Value: "v2"}, time.Now); err != nil {
		t.Fatalf("a rotation past its window refused another: %v", err)
	}
	if _, _, err := values.CompleteRotation(ctx, wd.w, alice(), tgt, "TOKEN", time.Now); err != nil {
		t.Fatal(err)
	}
	if s := wd.rotationState("TOKEN"); s.retiring.Valid || s.deadline.Valid || s.started.Valid {
		t.Fatalf("completed: %+v", s)
	}
	answer, _, err := values.CompleteRotation(ctx, wd.w, alice(), tgt, "TOKEN", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := answer.Get("itemName"); v != "TOKEN" {
		t.Fatalf("a second completion: %v", answer)
	}
}
