// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// newWriter is a fresh database with an installation, two people, and an
// Organization "org_a" whose admin is idn_a.
func newWriter(t *testing.T) *Writer {
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
	exec(t, store,
		`INSERT INTO installation (id, kek_canary) VALUES ('inst_t', '{}')`,
		`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A'), ('idn_b', 'human', 'B')`,
		`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'a', 'A', '{}')`,
		`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('org_a', 'idn_a', 'admin')`,
	)
	return &Writer{Store: store, Gates: NewGates()}
}

func exec(t *testing.T, store *storage.DB, stmts ...string) {
	t.Helper()
	err := store.Write(context.Background(), func(tx *storage.Tx) error {
		for _, s := range stmts {
			if _, err := tx.ExecContext(context.Background(), s); err != nil {
				return errors.New(s + ": " + err.Error())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, store *storage.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// The checks inside a job, in lockLiveScope's order, with its refusals.
func TestCheckLive(t *testing.T) {
	w := newWriter(t)
	check := func(s Scope) error {
		return w.Store.Write(context.Background(), func(tx *storage.Tx) error { return CheckLive(context.Background(), tx, s) })
	}
	if err := check(Scope{OrganizationID: "org_a"}); err != nil {
		t.Fatal(err)
	}
	if err := check(Scope{OrganizationID: "org_none"}); code(err) != "RESOURCE_NOT_FOUND" || !strings.Contains(err.Error(), "Organization not found") {
		t.Errorf("unknown: %v", err)
	}
	exec(t, w.Store,
		`INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ('prj_a', 'org_a', 'p', 'P', 'managed')`,
		`INSERT INTO environments (id, project_id, name, kind, tier) VALUES ('env_a', 'prj_a', 'dev', 'shared', 'development'), ('env_b', 'prj_a', 'old', 'shared', 'development')`,
		`UPDATE environments SET deleted_at = 1 WHERE id = 'env_b'`,
	)
	if err := check(Scope{OrganizationID: "org_a", ProjectID: "prj_a", EnvironmentIDs: []string{"env_a", "env_a"}}); err != nil {
		t.Errorf("live scope: %v", err)
	}
	if err := check(Scope{OrganizationID: "org_a", ProjectID: "prj_a", EnvironmentIDs: []string{"env_a", "env_b"}}); code(err) != "RESOURCE_NOT_FOUND" || !strings.Contains(err.Error(), "Environment") {
		t.Errorf("deleted environment: %v", err)
	}
	if err := check(Scope{OrganizationID: "org_a", ProjectID: "prj_x"}); code(err) != "RESOURCE_NOT_FOUND" || !strings.Contains(err.Error(), "Project") {
		t.Errorf("unknown project: %v", err)
	}
	// An incident freeze refuses, unless the write names its exception.
	exec(t, w.Store, `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_1', 'org_a', 'idn_a', 1767225600000000, 'drill')`)
	var frozen *authz.FrozenError
	if err := check(Scope{OrganizationID: "org_a"}); !errors.As(err, &frozen) || frozen.FrozenAt != "2026-01-01T00:00:00.000Z" {
		t.Errorf("frozen: %v", err)
	}
	if err := check(Scope{OrganizationID: "org_a", DuringFreeze: authz.DuringFreezeRecovery}); err != nil {
		t.Errorf("frozen, recovery: %v", err)
	}
	// An open deletion refuses first, unless allowed.
	exec(t, w.Store, `INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) VALUES ('odl_1', 'org_a', 'idn_a', 1, 1767225600000000, 0)`)
	err := check(Scope{OrganizationID: "org_a"})
	var de *domainerr.Error
	if !errors.As(err, &de) || de.Code != "ORGANIZATION_DELETING" ||
		de.Message != "This Organization is being deleted: it may be deleted from 2026-01-01T00:00:00.000Z. Only reading, and approving or cancelling the deletion, are possible. Nothing was changed." ||
		string(jsvalue.Stringify(de.Details)) != `{"deletionId":"odl_1","runAfter":"2026-01-01T00:00:00.000Z"}` {
		t.Errorf("deleting: %v", err)
	}
	if err := check(Scope{OrganizationID: "org_a", AllowDeleting: true}); !errors.As(err, &frozen) {
		t.Errorf("deleting allowed, still frozen: %v", err)
	}
	exec(t, w.Store, `UPDATE organizations SET deleted_at = 2, wrapped_org_kek = NULL, org_kek_destroyed_at = 2 WHERE id = 'org_a'`)
	if err := check(Scope{OrganizationID: "org_a", AllowDeleting: true, DuringFreeze: authz.DuringFreezeRecovery}); code(err) != "RESOURCE_NOT_FOUND" {
		t.Errorf("deleted: %v", err)
	}
}

type vectors struct {
	Key        string `json:"key"`
	BodyHashes []struct {
		Name      string  `json:"name"`
		Body      *string `json:"body"`
		Undefined bool    `json:"undefined"`
		Hash      string  `json:"hash"`
	} `json:"bodyHashes"`
	Replays []struct {
		Name         string `json:"name"`
		Status       int    `json:"status"`
		First        string `json:"first"`
		Stored       string `json:"stored"`
		Replay       string `json:"replay"`
		ReplayStatus int    `json:"replayStatus"`
	} `json:"replays"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// bodyHash's digests, as the TypeScript server computes them
// (services/varlatchd/test/go-write-vectors.test.ts).
func TestBodyHashVectors(t *testing.T) {
	v := readVectors(t)
	key, err := hex.DecodeString(v.Key)
	if err != nil || len(key) != 32 {
		t.Fatalf("key: %v", err)
	}
	if len(v.BodyHashes) < 10 {
		t.Fatalf("%d vectors", len(v.BodyHashes))
	}
	for _, c := range v.BodyHashes {
		var body any
		if c.Body != nil {
			if body, err = jsvalue.Parse([]byte(*c.Body)); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		}
		if got := BodyHash(body, key); got != c.Hash {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Hash)
		}
	}
}

// A replay answers from the stored response with jsonb's member order, as
// the TypeScript server's does; the first answer keeps the route's.
func TestReplayVectors(t *testing.T) {
	v := readVectors(t)
	w := newWriter(t)
	ctx := context.Background()
	for i, c := range v.Replays {
		payload, err := jsvalue.Parse([]byte(c.First))
		if err != nil {
			t.Fatal(err)
		}
		claim := Claim{IdentityID: "idn_a", Endpoint: "vectors", Key: "k" + string(rune('0'+i)), Digest: "h"}
		run := func(tx *storage.Tx) (Response, error) { return Response{Status: c.Status, Payload: payload}, nil }
		first, replayed, err := Idempotent(ctx, w.Store, claim, nil, run)
		if err != nil || replayed || string(jsvalue.Stringify(first.Payload)) != c.First {
			t.Fatalf("%s: first %v %v %s", c.Name, err, replayed, jsvalue.Stringify(first.Payload))
		}
		var stored string
		if err := w.Store.Reader().QueryRow(`SELECT response FROM idempotency_keys WHERE idempotency_key = ?`, claim.Key).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if want, _ := jsvalue.Canonical([]byte(c.Stored)); stored != want {
			t.Errorf("%s: stored %s, want %s", c.Name, stored, want)
		}
		again, replayed, err := Idempotent(ctx, w.Store, claim, nil, func(tx *storage.Tx) (Response, error) {
			t.Fatal("the write ran again")
			return Response{}, nil
		})
		if err != nil || !replayed || again.Status != c.ReplayStatus || string(jsvalue.Stringify(again.Payload)) != c.Replay {
			t.Errorf("%s: replay %v %d %s, want %d %s", c.Name, err, again.Status, jsvalue.Stringify(again.Payload), c.ReplayStatus, c.Replay)
		}
		// A claim stored in another member order (copied from PostgreSQL,
		// whose text a copy need not keep) answers the same: the order is
		// jsonb's, applied on reading.
		parsed, err := jsvalue.Parse([]byte(stored))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE idempotency_keys SET response = ? WHERE idempotency_key = ?`, string(jsvalue.Stringify(reversed(parsed))), claim.Key)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		again, replayed, err = Idempotent(ctx, w.Store, claim, nil, func(tx *storage.Tx) (Response, error) {
			t.Fatal("the write ran again")
			return Response{}, nil
		})
		if err != nil || !replayed || string(jsvalue.Stringify(again.Payload)) != c.Replay {
			t.Errorf("%s: replay of a reordered claim %v %s, want %s", c.Name, err, jsvalue.Stringify(again.Payload), c.Replay)
		}
	}
}

// reversed is v with every object's members in reverse order.
func reversed(v any) any {
	switch x := v.(type) {
	case jsvalue.Object:
		o := make(jsvalue.Object, len(x))
		for i, m := range x {
			o[len(x)-1-i] = jsvalue.Member{Key: m.Key, Value: reversed(m.Value)}
		}
		return o
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = reversed(e)
		}
		return a
	}
	return v
}

// The claim, the write and the stored response are one job: a write that
// fails leaves no claim; another body is a conflict; a replay's own check
// (the checkpoint) can refuse it; a key over 200 UTF-16 units is refused
// before anything runs.
func TestIdempotent(t *testing.T) {
	w := newWriter(t)
	ctx := context.Background()
	claim := Claim{IdentityID: "idn_a", Endpoint: "PUT values env/A", Key: "key-1", Digest: "hmac-v1:1"}
	boom := domainerr.New("VERSION_CONFLICT", "no")
	_, _, err := Idempotent(ctx, w.Store, claim, nil, func(tx *storage.Tx) (Response, error) {
		if _, err := tx.ExecContext(ctx, `UPDATE organizations SET name = 'changed' WHERE id = 'org_a'`); err != nil {
			return Response{}, err
		}
		return Response{}, boom
	})
	if !errors.Is(err, boom) || count(t, w.Store, `SELECT count(*) FROM idempotency_keys`) != 0 || count(t, w.Store, `SELECT count(*) FROM organizations WHERE name = 'changed'`) != 0 {
		t.Fatalf("a failed write: %v", err)
	}
	runs := 0
	run := func(tx *storage.Tx) (Response, error) {
		runs++
		_, err := tx.ExecContext(ctx, `UPDATE organizations SET name = name || '+' WHERE id = 'org_a'`)
		return Response{Status: 200, Payload: jsvalue.Object{{Key: "n", Value: runs}}}, err
	}
	for range 3 {
		if _, _, err := Idempotent(ctx, w.Store, claim, nil, run); err != nil {
			t.Fatal(err)
		}
	}
	if runs != 1 || count(t, w.Store, `SELECT count(*) FROM organizations WHERE name = 'A+'`) != 1 {
		t.Errorf("ran %d times", runs)
	}
	other := claim
	other.Digest = "hmac-v1:2"
	if _, _, err := Idempotent(ctx, w.Store, other, nil, run); code(err) != "IDEMPOTENCY_CONFLICT" || err.Error() != "IDEMPOTENCY_CONFLICT: Idempotency key reused with a different request body" {
		t.Errorf("conflict: %v", err)
	}
	refused := domainerr.New("PASSKEY_VERIFICATION_REQUIRED", "x")
	if _, _, err := Idempotent(ctx, w.Store, claim, func(*storage.Tx) error { return refused }, run); !errors.Is(err, refused) {
		t.Errorf("replay refused: %v", err)
	}
	// Another person's key, or another endpoint's, is another claim.
	for _, c := range []Claim{{IdentityID: "idn_b", Endpoint: claim.Endpoint, Key: claim.Key, Digest: "x"}, {IdentityID: "idn_a", Endpoint: "other", Key: claim.Key, Digest: "x"}} {
		if _, replayed, err := Idempotent(ctx, w.Store, c, nil, run); err != nil || replayed {
			t.Errorf("%+v: %v %v", c, err, replayed)
		}
	}
	long := claim
	long.Key = strings.Repeat("😀", 100) + "x" // 201 UTF-16 units
	if _, _, err := Idempotent(ctx, w.Store, long, nil, run); code(err) != "VALIDATION_FAILED" || !strings.Contains(err.Error(), "Idempotency-Key exceeds 200 characters") {
		t.Errorf("long key: %v", err)
	}
	long.Key = strings.Repeat("😀", 100)
	if _, _, err := Idempotent(ctx, w.Store, long, nil, run); err != nil {
		t.Errorf("200 units: %v", err)
	}
	if runs != 4 {
		t.Errorf("ran %d times", runs)
	}
}

// Concurrent requests with one key: exactly one write, every answer the
// same (the claim is checked and written in one job on the single writer).
func TestIdempotentConcurrent(t *testing.T) {
	w := newWriter(t)
	ctx := context.Background()
	claim := Claim{IdentityID: "idn_a", Endpoint: "e", Key: "k", Digest: "d"}
	var mu sync.Mutex
	runs := 0
	var wg sync.WaitGroup
	answers := make(chan string, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _, err := Idempotent(ctx, w.Store, claim, nil, func(tx *storage.Tx) (Response, error) {
				mu.Lock()
				runs++
				mu.Unlock()
				_, err := audit.Record(ctx, tx, audit.Event{Type: "organization.renamed", Decision: audit.Info, OrganizationID: ptr("org_a")})
				return Response{Status: 200, Payload: jsvalue.Object{{Key: "id", Value: "x"}}}, err
			})
			if err != nil {
				t.Error(err)
			}
			answers <- string(jsvalue.Stringify(r.Payload))
		}()
	}
	wg.Wait()
	close(answers)
	for a := range answers {
		if a != `{"id":"x"}` {
			t.Errorf("answer %s", a)
		}
	}
	if runs != 1 || count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'organization.renamed'`) != 1 {
		t.Errorf("%d runs", runs)
	}
}

func ptr(s string) *string { return &s }

// PostgreSQL's text: U+0000 refused, a lone surrogate stored as U+FFFD.
func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                    "plain",
		"héllo ✓ 𝄞":                "héllo ✓ 𝄞",
		"a\xed\xa0\x80b":           "a�b",
		"\xed\xa0\x80\xed\xb0\x80": "��", // two surrogate sequences, each one U+FFFD
		"x\xffy":                   "x�y",
	} {
		if got, err := Text(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := Text("a\x00b"); !errors.Is(err, ErrPostgresText) {
		t.Errorf("U+0000: %v", err)
	}
	// An idempotent response jsonb would refuse fails the write with it.
	w := newWriter(t)
	_, _, err := Idempotent(context.Background(), w.Store, Claim{IdentityID: "idn_a", Endpoint: "e", Key: "k", Digest: "d"}, nil, func(tx *storage.Tx) (Response, error) {
		_, err := tx.ExecContext(context.Background(), `UPDATE organizations SET name = 'changed' WHERE id = 'org_a'`)
		return Response{Status: 200, Payload: jsvalue.Object{{Key: "v", Value: "a\x00b"}}}, err
	})
	if err == nil || count(t, w.Store, `SELECT count(*) FROM organizations WHERE name = 'changed'`) != 0 || count(t, w.Store, `SELECT count(*) FROM idempotency_keys`) != 0 {
		t.Errorf("a response with U+0000: %v", err)
	}
}
