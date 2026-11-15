// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/projects"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// retrieval-consistency (ADR-0038 Decision 6): a retrieval reads one
// snapshot. A write that commits while a retrieval is between two of its
// reads is invisible to it, never half-applied; the next retrieval sees
// it. The TypeScript test springs a trap on the snapshot's connection;
// here values.WithReadHook runs the write at the same points, through the
// single writer, while the retrieval's read transaction is open.

type world struct {
	t       *testing.T
	store   *storage.DB
	w       *write.Writer
	rootKEK []byte
	svc     *values.Service
	org     string
	project projects.Project
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
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
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := projects.Create(ctx, w, alice(), org.ID, "api", "API", "git", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	wd := &world{t: t, store: store, w: w, rootKEK: rootKEK, svc: values.New(store, rootKEK, values.Options{}), org: org.ID, project: p}
	t.Cleanup(wd.svc.Settled)
	tier := "development"
	if _, _, err := environments.Create(ctx, w, alice(), org.ID, p.ID, environments.Input{Name: "dev", Tier: &tier}, time.Now); err != nil {
		t.Fatal(err)
	}
	parent := "dev"
	if _, _, err := environments.Create(ctx, w, alice(), org.ID, p.ID, environments.Input{Name: "dev/child", ParentEnvironmentID: &parent}, time.Now); err != nil {
		t.Fatal(err)
	}
	return wd
}

// set writes a value through the single writer, as the route does.
func (wd *world) set(env, item, value string) {
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
	if _, _, _, err := values.SetValue(ctx, wd.w, wd.rootKEK, alice(), values.Target{OrganizationID: wd.org, Project: project, Env: e},
		item, values.SetInput{Value: value}, write.Claim{IdentityID: "idn_a"}, time.Now); err != nil {
		wd.t.Fatal(err)
	}
}

// contract pushes and activates a Contract of non-sensitive string items,
// with the named ones sensitive.
func (wd *world) contract(items []string, sensitive ...string) {
	wd.t.Helper()
	ctx := context.Background()
	list := make([]any, 0, len(items))
	for _, name := range items {
		s := false
		for _, x := range sensitive {
			s = s || x == name
		}
		list = append(list, jsvalue.Object{{Key: "name", Value: name}, {Key: "required", Value: jsvalue.Object{{Key: "kind", Value: "never"}}},
			{Key: "sensitive", Value: s}, {Key: "type", Value: "string"}})
	}
	rev, _, err := contracts.Push(ctx, wd.w, alice(), wd.org, wd.project.ID, jsvalue.Object{{Key: "schemaVersion", Value: 1.0}, {Key: "items", Value: list}}, nil)
	if err != nil {
		wd.t.Fatal(err)
	}
	if _, _, err := contracts.Activate(ctx, wd.w, alice(), wd.org, wd.project.ID, rev.ID); err != nil {
		wd.t.Fatal(err)
	}
}

// read is GET …/effective-configuration?include=values: each item's
// value (nil when withheld) and sensitivity, by name.
func (wd *world) read(ctx context.Context, p *auth.Principal, env string) (map[string]any, map[string]bool, error) {
	out, err := wd.svc.EffectiveConfiguration(ctx, values.Request{
		Principal: p, RequestID: "req_test", Method: "GET",
		Route: "/v1/organizations/:org/projects/:project/environments/:environment/effective-configuration",
		Org:   "acme", Project: "api", Environment: env,
	}, true, nil)
	if err != nil {
		return nil, nil, err
	}
	items, _ := out.Get("items")
	vals, sens := map[string]any{}, map[string]bool{}
	for _, it := range items.([]any) {
		o := it.(jsvalue.Object)
		name, _ := o.Get("name")
		v, _ := o.Get("value")
		s, _ := o.Get("sensitive")
		vals[name.(string)], sens[name.(string)] = v, s.(bool)
	}
	return vals, sens, nil
}

// once is a hook that runs fn the first time a retrieval reaches point;
// the test fails at its end unless it ran.
func once(t *testing.T, point string, fn func()) func(string) {
	var o sync.Once
	ran := false
	t.Cleanup(func() {
		if !ran {
			t.Errorf("no retrieval reached %q", point)
		}
	})
	return func(at string) {
		if at == point {
			o.Do(func() { ran = true; fn() })
		}
	}
}

const betweenValueReads = "between the environment's values and its parent's"

// A parent's write between the derived environment's two value reads is
// invisible to that retrieval; the next one sees it.
func TestParentWriteBetweenReadsIsInvisible(t *testing.T) {
	wd := newWorld(t)
	wd.contract([]string{"API_URL", "OWN"})
	wd.set("dev", "API_URL", "v1")
	wd.set("dev/child", "OWN", "mine")
	ctx := values.WithReadHook(context.Background(), once(t, betweenValueReads, func() { wd.set("dev", "API_URL", "v2") }))
	got, _, err := wd.read(ctx, alice(), "dev/child")
	if err != nil {
		t.Fatal(err)
	}
	if got["API_URL"] != "v1" || got["OWN"] != "mine" {
		t.Fatalf("in flight: %v", got)
	}
	if got, _, _ := wd.read(context.Background(), alice(), "dev/child"); got["API_URL"] != "v2" {
		t.Fatalf("after: %v", got)
	}
}

// A Contract activation between reads is invisible: sensitivity and
// values come from one revision.
func TestActivationBetweenReadsIsInvisible(t *testing.T) {
	wd := newWorld(t)
	wd.contract([]string{"TOKEN"})
	wd.set("dev", "TOKEN", "t1")
	ctx := values.WithReadHook(context.Background(), once(t, betweenValueReads, func() { wd.contract([]string{"TOKEN"}, "TOKEN") }))
	got, sens, err := wd.read(ctx, alice(), "dev/child")
	if err != nil {
		t.Fatal(err)
	}
	if sens["TOKEN"] || got["TOKEN"] != "t1" {
		t.Fatalf("in flight: %v %v", got, sens)
	}
	got, sens, _ = wd.read(context.Background(), alice(), "dev/child")
	if !sens["TOKEN"] || got["TOKEN"] != nil {
		t.Fatalf("after: %v %v", got, sens)
	}
}

// A grant revoked after the retrieval's snapshot began does not affect
// that retrieval; the next is refused.
func TestRevocationAfterTheSnapshotBegan(t *testing.T) {
	wd := newWorld(t)
	wd.contract([]string{"API_URL"})
	wd.set("dev", "API_URL", "v1")
	ctx := context.Background()
	exec := func(stmt string, args ...any) {
		if err := wd.store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, stmt, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_ci', 'service', 'ci', ?)`, wd.org)
	exec(`INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions) VALUES ('grt_ci', ?, 'idn_ci', ?, '["config.metadata.read","config.value.read"]')`,
		wd.org, `{"kind":"project","projectId":"`+wd.project.ID+`"}`)
	org := wd.org
	ci := &auth.Principal{Identity: auth.Identity{ID: "idn_ci", Kind: "service", OrganizationID: &org}, Credential: auth.Credential{ID: "crd_ci", Kind: auth.KindService}}
	hooked := values.WithReadHook(ctx, once(t, "after the scope, before authorization", func() {
		exec(`UPDATE grants SET revoked_at = 1 WHERE id = 'grt_ci'`)
	}))
	got, _, err := wd.read(hooked, ci, "dev")
	if err != nil || got["API_URL"] != "v1" {
		t.Fatalf("in flight: %v %v", got, err)
	}
	if _, _, err := wd.read(ctx, ci, "dev"); err == nil {
		t.Fatal("the next retrieval was not refused")
	}
}

// changeSet sets A and B together, in one change set, through the writer.
func (wd *world) changeSet(value string) {
	wd.t.Helper()
	ctx := context.Background()
	project, err := projects.Get(ctx, wd.store.Reader(), wd.org, "api")
	if err != nil {
		wd.t.Fatal(err)
	}
	e, err := environments.Get(ctx, wd.store.Reader(), project.ID, "dev")
	if err != nil {
		wd.t.Fatal(err)
	}
	if _, _, _, err := values.ApplyChangeSet(ctx, wd.w, wd.rootKEK, alice(), values.Target{OrganizationID: wd.org, Project: project, Env: e},
		[]values.Change{{Op: "set", Item: "A", Value: value}, {Op: "set", Item: "B", Value: value}}, "req_w", write.Claim{IdentityID: "idn_a"}, time.Now); err != nil {
		wd.t.Fatal(err)
	}
}

// Change sets, and their audit events, committing in the middle of
// retrievals never abort one nor show it half a set. A handshake makes the
// overlap certain: each retrieval's hook commits a change set (A and B to
// the round's number) between its reads, and returns only once the write
// committed; the retrieval must still see the previous round's pair, whole,
// and the next one the new pair. Every round's write must have committed
// mid-retrieval.
func TestConcurrentWritesNeverAbortARetrieval(t *testing.T) {
	wd := newWorld(t)
	wd.contract([]string{"A", "B"})
	wd.changeSet("0")
	const rounds = 20
	committed := 0
	for i := 1; i <= rounds; i++ {
		want := strconv.Itoa(i - 1)
		ctx := values.WithReadHook(context.Background(), once(t, betweenValueReads, func() {
			wd.changeSet(strconv.Itoa(i))
			committed++
		}))
		got, _, err := wd.read(ctx, alice(), "dev")
		if err != nil {
			t.Fatalf("round %d: the retrieval failed: %v", i, err)
		}
		if got["A"] != want || got["B"] != want {
			t.Fatalf("round %d: saw %v, want both %s", i, got, want)
		}
	}
	if committed != rounds {
		t.Fatalf("%d of %d writes committed mid-retrieval", committed, rounds)
	}
	if got, _, _ := wd.read(context.Background(), alice(), "dev"); got["A"] != strconv.Itoa(rounds) || got["B"] != strconv.Itoa(rounds) {
		t.Fatalf("after: %v", got)
	}
}

// A strict retrieval's values, manifest, state digest and verdicts all come
// from its snapshot: a write between its reads changes none of them; the
// next strict retrieval has the new value, version and digest.
func TestStrictRetrievalFromItsSnapshot(t *testing.T) {
	wd := newWorld(t)
	// PORT is an integer, so the write mid-retrieval makes it invalid.
	rev, _, err := contracts.Push(context.Background(), wd.w, alice(), wd.org, wd.project.ID, jsvalue.Object{
		{Key: "schemaVersion", Value: 1.0}, {Key: "semanticsVersion", Value: 3.0},
		{Key: "items", Value: []any{jsvalue.Object{{Key: "name", Value: "PORT"}, {Key: "required", Value: jsvalue.Object{{Key: "kind", Value: "always"}}},
			{Key: "sensitive", Value: false}, {Key: "type", Value: "integer"}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := contracts.Activate(context.Background(), wd.w, alice(), wd.org, wd.project.ID, rev.ID); err != nil {
		t.Fatal(err)
	}
	wd.set("dev", "PORT", "8080")
	strict := func(ctx context.Context) jsvalue.Object {
		t.Helper()
		out, err := wd.svc.StrictRetrieval(ctx, values.Request{
			Principal: alice(), RequestID: "req_test", Method: "POST",
			Route: "/v1/organizations/:org/projects/:project/environments/:environment/retrievals",
			Org:   "acme", Project: "api", Environment: "dev",
		}, func() (any, error) { return jsvalue.Object{{Key: "mode", Value: "strict"}}, nil })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	field := func(o jsvalue.Object, path ...string) any {
		var v any = o
		for _, k := range path {
			v, _ = v.(jsvalue.Object).Get(k)
		}
		return v
	}
	item := func(o jsvalue.Object) jsvalue.Object { return field(o, "items").([]any)[0].(jsvalue.Object) }
	before := strict(context.Background())
	during := strict(values.WithReadHook(context.Background(), once(t, betweenValueReads, func() { wd.set("dev", "PORT", "not a port") })))
	after := strict(context.Background())
	if field(item(during), "value") != "8080" || field(item(during), "versionId") != field(item(before), "versionId") ||
		field(during, "stateDigest") != field(before, "stateDigest") || field(during, "validation", "valid") != true {
		t.Fatalf("in flight: %v", during)
	}
	if v, ok := field(item(after), "versionId").(string); !ok || v == "" || v == field(item(before), "versionId") {
		t.Fatalf("after: the version %v, before %v", field(item(after), "versionId"), field(item(before), "versionId"))
	}
	if field(item(after), "value") != "not a port" || field(after, "stateDigest") == field(before, "stateDigest") ||
		field(after, "validation", "valid") != false {
		t.Fatalf("after: %v", after)
	}
}
