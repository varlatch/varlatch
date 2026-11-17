// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Decision 4's tests for completeRegistration and importGitHubApp: each is
// an external effect, the completion holding the registration's gate
// across GitHub's code exchange, with a fake GitHub blocked until the test
// releases it.

type world struct {
	t         *testing.T
	store     *storage.DB
	w         *write.Writer
	approvals *auth.Service
	org       authz.Organization
	s         *githubapps.Service
	key       string
	// The fake GitHub: a request blocks while block is open; with
	// noAnswer it fails instead of answering.
	mu       sync.Mutex
	block    chan struct{}
	reached  chan struct{}
	noAnswer bool
	calls    int
}

var alice = &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}

func rsaPEM(t testing.TB) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
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
	wd := &world{t: t, store: store, w: &write.Writer{Store: store, Gates: write.NewGates()}, key: rsaPEM(t)}
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = authz.Organization{ID: org.ID, Slug: "acme", Name: "Acme"}
	public, _ := url.Parse("http://127.0.0.1:8686")
	wd.approvals = auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK, PersonGate: wd.w.Gates.PersonGate})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log})
	t.Cleanup(policy.Close)
	wd.s = &githubapps.Service{Writer: wd.w, Approvals: wd.approvals, RootKEK: rootKEK, Policy: policy, Now: time.Now, Log: log}
	githubapps.UseClient(wd.s, &http.Client{Transport: roundTrip(wd.github)})
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) count(q string, args ...any) int {
	wd.t.Helper()
	var n int
	if err := wd.store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		wd.t.Fatal(err)
	}
	return n
}

// github answers a code exchange with an App on acme-inc, GET /app with
// App 4004; it blocks while wd.block is set, after saying so on
// wd.reached.
func (wd *world) github(r *http.Request) (*http.Response, error) {
	wd.mu.Lock()
	block, reached, noAnswer := wd.block, wd.reached, wd.noAnswer
	wd.calls++
	wd.mu.Unlock()
	if block != nil {
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-block:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	if noAnswer {
		return nil, fmt.Errorf("fetch failed")
	}
	var body jsvalue.Object
	if strings.HasPrefix(r.URL.Path, "/app-manifests/") {
		body = jsvalue.Object{{Key: "id", Value: int64(1001)}, {Key: "slug", Value: "varlatch-acme"}, {Key: "client_id", Value: "Iv1.acme"},
			{Key: "pem", Value: wd.key}, {Key: "owner", Value: jsvalue.Object{{Key: "login", Value: "acme-inc"}, {Key: "id", Value: int64(501)}, {Key: "type", Value: "Organization"}}}}
		return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(jsvalue.Stringify(body)))), Request: r}, nil
	}
	body = jsvalue.Object{{Key: "id", Value: int64(4004)}, {Key: "slug", Value: "imported"}, {Key: "client_id", Value: "Iv1.imported"},
		{Key: "owner", Value: jsvalue.Object{{Key: "login", Value: "acme-inc"}, {Key: "id", Value: int64(501)}, {Key: "type", Value: "Organization"}}},
		{Key: "permissions", Value: jsvalue.Object{{Key: "secrets", Value: "write"}, {Key: "environments", Value: "write"}, {Key: "metadata", Value: "read"}}}}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(jsvalue.Stringify(body)))), Request: r}, nil
}

func (wd *world) blockCalls() (release func()) {
	wd.mu.Lock()
	wd.block, wd.reached = make(chan struct{}), make(chan struct{}, 4)
	block := wd.block
	wd.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(block) }) }
}

func (wd *world) reachedCall() {
	wd.t.Helper()
	select {
	case <-wd.reached:
	case <-time.After(10 * time.Second):
		wd.t.Fatal("the effect never reached its call")
	}
}

// registration writes a fresh registration of alice's in acme, by its
// state, expiring after ttl; its id.
func (wd *world) registration(state string, ttl time.Duration) string {
	wd.t.Helper()
	id := ids.New(ids.GitHubAppRegistration)
	now := time.Now()
	wd.exec(`INSERT INTO github_app_registrations (id, state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at)
		VALUES (?, ?, ?, 'idn_a', 'acme-inc', 'organization', ?, ?)`, id, auth.HashToken(state), wd.org.ID, now.UnixMicro(), now.Add(ttl).UnixMicro())
	return id
}

// pending writes a converted registration of alice's in acme, past its
// hour when lapsed.
func (wd *world) pending(state string, lapsed bool) string {
	wd.t.Helper()
	id := wd.registration(state, time.Hour)
	converted, expires := time.Now(), time.Now().Add(time.Hour)
	if lapsed {
		converted, expires = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	}
	wd.exec(`UPDATE github_app_registrations SET consumed_at = ?, converted_at = ?, pending_expires_at = ?,
		pending_github_app_id = 2001, pending_slug = 'varlatch-old', pending_client_id = 'Iv1.old', pending_owner_login = 'acme-inc',
		pending_owner_id = 501, pending_owner_type = 'organization', pending_key_envelope = '{}' WHERE id = ?`,
		converted.UnixMicro(), converted.UnixMicro(), expires.UnixMicro(), id)
	return id
}

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func (wd *world) complete(state string) (githubapps.CompleteResult, error) {
	return wd.s.Complete(context.Background(), githubapps.Request{Principal: alice, RequestID: "req_c"}, wd.org, state, "code")
}

// waitsOnGate runs op, requires it to wait on a gate until release is
// called, and returns its error once it ends.
func (wd *world) waitsOnGate(t *testing.T, release func(), op func() error) error {
	waiting := make(chan struct{})
	var once sync.Once
	wd.w.Gates.Observe(func(event string, _ write.Gate) {
		if event == "waiting" {
			once.Do(func() { close(waiting) })
		}
	})
	defer wd.w.Gates.Observe(nil)
	finished := make(chan error, 1)
	go func() { finished <- op() }()
	select {
	case <-waiting:
	case err := <-finished:
		t.Fatalf("finished during the effect's call: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("never waited for the effect")
	}
	select {
	case err := <-finished:
		t.Fatalf("finished during the effect's call: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	return <-finished
}

// Two simultaneous completions of one registration: one reaches GitHub;
// the other waits on the registration's gate, then answers as the
// TypeScript server does once the first committed: CONSUMED.
func TestTwoCompletionsOneReachesGitHub(t *testing.T) {
	wd := newWorld(t)
	wd.registration("st", time.Hour)
	release := wd.blockCalls()
	first := make(chan error, 1)
	var res githubapps.CompleteResult
	go func() {
		var err error
		res, err = wd.complete("st")
		first <- err
	}()
	wd.reachedCall()
	err := wd.waitsOnGate(t, release, func() error {
		_, err := wd.complete("st")
		return err
	})
	if err := <-first; err != nil || res.Outcome.Kind != "registered" {
		t.Fatalf("the first completion: %+v, %v", res.Outcome, err)
	}
	if code(err) != "CONSUMED" {
		t.Fatalf("the second completion: %v, want CONSUMED", err)
	}
	if wd.calls != 1 {
		t.Fatalf("GitHub was asked %d times, want once", wd.calls)
	}
}

// A completion whose call gets no answer leaves the state free: GitHub may
// not have seen the code, so another attempt within the hour may complete.
func TestCompletionWithoutAnswerFreesTheState(t *testing.T) {
	wd := newWorld(t)
	id := wd.registration("st", time.Hour)
	wd.noAnswer = true
	res, err := wd.complete("st")
	if err != nil || res.Outcome.Kind != "failed" || !res.Outcome.Retryable {
		t.Fatalf("no answer: %+v, %v", res.Outcome, err)
	}
	if n := wd.count(`SELECT count(*) FROM github_app_registrations WHERE id = ? AND consumed_at IS NULL`, id); n != 1 {
		t.Fatal("the state was claimed though GitHub never answered")
	}
	wd.noAnswer = false
	if res, err := wd.complete("st"); err != nil || res.Outcome.Kind != "registered" {
		t.Fatalf("the next attempt: %+v, %v", res.Outcome, err)
	}
}

// A completion admitted just before the registration's expiry whose
// blocked call ends after it succeeds, as in TypeScript: the claim's
// eligibility and time were captured under the gate before the call.
func TestCompletionAdmittedBeforeExpiry(t *testing.T) {
	wd := newWorld(t)
	wd.registration("st", 300*time.Millisecond)
	release := wd.blockCalls()
	done := make(chan error, 1)
	var res githubapps.CompleteResult
	go func() {
		var err error
		res, err = wd.complete("st")
		done <- err
	}()
	wd.reachedCall()
	time.Sleep(500 * time.Millisecond)
	release()
	if err := <-done; err != nil || res.Outcome.Kind != "registered" {
		t.Fatalf("%+v, %v", res.Outcome, err)
	}
	// After its expiry, a fresh attempt is refused before anything is called.
	wd.registration("late", time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if _, err := wd.complete("late"); code(err) != "EXPIRED" {
		t.Fatalf("an expired registration: %v, want EXPIRED", err)
	}
}

// A discard of the registration during a blocked completion waits on its
// gate, then decides on what the completion committed: attached.
func TestDiscardDuringABlockedCompletionWaits(t *testing.T) {
	wd := newWorld(t)
	id := wd.registration("st", time.Hour)
	release := wd.blockCalls()
	done := make(chan error, 1)
	go func() {
		_, err := wd.complete("st")
		done <- err
	}()
	wd.reachedCall()
	var out jsvalue.Object
	err := wd.waitsOnGate(t, release, func() error {
		var err error
		out, _, err = wd.s.Discard(context.Background(), alice, wd.org, id)
		return err
	})
	if err := <-done; err != nil {
		t.Fatalf("the completion: %v", err)
	}
	if state, _ := out.Get("state"); err != nil || state != "attached" {
		t.Fatalf("the discard: %v, %v", out, err)
	}
}

// The sweep during a blocked completion: a completion claims only an
// unconverted registration, which is never the sweep's, so the sweep ends
// a lapsed conversion of the same Organization without waiting for GitHub,
// as TypeScript's SKIP LOCKED never waits; the completion then commits.
func TestSweepDuringABlockedCompletion(t *testing.T) {
	wd := newWorld(t)
	wd.registration("st", time.Hour)
	lapsed := wd.pending("old", true)
	release := wd.blockCalls()
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := wd.complete("st")
		done <- err
	}()
	wd.reachedCall()
	swept := make(chan error, 1)
	go func() {
		n, err := wd.s.Sweep(context.Background())
		if err == nil && n != 1 {
			err = fmt.Errorf("ended %d", n)
		}
		swept <- err
	}()
	select {
	case err := <-swept:
		if err != nil {
			t.Fatalf("the sweep: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep waited for GitHub")
	}
	if n := wd.count(`SELECT count(*) FROM github_app_registrations WHERE id = ? AND end_reason = 'expired'`, lapsed); n != 1 {
		t.Fatal("the lapsed conversion was not ended")
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("the completion: %v", err)
	}
}

func (wd *world) importApp() (githubapps.ImportOutcome, error) {
	out, _, err := wd.s.Import(context.Background(), githubapps.Request{Principal: alice, RequestID: "req_i"}, wd.org, 4004, wd.key)
	return out, err
}

// Two simultaneous imports: both call GitHub (an import holds no resource
// gate); the first to commit registers the App, the second answers
// STATE_CHANGED, as the TypeScript insert's conflict does.
func TestTwoImports(t *testing.T) {
	wd := newWorld(t)
	release := wd.blockCalls()
	type result struct {
		out githubapps.ImportOutcome
		err error
	}
	done := make(chan result, 2)
	for range 2 {
		go func() {
			out, err := wd.importApp()
			done <- result{out, err}
		}()
	}
	wd.reachedCall()
	wd.reachedCall()
	release()
	a, b := <-done, <-done
	if a.err != nil {
		a, b = b, a
	}
	if a.err != nil || !a.out.Registered || code(b.err) != "STATE_CHANGED" {
		t.Fatalf("%+v %v / %+v %v", a.out, a.err, b.out, b.err)
	}
	if n := wd.count(`SELECT count(*) FROM github_apps WHERE removed_at IS NULL`); n != 1 {
		t.Fatalf("%d live Apps", n)
	}
}

// An import whose call gets no answer keeps nothing: no App, no event.
func TestImportWithoutAnswerKeepsNothing(t *testing.T) {
	wd := newWorld(t)
	wd.noAnswer = true
	out, err := wd.importApp()
	if err != nil || out.Registered || out.Check.Status != "unreachable" {
		t.Fatalf("%+v, %v", out, err)
	}
	if n := wd.count(`SELECT count(*) FROM github_apps`); n != 0 {
		t.Fatalf("%d Apps", n)
	}
}

// A Security Control change during a blocked import waits for it (the
// Organization's gate, exclusive for the change, shared by the import).
func TestControlChangeWaitsForAnImport(t *testing.T) {
	wd := newWorld(t)
	release := wd.blockCalls()
	done := make(chan error, 1)
	go func() {
		_, err := wd.importApp()
		done <- err
	}()
	wd.reachedCall()
	err := wd.waitsOnGate(t, release, func() error {
		mode := security.Report
		_, _, err := security.ChangeControl(context.Background(), wd.w, wd.approvals, security.ChangeInput{
			OrganizationID: wd.org.ID, Control: security.AdminStepUp, Mode: &mode, Config: security.ConfigChange{Keep: true},
			Principal: alice, RequestID: "req_s",
		}, time.Now)
		return err
	})
	if err != nil {
		t.Fatalf("the change: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the import: %v", err)
	}
}
