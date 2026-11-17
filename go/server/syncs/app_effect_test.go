// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// Decision 4's tests for createAppConnection and rotateGitHubAppKey: each
// is an external effect holding the Organization and its requester
// (shared) across GitHub's call, with the fake GitHub blocked until the
// test releases it.

type appWorld struct {
	*world
	appRowID string
	mu       sync.Mutex
	block    chan struct{}
	reached  chan struct{}
}

func rsaKey(t testing.TB) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// newAppWorld is acme with an App (GitHub App 2002, its key sealed under
// the Organization KEK) and a fake GitHub that answers installation 77 on
// acme-inc and GET /app for App 2002.
func newAppWorld(t *testing.T) *appWorld {
	wd := &appWorld{world: newWorld(t), appRowID: "gha_aaaaaaaaaaaaaaaaaaaaaaaaaa"}
	var wrapped string
	if err := wd.store.Reader().QueryRow(`SELECT wrapped_org_kek FROM organizations WHERE id = ?`, wd.org.ID).Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped), &env); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(wd.s.RootKEK, env, wd.org.ID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := githubapps.SealKey(kek, wd.org.ID, wd.appRowID, rsaKey(t))
	if err != nil {
		t.Fatal(err)
	}
	wd.exec(`INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope, created_by, created_at)
		VALUES (?, ?, 2002, 'varlatch-acme', 'Iv1.acme', 'acme-inc', 501, 'organization', ?, 'idn_a', ?)`, wd.appRowID, wd.org.ID, sealed, time.Now().UnixMicro())
	syncs.UseClient(wd.s, &http.Client{Transport: roundTrip(wd.github)})
	return wd
}

func (wd *appWorld) github(r *http.Request) (*http.Response, error) {
	wd.mu.Lock()
	block, reached := wd.block, wd.reached
	wd.mu.Unlock()
	if block != nil {
		reached <- struct{}{}
		select {
		case <-block:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	body := `{"message":"Not Found"}`
	status := 404
	switch r.URL.Path {
	case "/app":
		body, status = `{"id":2002,"slug":"varlatch-acme","client_id":"Iv1.acme"}`, 200
	case "/app/installations/77":
		body, status = `{"id":77,"app_id":2002,"account":{"login":"acme-inc","id":577,"type":"Organization"},"suspended_at":null}`, 200
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// blockCalls blocks GitHub's answers until release; each blocked request
// says so on reached first.
func (wd *appWorld) blockCalls() (release func()) {
	wd.mu.Lock()
	wd.block, wd.reached = make(chan struct{}), make(chan struct{}, 8)
	block := wd.block
	wd.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(block) }) }
}

func (wd *appWorld) reachedCall(t *testing.T) {
	t.Helper()
	select {
	case <-wd.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the effect never reached GitHub")
	}
}

func (wd *appWorld) createApp(name string) (syncs.Connection, error) {
	c, _, err := wd.s.CreateApp(context.Background(), syncs.Request{Principal: alice, RequestID: "req_" + name}, wd.org,
		syncs.AppInput{InstallationID: 77, Name: name})
	return c, err
}

func (wd *appWorld) rotate(key string, version int64) (syncs.Rotation, error) {
	out, _, err := wd.s.RotateAppKey(context.Background(), syncs.Request{Principal: alice, RequestID: "req_r"}, wd.org,
		syncs.RotateInput{PrivateKey: key, ExpectedVersion: version}, syncs.DisclosureGate(alice, wd.org.ID, "req_r", "refused"))
	return out, err
}

// A Security Control change waits for a creation's installation read (the
// Organization's gate, exclusive for the change, shared by the creation),
// and the creation then completes.
func TestControlChangeWaitsForAnAppConnection(t *testing.T) {
	wd := newAppWorld(t)
	release := wd.blockCalls()
	done := make(chan error, 1)
	go func() {
		_, err := wd.createApp("Main")
		done <- err
	}()
	wd.reachedCall(t)
	changed := make(chan error, 1)
	go func() {
		mode := security.Report
		_, _, err := security.ChangeControl(context.Background(), wd.w, wd.approvals, security.ChangeInput{
			OrganizationID: wd.org.ID, Control: security.AdminStepUp, Mode: &mode, Config: security.ConfigChange{Keep: true},
			Principal: alice, RequestID: "req_s",
		}, time.Now)
		changed <- err
	}()
	select {
	case err := <-changed:
		t.Fatalf("the change did not wait for the creation: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("the creation: %v", err)
	}
	if err := <-changed; err != nil {
		t.Fatalf("the change: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM platform_connections WHERE credential_kind = 'github-app' AND github_installation_id = 77`); n != 1 {
		t.Fatalf("%d App Connections", n)
	}
}

// The App removed while a creation reads the installation (removal shares
// the Organization's gate): the final job finds it gone, answers
// STATE_CHANGED, and keeps nothing.
func TestAppRemovedDuringACreation(t *testing.T) {
	wd := newAppWorld(t)
	release := wd.blockCalls()
	defer release()
	done := make(chan error, 1)
	go func() {
		_, err := wd.createApp("Main")
		done <- err
	}()
	wd.reachedCall(t)
	gh := &githubapps.Service{Writer: wd.w, Approvals: wd.approvals, RootKEK: wd.s.RootKEK, Policy: wd.s.Policy, Now: time.Now, Log: wd.s.Log}
	if _, err := gh.Remove(context.Background(), githubapps.Request{Principal: alice, RequestID: "req_x"}, wd.org, wd.appRowID); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	release()
	err := <-done
	if code(err) != "STATE_CHANGED" || !strings.Contains(err.Error(), "removed meanwhile") {
		t.Fatalf("the creation: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM platform_connections`); n != 0 {
		t.Fatalf("%d Connections kept", n)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'sync.connection_created'`); n != 0 {
		t.Fatal("the creation was audited")
	}
}

// Two rotations past their checks at once, each verified by GitHub: the
// first final job re-keys the App, and the other finds a version it did
// not expect (re-keyed between its call and its final job) and answers
// VERSION_CONFLICT, keeping nothing.
func TestAppRekeyedBetweenTheCallAndTheFinalJob(t *testing.T) {
	wd := newAppWorld(t)
	release := wd.blockCalls()
	defer release()
	type result struct {
		out syncs.Rotation
		err error
	}
	results := make(chan result, 2)
	keys := []string{rsaKey(t), rsaKey(t)}
	for _, k := range keys {
		go func() {
			out, err := wd.rotate(k, 1)
			results <- result{out, err}
		}()
		wd.reachedCall(t)
	}
	release()
	var rotated, conflicts int
	for range keys {
		r := <-results
		switch {
		case r.err == nil && r.out.App != nil && r.out.App.Version == 2:
			rotated++
		case code(r.err) == "VERSION_CONFLICT":
			conflicts++
		default:
			t.Fatalf("a rotation: %+v, %v", r.out, r.err)
		}
	}
	if rotated != 1 || conflicts != 1 {
		t.Fatalf("%d rotated, %d conflicts", rotated, conflicts)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'sync.github_app_key_rotated'`); n != 1 {
		t.Fatalf("%d rotations audited", n)
	}
	app, err := githubapps.Get(context.Background(), query.DBTX(wd.store.Reader()), wd.org.ID)
	if err != nil || app.Version != 2 {
		t.Fatalf("the App: %+v, %v", app, err)
	}
}
