// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
)

// The test kit: an installation in a temporary database, a clock the test
// moves, and a software authenticator that registers and asserts as a
// browser's would (ES256, "none" attestation).

const origin = "https://varlatch.example.com"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	store *storage.DB
	svc   *auth.Service
	clock *clock
	ctx   context.Context
}

func newEnv(t *testing.T) *env {
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
		return query.New(tx).CreateInstallation(ctx, query.CreateInstallationParams{ID: "inst_test", KekCanary: "{}"})
	}); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
	u, _ := url.Parse(origin)
	return &env{t: t, store: store, svc: auth.New(store, auth.Options{PublicURL: u, Now: c.now}), clock: c, ctx: ctx}
}

func b64(b []byte) string { return authtest.B64(b) }

type softKey = authtest.Key

func newSoftKey(t *testing.T) *softKey { return authtest.New(t) }

const browserCSRF = "csrf-token-of-the-browser-under-test-0123456789"

// enroll runs a bootstrap enrollment in a browser and returns the session
// it started and the passkey.
func (e *env) enroll(k *softKey, csrf string) (auth.Registration, auth.Grant) {
	e.t.Helper()
	g, err := e.svc.IssueBootstrapGrant(e.ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	reg := e.enrollWith(k, csrf, g.Token)
	return reg, g
}

func (e *env) enrollWith(k *softKey, csrf, token string) auth.Registration {
	e.t.Helper()
	binding := auth.CSRFBinding(csrf)
	o, err := e.svc.RegistrationOptions(e.ctx, binding, token, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	reg, err := e.svc.Register(e.ctx, binding, nil, k.Register(e.t, o, origin), "Test passkey", "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
	if err != nil {
		e.t.Fatal(err)
	}
	return reg
}

func (e *env) signIn(k *softKey, csrf string) (auth.Started, error) {
	e.t.Helper()
	binding := auth.CSRFBinding(csrf)
	o, err := e.svc.SignInOptions(binding)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.svc.SignIn(e.ctx, binding, k.Assert(e.t, o, origin), "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
}

func (e *env) session(token string) *auth.Session {
	e.t.Helper()
	s, err := e.svc.SessionOf(e.ctx, token)
	if err != nil || s == nil {
		e.t.Fatalf("no session: %v", err)
	}
	return s
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.store.Reader().QueryRowContext(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// codeOf is a domain error's code, "" for anything else.
func codeOf(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// reasonOf is a domain error's details.reason, "" when it has none.
func reasonOf(err error) string {
	var de *domainerr.Error
	if !errors.As(err, &de) {
		return ""
	}
	r, _ := de.Details.Get("reason")
	s, _ := r.(string)
	return s
}
