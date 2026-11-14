// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
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

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// softKey is a software authenticator holding one credential.
type softKey struct {
	priv       *ecdsa.PrivateKey
	id         []byte
	counter    uint32
	userHandle []byte
	// noUV leaves user verification out of its assertions.
	noUV bool
	// fixedCounter keeps the counter where it is (an authenticator
	// without one, or a clone).
	fixedCounter bool
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id}
}

func (k *softKey) cose(t *testing.T) []byte {
	t.Helper()
	x, y := make([]byte, 32), make([]byte, 32)
	k.priv.PublicKey.X.FillBytes(x)
	k.priv.PublicKey.Y.FillBytes(y)
	b, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, XCoord: x, YCoord: y,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *softKey) flags(attested bool) byte {
	f := byte(0x01) // UP
	if !k.noUV {
		f |= 0x04 // UV
	}
	if attested {
		f |= 0x40 // AT
	}
	return f
}

func clientData(typ, challenge, from string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": from, "crossOrigin": false})
	return b
}

// register answers creation options as navigator.credentials.create would,
// from the origin `from`.
func (k *softKey) register(t *testing.T, o auth.CreationOptions, from string) json.RawMessage {
	t.Helper()
	k.userHandle, _ = base64.RawURLEncoding.DecodeString(o.User.ID)
	rpHash := sha256.Sum256([]byte(o.RP.ID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, k.flags(true))
	data = binary.BigEndian.AppendUint32(data, k.counter)
	data = append(data, make([]byte, 16)...) // AAGUID
	data = binary.BigEndian.AppendUint16(data, uint16(len(k.id)))
	data = append(data, k.id...)
	data = append(data, k.cose(t)...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64(clientData("webauthn.create", o.Challenge, from)), "attestationObject": b64(att),
			"transports": []string{"internal"},
		},
	})
	return b
}

// assertWith signs an assertion over challenge for rpID, from the origin
// `from`, with the given counter.
func (k *softKey) assertWith(t *testing.T, rpID, challenge, from string, counter uint32) json.RawMessage {
	t.Helper()
	rpHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, k.flags(false))
	data = binary.BigEndian.AppendUint32(data, counter)
	cd := clientData("webauthn.get", challenge, from)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, data...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64(cd), "authenticatorData": b64(data), "signature": b64(sig), "userHandle": b64(k.userHandle),
		},
	})
	return b
}

// assert answers request options, advancing its counter.
func (k *softKey) assert(t *testing.T, o auth.RequestOptions, from string) json.RawMessage {
	t.Helper()
	if !k.fixedCounter {
		k.counter++
	}
	return k.assertWith(t, o.RPID, o.Challenge, from, k.counter)
}

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
	reg, err := e.svc.Register(e.ctx, binding, nil, k.register(e.t, o, origin), "Test passkey", "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
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
	return e.svc.SignIn(e.ctx, binding, k.assert(e.t, o, origin), "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0")
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
