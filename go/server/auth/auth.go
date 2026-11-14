// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth is varlatchd's human and machine authentication (ADR-0059
// Decision 6, step 3.4), ported from the TypeScript server's auth/ and the
// domain code it calls (domain/bootstrap.ts, domain/passkeys.ts,
// domain/passkeyverification.ts, domain/device-sign-in.ts):
//
//   - opaque bearer credentials (ADR-0007): issued, authenticated, listed,
//     revoked, with expiry and use limits, stored as the SHA-256 of the
//     token (credentials.go);
//   - setup grants: bootstrap, recovery, invitation and re-enrollment links
//     (grants.go);
//   - browser sessions of its own, replacing Better Auth's: opaque tokens
//     stored hashed, ended by deleting the row, whose trigger revokes the
//     session's browser credentials (sessions.go);
//   - WebAuthn ceremonies with go-webauthn's protocol package: enrollment
//     through a setup grant, sign-in with a discoverable credential, adding
//     a passkey, and the assertions that approve one operation (device
//     sign-in, passkey confirmation) (webauthn.go, ceremonies.go);
//   - a passkey's provenance, sign-in evidence and passkey-verification
//     (ADR-0054 Decisions 4, 6 and 7) (passkeys.go);
//   - device-authorization sign-in (ADR-0043 Decision 2) (device.go).
//
// Every write runs as one job on the storage engine's single writer
// (lib/storage). Where the TypeScript server took row locks to serialize
// concurrent requests, the single writer already runs jobs one at a time:
// a job reads, checks and writes with nothing between, so the checks that
// guarded a lock (single use, counters that only move forward, a duplicate
// credential id) are made inside the same job. Times are microseconds since
// the Unix epoch, read from the Service's clock inside the job.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/url"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
)

// Service is the authentication state of one installation.
type Service struct {
	store *storage.DB
	// rp is the relying party, from the public URL; nil without one.
	rp *RelyingParty
	// now is the clock (tests replace it).
	now        func() time.Time
	ceremonies *ceremonyStore
	log        *slog.Logger
}

// Options configures a Service.
type Options struct {
	// PublicURL is the installation's public URL: the WebAuthn relying
	// party (its origin, and its host name as the RP ID). Without one no
	// passkey ceremony runs.
	PublicURL *url.URL
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// New returns the Service for store.
func New(store *storage.DB, opts Options) *Service {
	s := &Service{store: store, now: opts.Now, log: opts.Log, ceremonies: newCeremonyStore()}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if opts.PublicURL != nil {
		rp := RelyingPartyOf(opts.PublicURL)
		s.rp = &rp
	}
	return s
}

// Store is the storage the Service writes through.
func (s *Service) Store() *storage.DB { return s.store }

// RP returns the relying party, or nil when the installation has no public
// URL.
func (s *Service) RP() *RelyingParty { return s.rp }

func (s *Service) micros() int64 { return s.now().UnixMicro() }

// HashToken is the stored form of a token: the hex SHA-256 of its UTF-8
// bytes, as hashToken in credentials.ts.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomBase64URL(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Credential kinds and their token prefixes (credentials.ts PREFIX).
const (
	KindService  = "service"
	KindCLI      = "cli"
	KindBrowser  = "browser"
	KindAgentRun = "agent-run"
	KindOIDC     = "oidc"
)

var tokenPrefix = map[string]string{
	KindService:  "vlt_svc_",
	KindCLI:      "vlt_cli_",
	KindBrowser:  "vlt_web_",
	KindAgentRun: "vlt_agr_",
	KindOIDC:     "vlt_oidc_",
}

// GenerateToken returns a new token of a credential kind: its prefix and
// 32 random bytes in base64url.
func GenerateToken(kind string) string {
	return tokenPrefix[kind] + randomBase64URL(32)
}

// setupToken is a setup grant's token: vlt_setup_, vlt_recover_,
// vlt_invite_ or vlt_reenroll_ and 32 random bytes in base64url.
func setupToken(prefix string) string { return prefix + randomBase64URL(32) }

// ISO is a time as JavaScript's Date.prototype.toISOString writes it.
func ISO(micros int64) string { return audit.ISOTime(micros) }

func str(s string) *string { return &s }

// NewCSRFToken is a browser's CSRF token: 32 random bytes in base64url.
func NewCSRFToken() string { return randomBase64URL(32) }
