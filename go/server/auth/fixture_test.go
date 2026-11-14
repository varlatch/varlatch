// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// G4: passkeys and credentials from a v0.22.0 database keep their status in
// Go. testdata/passkeys-v0.22.0.json is made by the TypeScript server's
// code (services/varlatchd/test/go-passkey-fixture.test.ts): passkeys from
// before migration 39 (one quarantined as a duplicate credential id, the
// rest trusted, existing-at-upgrade), one a re-enrollment link enrolled,
// one a session added (unconfirmed), one confirmed, one with no provenance;
// and credentials carrying sign-in evidence. The rows are loaded here
// through the schema mapping (go/server/db/mapping.json), as the migration
// will copy them, and Go must say of them what the TypeScript code said.

type fixture struct {
	Keys     map[string]string           `json:"keys"`
	Rows     map[string][]map[string]any `json:"rows"`
	Expected struct {
		Passkeys map[string][]struct {
			ID, Trust            string
			TrustedVia           *string `json:"trustedVia"`
			SetupGrantKind       *string `json:"setupGrantKind"`
			ConfirmedByPasskeyID *string `json:"confirmedByPasskeyId"`
			DeviceType           string  `json:"deviceType"`
			BackedUp             bool    `json:"backedUp"`
			CreatedAt            *string `json:"createdAt"`
			Name                 *string `json:"name"`
		} `json:"passkeys"`
		Gaps     map[string]*string `json:"gaps"`
		Evidence map[string]*struct {
			UserVerified   bool   `json:"userVerified"`
			PasskeyID      string `json:"passkeyId"`
			Source         string `json:"source"`
			PasskeyTrusted bool   `json:"passkeyTrusted"`
		} `json:"evidence"`
	} `json:"expected"`
}

type mapping struct {
	Tables map[string]struct {
		SQLite  string            `json:"sqlite"`
		// A column maps to its SQLite name, or to an object for one that
		// changes more (none of the tables loaded here has one).
		Columns map[string]json.RawMessage `json:"columns"`
	} `json:"tables"`
}

var isoTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$`)

// load copies the fixture's rows into e's database, each PostgreSQL table
// and column by its mapping: booleans as 0 and 1, times as microseconds.
func (e *env) load(f fixture) {
	e.t.Helper()
	raw, err := os.ReadFile("../db/mapping.json")
	if err != nil {
		e.t.Fatal(err)
	}
	var m mapping
	if err := json.Unmarshal(raw, &m); err != nil {
		e.t.Fatal(err)
	}
	order := []string{"identities", "user", "auth_user_links", "passkey", "passkey_provenance", "passkey_quarantine", "auth_session_evidence", "credentials"}
	err = e.store.Write(e.ctx, func(tx *storage.Tx) error {
		for _, table := range order {
			tm, ok := m.Tables[table]
			if !ok {
				return fmt.Errorf("no mapping for %s", table)
			}
			for _, row := range f.Rows[table] {
				var cols, marks []string
				var args []any
				for pg, v := range row {
					var col string
					if err := json.Unmarshal(tm.Columns[pg], &col); err != nil {
						return fmt.Errorf("%s.%s has no column name in the mapping: %w", table, pg, err)
					}
					switch x := v.(type) {
					case bool:
						if x {
							v = 1
						} else {
							v = 0
						}
					case float64:
						v = int64(x)
					case string:
						if isoTime.MatchString(x) {
							ts, err := time.Parse(time.RFC3339Nano, x)
							if err != nil {
								return err
							}
							v = ts.UnixMicro()
						}
					}
					cols, marks, args = append(cols, col), append(marks, "?"), append(args, v)
				}
				q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tm.SQLite, strings.Join(cols, ", "), strings.Join(marks, ", "))
				if _, err := tx.ExecContext(e.ctx, q, args...); err != nil {
					return fmt.Errorf("%s: %w", q, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func readFixture(t *testing.T) fixture {
	t.Helper()
	b, err := os.ReadFile("testdata/passkeys-v0.22.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// Trusted, unconfirmed and quarantined passkeys keep their status, and
// credentials their evidence.
func TestV0220PasskeysKeepTheirStatus(t *testing.T) {
	e := newEnv(t)
	f := readFixture(t)
	e.load(f)
	for identity, want := range f.Expected.Passkeys {
		got, err := e.svc.ListOwnPasskeys(e.ctx, identity)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d passkeys, want %d", identity, len(got), len(want))
		}
		for i, w := range want {
			g := got[i]
			if g.ID != w.ID || g.Trust != w.Trust || deref(g.TrustedVia) != deref(w.TrustedVia) || deref(g.SetupGrantKind) != deref(w.SetupGrantKind) ||
				deref(g.ConfirmedByPasskeyID) != deref(w.ConfirmedByPasskeyID) || g.DeviceType != w.DeviceType || g.BackedUp != w.BackedUp ||
				deref(g.Name) != deref(w.Name) || (g.CreatedAt == nil) != (w.CreatedAt == nil) || (g.CreatedAt != nil && auth.ISO(*g.CreatedAt) != *w.CreatedAt) {
				t.Errorf("%s passkey %d: %+v, want %+v", identity, i, g, w)
			}
		}
	}
	for credential, want := range f.Expected.Gaps {
		got, err := auth.VerificationGap(e.ctx, e.store.Reader(), credential, auth.KindCLI)
		if err != nil {
			t.Fatal(err)
		}
		if got != deref(want) && !(want == nil && got == "") {
			t.Errorf("%s: gap %q, want %q", credential, got, deref(want))
		}
	}
	for credential, want := range f.Expected.Evidence {
		got, err := auth.EvidenceOf(e.ctx, e.store.Reader(), credential)
		if err != nil {
			t.Fatal(err)
		}
		if (got == nil) != (want == nil) || got != nil && (got.UserVerified != want.UserVerified || got.PasskeyID != want.PasskeyID ||
			got.Source != want.Source || got.PasskeyTrusted != want.PasskeyTrusted) {
			t.Errorf("%s: evidence %+v, want %+v", credential, got, want)
		}
	}
	// The quarantined passkey is not a passkey any more.
	if n := e.count(`SELECT count(*) FROM passkeys WHERE id = 'pk_bob_shared'`); n != 0 {
		t.Fatal("the quarantined passkey is back")
	}
	if n := e.count(`SELECT count(*) FROM passkey_quarantine WHERE id = 'pk_bob_shared' AND kept_passkey_id = 'pk_alice_shared'`); n != 1 {
		t.Fatal("the quarantine row is not kept")
	}
}

func fixtureKey(t *testing.T, f fixture, who, credentialID string, counter uint32) *authtest.Key {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(f.Keys[who])
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	id, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil {
		t.Fatal(err)
	}
	return &authtest.Key{Priv: priv.(*ecdsa.PrivateKey), ID: id, Counter: counter}
}

// A passkey the TypeScript server stored signs in to Go, its counter moving
// on from the stored one; Bob's quarantined passkey, which shares its
// credential id with Alice's kept one, does not sign in as anyone.
func TestV0220PasskeysSignIn(t *testing.T) {
	e := newEnv(t)
	f := readFixture(t)
	e.load(f)
	alice := fixtureKey(t, f, "alice", "Y3JlZC1hbGljZS1sYXB0b3A", 41)
	started, err := e.signIn(alice, browserCSRF)
	if err != nil || started.IdentityID != "idn_alice" {
		t.Fatalf("Alice's laptop: %+v %v", started, err)
	}
	if n := e.count(`SELECT counter FROM passkeys WHERE id = 'pk_alice_laptop'`); n != 42 {
		t.Fatalf("counter %d", n)
	}
	// A clone at the stored counter is refused.
	clone := fixtureKey(t, f, "alice", "Y3JlZC1hbGljZS1sYXB0b3A", 41)
	if _, err := e.signIn(clone, browserCSRF); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("clone: %v", err)
	}
	bob := fixtureKey(t, f, "bob", "Y3JlZC1zaGFyZWQ", 3)
	if _, err := e.signIn(bob, browserCSRF); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Fatalf("Bob's quarantined passkey signed in: %v", err)
	}
	// The trusted sign-in's evidence satisfies passkey-verification.
	b, _ := e.svc.MintBearer(e.ctx, e.session(started.SessionToken), nil)
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), mustID(t, e, b.Token), auth.KindBrowser); gap != "" {
		t.Fatalf("gap %q", gap)
	}
	// Bob's re-enrolled passkey signs in too; his unconfirmed one's sign-in
	// carries an untrusted passkey.
	reenrolled := fixtureKey(t, f, "bob", "Y3JlZC1ib2ItcmVlbnJvbGxlZA", 0)
	if _, err := e.signIn(reenrolled, browserCSRF); err != nil {
		t.Fatal(err)
	}
	added := fixtureKey(t, f, "bob", "Y3JlZC1ib2ItYWRkZWQ", 0)
	s, err := e.signIn(added, browserCSRF)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = e.svc.MintBearer(e.ctx, e.session(s.SessionToken), nil)
	if gap, _ := auth.VerificationGap(e.ctx, e.store.Reader(), mustID(t, e, b.Token), auth.KindBrowser); gap != auth.GapUntrusted {
		t.Fatalf("unconfirmed sign-in gap %q", gap)
	}
	if !slices.Contains([]string{"idn_bob"}, s.IdentityID) {
		t.Fatalf("signed in as %s", s.IdentityID)
	}
}
