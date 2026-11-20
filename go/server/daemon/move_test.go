// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
)

// seedPeople gives the installation's admin and a second person a passkey,
// a browser session and a browser credential minted from it each; it
// returns the second person's identity.
func seedPeople(t *testing.T, in install, adminID string) string {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	member := "idn_movetestmember"
	err = s.Write(context.Background(), func(tx *storage.Tx) error {
		exec := func(q string, args ...any) error {
			_, err := tx.ExecContext(context.Background(), q, args...)
			return err
		}
		if err := exec(`INSERT INTO identities (id, kind, name) VALUES (?, 'human', 'Member Person')`, member); err != nil {
			return err
		}
		far := time.Now().Add(time.Hour).UnixMicro()
		for i, id := range []string{adminID, member} {
			n := string(rune('a' + i))
			user, sess := "usr_move_"+n, "ses_move_"+n
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO auth_users (id, name, email) VALUES (?, ?, ?)`, []any{user, "person " + n, n + "@people.example"}},
				{`INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES (?, ?)`, []any{user, id}},
				{`INSERT INTO passkeys (id, public_key, user_id, credential_id, counter, device_type, backed_up) VALUES (?, 'public-key-words', ?, ?, 0, 'singleDevice', 0)`, []any{"pk_move_" + n, user, "credential-" + n}},
				{`INSERT INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES (?, ?, ?, ?)`, []any{sess, far, "session-hash-" + n, user}},
				{`INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at, auth_session_id) VALUES (?, ?, 'browser', ?, ?, ?)`, []any{"crd_move_browser_" + n, id, "browser-hash-" + n, far, sess}},
			} {
				if err := exec(q.sql, q.args...); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return member
}

func adminJSON(t *testing.T, into any, args ...string) {
	t.Helper()
	code, out, errOut := runAdmin(t, args...)
	if code != ExitOK || json.Unmarshal([]byte(out), into) != nil {
		t.Fatalf("%v: %d %q %q", args, code, out, errOut)
	}
}

// A move's host commands (slice 6.9): config check and move-facts read;
// public-url-changed removes the old relying party's passkeys once, ends
// the browser sessions and revokes their credentials, the CLI credential
// kept; reenroll issues one live link per person, admins first, each a
// grant enrollment accepts, the earlier one revoked. Through the socket
// while varlatchd runs, offline otherwise. No link reaches a log or an
// audit event.
func TestMoveCommands(t *testing.T) {
	in := newInstall(t, "public_url = https://vault.example.com\n")
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	adminID := m[1]
	member := seedPeople(t, in, adminID)

	var conf configFacts
	adminJSON(t, &conf, "config", "check", "--config", in.conf)
	if conf.Ingress != "external" || conf.PublicURL == nil || *conf.PublicURL != "https://vault.example.com" || conf.Tailnet || conf.ListenHTTPS != nil {
		t.Fatalf("config check: %+v", conf)
	}
	var facts struct {
		PublicURL *string `json:"publicUrl"`
		auth.MoveFacts
	}
	adminJSON(t, &facts, "move-facts", "--config", in.conf)
	if *facts.PublicURL != "https://vault.example.com" || facts.People != 2 || facts.InstallationAdmins != 1 || facts.AdminsWithPasskey != 1 || facts.Passkeys != 2 || facts.Sessions != 2 {
		t.Fatalf("move-facts before: %+v", facts)
	}
	// The address it already answers at is no move.
	if code, _, errOut := runAdmin(t, "public-url-changed", "--from", "https://vault.example.com/", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "already answers at this address") {
		t.Fatalf("the same address: %d %q", code, errOut)
	}

	// The new address, served: the commands go through the socket.
	in.write(t, "public_url = https://vault2.example.com\n")
	r := start(t, in)
	var changed map[string]any
	adminJSON(t, &changed, "public-url-changed", "--from", "https://vault.example.com", "--config", in.conf)
	if changed["from"] != "https://vault.example.com" || changed["to"] != "https://vault2.example.com" ||
		changed["passkeysRemoved"] != 2.0 || changed["sessionsEnded"] != 2.0 || changed["browserCredentialsRevoked"] != 2.0 {
		t.Fatalf("public-url-changed: %v", changed)
	}
	for _, from := range []string{"https://vault.example.com", "https://elsewhere.example.com"} {
		if code, _, errOut := runAdmin(t, "public-url-changed", "--from", from, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "were already removed") {
			t.Fatalf("a second run from %s: %d %q", from, code, errOut)
		}
	}
	var all struct {
		Links []reenrollLink `json:"links"`
	}
	adminJSON(t, &all, "reenroll", "--all", "--json", "--config", in.conf)
	if len(all.Links) != 2 || all.Links[0].IdentityID != adminID || !all.Links[0].InstallationAdmin || all.Links[1].IdentityID != member {
		t.Fatalf("reenroll --all: %+v", all.Links)
	}
	for _, l := range all.Links {
		if !strings.HasPrefix(l.Link, "https://vault2.example.com/enroll#vlt_reenroll_") {
			t.Fatalf("a link: %q", l.Link)
		}
		if exp, err := time.Parse(time.RFC3339, l.ExpiresAt); err != nil || exp.Sub(time.Now()) < 23*time.Hour || exp.Sub(time.Now()) > 25*time.Hour {
			t.Fatalf("a day's link: %q", l.ExpiresAt)
		}
	}
	code, out, errOut = runAdmin(t, "reenroll", "--identity", member, "--hours", "2", "--config", in.conf)
	if code != ExitOK || !strings.HasPrefix(out, "One-time re-enrollment links.") || !strings.Contains(out, "  Member Person ["+member+"]\n    https://vault2.example.com/enroll#vlt_reenroll_") ||
		strings.Contains(out, adminID) || !strings.Contains(out, "\nExpire: ") {
		t.Fatalf("reenroll --identity: %d %q %q", code, out, errOut)
	}
	latest := out[strings.Index(out, "#")+1 : strings.Index(out, "\nExpire")]
	for _, args := range [][]string{
		{"reenroll"}, {"reenroll", "--all", "--identity", member}, {"reenroll", "--all", "--hours", "0"}, {"reenroll", "--all", "--hours", "169"},
		{"public-url-changed"}, {"public-url-changed", "--from", "vault.example.com"}, {"move-facts", "--json"}, {"config"}, {"config", "check", "--json"},
	} {
		if code, _, _ := runAdmin(t, append(args, "--config", in.conf)...); code != 64 {
			t.Errorf("%v: %d, not a usage error", args, code)
		}
	}
	if code, _, errOut := runAdmin(t, "reenroll", "--identity", "idn_nosuchperson", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "No person with identity idn_nosuchperson") {
		t.Errorf("an unknown person: %d %q", code, errOut)
	}
	logs := r.stderr.String()
	r.stop(t)
	if strings.Contains(logs, "vlt_reenroll_") || strings.Contains(logs, "/enroll#") {
		t.Fatal("a link reached varlatchd's log")
	}
	if raw, err := os.ReadFile(in.accessLog); err == nil && strings.Contains(string(raw), "vlt_reenroll_") {
		t.Fatal("a link reached the access log")
	}

	// Offline: the same command, without a daemon.
	var offline struct {
		Links []reenrollLink `json:"links"`
	}
	adminJSON(t, &offline, "reenroll", "--identity", adminID, "--json", "--config", in.conf)
	if len(offline.Links) != 1 || offline.Links[0].IdentityID != adminID {
		t.Fatalf("offline: %+v", offline.Links)
	}
	adminJSON(t, &facts, "move-facts", "--config", in.conf)
	if *facts.PublicURL != "https://vault2.example.com" || facts.Passkeys != 0 || facts.Sessions != 0 || facts.People != 2 {
		t.Fatalf("move-facts after: %+v", facts)
	}

	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := s.Reader()
	count := func(q string, args ...any) int {
		var n int
		if err := db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The browser credentials revoked once each, with this reason; the
	// session trigger found none left; the CLI credential still live.
	if n := count(`SELECT count(*) FROM audit_events WHERE event_type = 'credential.revoked' AND metadata LIKE '%public-url-changed%'`); n != 2 {
		t.Errorf("credential.revoked for the move: %d", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE event_type = 'credential.revoked' AND metadata LIKE '%session-ended%'`); n != 0 {
		t.Errorf("credential.revoked by the session trigger: %d", n)
	}
	if n := count(`SELECT count(*) FROM credentials WHERE kind = 'cli' AND revoked_at IS NULL`); n != 1 {
		t.Errorf("live CLI credentials: %d", n)
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE event_type = 'installation.public_url_changed'`); n != 1 {
		t.Errorf("installation.public_url_changed: %d", n)
	}
	// One live link per person; four issued.
	if n := count(`SELECT count(*) FROM audit_events WHERE event_type = 'reenrollment.grant_issued'`); n != 4 {
		t.Errorf("reenrollment.grant_issued: %d", n)
	}
	for _, id := range []string{adminID, member} {
		if n := count(`SELECT count(*) FROM setup_grants WHERE kind = 'reenroll' AND subject_identity_id = ? AND consumed_at IS NULL AND revoked_at IS NULL`, id); n != 1 {
			t.Errorf("%s has %d live links", id, n)
		}
	}
	if n := count(`SELECT count(*) FROM audit_events WHERE metadata LIKE '%vlt_reenroll_%' OR resource LIKE '%vlt_reenroll_%'`); n != 0 {
		t.Errorf("a link in %d audit events", n)
	}
	// The member's latest link is the live one: enrollment accepts it and
	// refuses the one it replaced.
	svc := auth.New(s, auth.Options{})
	if g, err := svc.PeekSetupGrant(context.Background(), latest); err != nil || g.Kind != auth.GrantReenroll {
		t.Fatalf("the latest link: %+v %v", g, err)
	}
	earlier := all.Links[1].Link[strings.Index(all.Links[1].Link, "#")+1:]
	if _, err := svc.PeekSetupGrant(context.Background(), earlier); err == nil {
		t.Fatal("a replaced link is still accepted")
	}
}

// config check reports each ingress mode, and a configuration varlatchd
// would refuse is refused (78) without opening anything.
func TestConfigCheck(t *testing.T) {
	for _, c := range []struct{ extra, ingress string }{
		{"", "local"},
		{"public_url = http://localhost:8686\n", "local"},
		{"public_url = https://vault.example.com\n", "external"},
		{"public_url = https://vault.example.com\nlisten_https = 127.0.0.1:8443\nacme_ca = https://127.0.0.1:14000/dir\n", "public"},
	} {
		in := newInstall(t, c.extra)
		var f configFacts
		adminJSON(t, &f, "config", "check", "--config", in.conf)
		if f.Ingress != c.ingress {
			t.Errorf("%q: %+v", c.extra, f)
		}
		if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
			t.Errorf("%q: config check opened the database", c.extra)
		}
	}
	in := newInstall(t, "public_url = not a url\n")
	if code, _, errOut := runAdmin(t, "config", "check", "--config", in.conf); code != ExitConfig || !strings.Contains(errOut, "is not valid") {
		t.Fatalf("an invalid configuration: %d %q", code, errOut)
	}
}
