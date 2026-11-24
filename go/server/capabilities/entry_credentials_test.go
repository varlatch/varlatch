// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
)

// An entry link ends with the credential that made it (ADR-0063).

// credential gives an identity a credential of a kind, by the name it is
// called with; expires is the seconds it lives, 0 for no end.
func (w *world) credential(name, who, kind string, expires int64, session any) string {
	w.t.Helper()
	token := "vlt_x_" + name + strings.Repeat("x", 40)
	var end any
	if expires != 0 {
		end = w.now().Add(time.Duration(expires) * time.Second).UnixMicro()
	}
	w.exec("INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at, auth_session_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"crd_t_"+name, w.idn(who), kind, auth.HashToken(token), end, session, w.now().UnixMicro())
	w.f.Tokens[name] = token
	return "crd_t_" + name
}

// browser starts a browser session of a person, with a bearer called name.
func (w *world) browser(name, who, session string) string {
	w.t.Helper()
	user := "usr_" + w.idn(who)
	w.exec("INSERT INTO auth_users (id, name, email, created_at, updated_at) VALUES (?, ?, ?, 1, 1) ON CONFLICT DO NOTHING", user, who, who+"@test.invalid")
	if w.text("SELECT count(*) FROM auth_sessions WHERE id = ?", session) == "0" {
		w.exec("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 1)",
			session, user, auth.HashToken(session), w.now().Add(24*time.Hour).UnixMicro())
	}
	return w.credential(name, who, "browser", 900, session)
}

// bare is an answer without its request id.
func bare(a answer) string {
	return fmt.Sprint(a.status, " ", regexp.MustCompile(`"requestId":"[^"]*",`).ReplaceAllString(a.raw, ""))
}

const ended = `410 {"error":{"code":"EXPIRED","message":"This link has ended: ask for another one","details":{"status":"cancelled"}}}`

// wantEnded is a link that ended with its credential: looked at and used it
// is ended, with nothing about why, and its maker reads the reason.
func (w *world) wantEnded(maker string, l link, how string) {
	w.t.Helper()
	for _, as := range []string{"", "bob", "carol"} {
		if a := w.want("look as "+as, w.lookup(as, l), 410, "EXPIRED"); bare(a) != ended {
			w.t.Errorf("%s", a.raw)
		}
	}
	w.linkStatus(maker, l, "cancelled", "credential-ended")
	before := w.text("SELECT count(*) FROM value_versions")
	a := w.want("submit", w.submit("bob", l, nil), 410, "EXPIRED")
	if bare(a) != ended {
		w.t.Errorf("%s", a.raw)
	}
	md := map[string]any{"reason": "credential-ended"}
	if how != "" {
		md["credential"] = how
	}
	w.wantEvent("capability.denied", "bob", map[string]any{"entryLinkId": l.id}, md)
	if got := w.text("SELECT count(*) FROM value_versions"); got != before {
		w.t.Error("a value was written")
	}
	if got := w.text("SELECT status || ' ' || reason FROM entry_links WHERE id = ?", l.id); got != "cancelled credential-ended" {
		w.t.Errorf("%s", got)
	}
}

// wantCancelledAlike holds a link's refusal against a cancelled one's: the
// holder cannot tell them apart.
func (w *world) wantCancelledAlike(l link) {
	w.t.Helper()
	c := w.link("alice", with{"item": "ALIKE"})
	w.want("cancel", w.call("DELETE", entryPath+"/"+c.id, "alice", nil), 204, "")
	for _, as := range []string{"", "bob"} {
		if a, b := bare(w.lookup(as, l)), bare(w.lookup(as, c)); a != b {
			w.t.Errorf("%s\n%s", a, b)
		}
	}
	if a, b := bare(w.submit("bob", l, nil)), bare(w.submit("bob", c, nil)); a != b {
		w.t.Errorf("%s\n%s", a, b)
	}
}

func TestAMachinesLinkEndsWithItsCredential(t *testing.T) {
	const identities = "/v1/organizations/cap/identities/"
	for what, c := range map[string]struct {
		end func(w *world, id string)
		how string
	}{
		"revoked by an admin": {func(w *world, id string) {
			w.want("revoke", w.call("DELETE", identities+w.idn("svc")+"/credentials/"+id, "alice", nil), 204, "")
		}, "revoked"},
		"revoked by itself": {func(w *world, id string) {
			w.want("revoke", w.call("DELETE", "/v1/me/credentials/"+id, "one", nil), 204, "")
		}, "revoked"},
		"revoked by another server's release": {func(w *world, id string) {
			w.exec("UPDATE credentials SET revoked_at = ? WHERE id = ?", w.now().UnixMicro(), id)
		}, "revoked"},
		"retired": {func(w *world, id string) {
			w.want("retire", w.call("POST", identities+w.idn("svc")+"/retire", "alice", nil), 200, "")
		}, "identity-retired"},
		"retired and reactivated": {func(w *world, id string) {
			w.want("retire", w.call("POST", identities+w.idn("svc")+"/retire", "alice", nil), 200, "")
			w.want("reactivate", w.call("POST", identities+w.idn("svc")+"/reactivate", "alice", nil), 200, "")
		}, "revoked"},
		"given an earlier end": {func(w *world, id string) {
			w.exec("UPDATE credentials SET expires_at = 5 WHERE id = ?", id)
		}, "expired"},
	} {
		t.Run(what, func(t *testing.T) {
			w := entryWorld(t)
			w.allow("svc", "development", "entry-link.create-open")
			id := w.credential("one", "svc", "service", 0, nil)
			l, open := w.link("one", nil), w.link("one", with{"item": "OPEN", "restrictedTo": "anyone"})
			other := w.link("svc", with{"item": "OTHER"})
			if e := w.text("SELECT credential_id FROM entry_links WHERE id = ?", l.id); e != id {
				t.Errorf("%s", e)
			}
			w.want("before", w.lookup("bob", l), 200, "")
			c.end(w, id)
			w.wantEnded("alice", l, c.how)
			w.want("open", w.submit("", open, nil), 410, "EXPIRED")
			// Nothing brings it back, and nobody sees a difference to a cancelled one.
			w.exec("UPDATE credentials SET revoked_at = NULL, expires_at = NULL WHERE id = ?", id)
			w.exec("UPDATE identities SET disabled = 0 WHERE id = ?", w.idn("svc"))
			w.want("again", w.submit("bob", l, nil), 410, "EXPIRED")
			w.wantCancelledAlike(l)
			// Another credential of the identity keeps its links, when it lives.
			if !strings.HasPrefix(what, "retired") {
				w.want("the other one's", w.submit("bob", other, nil), 200, "")
			}
		})
	}
}

// A service credential's expiry ends its links; how the answer says so.
func TestALinkOutlivesNoServiceCredential(t *testing.T) {
	w := entryWorld(t)
	w.credential("short", "svc", "service", 120, nil)
	a := w.want("create", w.call("POST", entryPath, "short", map[string]any{"item": "NEW_KEY"}), 201, "")
	l := link{a.body["link"].(map[string]any)["id"].(string), strings.SplitN(a.body["url"].(string), "#", 2)[1]}
	if got, want := w.text("SELECT e.expires_at - c.expires_at FROM entry_links e JOIN credentials c ON c.id = e.credential_id WHERE e.id = ?", l.id), "0"; got != want {
		t.Errorf("%s µs past the credential", got)
	}
	w.later(119 * time.Second)
	w.want("look", w.lookup("bob", l), 200, "")
	w.later(2 * time.Second)
	w.want("submit", w.submit("bob", l, nil), 410, "EXPIRED")
	w.linkStatus("alice", l, "expired", nil)
	// One that ends later than the link shortens nothing.
	w.credential("long", "svc", "service", 7200, nil)
	l = w.link("long", nil)
	if got := w.text("SELECT (expires_at - created_at) / 1000000 FROM entry_links WHERE id = ?", l.id); got != "900" {
		t.Errorf("%s s", got)
	}
}

// A use limit used up is no withdrawal: making the link may be the last use.
func TestAUseLimitEndsNoLink(t *testing.T) {
	w := entryWorld(t)
	id := w.credential("once", "svc", "service", 0, nil)
	w.exec("UPDATE credentials SET max_uses = 1 WHERE id = ?", id)
	l := w.link("once", nil)
	w.want("used up", w.call("GET", entryPath, "once", nil), 401, "INVALID_CREDENTIAL")
	w.want("submit", w.submit("bob", l, nil), 200, "")
}

// An exchanged credential lives minutes: its expiry ends no link. What
// withdraws it does: its revocation, and that of the trust behind it.
func TestALinkOfAnExchangedCredential(t *testing.T) {
	bound := func(t *testing.T) (*world, string, string) {
		w := entryWorld(t)
		b := w.want("bind", w.bind("svc", nil), 201, "").body["id"].(string)
		ex := w.want("exchange", w.exchange(w.token(nil)), 201, "")
		w.f.Tokens["job"] = ex.body["token"].(string)
		return w, b, w.text("SELECT id FROM credentials WHERE token_hash = ?", auth.HashToken(w.f.Tokens["job"]))
	}
	bindings := func(w *world, b string) string {
		return "/v1/organizations/cap/identities/" + w.idn("svc") + "/oidc-bindings/" + b
	}
	t.Run("expired", func(t *testing.T) {
		w, _, id := bound(t)
		w.exec("UPDATE credentials SET expires_at = ? WHERE id = ?", w.now().Add(60*time.Second).UnixMicro(), id)
		l := w.link("job", nil)
		w.later(10 * time.Minute)
		w.want("expired", w.call("GET", entryPath, "job", nil), 401, "INVALID_CREDENTIAL")
		w.linkStatus("svc", l, "pending", nil)
		w.want("look", w.lookup("bob", l), 200, "")
		w.want("submit", w.submit("bob", l, nil), 200, "")
	})
	t.Run("revoked, also once expired", func(t *testing.T) {
		w, _, id := bound(t)
		l := w.link("job", nil)
		w.exec("UPDATE credentials SET expires_at = ? WHERE id = ?", w.now().Add(-time.Second).UnixMicro(), id)
		w.want("revoke", w.call("DELETE", "/v1/organizations/cap/identities/"+w.idn("svc")+"/credentials/"+id, "alice", nil), 204, "")
		w.wantEnded("svc", l, "revoked")
	})
	t.Run("its binding", func(t *testing.T) {
		w, b, _ := bound(t)
		l := w.link("job", nil)
		plain := w.link("svc", with{"item": "PLAIN"})
		w.want("revoke", w.call("DELETE", bindings(w, b), "alice", nil), 204, "")
		w.wantEnded("svc", l, "binding-revoked")
		// The credential it exchanged lives on until it expires, as it did;
		// it makes no more links.
		w.wantReason("make", w.call("POST", entryPath, "job", map[string]any{"item": "LATER"}), 403, "PERMISSION_DENIED", "credential-ended")
		// The identity's service credential has nothing to do with it.
		w.want("plain", w.submit("bob", plain, nil), 200, "")
	})
	t.Run("another binding, revoked before", func(t *testing.T) {
		w := entryWorld(t)
		b := w.want("bind", w.bind("svc", with{"claims": map[string]any{"team": "a"}}), 201, "").body["id"].(string)
		w.want("bind", w.bind("svc", nil), 201, "")
		w.want("revoke", w.call("DELETE", bindings(w, b), "alice", nil), 204, "")
		w.f.Tokens["job"] = w.exchanged(w.token(nil))
		w.want("submit", w.submit("bob", w.link("job", nil), nil), 200, "")
	})
}

// A person signs out, their bearers expire, they hand a session on to the
// CLI and log out there: none of it takes back a link they just sent.
func TestAPersonsOrdinaryEndsEndNoLink(t *testing.T) {
	for what, end := range map[string]func(w *world){
		"the bearer expires":  func(w *world) { w.later(16 * time.Minute) },
		"signs out":           func(w *world) { w.exec("DELETE FROM auth_sessions WHERE id = 'ses_a'") },
		"the session expires": func(w *world) { w.exec("UPDATE auth_sessions SET expires_at = 5"); w.exec("DELETE FROM auth_sessions") },
		"signs this one out":  func(w *world) { w.want("self", w.call("DELETE", "/v1/me/credentials/crd_t_a", "a", nil), 204, "") },
		"goes on in the CLI": func(w *world) {
			w.want("exchange", w.call("POST", "/v1/me/credentials/cli", "a", map[string]any{}), 201, "")
		},
		"another tab, reloaded": func(w *world) {
			w.want("same session", w.call("DELETE", "/v1/me/credentials/crd_t_a", "a2", nil), 204, "")
		},
		"this browser stays": func(w *world) {
			w.want("another session", w.call("DELETE", "/v1/me/credentials/crd_t_b", "a2", nil), 204, "")
		},
		"another person's": func(w *world) {
			w.want("bob's", w.call("DELETE", "/v1/me/credentials/crd_t_bobs", "bob", nil), 204, "")
		},
		"a machine's": func(w *world) {
			id := w.credential("m", "svc", "service", 0, nil)
			w.want("an admin's doing", w.call("DELETE", "/v1/organizations/cap/identities/"+w.idn("svc")+"/credentials/"+id, "b", nil), 204, "")
		},
		"nobody's": func(w *world) {
			w.want("another person's credential", w.call("DELETE", "/v1/me/credentials/crd_t_bobs", "b", nil), 404, "RESOURCE_NOT_FOUND")
		},
	} {
		t.Run(what, func(t *testing.T) {
			w := entryWorld(t)
			w.browser("a", "Alice", "ses_a")
			w.browser("a2", "Alice", "ses_a")
			w.browser("b", "Alice", "ses_b")
			w.browser("bobs", "bob", "ses_bob")
			l := w.link("a", with{"ttlSeconds": 3600})
			end(w)
			w.want("look", w.lookup("bob", l), 200, "")
			w.linkStatus("alice", l, "pending", nil)
			w.want("submit", w.submit("bob", l, nil), 200, "")
		})
	}
	// The CLI's: it expires, and `varlatch logout` revokes it with itself.
	w := entryWorld(t)
	w.credential("cli", "Alice", "cli", 60, nil)
	l := w.link("cli", nil)
	w.later(2 * time.Minute)
	w.want("expired", w.submit("bob", l, nil), 200, "")
	id := w.credential("cli2", "Alice", "cli", 60, nil)
	l = w.link("cli2", with{"item": "NEW_2"})
	w.want("logout", w.call("DELETE", "/v1/me/credentials/"+id, "cli2", nil), 204, "")
	w.want("logged out", w.submit("bob", l, nil), 200, "")
}

// Taking a session, or the person's access, away ends what was made with it.
func TestAPersonsLinkEndsWithAWithdrawal(t *testing.T) {
	ses := func(w *world) {
		w.browser("a", "Alice", "ses_a")
		w.browser("a2", "Alice", "ses_a")
		w.browser("b", "Alice", "ses_b")
		w.credential("cli", "Alice", "cli", 3600, nil)
		w.credential("cli2", "Alice", "cli", 3600, nil)
	}
	revoke := func(id, with string) func(w *world) {
		return func(w *world) { w.want("revoke", w.call("DELETE", "/v1/me/credentials/"+id, with, nil), 204, "") }
	}
	for what, c := range map[string]struct {
		as  string
		end func(w *world)
	}{
		"an unrelated one, from another session": {"a", revoke("crd_t_cli2", "b")},
		"the CLI's, given up by itself, and then another": {"cli", func(w *world) {
			revoke("crd_t_cli", "cli")(w)
			revoke("crd_t_cli2", "b")(w)
		}},
		"the CLI's, given up by itself, and then a browser": {"cli", func(w *world) {
			revoke("crd_t_cli", "cli")(w)
			revoke("crd_t_a", "b")(w)
		}},
		"the CLI's, given up by itself, and then again": {"cli", func(w *world) {
			revoke("crd_t_cli", "cli")(w)
			revoke("crd_t_cli", "b")(w)
		}},
		"a browser's that signed itself out, and then the CLI": {"a", func(w *world) {
			revoke("crd_t_a", "a")(w)
			revoke("crd_t_cli2", "b")(w)
		}},
		"its bearer, from another session": {"a", revoke("crd_t_a", "b")},
		"another bearer of the session":    {"a", revoke("crd_t_a2", "b")},
		"the bearer, from the CLI":         {"a", revoke("crd_t_a", "cli")},
		"one that expired, from another session": {"a", func(w *world) {
			w.exec("UPDATE credentials SET expires_at = 5 WHERE id = 'crd_t_a'")
			revoke("crd_t_a", "b")(w)
		}},
		"another browser session, from a third":      {"a", func(w *world) { w.browser("c", "Alice", "ses_c"); revoke("crd_t_b", "c")(w) }},
		"the CLI's, from a browser":                  {"cli", revoke("crd_t_cli", "a")},
		"the CLI's, from another CLI":                {"cli", revoke("crd_t_cli", "cli2")},
		"the move to another address":                {"a", func(w *world) { w.moved() }},
		"revoked from elsewhere, and then signs out": {"a", func(w *world) { revoke("crd_t_a", "b")(w); w.exec("DELETE FROM auth_sessions WHERE id = 'ses_a'") }},
	} {
		t.Run(what, func(t *testing.T) {
			w := entryWorld(t)
			ses(w)
			l := w.link(c.as, nil)
			bobs := w.link("bob", with{"item": "BOBS"})
			machines := w.link("svc", with{"item": "MACHINES"})
			c.end(w)
			if what != "the move to another address" {
				w.wantEvent("capability.revoked", "Alice", map[string]any{"entryLinkId": l.id}, map[string]any{"reason": "credential-ended", "entryLink": "member"})
			}
			w.wantEnded("alice", l, "")
			w.wantCancelledAlike(l)
			// Another person's links, and a machine's, are none of it.
			w.want("another person's", w.submit("alice", bobs, nil), 200, "")
			w.want("a machine's", w.submit("bob", machines, nil), 200, "")
		})
	}
	// What the one it is done with made stays: the login's own, and a browser's
	// in every tab of its session. Nobody else's, whatever was revoked.
	w := entryWorld(t)
	ses(w)
	l, m, n := w.link("a", nil), w.link("cli", with{"item": "NEW_2"}), w.link("a2", with{"item": "NEW_3"})
	revoke("crd_t_cli2", "a2")(w)
	w.want("the session's", w.submit("bob", l, nil), 200, "")
	w.want("the tab's own", w.submit("bob", n, nil), 200, "")
	w.want("the CLI's", w.submit("bob", m, nil), 410, "EXPIRED")
	l, m = w.link("a", with{"item": "NEW_4"}), w.link("cli", with{"item": "NEW_5"})
	revoke("crd_t_b", "cli")(w)
	w.want("the browser's", w.submit("bob", l, nil), 410, "EXPIRED")
	w.want("the CLI's own", w.submit("bob", m, nil), 200, "")
	// A CLI login handed on by a browser is a login of its own.
	w = entryWorld(t)
	ses(w)
	w.credential("handed", "Alice", "cli", 3600, "ses_a")
	l, m = w.link("handed", nil), w.link("a", with{"item": "NEW_2"})
	revoke("crd_t_cli2", "a")(w)
	w.want("the handed on one's", w.submit("bob", l, nil), 410, "EXPIRED")
	w.want("the browser's", w.submit("bob", m, nil), 200, "")
	l, m = w.link("handed", with{"item": "NEW_3"}), w.link("a", with{"item": "NEW_4"})
	revoke("crd_t_b", "handed")(w)
	w.want("its own", w.submit("bob", l, nil), 200, "")
	w.want("the browser's", w.submit("bob", m, nil), 410, "EXPIRED")
	// The membership: removed, and added again.
	w = entryWorld(t)
	w.browser("bobs", "bob", "ses_bob")
	l = w.link("bobs", nil)
	w.want("remove", w.call("DELETE", "/v1/organizations/cap/members/"+w.idn("bob"), "alice", nil), 200, "")
	w.exec("UPDATE org_memberships SET removed_at = NULL WHERE identity_id = ?", w.idn("bob"))
	w.wantEvent("capability.revoked", "Alice", map[string]any{"entryLinkId": l.id, "issuedByIdentityId": w.idn("bob")}, map[string]any{"reason": "credential-ended"})
	w.want("added again", w.submit("alice", l, nil), 410, "EXPIRED")
	// The person, disabled.
	w = entryWorld(t)
	l = w.link("bob", nil)
	w.exec("UPDATE identities SET disabled = 1 WHERE id = ?", w.idn("bob"))
	w.want("look", w.lookup("alice", l), 410, "EXPIRED")
	w.want("submit", w.submit("alice", l, nil), 410, "EXPIRED")
	w.wantEvent("capability.denied", "Alice", map[string]any{"entryLinkId": l.id}, map[string]any{"reason": "credential-ended", "credential": "identity-retired"})
}

// moved moves the installation to another address, as the operator's command
// does, which ends every browser session.
func (w *world) moved() {
	w.t.Helper()
	if _, err := w.approvals.CompletePublicURLChange(w.t.Context(), "http://127.0.0.1:8686", "http://127.0.0.1:9999"); err != nil {
		w.t.Fatal(err)
	}
}

// Machines that a deletion of their Organization suspended come back when it
// is cancelled, and so do their links: the Organization takes nothing
// meanwhile, and the link is not used up.
func TestASuspendedMachinesLinkIsNotEnded(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", nil)
	w.exec("INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) SELECT 'odl_t', id, ?, 1, 99999999999999999, 0 FROM organizations WHERE slug = 'cap'", w.idn("Alice"))
	w.exec("UPDATE identities SET disabled = 1, suspended_by_deletion = 'odl_t' WHERE id = ?", w.idn("svc"))
	w.wantReason("submit", w.submit("bob", l, nil), 403, "PERMISSION_DENIED", "organization-unavailable")
	w.exec("UPDATE identities SET disabled = 0, suspended_by_deletion = NULL WHERE id = ?", w.idn("svc"))
	w.exec("DELETE FROM organization_deletions WHERE id = 'odl_t'")
	w.want("submit", w.submit("bob", l, nil), 200, "")
}

// Links that ended with their credential leave the next one room.
func TestEndedLinksAreNotCounted(t *testing.T) {
	w := entryWorld(t)
	id := w.credential("one", "svc", "service", 0, nil)
	for i := range 100 {
		w.link("one", with{"item": fmt.Sprintf("NEW_%d", i)})
	}
	w.want("full", w.call("POST", entryPath, "svc", map[string]any{"item": "MORE"}), 429, "RATE_LIMITED")
	w.want("revoke", w.call("DELETE", "/v1/me/credentials/"+id, "one", nil), 204, "")
	w.link("svc", with{"item": "MORE"})
}

// Revoked while it is used, many times over: what the job that wrote first
// decided holds, and once the revocation is answered nothing is entered.
func TestRevokedWhileALinkIsUsed(t *testing.T) {
	for _, kind := range []string{"service", "browser"} {
		t.Run(kind, func(t *testing.T) {
			w := entryWorld(t)
			w.check = false
			entered, refused := 0, 0
			for round := range 12 {
				name := fmt.Sprintf("r%d", round)
				var id, revokeWith string
				if kind == "service" {
					id, revokeWith = w.credential(name, "svc", "service", 0, nil), name
				} else {
					id, revokeWith = w.browser(name, "Alice", "ses_"+name), "alice"
				}
				l := w.link(name, with{"item": fmt.Sprintf("RACE_%d", round)})
				var wg sync.WaitGroup
				var mu sync.Mutex
				ok := 0
				for i := range 8 {
					wg.Go(func() {
						if i == round%8 {
							if a := w.call("DELETE", "/v1/me/credentials/"+id, revokeWith, nil); a.status != 204 {
								t.Errorf("%s", a.raw)
							}
							// From here on it is too late.
							if a := w.submit("bob", l, nil); a.status != 410 {
								t.Errorf("after the revocation: %d %s", a.status, a.raw)
							}
							return
						}
						switch a := w.submit("bob", l, nil); a.status {
						case 200:
							mu.Lock()
							ok++
							mu.Unlock()
						case 410:
						default:
							t.Errorf("%d %s", a.status, a.raw)
						}
					})
				}
				wg.Wait()
				if ok > 1 {
					t.Errorf("entered %d times", ok)
				}
				versions := w.text("SELECT count(*) FROM value_versions v JOIN env_values e ON e.id = v.value_id WHERE e.item_name = ?", fmt.Sprintf("RACE_%d", round))
				if versions != fmt.Sprint(ok) {
					t.Errorf("%d entered, %s versions", ok, versions)
				}
				// The order the log has them in: entered before revoked, or not at all.
				if ok == 1 {
					entered++
					if got := w.text("SELECT (SELECT max(rowid) FROM audit_events WHERE event_type = 'value.written') < (SELECT max(rowid) FROM audit_events WHERE event_type = 'credential.revoked' AND credential_id = ?)", id); got != "1" {
						t.Error("a value was written after the credential was revoked")
					}
				} else {
					refused++
				}
			}
			t.Logf("%d entered first, %d revoked first", entered, refused)
		})
	}
}

// The credential is revoked between the request's authentication and the job
// that would make the link: none is made that its revocation did not see.
func TestRevokedWhileLinksAreMade(t *testing.T) {
	w := entryWorld(t)
	w.check = false
	for round := range 10 {
		name := fmt.Sprintf("m%d", round)
		id := w.browser(name, "Alice", "ses_"+name)
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				if i == round%8 {
					if a := w.call("DELETE", "/v1/me/credentials/"+id, "alice", nil); a.status != 204 {
						t.Errorf("%s", a.raw)
					}
					return
				}
				if a := w.call("POST", entryPath, name, map[string]any{"item": fmt.Sprintf("M_%d_%d", round, i)}); a.status != 201 && a.status != 401 {
					t.Errorf("%d %s", a.status, a.raw)
				}
			})
		}
		wg.Wait()
		if got := w.text("SELECT count(*) FROM entry_links WHERE credential_id = ? AND status = 'pending'", id); got != "0" {
			t.Errorf("round %d: %s links of a revoked credential", round, got)
		}
	}
}
