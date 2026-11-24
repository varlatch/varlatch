// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/entry"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
)

// Entry links (ADR-0063), over HTTP, on the parity fixture's rows.

const (
	entryPath = envPath + "/entry-links"
	prodEntry = "/v1/organizations/cap/projects/api/environments/production/entry-links"
	entered   = "made-up value 7f3a"
)

// allow gives subject an action in an environment of the Project.
func (w *world) allow(subject, environment string, actions ...string) string {
	w.t.Helper()
	a := w.want("grant", w.call("POST", "/v1/organizations/cap/grants", "alice", map[string]any{
		"subjectIdentityId": w.idn(subject), "actions": actions,
		"scope": map[string]any{"kind": "environments", "projectId": w.project(), "selector": map[string]any{"kind": "environments", "environmentIds": []string{w.env(environment)}}},
	}), 201, "")
	return a.body["id"].(string)
}

type link struct{ id, token string }

func (w *world) link(as string, more with) link {
	w.t.Helper()
	b := with{"item": "NEW_KEY"}
	for k, v := range more {
		b[k] = v
	}
	a := w.want("link as "+as, w.call("POST", entryPath, as, b), 201, "")
	url := a.body["url"].(string)
	before, token, ok := strings.Cut(url, "#")
	if !ok || before != "http://127.0.0.1:8686/entry" {
		w.t.Fatalf("url: %s", url)
	}
	return link{a.body["link"].(map[string]any)["id"].(string), token}
}

func (w *world) lookup(as string, l link) answer {
	return w.call("POST", "/v1/entry-links/lookup", as, map[string]any{"token": l.token})
}

func (w *world) submit(as string, l link, more with) answer {
	b := with{"token": l.token, "value": entered}
	for k, v := range more {
		b[k] = v
		if v == nil {
			delete(b, k)
		}
	}
	return w.call("POST", "/v1/entry-links/submit", as, b)
}

// linkStatus is a link as its maker reads it.
func (w *world) linkStatus(as string, l link, status string, reason any) map[string]any {
	w.t.Helper()
	a := w.want("get", w.call("GET", entryPath+"/"+l.id, as, nil), 200, "")
	if a.body["status"] != status || a.body["reason"] != reason {
		w.t.Fatalf("%v %v, want %s %v", a.body["status"], a.body["reason"], status, reason)
	}
	return a.body
}

// value is what an item is, as Alice reveals it ("" for none).
func (w *world) value(item string) string {
	w.t.Helper()
	a := w.want("reveal", w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{item}}), 200, "")
	for _, i := range a.body["items"].([]any) {
		if m := i.(map[string]any); m["name"] == item {
			return m["value"].(string)
		}
	}
	return ""
}

// agentCredential gives the Agent a credential, as agent-cred.
func (w *world) agentCredential() {
	w.t.Helper()
	token := "vlt_svc_agent" + strings.Repeat("x", 40)
	w.exec("INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_agent_t', ?, 'service', ?)", w.idn("agent"), auth.HashToken(token))
	w.f.Tokens["agent-cred"] = token
}

// noContract takes the Project's Contract away, so any name may be asked for.
func (w *world) noContract() { w.exec("UPDATE projects SET active_contract_revision_id = NULL") }

// entryWorld is a world without a Contract, whose svc may make links in
// development.
func entryWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	w.noContract()
	w.allow("svc", "development", "entry-link.create")
	return w
}

func TestAValueIsEnteredOnce(t *testing.T) {
	w := entryWorld(t)
	a := w.want("create", w.call("POST", entryPath, "svc", map[string]any{"item": "NEW_KEY", "description": "The key of the model provider's account."}), 201, "")
	made := a.body["link"].(map[string]any)
	if made["status"] != "pending" || made["restrictedTo"] != "member" || made["accepts"] != "value" || made["replace"] != false || made["requestedByIdentityId"] != w.idn("svc") || made["endedAt"] != nil {
		t.Errorf("%s", a.raw)
	}
	_, token, _ := strings.Cut(a.body["url"].(string), "#")
	l := link{made["id"].(string), token}
	w.wantEvent("capability.issued", "svc", map[string]any{"entryLinkId": l.id, "itemName": "NEW_KEY", "environmentId": w.env("development")},
		map[string]any{"entryLink": "member", "replace": false, "description": "The key of the model provider's account."})
	if e := w.event("capability.issued"); e["action"] != "entry-link.create" || !strings.Contains(fmt.Sprint(e["authz"]), "grt_") {
		t.Errorf("%v %v", e["action"], e["authz"])
	}
	// Looked at as often as a mail scanner likes, with no sign-in: no names.
	before := w.events("capability.denied")
	for range 5 {
		a := w.want("lookup", w.lookup("", l), 200, "")
		if a.raw != `{"restrictedTo":"member","signInRequired":true}` {
			t.Fatalf("%s", a.raw)
		}
	}
	w.linkStatus("svc", l, "pending", nil)
	// Signed in, what the page shows.
	a = w.want("lookup", w.lookup("bob", l), 200, "")
	for k, v := range map[string]any{"organization": "Cap", "item": "NEW_KEY", "accepts": "value", "replace": false, "environment": "development",
		"description": "The key of the model provider's account.", "signInRequired": false} {
		if k == "organization" {
			if a.body[k] == nil || a.body[k] == "" {
				t.Errorf("no %s", k)
			}
			continue
		}
		if a.body[k] != v {
			t.Errorf("%s: %v", k, a.body[k])
		}
	}
	if r := a.body["requestedBy"].(map[string]any); r["name"] != "svc" || r["kind"] != "service" {
		t.Errorf("%v", r)
	}
	if w.events("capability.denied") != before {
		t.Error("a look was recorded")
	}
	// Without a sign-in nothing is entered.
	w.want("anonymous", w.submit("", l, nil), 401, "AUTHENTICATION_REQUIRED")
	a = w.want("submit", w.submit("bob", l, nil), 200, "")
	if a.raw != `{"status":"entered"}` {
		t.Errorf("%s", a.raw)
	}
	if got := w.value("NEW_KEY"); got != entered {
		t.Errorf("%q", got)
	}
	// Bob wrote it; svc, which asked, knows that it was and nothing more.
	w.wantEvent("value.written", "bob", map[string]any{"itemName": "NEW_KEY"}, map[string]any{"entryLinkId": l.id, "entryLink": "member", "requestedByIdentityId": w.idn("svc")})
	if st := w.linkStatus("svc", l, "entered", nil); st["endedAt"] == nil {
		t.Errorf("%v", st)
	}
	// Once.
	w.want("again", w.submit("bob", l, with{"value": "another"}), 410, "CONSUMED")
	w.wantEvent("capability.denied", "bob", map[string]any{"entryLinkId": l.id}, map[string]any{"reason": "already-entered"})
	w.want("looked at again", w.lookup("bob", l), 410, "CONSUMED")
	if got := w.value("NEW_KEY"); got != entered {
		t.Errorf("%q", got)
	}
	// The link's secret, and the value, are in no table and no event.
	for _, r := range paritytest.Rows(t, w.store, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'") {
		for _, row := range paritytest.Rows(t, w.store, "SELECT * FROM "+r["name"].(string)) {
			if s := fmt.Sprint(row); strings.Contains(s, token) || strings.Contains(s, entered) {
				t.Errorf("the table %v holds %v", r["name"], row)
			}
		}
	}
	// svc gained nothing: it reads, reveals and writes no value.
	w.want("svc reveals", w.call("POST", envPath+"/disclosures", "svc", map[string]any{"items": []string{"NEW_KEY"}}), 403, "PERMISSION_DENIED")
	w.want("svc lists", w.call("GET", envPath+"/effective-configuration", "svc", nil), 403, "PERMISSION_DENIED")
	w.want("svc writes", w.call("PUT", envPath+"/values/OTHER", "svc", map[string]any{"value": "x"}), 403, "PERMISSION_DENIED")
	w.want("svc deletes", w.call("DELETE", envPath+"/values/NEW_KEY", "svc", nil), 403, "PERMISSION_DENIED")
}

// The restart between making a link and using it, and between using it and
// trying again.
func TestAnEntryLinkIsDurable(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", nil)
	w.restart()
	w.want("submit", w.submit("bob", l, nil), 200, "")
	w.restart()
	w.want("again", w.submit("bob", l, nil), 410, "CONSUMED")
}

func TestSubmittedByManyAtOnce(t *testing.T) {
	w := entryWorld(t)
	w.allow("svc", "development", "entry-link.create-open")
	w.check = false
	for round := range 3 {
		l := w.link("svc", with{"item": fmt.Sprintf("NEW_%d", round), "restrictedTo": "anyone"})
		var wg sync.WaitGroup
		var mu sync.Mutex
		statuses := map[int]int{}
		for i := range 20 {
			wg.Go(func() {
				a := w.submit("", l, with{"value": fmt.Sprintf("value %d", i)})
				mu.Lock()
				defer mu.Unlock()
				statuses[a.status]++
			})
		}
		wg.Wait()
		if statuses[200] != 1 || statuses[410] != 19 {
			t.Errorf("%v", statuses)
		}
		if n := w.text("SELECT count(*) FROM value_versions v JOIN env_values e ON e.id = v.value_id WHERE e.item_name = ?", fmt.Sprintf("NEW_%d", round)); n != "1" {
			t.Errorf("%s versions", n)
		}
	}
}

func TestWhoMayMakeEntryLinks(t *testing.T) {
	w := newWorld(t)
	w.noContract()
	ask := func(as string, more with) answer {
		b := with{"item": "NEW_KEY"}
		for k, v := range more {
			b[k] = v
		}
		return w.call("POST", entryPath, as, b)
	}
	// Nobody by role: not svc, which is no more than a member of it.
	w.want("svc without", ask("svc", nil), 403, "PERMISSION_DENIED")
	w.wantEvent("authorization.denied", "svc", map[string]any{"environmentId": w.env("development")}, nil)
	if e := w.event("authorization.denied"); e["action"] != "entry-link.create" {
		t.Errorf("%v", e["action"])
	}
	g := w.allow("svc", "development", "entry-link.create")
	// Only where it is given, and not for a link open to anyone.
	w.want("production", w.call("POST", prodEntry, "svc", map[string]any{"item": "NEW_KEY"}), 403, "PERMISSION_DENIED")
	w.want("anyone", ask("svc", with{"restrictedTo": "anyone"}), 403, "PERMISSION_DENIED")
	// Nor does that right make the other kind.
	w.allow("broker", "development", "entry-link.create-open")
	w.want("open", ask("broker", with{"restrictedTo": "anyone", "item": "OPEN_KEY"}), 201, "")
	w.want("for a member", ask("broker", nil), 403, "PERMISSION_DENIED")
	// To replace a value takes the right to write one.
	w.want("replace", ask("svc", with{"item": "SECRET_A", "replace": true}), 403, "PERMISSION_DENIED")
	if e := w.event("authorization.denied"); e["action"] != "config.value.write" {
		t.Errorf("%v", e["action"])
	}
	// It counts for no Agent and no person, whatever their Grants say.
	w.allow("agent", "development", "entry-link.create", "entry-link.create-open")
	w.agentCredential()
	w.want("an Agent", ask("agent-cred", nil), 403, "PERMISSION_DENIED")
	w.want("an Agent, anyone", ask("agent-cred", with{"restrictedTo": "anyone"}), 403, "PERMISSION_DENIED")
	w.allow("bob", "production", "entry-link.create", "entry-link.create-open")
	w.want("a person without config.value.write", w.call("POST", prodEntry, "bob", map[string]any{"item": "NEW_KEY"}), 403, "PERMISSION_DENIED")
	// A person with config.value.write makes any.
	w.want("alice", ask("alice", with{"restrictedTo": "anyone", "item": "ALICES"}), 201, "")
	w.want("alice replaces", ask("alice", with{"item": "SECRET_A", "replace": true}), 201, "")
	// Outsiders see nothing.
	w.want("carol", ask("carol", nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another Organization's", ask("obroker", nil), 404, "RESOURCE_NOT_FOUND")
	w.want("nobody", ask("", nil), 401, "AUTHENTICATION_REQUIRED")
	w.want("revoked", w.call("DELETE", "/v1/organizations/cap/grants/"+g, "alice", nil), 204, "")
	w.want("svc, its Grant removed", ask("svc", nil), 403, "PERMISSION_DENIED")
}

func TestEntryLinkActionsAreNoBuiltInRoles(t *testing.T) {
	w := newWorld(t)
	for _, a := range []string{"entry-link.create", "entry-link.create-open"} {
		r := w.want("permissions", w.call("GET", "/v1/organizations/cap/me/permissions", "alice", nil), 200, "")
		if strings.Contains(r.raw, a) {
			t.Errorf("an admin holds %s", a)
		}
	}
	// A machine's reach names them, where they are granted.
	w.allow("svc", "development", "entry-link.create")
	a := w.want("reach", w.call("GET", "/v1/organizations/cap/identities/"+w.idn("svc")+"/reach", "alice", nil), 200, "")
	if !strings.Contains(a.raw, `"entry-link.create"`) || strings.Contains(a.raw, `"entry-link.create-open"`) {
		t.Errorf("%s", a.raw)
	}
}

func TestWhatCannotBeEntered(t *testing.T) {
	w := newWorld(t)
	w.allow("svc", "development", "entry-link.create")
	for _, c := range []struct {
		what   string
		body   map[string]any
		status int
		code   string
		reason string
	}{
		{"an item there is", with{"item": "SECRET_A"}, 409, "VERSION_CONFLICT", "value-exists"},
		{"no Secret", with{"item": "PLAIN_HOST", "replace": false}, 422, "VALIDATION_FAILED", "not-sensitive"},
		{"not in the Contract", with{"item": "NODE_OPTIONS"}, 422, "VALIDATION_FAILED", "not-in-contract"},
		{"no name", with{"item": "lower"}, 422, "VALIDATION_FAILED", ""},
		{"a reserved name", with{"item": "VARLATCH_RUN_CONTEXT"}, 422, "VALIDATION_FAILED", ""},
		{"none", map[string]any{}, 422, "VALIDATION_FAILED", ""},
		{"too long", with{"item": "NEW", "ttlSeconds": 3601}, 422, "VALIDATION_FAILED", ""},
		{"too short", with{"item": "NEW", "ttlSeconds": 59}, 422, "VALIDATION_FAILED", ""},
		{"somebody, unnamed", with{"item": "NEW", "restrictedTo": "identity"}, 422, "VALIDATION_FAILED", ""},
		{"a name for nobody", with{"item": "NEW", "identityId": w.idn("bob")}, 422, "VALIDATION_FAILED", ""},
		{"a machine", with{"item": "NEW", "restrictedTo": "identity", "identityId": w.idn("broker")}, 422, "VALIDATION_FAILED", ""},
		{"an outsider", with{"item": "NEW", "restrictedTo": "identity", "identityId": w.idn("carol")}, 422, "VALIDATION_FAILED", ""},
		{"accepts", with{"item": "NEW", "accepts": "oauth"}, 422, "VALIDATION_FAILED", ""},
		{"a link in the words", with{"item": "NEW", "description": "see https://evil.example"}, 422, "VALIDATION_FAILED", ""},
	} {
		a := w.want(c.what, w.call("POST", entryPath, "svc", c.body), c.status, c.code)
		if c.reason != "" && !strings.Contains(a.raw, `"reason":"`+c.reason+`"`) {
			t.Errorf("%s: %s", c.what, a.raw)
		}
	}
	// A value where a seed is, and a seed where a value is.
	w.want("seed", w.setSeed(otpItem, uriA), 200, "")
	w.wantReason("over a seed", w.call("POST", entryPath, "alice", map[string]any{"item": otpItem, "replace": true}), 422, "VALIDATION_FAILED", "one-time-code")
	w.want("a seed, replaced", w.call("POST", entryPath, "alice", map[string]any{"item": otpItem, "replace": true, "accepts": "otpauth"}), 201, "")
	// What the Contract names and nobody set; and, for who may write, any.
	w.link("svc", with{"item": "SECRET_NOVAL"})
	w.link("alice", with{"item": "ANY_NAME"})
	w.allow("svc", "development", "config.value.write")
	w.link("svc", with{"item": "ANY_NAME"})
	// While it is rotated (the fixture's SECRET_B is).
	w.want("rotating", w.call("POST", entryPath, "alice", map[string]any{"item": "SECRET_B", "replace": true}), 409, "ROTATION_IN_PROGRESS")
}

func TestAnOAuthConnectionIsNotEntered(t *testing.T) {
	w := connected(t, nil)
	for _, accepts := range []string{"value", "otpauth"} {
		w.wantReason(accepts, w.call("POST", entryPath, "alice", map[string]any{"item": mailItem, "replace": true, "accepts": accepts}), 422, "VALIDATION_FAILED", "oauth-connection")
	}
	// Nor one that came after the link.
	l := w.link("alice", with{"item": "LATER_TOKEN"})
	w.create(with{"item": "LATER_TOKEN"})
	w.wantReason("later", w.submit("bob", l, nil), 409, "STATE_CHANGED", "value-changed")
	w.linkStatus("alice", l, "cancelled", "value-changed")
}

func TestAChangedValueEndsTheLink(t *testing.T) {
	for what, change := range map[string]func(w *world, item string){
		"written": func(w *world, item string) {
			w.want("set", w.call("PUT", envPath+"/values/"+item, "alice", map[string]any{"value": "made-up other"}), 200, "")
		},
		"another link": func(w *world, item string) {
			w.want("submit", w.submit("alice", w.link("alice", with{"item": item}), nil), 200, "")
		},
		"a seed": func(w *world, item string) {
			w.want("seed", w.setSeed(item, uriA), 200, "")
		},
		"not in the Contract any more": func(w *world, item string) {
			w.exec("UPDATE projects SET active_contract_revision_id = (SELECT id FROM contract_revisions WHERE project_id = projects.id LIMIT 1)")
		},
		"no Secret any more": func(w *world, item string) {
			w.exec("UPDATE projects SET active_contract_revision_id = (SELECT id FROM contract_revisions WHERE project_id = projects.id LIMIT 1)")
			w.exec("UPDATE contract_revisions SET contract = json_insert(contract, '$.items[#]', json('{\"name\":\"" + item + "\",\"type\":\"string\",\"required\":{\"kind\":\"never\"},\"sensitive\":false}')) WHERE project_id = '" + w.project() + "'")
		},
	} {
		t.Run(what, func(t *testing.T) {
			w := entryWorld(t)
			l := w.link("svc", nil)
			change(w, "NEW_KEY")
			w.wantReason("submit", w.submit("bob", l, nil), 409, "STATE_CHANGED", "value-changed")
			w.wantEvent("capability.denied", "bob", map[string]any{"entryLinkId": l.id, "issuedByIdentityId": w.idn("svc")}, map[string]any{"reason": "value-changed"})
			w.linkStatus("svc", l, "cancelled", "value-changed")
			w.want("again", w.submit("bob", l, nil), 410, "EXPIRED")
		})
	}
}

func TestReplacing(t *testing.T) {
	w := newWorld(t)
	w.noContract()
	w.allow("svc", "development", "entry-link.create", "config.value.write")
	l := w.link("svc", with{"item": "SECRET_A", "replace": true})
	w.want("submit", w.submit("bob", l, nil), 200, "")
	if got := w.value("SECRET_A"); got != entered {
		t.Errorf("%q", got)
	}
	// The one it was made for, and no other: replaced, deleted, rotated.
	for what, change := range map[string]func(item string){
		"written": func(item string) {
			w.want("set", w.call("PUT", envPath+"/values/"+item, "alice", map[string]any{"value": "made-up other"}), 200, "")
		},
		"deleted": func(item string) { w.want("delete", w.call("DELETE", envPath+"/values/"+item, "alice", nil), 204, "") },
		"rotated": func(item string) {
			w.want("rotate", w.call("POST", envPath+"/values/"+item+"/rotations", "alice", map[string]any{"value": "made-up other"}), 201, "")
		},
	} {
		w.want("set", w.call("PUT", envPath+"/values/SECRET_R", "alice", map[string]any{"value": "made-up first"}), 200, "")
		l := w.link("svc", with{"item": "SECRET_R", "replace": true})
		change("SECRET_R")
		w.wantReason(what, w.submit("bob", l, nil), 409, "STATE_CHANGED", "value-changed")
	}
	// Nothing there: it must still be nothing.
	l = w.link("svc", with{"item": "NOTHING_YET", "replace": true})
	w.want("submit", w.submit("bob", l, nil), 200, "")
	// The right to write, removed meanwhile.
	l = w.link("svc", with{"item": "SECRET_A", "replace": true})
	w.exec("UPDATE grants SET actions = json('[\"entry-link.create\"]') WHERE subject_identity_id = ?", w.idn("svc"))
	w.wantReason("no right to write", w.submit("bob", l, nil), 403, "PERMISSION_DENIED", "requester-not-allowed")
}

// An inherited value is a value: a link overrides none without saying so.
func TestAnInheritedValueIsNotOverridden(t *testing.T) {
	w := newWorld(t)
	w.noContract()
	w.want("derive", w.call("POST", "/v1/organizations/cap/projects/api/environments", "alice",
		map[string]any{"name": "development/preview", "kind": "preview", "parentEnvironmentId": w.env("development"), "expiresAt": w.now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z")}), 201, "")
	path := "/v1/organizations/cap/projects/api/environments/development%2Fpreview/entry-links"
	w.allow("svc", "development", "entry-link.create")
	w.wantReason("inherited", w.call("POST", path, "svc", map[string]any{"item": "SECRET_A"}), 409, "VERSION_CONFLICT", "value-exists")
	// One that the parent was given meanwhile.
	a := w.want("new", w.call("POST", path, "svc", map[string]any{"item": "NEW_KEY"}), 201, "")
	_, token, _ := strings.Cut(a.body["url"].(string), "#")
	w.want("set", w.call("PUT", envPath+"/values/NEW_KEY", "alice", map[string]any{"value": "made-up parent's"}), 200, "")
	w.wantReason("inherited meanwhile", w.submit("bob", link{token: token}, nil), 409, "STATE_CHANGED", "value-changed")
	// Asked to replace it, the environment's own value is written.
	a = w.want("replace", w.call("POST", path, "alice", map[string]any{"item": "SECRET_A", "replace": true}), 201, "")
	_, token, _ = strings.Cut(a.body["url"].(string), "#")
	w.want("submit", w.submit("bob", link{token: token}, nil), 200, "")
	if got := w.value("SECRET_A"); got != "a-secret" {
		t.Errorf("the parent's value is %q", got)
	}
}

func TestWhoMayEnter(t *testing.T) {
	w := entryWorld(t)
	w.allow("svc", "development", "entry-link.create-open")
	// One person.
	l := w.link("svc", with{"restrictedTo": "identity", "identityId": w.idn("bob")})
	if a := w.lookup("", l); a.raw != `{"restrictedTo":"identity","signInRequired":true}` {
		t.Errorf("%s", a.raw)
	}
	for _, as := range []string{"alice", "carol", "svc", "broker"} {
		w.wantReason("look as "+as, w.lookup(as, l), 403, "PERMISSION_DENIED", "not-for-you")
		w.wantReason("as "+as, w.submit(as, l, nil), 403, "PERMISSION_DENIED", "not-for-you")
	}
	w.agentCredential()
	w.wantReason("an Agent", w.submit("agent-cred", l, nil), 403, "PERMISSION_DENIED", "not-for-you")
	w.want("no credential", w.submit("vlt_made_up", l, nil), 401, "INVALID_CREDENTIAL")
	w.linkStatus("svc", l, "pending", nil)
	w.want("bob", w.submit("bob", l, nil), 200, "")
	// A member.
	l = w.link("svc", with{"item": "NEW_2"})
	for _, as := range []string{"carol", "broker", "obroker"} {
		a := w.wantReason("as "+as, w.submit(as, l, nil), 403, "PERMISSION_DENIED", "not-for-you")
		if strings.Contains(a.raw, "NEW_2") || strings.Contains(a.raw, "svc") {
			t.Errorf("%s", a.raw)
		}
	}
	w.want("alice", w.submit("alice", l, nil), 200, "")
	// A member who is one no longer.
	l = w.link("svc", with{"item": "NEW_3", "restrictedTo": "identity", "identityId": w.idn("bob")})
	w.exec("UPDATE org_memberships SET removed_at = 5 WHERE identity_id = ?", w.idn("bob"))
	w.wantReason("removed", w.submit("bob", l, nil), 403, "PERMISSION_DENIED", "not-for-you")
	// Anyone: nobody known is recorded, whoever's browser it is.
	l = w.link("svc", with{"item": "NEW_4", "restrictedTo": "anyone"})
	a := w.want("lookup", w.lookup("", l), 200, "")
	if a.body["item"] != "NEW_4" || a.body["signInRequired"] != false {
		t.Errorf("%s", a.raw)
	}
	w.want("submit", w.submit("alice", l, nil), 200, "")
	e := w.event("value.written")
	if e["actor_identity_id"] != nil || e["credential_id"] != nil {
		t.Errorf("actor %v", e["actor_identity_id"])
	}
	if by := paritytest.Rows(t, w.store, "SELECT s.created_by FROM env_values v JOIN value_versions s ON s.id = v.current_version_id WHERE v.item_name = 'NEW_4'"); by[0]["created_by"] != nil {
		t.Errorf("%v", by)
	}
	// And everything reads it as any value.
	if got := w.value("NEW_4"); got != entered {
		t.Errorf("%q", got)
	}
	w.want("listed", w.call("GET", envPath+"/effective-configuration", "alice", nil), 200, "")
	w.want("exposure", w.call("GET", "/v1/organizations/cap/members/"+w.idn("Alice")+"/exposure", "alice", nil), 200, "")
}

func TestASeedIsEntered(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", with{"item": "PORTAL_NEW_OTP", "accepts": "otpauth"})
	if a := w.want("look", w.lookup("bob", l), 200, ""); a.body["accepts"] != "otpauth" {
		t.Errorf("%s", a.raw)
	}
	w.want("a value", w.submit("bob", l, nil), 422, "VALIDATION_FAILED")
	a := w.want("no URI", w.submit("bob", l, with{"value": nil, "otpauth": "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"}), 422, "VALIDATION_FAILED")
	if strings.Contains(a.raw, "JBSWY") {
		t.Errorf("%s", a.raw)
	}
	w.want("both", w.submit("bob", l, with{"otpauth": uriA}), 422, "VALIDATION_FAILED")
	w.want("a seed", w.submit("bob", l, with{"value": nil, "otpauth": uriA}), 200, "")
	w.wantEvent("value.written", "bob", map[string]any{"itemName": "PORTAL_NEW_OTP"}, map[string]any{"totp": true, "entryLinkId": l.id})
	if got := w.value("PORTAL_NEW_OTP"); got != "" {
		t.Errorf("revealed as a value: %q", got)
	}
	// And a seed where a value is asked for.
	l = w.link("svc", nil)
	w.want("a seed", w.submit("bob", l, with{"value": nil, "otpauth": uriA}), 422, "VALIDATION_FAILED")
	w.want("nothing", w.submit("bob", l, with{"value": nil}), 422, "VALIDATION_FAILED")
	w.want("empty", w.submit("bob", l, with{"value": ""}), 422, "VALIDATION_FAILED")
	w.want("too long", w.submit("bob", l, with{"value": strings.Repeat("x", entry.MaxValue+1)}), 422, "VALIDATION_FAILED")
	w.want("too long in bytes", w.submit("bob", l, with{"value": strings.Repeat("é", entry.MaxValue/2+1)}), 422, "VALIDATION_FAILED")
	w.linkStatus("svc", l, "pending", nil)
	// A value that would be replaced by another one where it is used.
	for _, v := range []string{"${SECRET_A}", "a ${X} b", "$${SECRET_A}"} {
		w.wantReason(v, w.submit("bob", l, with{"value": v}), 422, "VALIDATION_FAILED", "reference")
	}
	w.linkStatus("svc", l, "pending", nil)
	// Lines and spaces are the value's.
	lines := "-----BEGIN MADE UP-----\r\nAAAA $ {B} ${ \n -----END MADE UP-----\n"
	w.want("lines", w.submit("bob", l, with{"value": lines}), 200, "")
	if got := w.value("NEW_KEY"); got != lines {
		t.Errorf("%q", got)
	}
}

func TestExpiredAndCancelled(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", with{"ttlSeconds": 60})
	w.later(59 * time.Second)
	w.want("look", w.lookup("bob", l), 200, "")
	w.later(2 * time.Second)
	a := w.want("look", w.lookup("bob", l), 410, "EXPIRED")
	if !strings.Contains(a.raw, `"status":"expired"`) {
		t.Errorf("%s", a.raw)
	}
	w.want("submit", w.submit("bob", l, nil), 410, "EXPIRED")
	w.linkStatus("svc", l, "expired", nil)
	w.want("cancel an expired one", w.call("DELETE", entryPath+"/"+l.id, "svc", nil), 404, "RESOURCE_NOT_FOUND")
	// Cancelled by who made it, or by a person who may write.
	for _, as := range []string{"svc", "alice"} {
		l := w.link("svc", nil)
		w.want("cancel as "+as, w.call("DELETE", entryPath+"/"+l.id, as, nil), 204, "")
		w.linkStatus("svc", l, "cancelled", "cancelled")
		a := w.want("submit", w.submit("bob", l, nil), 410, "EXPIRED")
		if !strings.Contains(a.raw, `"status":"cancelled"`) {
			t.Errorf("%s", a.raw)
		}
		w.want("again", w.call("DELETE", entryPath+"/"+l.id, as, nil), 404, "RESOURCE_NOT_FOUND")
	}
	w.wantEvent("capability.revoked", "Alice", map[string]any{"issuedByIdentityId": w.idn("svc")}, map[string]any{"entryLink": "member"})
	// Cancelling takes away, so its maker does it with or without the Grant.
	l = w.link("svc", nil)
	w.exec("DELETE FROM grants WHERE subject_identity_id = ?", w.idn("svc"))
	w.want("cancel without", w.call("DELETE", entryPath+"/"+l.id, "svc", nil), 204, "")
}

func TestListAndGetEntryLinks(t *testing.T) {
	w := entryWorld(t)
	w.allow("broker", "development", "entry-link.create")
	mine := w.link("svc", nil)
	theirs := w.link("broker", with{"item": "BROKERS"})
	a := w.want("list", w.call("GET", entryPath, "svc", nil), 200, "")
	if items := a.body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != mine.id || strings.Contains(a.raw, "vlt_entry_") || strings.Contains(a.raw, "hash") {
		t.Errorf("%s", a.raw)
	}
	a = w.want("list", w.call("GET", entryPath, "alice", nil), 200, "")
	if items := a.body["items"].([]any); len(items) != 2 {
		t.Errorf("%s", a.raw)
	}
	for _, c := range [][3]string{{"GET", "svc", theirs.id}, {"DELETE", "svc", theirs.id}, {"GET", "broker2", mine.id}, {"GET", "svc", "enl_none"}, {"GET", "carol", mine.id},
		{"DELETE", "carol", mine.id}, {"GET", "obroker", mine.id}} {
		w.want(c[0]+" as "+c[1], w.call(c[0], entryPath+"/"+c[2], c[1], nil), 404, "RESOURCE_NOT_FOUND")
	}
	// In its own environment only.
	w.want("another environment", w.call("GET", prodEntry+"/"+mine.id, "svc", nil), 404, "RESOURCE_NOT_FOUND")
	// A person without config.value.write.
	w.want("bob in production", w.call("GET", prodEntry, "bob", nil), 403, "PERMISSION_DENIED")
	// An Agent sees its own: none.
	w.agentCredential()
	if a := w.want("agent", w.call("GET", entryPath, "agent-cred", nil), 200, ""); len(a.body["items"].([]any)) != 0 {
		t.Errorf("%s", a.raw)
	}
}

func TestWhatEndsWithItsMaker(t *testing.T) {
	for what, end := range map[string]func(w *world){
		"its Grant":  func(w *world) { w.exec("DELETE FROM grants WHERE subject_identity_id = ?", w.idn("svc")) },
		"its action": func(w *world) { w.exec("UPDATE grants SET actions = json('[\"entry-link.create-open\"]')") },
	} {
		t.Run(what, func(t *testing.T) {
			w := entryWorld(t)
			l := w.link("svc", nil)
			end(w)
			w.wantReason("look", w.lookup("bob", l), 403, "PERMISSION_DENIED", "requester-not-allowed")
			w.wantReason("submit", w.submit("bob", l, nil), 403, "PERMISSION_DENIED", "requester-not-allowed")
			if got := w.text("SELECT status FROM entry_links WHERE id = ?", l.id); got != "pending" {
				t.Errorf("%s", got)
			}
		})
	}
	// A person's, once they may not write there or are no member.
	w := newWorld(t)
	l := w.link("bob", nil)
	w.exec("UPDATE org_memberships SET removed_at = 5 WHERE identity_id = ?", w.idn("bob"))
	w.wantReason("removed", w.submit("alice", l, nil), 403, "PERMISSION_DENIED", "requester-not-allowed")
}

func TestFrozenAndDeleted(t *testing.T) {
	w := entryWorld(t)
	w.allow("svc", "development", "entry-link.create-open")
	l, open, gone := w.link("svc", nil), w.link("svc", with{"item": "OPEN", "restrictedTo": "anyone"}), w.link("svc", with{"item": "GONE"})
	w.exec("INSERT INTO organization_freezes (id, organization_id, frozen_by, reason, frozen_at) SELECT 'ofz_t', id, ?, 'x', 1 FROM organizations WHERE slug = 'cap'", w.idn("Alice"))
	for as, l := range map[string]link{"bob": l, "": open} {
		w.wantReason("look", w.lookup(as, l), 403, "PERMISSION_DENIED", "organization-unavailable")
		w.wantReason("submit", w.submit(as, l, nil), 403, "PERMISSION_DENIED", "organization-unavailable")
	}
	w.want("create", w.call("POST", entryPath, "svc", map[string]any{"item": "X"}), 409, "ORGANIZATION_FROZEN")
	w.want("list", w.call("GET", entryPath, "svc", nil), 200, "")
	w.want("cancel", w.call("DELETE", entryPath+"/"+gone.id, "svc", nil), 204, "")
	w.exec("UPDATE organization_freezes SET lifted_at = 2, lifted_by = frozen_by, lift_method = 'approval' WHERE id = 'ofz_t'")
	// A deletion in progress.
	w.exec("INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required) SELECT 'odl_t', id, ?, 1, 99999999999999999, 0 FROM organizations WHERE slug = 'cap'", w.idn("Alice"))
	w.wantReason("deleting", w.submit("", open, nil), 403, "PERMISSION_DENIED", "organization-unavailable")
	w.exec("DELETE FROM organization_deletions WHERE id = 'odl_t'")
	// The environment expires, and is deleted.
	w.exec("UPDATE environments SET expires_at = 5 WHERE id = ?", w.env("development"))
	w.want("expired", w.submit("", open, nil), 410, "EXPIRED")
	w.exec("UPDATE environments SET expires_at = NULL WHERE id = ?", w.env("development"))
	w.want("delete", w.call("DELETE", envPath, "alice", nil), 204, "")
	w.want("deleted", w.submit("", open, nil), 410, "EXPIRED")
	w.want("deleted", w.lookup("bob", l), 410, "EXPIRED")
	// The Organization.
	w.exec("UPDATE organizations SET deleted_at = 5 WHERE slug = 'cap'")
	w.want("no organization", w.submit("", open, nil), 410, "EXPIRED")
}

func TestPasskeyVerification(t *testing.T) {
	w := entryWorld(t)
	w.allow("svc", "development", "entry-link.create-open")
	control := func(mode string) {
		w.exec("INSERT INTO security_controls (organization_id, control, mode, version) SELECT id, 'passkey-verification', ?, 1 FROM organizations WHERE slug = 'cap' ON CONFLICT DO UPDATE SET mode = excluded.mode", mode)
	}
	member, open := w.link("svc", nil), w.link("svc", with{"item": "OPEN", "restrictedTo": "anyone"})
	// Under report nothing is refused, and a link open to anyone is counted.
	control("report")
	w.link("svc", with{"item": "OPEN_2", "restrictedTo": "anyone"})
	w.link("svc", with{"item": "NEW_2"})
	if got := w.text("SELECT coalesce(max(operation || ' ' || reason || ' ' || actor_identity_id), '') FROM security_control_counters"); got != "entry-link.create-open no-evidence "+w.idn("svc") {
		t.Errorf("%q", got)
	}
	control("enforce")
	w.wantReason("create", w.call("POST", entryPath, "svc", map[string]any{"item": "OPEN_3", "restrictedTo": "anyone"}), 403, "PERMISSION_DENIED", "passkey-verification")
	w.wantReason("look", w.lookup("", open), 403, "PERMISSION_DENIED", "passkey-verification")
	w.wantReason("submit", w.submit("", open, nil), 403, "PERMISSION_DENIED", "passkey-verification")
	// A person whose sign-in has no evidence: as for any write of a value.
	w.want("write", w.call("PUT", envPath+"/values/X", "bob", map[string]any{"value": "x"}), 403, "PASSKEY_VERIFICATION_REQUIRED")
	w.want("submit", w.submit("bob", member, nil), 403, "PASSKEY_VERIFICATION_REQUIRED")
	w.wantEvent("capability.denied", "bob", map[string]any{"entryLinkId": member.id}, map[string]any{"reason": "passkey-verification"})
	control("off")
	w.want("submit", w.submit("bob", member, nil), 200, "")
	w.want("submit", w.submit("", open, nil), 200, "")
}

func TestUnknownLinks(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", nil)
	before := w.text("SELECT count(*) FROM audit_events")
	bad := []string{"vlt_entry_" + strings.Repeat("A", 43), l.token + "x", l.token[:len(l.token)-1], strings.TrimPrefix(l.token, "vlt_entry_"), l.id, "x", strings.ToUpper(l.token)}
	for i, b := range bad {
		for _, path := range []string{"lookup", "submit"} {
			a := w.want("unknown", w.call("POST", "/v1/entry-links/"+path, "", map[string]any{"token": b, "value": "x"}), 404, "RESOURCE_NOT_FOUND")
			if path == "lookup" && a.body["error"].(map[string]any)["message"] != "There is no such entry link: it may be old, or not copied whole" {
				t.Errorf("%d: %s", i, a.raw)
			}
		}
	}
	for range 6 {
		w.want("unknown", w.lookup("", link{token: "x"}), 404, "RESOURCE_NOT_FOUND")
	}
	// The twenty-first waits, whatever it asks for; another address does not.
	a := w.want("limited", w.lookup("", link{token: "x"}), 429, "RATE_LIMITED")
	if !strings.Contains(a.raw, "retryAfterSeconds") {
		t.Errorf("%s", a.raw)
	}
	w.want("limited", w.lookup("bob", l), 429, "RATE_LIMITED")
	w.later(10*time.Minute + time.Second)
	w.want("later", w.lookup("bob", l), 200, "")
	if got := w.text("SELECT count(*) FROM audit_events"); got != before {
		t.Error("unknown links were recorded")
	}
	// A body that is none.
	w.want("no token", w.call("POST", "/v1/entry-links/lookup", "", map[string]any{}), 422, "VALIDATION_FAILED")
	w.check = false
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
		if a := w.call(m, "/v1/entry-links/lookup?token="+l.token, "", nil); a.status == 200 || a.status == 201 {
			t.Errorf("%s: %d", m, a.status)
		}
	}
}

func TestLimits(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", nil)
	for i := range 99 {
		w.link("svc", with{"item": fmt.Sprintf("NEW_%d", i)})
	}
	w.want("a hundred and one", w.call("POST", entryPath, "svc", map[string]any{"item": "MORE"}), 429, "RATE_LIMITED")
	// Another identity's are its own.
	w.link("alice", with{"item": "ALICES"})
	// Refusals of one link: the first twenty are recorded, and it is not
	// used up by them.
	before := w.events("capability.denied")
	for range 30 {
		w.want("not theirs", w.submit("carol", l, nil), 403, "PERMISSION_DENIED")
	}
	if got := w.events("capability.denied"); got == before || fmt.Sprint(got) != fmt.Sprint(atoi(t, before)+20) {
		t.Errorf("%s before, %s after", before, got)
	}
	w.want("bob", w.submit("bob", l, nil), 200, "")
	// Forgotten a day after they expired, by the next one made, or the worker.
	w.later(26 * time.Hour)
	if err := entry.Prune(t.Context(), w.store, w.now()); err != nil {
		t.Fatal(err)
	}
	if got := w.text("SELECT count(*) FROM entry_links"); got != "0" {
		t.Errorf("%s rows", got)
	}
	w.link("svc", with{"item": "AGAIN"})
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Without a public URL there is no page, so there is no link.
func TestNoPublicURL(t *testing.T) {
	w := entryWorld(t)
	for _, b := range []string{"http://varlatch.example", ""} {
		w.public = &b
		w.restart()
		w.wantReason("create", w.call("POST", entryPath, "svc", map[string]any{"item": "NEW_KEY"}), 422, "VALIDATION_FAILED", "no-public-url")
	}
}

// Two of one item: the first one entered is the one.
func TestTwoLinksOfOneItem(t *testing.T) {
	w := entryWorld(t)
	a, b := w.link("svc", nil), w.link("svc", nil)
	w.want("b", w.submit("bob", b, nil), 200, "")
	w.wantReason("a", w.submit("alice", a, nil), 409, "STATE_CHANGED", "value-changed")
}

// A row of a later release, or changed by hand, is refused and not widened.
func TestARowChangedByHand(t *testing.T) {
	w := entryWorld(t)
	l := w.link("svc", with{"restrictedTo": "identity", "identityId": w.idn("bob")})
	for _, q := range []string{"UPDATE entry_links SET restricted_to = 'anyone'", "UPDATE entry_links SET restricted_to = 'nobody'", "UPDATE entry_links SET identity_id = NULL",
		"UPDATE entry_links SET status = 'entered'", "UPDATE entry_links SET bound_version_id = 'ver_x'"} {
		if err := w.store.Write(t.Context(), func(tx *storage.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	w.want("bob", w.submit("bob", l, nil), 200, "")
}

// What 0.50.0-rc.2 and the TypeScript server have of a link: nothing. The
// operations are none of theirs, so they ask for a credential first; here the
// two a link's holder calls are the only ones that need none.
func TestOpenOperations(t *testing.T) {
	w := entryWorld(t)
	w.check = false
	var open []string
	for _, p := range httpserver.BuiltOperations {
		method, route, _ := strings.Cut(p, " ")
		if a := w.call(method, route, "", map[string]any{}); a.status != 401 {
			open = append(open, p)
		}
	}
	slices.Sort(open)
	want := []string{"GET /v1/meta", "POST /v1/auth/device", "POST /v1/auth/device/token", "POST /v1/entry-links/lookup", "POST /v1/entry-links/submit", "POST /v1/oidc/token"}
	if !slices.Equal(open, want) {
		t.Errorf("%q", open)
	}
}
