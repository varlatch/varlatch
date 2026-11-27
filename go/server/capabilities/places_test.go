// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/paritytest"
)

// Pages and applications as destinations, pipe and field targets (ADR-0064),
// over HTTP, on the parity fixture's rows. The matching itself is
// go/server/authz's place_test.go.

const loginPage = "web:https://portal.example.com/login"

func page(url string) with {
	return with{"destination": map[string]any{"url": url}, "placements": field("SECRET_A", "Password")}
}

func application(name string) with {
	return with{"destination": map[string]any{"app": name}, "placements": field("SECRET_A", "Password")}
}

func field(item, name string) []any {
	return []any{map[string]any{"item": item, "target": "field:" + name}}
}

// typed is an issuance of SECRET_A for a field, at destinations.
func typed(destinations ...string) with {
	return with{"destinations": destinations, "targets": map[string]any{"SECRET_A": []string{"field:Password"}}}
}

func (w *world) app(name, broker string) string { return "app:" + name + "@" + w.idn(broker) }

func TestTypedIntoAPage(t *testing.T) {
	w := newWorld(t)
	a := w.want("issue", w.call("POST", capsPath, "broker", w.issueBody(typed("web:https://Portal.Example.com/login/*", "web:https://*.idp.example"))), 201, "")
	if fmt.Sprint(a.body["destinations"]) != "[web:https://portal.example.com:443/login web:https://*.idp.example:443/]" || fmt.Sprint(a.body["targets"]) != "map[SECRET_A:[field:Password]]" {
		t.Errorf("%s", a.raw)
	}
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	w.wantEvent("capability.issued", "broker", nil, map[string]any{"destinations": "web:https://portal.example.com:443/login,web:https://*.idp.example:443/", "targets": "SECRET_A=field:Password"})
	w.wantValue("its page", w.exercise("broker", c, page("https://portal.example.com/login/step2?session=made-up#frag")))
	// What the log says of it: the kind, the page without its query, the
	// selector, and the target.
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{
		"destination": "web:https://portal.example.com:443/login/step2", "destinationKind": "web", "selector": "web:https://portal.example.com:443/login", "placements": "SECRET_A=field:Password"})
	if s := w.text("SELECT coalesce(group_concat(metadata), '') FROM audit_events"); strings.Contains(s, "made-up") || strings.Contains(s, "frag") {
		t.Error("the query is in the audit log")
	}
	w.wantValue("a frame named too", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://a.idp.example/f", "topUrl": "https://portal.example.com/login"}, "placements": field("SECRET_A", "Password")}))
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"destination": "web:https://a.idp.example:443/f", "topDestination": "web:https://portal.example.com:443/login", "selector": "web:https://*.idp.example:443/"})
	// Anywhere else: refused, and recorded with what was reported.
	for url, text := range map[string]string{
		"https://evil.example/login":                "web:https://evil.example:443/login",
		"https://portal.example.com/other":          "web:https://portal.example.com:443/other",
		"http://portal.example.com/login":           "web:http://portal.example.com:80/login",
		"https://portal.example.com:8443/login":     "web:https://portal.example.com:8443/login",
		"https://portal.example.com@evil.example/":  "web:unreadable",
		"https://portal.example.com/login/%2e%2e/x": "web:unreadable",
		"about:blank":          "web:unreadable",
		"https://idp.example/": "web:https://idp.example:443/",
		"https://portal.example.com.evil.example/login": "web:https://portal.example.com.evil.example:443/login",
	} {
		w.wantReason(url, w.exercise("broker", c, page(url)), 403, "PERMISSION_DENIED", "destination-mismatch")
		w.wantEvent("capability.denied", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"reason": "destination-mismatch", "destination": text, "destinationKind": "web"})
	}
	w.wantReason("a frame in another page", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login", "topUrl": "https://evil.example/"}, "placements": field("SECRET_A", "Password")}), 403, "PERMISSION_DENIED", "destination-mismatch")
	w.wantEvent("capability.denied", "broker", nil, map[string]any{"destination": "web:https://portal.example.com:443/login", "topDestination": "web:https://evil.example:443/"})
	// The same host, as a host: no page.
	w.wantReason("the host", w.exercise("broker", c, with{"destination": map[string]any{"host": "portal.example.com", "port": 443}, "placements": field("SECRET_A", "Password")}), 403, "PERMISSION_DENIED", "destination-mismatch")
	// Another field than the one it names.
	w.wantReason("another field", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login"}, "placements": field("SECRET_A", "Search")}), 403, "PERMISSION_DENIED", "placement-not-targeted")
	w.wantReason("no field", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login"}}), 403, "PERMISSION_DENIED", "placement-not-targeted")
}

// What a Broker reports beside where it types is nowhere afterwards: not in
// an event of a use or a refusal, which is what webhooks and exports carry,
// not in a table, an answer or the log. A window's title is no part of a
// report, and one that is sent all the same is dropped.
func TestNothingElseOfAReportIsKept(t *testing.T) {
	w := newWorld(t)
	w.stop()
	var log bytes.Buffer
	w.log = &log
	w.start()
	// A window is no member of the document's, so these calls are not held
	// against it.
	w.check = false
	c := w.issue("broker", typed(loginPage, w.app("CRM", "broker")))
	const mark = "made-up-mark"
	see := func(a answer, status int) {
		t.Helper()
		if a.status != status || strings.Contains(a.raw, mark) {
			t.Errorf("%d %s", a.status, a.raw)
		}
	}
	for path, status := range map[string]int{
		"/login":       200,
		"/login/step2": 200,
		"/elsewhere":   403,
	} {
		for _, tail := range []string{"", "?" + mark, "?a=" + mark + "#" + mark, "#" + mark, "/a;sid=" + mark, "/a%3Bsid=" + mark, "/a%3F" + mark, "/a%23" + mark, "/a?%3F" + mark} {
			see(w.exercise("broker", c, page("https://portal.example.com"+path+tail)), status)
			see(w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login", "topUrl": "https://portal.example.com" + path + tail}, "placements": field("SECRET_A", "Password")}), status)
		}
	}
	for _, url := range []string{"https://" + mark + "@portal.example.com/login", "https://u:" + mark + "@portal.example.com/login", "https://portal.example.com/login%253F" + mark,
		"data:text/plain," + mark, mark, "https://portal.example.com\\" + mark + "/login", "https://portal.example.com/../" + mark} {
		see(w.exercise("broker", c, page(url)), 403)
	}
	for name, status := range map[string]int{"CRM": 200, "Notepad": 403} {
		see(w.exercise("broker", c, with{"destination": map[string]any{"app": name, "window": mark, "title": mark, "windowTitle": mark}, "placements": field("SECRET_A", "Password")}), status)
	}
	see(w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login", "title": mark, "window": mark}, "placements": field("SECRET_A", "Password")}), 200)
	see(w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/?" + mark, "app": "CRM"}}), 422)
	see(w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/?" + mark + strings.Repeat("x", authz.MaxReported)}}), 422)
	// Nor is a selector that was refused repeated.
	for _, s := range []string{"web:https://u:" + mark + "@x.example/", "web:https://x.example/?" + mark, "WEB:https://x.example/#" + mark, " web:ftp://" + mark} {
		see(w.call("POST", capsPath, "broker", w.issueBody(typed(s))), 422)
	}
	for _, r := range paritytest.Rows(t, w.store, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'") {
		for _, row := range paritytest.Rows(t, w.store, "SELECT * FROM "+r["name"].(string)) {
			if s := fmt.Sprint(row); strings.Contains(s, mark) {
				t.Errorf("the table %v holds %v", r["name"], row)
			}
		}
	}
	for _, r := range paritytest.Rows(t, w.store, "SELECT metadata FROM audit_events WHERE event_type IN ('capability.exercised', 'capability.denied')") {
		if s := fmt.Sprint(r["metadata"]); strings.Contains(strings.ToLower(s), "window") || strings.Contains(strings.ToLower(s), "title") {
			t.Errorf("%s", s)
		}
	}
	w.stop()
	if strings.Contains(log.String(), mark) {
		t.Errorf("the log holds it: %s", log.String())
	}
	w.start()
}

// A page without TLS is allowed where it is written out, and nowhere else.
func TestAPageWithoutTLS(t *testing.T) {
	w := newWorld(t)
	a := w.want("issue", w.call("POST", capsPath, "broker", w.issueBody(typed("web:http://intra.example/login"))), 201, "")
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	w.wantValue("as it is written", w.exercise("broker", c, page("http://intra.example/login")))
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"destination": "web:http://intra.example:80/login", "selector": "web:http://intra.example:80/login"})
	w.wantReason("with TLS", w.exercise("broker", c, page("https://intra.example/login")), 403, "PERMISSION_DENIED", "destination-mismatch")
	// No scheme is none of the two.
	for _, s := range []string{"web:intra.example/login", "web://intra.example/login", "web:*://intra.example/login"} {
		w.want(s, w.call("POST", capsPath, "broker", w.issueBody(typed(s))), 422, "VALIDATION_FAILED")
	}
}

func TestTypedIntoAnApplication(t *testing.T) {
	w := newWorld(t)
	c := w.issue("broker", typed(w.app("CRM Client", "broker"), w.app("Café", "broker")))
	w.wantValue("its application", w.exercise("broker", c, with{"destination": map[string]any{"app": "CRM Client"}, "placements": field("SECRET_A", "Password")}))
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"destination": w.app("CRM Client", "broker"), "destinationKind": "app", "selector": w.app("CRM Client", "broker"), "window": nil})
	w.wantValue("another spelling of one name", w.exercise("broker", c, application("Café")))
	for _, name := range []string{"crm client", "CRM", "Notepad", "CRM Client@" + w.idn("broker"), "CRM Client ", "*"} {
		w.wantReason(name, w.exercise("broker", c, application(name)), 403, "PERMISSION_DENIED", "destination-mismatch")
	}
	w.wantEvent("capability.denied", "broker", nil, map[string]any{"reason": "destination-mismatch", "destinationKind": "app"})
	// The machine is the Broker's own, which is authenticated: no other
	// Broker's Capability, and no other machine.
	w.want("another Broker", w.exercise("broker2", c, application("CRM Client")), 404, "RESOURCE_NOT_FOUND")
	w.wantReason("another machine", w.call("POST", capsPath, "broker", w.issueBody(typed(w.app("CRM Client", "broker2")))), 422, "VALIDATION_FAILED", "app-machine")
	w.grant("svc", "development")
	w.wantReason("the issuer's", w.call("POST", capsPath, "svc", w.issueBody(with{"brokerIdentityId": w.idn("broker"), "destinations": []string{w.app("CRM Client", "svc")}, "targets": map[string]any{"SECRET_A": []string{"field:Password"}}})), 422, "VALIDATION_FAILED", "app-machine")
	// A row changed by hand to another machine's matches nothing here.
	w.exec("UPDATE capabilities SET destinations = json_array(?) WHERE id = ?", w.app("CRM Client", "broker2"), c.id)
	w.wantReason("a changed row", w.exercise("broker", c, application("CRM Client")), 403, "PERMISSION_DENIED", "destination-mismatch")
}

// A document over a pipe is a target of its own.
func TestHandedOverAPipe(t *testing.T) {
	w := newWorld(t)
	pipe := func(destination any) with {
		return with{"destination": destination, "placements": []any{map[string]any{"item": "SECRET_A", "target": "pipe:/secrets/0/password"}}}
	}
	targets := map[string]any{"SECRET_A": []string{"pipe:/secrets/0/password"}}
	c := w.issue("broker", with{"targets": targets})
	w.wantValue("a process that talks to a host", w.exercise("broker", c, pipe(map[string]any{"host": "api.example.com", "port": 443})))
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"destination": "api.example.com:443", "placements": "SECRET_A=pipe:/secrets/0/password", "destinationKind": nil})
	// Not at the JSON pointer of a request's body: they are told apart.
	w.wantReason("json", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_A", "target": "json:/secrets/0/password"}}}), 403, "PERMISSION_DENIED", "placement-not-targeted")
	c = w.issue("broker", with{"targets": targets, "destinations": []string{w.app("importer", "broker")}})
	w.wantValue("a process", w.exercise("broker", c, pipe(map[string]any{"app": "importer"})))
	w.wantReason("to a page", w.call("POST", capsPath, "broker", w.issueBody(with{"targets": targets, "destinations": []string{loginPage}})), 422, "VALIDATION_FAILED", "target-without-destination")
	// What brokers borrowed until now works as it did.
	c = w.issue("broker", with{"targets": map[string]any{"SECRET_A": []string{"json:/secret/field"}}})
	w.wantValue("json", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_A", "target": "json:/secret/field"}}}))
}

func TestWhatDoesNotGoTogether(t *testing.T) {
	w := newWorld(t)
	issue := func(destinations []string, targets ...string) answer {
		return w.call("POST", capsPath, "broker", w.issueBody(with{"destinations": destinations, "targets": map[string]any{"SECRET_A": targets}}))
	}
	crm := w.app("CRM", "broker")
	for what, c := range map[string]struct {
		destinations []string
		targets      []string
		reason       string
	}{
		"a page and a host":             {[]string{loginPage, "api.example.com"}, []string{"field:x"}, "mixed-destinations"},
		"an application and a host":     {[]string{"api.example.com", crm}, []string{"header:authorization", "field:x"}, "mixed-destinations"},
		"a header of a page":            {[]string{loginPage}, []string{"header:authorization"}, "target-without-destination"},
		"a header of an application":    {[]string{crm}, []string{"field:x", "header:authorization"}, "target-without-destination"},
		"a query, form or json of it":   {[]string{loginPage, crm}, []string{"query:x"}, "target-without-destination"},
		"a field of a host":             {[]string{"api.example.com"}, []string{"field:x"}, "target-without-destination"},
		"a pipe to a page":              {[]string{loginPage}, []string{"field:x", "pipe:/x"}, "target-without-destination"},
		"no selector: credentials":      {[]string{"web:https://u:p@x.example/"}, []string{"field:x"}, ""},
		"no selector: a query":          {[]string{"web:https://x.example/?a"}, []string{"field:x"}, ""},
		"no selector: a top level":      {[]string{"web:https://*.com/"}, []string{"field:x"}, ""},
		"no selector: another scheme":   {[]string{"web:ftp://x.example/"}, []string{"field:x"}, ""},
		"no selector: an app's name":    {[]string{"app:a*@" + w.idn("broker")}, []string{"field:x"}, ""},
		"no selector: no machine":       {[]string{"app:CRM"}, []string{"field:x"}, ""},
		"no selector: what is none":     {[]string{"app:CRM@nobody"}, []string{"field:x"}, ""},
		"no target: an unknown kind":    {[]string{crm}, []string{"keyboard:x"}, ""},
		"no target: an empty field":     {[]string{crm}, []string{"field:"}, ""},
		"no target: control characters": {[]string{crm}, []string{"field:a\nb"}, ""},
		"no target: no pointer":         {[]string{crm}, []string{"pipe:x"}, ""},
		"no target: a bad pointer":      {[]string{crm}, []string{"pipe:/a~2"}, ""},
	} {
		a := w.want(what, issue(c.destinations, c.targets...), 422, "VALIDATION_FAILED")
		if c.reason != "" && !strings.Contains(a.raw, `"reason":"`+c.reason+`"`) {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	w.want("a page and an application", issue([]string{loginPage, crm}, "field:x"), 201, "")
	w.want("a pipe and a field", issue([]string{loginPage, crm}, "field:x", "pipe:/x"), 201, "")
	// At use: a pipe is not for the page of the same Capability.
	a := issue([]string{loginPage, crm}, "field:x", "pipe:/x")
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	pipe := []any{map[string]any{"item": "SECRET_A", "target": "pipe:/x"}}
	w.wantReason("a pipe to a page", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login"}, "placements": pipe}), 403, "PERMISSION_DENIED", "placement-not-for-destination")
	w.wantEvent("capability.denied", "broker", nil, map[string]any{"reason": "placement-not-for-destination", "target": "pipe:/x", "destinationKind": "web"})
	w.wantValue("to the application", w.exercise("broker", c, with{"destination": map[string]any{"app": "CRM"}, "placements": pipe}))
	// A row changed by hand, a host among pages: a field is not for a host.
	w.exec(`UPDATE capabilities SET destinations = json_array('api.example.com:443', ?) WHERE id = ?`, loginPage, c.id)
	w.wantReason("a field to a host", w.exercise("broker", c, with{"placements": field("SECRET_A", "x")}), 403, "PERMISSION_DENIED", "placement-not-for-destination")
}

// The report is one destination, whole.
func TestWhatIsReported(t *testing.T) {
	w := newWorld(t)
	c := w.issue("broker", typed(loginPage))
	for what, d := range map[string]any{
		"a page and a host":            map[string]any{"url": "https://portal.example.com/login", "host": "api.example.com", "port": 443},
		"a page and a port":            map[string]any{"url": "https://portal.example.com/login", "port": 443},
		"a page and an application":    map[string]any{"url": "https://portal.example.com/login", "app": "x"},
		"an application and a host":    map[string]any{"host": "api.example.com", "port": 443, "app": "x"},
		"the page around, and no page": map[string]any{"topUrl": "https://portal.example.com/login"},
		"a window, and no application": map[string]any{"window": "x"},
		"nothing":                      map[string]any{},
		"null":                         nil,
		"a list":                       []any{"https://portal.example.com/login"},
		"a text":                       "https://portal.example.com/login",
		"an empty address":             map[string]any{"url": ""},
		"no text":                      map[string]any{"url": 1},
		"null for an address":          map[string]any{"url": nil},
		"null around it":               map[string]any{"url": "https://portal.example.com/login", "topUrl": nil},
		"too long":                     map[string]any{"url": "https://portal.example.com/login?" + strings.Repeat("x", authz.MaxReported)},
		"a port that is none":          map[string]any{"host": "api.example.com", "port": 0},
	} {
		w.want(what, w.exercise("broker", c, with{"destination": d, "placements": field("SECRET_A", "Password")}), 422, "VALIDATION_FAILED")
	}
	// A host's errors are what they were.
	if a := w.exercise("broker", c, with{"destination": map[string]any{"host": "x"}}); a.err() != "VALIDATION_FAILED: destination.port: Invalid input: expected number, received undefined" {
		t.Errorf("%s", a.raw)
	}
	if a := w.exercise("broker", c, with{"destination": map[string]any{}}); !strings.HasPrefix(a.err(), "VALIDATION_FAILED: destination.host: Invalid input: expected string, received undefined; destination.port:") {
		t.Errorf("%s", a.raw)
	}
}

// Delegated, exercise-only, single-use and tied to a run, at once, and spent
// by the first that is granted.
func TestADelegatedPage(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job"}), 201, "")
	machine := w.exchanged(w.token(map[string]any{"job": "run-1"}))
	more := typed(loginPage, w.app("CRM", "broker"))
	for k, v := range (with{"brokerIdentityId": w.idn("broker"), "singleUse": true, "runId": "run-1"}) {
		more[k] = v
	}
	c := w.issue("svc", more)
	w.want("the issuer", w.exercise("svc", c, page("https://portal.example.com/login")), 404, "RESOURCE_NOT_FOUND")
	w.wantReason("elsewhere", w.exercise(machine, c, page("https://evil.example/")), 403, "PERMISSION_DENIED", "destination-mismatch")
	w.wantReason("for another kind", w.exercise(machine, c, with{"destination": map[string]any{"app": "CRM"}}), 403, "PERMISSION_DENIED", "placement-not-targeted")
	var granted, refused atomic.Int64
	var wg sync.WaitGroup
	w.check = false
	for i := range 12 {
		wg.Go(func() {
			more := page("https://portal.example.com/login")
			if i%2 == 1 {
				more = application("CRM")
			}
			switch a := w.exercise(machine, c, more); a.status {
			case 200:
				granted.Add(1)
			case 403:
				refused.Add(1)
			}
		})
	}
	wg.Wait()
	if granted.Load() != 1 || refused.Load() != 11 {
		t.Errorf("%d granted, %d refused", granted.Load(), refused.Load())
	}
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"issuedByIdentityId": w.idn("svc"), "singleUse": true, "runId": "run-1"})
	w.want("the Agent's Grant decides", w.exercise("broker", w.issue("broker", func() with {
		m := typed(loginPage)
		m["agentIdentityId"] = w.idn("nogrant")
		return m
	}()), page("https://portal.example.com/login")), 403, "PERMISSION_DENIED")
}

// A code typed into a page, with the password.
func TestACodeForAPage(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.issue("broker", with{"items": []string{"SECRET_A", otpItem}, "destinations": []string{loginPage},
		"targets": map[string]any{"SECRET_A": []string{"field:Password"}, otpItem: []string{"field:Code"}}})
	at := map[string]any{"url": "https://portal.example.com/login"}
	a := w.want("both", w.exercise("broker", c, with{"destination": at, "fresh": true, "placements": append(field("SECRET_A", "Password"), field(otpItem, "Code")...)}), 200, "")
	raw, _ := json.Marshal(a.body["items"])
	if !strings.Contains(string(raw), `"kind":"totp"`) || !strings.Contains(string(raw), `"a-secret"`) {
		t.Errorf("%s", raw)
	}
	// A refusal gives no code away: the current one is still fresh.
	w.later(30 * time.Second)
	w.wantReason("elsewhere", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://evil.example/"}, "fresh": true, "placements": field(otpItem, "Code")}), 403, "PERMISSION_DENIED", "destination-mismatch")
	w.want("here", w.exercise("broker", c, with{"destination": at, "fresh": true, "placements": field(otpItem, "Code")}), 200, "")
}

// A connection's hosts bound pages too, and no application is one of them.
func TestAConnectionsHostsAndPages(t *testing.T) {
	w := connected(t, with{"hosts": []string{"portal.example.com", "*.idp.example"}})
	issue := func(dest ...string) answer {
		return w.call("POST", capsPath, "broker", w.issueBody(with{"items": []string{mailItem}, "targets": map[string]any{mailItem: []string{"field:Token"}}, "destinations": dest, "ttlSeconds": 86_400}))
	}
	for _, ok := range [][]string{{loginPage}, {"web:https://a.idp.example/x", "web:https://*.idp.example"}} {
		w.want(fmt.Sprint(ok), issue(ok...), 201, "")
	}
	for _, no := range []string{"web:https://evil.example/", "web:https://*.example.com/", "web:https://portal.example.com:8443/", "web:http://portal.example.com/", "web:http://portal.example.com:443/", "web:https://idp.example/", w.app("CRM", "broker")} {
		w.wantReason(no, issue(no), 422, "VALIDATION_FAILED", "connection-host")
	}
	a := issue(loginPage, "web:https://*.idp.example")
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	at := func(url, top string) answer {
		d := map[string]any{"url": url}
		if top != "" {
			d["topUrl"] = top
		}
		return w.exercise("broker", c, with{"destination": d, "placements": field(mailItem, "Token")})
	}
	w.token1("its page", at("https://portal.example.com/login", ""))
	w.token1("a frame, both named", at("https://a.idp.example/", "https://portal.example.com/login"))
	// Fewer hosts bind at use, the page around it too.
	w.want("fewer", w.call("PATCH", mailPath, "alice", map[string]any{"hosts": []string{"*.idp.example"}}), 200, "")
	n := w.idp.Count("refresh_token")
	w.later(2 * time.Hour)
	w.wantReason("no host any more", at("https://portal.example.com/login", ""), 403, "PERMISSION_DENIED", "destination-mismatch")
	w.wantReason("nor around it", at("https://a.idp.example/", "https://portal.example.com/login"), 403, "PERMISSION_DENIED", "destination-mismatch")
	if w.idp.Count("refresh_token") != n {
		t.Error("refreshed for a refused exercise")
	}
	w.token1("one that is", at("https://a.idp.example/", ""))
	w.exec("UPDATE capabilities SET destinations = json_insert(destinations, '$[#]', 'web:http://a.idp.example:443/') WHERE id = ?", c.id)
	w.wantReason("without TLS", at("http://a.idp.example:443/", ""), 403, "PERMISSION_DENIED", "destination-mismatch")
	// Without hosts, whatever the Capability says.
	w.want("none", w.call("PATCH", mailPath, "alice", map[string]any{"hosts": []string{}}), 200, "")
	a = issue(w.app("CRM", "broker"))
	c = capability{a.body["id"].(string), a.body["secret"].(string)}
	w.token1("an application", w.exercise("broker", c, with{"destination": map[string]any{"app": "CRM"}, "placements": field(mailItem, "Token")}))
	// Hosts that came afterwards bind that Capability.
	w.want("hosts", w.call("PATCH", mailPath, "alice", map[string]any{"hosts": []string{"portal.example.com"}}), 200, "")
	w.wantReason("no host is an application", w.exercise("broker", c, with{"destination": map[string]any{"app": "CRM"}, "placements": field(mailItem, "Token")}), 403, "PERMISSION_DENIED", "destination-mismatch")
}

// What an older varlatchd, and the TypeScript server, make of the rows: the
// parser both have reads no such destination, so every exercise is refused.
func TestAnOlderServerMatchesNoPage(t *testing.T) {
	w := newWorld(t)
	w.issue("broker", typed(loginPage, "web:http://*.intra.example:8080/a", w.app("CRM", "broker"), w.app("a:1", "broker")))
	raw := w.text("SELECT destinations FROM capabilities ORDER BY created_at DESC LIMIT 1")
	var stored []string
	if err := json.Unmarshal([]byte(raw), &stored); err != nil || len(stored) != 4 {
		t.Fatalf("%s: %v", raw, err)
	}
	for _, s := range stored {
		if sel, ok := authz.ParseDestinationSelector(s); ok {
			t.Errorf("%s is %v there", s, sel)
		}
	}
	a := w.want("listed", w.call("GET", capsPath, "alice", nil), 200, "")
	if !strings.Contains(a.raw, loginPage[:len("web:https://portal.example.com")]) {
		t.Errorf("%s", a.raw)
	}
}

// What is recorded of targets and placements has an entry for each there is,
// whatever the names in them.
func TestPlacementsAreRecordedAsTheyAre(t *testing.T) {
	w := newWorld(t)
	web := with{"items": []string{"SECRET_A"}, "destinations": []string{"web:https://portal.example.com"}}
	for _, bad := range []string{"field:x;SECRET_B=header:authorization", "field:a=b", "field:Pass‮dnrow​", "field: a"} {
		web["targets"] = map[string]any{"SECRET_A": []string{bad}}
		w.want(bad, w.call("POST", capsPath, "broker", w.issueBody(web)), 422, "VALIDATION_FAILED")
	}
	for _, bad := range []string{"pipe:/x;SECRET_B=header:authorization", "pipe:/a‮b"} {
		w.want(bad, w.call("POST", capsPath, "broker", w.issueBody(with{"items": []string{"SECRET_A"}, "targets": map[string]any{"SECRET_A": []string{bad}}})), 422, "VALIDATION_FAILED")
	}
	// The targets of a request, which may hold such characters.
	for _, kind := range []string{"json:/", "query:", "form:"} {
		target := kind + "x;SECRET_B=header:authorization‮"
		want := "SECRET_A=" + kind + "x%3BSECRET_B=header:authorization%E2%80%AE"
		c := w.issue("broker", with{"items": []string{"SECRET_A"}, "targets": map[string]any{"SECRET_A": []string{target}}})
		w.wantEvent("capability.issued", "broker", nil, map[string]any{"targets": want})
		w.want("exercise", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_A", "target": target}}}), 200, "")
		w.wantEvent("capability.exercised", "broker", nil, map[string]any{"placements": want})
		// Refused for a page (a row changed by hand): recorded alike, and,
		// as in every denial, with no selector.
		w.exec(`UPDATE capabilities SET destinations = json_insert(destinations, '$[#]', ?) WHERE id = ?`, loginPage, c.id)
		w.wantReason("to a page", w.exercise("broker", c, with{"destination": map[string]any{"url": "https://portal.example.com/login"},
			"placements": []any{map[string]any{"item": "SECRET_A", "target": target}}}), 403, "PERMISSION_DENIED", "placement-not-for-destination")
		w.wantEvent("capability.denied", "broker", nil, map[string]any{"target": strings.TrimPrefix(want, "SECRET_A="), "destinationKind": "web"})
		if md := fmt.Sprint(w.event("capability.denied")["metadata"]); strings.Contains(md, "selector") || strings.Contains(md, "\\u202e") || strings.Contains(md, "\u202e") {
			t.Errorf("%s", md)
		}
	}
}
