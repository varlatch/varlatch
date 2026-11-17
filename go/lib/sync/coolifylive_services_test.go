// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestCoolifyLiveServices is scripts/test-coolify-live.mjs on the Go
// adapter: the Coolify adapter's service support (ADR-0031 amendment
// 2026-10-21) against the lab Coolify. It creates one project and one
// service (three busybox containers that print their environment), pushes
// canary values through the adapter, reads them back and from the
// containers' logs byte for byte, checks the refusals, the compose
// verdicts, the rewrite of a row stored without the literal flags, restart,
// and Coolify's re-creation of referenced names, then deletes the service
// and the project. Only canary values are written, every name with the
// run's prefix. The TypeScript script's last run: Coolify 4.4.6, 85/85.
func TestCoolifyLiveServices(t *testing.T) {
	l := newLive(t)
	l.begin()
	defer l.finish()
	n := l.name
	P := n("")

	compose := servicesCompose(P)
	type kv struct{ short, value string }
	values := []kv{
		{"PLAIN", "plain-canary-1"}, {"DOLLARS", "pa$$word$HOME${X}"}, {"HASH", "abc #x"}, {"MULTI", "line1\nline2"},
		{"JSON_PLAIN", `{"a":"b","n":1}`}, {"DQUOTE", `say "hi"`}, {"BSLASH", `a\b`}, {"UNICODE", "héllo ✓ ünï"},
		{"REFERENCED", "ref-canary"}, {"DEFAULTED", "dflt-canary"}, {"SHADOWED", "pushed-canary"}, {"UNMENTIONED", "unmentioned-canary"},
		{"ESCAPED_REF", "esc-canary"}, {"BARE_LIST", "bare-canary"},
	}
	refused := []kv{{"QUOTE", "it's"}, {"TRAIL", "x "}, {"SHARED", "{{environment.X}}"}}

	t.Logf("instance version: %s", l.version())

	var project struct{ UUID string }
	l.intend("project", "varlatch-coolify-services-"+l.run, "/projects")
	if code := l.json("POST", "/projects", map[string]any{"name": "varlatch-coolify-services-" + l.run, "description": "Temporary Varlatch adapter live test " + l.run + ", deleted afterwards"}, &project); project.UUID == "" {
		t.Fatalf("project not created (HTTP %d)", code)
	}
	l.record("project", project.UUID, "/projects/"+project.UUID, "/projects/"+project.UUID)
	var created struct{ UUID string }
	l.intend("service", "varlatch-probe-"+l.run, "/services in project "+project.UUID)
	code := l.json("POST", "/services", map[string]any{
		"project_uuid": project.UUID, "environment_name": "production", "server_uuid": l.server,
		"name": "varlatch-probe-" + l.run, "docker_compose_raw": base64.StdEncoding.EncodeToString([]byte(compose)), "instant_deploy": false,
	}, &created)
	if created.UUID == "" {
		t.Fatalf("service not created (HTTP %d)", code)
	}
	svc := created.UUID
	l.record("service", svc, "/services/"+svc+"?delete_configurations=true&delete_volumes=true&docker_cleanup=true&delete_connected_networks=true", "/services/"+svc)
	t.Logf("service: %s", svc)
	dest, err := coolify{}.CanonicalizeDestination(Object{{Key: "serviceUuid", Value: svc}})
	if err != nil {
		t.Fatal(err)
	}
	req := func(usage *UsageReport) *Request { return l.req(dest.Fields, usage) }

	// Access check and listing.
	access := coolify{}.CheckAccess(liveCtx(), req(nil))
	l.check("access check ok", access.Status == StatusOK, access.Message)
	l.check("access check names containers", strings.Contains(access.Message, "probe") && strings.Contains(access.Message, "other"), "")
	listing := coolify{}.ListDestinations(liveCtx(), req(nil))
	has := false
	for _, o := range listing.Items {
		if o.Destination.Get("serviceUuid") == svc {
			has = true
		}
	}
	l.check("listing has the service", has, listing.Check.Message)

	// Usage before any value: verdicts from the compose file.
	var names []string
	for _, v := range values {
		names = append(names, n(v.short))
	}
	names = append(names, n("DEFAULTED_RAW"), n("PREEXIST"))
	usage := coolify{}.InspectUsage(liveCtx(), req(nil), names)
	l.check("usage checked", usage != nil && usage.Checked, reason(usage))
	u := func(short string) NameUsage { got, _ := usage.Get(n(short)); return got }
	jsonOf := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	l.check("SHADOWED shadowed in probe", reflect.DeepEqual(u("SHADOWED").ShadowedIn, []string{"probe"}), jsonOf(u("SHADOWED")))
	l.check("REFERENCED referenced, not copied", u("REFERENCED").Referenced && !u("REFERENCED").CopiedIntoCompose, jsonOf(u("REFERENCED")))
	l.check("DEFAULTED copied into compose", u("DEFAULTED").CopiedIntoCompose, jsonOf(u("DEFAULTED")))
	l.check("UNMENTIONED plain", reflect.DeepEqual(u("UNMENTIONED"), NameUsage{}), jsonOf(u("UNMENTIONED")))
	l.check("ESCAPED_REF referenced through YAML decoding", u("ESCAPED_REF").Referenced, jsonOf(u("ESCAPED_REF")))
	l.check("BARE_LIST copied into compose (pure list)", u("BARE_LIST").CopiedIntoCompose, jsonOf(u("BARE_LIST")))
	l.check("$ refused for a copied name", strings.Contains(coolify{}.ValueProblem(dest.Fields, n("BARE_LIST"), "a$b", usage), "copies this value"), "")
	l.check("$ refused while usage is unknown", strings.Contains(coolify{}.ValueProblem(dest.Fields, n("UNMENTIONED"), "a$b", &UsageReport{Checked: false}), "could not check"), "")
	l.check("$ allowed for a name the compose file does not copy", coolify{}.ValueProblem(dest.Fields, n("UNMENTIONED"), "a$b", usage) == "", "")

	// A pre-existing row with the matching value but without the literal flags.
	code, _ = l.do("POST", "/services/"+svc+"/envs", map[string]any{"key": n("PREEXIST"), "value": "abc$HOME #x", "is_literal": false, "is_multiline": false})
	l.check("pre-existing row without flags created", code == 201, httpStatus(code))
	state, err := coolify{}.ReadRemote(liveCtx(), req(nil))
	l.check("read-back flags it for rewrite though its value matches", err == nil && eq(state.Values[n("PREEXIST")], "abc$HOME #x") && state.Rewrite[n("PREEXIST")], errText(err))
	pre2, err := coolify{}.WriteValues(liveCtx(), req(usage), []SyncItem{{Name: n("PREEXIST"), Value: "abc$HOME #x"}})
	l.check("rewrite with the flags", err == nil && len(pre2) == 1 && pre2[0].OK, outcomeText(pre2, err))
	state, err = coolify{}.ReadRemote(liveCtx(), req(nil))
	l.check("no rewrite needed after", err == nil && !state.Rewrite[n("PREEXIST")], errText(err))

	// Writes through the adapter.
	var items []SyncItem
	refuse := map[string]bool{}
	for _, v := range values {
		items = append(items, SyncItem{Name: n(v.short), Value: v.value})
	}
	for _, v := range refused {
		items = append(items, SyncItem{Name: n(v.short), Value: v.value})
		refuse[n(v.short)] = true
	}
	outcomes, err := coolify{}.WriteValues(liveCtx(), req(usage), items)
	if err != nil {
		l.check("writes", false, err.Error())
	}
	for _, o := range outcomes {
		short := strings.TrimPrefix(o.Name, P)
		want := "ok"
		if refuse[o.Name] {
			want = "refused"
		}
		l.check("write "+short+" "+want, o.OK == !refuse[o.Name], o.Error)
	}
	// The premise of the copied-$ rule: write a $ value past the adapter,
	// raw. Coolify's parse at creation already made the row (the compose
	// file references it).
	code, _ = l.do("PATCH", "/services/"+svc+"/envs", map[string]any{"key": n("DEFAULTED_RAW"), "value": "a$HOME-b", "is_literal": true, "is_multiline": true})
	l.check("raw write for the $-expansion premise", code == 200 || code == 201, httpStatus(code))

	// Read-back is exact.
	back, err := coolify{}.ReadValues(liveCtx(), req(nil))
	if err != nil {
		l.check("read back", false, err.Error())
	}
	for _, v := range values {
		l.check("read back "+v.short, eq(back[n(v.short)], v.value), "")
	}

	// Start, then read what the containers got.
	code, _ = l.do("POST", "/services/"+svc+"/start", nil)
	l.check("start queued", code == 200, httpStatus(code))
	l.check("service running", l.waitRunning(svc), "")
	env, ok := l.envOf(svc, "probe", n("PLAIN")+"=plain-canary-1")
	l.check("probe env read", ok, "")
	if ok {
		for _, v := range values {
			expected := v.value
			if v.short == "SHADOWED" {
				expected = "fixed-in-compose"
			}
			l.check("probe "+v.short+" byte for byte", hasLine(env, n(v.short), expected), "")
		}
		for _, v := range refused {
			l.check("probe has no "+v.short, !strings.Contains(env, "\n"+n(v.short)+"="), "")
		}
		l.check("probe PREEXIST byte for byte after the rewrite", hasLine(env, n("PREEXIST"), "abc$HOME #x"), "")
		raw, found := lineValue(env, n("DEFAULTED_RAW"))
		l.check("premise: Compose expands $ in a copied value", found && raw != "a$HOME-b", "")
	}
	usageRunning := coolify{}.InspectUsage(liveCtx(), req(nil), names)
	l.check("usage after start agrees", usageRunning != nil && reflect.DeepEqual(usageRunning.Names, usage.Names), "")
	listerEnv, ok := l.envOf(svc, "lister", n("BARE_LIST")+"=")
	l.check("lister BARE_LIST through the copied path", ok && hasLine(listerEnv, n("BARE_LIST"), "bare-canary"), "")
	l.check("lister LIST_SET from the compose file", ok && hasLine(listerEnv, n("LIST_SET"), "from-list"), "")
	otherEnv, ok := l.envOf(svc, "other", n("UNMENTIONED")+"=")
	l.check("other container gets every variable through .env", ok && hasLine(otherEnv, n("UNMENTIONED"), "unmentioned-canary"), "")

	// A change, then the adapter's restart, reaches the containers.
	changed, err := coolify{}.WriteValues(liveCtx(), req(usage), []SyncItem{{Name: n("PLAIN"), Value: "plain-canary-2"}})
	l.check("change written", err == nil && len(changed) == 1 && changed[0].OK, outcomeText(changed, err))
	_, err = coolify{}.TriggerRedeploy(liveCtx(), req(nil))
	l.check("restart requested", err == nil, errText(err))
	_, ok = l.envOf(svc, "probe", n("PLAIN")+"=plain-canary-2")
	l.check("restart delivers the change", ok, "")

	// Delete: a referenced name comes back at every parse; an unmentioned
	// one does not.
	del, err := coolify{}.DeleteNames(liveCtx(), req(nil), []string{n("REFERENCED"), n("UNMENTIONED"), n("ESCAPED_REF")})
	allOK := err == nil
	for _, o := range del {
		allOK = allOK && o.OK
	}
	l.check("deletes ok", allOK, outcomeText(del, err))
	for _, round := range []string{"1", "2"} {
		_, _ = coolify{}.TriggerRedeploy(liveCtx(), req(nil))
		time.Sleep(10 * time.Second)
		l.waitRunning(svc)
		l.envOf(svc, "probe", n("PLAIN")+"=plain-canary-2")
		time.Sleep(15 * time.Second)
		later, err := coolify{}.ReadValues(liveCtx(), req(nil))
		_, ref := later[n("REFERENCED")]
		_, esc := later[n("ESCAPED_REF")]
		_, unm := later[n("UNMENTIONED")]
		l.check("restart "+round+": Coolify re-creates the referenced name", err == nil && ref, "")
		l.check("restart "+round+": Coolify re-creates the YAML-escaped reference", err == nil && esc, "")
		l.check("restart "+round+": an unmentioned name stays deleted", err == nil && !unm, "")
	}
}

// waitRunning waits for the service to run (5 minutes at most).
func (l *live) waitRunning(svc string) bool {
	for i := 0; i < 60; i++ {
		var s struct{ Status string }
		l.json("GET", "/services/"+svc, nil, &s)
		if strings.HasPrefix(s.Status, "running") {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

var hexLine = regexp.MustCompile(`^[0-9a-f]+$`)

// envOf polls a container's log for its environment (the hex line it
// prints) until want appears, 5 minutes at most. The environment holds
// canary values only.
func (l *live) envOf(svc, container, want string) (string, bool) {
	for i := 0; i < 60; i++ {
		var r struct{ Logs string }
		if code := l.json("GET", "/services/"+svc+"/logs?sub_service_name="+container+"&lines=20", nil, &r); code == 200 {
			var last string
			for _, line := range strings.Split(strings.TrimSpace(r.Logs), "\n") {
				if line = strings.TrimSpace(line); hexLine.MatchString(line) {
					last = line
				}
			}
			if last != "" {
				if b, err := hex.DecodeString(last); err == nil {
					env := "\n" + string(b)
					if want == "" || strings.Contains(env, want) {
						return env, true
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	return "", false
}

// hasLine reports whether env (newline-led) holds name=value as a whole
// line.
func hasLine(env, name, value string) bool {
	return strings.Contains(env+"\n", "\n"+name+"="+value+"\n")
}

// lineValue is name's value in env, if a line sets it.
func lineValue(env, name string) (string, bool) {
	for _, line := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

func eq(got *string, want string) bool { return got != nil && *got == want }

func reason(u *UsageReport) string {
	if u == nil {
		return "no report"
	}
	return u.Reason
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func outcomeText(o []NameOutcome, err error) string {
	if err != nil {
		return err.Error()
	}
	var s []string
	for _, x := range o {
		if !x.OK {
			s = append(s, x.Error)
		}
	}
	return strings.Join(s, "; ")
}

func httpStatus(code int) string { return "HTTP " + itoaLive(code) }

func itoaLive(n int) string { b, _ := json.Marshal(n); return string(b) }

// servicesCompose is the service's compose file, its names with the run's
// prefix P. ESCAPED_REF's value is a YAML escape of "$" (as in the
// TypeScript fixture), so the reference appears only once the YAML is
// decoded.
func servicesCompose(P string) string {
	return `services:
  probe:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\n'; echo; sleep 2147483647"]
    environment:
      ` + P + `SHADOWED: fixed-in-compose
      ` + P + `REFERENCED: ${` + P + `REFERENCED}
      ` + P + `DEFAULTED: ${` + P + `DEFAULTED:-from-compose}
      ` + P + `DEFAULTED_RAW: ${` + P + `DEFAULTED_RAW:-from-compose}
      ` + P + `ESCAPED_REF: "\u0024` + P + `ESCAPED_REF"
  lister:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\n'; echo; sleep 2147483647"]
    environment:
      - ` + P + `BARE_LIST
      - ` + P + `LIST_SET=from-list
  other:
    image: busybox:1.37
    command: ["sh", "-c", "env | od -An -tx1 | tr -d ' \\n'; echo; sleep 2147483647"]
`
}
