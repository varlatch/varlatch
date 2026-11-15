// SPDX-License-Identifier: AGPL-3.0-or-later

package security_test

import (
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// The approval vectors (services/varlatchd/test/go-approval-vectors.test.ts,
// testdata/approval-vectors.json): the TypeScript code's labels, the code
// points it writes escaped, its canonical JSON and keyed digests of the
// bodies and queries an approval binds, and its export bindings. Read with
// jsvalue, so strings keep what JSON.parse gives them.
func TestApprovalVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/approval-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	v := parsed.(jsvalue.Object)
	get := func(o any, key string) any { x, _ := o.(jsvalue.Object).Get(key); return x }
	str := func(o any, key string) string { s, _ := get(o, key).(string); return s }
	strs := func(o any, key string) []string {
		var out []string
		for _, e := range get(o, key).([]any) {
			out = append(out, e.(string))
		}
		return out
	}

	// The escaped code points, over all of Unicode but the surrogates.
	var ranges [][2]rune
	for _, r := range get(v, "invisible").([]any) {
		pair := r.([]any)
		ranges = append(ranges, [2]rune{rune(pair[0].(float64)), rune(pair[1].(float64))})
	}
	in := func(r rune) bool {
		for _, x := range ranges {
			if r >= x[0] && r <= x[1] {
				return true
			}
		}
		return false
	}
	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		want := in(r)
		got := security.Quoted(string(r)) != string(jsvalue.Stringify(string(r)))
		if r < 0x20 || r == '"' || r == '\\' {
			// JSON.stringify escapes these itself; they never reach the check.
			continue
		}
		if got != want {
			t.Errorf("U+%04X: escaped %v, TypeScript %v", r, got, want)
		}
	}

	for _, c := range get(v, "labels").([]any) {
		name := str(c, "name")
		for _, check := range []struct{ what, got, want string }{
			{"quoted", security.Quoted(name), str(c, "quoted")},
			{"labelWithId", security.LabelWithID("role", name, "rol_abcdefghijklmnopqrstuvwxyz"), str(c, "labelWithId")},
			{"labelWithoutKind", security.LabelWithID("", name, "idn_abcdefghijklmnopqrstuvwxyz"), str(c, "labelWithoutKind")},
			{"unnamed", security.Unnamed("grant", name), str(c, "unnamed")},
		} {
			if check.got != check.want {
				t.Errorf("%s(%q) = %s, TypeScript %s", check.what, name, check.got, check.want)
			}
		}
	}
	for _, c := range get(v, "lists").([]any) {
		names := strs(c, "names")
		if got := security.QuotedList(names); got != str(c, "quotedList") {
			t.Errorf("quotedList(%q) = %s, TypeScript %s", names, got, str(c, "quotedList"))
		}
		labels := make([]string, len(names))
		for i, n := range names {
			labels[i] = security.LabelWithID("", n, "idn_x")
		}
		if got := security.LabelList(labels); got != str(c, "list") {
			t.Errorf("list(%q) = %s, TypeScript %s", names, got, str(c, "list"))
		}
	}
	for _, c := range get(v, "maps").([]any) {
		m := map[string]string{}
		for _, kv := range get(c, "map").(jsvalue.Object) {
			m[kv.Key] = kv.Value.(string)
		}
		if got := security.QuotedMap(m); got != str(c, "quotedMap") {
			t.Errorf("quotedMap = %s, TypeScript %s", got, str(c, "quotedMap"))
		}
	}

	key, _ := hex.DecodeString(str(v, "key"))
	for _, c := range get(v, "digests").([]any) {
		value := get(c, "value")
		if got := auth.CanonicalJSON(value); got != str(c, "canonical") {
			t.Errorf("canonicalJson = %s, TypeScript %s", got, str(c, "canonical"))
		}
		for _, kind := range []string{"body", "query"} {
			if got := auth.ApprovalHash(key, kind, value); got != str(c, kind) {
				t.Errorf("approvalHash(%s, %s) = %s, TypeScript %s", kind, auth.CanonicalJSON(value), got, str(c, kind))
			}
		}
	}

	// The operation catalogues.
	if g, w := strings.Join(auth.ApprovalOperations, ","), strings.Join(strs(v, "operations"), ","); g != w {
		t.Errorf("approval operations\n  %s\n want %s", g, w)
	}
	for _, m := range get(v, "controlOperations").(jsvalue.Object) {
		if g, w := strings.Join(auth.ControlApprovalOperations[m.Key], ","), strings.Join(strs(get(v, "controlOperations"), m.Key), ","); g != w {
			t.Errorf("%s's operations\n  %s\n want %s", m.Key, g, w)
		}
	}
	if n := len(get(v, "controlOperations").(jsvalue.Object)); n != len(auth.ControlApprovalOperations) {
		t.Errorf("%d controls ask approvals, TypeScript %d", len(auth.ControlApprovalOperations), n)
	}
	var frozen []string
	for op := range auth.OperationsDuringFreeze {
		frozen = append(frozen, op)
	}
	slices.Sort(frozen)
	if g, w := strings.Join(frozen, ","), strings.Join(strs(v, "duringFreeze"), ","); g != w {
		t.Errorf("operations during a freeze %s, want %s", g, w)
	}

	for _, c := range get(v, "exports").([]any) {
		req := get(c, "request")
		_, all := req.(jsvalue.Object).Get("scope")
		var requested []string
		if _, ok := req.(jsvalue.Object).Get("items"); ok {
			requested = strs(req, "items")
		}
		b := security.ExportBinding(security.ExportTarget{
			OrganizationID: "org_aaaaaaaaaaaaaaaaaaaaaaaaaa", ProjectID: "prj_aaaaaaaaaaaaaaaaaaaaaaaaaa", ProjectName: str(c, "project"),
			EnvironmentID: "env_aaaaaaaaaaaaaaaaaaaaaaaaaa", EnvName: str(c, "environment"),
		}, all, requested, strs(c, "selected"))
		want := get(c, "binding")
		if want == nil || b == nil {
			if (want == nil) != (b == nil) {
				t.Errorf("export %s: binding %v, TypeScript %v", jsvalue.Stringify(req), b, want)
			}
			continue
		}
		got := jsvalue.Object{
			{Key: "operation", Value: b.Operation}, {Key: "organizationId", Value: *b.OrganizationID},
			{Key: "target", Value: jsvalue.Object{{Key: "projectId", Value: b.Target["projectId"]}, {Key: "environmentId", Value: b.Target["environmentId"]}}},
			{Key: "body", Value: b.Body}, {Key: "query", Value: jsvalue.Object{}}, {Key: "expectedVersion", Value: nil},
			{Key: "summary", Value: b.Summary.JS()},
		}
		if g, w := string(jsvalue.Stringify(got)), string(jsvalue.Stringify(want)); g != w {
			t.Errorf("export binding\n  %s\n want %s", g, w)
		}
	}
}
