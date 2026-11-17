// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A route inside a Project or an environment answers a principal that
// cannot see the Organization (here a machine of another Organization) as
// an unknown Organization, before it looks anything up: the same answer
// for an existing and a missing Project or environment, on the routes of
// projects, environments, Contracts, values and capabilities.
func TestScopedRoutesCheckTheOrganizationFirst(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	defer r.stop(t)
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	admin, base := m[2], "http://"+r.addr
	call := func(method, path, bearer, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		if e, ok := v["error"].(map[string]any); ok {
			delete(e, "requestId")
		}
		return res.StatusCode, v
	}
	for _, s := range []struct{ method, path, body string }{
		{"POST", "/v1/organizations", `{"name":"Acme","slug":"acme"}`},
		{"POST", "/v1/organizations", `{"name":"Beta","slug":"beta"}`},
		{"POST", "/v1/organizations/acme/projects", `{"slug":"web","name":"Web","contractAuthority":"managed"}`},
		{"POST", "/v1/organizations/acme/projects/web/environments", `{"name":"dev","tier":"development"}`},
	} {
		if code, v := call(s.method, s.path, admin, s.body); code != 201 {
			t.Fatalf("%s %s: %d %v", s.method, s.path, code, v)
		}
	}
	code, svc := call("POST", "/v1/organizations/beta/identities", admin, `{"name":"runner","kind":"service"}`)
	runner, _ := svc["credential"].(string)
	if code != 201 || runner == "" {
		t.Fatalf("the runner: %d %v", code, svc)
	}
	routes := []struct {
		method string
		path   func(p, e string) string
		body   string
	}{
		{"GET", func(p, _ string) string { return "/v1/organizations/acme/projects/" + p }, ""},
		{"PATCH", func(p, _ string) string { return "/v1/organizations/acme/projects/" + p }, `{"name":"x"}`},
		{"GET", func(p, _ string) string { return "/v1/organizations/acme/projects/" + p + "/environments" }, ""},
		{"POST", func(p, _ string) string { return "/v1/organizations/acme/projects/" + p + "/environments" }, `{"name":"","tier":"development"}`},
		{"GET", func(p, e string) string { return "/v1/organizations/acme/projects/" + p + "/environments/" + e }, ""},
		{"GET", func(p, _ string) string { return "/v1/organizations/acme/projects/" + p + "/contract" }, ""},
		{"GET", func(p, e string) string {
			return "/v1/organizations/acme/projects/" + p + "/environments/" + e + "/effective-configuration"
		}, ""},
		{"GET", func(p, e string) string {
			return "/v1/organizations/acme/projects/" + p + "/environments/" + e + "/capabilities"
		}, ""},
		{"POST", func(p, e string) string {
			return "/v1/organizations/acme/projects/" + p + "/environments/" + e + "/capabilities"
		}, `{}`},
	}
	for _, rt := range routes {
		code, v := call(rt.method, rt.path("web", "dev"), runner, rt.body)
		e, _ := v["error"].(map[string]any)
		if code != 404 || e["code"] != "RESOURCE_NOT_FOUND" || e["message"] != "Organization not found" {
			t.Errorf("%s %s: %d %v, want the unknown Organization's answer", rt.method, rt.path("web", "dev"), code, v)
			continue
		}
		for _, missing := range [][2]string{{"nope", "dev"}, {"web", "nope"}} {
			c2, v2 := call(rt.method, rt.path(missing[0], missing[1]), runner, rt.body)
			b1, _ := json.Marshal(v)
			b2, _ := json.Marshal(v2)
			if c2 != code || string(b1) != string(b2) {
				t.Errorf("%s %s: %d %s, but %d %s for the existing one", rt.method, rt.path(missing[0], missing[1]), c2, b2, code, b1)
			}
		}
	}
}
