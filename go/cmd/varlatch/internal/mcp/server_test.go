// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
)

// The tests of packages/mcp-server/src/server.test.ts, ported: the tools
// over the protocol, with the API client against a fake server.

type recordedRequest struct {
	method, path string
	body         map[string]any
}

// fakeServer answers each path with its stub: a JSON body, or {status,
// error} for an API error; anything else is a 404.
func fakeServer(t *testing.T, stubs map[string]any) (*apiclient.Client, func() []recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		mu.Lock()
		requests = append(requests, recordedRequest{r.Method, r.URL.RequestURI(), body})
		mu.Unlock()
		stub, ok := stubs[r.URL.Path]
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":{"code":"NOT_FOUND","message":"no stub for `+r.URL.Path+`","requestId":"t"}}`)
			return
		}
		if e, ok := stub.(apiError); ok {
			w.WriteHeader(e.status)
			_, _ = io.WriteString(w, `{"error":{"code":"`+e.code+`","message":"`+e.code+`","requestId":"t"}}`)
			return
		}
		out, _ := json.Marshal(stub)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	client := apiclient.New(apiclient.Options{Server: srv.URL, Token: "tok"})
	return client, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(requests)
	}
}

type apiError struct {
	status int
	code   string
}

var testDefaults = Defaults{{Key: "organization", Value: "acme"}, {Key: "project", Value: "api"}, {Key: "environment", Value: "dev"}}

// call sends one tools/call and returns its result: its text, and whether
// it is an error.
func call(t *testing.T, opts Options, name string, args map[string]any) (string, bool) {
	t.Helper()
	request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	var out strings.Builder
	New(opts).Serve(context.Background(), strings.NewReader(string(request)+"\n"), func(l string) { out.WriteString(l) })
	var answer struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if err := json.Unmarshal([]byte(out.String()), &answer); err != nil || len(answer.Result.Content) != 1 {
		t.Fatalf("%s: answer %q", name, out.String())
	}
	return answer.Result.Content[0].Text, answer.Result.IsError
}

func toolNames(t *testing.T, opts Options) []string {
	t.Helper()
	var out strings.Builder
	New(opts).Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), func(l string) { out.WriteString(l) })
	var answer struct {
		Result struct{ Tools []struct{ Name string } }
	}
	if err := json.Unmarshal([]byte(out.String()), &answer); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range answer.Result.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func TestReadToolsByDefault(t *testing.T) {
	client, _ := fakeServer(t, nil)
	got := toolNames(t, Options{Client: client, Defaults: testDefaults})
	want := []string{"varlatch_effective_configuration", "varlatch_get_active_contract", "varlatch_list_audit_events", "varlatch_list_environments",
		"varlatch_list_organizations", "varlatch_list_projects", "varlatch_validate_environment", "varlatch_whoami"}
	if !slices.Equal(got, want) {
		t.Fatalf("tools %q", got)
	}
}

func TestWriteToolsWhenEnabledNeverDisclosure(t *testing.T) {
	client, _ := fakeServer(t, nil)
	opts := Options{Client: client, Defaults: testDefaults, AllowWrites: true}
	names := toolNames(t, opts)
	if !slices.Contains(names, "varlatch_set_value") || !slices.Contains(names, "varlatch_delete_value") {
		t.Fatalf("tools %q", names)
	}
	for _, n := range names {
		if regexp.MustCompile(`(?i)disclose|secret|reveal`).MatchString(n) {
			t.Fatalf("tool %s", n)
		}
	}
	// Calling it by name reaches no handler.
	text, isError := call(t, opts, "varlatch_disclose_secrets", map[string]any{"items": []string{"API_KEY"}})
	if !isError || !strings.Contains(text, "Tool varlatch_disclose_secrets not found") {
		t.Fatalf("%v %q", isError, text)
	}
}

func TestListProjectsDefaultOrganization(t *testing.T) {
	client, requests := fakeServer(t, map[string]any{"/v1/organizations/acme/projects": map[string]any{"items": []any{map[string]any{"slug": "api"}}, "nextCursor": nil}})
	text, isError := call(t, Options{Client: client, Defaults: testDefaults}, "varlatch_list_projects", map[string]any{})
	if isError || !strings.Contains(text, `"slug": "api"`) {
		t.Fatalf("%v %q", isError, text)
	}
	if r := requests(); len(r) != 1 || r[0].method != "GET" {
		t.Fatalf("requests %v", r)
	}
}

const (
	contractPath  = "/v1/organizations/acme/projects/api/contract"
	effectivePath = "/v1/organizations/acme/projects/api/environments/dev/effective-configuration"
	logLevelPath  = "/v1/organizations/acme/projects/api/environments/dev/values/LOG_LEVEL"
)

var contract = map[string]any{"id": "crv_1", "contract": map[string]any{"schemaVersion": 1, "items": []any{
	map[string]any{"name": "LOG_LEVEL", "sensitive": false, "type": "string", "required": map[string]any{"kind": "never"}},
	map[string]any{"name": "API_KEY", "sensitive": true, "type": "string", "required": map[string]any{"kind": "never"}},
}}}

func effectiveWith(items ...map[string]any) map[string]any {
	list := []any{}
	for _, i := range items {
		i["sensitive"] = false
		list = append(list, i)
	}
	return map[string]any{"environmentId": "env_1", "items": list}
}

func puts(r []recordedRequest) []recordedRequest {
	var out []recordedRequest
	for _, x := range r {
		if x.method == "PUT" {
			out = append(out, x)
		}
	}
	return out
}

func TestSetNewValueWithoutReplace(t *testing.T) {
	client, requests := fakeServer(t, map[string]any{contractPath: contract, effectivePath: effectiveWith(), logLevelPath: map[string]any{"versionId": "v1"}})
	_, isError := call(t, Options{Client: client, Defaults: testDefaults, AllowWrites: true}, "varlatch_set_value", map[string]any{"item": "LOG_LEVEL", "value": "debug"})
	p := puts(requests())
	if isError || len(p) != 1 || p[0].body["value"] != "debug" {
		t.Fatalf("%v %v", isError, p)
	}
	// Existence from metadata only: no values are read.
	for _, r := range requests() {
		if strings.Contains(r.path, "/effective-configuration") && strings.Contains(r.path, "include") {
			t.Fatalf("read values: %s", r.path)
		}
	}
}

func TestReplacingNeedsReplace(t *testing.T) {
	for _, c := range []struct {
		name     string
		existing any
		message  string
	}{
		{"own", effectiveWith(map[string]any{"name": "LOG_LEVEL", "source": "self"}), `LOG_LEVEL already has a value in dev; setting it replaces that value.`},
		{"inherited", effectiveWith(map[string]any{"name": "LOG_LEVEL", "source": "parent"}), `dev inherits a value for LOG_LEVEL from its parent environment; setting it here overrides that value in dev.`},
		{"unknown", apiError{403, "PERMISSION_DENIED"}, `whether LOG_LEVEL already has a value in dev cannot be checked (403 PERMISSION_DENIED), so it counts as existing.`},
	} {
		client, requests := fakeServer(t, map[string]any{contractPath: contract, effectivePath: c.existing, logLevelPath: map[string]any{"versionId": "v2"}})
		opts := Options{Client: client, Defaults: testDefaults, AllowWrites: true}
		// expectedVersionId guards against a concurrent change; it is no substitute for replace.
		for _, args := range []map[string]any{{"item": "LOG_LEVEL", "value": "debug"}, {"item": "LOG_LEVEL", "value": "debug", "expectedVersionId": "v1"}} {
			text, isError := call(t, opts, "varlatch_set_value", args)
			if !isError || !strings.Contains(text, c.message) ||
				!strings.Contains(text, `Replacing it is the human's decision, for this item only: ask them, and with their approval pass replace: "LOG_LEVEL". Nothing was stored.`) {
				t.Fatalf("%s: %v %q", c.name, isError, text)
			}
		}
		if p := puts(requests()); len(p) != 0 {
			t.Fatalf("%s: wrote %v", c.name, p)
		}
		_, isError := call(t, opts, "varlatch_set_value", map[string]any{"item": "LOG_LEVEL", "value": "debug", "expectedVersionId": "v1", "replace": "LOG_LEVEL"})
		p := puts(requests())
		if isError || len(p) != 1 || p[0].body["value"] != "debug" || p[0].body["expectedVersionId"] != "v1" {
			t.Fatalf("%s: %v %v", c.name, isError, p)
		}
	}
}

func TestReplaceNamingAnotherItem(t *testing.T) {
	client, requests := fakeServer(t, map[string]any{contractPath: contract, effectivePath: effectiveWith(), logLevelPath: map[string]any{"versionId": "v1"}})
	text, isError := call(t, Options{Client: client, Defaults: testDefaults, AllowWrites: true}, "varlatch_set_value", map[string]any{"item": "LOG_LEVEL", "value": "debug", "replace": "API_KEY"})
	if !isError || text != "replace names API_KEY, but this call sets LOG_LEVEL; approval for one item never covers another. Nothing was stored." || len(requests()) != 0 {
		t.Fatalf("%v %q %v", isError, text, requests())
	}
}

func TestNeverWritesASecret(t *testing.T) {
	for _, c := range []struct {
		name, item string
		stubs      map[string]any
	}{
		{"a Secret in the Contract", "API_KEY", map[string]any{contractPath: contract}},
		{"an item outside the Contract", "UNLISTED", map[string]any{contractPath: contract}},
		{"any item of a project without a Contract", "LOG_LEVEL", map[string]any{}},
		{"any item when the Contract cannot be read", "LOG_LEVEL", map[string]any{contractPath: apiError{403, "PERMISSION_DENIED"}}},
	} {
		c.stubs["/v1/organizations/acme/projects/api/environments/dev/values/"+c.item] = map[string]any{"versionId": "v1"}
		client, requests := fakeServer(t, c.stubs)
		opts := Options{Client: client, Defaults: testDefaults, AllowWrites: true}
		// replace never makes a Secret writable.
		for _, extra := range []map[string]any{{}, {"replace": c.item}} {
			args := map[string]any{"item": c.item, "value": "mcp-secret-value-1"}
			for k, v := range extra {
				args[k] = v
			}
			text, isError := call(t, opts, "varlatch_set_value", args)
			if !isError || !strings.Contains(text, c.item+" is a Secret, and its value is never written through MCP") ||
				!strings.Contains(text, "--generate hex:32") || strings.Contains(text, "mcp-secret-value-1") {
				t.Fatalf("%s: %v %q", c.name, isError, text)
			}
		}
		for _, r := range requests() {
			if r.method != "GET" {
				t.Fatalf("%s: %v", c.name, r)
			}
		}
	}
}

func TestDeleteWithConfirm(t *testing.T) {
	path := "/v1/organizations/acme/projects/api/environments/dev/values/API_KEY"
	client, requests := fakeServer(t, map[string]any{path: map[string]any{}})
	_, isError := call(t, Options{Client: client, Defaults: testDefaults, AllowWrites: true}, "varlatch_delete_value", map[string]any{"item": "API_KEY", "confirm": "API_KEY"})
	if r := requests(); isError || len(r) != 1 || r[0].method != "DELETE" || r[0].path != path {
		t.Fatalf("%v %v", isError, r)
	}
}

func TestDeleteRefusals(t *testing.T) {
	for _, c := range []struct {
		name    string
		args    map[string]any
		message string
	}{
		{"no confirm", map[string]any{"item": "API_KEY"}, `deleting API_KEY from dev is the human's decision, for this item in this environment. Ask the human, and with their approval for API_KEY in dev, pass confirm: "API_KEY". Nothing was deleted.`},
		{"confirm naming another item", map[string]any{"item": "API_KEY", "confirm": "LOG_LEVEL"}, `confirm names LOG_LEVEL, but this call deletes API_KEY; approval for one item never covers another`},
		{"a plain item without confirm", map[string]any{"item": "LOG_LEVEL"}, `deleting LOG_LEVEL from dev is the human's decision`},
		{"an empty confirm", map[string]any{"item": "API_KEY", "confirm": ""}, `confirm names , but this call deletes API_KEY`},
	} {
		client, requests := fakeServer(t, nil)
		text, isError := call(t, Options{Client: client, Defaults: testDefaults, AllowWrites: true}, "varlatch_delete_value", c.args)
		if !isError || !strings.Contains(text, c.message) || len(requests()) != 0 {
			t.Fatalf("%s: %v %q %v", c.name, isError, text, requests())
		}
	}
}

func TestDeleteConfirmationNamesTheEnvironment(t *testing.T) {
	path := "/v1/organizations/acme/projects/api/environments/production/values/API_KEY"
	client, requests := fakeServer(t, map[string]any{path: map[string]any{}})
	opts := Options{Client: client, Defaults: testDefaults, AllowWrites: true}
	text, _ := call(t, opts, "varlatch_delete_value", map[string]any{"item": "API_KEY", "environment": "production"})
	if !regexp.MustCompile(`from production .* for API_KEY in production`).MatchString(text) || len(requests()) != 0 {
		t.Fatalf("%q", text)
	}
	if _, isError := call(t, opts, "varlatch_delete_value", map[string]any{"item": "API_KEY", "environment": "production", "confirm": "API_KEY"}); isError {
		t.Fatal("refused")
	}
	if r := requests(); len(r) != 1 || r[0].method != "DELETE" || r[0].path != path {
		t.Fatalf("%v", r)
	}
}

func TestWhoami(t *testing.T) {
	caller := map[string]any{
		"identity":     map[string]any{"id": "idn_1", "name": "runner-macmini", "kind": "service", "email": nil},
		"organization": map[string]any{"id": "org_1", "slug": "acme", "name": "Acme", "createdAt": "2026-09-01T00:00:00.000Z"},
		"credential":   map[string]any{"id": "crd_1", "name": "desktop-runner", "kind": "service", "expiresAt": nil},
		"listener":     "tailnet",
	}
	meta := func(capabilities ...string) map[string]any {
		return map[string]any{"apiMajor": 1, "serverVersion": "0.17.0", "capabilities": append([]string{}, capabilities...)}
	}
	whoami := func(stubs map[string]any) (map[string]any, []recordedRequest, string) {
		client, requests := fakeServer(t, stubs)
		text, isError := call(t, Options{Client: client, Defaults: testDefaults}, "varlatch_whoami", map[string]any{})
		if isError {
			t.Fatalf("error %q", text)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(text), &body); err != nil {
			t.Fatal(err)
		}
		return body, requests(), text
	}
	paths := func(r []recordedRequest) []string {
		var out []string
		for _, x := range r {
			out = append(out, x.path)
		}
		return out
	}

	// The caller: identity, organization, credential, and device, never a token.
	body, requests, text := whoami(map[string]any{"/v1/meta": meta("identity.whoami"), "/v1/me": caller})
	want, _ := json.Marshal(caller)
	got, _ := json.Marshal(body["caller"])
	if string(got) != string(want) || body["allowWrites"] != false || strings.Contains(text, "tok") || body["callerUnavailable"] != nil {
		t.Fatalf("%s", text)
	}
	if d, _ := json.Marshal(body["defaults"]); string(d) != `{"environment":"dev","organization":"acme","project":"api"}` {
		t.Fatalf("defaults %s", d)
	}
	if p := paths(requests); !slices.Equal(p, []string{"/v1/meta", "/v1/me"}) {
		t.Fatalf("%v", p)
	}
	if !strings.HasPrefix(body["server"].(string), "http://127.0.0.1:") {
		t.Fatalf("server %v", body["server"])
	}

	// Without identity.whoami: says so, still answers, never asks /v1/me.
	body, requests, _ = whoami(map[string]any{"/v1/meta": meta()})
	if body["caller"] != nil || !strings.Contains(body["callerUnavailable"].(string), "no identity.whoami capability") || !slices.Equal(paths(requests), []string{"/v1/meta"}) {
		t.Fatalf("%v %v", body, requests)
	}

	// A credential the server refuses: says why, still answers.
	body, _, _ = whoami(map[string]any{"/v1/meta": meta("identity.whoami"), "/v1/me": apiError{401, "INVALID_CREDENTIAL"}})
	if body["caller"] != nil || !strings.Contains(body["callerUnavailable"].(string), "401 (INVALID_CREDENTIAL") {
		t.Fatalf("%v", body)
	}
}

func TestScopeNotResolved(t *testing.T) {
	client, _ := fakeServer(t, nil)
	text, isError := call(t, Options{Client: client, Defaults: Defaults{}}, "varlatch_list_projects", map[string]any{})
	if !isError || !strings.Contains(text, "organization") {
		t.Fatalf("%v %q", isError, text)
	}
}

func TestAPIErrorsWithCodeAndRequest(t *testing.T) {
	client, _ := fakeServer(t, nil)
	text, isError := call(t, Options{Client: client, Defaults: testDefaults}, "varlatch_list_organizations", map[string]any{})
	if !isError || !strings.Contains(text, "NOT_FOUND") || !strings.Contains(text, "request t") {
		t.Fatalf("%v %q", isError, text)
	}
}
