// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// stub stands in for varlatchd's handlers, which step 3 writes. Its methods
// come from the embedded interface, so this checks that the generated
// interface, the strict handler and the net/http wiring fit together, not
// any behavior.
type stub struct{ StrictServerInterface }

var _ StrictServerInterface = stub{}

// Every operation registers on one ServeMux under /v1 without a conflict
// (ServeMux panics on two patterns that match the same requests, and on a
// path it cannot read), and a request reaches the operation's pattern.
func TestRoutesRegister(t *testing.T) {
	mux := http.NewServeMux()
	HandlerWithOptions(NewStrictHandler(stub{}, nil), StdHTTPServerOptions{BaseURL: "/v1", BaseRouter: mux})
	for _, c := range []struct{ method, path, pattern string }{
		{http.MethodGet, "/v1/meta", "GET /v1/meta"},
		{http.MethodGet, "/v1/organizations/acme", "GET /v1/organizations/{org}"},
		{http.MethodPatch, "/v1/organizations/acme", "PATCH /v1/organizations/{org}"},
	} {
		req, err := http.NewRequest(c.method, c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, pattern := mux.Handler(req); pattern != c.pattern {
			t.Errorf("%s %s: pattern %q, want %q", c.method, c.path, pattern, c.pattern)
		}
	}
}

// A nullable field keeps three states (nullable-type in oapi-codegen.yaml):
// the TypeScript server treats an omitted field and an explicit null
// differently, for example PATCH /v1/me/profile leaves the avatar as it is
// when image is omitted and removes it when image is null. The Go server
// must be able to tell them apart.
func TestNullableKeepsThreeStates(t *testing.T) {
	for _, c := range []struct {
		body           string
		specified, nul bool
		value          string
	}{
		{`{}`, false, false, ""},
		{`{"image":null}`, true, true, ""},
		{`{"image":"https://example.com/a.png"}`, true, false, "https://example.com/a.png"},
	} {
		var b UpdateMyProfileJSONBody
		if err := json.Unmarshal([]byte(c.body), &b); err != nil {
			t.Fatalf("%s: %v", c.body, err)
		}
		if b.Image.IsSpecified() != c.specified || b.Image.IsNull() != c.nul {
			t.Errorf("%s: specified %v null %v, want %v %v", c.body, b.Image.IsSpecified(), b.Image.IsNull(), c.specified, c.nul)
		}
		if v, err := b.Image.Get(); c.value != "" && (err != nil || v != c.value) {
			t.Errorf("%s: value %q (%v), want %q", c.body, v, err, c.value)
		}
	}
}
