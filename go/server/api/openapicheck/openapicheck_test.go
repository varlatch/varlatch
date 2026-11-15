// SPDX-License-Identifier: AGPL-3.0-or-later

package openapicheck

import (
	"strings"
	"testing"
)

// The check finds what the TypeScript check finds, and lets through what
// the document describes.
func TestCheck(t *testing.T) {
	org := `{"id":"org_x","slug":"acme","name":"Acme","createdAt":"2026-01-01T00:00:00.000Z"`
	errorBody := `{"error":{"code":"RESOURCE_NOT_FOUND","message":"Organization not found","requestId":"r"}}`
	cases := []struct {
		name string
		e    Exchange
		opts Options
		want string // the mismatch kinds, joined by ","
	}{
		{"a valid answer", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 200, ResponseContentType: "application/json", ResponseBody: []byte(org + `,"incidentFreeze":null}`)}, Options{}, ""},
		{"an error envelope", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 404, ResponseContentType: "application/json", ResponseBody: []byte(errorBody)}, Options{}, ""},
		{"a member the document does not name", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 200, ResponseContentType: "application/json", ResponseBody: []byte(org + `,"incidentFreeze":null,"extra":1}`)}, Options{}, "response-undocumented-field"},
		{"a member of the wrong type", Exchange{Method: "POST", Path: "/v1/organizations", Status: 201, ResponseContentType: "application/json", ResponseBody: []byte(`{"id":"org_x","slug":"acme","name":1,"createdAt":"2026-01-01T00:00:00.000Z"}`)}, Options{}, "response-schema"},
		// Every operation documents a default response (the error envelope).
		{"another status, an error envelope", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 418, ResponseContentType: "application/json", ResponseBody: []byte(errorBody)}, Options{}, ""},
		{"another status, not an error envelope", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 418, ResponseContentType: "application/json", ResponseBody: []byte(org + `}`)}, Options{}, "response-schema"},
		{"no body where one is documented", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 200, ResponseContentType: "application/json"}, Options{}, "missing-response-body"},
		{"a body that is not JSON", Exchange{Method: "GET", Path: "/v1/organizations/acme", Status: 200, ResponseContentType: "application/json", ResponseBody: []byte("{")}, Options{}, "response-not-json"},
		{"an operation the document does not have", Exchange{Method: "GET", Path: "/v1/nowhere", Status: 200, ResponseContentType: "application/json", ResponseBody: []byte("{}")}, Options{}, "undocumented-operation"},
		{"a refused made-up path", Exchange{Method: "GET", Path: "/v1/nowhere", Status: 404}, Options{}, ""},
		{"an excused request member", Exchange{Method: "PATCH", Path: "/v1/organizations/acme", RequestContentType: "application/json", RequestBody: []byte(`{"name":"A","slug":"other"}`), Status: 200, ResponseContentType: "application/json", ResponseBody: []byte(org + `}`)}, Options{Requests: true}, ""},
		{"a request member not excused", Exchange{Method: "PATCH", Path: "/v1/organizations/acme", RequestContentType: "application/json", RequestBody: []byte(`{"name":"A","colour":"red"}`), Status: 200, ResponseContentType: "application/json", ResponseBody: []byte(org + `}`)}, Options{Requests: true}, "request-undocumented-field"},
		{"requests not judged", Exchange{Method: "PATCH", Path: "/v1/organizations/acme", RequestContentType: "application/json", RequestBody: []byte(`{"name":"A","colour":"red"}`), Status: 200, ResponseContentType: "application/json", ResponseBody: []byte(org + `}`)}, Options{}, ""},
		{"outside /v1", Exchange{Method: "GET", Path: "/healthz", Status: 200}, Options{}, ""},
	}
	for _, c := range cases {
		ms, err := Check(c.e, c.opts)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var kinds []string
		for _, m := range ms {
			kinds = append(kinds, m.Kind)
		}
		if got := strings.Join(kinds, ","); got != c.want {
			t.Errorf("%s: %q, want %q (%v)", c.name, got, c.want, ms)
		}
	}
}
