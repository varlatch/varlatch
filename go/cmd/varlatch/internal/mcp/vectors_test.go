// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// fakeClient answers every call as the vectors' TypeScript client does for
// its configuration: failing, with nothing, with null, or with an API error.
type fakeClient struct {
	server string
	answer func() (any, error)
}

func (f fakeClient) Server() string                                    { return f.server }
func (f fakeClient) Meta(context.Context) (any, error)                 { return f.answer() }
func (f fakeClient) WhoAmI(context.Context) (any, error)               { return f.answer() }
func (f fakeClient) ListOrganizations(context.Context) (any, error)    { return f.answer() }
func (f fakeClient) ListProjects(context.Context, string) (any, error) { return f.answer() }
func (f fakeClient) ListEnvironments(context.Context, string, string) (any, error) {
	return f.answer()
}
func (f fakeClient) EffectiveConfiguration(context.Context, string, string, string, bool) (any, error) {
	return f.answer()
}
func (f fakeClient) ValidateEnvironment(context.Context, string, string, string) (any, error) {
	return f.answer()
}
func (f fakeClient) GetActiveContract(context.Context, string, string) (any, error) {
	return f.answer()
}
func (f fakeClient) ListAuditEvents(context.Context, string, float64, string) (any, error) {
	return f.answer()
}
func (f fakeClient) SetValueWith(context.Context, string, string, string, string, jsjson.Object) (any, error) {
	return f.answer()
}
func (f fakeClient) DeleteValue(context.Context, string, string, string, string) (any, error) {
	return f.answer()
}

// TestVectors replays testdata/vectors/mcp.json (written by
// apps/cli/test/go-vectors-mcp.test.ts from the TypeScript server through
// the SDK's stdio transport): each input's lines, compared as a multiset
// (the order of concurrent answers is the order they finish).
func TestVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	file := parsed.(jsjson.Object)
	server := file.Value("server").(string)
	version := file.Value("version").(string)
	failure := file.Value("failure").(string)
	apiError := file.Value("apiError").(jsjson.Object)
	cases, _ := file.Value("cases").([]any)
	if len(cases) < 500 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		id := c.Value("id").(string)
		config := c.Value("config").(string)
		input := c.Value("input").(string)
		var want []string
		for _, l := range c.Value("output").([]any) {
			want = append(want, l.(string))
		}
		answer := func() (any, error) { return nil, errors.New(failure) }
		switch config {
		case "undefined-answers":
			answer = func() (any, error) { return apiclient.Undefined, nil }
		case "null-answers":
			answer = func() (any, error) { return nil, nil }
		case "api-error":
			answer = func() (any, error) {
				return nil, &apiclient.APIError{Status: int(apiError.Value("status").(float64)), Code: apiError.Value("code"),
					Message: apiError.Value("message").(string), RequestID: apiError.Value("requestId"), Details: apiclient.Undefined}
			}
		}
		opts := Options{Client: fakeClient{server: server, answer: answer}, Version: version}
		if config != "bare" {
			opts.Defaults = Defaults{{Key: "organization", Value: "acme"}, {Key: "project", Value: "web"}, {Key: "environment", Value: "dev"}}
			opts.AllowWrites = true
		}
		var written strings.Builder
		New(opts).Serve(context.Background(), strings.NewReader(input), func(line string) { written.WriteString(line) })
		var got []string
		if s := written.String(); s != "" {
			got = strings.Split(strings.TrimSuffix(s, "\n"), "\n")
		}
		slices.Sort(got)
		sortedWant := slices.Clone(want)
		slices.Sort(sortedWant)
		if !slices.Equal(got, sortedWant) {
			t.Errorf("%s: input %q\n got %q\nwant %q", id, input, got, want)
		}
	}
}
