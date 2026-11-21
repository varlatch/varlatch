// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"slices"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// scanVectors is testdata/vectors/scan.json (recorded by
// apps/cli/test/go-vectors-scan.test.ts); internal/scan replays the rest.
func scanVectors(t *testing.T) jsjson.Object {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(jsjson.Object)
}

func optionalString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestScanArgsVectors: parseScanArgs' options or refusal for each command
// line, as TypeScript reads it.
func TestScanArgsVectors(t *testing.T) {
	for _, raw := range scanVectors(t).Value("args").([]any) {
		c := raw.(jsjson.Object)
		var args []string
		for _, a := range c.Value("args").([]any) {
			args = append(args, a.(string))
		}
		opts, err := parseScanArgs(args)
		if want, isError := c.Get("error"); isError {
			if err == nil || err.Error() != want {
				t.Errorf("%q: %v, want %q", args, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", args, err)
			continue
		}
		paths := []any{}
		for _, p := range opts.paths {
			paths = append(paths, p)
		}
		got := jsjson.Object{
			{Key: "staged", Value: opts.staged}, {Key: "paths", Value: paths}, {Key: "json", Value: opts.json},
			{Key: "installHook", Value: opts.installHook}, {Key: "baseline", Value: optionalString(opts.baseline)},
			{Key: "writeBaseline", Value: opts.writeBaseline},
			{Key: "limits", Value: jsjson.Object{{Key: "maxFileSize", Value: float64(opts.limits.MaxFileSize)}, {Key: "maxTotalSize", Value: float64(opts.limits.MaxTotalSize)}}},
			{Key: "environment", Value: optionalString(opts.environment)}, {Key: "findFiles", Value: opts.findFiles},
		}
		if g, w := string(jsjson.Stringify(got)), string(jsjson.Stringify(c.Value("options"))); g != w {
			t.Errorf("%q:\n got %s\nwant %s", args, g, w)
		}
	}
}

// TestHookScriptVectors: the hook's text for each project directory and
// environment, byte for byte.
func TestHookScriptVectors(t *testing.T) {
	hooks := scanVectors(t).Value("hooks").([]any)
	if len(hooks) == 0 {
		t.Fatal("no hook vectors")
	}
	for _, raw := range hooks {
		c := raw.(jsjson.Object)
		var environment *string
		if e, ok := c.Value("environment").(string); ok {
			environment = &e
		}
		if got := hookScript(c.Value("projectDir").(string), environment); got != c.Value("script") {
			t.Errorf("hookScript(%q, %v)\n got %q\nwant %q", c.Value("projectDir"), c.Value("environment"), got, c.Value("script"))
		}
	}
	if !slices.ContainsFunc(hooks, func(h any) bool { return h.(jsjson.Object).Value("environment") != nil }) {
		t.Fatal("no hook with an environment")
	}
}
