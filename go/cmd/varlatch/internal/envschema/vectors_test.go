// SPDX-License-Identifier: Apache-2.0

package envschema

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/varlatch/varlatch/go/lib/contract"
)

// The vectors of ../../testdata/vectors/envschema.json, written by
// apps/cli/test/go-vectors-envschema.test.ts from packages/env-schema.

type schemaVector struct {
	Source       string
	Draft        map[string]any
	Contract     json.RawMessage
	Canonical    string
	Hash         string
	Error        *string
	Line         int
	Kind         string
	ResolveError *struct {
		Error string
		Kind  string
	}
}

// valueFree are the package's messages that repeat part of the file, and
// the Go wording that does not (the package says, then the fragment).
var valueFree = []struct {
	ts  *regexp.Regexp
	go_ string
}{
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Unrecognized line: .*$`), "${1}Unrecognized line (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Unexpected text after the value: .*$`), "${1}Unexpected text after the value (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Malformed decorator: .*$`), "${1}Malformed decorator (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Unsupported @required form: .*$`), "${1}Unsupported @required form (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Unsupported @sensitive form: .*$`), "${1}Unsupported @sensitive form (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^(\.env\.schema line \d+: )Unsupported @type: .*$`), "${1}Unsupported @type (not shown, since it may hold a value)"},
}

// goMessage is the TypeScript message as the Go parser words it.
func goMessage(ts string) string {
	for _, v := range valueFree {
		if v.ts.MatchString(ts) {
			return v.ts.ReplaceAllString(ts, v.go_)
		}
	}
	return ts
}

func loadVectors(t *testing.T) (envs []Environment, schemas []schemaVector, push []struct {
	Name             string
	Input            string
	VersionUndecided bool
	Canonical, Hash  string
}) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/envschema.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Environments []struct {
			ID, Name            string
			ParentEnvironmentID *string `json:"parentEnvironmentId"`
		}
		EnvSchema []schemaVector
		Push      []struct {
			Name             string
			Input            string
			VersionUndecided bool
			Canonical, Hash  string
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.Environments {
		env := Environment{ID: e.ID, Name: e.Name, HasParent: e.ParentEnvironmentID != nil}
		if e.ParentEnvironmentID != nil {
			env.ParentID = *e.ParentEnvironmentID
		}
		envs = append(envs, env)
	}
	return envs, f.EnvSchema, f.Push
}

// draftJSON is a Draft as the package's ContractDraft serialises.
func draftJSON(d *Draft) map[string]any {
	required := func(r *Required) any {
		if r == nil {
			return nil
		}
		o := map[string]any{"kind": r.Kind}
		switch r.Kind {
		case "environments":
			names := []any{}
			for _, n := range r.Names {
				names = append(names, n)
			}
			o["names"] = names
		case "tier":
			o["tier"] = r.Tier
		}
		return o
	}
	items := []any{}
	for _, it := range d.Items {
		o := map[string]any{"name": it.Name, "required": required(it.Required), "type": it.Type, "sensitive": nil}
		if it.Sensitive != nil {
			o["sensitive"] = *it.Sensitive
		}
		if it.EnumValues != nil {
			vs := []any{}
			for _, v := range it.EnumValues {
				vs = append(vs, v)
			}
			o["enumValues"] = vs
		}
		for key, v := range map[string]*string{"defaultValue": it.DefaultValue, "description": it.Description, "example": it.Example, "rotationHint": it.RotationHint} {
			if v != nil {
				o[key] = *v
			}
		}
		if it.RotationGraceSeconds != nil {
			o["rotationGraceSeconds"] = float64(*it.RotationGraceSeconds)
		}
		items = append(items, o)
	}
	names := []any{}
	for _, n := range d.EnvironmentNames {
		names = append(names, n)
	}
	return map[string]any{
		"defaults":         map[string]any{"sensitive": d.DefaultSensitive, "required": required(&d.DefaultRequired)},
		"items":            items,
		"environmentNames": names,
	}
}

func TestEnvSchemaVectors(t *testing.T) {
	envs, schemas, _ := loadVectors(t)
	if len(schemas) < 100 {
		t.Fatalf("only %d vectors", len(schemas))
	}
	for _, v := range schemas {
		draft, err := Parse(v.Source)
		if v.Error != nil {
			pe, ok := err.(*ParseError)
			if !ok || pe.Error() != goMessage(*v.Error) || pe.Line != v.Line {
				t.Errorf("%q: got %v, want %q (line %d)", v.Source, err, goMessage(*v.Error), v.Line)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", v.Source, err)
			continue
		}
		if got := draftJSON(draft); !reflect.DeepEqual(got, v.Draft) {
			t.Errorf("%q: draft\n got %v\nwant %v", v.Source, got, v.Draft)
		}
		resolved, err := Resolve(draft, envs)
		if v.ResolveError != nil {
			if err == nil || err.Error() != v.ResolveError.Error {
				t.Errorf("%q: resolve got %v, want %q", v.Source, err, v.ResolveError.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: resolve: %v", v.Source, err)
			continue
		}
		if string(resolved.Bytes()) != v.Canonical || resolved.Hash() != v.Hash {
			t.Errorf("%q: canonical\n got %s %s\nwant %s %s", v.Source, resolved.Bytes(), resolved.Hash(), v.Canonical, v.Hash)
		}
		// The Contract as the CLI sends it: the package's member order.
		var want any
		if err := json.Unmarshal(v.Contract, &want); err != nil {
			t.Fatal(err)
		}
		if string(contract.Canonical(resolved.Value())) != string(contract.Canonical(toObject(want))) {
			t.Errorf("%q: value differs", v.Source)
		}
	}
}

// toObject is an encoding/json value as lib/contract holds one.
func toObject(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := contract.Object{}
		for k, e := range x {
			o = append(o, contract.Member{Key: k, Value: toObject(e)})
		}
		return o
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = toObject(e)
		}
		return out
	}
	return v
}
