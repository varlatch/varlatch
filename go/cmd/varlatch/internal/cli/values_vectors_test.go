// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/dotenv"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors of ../../testdata/vectors/values.json for validate and import,
// written by apps/cli/test/go-vectors-values.test.ts from validation.ts and
// importCommand.ts.

const valuesVectors = "../../testdata/vectors/values.json"

func loadValuesVectors(t *testing.T) any {
	t.Helper()
	data, err := os.ReadFile(valuesVectors)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func section(t *testing.T, doc any, name string) []any {
	t.Helper()
	v, _ := jsval.Get(doc, name)
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("no %s vectors", name)
	}
	return list
}

func strings_(v any) []string {
	list, _ := v.([]any)
	out := []string{}
	for _, s := range list {
		out = append(out, s.(string))
	}
	return out
}

func TestValidationVectors(t *testing.T) {
	doc := loadValuesVectors(t)
	for _, v := range section(t, doc, "validation") {
		environment, _ := jsval.Get(v, "environment")
		report, _ := jsval.Get(v, "report")
		want, _ := jsval.Get(v, "outcome")
		got, err := ValidationOutcomeOf(environment.(string), report)
		if err != nil {
			t.Fatalf("%s: %v", jsjson.Stringify(report), err)
		}
		code, _ := jsval.Get(want, "exitCode")
		stdout, _ := jsval.Get(want, "stdout")
		stderr, _ := jsval.Get(want, "stderr")
		if got.ExitCode != int(code.(float64)) || !slices.Equal(nonNil(got.Out), strings_(stdout)) || !slices.Equal(nonNil(got.Err), strings_(stderr)) {
			t.Errorf("%s:\n got %+v\nwant %s", jsjson.Stringify(report), got, jsjson.Stringify(want))
		}
		document, err := ValidationDocument(environment, report, got.ExitCode)
		if err != nil {
			t.Fatal(err)
		}
		wantDoc, _ := jsval.Get(v, "document")
		if string(jsjson.Stringify(document)) != string(jsjson.Stringify(wantDoc)) {
			t.Errorf("%s:\n got %s\nwant %s", jsjson.Stringify(report), jsjson.Stringify(document), jsjson.Stringify(wantDoc))
		}
	}
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func TestInferTypeVectors(t *testing.T) {
	for _, v := range section(t, loadValuesVectors(t), "inferType") {
		value, _ := jsval.Get(v, "value")
		version, _ := jsval.Get(v, "semanticsVersion")
		want, _ := jsval.Get(v, "type")
		got, err := InferType(value.(string), version)
		if err != nil || got != want {
			t.Errorf("%q (semantics %v): got %q %v, want %q", value, version, got, err, want)
		}
	}
}

func TestInferTypeRefusesAnUnknownSemanticsVersion(t *testing.T) {
	for _, version := range []any{float64(4), "2", float64(2.5), nil} {
		if _, err := InferType("12", version); err == nil {
			t.Errorf("semantics %v accepted", version)
		}
	}
	// No version is read for a value whose type needs none.
	if got, err := InferType("true", float64(9)); err != nil || got != "boolean" {
		t.Errorf("got %q %v", got, err)
	}
}

func TestCheckEntriesVectors(t *testing.T) {
	data, err := os.ReadFile(valuesVectors)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		CheckEntries []struct {
			Entries  []dotenv.Entry
			Problems []string
		}
		DecodeStrict []struct {
			Bytes []int
			Text  *string
			Error *string
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.CheckEntries {
		if got := checkEntries(v.Entries); !slices.Equal(nonNil(got), v.Problems) {
			t.Errorf("%+v:\n got %q\nwant %q", v.Entries, got, v.Problems)
		}
	}
	for _, v := range f.DecodeStrict {
		b := make([]byte, len(v.Bytes))
		for i, x := range v.Bytes {
			b[i] = byte(x)
		}
		text, err := decodeStrict(b, ".env")
		if v.Error != nil {
			var ie *importError
			if !errors.As(err, &ie) || ie.message != *v.Error {
				t.Errorf("% x: got %q %v, want error %q", b, text, err, *v.Error)
			}
			continue
		}
		if err != nil || text != *v.Text {
			t.Errorf("% x: got %q %v, want %q", b, text, err, *v.Text)
		}
	}
}

// TestValidationRequiresHintReadsOwnNames: a requirement named like a
// property of Object.prototype is not one the protocol defines, so it is
// shown as an unrecognized requirement (step 5 defect 23: TypeScript's
// lookup reads the prototype and prints a function's source).
func TestValidationRequiresHintReadsOwnNames(t *testing.T) {
	report, err := jsjson.Parse([]byte(`{"valid": false, "notEvaluated": [{"name": "A", "requires": "constructor", "reason": "permission"}, {"name": "B", "requires": "toString", "reason": "requirement"}, {"name": "C", "requires": "secret.reveal", "reason": "permission"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidationOutcomeOf("dev", report)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"dev: INCOMPLETE: not every item could be evaluated with this identity's access",
		"  not evaluated: A (an unrecognized requirement)",
		"  not evaluated: B (an unrecognized requirement; a Requirement (e.g. Tailnet Constraint) is not met)",
		"  not evaluated: C (needs secret.reveal)",
	}
	if !slices.Equal(got.Err, want) || got.ExitCode != 2 {
		t.Errorf("got %q (%d), want %q", got.Err, got.ExitCode, want)
	}
}
