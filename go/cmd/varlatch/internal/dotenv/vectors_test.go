// SPDX-License-Identifier: Apache-2.0

package dotenv

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The dotenv vectors of ../../testdata/vectors/values.json, written by
// apps/cli/test/go-vectors-values.test.ts from dotenv.ts's parseDotenv.
func TestDotenvVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/values.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Dotenv []struct {
			Source  string
			Entries []Entry
			Error   *string
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Dotenv) < 50 {
		t.Fatalf("only %d vectors", len(f.Dotenv))
	}
	for _, v := range f.Dotenv {
		entries, err := Parse(v.Source)
		if v.Error != nil {
			if err == nil || err.Error() != *v.Error {
				t.Errorf("%q: got %+v %v, want error %q", v.Source, entries, err, *v.Error)
			}
			continue
		}
		if err != nil || len(entries) != len(v.Entries) || len(entries) > 0 && !reflect.DeepEqual(entries, v.Entries) {
			t.Errorf("%q: got %+v %v, want %+v", v.Source, entries, err, v.Entries)
		}
	}
}

// TestErrorsNeverQuoteTheFile: a parse error names a line and a reason,
// never the line's text or any part of a value.
func TestErrorsNeverQuoteTheFile(t *testing.T) {
	for _, source := range []string{"SECRET_VALUE_HERE", "\n=s3cr3t-value", "A=\"s3cr3t-value\nmore", "A='s3cr3t' tail", "A=\"s3cr3t\\"} {
		_, err := Parse(source)
		if err == nil {
			t.Fatalf("%q parsed", source)
		}
		for _, part := range []string{"s3cr3t", "SECRET_VALUE"} {
			if contains(err.Error(), part) {
				t.Errorf("%q: %q quotes the file", source, err)
			}
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
