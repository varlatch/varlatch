// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The shared vectors of packages/contract (ADR-0059 Decision 10): every
// Contract Semantics version's golden and portability vectors, as the
// TypeScript package's own tests run them.
func TestSemanticsVectors(t *testing.T) {
	files, err := filepath.Glob("../../../packages/contract/test/vectors/semantics-v*.json")
	if err != nil || len(files) < 5 {
		t.Fatalf("%d vector files: %v", len(files), err)
	}
	total := 0
	defer func() {
		if total < 500 {
			t.Errorf("%d validate vectors run", total)
		}
	}()
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			var v struct {
				SemanticsVersion int `json:"semanticsVersion"`
				Validate         []struct {
					Type       string   `json:"type"`
					EnumValues []string `json:"enumValues"`
					Value      string   `json:"value"`
					Valid      bool     `json:"valid"`
					Reason     string   `json:"reason"`
					Converted  *struct {
						String  *string `json:"string"`
						Number  *string `json:"number"`
						Boolean *bool   `json:"boolean"`
					} `json:"converted"`
				} `json:"validate"`
				Required []struct {
					Required          json.RawMessage `json:"required"`
					DefaultValue      *string         `json:"defaultValue"`
					Environment       struct{ RootID, Tier string }
					RequiredApplies   bool `json:"requiredApplies"`
					MissingWhenAbsent bool `json:"missingWhenAbsent"`
				} `json:"required"`
			}
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			s, err := SemanticsFor(v.SemanticsVersion)
			if err != nil {
				t.Fatal(err)
			}
			total += len(v.Validate)
			for _, c := range v.Validate {
				name := c.Type + " " + strconv.Quote(c.Value)
				it := Item{Name: "ITEM", Required: Requiredness{Kind: "never"}, Type: c.Type, EnumValues: c.EnumValues}
				want := ""
				if !c.Valid {
					want = c.Reason
				}
				if got := s.Validate(it, c.Value); got != want {
					t.Errorf("validate %s: %q, want %q", name, got, want)
				}
				if !s.HasParse() {
					if c.Converted != nil {
						t.Errorf("%s: a version without conversion has converted vectors", name)
					}
					continue
				}
				got, reason := s.Parse(it, c.Value)
				if reason != want {
					t.Errorf("parse %s: reason %q, want %q", name, reason, want)
					continue
				}
				if !c.Valid {
					continue
				}
				switch cv := c.Converted; {
				case cv == nil:
					t.Errorf("%s: a valid vector without its conversion", name)
				case cv.Number != nil:
					want, _ := strconv.ParseFloat(*cv.Number, 64)
					if got.Kind != "number" || got.Number != want || math.Signbit(got.Number) != math.Signbit(want) {
						t.Errorf("parse %s: %+v, want the number %s", name, got, *cv.Number)
					}
				case cv.Boolean != nil:
					if got.Kind != "boolean" || got.Bool != *cv.Boolean {
						t.Errorf("parse %s: %+v, want %v", name, got, *cv.Boolean)
					}
				case cv.String != nil:
					if got.Kind != "string" || got.String != *cv.String {
						t.Errorf("parse %s: %+v, want %q", name, got, *cv.String)
					}
				}
			}
			for i, c := range v.Required {
				in, err := ParseJSON(c.Required)
				if err != nil {
					t.Fatal(err)
				}
				doc := Object{{"schemaVersion", 1.0}, {"items", []any{Object{
					{"name", "ITEM"}, {"required", in}, {"sensitive", false}, {"type", "string"},
				}}}}
				norm, err := Normalize(doc, Options{})
				if err != nil {
					t.Fatalf("requiredness vector %d: %v", i, err)
				}
				it := norm.Items[0]
				it.DefaultValue = c.DefaultValue
				env := Environment{RootID: c.Environment.RootID, Tier: c.Environment.Tier}
				if s.RequiredApplies(it, env) != c.RequiredApplies || s.MissingWhenAbsent(it, env) != c.MissingWhenAbsent {
					t.Errorf("requiredness vector %d: %v %v", i, s.RequiredApplies(it, env), s.MissingWhenAbsent(it, env))
				}
			}
		})
	}
	if _, err := SemanticsFor(4); err == nil || err.Error() != "Contract semantics version 4 is not supported (supported: 1, 2, 3)" {
		t.Errorf("version 4: %v", err)
	}
}

type tsVectors struct {
	Normalize []struct {
		Name             string   `json:"name"`
		Input            string   `json:"input"`
		VersionUndecided bool     `json:"versionUndecided"`
		Canonical        *string  `json:"canonical"`
		Hash             string   `json:"hash"`
		Message          string   `json:"message"`
		Issues           []string `json:"issues"`
	} `json:"normalize"`
	Diff []struct {
		Name string          `json:"name"`
		From string          `json:"from"`
		To   string          `json:"to"`
		Diff json.RawMessage `json:"diff"`
	} `json:"diff"`
}

func readTSVectors(t *testing.T) tsVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v tsVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// normalizeContract's answers, byte for byte: the canonical bytes and the
// content hash of what it accepts, the issues of what it refuses.
func TestNormalizeVectors(t *testing.T) {
	v := readTSVectors(t)
	if len(v.Normalize) < 100 {
		t.Fatalf("%d vectors", len(v.Normalize))
	}
	for _, c := range v.Normalize {
		in, err := ParseJSON([]byte(c.Input))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := Normalize(in, Options{VersionUndecided: c.VersionUndecided})
		if c.Canonical != nil {
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			if string(got.Bytes()) != *c.Canonical || got.Hash() != c.Hash {
				t.Errorf("%s:\n  %s %s\n want %s %s", c.Name, got.Bytes(), got.Hash(), *c.Canonical, c.Hash)
			}
			// Normalizing the canonical form again changes nothing.
			again, err := ParseJSON(got.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if n, err := Normalize(again, Options{VersionUndecided: c.VersionUndecided}); err != nil || n.Hash() != c.Hash {
				t.Errorf("%s: not idempotent: %v", c.Name, err)
			}
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: %v, want the issues %q", c.Name, err, c.Issues)
			continue
		}
		if !slices.Equal(ve.Issues, c.Issues) || ve.Error() != c.Message {
			t.Errorf("%s:\n  %q\n want %q", c.Name, ve.Issues, c.Issues)
		}
	}
}

// diffContracts' answers.
func TestDiffVectors(t *testing.T) {
	for _, c := range readTSVectors(t).Diff {
		parse := func(s string) Contract {
			in, err := ParseJSON([]byte(s))
			if err != nil {
				t.Fatal(err)
			}
			n, err := Normalize(in, Options{})
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		got := Canonical(DiffContracts(parse(c.From), parse(c.To)).Value())
		want, err := ParseJSON(c.Diff)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(Canonical(want)) {
			t.Errorf("%s:\n  %s\n want %s", c.Name, got, Canonical(want))
		}
	}
}

// A Contract's strings measured and ordered as JavaScript does, lone
// surrogates (kept as WTF-8 by the server's JSON reader) included.
func TestJavaScriptStrings(t *testing.T) {
	lone := "a\xed\xa0\x80b" // a, U+D800, b
	if codePoints(lone) != 3 || len(units(lone)) != 3 || codePoints("😀") != 1 || len(units("😀")) != 2 {
		t.Error("lengths")
	}
	if !less("😀", "\uffff") {
		t.Error("an astral code point sorts before U+FFFF by its high surrogate")
	}
	if got := string(Canonical(lone)); got != `"a\ud800b"` {
		t.Errorf("quote %s", got)
	}
	if !strings.Contains(string(Canonical("\u2028\x7f")), "\u2028\x7f") {
		t.Error("JSON.stringify leaves U+2028 and DEL")
	}
}
