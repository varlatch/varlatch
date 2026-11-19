// SPDX-License-Identifier: Apache-2.0

package secretinput

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors of ../../testdata/vectors/values.json, written by
// apps/cli/test/go-vectors-values.test.ts from secretInput.ts itself.

const vectorsFile = "../../testdata/vectors/values.json"

type vectorFile struct {
	GenerateSpec []struct {
		Raw         string
		Spec        *GenerateSpec
		Description string
		Error       *string
		Usage       bool
	}
	ValueSource []struct {
		Options struct {
			Value    *string
			Stdin    bool
			File     *string
			Generate *string
		}
		Source *struct {
			Kind  string
			Value string
			Path  string
			Spec  *GenerateSpec
		}
		Error *string
		Usage bool
	}
	ValueFromBytes []struct {
		Raw   []int `json:"bytes"`
		Value *string
		Error *string
		Usage bool
	}
	HiddenInput []struct {
		Chunks []string
		Value  *string
	}
	DropLastCharacter []struct {
		Text     string
		Result   string
		Segments []string
	}
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func TestGenerateSpecVectors(t *testing.T) {
	for _, v := range loadVectors(t).GenerateSpec {
		spec, err := ParseGenerateSpec(v.Raw)
		if v.Error != nil {
			e, ok := err.(*Error)
			if !ok || e.Message != *v.Error || e.Usage != v.Usage {
				t.Errorf("%q: got %v, want error %q (usage %v)", v.Raw, err, *v.Error, v.Usage)
			}
			continue
		}
		if err != nil || spec != *v.Spec || DescribeGenerated(spec) != v.Description {
			t.Errorf("%q: got %+v %v, want %+v %q", v.Raw, spec, err, *v.Spec, v.Description)
		}
	}
}

func TestGeneratedValuesHaveTheirShape(t *testing.T) {
	for raw, shape := range map[string]string{"hex:32": "^[0-9a-f]{64}$", "base64:48": "^[A-Za-z0-9+/]{64}$", "base64:16": "^[A-Za-z0-9+/]{22}==$", "base64url:24": "^[A-Za-z0-9_-]{32}$", "base64url:16": "^[A-Za-z0-9_-]{22}$", "alnum:40": "^[A-Za-z0-9]{40}$"} {
		spec, err := ParseGenerateSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := GenerateValue(spec)
		b, _ := GenerateValue(spec)
		if !matches(shape, a) || a == b {
			t.Errorf("%s: %d characters, fresh %v", raw, len(a), a != b)
		}
	}
}

func TestValueSourceVectors(t *testing.T) {
	for _, v := range loadVectors(t).ValueSource {
		o := Options{Stdin: v.Options.Stdin}
		if v.Options.Value != nil {
			o.Value, o.HasValue = *v.Options.Value, true
		}
		if v.Options.File != nil {
			o.File, o.HasFile = *v.Options.File, true
		}
		if v.Options.Generate != nil {
			o.Generate, o.HasGen = *v.Options.Generate, true
		}
		source, err := SourceOf(o)
		if v.Error != nil {
			e, ok := err.(*Error)
			if !ok || e.Message != *v.Error || e.Usage != v.Usage {
				t.Errorf("%+v: got %v, want error %q", v.Options, err, *v.Error)
			}
			continue
		}
		want := Source{Kind: Kind(v.Source.Kind), Value: v.Source.Value, Path: v.Source.Path}
		if v.Source.Spec != nil {
			want.Spec = *v.Source.Spec
		}
		if err != nil || source != want {
			t.Errorf("%+v: got %+v %v, want %+v", v.Options, source, err, want)
		}
	}
}

func TestValueFromBytesVectors(t *testing.T) {
	for _, v := range loadVectors(t).ValueFromBytes {
		b := make([]byte, len(v.Raw))
		for i, x := range v.Raw {
			b[i] = byte(x)
		}
		value, err := FromBytes(b, "standard input")
		if v.Error != nil {
			if err == nil || err.Error() != *v.Error {
				t.Errorf("% x: got %q %v, want error %q", b, value, err, *v.Error)
			}
			// No message ever quotes the input.
			if err != nil && len(b) > 3 && strings.Contains(err.Error(), string(b[:3])) {
				t.Errorf("% x: the error quotes the input", b)
			}
			continue
		}
		if err != nil || value != *v.Value {
			t.Errorf("% x: got %q %v, want %q", b, value, err, *v.Value)
		}
	}
}

// TestWellFormedVectors reads the texts as JavaScript holds them, lone
// surrogates included (lib/jsjson keeps them as WTF-8).
func TestWellFormedVectors(t *testing.T) {
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := jsval.Get(doc, "wellFormed")
	for _, v := range list.([]any) {
		text, _ := jsval.Get(v, "text")
		want, _ := jsval.Get(v, "wellFormed")
		if IsWellFormed(text.(string)) != want.(bool) {
			t.Errorf("%q: got %v, want %v", text, !want.(bool), want)
		}
	}
}

func TestHiddenInputVectors(t *testing.T) {
	for _, v := range loadVectors(t).HiddenInput {
		var input HiddenInput
		var got *string
		for _, chunk := range v.Chunks {
			if value, done := input.Feed(chunk); done {
				got = &value
				break
			}
		}
		if (got == nil) != (v.Value == nil) || got != nil && *got != *v.Value {
			t.Errorf("%q: got %v, want %v", v.Chunks, deref(got), deref(v.Value))
		}
	}
}

func TestDropLastCharacterVectors(t *testing.T) {
	vectors := loadVectors(t).DropLastCharacter
	if len(vectors) < 1000 {
		t.Fatalf("only %d segmentation vectors", len(vectors))
	}
	for _, v := range vectors {
		if got := DropLastCharacter(v.Text); got != v.Result {
			t.Errorf("%+q: got %+q, want %+q", v.Text, got, v.Result)
		}
		starts := Boundaries(v.Text)
		var segments []string
		for i, s := range starts {
			end := len(v.Text)
			if i+1 < len(starts) {
				end = starts[i+1]
			}
			segments = append(segments, v.Text[s:end])
		}
		if !slices.Equal(segments, v.Segments) && (len(segments) > 0 || len(v.Segments) > 0) {
			t.Errorf("%+q: segments %+q, want %+q", v.Text, segments, v.Segments)
		}
	}
}

// TestGraphemeTableIsWhole: the table covers no surrogate and its ranges
// are ordered and disjoint, so the lookup's binary search is sound.
func TestGraphemeTableIsWhole(t *testing.T) {
	graphemeOnce.Do(loadGraphemes)
	if len(graphemeRanges) < 1000 {
		t.Fatalf("only %d ranges", len(graphemeRanges))
	}
	for i, r := range graphemeRanges {
		if r.lo > r.hi || i > 0 && r.lo <= graphemeRanges[i-1].hi || !utf8.ValidRune(r.lo) {
			t.Fatalf("range %d: %x..%x", i, r.lo, r.hi)
		}
	}
}

func matches(pattern, s string) bool { return regexp.MustCompile(pattern).MatchString(s) }

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
