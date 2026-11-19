// SPDX-License-Identifier: Apache-2.0

package typegen

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestTypesVectors: for every revision of testdata/vectors/types.json
// (apps/cli/test/go-vectors-types.test.ts, from the TypeScript generators),
// both generators give the TypeScript module byte for byte, or the same
// TypesError message.
func TestTypesVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "types.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	file := doc.(jsjson.Object)
	placeholder, _ := file.Get("runtime")
	defaultVersion, _ := file.Get("generatorVersion")
	list, _ := file.Get("vectors")
	modules := 0
	for _, e := range list.([]any) {
		v := e.(jsjson.Object)
		name, _ := v.Get("name")
		answer, _ := v.Get("revision")
		field := func(key string) any {
			if x, ok := answer.(jsjson.Object).Get(key); ok {
				return x
			}
			return Absent
		}
		r := Revision{ID: field("id"), ContentHash: field("contentHash"), SemanticsVersion: field("semanticsVersion"), Contract: field("contract")}
		version := defaultVersion.(string)
		if gv, ok := v.Get("generatorVersion"); ok {
			version = gv.(string)
		}
		for _, lang := range []struct {
			key      string
			generate func(Revision, string) (string, error)
			runtime  string
		}{
			{"typescript", TypeScript, accessorRuntimeSource},
			{"python", Python, trimEnd(pythonRuntimeSource)},
		} {
			want, _ := v.Get(lang.key)
			got, err := lang.generate(r, version)
			if module, ok := want.(jsjson.Object).Get("module"); ok {
				modules++
				// The bytes the file holds (the vectors keep what
				// TypeScript writes, not the string it generated).
				full := []byte(strings.Replace(module.(string), placeholder.(string), lang.runtime, 1))
				if err != nil {
					t.Errorf("%s (%s): %v, want a module", name, lang.key, err)
				} else if written := Encode(got); !bytes.Equal(written, full) {
					t.Errorf("%s (%s): the module differs at %s", name, lang.key, firstDifference(string(written), string(full)))
				}
				continue
			}
			message, _ := want.(jsjson.Object).Get("error")
			var typesErr *Error
			if !errors.As(err, &typesErr) || typesErr.Message != message {
				t.Errorf("%s (%s): %v, want the error %q", name, lang.key, err, message)
			}
		}
	}
	if modules < 100 {
		t.Errorf("%d modules compared, want the whole file's", modules)
	}
}

// firstDifference names where two texts first differ, by line.
func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return "line " + strconv.Itoa(i+1) + ":\n  got  " + quote(g[i]) + "\n  want " + quote(w[i])
		}
	}
	return "the end: " + strconv.Itoa(len(g)) + " lines, want " + strconv.Itoa(len(w))
}

func quote(s string) string {
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return string(jsjson.Stringify(s))
}

// TestRuntimesAreTheTypeScriptOnes: the embedded copies are what the
// generators embed (go.yml checks them against the packages' build).
func TestRuntimesAreTheTypeScriptOnes(t *testing.T) {
	if !strings.HasPrefix(accessorRuntimeSource, "function "+runtimes.AccessorRuntimeName+"() {\n") || !strings.HasSuffix(accessorRuntimeSource, "\nreturn module.exports;\n}") {
		t.Error("embedded/accessor-runtime.js.txt is not one function declaration named by runtimes.json")
	}
	if strings.Contains(pythonRuntimeSource, "SPDX-License-Identifier") || !strings.HasSuffix(pythonRuntimeSource, "\n") {
		t.Error("embedded/python-runtime.py.txt is not PYTHON_RUNTIME_SOURCE")
	}
	if strings.Contains(accessorRuntimeSource, "\r") || strings.Contains(pythonRuntimeSource, "\r") {
		t.Error("a runtime copy has a carriage return: the checkout converted it (.gitattributes)")
	}
}
