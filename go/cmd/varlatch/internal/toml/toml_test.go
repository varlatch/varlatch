// SPDX-License-Identifier: Apache-2.0

package toml

import (
	"strings"
	"testing"
	"unicode/utf16"
)

// The parser's agreement with smol-toml is held by the context vectors
// (internal/clientctx's TestRepoConfigVectors, 213 documents). Here: no
// input makes it fail other than with smol-toml's own error.

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"organization = \"acme\"\nproject = \"web\"\n",
		"[a.b]\n[[c]]\nx = { y.z = [1, 2.5e3, 0x1f, 1979-05-27T07:32:00Z, 07:32, \"\"\"s\"\"\", '''l'''] }\n",
		"a = \"\\u00e9\\U0001F600\\x41\\e\"\n",
		"[[a.b]]\n[a]\n[[a.b]]\n",
		"a = [[[[[[",
		"\xef\xbb\xbfa = 1\r\nb = 2",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		table, err := Parse(utf16.Encode([]rune(text)))
		if err == nil && table == nil {
			t.Fatal("no table and no error")
		}
		if err != nil && !strings.HasPrefix(err.Error(), "Invalid TOML document: ") {
			t.Fatalf("error %q", err)
		}
	})
}

func TestErrorMessageShape(t *testing.T) {
	_, err := ParseString("a = 1\n\nb = = 2\n")
	if err == nil {
		t.Fatal("accepted")
	}
	// smol-toml skips empty lines in its code block.
	want := "Invalid TOML document: invalid value\n\n3:  b = = 2\n        ^\n"
	if err.Error() != want {
		t.Errorf("%q, want %q", err.Error(), want)
	}
}
