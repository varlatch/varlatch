// SPDX-License-Identifier: Apache-2.0

package envschema

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
)

// TestErrorsNeverQuoteTheFile: a file given as --schema by mistake may be a
// .env holding values, so no error quotes any part of a line: each names
// the line and the problem (go/README.md, "No message holds a value").
func TestErrorsNeverQuoteTheFile(t *testing.T) {
	const canary = "s3cr3tCanary"
	for _, source := range []string{
		"api_key=" + canary + "\n",                // not an item
		"A='it\\'s-" + canary + "'\n",             // text after a quoted value
		"A=\"x\" " + canary + "\n",                // the same, double quotes
		"# @" + canary + "!\nA=\n",                // a malformed decorator
		"# @required=" + canary + "\nA=\n",        // an unsupported @required form
		"# @sensitive=" + canary + "\nA=\n",       // an unsupported @sensitive form
		"# @type=" + canary + "\nA=\n",            // an unsupported @type
		"# @type=enum(" + canary + "\nA=\n",       // an unclosed enum
		"A=\"" + canary + "\n",                    // an unterminated quote
		"# @rotationGrace=" + canary + "\nA=\n",   // a grace window that is not seconds
		"# @rotationHint=\t" + canary + "\nA=\n",  // a hint with a tab
		"# @defaultRequired=" + canary + "\nA=\n", // a root decorator's value
	} {
		_, err := Parse(source)
		if err == nil {
			t.Fatalf("%q parsed", source)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%q: %q quotes the file", source, err)
		}
	}
}

// TestErrorsReadAfterTheFailSafe: no parse error the vectors hold is
// changed by the CLI's fail-safe (a colon before a decorator's at-sign
// would read as a URL's user name and password), so each prints as worded.
func TestErrorsReadAfterTheFailSafe(t *testing.T) {
	_, schemas, _ := loadVectors(t)
	n := 0
	for _, v := range schemas {
		if v.Error == nil {
			continue
		}
		n++
		if m := goMessage(*v.Error); clientctx.MaskUserinfoInText(m) != m {
			t.Errorf("%q: the fail-safe rewrites %q", v.Source, m)
		}
	}
	if n < 40 {
		t.Fatalf("only %d errors", n)
	}
}
