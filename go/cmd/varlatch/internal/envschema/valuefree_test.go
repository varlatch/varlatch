// SPDX-License-Identifier: Apache-2.0

package envschema

import (
	"strings"
	"testing"
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
