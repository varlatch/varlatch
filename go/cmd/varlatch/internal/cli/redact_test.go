// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestRedactDiagnostic: the fail-safe every diagnostic goes through masks a
// URL's user name and password and every Varlatch token, whatever the text
// around them, and keeps text with neither as it is.
func TestRedactDiagnostic(t *testing.T) {
	for in, want := range map[string]string{
		"varlatch: unknown command vlt_cli_secretCANARY":                            "varlatch: unknown command [redacted]",
		"varlatch: unknown command run-vlt_cli_secretCANARY-x":                      "varlatch: unknown command run-[redacted]",
		"Failed to parse URL from vlt_cli_secretCANARY/v1/meta":                     "Failed to parse URL from [redacted]/v1/meta",
		"two: vlt_svc_aaaaaaaa and vlt_agt_bbbbbbbb":                                "two: [redacted] and [redacted]",
		"varlatch server: https://u:fake@h.example: unexpected argument":            "varlatch server:[redacted]@h.example: unexpected argument",
		"a plain message, vlt_ alone and vlt_cli without a body, a@b with no colon": "a plain message, vlt_ alone and vlt_cli without a body, a@b with no colon",
	} {
		if got := RedactDiagnostic(in); got != want {
			t.Errorf("RedactDiagnostic(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParserEchoesNoOptionValue: the shared parser never echoes the value
// of an option it refuses when the value is attached (`--name=value`,
// `-Hvalue`), whatever the option; a value given separately to an option
// it knows is taken, and what it refuses after is shown without its value.
func TestParserEchoesNoOptionValue(t *testing.T) {
	spec := OptionSpec{Lists: []string{"--header"}, Values: []string{"--data"}, Aliases: []Alias{{"-H", "--header"}}, Positionals: 0}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--header=Authorization: Bearer vlt_cli_secretCANARY"}, "unknown option --header=[redacted]"},
		{[]string{"--anything=CANARY"}, "unknown option --anything=[redacted]"},
		{[]string{"-HAuthorization: Bearer CANARY"}, "unknown option -H[redacted]"},
		{[]string{"-H", "Authorization: Bearer CANARY", "--bogus=CANARY"}, "unknown option --bogus=[redacted]"},
		{[]string{"-H", "Authorization: Bearer CANARY", "-xCANARY"}, "unknown option -x[redacted]"},
		{[]string{"-H", "x", "vlt_cli_secretCANARY"}, "unexpected argument [redacted]"},
		{[]string{"--data", "CANARY", "--data", "CANARY"}, "--data given twice"},
	} {
		_, err := ParseOptions(c.args, spec)
		var o *OptionsError
		if !errors.As(err, &o) || o.Message != c.want {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
}

// TestJSONKeysAreLeftAlone: printJSON redacts every string value and leaves
// keys as they are, so two keys that look like tokens stay two distinct
// keys and the document stays valid JSON.
func TestJSONKeysAreLeftAlone(t *testing.T) {
	var stdout bytes.Buffer
	r := &Run{IO: IO{Stdout: &stdout, Stderr: &bytes.Buffer{}}}
	doc := jsjson.Object{
		{Key: "vlt_cli_firstAAAA", Value: "vlt_cli_valueAAAA"},
		{Key: "vlt_cli_secondBBBB", Value: jsjson.Object{{Key: "url", Value: "see https://u:pass@h.example/x"}}},
	}
	if err := r.printJSON(doc); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, stdout.String())
	}
	want := "{\n  \"vlt_cli_firstAAAA\": \"[redacted]\",\n  \"vlt_cli_secondBBBB\": {\n    \"url\": \"see https:[redacted]@h.example/x\"\n  }\n}\n"
	if stdout.String() != want || len(parsed) != 2 {
		t.Errorf("stdout\n%s\nwant\n%s", stdout.String(), want)
	}
}

// TestOutJSONTakesOnlyARedactedDocument: outJSON's parameter is the
// redactedJSON type, which only redactJSON makes (its field is unexported,
// and the write guard fails on any other composite literal), so a method
// value of outJSON cannot print arbitrary text; redactJSON redacts every
// string value, a []string included.
func TestOutJSONTakesOnlyARedactedDocument(t *testing.T) {
	if got := reflect.TypeOf((*Run).outJSON).In(1); got != reflect.TypeOf(redactedJSON{}) {
		t.Fatalf("outJSON takes %v, want redactedJSON", got)
	}
	doc := redactJSON(jsjson.Object{{Key: "list", Value: []string{"vlt_cli_listAAAA", "https://u:pass@h.example"}}, {Key: "n", Value: 5}})
	want := "{\n  \"list\": [\n    \"[redacted]\",\n    \"https:[redacted]@h.example\"\n  ],\n  \"n\": 5\n}"
	if doc.document != want {
		t.Errorf("redactJSON:\n%s\nwant\n%s", doc.document, want)
	}
}

// TestNoPasswordInOutput is the output side of clientctx's property test,
// with a fixed seed: generated user names and passwords (RFC 3986 userinfo
// characters, digits, letters of other scripts) in a URL, nested in
// another's query, scheme-relative, quoted, in prose, with each at-sign
// form, go through a --json document (redactJSON) and the stderr
// fail-safe (RedactDiagnostic); the password never shows.
func TestNoPasswordInOutput(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 278))
	const ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;="
	letters := []string{"é", "ü", "ж", "字"}
	gen := func(password bool) string {
		var b strings.Builder
		for range 1 + r.IntN(20) {
			switch k := r.IntN(10); {
			case k == 0:
				fmt.Fprintf(&b, "%%%02X", r.IntN(256))
			case k == 1:
				b.WriteString(letters[r.IntN(len(letters))])
			case k == 2 && password:
				b.WriteByte(':')
			default:
				b.WriteByte(ascii[r.IntN(len(ascii))])
			}
		}
		return b.String()
	}
	contexts := []string{"%s://%s:%s%sh.example/x", "//%[2]s:%[3]s%[4]sh.example", "https://a.example/?next=%s://%s:%s%sh.example",
		"see %s://%s:%s%sh.example here", " //%[2]s:%[3]s%[4]sup.example", "//outer:o-pw@gw/?next=//%[2]s:%[3]s%[4]sh"}
	judged := 0
	for range 4000 {
		user, pass := gen(false), gen(true)
		scheme := []string{"https", "http", "postgres", "foo"}[r.IntN(4)]
		at := []string{"@", "%40", `\u0040`}[r.IntN(3)]
		format := contexts[r.IntN(len(contexts))]
		in := fmt.Sprintf(format, scheme, user, pass, at)
		// The fixed text around it (the context, the message, the JSON keys)
		// must not hold the password, or there is nothing to judge.
		if strings.Contains(fmt.Sprintf(format, scheme, user, "", at)+"varlatch: : refused value list {}[]\",\n", pass) {
			continue
		}
		judged++
		doc := redactJSON(jsjson.Object{{Key: "value", Value: in}, {Key: "list", Value: []string{in}}}).document
		for name, got := range map[string]string{"--json": doc, "stderr": RedactDiagnostic("varlatch: " + in + ": refused")} {
			if strings.Contains(strings.ReplaceAll(got, "[redacted]", "\x00"), pass) {
				t.Fatalf("%s of %q: %q shows the password %q", name, in, got, pass)
			}
		}
	}
	if judged < 3000 {
		t.Fatalf("only %d cases judged", judged)
	}
}
