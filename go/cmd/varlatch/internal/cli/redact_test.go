// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

// TestEveryStderrWriteGoesThroughTheFailSafe: in this package, stderr is
// written in two places only, Run.finish and Run.warn, and both apply
// RedactDiagnostic; any other write would bypass it.
func TestEveryStderrWriteGoesThroughTheFailSafe(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	write := regexp.MustCompile(`(Fprint\w*|WriteString|Write)\(r\.Stderr|r\.Stderr\.Write`)
	var sites []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if write.MatchString(line) {
				if !strings.Contains(line, "RedactDiagnostic(") {
					t.Errorf("%s:%d writes stderr without RedactDiagnostic: %s", f, i+1, strings.TrimSpace(line))
				}
				sites = append(sites, f)
			}
		}
	}
	if len(sites) != 2 {
		t.Errorf("stderr is written at %d sites (%v), want 2: Run.finish and Run.warn", len(sites), sites)
	}
}
