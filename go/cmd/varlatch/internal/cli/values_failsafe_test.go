// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// A value in flight never disables the other detections of the fail-safe:
// every sensitive span (a URL's user name and password, a token, each
// value) is found in the original text before anything is replaced, so a
// value such as "@", ":", "/" or a token's prefix never hides the
// at-sign, the scheme or the token that marks a credential (#277 round 2).

const (
	failsafePassword = "pa55-s3cr3t-word"
	failsafeToken    = "vlt_cli_tokenS3cr3tAAAA"
	failsafeURL      = "https://user:" + failsafePassword + "@h.example/x"
)

var inFlightShapes = []string{"@", ":", "/", "vlt_", "vlt_cli_", "%40", "user:", "h.example"}

func leaked(text, value string) []string {
	var out []string
	for _, secret := range []string{failsafePassword, "tokenS3cr3t", value} {
		if strings.Contains(text, secret) {
			out = append(out, secret)
		}
	}
	return out
}

func TestInFlightValuesNeverDisableTheFailSafe(t *testing.T) {
	for _, value := range inFlightShapes {
		for _, message := range []string{
			"varlatch: refused for " + failsafeURL + " and " + failsafeToken + " (" + value + ")",
			"refused for " + failsafeURL + " and " + failsafeToken + " (" + value + ")", // the URL's scheme is the first colon
			failsafeToken + " " + value + " " + failsafeURL,
		} {
			if got := RedactDiagnostic(message, value); len(leaked(got, value)) > 0 {
				t.Errorf("diagnostic, value %q: %q leaks %q", value, got, leaked(got, value))
			}
		}
		// stdout: the token and the value (a URL is masked where it is shown).
		line := "set " + failsafeToken + " " + value + " done"
		if got := RedactOutput(line, value); strings.Contains(got, "tokenS3cr3t") || strings.Contains(got, value) {
			t.Errorf("output, value %q: %q", value, got)
		}
		doc := jsjson.Object{{Key: "server", Value: failsafeURL}, {Key: "token", Value: failsafeToken}, {Key: "both", Value: value + failsafeToken + value}}
		redacted, err := RedactValue(doc, value)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range redacted.(jsjson.Object) {
			if s := m.Value.(string); len(leaked(s, value)) > 0 {
				t.Errorf("JSON, value %q: %s = %q leaks %q", value, m.Key, s, leaked(s, value))
			}
		}
	}
	// Without values in flight, the fail-safe's bytes are as before.
	for _, text := range []string{"varlatch: " + failsafeURL, "refused for " + failsafeURL + " now", "no credential here: a@b"} {
		if got, want := RedactDiagnostic(text), clientctx.MaskUserinfoInText(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}

// TestInFlightValuesNeverDisableTheFailSafeEndToEnd: the same through the
// CLI, a server echoing a credentialed URL and a token with the value, on
// stderr, and in a --json document on stdout.
func TestInFlightValuesNeverDisableTheFailSafeEndToEnd(t *testing.T) {
	for _, value := range inFlightShapes {
		t.Run(value, func(t *testing.T) {
			s := newValuesServer(t)
			s.answer("PUT", envPath+"/values/API_KEY", 400, `{"error": {"code": "VALIDATION_FAILED", "message": "refused {{value}} for `+failsafeURL+` and `+failsafeToken+`"}}`)
			_, stdout, stderr := runIn(t, s, value+"\n", nil, nil, "values", "set", "API_KEY", "--stdin")
			if l := leaked(stdout+stderr, value); len(l) > 0 {
				t.Errorf("stderr %q leaks %q", stderr, l)
			}
			s = newValuesServer(t)
			s.answer("GET", envPath+"/effective-configuration", 200, `{"items": [{"name": "API_KEY", "sensitive": true, "source": "`+failsafeURL+`"}, {"name": "B", "sensitive": true, "source": "`+failsafeToken+`"}]}`)
			_, stdout, stderr = runIn(t, s, "A="+value+"\n", map[string]string{".env": "API_KEY=" + value + "\n"}, nil, "values", "list", "--json")
			if strings.Contains(stdout, failsafePassword) || strings.Contains(stdout, "tokenS3cr3t") {
				t.Errorf("--json %q", stdout)
			}
			_ = stderr
		})
	}
}
