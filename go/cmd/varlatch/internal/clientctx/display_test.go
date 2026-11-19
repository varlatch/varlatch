// SPDX-License-Identifier: Apache-2.0

package clientctx

import "testing"

// TestDisplayServer: every server URL is shown through an allow-list of
// its parts. An ordinary URL keeps its bytes; a user name and password
// never show; a query, a fragment and a path outside the allow-list are
// left out with a marker; anything else is UnrecognisedServer, never the
// value (Sol's round-6 canaries on #278 included).
func TestDisplayServer(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"http://127.0.0.1:1234", "http://127.0.0.1:1234"},
		{"http://127.0.0.1:1234/", "http://127.0.0.1:1234/"},
		{"https://h.example/varlatch/", "https://h.example/varlatch/"},
		{"https://a.example", "https://a.example"},
		{"HTTPS://Example.COM:8443/Path", "HTTPS://Example.COM:8443/Path"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"https://bücher.example", "https://bücher.example"},
		{"//h.example/p", "//h.example/p"},
		{"https://h.example/?", "https://h.example/?"},
		{"https://u:p@h.example/x", "https://h.example/x"},
		{"https://ghp_TokenAsUserName@h.example", "https://h.example"},
		{"//ci-bot:pw@h.example", "//h.example"},
		{" //ci-bot_:example-password@upstream.example", "//upstream.example"},
		{"http://user:hunter2@127.0.0.1:2", "http://127.0.0.1:2"},
		{"//gateway.example/?next=//ghp_RoundSixCanary@upstream.example", "//gateway.example/?[redacted]"},
		{"//gateway.example/?next=%2F%2Fci-bot%3ARoundSixPassword%40upstream.example", "//gateway.example/?[redacted]"},
		{"https://h.example/?token=ghp_abcdef", "https://h.example/?[redacted]"},
		{"https://h.example/p#ghp_abcdef", "https://h.example/p#[redacted]"},
		{"https://h.example/?a=%40b%3Ac#x=https://u:p@h", "https://h.example/?[redacted]#[redacted]"},
		{"https://h.example?next=https://a.example/?next=https://u:p@h", "https://h.example?[redacted]"},
		{"https://h.example/#", "https://h.example/#"},
		{"https://gw.example/next/https://u:p@h.example", "https://gw.example/next/[redacted]"},
		// Only unreserved characters and "/" are shown (Sol, #278 round 7):
		// a matrix parameter, an escape or a colon hides the rest of the path.
		{"https://gateway.example/varlatch;jsessionid=RoundSevenCanary", "https://gateway.example/[redacted]"},
		{"https://h.example/;token=ghp_RoundSeven", "https://h.example/[redacted]"},
		{"https://h.example/api/v1;token=x/more", "https://h.example/api/[redacted]"},
		{"https://h.example/api/v1/", "https://h.example/api/v1/"},
		{"https://h.example/a%20b", "https://h.example/[redacted]"},
		{"https://h.example/api/ghp%5FRoundSeven", "https://h.example/api/[redacted]"},
		{"https://h.example/next:ghp_RoundSeven", "https://h.example/[redacted]"},
		{"https://h.example/x=1,y=2", "https://h.example/[redacted]"},
		{"//h.example/varlatch;jsessionid=RoundSevenCanary?x#y", "//h.example/[redacted]?[redacted]#[redacted]"},
		{"https://gw.example/%2F%2Fu%3Ap%40h", "https://gw.example/[redacted]"},
		{"https://gw.example/ghp_x%2540h", "https://gw.example/[redacted]"},
		{"http:/u:p@[::1", "[unrecognised server URL]"},
		{"not a url", "[unrecognised server URL]"},
		{"nosuch", "[unrecognised server URL]"},
		{"mailto:ci-bot@h.example", "[unrecognised server URL]"},
		{"https://h ex.example", "[unrecognised server URL]"},
		{"ht\ttps://u:p@h", "[unrecognised server URL]"},
		{"https://example.com\\path@segment", "[unrecognised server URL]"},
		{"HTTPS://TOKEN\\u0040h.example/path", "[unrecognised server URL]"},
		{"foo://TOKEN\\u0040h.example", "[unrecognised server URL]"},
		{"", "[unrecognised server URL]"},
	} {
		if got := DisplayServer(c.in); got != c.want {
			t.Errorf("DisplayServer(%q) = %q, want %q", c.in, got, c.want)
		}
		// What is shown is shown as it is again: no part of it is ever
		// taken for a user name, a password or an at-sign.
		if got := DisplayServer(c.in); got != UnrecognisedServer && (DisplayServer(got) != got || HasAtSign(got) || MaskURLInValue(got) != got) {
			t.Errorf("DisplayServer(%q) = %q is not shown as it is again", c.in, got)
		}
	}
}
