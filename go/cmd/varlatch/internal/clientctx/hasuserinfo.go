// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// HasUserinfo is whether a server URL holds a user name or password, read
// from the URL itself (WHATWG parsing, as `new URL` reads it), never from
// what masking makes of it: a user name that looks like a mask is still
// one. For a URL that parses it agrees with MaskUserinfo (which masks
// exactly when WHATWG reads a user name or password). A text that does not
// parse counts when it holds an at-sign in any form the fail-safe knows
// (HasAtSign: "@", "%40", "\u0040", ...), so a malformed URL is never
// taken for a clean one; that is broader than masking, on purpose, since
// it decides what may be committed.
//
// A URL that parses holds one too when it has a backslash and an at-sign
// in any form: WHATWG ends a special scheme's authority at the backslash
// ("https://u:p\u0040host" has the host "u" and the path "\u0040host"),
// but a reader that decodes escapes, or one that does not take a backslash
// for a slash, sees "u:p@host".
func HasUserinfo(server string) bool {
	u, ok := whatwg.ParseURL(server)
	if !ok {
		return HasAtSign(server)
	}
	if u.Username != "" || u.Password != "" {
		return true
	}
	return strings.ContainsRune(server, '\\') && HasAtSign(server)
}
