// SPDX-License-Identifier: Apache-2.0

package clientctx

import "github.com/varlatch/varlatch/go/lib/whatwg"

// HasUserinfo is whether a server URL holds a user name or password, read
// from the URL itself (WHATWG parsing, as `new URL` reads it), never from
// what masking makes of it: a user name that looks like a mask is still
// one. For a URL that parses it agrees with MaskUserinfo (which masks
// exactly when WHATWG reads a user name or password). A text that does not
// parse counts when it holds an at-sign in any form the fail-safe knows
// (HasAtSign: "@", "%40", "\u0040", ...), so a malformed URL is never
// taken for a clean one; that is broader than masking, on purpose, since
// it decides what may be committed.
func HasUserinfo(server string) bool {
	u, ok := whatwg.ParseURL(server)
	if !ok {
		return HasAtSign(server)
	}
	return u.Username != "" || u.Password != ""
}
