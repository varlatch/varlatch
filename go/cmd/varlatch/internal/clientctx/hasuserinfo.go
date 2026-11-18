// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// HasUserinfo is whether a server URL holds a user name or password, read
// from the URL itself (WHATWG parsing, as `new URL` reads it), never from
// what masking makes of it: a user name that looks like a mask is still
// one. A text that does not parse as a URL counts when it holds an "@"
// anywhere, so a malformed URL is never taken for a clean one.
func HasUserinfo(server string) bool {
	u, ok := whatwg.ParseURL(server)
	if !ok {
		return strings.Contains(server, "@")
	}
	return u.Username != "" || u.Password != ""
}
