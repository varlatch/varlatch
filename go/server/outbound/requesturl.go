// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"net/url"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// RequestURL is the URL as fetch sends it: parsed and serialized as
// `new URL` does (the host the outbound check decided, not one Go's parser
// reads differently), the path and query exactly as fetch writes them,
// no fragment.
//
// The path goes out as written through Opaque, except one that starts with
// "//": net/url sends an Opaque of that form as an absolute URL
// ("http://x/y" for the path //x/y). That one goes through Path and
// RawPath, which net/url sends as written when it can; a path it would
// write otherwise (a "|", which it escapes, or a stray "%") then differs
// from fetch's in those characters only.
func RequestURL(raw string) (*url.URL, bool) {
	u, ok := whatwg.ParseURL(raw)
	if !ok || u.Username != "" || u.Password != "" {
		return nil, false
	}
	path, q := u.RequestTarget()
	out := &url.URL{Scheme: u.Protocol[:len(u.Protocol)-1], Host: u.Host, RawQuery: q}
	if !strings.HasPrefix(path, "//") {
		out.Opaque = path
		return out, true
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		out.Path, out.RawPath = decoded, path
	} else {
		out.Path = path
	}
	return out, true
}
