// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import "testing"

// The path algorithms on their own; the shared table (pathVectors in
// testdata/known-differences.json) checks honoPath against Hono's getPath.
func TestTargetPaths(t *testing.T) {
	for _, c := range []struct{ target, normalized, hono, nginx string }{
		{"/v1/meta", "/v1/meta", "/v1/meta", "/v1/meta"},
		{"/v1/organizations/../meta", "/v1/meta", "/v1/meta", "/v1/meta"},
		{"/v1/organizations/%2e%2E/meta", "/v1/meta", "/v1/meta", "/v1/meta"},
		{"/v1/./meta/.", "/v1/meta/", "/v1/meta/", "/v1/meta/"},
		{"/v1/..", "/", "/", "/"},
		{"/..", "/", "/", "/"},
		{"/v1//organizations", "/v1//organizations", "/v1//organizations", "/v1/organizations"},
		{"/v1%2fmeta", "/v1%2fmeta", "/v1%2fmeta", "/v1/meta"},
		{"/v1/%6deta", "/v1/%6deta", "/v1/meta", "/v1/meta"},
		{"/v1/%25", "/v1/%25", "/v1/%25", "/v1/%"},
		{"/v1/%ff", "/v1/%ff", "/v1/%ff", "/v1/\xff"},
		{"/v1/%ff/%6deta", "/v1/%ff/%6deta", "/v1/%ff/meta", "/v1/\xff/meta"},
		{"/v1/%E2%82%AC%3B", "/v1/%E2%82%AC%3B", "/v1/€%3B", "/v1/€;"},
		{"/v1/%EF%BF%BD", "/v1/%EF%BF%BD", "/v1/�", "/v1/�"},
		{"/v1/a{b", "/v1/a%7Bb", "/v1/a{b", "/v1/a{b"},
		{"/v1/organizations/..%2fmeta", "/v1/organizations/..%2fmeta", "/v1/organizations/..%2fmeta", "/v1/meta"},
		{"/V1/meta", "/V1/meta", "/V1/meta", "/V1/meta"},
		// The orders differ: nginx decodes %2f before dot segments.
		{"/foo%2fbar/../v1/meta", "/v1/meta", "/v1/meta", "/foo/v1/meta"},
		{"/v1%2fx/../dashboard", "/dashboard", "/dashboard", "/v1/dashboard"},
		{"/x%2f..%2fv1/meta", "/x%2f..%2fv1/meta", "/x%2f..%2fv1/meta", "/v1/meta"},
	} {
		n := normalizeTarget(c.target)
		if n != c.normalized || honoPath(n) != c.hono || nginxPath(c.target) != c.nginx {
			t.Errorf("%s: normalized %q hono %q nginx %q, want %q %q %q", c.target, n, honoPath(n), nginxPath(c.target), c.normalized, c.hono, c.nginx)
		}
	}
}
