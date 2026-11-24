// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

// ContentSecurityPolicy is the dashboard's policy without a tailnet
// browser endpoint, as the dashboard's container writes it
// (apps/web/docker-entrypoint.d/10-varlatch-config.sh): scripts and styles
// from this origin only, nothing inline, no framing. Its connect-src is
// this origin: the Go server has no Convex backend (ADR-0059 Decision 4;
// the dashboard's realtime comes from this origin with server-sent events,
// step 3.5). With a browser endpoint, contentSecurityPolicy adds it.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; " +
	"font-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; " +
	"form-action 'self' https://github.com; frame-ancestors 'none'; object-src 'none'"

// endpointOrigin is an https origin and nothing else, the form the
// dashboard container's script requires of VARLATCH_TAILNET_ENDPOINT
// before it writes it into connect-src.
var endpointOrigin = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// contentSecurityPolicy is the dashboard's policy for a browser endpoint
// (ADR-0046): its origin added to connect-src, as the TypeScript
// installation adds VARLATCH_TAILNET_ENDPOINT, so the dashboard can Connect
// to it. endpoint is the endpoint as getTailnetEndpoint answers it now
// (from the pin: none before enrolment or once the pin is closed); one
// that is not exactly an https origin is left out.
func contentSecurityPolicy(endpoint string) string {
	if endpoint == "" || !endpointOrigin.MatchString(endpoint) {
		return ContentSecurityPolicy
	}
	return strings.Replace(ContentSecurityPolicy, "connect-src 'self';", "connect-src 'self' "+endpoint+";", 1)
}

// oauthCallbackPath is where an OAuth provider sends the browser back to
// (ADR-0062), with the authorization code in the address: no request the page
// makes names that address, whatever it loads first, and no cache keeps it.
const oauthCallbackPath = "/oauth/callback/"

// entryPath is the entry page (ADR-0063), a page of the dashboard's build
// that is none of the dashboard: people from outside open it from a link
// somebody sent them, and it holds a secret value until it is sent.
const entryPath = "/entry"

// entryHeaders are its own: nothing from another origin, no form that sends
// itself (a value would be in an address), no referrer, no frame, no opener,
// nothing kept in a cache. The link's secret is after the #, so it is in no
// request; the page takes it out of the address before it does anything.
var entryHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; " +
		"connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
	"Referrer-Policy":              "no-referrer",
	"Cache-Control":                "no-store",
	"X-Content-Type-Options":       "nosniff",
	"X-Frame-Options":              "DENY",
	"X-Robots-Tag":                 "noindex, nofollow, noarchive",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), clipboard-read=()",
}

// serveWeb serves the dashboard as nginx did (try_files $uri /index.html):
// a file of the build when the path names one, the app's index.html for
// every other path (single-page routing). /v1, /auth, /enroll and /convex
// never get here (ServeHTTP). HTML answers Cache-Control: no-cache (except
// /device and /oauth/callback/, which are never cached: no-store) so browsers
// revalidate after a migration or upgrade instead of serving a stale app from
// heuristic cache.
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if !isGet(r) {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 Method Not Allowed"))
		return
	}
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy(s.opts.browserEndpoint()))
	if r.URL.Path == "/device" {
		w.Header().Set("Cache-Control", "no-store")
	}
	if strings.HasPrefix(path.Clean("/"+r.URL.Path)+"/", oauthCallbackPath) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
	}
	if r.URL.Path == entryPath {
		for k, v := range entryHeaders {
			w.Header().Set(k, v)
		}
	}
	if !s.webExists {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if f, err := s.opts.Web.Open(name); err == nil {
			defer f.Close()
			if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
				if rs, ok := f.(io.ReadSeeker); ok {
					if name == "varlatch-config.js" {
						w.Header().Set("Cache-Control", "no-cache")
					}
					http.ServeContent(w, r, name, time.Time{}, rs)
					return
				}
			}
		}
	}
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(s.webIndex))
}
