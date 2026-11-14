// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// ContentSecurityPolicy is the dashboard's policy, as the dashboard's
// container writes it today (apps/web/docker-entrypoint.d/
// 10-varlatch-config.sh): scripts and styles from this origin only, nothing
// inline, no framing. Its connect-src is this origin alone: the Go server
// has no Convex backend (ADR-0059 Decision 4; the dashboard's realtime
// comes from this origin with server-sent events, step 3.5), and no tailnet
// browser endpoint yet.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; " +
	"font-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; " +
	"form-action 'self' https://github.com; frame-ancestors 'none'; object-src 'none'"

// serveWeb serves the dashboard as nginx did (try_files $uri /index.html):
// a file of the build when the path names one, the app's index.html for
// every other path (single-page routing). /v1, /auth and /enroll never get
// here (ServeHTTP). Device sign-in's verification page is never cached.
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if !isGet(r) {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 Method Not Allowed"))
		return
	}
	w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
	if r.URL.Path == "/device" {
		w.Header().Set("Cache-Control", "no-store")
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
					http.ServeContent(w, r, name, time.Time{}, rs)
					return
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(s.webIndex))
}
