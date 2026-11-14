// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	_ "embed"
	"net/http"
)

// The enrollment page (/enroll): the one-time link an admin command or an
// invitation prints, and the CLI's browser hand-off. enroll/enroll.html is
// the TypeScript server's page as it serves it (services/varlatchd/src/
// enroll/page.ts ENROLL_HTML, byte for byte; the go-parity vitest checks
// it), so the e2e suites drive one page on both servers. Its script,
// enroll/enroll.js, runs the ceremonies on varlatchd's own browser session
// (browser.go) where the TypeScript page runs Better Auth's client. Both
// are served as the TypeScript server serves them: the page as HTML, the
// script as JavaScript, with no Content-Security-Policy of their own.
var (
	//go:embed enroll/enroll.html
	enrollHTML []byte
	//go:embed enroll/enroll.js
	enrollJS []byte
)

func serveEnroll(w http.ResponseWriter, r *http.Request) {
	body, contentType := enrollHTML, "text/html; charset=UTF-8"
	if r.URL.Path == "/enroll.js" {
		body, contentType = enrollJS, "text/javascript"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
