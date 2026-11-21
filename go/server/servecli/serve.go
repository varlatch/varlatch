// SPDX-License-Identifier: AGPL-3.0-or-later

package servecli

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Paths are the paths the installation answers: the installers at its
// root, and its release's files under PathPrefix + "v<version>/".
const PathPrefix = "/cli/"

// IsPath is whether p is one serve_cli answers (or would, when on).
func IsPath(p string) bool {
	return p == "/install.sh" || p == "/install.ps1" || strings.HasPrefix(p, PathPrefix)
}

// ServeHTTP answers GET and HEAD of the installers (stamped with the
// installation's address) and of this version's files, each looked up by
// its exact name in the verified set; anything else is not found.
func (r *Release) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		notFound(w)
		return
	}
	p := req.URL.Path
	if name, ok := strings.CutPrefix(p, "/"); ok && (name == "install.sh" || name == "install.ps1") {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		http.ServeContent(w, req, "", time.Time{}, strings.NewReader(string(r.scripts[name])))
		return
	}
	name, ok := strings.CutPrefix(p, PathPrefix+"v"+r.Version+"/")
	f, known := r.files[name]
	if !ok || !known {
		notFound(w)
		return
	}
	file, err := os.Open(f.path)
	if err != nil {
		http.Error(w, "the file cannot be read", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	switch name {
	case Sums:
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	case Bundle:
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	http.ServeContent(w, req, "", time.Time{}, file)
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found"))
}

// Manager prepares the release in the background and serves it once it is
// ready: until then, and when preparing fails, the CLI is not served and
// /v1/meta does not list cli.download. A failure is retried, a minute
// after the first and up to an hour apart; it never stops varlatchd.
type Manager struct {
	current atomic.Pointer[Release]
	log     *slog.Logger
}

// attemptTimeout bounds one attempt: the trusted root, SHA256SUMS and every
// file.
const attemptTimeout = 15 * time.Minute

// Start begins preparing o's release; it stops when ctx ends.
func Start(ctx context.Context, o Options, log *slog.Logger) *Manager {
	m := &Manager{log: log}
	go m.run(ctx, o)
	return m
}

func (m *Manager) run(ctx context.Context, o Options) {
	wait := o.RetryAfter
	if wait <= 0 {
		wait = time.Minute
	}
	for {
		actx, cancel := context.WithTimeout(ctx, attemptTimeout)
		r, err := Prepare(actx, o)
		cancel()
		if err == nil {
			m.current.Store(r)
			m.log.Info("serve_cli: serving the CLI", "version", r.Version, "files", r.Names())
			return
		}
		if ctx.Err() != nil {
			return
		}
		m.log.Warn("serve_cli: the CLI is not served yet; trying again", "version", o.Version, "error", err.Error(), "retryIn", wait.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Hour)
	}
}

// Current is the release being served, nil while there is none.
func (m *Manager) Current() *Release {
	if m == nil {
		return nil
	}
	return m.current.Load()
}
