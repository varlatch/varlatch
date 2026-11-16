// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The tailnet listener (ADR-0059 Decision 5, step 4.13b): varlatchd's own
// tsnet node, its pin and listeners report (server/tailnet), and the API
// served on the node's addresses by a tailnet listener of its own
// (httpserver's Options.Tailnet). The public listener never sees a tailnet
// peer's identity, and the tailnet one never answers without it.

// tailnetRunner is the running tailnet listener.
type tailnetRunner struct {
	cfg      *config.Tailnet
	node     *tailnet.TSNode
	manager  *tailnet.Manager
	resolver *tailnet.Resolver
	log      *slog.Logger
	done     chan struct{}

	mu      sync.Mutex
	srv     *http.Server
	stopped bool
}

// startTailnet starts the node (it returns at once; the node joins its
// tailnet in the background) and loads its pin. The auth key is read only
// while the node has no state of its own: once enrolled it is never
// needed again. controlURL is the configured one (tests replace it).
func startTailnet(cfg *config.Config, controlURL string, log *slog.Logger) (*tailnetRunner, error) {
	t := cfg.Tailnet
	dir := filepath.Join(cfg.DataDir, tailnet.StateDir)
	authKey := ""
	if _, err := os.Stat(filepath.Join(dir, "tailscaled.state")); errors.Is(err, os.ErrNotExist) && t.AuthKeyFile != "" {
		b, err := os.ReadFile(t.AuthKeyFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			log.Warn("the tailnet node is not enrolled and has no auth key; it waits for one", "file", t.AuthKeyFile)
		case err != nil:
			return nil, fmt.Errorf("reading the tailnet auth key: %w", err)
		default:
			authKey = strings.TrimSpace(string(b))
		}
	}
	tslog := log.With("component", "tsnet")
	node, err := tailnet.StartNode(tailnet.NodeConfig{
		Dir: dir, Hostname: t.Hostname, ControlURL: controlURL, AuthKey: authKey, Tags: t.Tags,
		Logf: func(format string, args ...any) { tslog.Debug(fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		return nil, err
	}
	m, err := tailnet.NewManager(node, controlURL, cfg.DataDir, t.Port, log, nil)
	if err != nil {
		_ = node.Close()
		return nil, err
	}
	return &tailnetRunner{cfg: t, node: node, manager: m, resolver: tailnet.NewPinnedResolver(node, m, log), log: log, done: make(chan struct{})}, nil
}

// serve waits for the node to join its tailnet, checks (or records) the
// pin, then serves handler on the node's addresses, and checks the node
// every minute until ctx ends.
func (r *tailnetRunner) serve(ctx context.Context, handler http.Handler) {
	defer close(r.done)
	if err := r.node.Up(ctx); err != nil {
		if ctx.Err() == nil {
			r.log.Error("the tailnet node did not join its tailnet; the tailnet listener is not serving", "error", err)
		}
		return
	}
	r.manager.Check(ctx)
	ln, err := r.node.Listen(r.cfg.Port)
	r.manager.Listening(err == nil)
	if err != nil {
		r.log.Error("the tailnet listener cannot listen", "port", r.cfg.Port, "error", err)
		return
	}
	srv := &http.Server{
		Handler: handler, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, IdleTimeout: idleTimeout,
		ErrorLog: slog.NewLogLogger(r.log.Handler(), slog.LevelWarn),
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		_ = ln.Close()
		return
	}
	r.srv = srv
	r.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	suffix, open := r.manager.Pinned()
	r.log.Info("varlatchd tailnet listener is serving", "port", r.cfg.Port, "tailnet", suffix, "open", open)
	tick := time.NewTicker(tailnet.CheckEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.manager.Check(ctx)
		}
	}
}

// stop ends the listener and leaves the tailnet (never logging out: the
// node keeps its identity). Only the first call does anything.
func (r *tailnetRunner) stop(ctx context.Context) {
	r.mu.Lock()
	srv, already := r.srv, r.stopped
	r.stopped = true
	r.mu.Unlock()
	if already {
		return
	}
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
	}
	_ = r.node.Close()
}

// tailnetUsage is `admin tailnet`'s usage.
const tailnetUsage = "Usage: varlatchd admin tailnet repin [--yes] [--json]"

// tailnetArgs checks `admin tailnet` arguments: whether to apply, and to
// print JSON; a non-empty message is a usage error.
func tailnetArgs(rest []string) (yes, asJSON bool, msg string) {
	if len(rest) == 0 || rest[0] != "repin" {
		return false, false, tailnetUsage
	}
	for _, a := range rest[1:] {
		switch a {
		case "--yes":
			yes = true
		case "--json":
			asJSON = true
		default:
			return false, false, tailnetUsage
		}
	}
	return yes, asJSON, ""
}

// runTailnetRepin is `varlatchd admin tailnet repin`, the host's re-pin
// primitive (step 6's `varlatch tailnet repin` runs it): in the running
// daemon only, since it compares the pin with what the node observes now.
// It shows both; with --yes it takes the observed suffix when that is the
// only change, and refuses a different tailnet (StableID or control URL),
// which means enrolling the node again. Every re-pin is kept in the pin's
// history and logged.
func runTailnetRepin(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	yes, asJSON, msg := tailnetArgs(rest)
	if msg != "" {
		fmt.Fprintln(stderr, msg)
		return 64
	}
	if env.tailnet == nil {
		fmt.Fprintln(stderr, "varlatchd admin tailnet repin: it runs in a running varlatchd with tailnet = on, which compares the pin with what its node observes now. "+
			"Start varlatchd (with tailnet = on in varlatchd.conf) and run it again.")
		return ExitFailure
	}
	v := env.tailnet.RepinView(ctx)
	if asJSON && !yes {
		b, _ := json.Marshal(v)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	pinned, observed := "none", "unknown"
	if v.Pinned != nil {
		pinned = describePin(v.Pinned.ControlURL, v.Pinned.TailnetID, v.Pinned.Suffix)
	}
	if v.Observed != nil {
		observed = describePin(v.Observed.ControlURL, v.Observed.TailnetID, v.Observed.Suffix)
	}
	fmt.Fprintf(stdout, "pinned:   %s\nobserved: %s\n", pinned, observed)
	switch {
	case v.Pinned == nil || v.Observed == nil:
		fmt.Fprintln(stderr, "varlatchd admin tailnet repin: "+tailnet.ErrNothingToRepin.Error())
		return ExitFailure
	case v.Reason == "":
		fmt.Fprintln(stdout, "The pin holds: nothing to re-pin.")
		return ExitOK
	case !v.Offered:
		fmt.Fprintf(stderr, "varlatchd admin tailnet repin: %s (%s). Tailnet access stays closed.\n", tailnet.ErrNotRepinnable.Error(), v.Reason)
		return ExitFailure
	case !yes:
		fmt.Fprintln(stdout, "The tailnet's MagicDNS suffix changed under the same tailnet. Run again with --yes to pin the observed suffix and reopen tailnet access.")
		return ExitOK
	}
	old, next, err := env.tailnet.Repin(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin tailnet repin: %s\n", err.Error())
		return ExitFailure
	}
	if next == nil {
		fmt.Fprintln(stdout, "The pin holds: nothing to re-pin.")
		return ExitOK
	}
	fmt.Fprintf(stdout, "Re-pinned the tailnet from %s to %s; tailnet access is open.\n", old.Suffix, next.Suffix)
	return ExitOK
}

func describePin(controlURL, tailnetID, suffix string) string {
	if controlURL == "" {
		controlURL = config.TailscaleControlURL
	}
	if tailnetID == "" {
		tailnetID = "(none)"
	}
	return fmt.Sprintf("suffix %s, tailnet %s, control %s", suffix, tailnetID, controlURL)
}
