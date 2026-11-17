// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The tailnet listener (ADR-0059 Decision 5, step 4.13b): varlatchd's own
// tsnet node, its pin and listeners report (server/tailnet), and the API
// served on the node's addresses by a tailnet listener of its own
// (httpserver's Options.Tailnet). The public listener never sees a tailnet
// peer's identity, and the tailnet one never answers without it.

// tailnetRunner is the running tailnet listener, and the browser endpoint
// when it is configured (step 4.13c).
type tailnetRunner struct {
	cfg      *config.Tailnet
	node     *tailnet.TSNode
	manager  *tailnet.Manager
	resolver *tailnet.Resolver
	// cert is the browser endpoint's certificate; nil when it is off.
	cert *tailnet.Certificate
	log  *slog.Logger
	done chan struct{}

	mu      sync.Mutex
	srvs    []*http.Server
	stopped bool
}

// startTailnet starts the node (it returns at once; the node joins its
// tailnet in the background) and loads its pin. The auth key is read only
// while the node has no state of its own: once enrolled it is never
// needed again. controlURL is the configured one, certs where the browser
// endpoint's certificate comes from (nil: the node; tests replace both).
func startTailnet(cfg *config.Config, controlURL string, certs tailnet.CertSource, log *slog.Logger) (*tailnetRunner, error) {
	t := cfg.Tailnet
	dir := filepath.Join(cfg.DataDir, tailnet.StateDir)
	authKey := ""
	_, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	fresh := errors.Is(err, os.ErrNotExist)
	if fresh {
		// A node with no state of its own enrols: its first tailnet becomes
		// the pin. A node with state and no pin is never pinned silently.
		if err := tailnet.BeginEnrolment(cfg.DataDir); err != nil {
			return nil, fmt.Errorf("recording the tailnet enrolment: %w", err)
		}
	}
	if fresh && t.AuthKeyFile != "" {
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
	r := &tailnetRunner{cfg: t, node: node, manager: m, resolver: tailnet.NewPinnedResolver(node, m, log), log: log, done: make(chan struct{})}
	if t.HTTPSPort != 0 {
		if certs == nil {
			certs = node
		}
		m.SetBrowser(t.Hostname, t.HTTPSPort)
		// A certificate swapped in is checked at once, not at the next
		// minute.
		r.cert = tailnet.NewCertificate(certs, m.BrowserHost, log, nil, func() { m.Check(context.Background()) })
		m.SetCertificate(r.cert)
	}
	return r, nil
}

// browserEndpoint is the browser endpoint's gate: the node's name in the
// pinned tailnet, its port, the allowlisted origins; nil when it is off.
func (r *tailnetRunner) browserEndpoint() *httpserver.BrowserEndpoint {
	if r.cert == nil {
		return nil
	}
	return &httpserver.BrowserEndpoint{Host: r.manager.BrowserHost, Port: r.cfg.HTTPSPort, Origins: r.cfg.BrowserOrigins}
}

// serve waits for the node to join its tailnet, checks (or records) the
// pin, then serves handler on the node's addresses and, when configured,
// browser over HTTPS with the node's certificate, and checks the node
// every minute until ctx ends. A browser endpoint that cannot listen never
// takes the tailnet listener down with it.
func (r *tailnetRunner) serve(ctx context.Context, handler, browser http.Handler) {
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
	} else if r.start(handler, ln, slog.LevelWarn) {
		suffix, open := r.manager.Pinned()
		r.log.Info("varlatchd tailnet listener is serving", "port", r.cfg.Port, "tailnet", suffix, "open", open)
	}
	if r.cert != nil {
		go r.cert.Run(ctx)
		bln, err := r.node.Listen(r.cfg.HTTPSPort)
		r.manager.ListeningBrowser(err == nil)
		if err != nil {
			r.log.Error("the tailnet browser endpoint cannot listen", "port", r.cfg.HTTPSPort, "error", err)
		} else if r.start(browser, tls.NewListener(bln, r.cert.TLSConfig()), slog.LevelDebug) {
			// Refused handshakes (another name, no certificate) are logged
			// at debug only: anyone on the tailnet can make them.
			r.log.Info("varlatchd tailnet browser endpoint is serving", "endpoint", r.manager.BrowserEndpoint(), "origins", strings.Join(r.cfg.BrowserOrigins, ", "))
		}
		r.manager.Check(ctx)
	}
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

// start serves handler on ln, unless the runner stopped first.
func (r *tailnetRunner) start(handler http.Handler, ln net.Listener, level slog.Level) bool {
	srv := &http.Server{
		Handler: handler, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, IdleTimeout: idleTimeout,
		ErrorLog: slog.NewLogLogger(r.log.Handler(), level),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		_ = ln.Close()
		return false
	}
	r.srvs = append(r.srvs, srv)
	go func() { _ = srv.Serve(ln) }()
	return true
}

// stop ends the listeners and leaves the tailnet (never logging out: the
// node keeps its identity). Only the first call does anything.
func (r *tailnetRunner) stop(ctx context.Context) {
	r.mu.Lock()
	srvs, already := r.srvs, r.stopped
	r.stopped = true
	r.mu.Unlock()
	if already {
		return
	}
	for _, srv := range srvs {
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
	}
	_ = r.node.Close()
}

// tailnetUsage is `admin tailnet`'s usage.
const tailnetUsage = "Usage: varlatchd admin tailnet repin [--yes [--adopt]] [--json]"

// repinArgs are `admin tailnet repin`'s flags.
type repinArgs struct{ yes, adopt, asJSON bool }

// tailnetArgs checks `admin tailnet` arguments; a non-empty message is a
// usage error.
func tailnetArgs(rest []string) (repinArgs, string) {
	var a repinArgs
	if len(rest) == 0 || rest[0] != "repin" {
		return a, tailnetUsage
	}
	for _, arg := range rest[1:] {
		switch arg {
		case "--yes":
			a.yes = true
		case "--adopt":
			a.adopt = true
		case "--json":
			a.asJSON = true
		default:
			return repinArgs{}, tailnetUsage
		}
	}
	if a.adopt && !a.yes {
		return repinArgs{}, tailnetUsage
	}
	return a, ""
}

// runTailnetRepin is `varlatchd admin tailnet repin`, the host's re-pin
// primitive (step 6's `varlatch tailnet repin` runs it): in the running
// daemon only, since it compares the pin with what the node observes now,
// from a fresh check that must succeed. It shows both; with --yes it
// takes the observed suffix when that is the only change, or reopens a
// pin the tailnet matches again after a change; with --yes --adopt it pins
// the tailnet an enrolled node without a pin is on. A different tailnet
// (StableID or control URL) is refused: that means enrolling the node
// again. Every re-pin is kept in the pin's history and logged.
func runTailnetRepin(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	a, msg := tailnetArgs(rest)
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
	if a.asJSON && !a.yes {
		b, _ := json.Marshal(v)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
	pinned, observed := "none", "unknown"
	if v.Pinned != nil && !v.Pinned.Enrolling {
		pinned = describePin(v.Pinned.ControlURL, v.Pinned.TailnetID, v.Pinned.Suffix)
	}
	if v.Observed != nil {
		observed = describePin(v.Observed.ControlURL, v.Observed.TailnetID, v.Observed.Suffix)
	}
	fmt.Fprintf(stdout, "pinned:   %s\nobserved: %s\n", pinned, observed)
	refuse := func(msg string) int {
		fmt.Fprintln(stderr, "varlatchd admin tailnet repin: "+msg)
		return ExitFailure
	}
	switch {
	case v.Observed == nil:
		return refuse(tailnet.ErrNothingToRepin.Error())
	case v.Missing && !a.adopt:
		return refuse("the pin is missing, but this node was enrolled before: tailnet access stays closed. If the observed tailnet is the one this installation trusts, run again with --yes --adopt.")
	case v.Pinned != nil && v.Pinned.Enrolling:
		fmt.Fprintln(stdout, "The node is enrolling: its tailnet is pinned the first time it runs on one.")
		return ExitOK
	case !v.Missing && v.Reason == "" && v.Closed == "":
		fmt.Fprintln(stdout, "The pin holds: nothing to re-pin.")
		return ExitOK
	case !v.Offered:
		return refuse(fmt.Sprintf("%s (%s). Tailnet access stays closed.", tailnet.ErrNotRepinnable.Error(), v.Reason))
	case !a.yes && v.Reason == tailnet.PinSuffix:
		fmt.Fprintln(stdout, "The tailnet's MagicDNS suffix changed under the same tailnet. Run again with --yes to pin the observed suffix and reopen tailnet access.")
		return ExitOK
	case !a.yes:
		fmt.Fprintf(stdout, "The tailnet matches its pin again, but access stays closed since it changed (%s). Run again with --yes to reopen tailnet access.\n", v.Closed)
		return ExitOK
	}
	old, next, err := env.tailnet.Repin(ctx, a.adopt)
	switch {
	case err != nil:
		return refuse(err.Error())
	case next == nil:
		fmt.Fprintln(stdout, "The pin holds: nothing to re-pin.")
	case old == nil:
		fmt.Fprintf(stdout, "Adopted %s as the pinned tailnet; tailnet access is open.\n", next.Suffix)
	case old.Suffix != next.Suffix:
		fmt.Fprintf(stdout, "Re-pinned the tailnet from %s to %s; tailnet access is open.\n", old.Suffix, next.Suffix)
	default:
		fmt.Fprintf(stdout, "Reopened tailnet access on %s.\n", next.Suffix)
	}
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
