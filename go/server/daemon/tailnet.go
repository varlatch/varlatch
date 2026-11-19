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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/write"
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
const tailnetUsage = "Usage: varlatchd admin tailnet repin [--yes [--adopt] [--offer <token>]] [--json]"

// repinArgs are `admin tailnet repin`'s flags.
type repinArgs struct {
	yes, adopt, asJSON bool
	// offer is the offer the confirmation was given for (--offer), "" for
	// none: --yes then acts on the observation at that moment.
	offer string
}

// offerToken is an offer as RepinView.OfferToken writes it.
var offerToken = regexp.MustCompile(`^[0-9a-f]{32}$`)

// tailnetArgs checks `admin tailnet` arguments; a non-empty message is a
// usage error.
func tailnetArgs(rest []string) (repinArgs, string) {
	var a repinArgs
	if len(rest) == 0 || rest[0] != "repin" {
		return a, tailnetUsage
	}
	args := rest[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--yes":
			a.yes = true
		case "--adopt":
			a.adopt = true
		case "--json":
			a.asJSON = true
		case "--offer":
			if i+1 >= len(args) || !offerToken.MatchString(args[i+1]) || a.offer != "" {
				return repinArgs{}, tailnetUsage
			}
			a.offer = args[i+1]
			i++
		default:
			return repinArgs{}, tailnetUsage
		}
	}
	if (a.adopt || a.offer != "") && !a.yes {
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
// again. Every re-pin is kept in the pin's history, logged, and recorded
// as the audit event tailnet.repinned (by the host operator, committed
// before the pin changes; no re-pin without its event).
//
// The text is as before. With --json it prints one document instead,
// --yes or not (repinResult): the view's fields under stable names, the
// outcome, the lines the text gives, and the pin after a re-pin; the exit
// status is the text's.
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
	res := repin(ctx, env, a)
	if a.asJSON {
		b, _ := json.Marshal(res)
		fmt.Fprintln(stdout, string(b))
		return res.code
	}
	fmt.Fprintf(stdout, "pinned:   %s\nobserved: %s\n", res.PinnedText, res.ObservedText)
	if res.Message != "" {
		if res.code != ExitOK {
			fmt.Fprintln(stderr, "varlatchd admin tailnet repin: "+res.Message)
		} else {
			fmt.Fprintln(stdout, res.Message)
		}
	}
	return res.code
}

// repinResult is what a re-pin did, as --json prints it (stable names).
type repinResult struct {
	tailnet.RepinView
	// PinnedText and ObservedText are the text's "pinned:" and "observed:"
	// values.
	PinnedText   string `json:"pinnedText"`
	ObservedText string `json:"observedText"`
	// Outcome is one of: nothing-observed, adoption-needed, enrolling,
	// holds, not-repinnable, suffix-changed, reopen-offered, offer-changed
	// (these change nothing), repinned, reopened, adopted, failed.
	Outcome string `json:"outcome"`
	// Message is the text's last line (on stderr when the status is not 0).
	Message string `json:"message"`
	// Pin is the pin after a re-pin, null otherwise.
	Pin  *tailnet.Pin `json:"pin"`
	code int
}

// resultFor is a result showing v.
func resultFor(v tailnet.RepinView) repinResult {
	res := repinResult{RepinView: v, PinnedText: "none", ObservedText: "unknown"}
	if v.Pinned != nil && !v.Pinned.Enrolling {
		res.PinnedText = describePin(v.Pinned.ControlURL, v.Pinned.TailnetID, v.Pinned.Suffix)
	}
	if v.Observed != nil {
		res.ObservedText = describePin(v.Observed.ControlURL, v.Observed.TailnetID, v.Observed.Suffix)
	}
	return res
}

// repin decides, and with --yes does, the re-pin.
func repin(ctx context.Context, env *hostEnv, a repinArgs) repinResult {
	v := env.tailnet.RepinView(ctx)
	res := resultFor(v)
	done := func(outcome, message string, code int) repinResult {
		res.Outcome, res.Message, res.code = outcome, message, code
		return res
	}
	switch {
	case v.Observed == nil:
		return done("nothing-observed", tailnet.ErrNothingToRepin.Error(), ExitFailure)
	case v.Missing && !a.adopt:
		return done("adoption-needed", "the pin is missing, but this node was enrolled before: tailnet access stays closed. If the observed tailnet is the one this installation trusts, run again with --yes --adopt.", ExitFailure)
	case v.Pinned != nil && v.Pinned.Enrolling:
		return done("enrolling", "The node is enrolling: its tailnet is pinned the first time it runs on one.", ExitOK)
	case !v.Missing && v.Reason == "" && v.Closed == "":
		return done("holds", "The pin holds: nothing to re-pin.", ExitOK)
	case !v.Offered:
		return done("not-repinnable", fmt.Sprintf("%s (%s). Tailnet access stays closed.", tailnet.ErrNotRepinnable.Error(), v.Reason), ExitFailure)
	case !a.yes && v.Reason == tailnet.PinSuffix:
		return done("suffix-changed", "The tailnet's MagicDNS suffix changed under the same tailnet. Run again with --yes to pin the observed suffix and reopen tailnet access.", ExitOK)
	case !a.yes:
		return done("reopen-offered", fmt.Sprintf("The tailnet matches its pin again, but access stays closed since it changed (%s). Run again with --yes to reopen tailnet access.", v.Closed), ExitOK)
	}
	w := &write.Writer{Store: env.store, Gates: env.gates}
	record := func(old, next *tailnet.Pin, reason string) error {
		return w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
			_, err := audit.Record(ctx, tx, repinEvent(old, next, reason))
			return err
		})
	}
	old, next, err := env.tailnet.Repin(ctx, a.adopt, a.offer, record)
	var changed *tailnet.ErrOfferChanged
	switch {
	case errors.As(err, &changed):
		// The confirmation was for another offer: nothing changed; the
		// fresh view, to show and confirm again.
		res = resultFor(changed.View)
		return done("offer-changed", "The tailnet changed since the re-pin was offered: nothing was re-pinned. Look at the pinned and the observed tailnet again, and confirm again.", ExitFailure)
	case err != nil:
		return done("failed", err.Error(), ExitFailure)
	case next == nil:
		return done("holds", "The pin holds: nothing to re-pin.", ExitOK)
	}
	res.Pin = next
	switch {
	case old == nil:
		return done("adopted", fmt.Sprintf("Adopted %s as the pinned tailnet; tailnet access is open.", next.Suffix), ExitOK)
	case old.Suffix != next.Suffix:
		return done("repinned", fmt.Sprintf("Re-pinned the tailnet from %s to %s; tailnet access is open.", old.Suffix, next.Suffix), ExitOK)
	default:
		return done("reopened", fmt.Sprintf("Reopened tailnet access on %s.", next.Suffix), ExitOK)
	}
}

// repinEvent is the audit event of a re-pin: tailnet.repinned, by the host
// operator (no identity: the control socket's peer is the data
// directory's owner or root), with what changed and why, and no value:
// suffixes, the tailnet's StableID and the closure's reason, never the
// control server's URL.
func repinEvent(old, next *tailnet.Pin, why string) audit.Event {
	action := "adopted"
	var from any
	if old != nil {
		from = old.Suffix
		action = "reopened"
		if old.Suffix != next.Suffix {
			action = "repinned"
		}
	}
	// The reason the re-pin's own check found, not an earlier look's.
	var reason any
	if why != "" {
		reason = why
	}
	return audit.Event{
		Type: "tailnet.repinned", Decision: audit.Info,
		Resource: jsvalue.Object{{Key: "tailnet", Value: next.TailnetID}},
		Metadata: jsvalue.Object{
			{Key: "action", Value: action},
			{Key: "fromSuffix", Value: from},
			{Key: "toSuffix", Value: next.Suffix},
			{Key: "tailnetId", Value: next.TailnetID},
			{Key: "reason", Value: reason},
			{Key: "operator", Value: true},
		},
	}
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
