// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The address transfer (go-step7 decision 12, slice 7.4b). What stays the
// same is the origin people open (scheme, host and port) and so the
// passkeys' RP ID (its host); the node, its key or its address may change.
// The target serves during the transfer, isolated by the migration's gate
// (it answers GET /v1/meta and nothing else), so the public URL can be
// checked before the switch, and the undo can still reopen the source:
//
//   - public ingress: the source's Caddy stops, the target starts, takes
//     its certificate on the same name over ACME and binds 80 and 443;
//   - own proxy: the source's dashboard stops, freeing the loopback port
//     the operator's proxy targets, and the target starts on it;
//   - Coolify: the source's dashboard stops, and migrate with it, saying
//     the exact domain move to make by hand (O3, no Coolify adapter);
//     --resume checks it. A container keeps the router its labels give it
//     until it is made again, whatever Coolify's domain setting says, and
//     of two that name one domain the proxy picks either, anew at each
//     container that starts or stops on the host (Coolify 4.7.6, Traefik
//     3.6, measured): so one of the two is stopped, and the other serves.
//
// Then the public URL must answer with the migrated installation's id and
// the target's release. If it does not, the address goes back: the target
// stops, the source's ingress starts again (the Coolify shape says how to
// move the domain back), and the migration is undone.

// ErrAwaitingOperator is the Coolify shape's stop: the operator moves the
// domain, then runs --resume (or --abort).
var ErrAwaitingOperator = errors.New("waiting for the operator's domain move")

// transferEstimate is the transfer's share of the projected downtime, by
// shape (decision 19), with the target's restart at open.
func transferEstimate(kind Ingress) time.Duration {
	const restart = 5 * time.Second
	switch kind {
	case Public, Coolify:
		return time.Minute + restart
	}
	return 5*time.Second + restart
}

// origin is a URL's origin: scheme://host[:port], the default port left
// out, the host in lower case.
func origin(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", "", fmt.Errorf("%q is not an http or https URL", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	o := u.Scheme + "://" + host
	if strings.Contains(host, ":") {
		o = u.Scheme + "://[" + host + "]"
	}
	if port != "" {
		o += ":" + port
	}
	return o, host, nil
}

// sameAddress checks, before anything, that the target keeps the source's
// origin (and so its RP ID), and that the target is set up for the shape:
// public ingress needs its own HTTPS (listen_https); an own proxy needs it
// on the dashboard's loopback port. It gives the origin.
func (e *Engine) sameAddress(ing IngressInfo, tgt TargetInfo) (string, error) {
	kind := e.Options.Ingress
	if !slices.Contains(Ingresses, kind) {
		return "", fmt.Errorf("--ingress is public, proxy or coolify: the source's ingress shape (the address transfer differs by it)")
	}
	src, srcHost, err := origin(ing.PublicURL)
	if err != nil {
		return "", fmt.Errorf("the source's public URL (VARLATCH_PUBLIC_URL): %v", err)
	}
	dst, dstHost, err := origin(tgt.PublicURL)
	if err != nil {
		return "", fmt.Errorf("the target's public_url: %v", err)
	}
	if src != dst {
		return "", fmt.Errorf("the target's public_url is %s, the source's %s: a migration keeps the origin (and the passkeys' RP ID, %s)", dst, src, srcHost)
	}
	if srcHost != dstHost {
		return "", fmt.Errorf("the target's RP ID would be %s, the source's %s", dstHost, srcHost)
	}
	switch kind {
	case Public:
		if !ing.Caddy {
			return "", errors.New("--ingress public: the source runs no Caddy (docker-compose.caddy.yml): is its ingress another shape?")
		}
		if tgt.ListenHTTPS == "" {
			return "", errors.New("--ingress public: the target's configuration has no listen_https: it takes over HTTPS with its own certificate")
		}
	case Proxy:
		// An image's service publishes its port as Docker or Coolify maps
		// it: the operator's, said in the start step.
		if tgt.Kind != "image" && (ing.WebAddress == "" || !sameListen(ing.WebAddress, tgt.Listen)) {
			return "", fmt.Errorf("--ingress proxy: the target listens on %s, the source's dashboard on %s, which the proxy targets: set the target's listen to it", orNone(tgt.Listen), orNone(ing.WebAddress))
		}
	}
	return src, nil
}

// sameListen compares two host:port listen addresses.
func sameListen(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	return err1 == nil && err2 == nil && ap == bp && strings.EqualFold(ah, bh)
}

// transfer moves the address (journalled first: the target's journal
// enters transfer with its gate), then waits for the public URL to answer
// from the target. A shape whose undo is this host's (public, proxy) is
// undone when it does not; the Coolify shape waits for the operator.
func (e *Engine) transfer(ctx context.Context, j *Journal) error {
	if j.Transfer == nil {
		return e.undo(ctx, j, errors.New("the journal records no address to transfer"))
	}
	// Before the address moves, in every shape (Coolify's asks nothing of
	// the source here): still the installation that was copied. --resume
	// checked it (Resume).
	if err := e.checkProject(ctx); err != nil {
		return e.undo(ctx, j, err)
	}
	if j.Phase != Transfer {
		if err := e.enter(ctx, j, Transfer); err != nil {
			return e.undo(ctx, j, err)
		}
	}
	kind := j.Ingress
	e.say("Address transfer: the source's %s stops; the target starts on the same address.", ingressPart(kind))
	if err := e.Source.StopIngress(ctx, kind); err != nil {
		return e.undo(ctx, j, fmt.Errorf("stopping the source's %s: %w", ingressPart(kind), err))
	}
	startErr := e.Target.Start(ctx)
	if startErr == nil {
		crashPoint("transfer started")
	}
	var human *HumanStep
	if startErr != nil && !errors.As(startErr, &human) {
		return e.undo(ctx, j, fmt.Errorf("starting the target: %w", startErr))
	}
	if human != nil || (kind == Coolify && !j.Transfer.Asked) {
		// One stop for every step the operator takes: the target's start
		// (an image's service) and the domain move (Coolify), then
		// --resume checks both through the public URL.
		j.Transfer.Asked = true
		if err := e.save(ctx, j); err != nil {
			return err
		}
		n := 1
		if kind == Coolify {
			// Before the target's container is made: its labels are the
			// domain setting's then.
			e.say("Address transfer, by hand, step %d: in Coolify, move the domain of %s from the TypeScript application to the Go one (its domain setting; Save only). "+
				"Do not Deploy, Restart or Stop the TypeScript application: its stopped dashboard is the way back.", n, j.Transfer.Origin)
			n++
		}
		if human != nil {
			publish := ""
			if kind == Proxy && j.Transfer.Publish != "" {
				// An image's service publishes its port as Docker or
				// Coolify maps it: the operator maps it to what the proxy
				// targets.
				publish = fmt.Sprintf(" Publish its listen (%s) on %s, the address your proxy targets, which the source's dashboard has freed.",
					orNone(j.Target.Listen), j.Transfer.Publish)
			}
			e.say("Address transfer, by hand, step %d: %s%s", n, human.Instruction, publish)
		}
		e.say("Then run varlatch migrate --resume, which checks %s/v1/meta answers from the target; or varlatch migrate --abort, which undoes the migration "+
			"(the target stops first, then the source's %s starts again and is waited for).", j.Transfer.Origin, ingressPart(kind))
		return ErrAwaitingOperator
	}
	if err := e.waitForTarget(ctx, j); err != nil {
		if kind == Coolify {
			return fmt.Errorf("%w; once the domain is moved, varlatch migrate --resume checks again; varlatch migrate --abort undoes the migration: stop the Go service first when it asks, then it starts the TypeScript dashboard, which routes the domain itself, and waits for it; set the domain back in Coolify after that", err)
		}
		return e.undo(ctx, j, err)
	}
	j.Transfer.VerifiedAt = e.now().UTC().Format(time.RFC3339Nano)
	return e.save(ctx, j)
}

func ingressPart(kind Ingress) string {
	if kind == Public {
		return "Caddy"
	}
	return "dashboard"
}

// waitForTarget probes the public URL until it answers with the migrated
// installation's id and the target's release, or the transfer's timeout.
func (e *Engine) waitForTarget(ctx context.Context, j *Journal) error {
	timeout := e.Options.TransferTimeout
	if timeout <= 0 {
		timeout = DefaultTransferTimeout
	}
	every := e.Options.ProbeEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	sleep := e.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	want := ""
	if j.Copy != nil {
		want = j.Copy.InstallationID
	}
	deadline := e.now().Add(timeout)
	var last error
	for {
		id, version, err := e.Prober.Probe(ctx, j.Transfer.Origin)
		switch {
		case err != nil:
			last = err
		case id != want:
			last = fmt.Errorf("it answers as the installation %s, not the migrated %s", orNone(id), want)
		case version != j.Target.Release:
			last = fmt.Errorf("it answers with release %s, not the target's %s", orNone(version), j.Target.Release)
		default:
			e.say("The public URL %s answers from the target (installation %s, release %s).", j.Transfer.Origin, id, version)
			return nil
		}
		if !e.now().Before(deadline) {
			return fmt.Errorf("the public URL %s did not answer from the target within %s: %v", j.Transfer.Origin, timeout, last)
		}
		sleep(every)
	}
}

// stopTargetForUndo is an undo's first step in the transfer: the target
// stops serving the address. What it could not do is returned.
func (e *Engine) stopTargetForUndo(ctx context.Context) []error {
	if err := e.Target.Stop(ctx); err != nil {
		var human *HumanStep
		if errors.As(err, &human) {
			e.say("To undo, by hand: %s Then run varlatch migrate --abort (or --resume) again.", human.Instruction)
		}
		return []error{fmt.Errorf("stopping the target: %w", err)}
	}
	return nil
}

// returnAddress gives the address back during an undo, once the source's
// barrier is lifted: its ingress starts again (in the Coolify shape too,
// which says what to set back in Coolify). Started behind the barrier, the ingress would
// not come up: Compose starts the dashboard's one-off dependency
// (varlatch-migrate, service_completed_successfully) again with it, and
// that refuses while the source is behind a gate (run r8 of the 7.8b
// rehearsal). What it could not do is returned.
func (e *Engine) returnAddress(ctx context.Context, j *Journal) []error {
	if j.Ingress == Coolify {
		// Its stopped container has its router still; only Coolify's own
		// setting is the operator's.
		origin := "the installation's address"
		if j.Transfer != nil {
			origin = j.Transfer.Origin
		}
		e.say("The dashboard's container still routes the domain, and starts again. By hand, for later deploys: in Coolify, move the domain of %s back to the TypeScript application (its domain setting; Save only, do not Deploy it for this).", origin)
	}
	if err := e.Source.StartIngress(ctx, j.Ingress, j.UndoUnanswered); err != nil {
		return []error{fmt.Errorf("starting the source's %s again: %w", ingressPart(j.Ingress), err)}
	}
	return nil
}

// GateProber is a Prober that also asks which gate answers, and by which
// route.
type GateProber interface {
	ProbeGate(ctx context.Context, origin string) (GateAnswer, error)
}

// GateAnswer is an answer at an address: the route header its proxy put on
// it ("" for none), and the state of the gate that answers ("" for none, or
// when what answers is not a Varlatch server, as a proxy's own error).
type GateAnswer struct {
	Route  string
	Server bool
	State  string
}

func (a GateAnswer) String() string {
	switch {
	case !a.Server:
		return "not a Varlatch server"
	case a.State == "":
		return "a Varlatch server, ready or not saying"
	}
	return "a Varlatch server in the state " + a.State
}

// routeHeader is what the operator's route (RouteFile) puts on each answer
// through it, a proxy's own error among them: the migration's id. It is the
// proof of which router answered: the containers' own name the same host.
const routeHeader = "X-Varlatch-Rollback"

// ProbeGate is GET <origin>/readyz: the TypeScript release names its gate
// there (503, "state": "migrated-out").
func (p HTTPProber) ProbeGate(ctx context.Context, origin string) (GateAnswer, error) {
	_, header, body, err := p.get(ctx, origin+"/readyz")
	if err != nil {
		return GateAnswer{}, err
	}
	a := GateAnswer{Route: header.Get(routeHeader)}
	var r struct {
		Ready *bool  `json:"ready"`
		State string `json:"state"`
	}
	if json.Unmarshal(body, &r) == nil && r.Ready != nil {
		a.Server, a.State = true, r.State
	}
	return a, nil
}

// HTTPProber asks over HTTP(S), certificates verified as any client
// would.
type HTTPProber struct {
	Client *http.Client
}

// Probe is GET <origin>/v1/meta.
func (p HTTPProber) Probe(ctx context.Context, origin string) (string, string, error) {
	status, _, body, err := p.get(ctx, origin+"/v1/meta")
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", fmt.Errorf("GET /v1/meta answered %d", status)
	}
	var meta struct {
		InstallationID string `json:"installationId"`
		ServerVersion  string `json:"serverVersion"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", "", errors.New("GET /v1/meta did not answer in JSON")
	}
	return meta.InstallationID, meta.ServerVersion, nil
}

func (p HTTPProber) get(ctx context.Context, url string) (int, http.Header, []byte, error) {
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	// An operator's proxy or CDN must not answer from a cached one: the
	// pre-migration answer has the same installation id.
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	res, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, res.Header, body, nil
}
