// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The tailnet listeners (ADR-0014 §7, ADR-0046; ADR-0059 step 4.13), as
// the TypeScript server serves them: each is a server of its own, with no
// dashboard, no browser session and no public URL, whose every request is
// resolved, from the accepted socket's own peer address and nothing the
// request says, to a verified Tailnet Context or the reason there is none.
// The ordinary listener never has a resolver, so a Tailnet Context cannot
// arise there. The browser endpoint is a tailnet listener that also answers
// the allowlisted dashboard origins cross-origin.

// TailnetListener makes a server a tailnet listener.
type TailnetListener struct {
	// Resolve is the device check on the connection's own peer address
	// ("ip:port"): tailnet.Resolver's, or a stand-in in tests.
	Resolve func(ctx context.Context, remote string) tailnet.Resolution
	// Admit, when set, is the listener's admission (tailnet.Manager's):
	// while tailnet access is closed (the pin broken, missing, or not
	// known now) every request is refused, whatever it asks for; an
	// admitted request runs under a context cancelled when access closes.
	Admit func(ctx context.Context) (context.Context, func(), bool)
	// Browser, when set, makes it the browser endpoint.
	Browser *BrowserEndpoint
}

// TailnetClosedMessage is the refusal of every request on a tailnet
// listener while tailnet access is closed. The TypeScript server pins its
// tailnet in its configuration and has no such state.
const TailnetClosedMessage = tailnet.ClosedMessage

// BrowserEndpoint is the browser endpoint's gate (ADR-0046 Decisions 3
// and 4).
type BrowserEndpoint struct {
	// Host is the node's MagicDNS name, lower case ("" while it is not
	// known, and every request is refused); Port its HTTPS port.
	Host func() string
	Port int
	// Origins are the exact origins allowed to read cross-origin.
	Origins []string
}

const (
	tailnetEndpointPattern = "GET /v1/tailnet/endpoint"
	tailnetContextPattern  = "GET /v1/tailnet/context"
	listenersPattern       = "GET /v1/installation/listeners"
)

type resolutionKey struct{}

// resolutionOf is the request's tailnet resolution, and whether it came in
// on a tailnet listener.
func resolutionOf(ctx context.Context) (tailnet.Resolution, bool) {
	r, ok := ctx.Value(resolutionKey{}).(tailnet.Resolution)
	return r, ok
}

// withResolution puts a tailnet listener's resolution on the request: its
// Tailnet Context, which every authorization decision then reads.
func withResolution(r *http.Request, res tailnet.Resolution) *http.Request {
	ctx := context.WithValue(r.Context(), resolutionKey{}, res)
	if res.Context != nil {
		ctx = authz.WithTailnet(ctx, res.Context, res.Valid)
	}
	return r.WithContext(ctx)
}

// listenerOf is "tailnet" on a tailnet listener, else "ordinary".
func listenerOf(ctx context.Context) string {
	if _, ok := resolutionOf(ctx); ok {
		return "tailnet"
	}
	return "ordinary"
}

const browserEnvRoute = `^/v1/organizations/[^/]+/projects/[^/]+/environments/[^/]+`

// browserRoutes are the only routes a page may call cross-origin: the
// protected value reads and the device check.
var browserRoutes = []struct {
	method string
	path   *regexp.Regexp
}{
	{"GET", regexp.MustCompile(browserEnvRoute + `/effective-configuration$`)},
	{"POST", regexp.MustCompile(browserEnvRoute + `/disclosures$`)},
	{"POST", regexp.MustCompile(browserEnvRoute + `/validate$`)},
	{"GET", regexp.MustCompile(`^/v1/tailnet/context$`)},
}

func isBrowserRoute(method, p string) bool {
	for _, r := range browserRoutes {
		if r.method == method && r.path.MatchString(p) {
			return true
		}
	}
	return false
}

// gate is tailnetBrowserGate, run before the device check and
// authentication: only the node's own name is answered; a request without
// Origin (the CLI, scripts) passes; one with Origin only from an exactly
// allowlisted origin to a browser route, else 403 without CORS headers.
// An allowed request, errors included, gets CORS headers for its origin,
// never Access-Control-Allow-Credentials. It returns false when it
// answered.
func (b *BrowserEndpoint) gate(w http.ResponseWriter, r *http.Request, p string) bool {
	host, name := strings.ToLower(r.Host), b.Host()
	if name == "" || host != name && host != name+":"+strconv.Itoa(b.Port) {
		writeError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "This endpoint answers only as "+name)
		return false
	}
	origins, present := r.Header["Origin"]
	if !present {
		return true
	}
	origin := strings.Join(origins, ", ")
	preflight := r.Method == http.MethodOptions
	method := r.Method
	if preflight {
		method = headerValue(r, "Access-Control-Request-Method")
	}
	allowed := false
	for _, o := range b.Origins {
		allowed = allowed || o == origin
	}
	if !allowed || !isBrowserRoute(method, p) {
		w.Header().Set("Vary", "Origin")
		writeError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "This origin may not make this request here")
		return false
	}
	h := w.Header()
	if preflight {
		// Varlatch-Approval: an export the dashboard repeats with its
		// step-up approval (ADR-0054 amendment C), allowed only when the
		// preflight asks for it.
		allow := "Authorization, Content-Type"
		for _, asked := range strings.Split(headerValue(r, "Access-Control-Request-Headers"), ",") {
			if strings.ToLower(strings.TrimSpace(asked)) == "varlatch-approval" {
				allow = "Authorization, Content-Type, Varlatch-Approval"
			}
		}
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", allow)
		h.Set("Access-Control-Max-Age", "300")
		// A public dashboard reaching this tailnet address: Chromium's
		// Private Network Access preflight asks whether that is allowed.
		// (Its successor, Local Network Access, asks the user instead.)
		if strings.EqualFold(strings.TrimSpace(headerValue(r, "Access-Control-Request-Private-Network")), "true") {
			h.Set("Access-Control-Allow-Private-Network", "true")
		}
		h.Set("Vary", "Origin")
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Expose-Headers", "Retry-After, X-Request-Id, "+CredentialExpiresHeader)
	h.Add("Vary", "Origin")
	return true
}

func (r reply) VisitGetTailnetEndpointResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitGetTailnetContextResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitGetInstallationListenersResponse(w http.ResponseWriter) error { return r.visit(w) }

// notRouted answers as a path no route serves (404 Not Found).
type notRouted struct{}

func (notRouted) VisitGetTailnetContextResponse(w http.ResponseWriter) error {
	writeNotFound(w)
	return nil
}

// GetTailnetEndpoint is GET /v1/tailnet/endpoint, on every listener, for
// any authenticated caller: where a browser reads tailnet-protected
// values, null when this installation serves no browser endpoint. It says
// nothing about whether this caller can reach it (ADR-0046 Decision 6).
func (o *operations) GetTailnetEndpoint(ctx context.Context, _ api.GetTailnetEndpointRequestObject) (api.GetTailnetEndpointResponseObject, error) {
	var endpoint any
	if u := o.s.opts.browserEndpoint(); u != "" {
		endpoint = u
	}
	return ok(jsvalue.Object{{Key: "browserEndpoint", Value: endpoint}}), nil
}

// GetTailnetContext is GET /v1/tailnet/context, on the browser endpoint
// only (elsewhere the route does not exist): the caller's own device as
// this request's connection resolved, evaluating no Requirement. The
// dashboard's Connect action (ADR-0046 Decision 5).
func (o *operations) GetTailnetContext(ctx context.Context, _ api.GetTailnetContextRequestObject) (api.GetTailnetContextResponseObject, error) {
	if o.s.opts.Tailnet == nil || o.s.opts.Tailnet.Browser == nil {
		return notRouted{}, nil
	}
	res, _ := resolutionOf(ctx)
	return ok(res.Device()), nil
}

// GetInstallationListeners is GET /v1/installation/listeners, for
// Installation Admins: the tailnet listeners as configured and as
// varlatchd last observed them, null without a tailnet listener; never
// reachability from a client, which only the client can see.
func (o *operations) GetInstallationListeners(ctx context.Context, _ api.GetInstallationListenersRequestObject) (api.GetInstallationListenersResponseObject, error) {
	if err := installationAdmin(ctx); err != nil {
		return nil, err
	}
	var report any
	if o.s.opts.TailnetListeners != nil {
		report = o.s.opts.TailnetListeners()
	}
	return ok(jsvalue.Object{{Key: "tailnet", Value: report}}), nil
}

// browserEndpoint is the browser endpoint's URL now, "" for none.
func (o *Options) browserEndpoint() string {
	if o.BrowserEndpoint == nil {
		return ""
	}
	return o.BrowserEndpoint()
}
