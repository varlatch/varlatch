// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httpserver is varlatchd's HTTP layer (ADR-0059 step 3.2): the /v1
// strict server generated from the OpenAPI document (go/server/api), the
// shared stub of the operations not built yet, the request window, client
// addresses, the access log, /healthz and /readyz, and the embedded
// dashboard.
//
// The behaviour follows the TypeScript server (services/varlatchd/src/http/
// app.ts) and the dashboard's nginx in front of it (apps/web/nginx.conf),
// since varlatchd now serves both:
//
//   - every response from the API side carries X-Request-Id;
//   - a request body over 1 MiB answers 413 VALIDATION_FAILED;
//   - each client address gets WindowLimit requests per WindowLength;
//     beyond that, 429 with PERMISSION_DENIED and Retry-After;
//   - an unknown route under the API side answers Hono's plain-text
//     "404 Not Found", after the authentication the TypeScript server runs
//     first for /v1 (unknownV1);
//   - every other path serves the dashboard (single-page routing), with
//     its Content-Security-Policy. /v1, /auth and /enroll never do.
package httpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/clientaddr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/pgtime"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// MaxBody is the largest request body accepted (Hono's bodyLimit in
// app.ts).
const MaxBody = 1 << 20

// Backend is what the HTTP layer reads from the server's state.
type Backend interface {
	// InstallationID is the installation's ID, or "" when there is none.
	InstallationID(ctx context.Context) (string, error)
	// Ready reports /readyz's checks: the schema is current, the loaded
	// Root KEK opens the installation's canary, and the installation
	// exists.
	Ready(ctx context.Context) (schema, kek, installation bool)
}

// Options configures the handler.
type Options struct {
	// Maintenance, when set, is the maintenance admission (ADR-0036 D6):
	// while it admits nothing, the API answers 503 MAINTENANCE.
	Maintenance Admission
	// Backups, when set, is the backup status getInstallationBackups
	// answers (ADR-0059 step 4.14).
	Backups BackupStatus
	// Outbound is the outbound policy (ADR-0057), from outbound_allow; nil
	// is the strict policy (nothing beyond public https).
	Outbound *outbound.Policy
	// Version is the server version /v1/meta reports.
	Version string
	// ReleaseCheckDir holds the host's release check (release-check.json,
	// ADR-0049), which `varlatch upgrade --check` records and
	// getInstallationRelease reads; "" when there is none to read.
	ReleaseCheckDir string
	// PublicURL is the configured public URL; nil when not set.
	PublicURL *url.URL
	// Sync is the outbound sync installation switch; SyncAdapters narrows
	// the adapters (nil: all).
	Sync         bool
	SyncAdapters []string
	// SyncClient replaces the outbound policy's clients for the platforms'
	// requests (tests: the fake platforms); nil in varlatchd.
	SyncClient *http.Client
	// TrustedProxies decides whose X-Forwarded-For is believed; nil trusts
	// no proxy.
	TrustedProxies func(address string) bool
	// AccessLog receives a record per request; nil writes none.
	AccessLog *AccessLog
	// Web is the dashboard: index.html at its root and the files it loads.
	Web fs.FS
	// Backend reads server state.
	Backend Backend
	// Auth is authentication: credentials, browser sessions, passkeys and
	// device sign-in (ADR-0059 step 3.4). Without it no bearer
	// authenticates and the browser session is not served.
	Auth *auth.Service
	// Writer is the write path (go/server/write): the single writer and
	// the process's gates. RootKEK wraps a new Organization's KEK.
	Writer  *write.Writer
	RootKEK []byte
	// Values is the read path of values (ADR-0059 step 3.6): the effective
	// configuration and disclosures. Without it they answer 500.
	Values *values.Service
	// Realtime publishes the dashboard's live updates (GET /auth/events,
	// events.go; ADR-0059 Decision 4). Served only with Auth, which
	// authenticates the streams; /v1/meta then lists realtime.sse.
	Realtime *realtime.Hub
	// Log receives errors (never request bodies or credentials).
	Log *slog.Logger
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
	// Zones is the tz database a cursor's time names zones from, as
	// PostgreSQL reads its host's (pgtime); nil is pgtime.System.
	Zones *pgtime.Zones
	// AuditExportOff is the host's audit_export = off (VARLATCH_AUDIT_EXPORT):
	// the audit export's writes are refused, but for its removal.
	AuditExportOff bool
	// AuditExportVerifiedProvider treats an endpoint as a verified Object
	// Lock provider (tests: a local S3 server); nil for none.
	AuditExportVerifiedProvider func(endpoint string) bool
	// OIDCFetch replaces the OIDC exchange's fetch of issuer documents
	// (tests); nil is the outbound policy's oidc client.
	OIDCFetch oidc.Fetcher
	// Tailnet, when set, makes this server a tailnet listener (tailnet.go):
	// no dashboard, browser session, enrollment page or public URL, every
	// request resolved to its peer's Tailnet Context first.
	Tailnet *TailnetListener
	// BrowserEndpoint is the tailnet browser endpoint's URL when this
	// installation serves one, "" (or nil) for none, on every listener: GET
	// /v1/tailnet/endpoint answers it and /v1/meta lists
	// tailnet.browser-reads. A function: the URL names the pinned tailnet,
	// known once the node is enrolled.
	BrowserEndpoint func() string
	// TailnetListeners is what varlatchd last observed of its tailnet
	// listeners (GET /v1/installation/listeners); nil without one.
	TailnetListeners func() any
	// Built adds operations, by route pattern ("GET /v1/organizations"), to
	// the ones this build has, for tests of the stub's wiring. Each is
	// served by the generated strict handler: a pattern whose operation
	// this package does not implement answers 500 if it is ever reached.
	Built []string
	// Stubbed takes operations, by route pattern, out of the ones this
	// build has, for tests of the stub itself now that every /v1 operation
	// is built: each answers the shared stub. Built wins over it.
	Stubbed []string
}

// BuiltOperations are the /v1 operations this build serves, by the route
// pattern the generated server registers (method, "/v1" and the path).
// Every other operation answers the shared stub (NotImplementedYet).
var BuiltOperations = []string{
	"GET /v1/meta",
	// Step 3.4: who am I, the caller's credentials and passkeys, device
	// sign-in, the profile and the caller's organizations.
	"GET /v1/me",
	"GET /v1/me/profile",
	"GET /v1/me/credentials",
	"POST /v1/me/credentials/cli",
	"DELETE /v1/me/credentials/{credential}",
	"GET /v1/me/passkeys",
	"DELETE /v1/me/passkeys/{passkey}",
	"POST /v1/me/passkeys/{passkey}/confirmation/options",
	"POST /v1/me/passkeys/{passkey}/confirmation",
	"GET /v1/me/approvals/{approval}",
	"POST /v1/me/approvals/{approval}/options",
	"POST /v1/me/approvals/{approval}/approve",
	"POST /v1/me/approvals/{approval}/cancel",
	"POST /v1/auth/device",
	"POST /v1/auth/device/token",
	"POST /v1/auth/device/lookup",
	"POST /v1/auth/device/approve",
	"GET /v1/organizations",
	// Step 3.6: the read path of values (values.go).
	effectivePattern,
	disclosurePattern,
	// Step 4.1a: Organizations (organizations.go).
	createOrganizationPattern,
	getOrganizationPattern,
	renameOrganizationPattern,
	// Step 4.1b: Contracts (contracts.go).
	activeContractPattern,
	pushRevisionPattern,
	getRevisionPattern,
	activateRevisionPattern,
	// Step 4.1c: Projects and environments (projects.go), and the two
	// installation reads (installation.go).
	listProjectsPattern,
	createProjectPattern,
	getProjectPattern,
	renameProjectPattern,
	deleteProjectPattern,
	listEnvironmentsPattern,
	createEnvironmentPattern,
	getEnvironmentPattern,
	deleteEnvironmentPattern,
	"GET /v1/installation/release",
	"GET /v1/installation/backups",
	// Step 4.1d: the writes of values (valuewrites.go).
	setValuePattern,
	deleteValuePattern,
	applyChangeSetPattern,
	// Step 4.1d: validation and strict retrieval (values.go), and the
	// Config Item search (search.go).
	validatePattern,
	strictPattern,
	searchPattern,
	// Step 4.3a: Security Controls (security.go).
	listSecurityControlsPattern,
	changeSecurityControlPattern,
	securityControlReportPattern,
	securityApprovalKeysPattern,
	// Step 4.2: rotation (valuewrites.go).
	beginRotationPattern,
	completeRotationPattern,
	// Step 4.3c: the incident freeze (freeze.go) and the audit log's reads
	// (auditevents.go).
	getIncidentFreezePattern,
	freezeOrganizationPattern,
	liftIncidentFreezePattern,
	listAuditEventsPattern,
	exportAuditEventsPattern,
	// Step 4.4a: machine identities and their credentials (identities.go).
	listIdentitiesPattern,
	createServiceIdentityPattern,
	renameIdentityPattern,
	retireIdentityPattern,
	reactivateIdentityPattern,
	listIdentityCredentialsPattern,
	issueIdentityCredentialPattern,
	revokeIdentityCredentialPattern,
	// Step 4.4b: Grants, Roles, Groups and Teams (access.go).
	listGrantsPattern, createGrantPattern, deleteGrantPattern, replaceGrantPattern,
	listRolesPattern, createRolePattern, updateRolePattern, deleteRolePattern,
	listGroupsPattern, createGroupPattern, updateGroupPattern, deleteGroupPattern,
	listGroupMembersPattern, addGroupMemberPattern, removeGroupMemberPattern,
	listTeamsPattern, createTeamPattern, updateTeamPattern, deleteTeamPattern,
	listTeamMembersPattern, addTeamMemberPattern, removeTeamMemberPattern,
	listTeamProjectsPattern, addTeamProjectPattern, removeTeamProjectPattern,
	// Step 4.7a: the outbound policy's refused destinations (outbound.go).
	getInstallationOutboundPattern,
	refusedDestinationsPattern,
	// Step 4.4c: Tailnet Requirements and the access reports
	// (requirements.go).
	listRequirementsPattern, createRequirementPattern, updateRequirementPattern, deleteRequirementPattern,
	credentialReviewPattern, machineReachPattern, myPermissionsPattern,
	// Step 4.7b: audit webhooks (webhooks.go).
	listWebhooksPattern, createWebhookPattern, updateWebhookPattern, revokeWebhookPattern,
	// Step 4.11a: the audit export's configuration (auditexport.go).
	getAuditExportPattern, createAuditExportPattern, checkAuditExportPattern, changeAuditExportPattern,
	replaceAuditExportPattern, removeAuditExportPattern,
	// Step 4.5a: invitations, members and the profile (people.go).
	listInvitationsPattern, createInvitationPattern, revokeInvitationPattern,
	reviewMemberPattern, removeMemberPattern, changeMemberRolePattern, updateMyProfilePattern,
	// Step 4.5b: the exposure report and confirmations (people.go).
	memberExposurePattern, confirmExposureRevocationPattern,
	// Step 4.6: broker Capabilities (capabilities.go).
	listCapabilitiesPattern, issueCapabilityPattern, revokeCapabilityPattern, exerciseCapabilityPattern,
	// Step 4.8: OIDC workload identity (oidc.go).
	listOidcBindingsPattern, createOidcBindingPattern, revokeOidcBindingPattern, exchangeOidcTokenPattern,
	// Step 4.13a: the tailnet listeners (tailnet.go).
	tailnetEndpointPattern, tailnetContextPattern, listenersPattern,
	// Step 4.9b: Platform Connections (connections.go).
	listConnectionsPattern, createConnectionPattern, checkPlatformPattern, listDestinationsPattern,
	getConnectionPattern, replaceCredentialPattern, revokeConnectionPattern,
	// Step 4.9c: Sync Targets (targets.go).
	listOrgSyncTargetsPattern, listSyncTargetsPattern, createSyncTargetPattern, getSyncTargetPattern,
	updateSyncTargetPattern, revokeSyncTargetPattern, pauseSyncTargetPattern, resumeSyncTargetPattern,
	// Step 4.12b: Organization deletion and the audit-access tombstone
	// (orgdeletion.go).
	getOrganizationDeletionPattern, scheduleOrganizationDeletionPattern,
	approveOrganizationDeletionPattern, cancelOrganizationDeletionPattern,
	deletedAuditEventsPattern, deletedAuditExportPattern,
	listDeletedOrganizationsPattern, removeDeletedReaderPattern,
	// Step 4.9d: pushing (targets.go; the engine in syncs/converge.go).
	pushSyncTargetPattern,
	// Step 4.10a: the GitHub App, its registration and import (githubapp.go).
	getGitHubAppPattern, removeGitHubAppPattern, startRegistrationPattern, completeRegistrationPattern,
	attachRegistrationPattern, discardRegistrationPattern, importGitHubAppPattern, rotateGitHubAppKeyPattern, listInstallationsPattern,
}

// Server is the handler.
type Server struct {
	opts      Options
	window    *requestWindow
	apiMux    *http.ServeMux
	patterns  []string // every operation the generated server registers
	stubbed   []string // the ones answered by the stub
	webIndex  []byte
	webExists bool
	browser   http.Handler
	// oidc is the OIDC exchange, with its bounded issuer caches (one per
	// process).
	oidc *oidc.Service
}

// New builds the handler.
func New(opts Options) (*Server, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Zones == nil {
		opts.Zones = pgtime.System
	}
	if opts.Backend == nil {
		return nil, errors.New("httpserver: no backend")
	}
	s := &Server{opts: opts, window: newRequestWindow(opts.Now)}
	if opts.Writer != nil && (opts.Outbound != nil || opts.OIDCFetch != nil) {
		fetch := opts.OIDCFetch
		if fetch == nil {
			fetch = oidc.PolicyFetcher(opts.Outbound)
		}
		s.oidc = &oidc.Service{Writer: opts.Writer, Policy: opts.Outbound, Verifier: &oidc.Verifier{Fetch: fetch, Now: opts.Now}, Now: opts.Now, Log: opts.Log}
	}
	built := map[string]bool{}
	for _, p := range BuiltOperations {
		built[p] = true
	}
	for _, p := range opts.Stubbed {
		if !built[p] {
			return nil, fmt.Errorf("httpserver: %s is not a built operation", p)
		}
		delete(built, p)
	}
	for _, p := range opts.Built {
		built[p] = true
	}
	mux := &operationMux{ServeMux: http.NewServeMux(), built: built, wrap: s.builtOperation}
	strict := api.NewStrictHandlerWithOptions(&operations{s: s}, nil, api.StrictHTTPServerOptions{
		// A body the generated decoder cannot read: zod's 422. A built
		// operation's body was checked against its schema first (body.go),
		// so this answers only what that check let through.
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
		},
		ResponseErrorHandlerFunc: s.answerError,
	})
	api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseURL:    "/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		},
	})
	for p := range built {
		if !mux.registered[p] {
			return nil, fmt.Errorf("httpserver: %s is not an operation of the OpenAPI document", p)
		}
	}
	// Anything else under /v1: no such route.
	mux.ServeMux.HandleFunc("/v1/", s.unknownV1)
	s.apiMux = mux.ServeMux
	s.patterns = mux.patterns
	s.stubbed = mux.stubbed
	if opts.Auth != nil && opts.Tailnet == nil {
		s.browser = s.newBrowserHandler()
	}
	if opts.Web != nil {
		if b, err := fs.ReadFile(opts.Web, "index.html"); err == nil {
			s.webIndex, s.webExists = b, true
		}
	}
	return s, nil
}

// Operations returns every /v1 route pattern the generated server has.
func (s *Server) Operations() []string { return append([]string{}, s.patterns...) }

// Stubbed returns the route patterns answered by the shared stub.
func (s *Server) Stubbed() []string { return append([]string{}, s.stubbed...) }

// operationMux takes the generated server's routes: an operation this
// build has gets its generated handler; every other one gets the stub,
// which answers before the generated wrapper binds parameters and before
// the strict handler decodes the body, so a request to it is never
// authenticated, validated, decoded or stored.
type operationMux struct {
	*http.ServeMux
	built map[string]bool
	// wrap adds what a built operation runs first (authentication).
	wrap       func(pattern string, h http.HandlerFunc) http.HandlerFunc
	registered map[string]bool
	patterns   []string
	stubbed    []string
}

func (m *operationMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	if m.registered == nil {
		m.registered = map[string]bool{}
	}
	m.registered[pattern] = true
	m.patterns = append(m.patterns, pattern)
	if m.built[pattern] {
		m.ServeMux.HandleFunc(pattern, m.wrap(pattern, h))
		return
	}
	m.stubbed = append(m.stubbed, pattern)
	m.ServeMux.Handle(pattern, notBuilt(pattern))
}

// notBuilt is the shared stub: 501 NOT_IMPLEMENTED_YET, naming the
// operation's route.
func notBuilt(operation string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotImplemented, NotImplementedYet,
			operation+" is not built yet in this varlatchd (ADR-0059: the Go server is being written)")
	})
}

type ctxKey int

const requestIDKey ctxKey = 0

// clientKey carries the request's client address, as the request window
// counts it.
type clientKey struct{}

func requestIDOf(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

// The paths the dashboard's nginx passed to varlatchd (apps/web/nginx.conf:
// a prefix match, so /authx and /v1x are varlatchd's too, and answer its
// 404), and the CLI download paths (exact).
var (
	apiPrefix = regexp.MustCompile(`^/(auth|v1|enroll|healthz|readyz|\.well-known)`)
	cliPaths  = map[string]bool{"/install.sh": true, "/install.ps1": true, "/cli/varlatch.cjs": true}
)

// ServeHTTP answers a request.
// Admission is the maintenance admission (server/maintenance).
type Admission interface {
	// Enter admits one request, false while a gate is open; leave ends it.
	Enter() (leave func(), ok bool)
}

// BackupStatus is the backup status (server/backups), as JSON.
type BackupStatus interface {
	StatusJSON() ([]byte, error)
}

// MaintenanceMessage is the 503's message (http/app.ts).
const MaintenanceMessage = "Installation maintenance; retry later"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	arrived := s.opts.Now()
	id := newRequestID()
	// The request's audit events take varlatchd's clock, as its services do.
	r = r.WithContext(audit.WithClock(context.WithValue(r.Context(), requestIDKey, id), s.opts.Now))
	rec := &recorder{ResponseWriter: w}
	// The paths of the TypeScript deployment (target.go): nginx's decides
	// whether the request reaches the API side at all; varlatchd's router
	// (Hono's) routes, authenticates and counts it there. Handlers see the
	// path they route on as URL.Path.
	// Each from the raw target, in its own order: the two do not commute
	// (nginx decodes %2f before resolving dot segments; the URL parser
	// resolves them first and keeps %2f).
	target := requestTarget(r)
	normalized := normalizeTarget(target)
	front := nginxPath(target)
	isAPI := apiPrefix.MatchString(front) || cliPaths[front]
	p := front
	if s.opts.Tailnet != nil {
		// A tailnet listener is the API alone: no nginx in front of it.
		isAPI = true
	}
	if isAPI {
		p = honoPath(normalized)
	}
	routed := *r.URL
	routed.Path, routed.RawPath = p, ""
	r.URL = &routed
	counted := isAPI && p != "/healthz" && p != "/readyz"
	// windowed: the request window actually admitted or refused this
	// request (a request refused earlier, by the body limit, is not charged).
	windowed := false
	var windowOpened time.Time
	// Every X-Forwarded-For line, joined as Node joins them: a proxy that
	// adds a line of its own instead of appending to the caller's is read
	// from the right like any other (the caller's forged line stays left).
	client := clientaddr.Of(r.RemoteAddr, headerValue(r, "X-Forwarded-For"), s.opts.TrustedProxies)
	r = r.WithContext(context.WithValue(r.Context(), clientKey{}, client))
	windowKey := client
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			s.opts.Log.Error("a request handler panicked", "method", r.Method, "path", p, "requestId", id, "panic", fmt.Sprint(v))
			if rec.status == 0 {
				writeError(rec, r, http.StatusInternalServerError, "INTERNAL", "Internal error")
			}
		}
		s.log(r, rec, arrived, client, windowed, windowOpened, id)
	}()
	if isAPI {
		rec.Header().Set("X-Request-Id", id)
		if t := s.opts.Tailnet; t != nil {
			// The browser endpoint's gate, then the device check, before
			// anything costs a lookup or authentication (app.ts's order).
			if t.Browser != nil && !t.Browser.gate(rec, r, p) {
				return
			}
			// The listener's admission: nothing is served while tailnet
			// access is closed, and what was admitted stops when it closes.
			if t.Admit != nil {
				actx, release, ok := t.Admit(r.Context())
				if !ok {
					writeError(rec, r, http.StatusForbidden, "TAILNET_CONTEXT_UNAVAILABLE", TailnetClosedMessage)
					return
				}
				defer release()
				r = r.WithContext(actx)
			}
			res := t.Resolve(r.Context(), r.RemoteAddr)
			r = withResolution(r, res)
			if res.Context != nil {
				// Every peer on a tailnet listener comes from the node:
				// a recognized device gets a request window of its own.
				windowKey = "node:" + res.Context.NodeID
			}
		}
		// The maintenance admission, first (http/app.ts): /healthz always
		// answers, /readyz says the server is not ready, and every other
		// route answers 503 MAINTENANCE with Retry-After. The dashboard's
		// own files are served regardless, so it can show the
		// maintenance screen.
		if s.opts.Maintenance != nil && p != "/healthz" {
			leave, ok := s.opts.Maintenance.Enter()
			if !ok {
				if p == "/readyz" {
					writeJS(rec, http.StatusServiceUnavailable, jsvalue.Object{
						{Key: "ready", Value: false}, {Key: "checks", Value: jsvalue.Object{{Key: "maintenance", Value: false}}},
					})
					return
				}
				rec.Header().Set("Retry-After", "5")
				writeError(rec, r, http.StatusServiceUnavailable, "MAINTENANCE", MaintenanceMessage)
				return
			}
			defer leave()
		}
		// Hono's bodyLimit, on every route, before the request window,
		// authentication and any handler: a declared length is judged by
		// the header; a body without one (chunked) is read up to the limit
		// first, and one byte more refuses it.
		// @hono/node-server gives a GET, HEAD or TRACE request no body at
		// all, so bodyLimit never looks at what one carries: it is neither
		// read nor limited here, and handlers never see it.
		if bodyless(r.Method) {
			r.Body = http.NoBody
		} else if r.ContentLength > MaxBody {
			writeError(rec, r, http.StatusRequestEntityTooLarge, "VALIDATION_FAILED", "Request body exceeds 1 MiB")
			return
		} else if r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody {
			body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
			_ = r.Body.Close()
			if err != nil {
				// The client stopped sending: nothing can be answered usefully.
				writeError(rec, r, http.StatusBadRequest, "VALIDATION_FAILED", "Request body could not be read")
				return
			}
			if len(body) > MaxBody {
				writeError(rec, r, http.StatusRequestEntityTooLarge, "VALIDATION_FAILED", "Request body exceeds 1 MiB")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		r.Body = http.MaxBytesReader(rec, r.Body, MaxBody)
	}
	if counted {
		windowed = true
		ok, retry, opened := s.window.admit(windowKey)
		windowOpened = opened
		if !ok {
			rec.Header().Set("Retry-After", retry)
			writeError(rec, r, http.StatusTooManyRequests, "PERMISSION_DENIED", RateExceededMessage)
			return
		}
	}
	if !isAPI {
		s.serveWeb(rec, r)
		return
	}
	s.serveAPI(rec, r)
}

// bodyless reports whether the Node adapter passes a request of this
// method on without its body (@hono/node-server newRequestFromIncoming:
// GET and HEAD, and TRACE, which it turns into GET).
func bodyless(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodTrace
}

func (s *Server) log(r *http.Request, rec *recorder, arrived time.Time, client string, windowed bool, windowOpened time.Time, id string) {
	if s.opts.AccessLog == nil {
		return
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	record := &AccessRecord{
		Arrived: arrived.UTC(), Completed: s.opts.Now().UTC(), Client: client,
		Method: r.Method, Path: r.URL.Path, Status: status, Bytes: rec.bytes, Window: windowed, RequestID: id,
	}
	if windowed && !windowOpened.IsZero() {
		w := windowOpened.UTC()
		record.WindowOpened = &w
	}
	if v, ok := r.Header["X-Forwarded-For"]; ok {
		joined := strings.Join(v, ", ")
		record.ForwardedFor = &joined
	}
	s.opts.AccessLog.write(record)
}

func isGet(r *http.Request) bool { return r.Method == http.MethodGet || r.Method == http.MethodHead }

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/healthz" && isGet(r):
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case p == "/readyz" && isGet(r):
		s.readyz(w, r)
	case cliPaths[p] && isGet(r):
		// ADR-0058 Decision 3, off (VARLATCH_SERVE_CLI's default): the same
		// answer as a path that does not exist, as the TypeScript server's.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not found"))
	case p == "/auth" || strings.HasPrefix(p, "/auth/"):
		// The browser session (browser.go).
		if s.browser == nil {
			writeNotFound(w)
			return
		}
		s.browser.ServeHTTP(w, r)
	case (p == "/enroll" || p == "/enroll.js") && isGet(r) && s.opts.Tailnet == nil:
		// The enrollment page (enroll.go).
		serveEnroll(w, r)
	case p == "/v1" || strings.HasPrefix(p, "/v1/"):
		// Hono matches the path as sent; Go's mux would redirect a path
		// that is not clean (// or a dot segment, a trailing slash). Such a
		// path names no route.
		if p == "/v1" || p != path.Clean(p) {
			s.unknownV1(w, r)
			return
		}
		s.apiMux.ServeHTTP(w, r)
	default:
		writeNotFound(w)
	}
}

// headerValue is a request header as Node and the Fetch Headers give it to
// the TypeScript server: every line of it, joined with ", " (Go's Get would
// return the first line only).
func headerValue(r *http.Request, name string) string {
	return strings.Join(r.Header.Values(name), ", ")
}

// authenticates reports whether the TypeScript server's bearer middleware
// (app.ts, app.use("/v1/*")) authenticates a request to path with method
// before routing it: every /v1 path but /v1/meta (any method), and the
// three operations that authenticate otherwise (the OIDC exchange and
// device sign-in's two CLI calls, POST only).
func authenticates(method, p string) bool {
	if p == "/v1/meta" {
		return false
	}
	if method == http.MethodPost && (p == "/v1/oidc/token" || p == "/v1/auth/device" || p == "/v1/auth/device/token") {
		return false
	}
	return true
}

// unknownV1 answers a /v1 route the OpenAPI document does not describe (a
// path it does not list, or a method that path does not have) in the
// TypeScript server's order: its authentication runs for every /v1 path
// (authenticates) before Hono's not-found answer. So without a bearer
// credential the answer is 401 AUTHENTICATION_REQUIRED, the error
// envelope; the plain-text 404 comes only for a request that passed
// authentication, or one to /v1/meta's path, which needs none.
//
// Known operations not built yet never get here: the stub answers them
// first, before any authentication (operationMux).
func (s *Server) unknownV1(w http.ResponseWriter, r *http.Request) {
	if authenticates(r.Method, r.URL.Path) {
		// The credential is verified first, as the TypeScript server does:
		// an invalid, revoked or expired one answers 401 INVALID_CREDENTIAL
		// (with its authentication.failed audit event), and an agent-run
		// credential on a method other than GET or HEAD answers 403
		// PERMISSION_DENIED.
		if _, ok := s.authenticate(w, r); !ok {
			return
		}
	}
	writeNotFound(w)
}

type readiness struct {
	Ready  bool `json:"ready"`
	Checks struct {
		Schema       bool `json:"schema"`
		KEK          bool `json:"kek"`
		Installation bool `json:"installation"`
	} `json:"checks"`
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	var out readiness
	out.Checks.Schema, out.Checks.KEK, out.Checks.Installation = s.opts.Backend.Ready(r.Context())
	out.Ready = out.Checks.Schema && out.Checks.KEK && out.Checks.Installation
	status := http.StatusOK
	if !out.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, out)
}
