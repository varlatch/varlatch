// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The local Broker (ADR-0022, amended by ADR-0039), apps/cli/src/broker.ts:
// a loopback-only forward proxy that substitutes per-run Placeholders with
// real secret material only at the Substitution Targets varlatchd recorded
// on the Capability, in requests it originates itself over verified TLS to
// allowlisted destinations. It is credential mediation, not a network
// sandbox: traffic to other destinations passes through unchanged
// (Placeholders intact, useless) unless strict mode blocks it. An opaque
// CONNECT tunnel cannot be inspected without MITM, which Varlatch does not
// do: CONNECT to a destination that uses Secrets is refused with a precise
// diagnostic. No Secret is kept across requests.
//
// The Agent reaches it only with the per-run proxy credential, checked in
// constant time once the request's line and headers are read and before
// anything else of the request is read or acted on.

// TunnelsPath is TUNNELS_PATH: the tunnels refused so far, by destination.
const TunnelsPath = "/varlatch-broker/tunnels"

// GeneratePlaceholder is generatePlaceholder: an opaque per-run token that
// encodes no item name or metadata.
func GeneratePlaceholder() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "vlch_ph_v1_" + hex.EncodeToString(b)
}

// Exercised is what exercising the Capability gave for one request: the
// values of the placed items only, the targets varlatchd holds, the placed
// items no longer stored, and a rotating item's retiring value (scrubbed
// from responses like the current one).
type Exercised struct {
	Values   map[string]string
	Targets  map[string][]string
	Withheld []string
	Retiring map[string]string
}

// Options is BrokerOptions.
type Options struct {
	// Placeholders maps each of this run's Placeholders to its item.
	Placeholders map[string]string
	// Destinations are the issued Capability's canonical selectors.
	Destinations []string
	// Targets are the ones varlatchd recorded on the Capability.
	Targets map[string][]string
	// Exercise exercises the Capability for one destination and the
	// placements the request needs.
	Exercise func(ctx context.Context, host string, port int, placements []Placement) (Exercised, error)
	// Strict blocks traffic to other destinations instead of passing it on.
	Strict bool
	Report func(Event)
	Limits Limits
	// RootCAs verify destinations' TLS; nil is the system's.
	RootCAs *x509.CertPool
}

// Running is RunningBroker.
type Running struct {
	Port int
	// Token is the per-run proxy credential, in http://vlt:<token>@127.0.0.1:<port>.
	Token    string
	ProxyURL string
	listener net.Listener
	b        *broker
}

// HeldValues is how many exercised value sets the Broker holds right now
// (0 between requests: nothing is kept).
func (r *Running) HeldValues() int {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	return r.b.held
}

// Close stops the Broker and ends every connection.
func (r *Running) Close() error {
	err := r.listener.Close()
	r.b.mu.Lock()
	for c := range r.b.conns {
		_ = c.Close()
	}
	r.b.mu.Unlock()
	r.b.wg.Wait()
	return err
}

type broker struct {
	opts        Options
	token       string
	selectors   []Selector
	targets     map[string][]Target
	placeholder map[string][]byte
	transport   *http.Transport
	mu          sync.Mutex
	held        int
	tunnels     map[string]int
	conns       map[net.Conn]bool
	wg          sync.WaitGroup
}

// Start is startBroker: a target varlatchd recorded that cannot be parsed
// stops the run before it starts.
func Start(opts Options) (*Running, error) {
	if opts.Report == nil {
		opts.Report = func(Event) {}
	}
	// Each bound not given is the default's, as {...SCRUB_LIMITS, ...limits}.
	if opts.Limits.MaxDecodedBytes == 0 {
		opts.Limits.MaxDecodedBytes = DefaultLimits.MaxDecodedBytes
	}
	if opts.Limits.IdleMillis == 0 {
		opts.Limits.IdleMillis = DefaultLimits.IdleMillis
	}
	if opts.Limits.BufferedBytes == 0 {
		opts.Limits.BufferedBytes = DefaultLimits.BufferedBytes
	}
	targets := map[string][]Target{}
	for item, list := range opts.Targets {
		for _, raw := range list {
			t, err := ParseTarget(raw)
			if err != nil {
				return nil, err
			}
			targets[item] = append(targets[item], t)
		}
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	b := &broker{
		opts:        opts,
		token:       base64.RawURLEncoding.EncodeToString(tokenBytes),
		selectors:   ParseSelectors(opts.Destinations),
		targets:     targets,
		placeholder: map[string][]byte{},
		tunnels:     map[string]int{},
		conns:       map[net.Conn]bool{},
		transport: &http.Transport{
			// Stock TLS verification; redirects are relayed, never followed
			// (RoundTrip does not follow them); no proxy of its own.
			TLSClientConfig:    &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12},
			DisableCompression: true,
			DisableKeepAlives:  true,
			Proxy:              nil,
		},
	}
	for p, item := range opts.Placeholders {
		b.placeholder[item] = []byte(p)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	r := &Running{Port: port, Token: b.token, ProxyURL: "http://vlt:" + b.token + "@127.0.0.1:" + strconv.Itoa(port), listener: listener, b: b}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns[conn] = true
			b.mu.Unlock()
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()
				defer func() {
					b.mu.Lock()
					delete(b.conns, conn)
					b.mu.Unlock()
					_ = conn.Close()
				}()
				b.serve(conn)
			}()
		}
	}()
	return r, nil
}

// checkProxyAuth is checkProxyAuth: Basic, the user vlt and the run's
// token, compared in constant time.
func (b *broker) checkProxyAuth(h *head) bool {
	header, ok := h.first("proxy-authorization")
	if !ok {
		return false
	}
	parts := strings.Split(header, " ")
	if strings.ToLower(parts[0]) != "basic" || len(parts) < 2 || parts[1] == "" {
		return false
	}
	expected := []byte(base64.StdEncoding.EncodeToString([]byte("vlt:" + b.token)))
	given, ok := latin1Bytes(parts[1])
	return ok && len(given) == len(expected) && subtle.ConstantTimeCompare(given, expected) == 1
}

// serve reads requests on one connection until it ends.
func (b *broker) serve(conn net.Conn) {
	r := bufio.NewReaderSize(conn, 4096)
	w := bufio.NewWriter(conn)
	first := true
	for {
		// An idle kept-alive connection ends quietly.
		if !first {
			_ = conn.SetReadDeadline(time.Now().Add(keepAliveIdle))
			if _, err := r.Peek(1); err != nil {
				return
			}
		}
		first = false
		started := time.Now()
		_ = conn.SetReadDeadline(started.Add(headTimeout))
		h, err := readHead(r)
		if err != nil {
			var ne net.Error
			switch {
			case errors.Is(err, io.EOF):
			case errors.As(err, &ne) && ne.Timeout():
				_, _ = conn.Write([]byte(rawRefusal(errTimeout)))
			case errors.Is(err, errNoHost):
				_ = nodeReply(w, false, 400, []Pair{{"Connection", "close"}}, "")
			default:
				_, _ = conn.Write([]byte(rawRefusal(err)))
			}
			return
		}
		_ = conn.SetReadDeadline(started.Add(requestTimeout))
		if h.method == "CONNECT" {
			b.connect(conn, r, w, h)
			return
		}
		if !b.handle(conn, r, w, h) {
			return
		}
	}
}

// deny is deny: a refusal the Broker makes itself, marked as its own.
func deny(w *bufio.Writer, h *head, status int, message string, extra ...Pair) {
	headers := append([]Pair{{"Content-Type", "text/plain"}, {"Connection", "close"}, {ReplyHeader, "refused"}}, extra...)
	_ = nodeReply(w, h.http10(), status, headers, "varlatch-broker: "+message+"\n")
}

// connectDiagnostic is CONNECT_DIAGNOSTIC.
func connectDiagnostic(host string) string {
	return "Varlatch blocked an HTTPS CONNECT tunnel to " + host + ". " +
		"Agent-safe secret substitution requires the broker to inspect the outbound " +
		"request before establishing TLS. This client uses an opaque CONNECT tunnel, " +
		"which Varlatch intentionally does not MITM. Send the request with " +
		"varlatch request (a curl-like client, for example: varlatch request -H " +
		`"Authorization: Bearer $API_KEY" https://` + host + "/...), or send plain HTTP " +
		"requests with absolute URIs through the proxy."
}

// connectStatus is CONNECT_STATUS: the reason phrase reaches people the
// body does not (curl -v, Python's http.client).
const connectStatus = "502 Tunnel refused by Varlatch, use varlatch request"

// connect handles an opaque tunnel: never inspected, never substituted.
func (b *broker) connect(conn net.Conn, r *bufio.Reader, w *bufio.Writer, h *head) {
	if !b.checkProxyAuth(h) {
		_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n" + ReplyHeader + ": refused\r\n\r\n"))
		return
	}
	// The request-target as JavaScript's split(":") reads it.
	fields := strings.Split(h.target, ":")
	host, portRaw := fields[0], "443"
	if len(fields) > 1 {
		portRaw = fields[1]
	}
	port := jsNumber(portRaw)
	if port == 0 || port != port {
		port = 443
	}
	if MatchesSelectors(b.selectors, host, port) {
		destination := canonicalHost(host) + ":" + jsjson.Number(port)
		b.mu.Lock()
		b.tunnels[destination]++
		b.mu.Unlock()
		b.opts.Report(Event{Kind: "tunnel", Destination: destination})
		_, _ = conn.Write([]byte("HTTP/1.1 " + connectStatus + "\r\nContent-Type: text/plain\r\nConnection: close\r\n" + ReplyHeader + ": refused\r\n\r\n" + connectDiagnostic(host) + "\n"))
		return
	}
	if b.opts.Strict {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n" + ReplyHeader + ": refused\r\n\r\nvarlatch-broker: blocked by --agent-network=strict\n"))
		return
	}
	upstream, err := net.Dial("tcp", net.JoinHostPort(host, jsjson.Number(port)))
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, r); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

// brokerOwned are the headers the Broker owns on the connection it opens:
// hop-by-hop and proxy headers are dropped; Host and Content-Length come
// from the authorized URL and the body actually sent.
var brokerOwned = []string{"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "host", "content-length"}

// afterExercise is a failure after exercise: the request is dropped with
// its plaintext.
type afterExercise struct{ rule, message string }

func (e afterExercise) Error() string { return e.message }

// isMaintenance is isMaintenance: isolating maintenance (ADR-0036 D6) is
// transient, so the Agent is told to retry.
func isMaintenance(err error) bool {
	var api *apiclient.APIError
	return errors.As(err, &api) && api.Code == "MAINTENANCE"
}

// handle is handleRequest for one request; false ends the connection.
func (b *broker) handle(conn net.Conn, r *bufio.Reader, w *bufio.Writer, h *head) bool {
	// Expect is answered before anything else, as Node.js's server does for
	// HTTP/1.1: a 100 invites a body that is read only once the credential
	// is checked.
	if expect, ok := h.first("expect"); ok && !h.http10() {
		if !strings.EqualFold(strings.TrimSpace(expect), "100-continue") {
			// As Node.js answers it: the connection stays open when the
			// request has no body left to read.
			_, _ = conn.Write([]byte("HTTP/1.1 417 Expectation Failed\r\nDate: " + nodeDate() + "\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
			return h.framing == "none" || h.framing == "length" && h.length == 0
		}
		_, _ = conn.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))
	}
	if !b.checkProxyAuth(h) {
		_ = nodeReply(w, h.http10(), 407, []Pair{{"Proxy-Authenticate", "Basic"}, {"Connection", "close"}, {ReplyHeader, "refused"}}, "")
		return false
	}
	if h.target == TunnelsPath {
		if h.method != "GET" {
			deny(w, h, 405, TunnelsPath+" answers GET only", Pair{"Allow", "GET"})
			return false
		}
		b.mu.Lock()
		destinations := make([]string, 0, len(b.tunnels))
		for d := range b.tunnels {
			destinations = append(destinations, d)
		}
		slices.SortFunc(destinations, localeCompare)
		list := make([]any, len(destinations))
		for k, d := range destinations {
			list[k] = jsjson.Object{{Key: "destination", Value: d}, {Key: "count", Value: float64(b.tunnels[d])}}
		}
		b.mu.Unlock()
		_ = nodeReply(w, h.http10(), 200, []Pair{{"Content-Type", "application/json"}, {"Connection", "close"}}, string(jsjson.Stringify(jsjson.Object{{Key: "tunnels", Value: list}})))
		return false
	}
	// Proxy requests carry absolute URIs; origin-form has no destination.
	target, ok := whatwg.ParseURL(h.target)
	if !ok {
		deny(w, h, 400, "expected an absolute-URI proxy request")
		return false
	}
	if target.Protocol != "http:" && target.Protocol != "https:" {
		deny(w, h, 400, "unsupported scheme "+target.Protocol)
		return false
	}
	hostname, portText := splitHost(target.Host)
	host := canonicalHost(hostname)
	port := jsNumber(portText)
	if port == 0 {
		port = 80
		if target.Protocol == "https:" {
			port = 443
		}
	}
	allowed := MatchesSelectors(b.selectors, host, port)
	if !allowed && b.opts.Strict {
		deny(w, h, 403, "destination "+host+":"+jsjson.Number(port)+" blocked by --agent-network=strict")
		return false
	}
	// A declared length over the bound is refused before any byte is read.
	if h.framing == "length" && h.length > BodyLimit {
		deny(w, h, 413, "request body exceeds the "+strconv.Itoa(BodyLimit)+"-byte broker limit")
		return false
	}
	body, over, err := readBody(r, h, BodyLimit)
	if err != nil {
		_, _ = conn.Write([]byte(rawRefusal(err)))
		return false
	}
	if over {
		// A partly read (and possibly partly substituted) request is never
		// forwarded.
		deny(w, h, 413, "request body exceeds the "+strconv.Itoa(BodyLimit)+"-byte broker limit")
		return false
	}
	_ = conn.SetReadDeadline(time.Time{})
	path, query := target.RequestTarget()
	req := Request{Body: body}
	if target.Search != "" && target.Search != "?" {
		req.Query = &query
	}
	for _, p := range h.headers {
		if !slices.Contains(brokerOwned, strings.ToLower(p.Name)) {
			req.Headers = append(req.Headers, p)
		}
	}
	_, hadLength := h.first("content-length")
	out := forwardTo{b: b, conn: conn, w: w, h: h, target: target, host: hostname, dial: hostname + ":" + jsjson.Number(port), path: path}

	// Traffic to other destinations passes through unchanged, Placeholders inert.
	if !allowed {
		return out.pass(req, hadLength)
	}
	plan := PlanPlacement(req, b.opts.Placeholders, b.targets)
	if plan.Kind != "block" {
		for _, s := range plan.Strays {
			b.opts.Report(Event{Kind: "stray", Item: s.Item, Surface: s.Surface})
		}
	}
	switch plan.Kind {
	case "block":
		b.opts.Report(Event{Kind: "blocked", Status: plan.Status, Rule: plan.Rule, Message: plan.Message})
		deny(w, h, plan.Status, plan.Message)
		return false
	case "pass":
		return out.pass(req, hadLength)
	}
	if target.Protocol != "https:" {
		deny(w, h, 502, "secret substitution requires an HTTPS destination with verified TLS")
		return false
	}
	exercised, err := b.opts.Exercise(context.Background(), host, int(port), plan.Placements)
	if err != nil {
		if isMaintenance(err) {
			deny(w, h, 503, "the Varlatch installation is in maintenance (restore or upgrade); retry later", Pair{"Retry-After", "15"})
		} else {
			deny(w, h, 502, err.Error())
		}
		return false
	}
	// Exercised values live for this request and its response only.
	b.mu.Lock()
	b.held++
	b.mu.Unlock()
	defer func() {
		clear(exercised.Values)
		clear(exercised.Retiring)
		b.mu.Lock()
		b.held--
		b.mu.Unlock()
	}()
	built, err := b.check(plan, exercised)
	if err != nil {
		var ae afterExercise
		errors.As(err, &ae)
		b.opts.Report(Event{Kind: "failed", Rule: ae.rule, Message: ae.message})
		deny(w, h, 502, ae.message)
		return false
	}
	// The response is scrubbed of exactly the values exercised for it.
	var entries []matcher.SecretEntry
	for _, item := range sortedKeys(exercised.Values) {
		entries = append(entries, matcher.SecretEntry{Item: item, Value: exercised.Values[item]})
	}
	for _, item := range sortedKeys(exercised.Retiring) {
		entries = append(entries, matcher.SecretEntry{Item: item, Value: exercised.Retiring[item]})
	}
	scrubber := NewScrubber(entries, func(item string) []byte {
		if p, ok := b.placeholder[item]; ok {
			return p
		}
		return []byte("vlch_ph_v1_unknown")
	}, b.opts.Report)
	out.substituted(adjustForScrubbing(built), hadLength, scrubber)
	return false
}

// check is the checks after exercise, then apply.
func (b *broker) check(plan Plan, exercised Exercised) (Request, error) {
	if !SameTargets(exercised.Targets, b.opts.Targets) {
		return Request{}, afterExercise{"exercise-mismatch", "the exercise response carries different targets than the Capability was issued with"}
	}
	if len(exercised.Withheld) > 0 {
		withheld := slices.Clone(exercised.Withheld)
		slices.Sort(withheld)
		return Request{}, afterExercise{"missing-value", strings.Join(withheld, ", ") + ": no longer stored in this environment"}
	}
	placed := map[string]bool{}
	for _, p := range plan.Placements {
		placed[p.Item] = true
	}
	mismatch := len(exercised.Values) != len(placed)
	for item := range exercised.Values {
		mismatch = mismatch || !placed[item]
	}
	if mismatch {
		return Request{}, afterExercise{"exercise-mismatch", "the exercise response carries different items than the request places"}
	}
	applied := plan.Apply(exercised.Values)
	if !applied.OK {
		return Request{}, afterExercise{applied.Rule, applied.Message}
	}
	return Request{Headers: applied.Headers, Query: applied.Query, Body: applied.Body}, nil
}

// adjustForScrubbing is adjustForScrubbing: a substituted request asks for
// identity content and a whole representation (ADR-0039 Decision 16).
func adjustForScrubbing(r Request) Request {
	var headers []Pair
	for _, p := range r.Headers {
		switch strings.ToLower(p.Name) {
		case "accept-encoding", "range", "if-range":
		default:
			headers = append(headers, p)
		}
	}
	r.Headers = append(headers, Pair{"Accept-Encoding", "identity"})
	return r
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// splitHost is a URL's host as its hostname and port.
func splitHost(host string) (hostname, port string) {
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		hostname = host[:end+1]
		if rest := host[end+1:]; strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return hostname, port
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i], host[i+1:]
	}
	return host, ""
}

// forwardTo is forward: the Broker's own request upstream, opened only
// once the request is complete. The request's authority is the authorized
// URL's, never the caller's Host header.
type forwardTo struct {
	b      *broker
	conn   net.Conn
	w      *bufio.Writer
	h      *head
	target whatwg.URL
	host   string
	// dial is the authority the Broker connects to: the URL's host and the
	// port the allowance was checked against (its scheme's for none or 0).
	dial string
	path string
}

// request is the upstream request: headers in order as JavaScript strings
// (one character per byte; a character above U+00FF cannot be sent, as
// Node.js refuses it), Content-Length from the body sent.
func (f forwardTo) request(ctx context.Context, r Request, hadLength bool) (*http.Request, error) {
	u := &url.URL{Scheme: strings.TrimSuffix(f.target.Protocol, ":"), Host: f.dial, Opaque: f.path}
	if r.Query != nil {
		u.RawQuery = *r.Query
	}
	req, err := http.NewRequestWithContext(ctx, f.h.method, "", nil)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = f.target.Host
	req.Header = http.Header{}
	for _, p := range r.Headers {
		value, ok := latin1Bytes(p.Value)
		if !ok {
			return nil, errors.New(`Invalid character in header content ["` + p.Name + `"]`)
		}
		req.Header[p.Name] = append(req.Header[p.Name], string(value))
	}
	if len(r.Body) > 0 || hadLength {
		req.Body = io.NopCloser(strings.NewReader(string(r.Body)))
		req.ContentLength = int64(len(r.Body))
		if len(r.Body) == 0 {
			req.Body = http.NoBody
		}
	}
	return req, nil
}

// upstreamHeaders are a response's headers as JavaScript strings.
func upstreamHeaders(resp *http.Response) []Pair {
	var out []Pair
	for _, name := range sortedNames(resp.Header) {
		for _, v := range resp.Header[name] {
			out = append(out, Pair{name, latin1([]byte(v))})
		}
	}
	return out
}

func sortedNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// failure is an upstream failure's message, without the URL Go's client
// puts in it (a query may hold a substituted value).
func failure(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}

// pass forwards a request unchanged and relays the response as it comes.
func (f forwardTo) pass(r Request, hadLength bool) bool {
	req, err := f.request(context.Background(), r, hadLength)
	if err != nil {
		deny(f.w, f.h, 502, err.Error())
		return false
	}
	resp, err := f.b.transport.RoundTrip(req)
	if err != nil {
		deny(f.w, f.h, 502, failure(err))
		return false
	}
	defer resp.Body.Close()
	if strings.ContainsRune(resp.Status, '\r') {
		// A status line Node.js's client refuses never reaches the Agent.
		deny(f.w, f.h, 502, "Parse Error: Expected LF after CR")
		return false
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		deny(f.w, f.h, 502, "the destination switched protocols; the Broker relays HTTP only")
		return false
	}
	var headers []Pair
	for _, p := range upstreamHeaders(resp) {
		// The Broker's own marker is never relayed from a destination.
		if !strings.EqualFold(p.Name, ReplyHeader) && !slices.Contains(hopByHop, strings.ToLower(p.Name)) {
			headers = append(headers, Pair{strings.ToLower(p.Name), p.Value})
		}
	}
	// The destination's Connection: close ends the Agent's connection too, as
	// Node.js does with the header it relays.
	res := &agentResponse{w: f.w, http10: f.h.http10(), closeAfter: f.h.wantsClose() || resp.Close, aborted: func() { _ = f.conn.Close() }}
	length := resp.ContentLength
	if f.h.method == "HEAD" || resp.StatusCode == 204 || resp.StatusCode == 304 {
		length = -2
	}
	if err := res.WriteHead(resp.StatusCode, statusTextOf(resp.StatusCode), headers, length); err != nil {
		return false
	}
	if length == -2 {
		return res.End() == nil && !res.closeAfter
	}
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if res.Write(buf[:n]) != nil {
				return false
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			res.Abort()
			return false
		}
	}
	return res.End() == nil && !res.closeAfter
}

// substituted forwards a substituted request and relays its response
// through the scrubber; the Agent's connection ends after it.
func (f forwardTo) substituted(r Request, hadLength bool, s *Scrubber) {
	limits := f.b.opts.Limits
	idle := time.Duration(limits.IdleMillis) * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	// A substituted request's response is bounded by an idle timeout from
	// the moment the request is sent, headers included.
	cutoff := errCutoff{"no data from the destination for " + jsjson.Number(float64(limits.IdleMillis)/1000) + " seconds"}
	timer := time.AfterFunc(idle, func() { cancel(cutoff) })
	touch := func() { timer.Reset(idle) }
	stop := func() { timer.Stop() }
	// The Agent going away cancels the upstream request and discards held bytes.
	go func() {
		one := make([]byte, 1)
		for {
			if _, err := f.conn.Read(one); err != nil {
				cancel(errCutoff{"the Agent disconnected"})
				return
			}
		}
	}()
	req, err := f.request(ctx, r, hadLength)
	if err != nil {
		stop()
		deny(f.w, f.h, 502, s.mask(err.Error()))
		return
	}
	resp, err := f.b.transport.RoundTrip(req)
	if err != nil {
		stop()
		if cause := context.Cause(ctx); cause != nil {
			var cut errCutoff
			if errors.As(cause, &cut) {
				f.b.opts.Report(Event{Kind: "aborted", Reason: cut.message})
				deny(f.w, f.h, 502, cut.message)
				return
			}
		}
		deny(f.w, f.h, 502, s.mask(failure(err)))
		return
	}
	if strings.ContainsRune(resp.Status, '\r') {
		stop()
		resp.Body.Close()
		deny(f.w, f.h, 502, "Parse Error: Expected LF after CR")
		return
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// No protocol switch on a substituted request: the rest could not be scrubbed.
		stop()
		resp.Body.Close()
		message := "the destination switched protocols; not relayed on a substituted request"
		f.b.opts.Report(Event{Kind: "aborted", Reason: message})
		deny(f.w, f.h, 502, message)
		return
	}
	touch()
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	res := &agentResponse{w: f.w, http10: f.h.http10(), closeAfter: true, aborted: func() { _ = f.conn.Close() }}
	body := &causeReader{r: resp.Body, ctx: ctx}
	up := Upstream{Status: resp.StatusCode, Reason: latin1([]byte(reason)), Headers: upstreamHeaders(resp), Body: body}
	if err := Relay(f.h.method, up, res, s, limits, touch, stop, f.b.opts.Report); err != nil {
		var before errBeforeHeaders
		if errors.As(err, &before) {
			f.b.opts.Report(Event{Kind: "aborted", Reason: before.message})
			deny(f.w, f.h, 502, before.message)
		}
	}
}

// causeReader reads a body, its error the cause its context was cancelled
// with (the idle cutoff, the Agent going away) when it was.
type causeReader struct {
	r   io.ReadCloser
	ctx context.Context
}

func (c *causeReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && err != io.EOF {
		if cause := context.Cause(c.ctx); cause != nil {
			return n, cause
		}
	}
	return n, err
}

func (c *causeReader) Close() error { return c.r.Close() }

// mask is a message with every exercised value replaced, for a failure
// whose text the Broker does not write itself.
func (s *Scrubber) mask(message string) string {
	masked, err := s.HeaderValue(message)
	if err != nil {
		return "the request could not be sent"
	}
	return masked
}

func statusTextOf(code int) string {
	if t, ok := statusText[code]; ok {
		return t
	}
	return http.StatusText(code)
}
