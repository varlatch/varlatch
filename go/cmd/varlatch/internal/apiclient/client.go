// SPDX-License-Identifier: Apache-2.0

// Package apiclient is the Go CLI's client of varlatchd's /v1 API (ADR-0059
// step 5; internal docs/design/go-cli.md, slice 5.1c): a port of the client
// half of packages/sdk (VarlatchClient). It sends the same requests in the
// same order as the TypeScript CLI (method, path and query, Authorization,
// User-Agent, Content-Type, Accept, Idempotency-Key, bodies equal as JSON),
// rides out an installation's maintenance window as the SDK does, and hands
// back what the server answered as a lib/jsjson value, so whatever the CLI
// prints from it is what JavaScript would print (decision 2).
package apiclient

import (
	"context"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Undefined is an answer with no body (204, or an empty one): JavaScript's
// undefined, which is not null.
var Undefined any = undefined{}

type undefined struct{}

// ApprovalHeader carries an approved step-up approval's id with the request
// it approves (ADR-0054 Decision 3).
const ApprovalHeader = "Varlatch-Approval"

// CredentialExpiresHeader names the presenting machine credential's expiry
// in its last 7 days (ADR-0054 Decision 8).
const CredentialExpiresHeader = "Varlatch-Credential-Expires"

// DefaultMaintenanceRetry is how long a client rides out 503 MAINTENANCE
// answers (ADR-0036 D6), the SDK's default.
const DefaultMaintenanceRetry = 180 * time.Second

// MaintenanceWait is one wait of the maintenance retry: how long it lasts,
// and what remains of the client's budget after it.
type MaintenanceWait struct {
	RetryIn   time.Duration
	Remaining time.Duration
}

// Options are VarlatchClientOptions.
type Options struct {
	// Server is the server's URL; trailing slashes are removed.
	Server string
	// Token is the bearer credential, "" for none.
	Token string
	// UserAgent is sent on every request when not "".
	UserAgent string
	// MaintenanceRetry is the client's budget for riding out maintenance;
	// nil is DefaultMaintenanceRetry, and 0 disables the retry.
	MaintenanceRetry *time.Duration
	// OnMaintenance is called before each maintenance wait.
	OnMaintenance func(MaintenanceWait)
	// OnCredentialExpires is called with the Varlatch-Credential-Expires
	// header's value whenever an answer carries it, before the answer is
	// read.
	OnCredentialExpires func(expiresAt string)
	// OnStepUp handles STEP_UP_REQUIRED (ADR-0054 Decision 3; the CLI's
	// handler is approvals.go's): true once the person approved, and the
	// client repeats the request once with the approval.
	OnStepUp func(approval any) (bool, error)
	// Approval is sent as the Varlatch-Approval header with every request
	// that is not a GET (`--approval <id>`).
	Approval string
	// Ready is called with each request's method before it is sent (the
	// CLI's resuming fetch: before the first change request it waits for
	// the approval); an error is the request's.
	Ready func(method string) error
	// Env is where the transport reads NODE_EXTRA_CA_CERTS.
	Env Env
	// For tests: the clock, the wait, and Math.random.
	Now    func() time.Time
	Sleep  func(time.Duration)
	Random func() float64
}

// Client is VarlatchClient.
type Client struct {
	server            string
	opts              Options
	transport         *Transport
	maintenanceBudget time.Duration
	// maintenanceDeadline is the SDK's one budget for the client, shared
	// by requests in flight together (the MCP server's tool calls), so it
	// is read and written under deadlineMu.
	deadlineMu          sync.Mutex
	maintenanceDeadline *time.Time
}

// New is `new VarlatchClient(options)`.
func New(opts Options) *Client {
	c := &Client{server: strings.TrimRight(opts.Server, "/"), opts: opts, transport: NewTransport(opts.Env), maintenanceBudget: DefaultMaintenanceRetry}
	if opts.MaintenanceRetry != nil {
		c.maintenanceBudget = *opts.MaintenanceRetry
	}
	if c.opts.Now == nil {
		c.opts.Now = time.Now
	}
	if c.opts.Sleep == nil {
		c.opts.Sleep = time.Sleep
	}
	if c.opts.Random == nil {
		c.opts.Random = rand.Float64
	}
	return c
}

// Server is the server's URL without trailing slashes.
func (c *Client) Server() string { return c.server }

// Header is one extra request header.
type Header struct{ Name, Value string }

// IdempotencyKey is the header that makes a write safe to repeat; the SDK
// sends it where its caller gives one (the TypeScript CLI gives none).
func IdempotencyKey(key string) []Header {
	if key == "" {
		return nil
	}
	return []Header{{"Idempotency-Key", key}}
}

// NoBody is a request without a body (undefined in the SDK).
var NoBody any = Undefined

// Request is the SDK's request(): body is a JSON value (NoBody for none),
// and the answer comes back as a JSON value (Undefined for none).
func (c *Client) Request(ctx context.Context, method, path string, body any, headers []Header) (any, error) {
	sent := headers
	if c.opts.Approval != "" && method != "GET" && !hasHeader(headers, ApprovalHeader) {
		sent = append(append([]Header(nil), headers...), Header{ApprovalHeader, c.opts.Approval})
	}
	v, err := c.requestApproved(ctx, method, path, body, sent)
	if err == nil {
		return v, nil
	}
	approval := StepUpApproval(err)
	if approval == nil || c.opts.OnStepUp == nil || hasHeader(sent, ApprovalHeader) {
		return nil, err
	}
	approved, hErr := c.opts.OnStepUp(approval)
	if hErr != nil {
		return nil, hErr
	}
	if !approved {
		return nil, err
	}
	id, _ := jsval.Get(approval, "id")
	return c.requestApproved(ctx, method, path, body, append(append([]Header(nil), sent...), Header{ApprovalHeader, id.(string)}))
}

func hasHeader(headers []Header, name string) bool {
	for _, h := range headers {
		if h.Name == name {
			return true
		}
	}
	return false
}

// StepUpApproval is the pending approval a STEP_UP_REQUIRED error carries
// (details.approval, with a string id), or nil.
func StepUpApproval(err error) any {
	e, ok := err.(*APIError)
	if !ok || !e.CodeIs("STEP_UP_REQUIRED") {
		return nil
	}
	approval, ok := get(e.Details, "approval")
	if !ok || approval == nil {
		return nil
	}
	if id, ok := get(approval, "id"); !ok {
		return nil
	} else if _, isString := id.(string); !isString {
		return nil
	}
	return approval
}

// requestApproved repeats a request carrying an approval whose read the
// server found stale (STATE_CHANGED, reason stale-capture; ADR-0054
// amendment C) at most twice.
func (c *Client) requestApproved(ctx context.Context, method, path string, body any, headers []Header) (any, error) {
	for repeats := 0; ; repeats++ {
		v, err := c.requestRiding(ctx, method, path, body, headers)
		if err == nil {
			return v, nil
		}
		e, ok := err.(*APIError)
		stale := ok && e.CodeIs("STATE_CHANGED")
		if stale {
			reason, _ := get(e.Details, "reason")
			stale = reason == "stale-capture"
		}
		if !stale || !hasHeader(headers, ApprovalHeader) || repeats >= 2 {
			return nil, err
		}
	}
}

// requestRiding rides out an installation's maintenance (ADR-0036 D6): a
// 503 whose body's error code is MAINTENANCE is retried after its
// Retry-After (with ±20% jitter), within the client's budget, which starts
// at the first such answer and resets once the server answers otherwise.
func (c *Client) requestRiding(ctx context.Context, method, path string, body any, headers []Header) (any, error) {
	for {
		res, err := c.requestOnce(ctx, method, path, body, headers)
		if err != nil {
			return nil, err
		}
		if res.Status != 503 {
			c.deadlineMu.Lock()
			c.maintenanceDeadline = nil
			c.deadlineMu.Unlock()
			return finish(res)
		}
		if !isMaintenance(res) {
			return finish(res)
		}
		c.deadlineMu.Lock()
		if c.maintenanceDeadline == nil {
			d := c.opts.Now().Add(c.maintenanceBudget)
			c.maintenanceDeadline = &d
		}
		deadline := *c.maintenanceDeadline
		c.deadlineMu.Unlock()
		remaining := ms(deadline.Sub(c.opts.Now()))
		if remaining <= 0 {
			return finish(res)
		}
		value, present := res.Header("Retry-After")
		after := 0.0 // Number(null) is 0
		valid := true
		if present {
			after, valid = jsval.ToNumber(jsval.UTF16(value))
		}
		base := 5.0
		if valid && !math.IsInf(after, 0) && after >= 0 {
			base = after
		}
		base *= 1000
		retryIn := min(jsRound(base*(0.8+0.4*c.opts.Random())), remaining)
		if c.opts.OnMaintenance != nil {
			c.opts.OnMaintenance(MaintenanceWait{RetryIn: fromMS(retryIn), Remaining: fromMS(remaining - retryIn)})
		}
		c.opts.Sleep(fromMS(retryIn))
	}
}

// ms is a duration in whole milliseconds, as Date.now() differences are.
func ms(d time.Duration) float64 { return float64(d.Milliseconds()) }

func fromMS(x float64) time.Duration { return time.Duration(x * float64(time.Millisecond)) }

// jsRound is Math.round: halves round up.
func jsRound(x float64) float64 { return math.Floor(x + 0.5) }

// isMaintenance is `(await res.clone().json().catch(() => undefined))?.error?.code === "MAINTENANCE"`.
func isMaintenance(res *Response) bool {
	if res.BodyErr != nil {
		return false
	}
	parsed, err := jsjson.Parse([]byte(decodeBody(res.Body)))
	if err != nil {
		return false
	}
	e, ok := get(parsed, "error")
	if !ok || e == nil {
		return false
	}
	code, _ := get(e, "code")
	return code == "MAINTENANCE"
}

// requestOnce sends one request: Authorization when there is a token,
// User-Agent when there is one, Content-Type for a body, then the extra
// headers (which replace those of the same name).
func (c *Client) requestOnce(ctx context.Context, method, path string, body any, headers []Header) (*Response, error) {
	if c.opts.Ready != nil {
		if err := c.opts.Ready(method); err != nil {
			return nil, err
		}
	}
	var list [][2]string
	if c.opts.Token != "" {
		list = append(list, [2]string{"Authorization", "Bearer " + c.opts.Token})
	}
	if c.opts.UserAgent != "" {
		list = append(list, [2]string{"User-Agent", c.opts.UserAgent})
	}
	var payload []byte
	if body != Undefined {
		list = append(list, [2]string{"Content-Type", "application/json"})
		payload = jsjson.Stringify(body)
	}
	for _, h := range headers {
		list = append(list, [2]string{h.Name, h.Value})
	}
	for i, h := range list {
		value, err := headerValue(h[0], h[1])
		if err != nil {
			return nil, err
		}
		list[i][1] = value
	}
	res, err := c.transport.Do(ctx, Request{Method: method, URL: c.server + path, Headers: list, Body: payload})
	if err != nil {
		return nil, err
	}
	if c.opts.OnCredentialExpires != nil {
		if expiresAt, ok := res.Header(CredentialExpiresHeader); ok && expiresAt != "" {
			c.opts.OnCredentialExpires(expiresAt)
		}
	}
	return res, nil
}

// headerValue is a header value as fetch's Headers takes it: a ByteString
// (every UTF-16 unit at most 255, sent as that byte), its leading and
// trailing HTTP whitespace removed, and no NUL, CR or LF left in it. A
// value fetch refuses is refused here before anything is sent, but the
// message names the header and never shows its value: diagnostics never
// print credential values, and Authorization holds one (go/README.md, the
// Go CLI's accepted differences).
func headerValue(name, value string) (string, error) {
	units := jsval.UTF16(value)
	b := make([]byte, 0, len(units))
	for _, u := range units {
		if u > 255 {
			return "", refusedHeader(name)
		}
		b = append(b, byte(u))
	}
	trimmed := strings.Trim(string(b), " \t\r\n")
	if strings.ContainsAny(trimmed, "\x00\r\n") {
		return "", refusedHeader(name)
	}
	return trimmed, nil
}

// refusedHeader is the error for a header value fetch refuses: a TypeError
// before any request, which is not a network failure.
func refusedHeader(name string) *FetchError {
	if strings.EqualFold(name, "Authorization") {
		return &FetchError{Message: "the credential contains a character that is not allowed in an HTTP header"}
	}
	return &FetchError{Message: "the " + name + " header contains a character that is not allowed in an HTTP header"}
}

// decodeBody is Response.text(): UTF-8 decoded, a leading byte order mark
// removed, malformed bytes as U+FFFD.
func decodeBody(b []byte) string {
	return jsval.DecodeUTF8([]byte(strings.TrimPrefix(string(b), "\xef\xbb\xbf")))
}

// finish is the SDK's finish(): 204 is undefined; an answer that is not OK
// becomes an APIError (its own error when the body is a Varlatch API error,
// else a fallback that never echoes the body); an OK answer that is not
// JSON too.
func finish(res *Response) (any, error) {
	if res.Status == 204 {
		return Undefined, nil
	}
	if res.BodyErr != nil {
		return nil, res.BodyErr
	}
	text := decodeBody(res.Body)
	var parsed any = Undefined
	isJSON := true
	if text != "" {
		v, err := jsjson.Parse([]byte(text))
		if err != nil {
			isJSON = false
		} else {
			parsed = v
		}
	}
	fallback := func(message string) *APIError {
		requestID, ok := res.Header("X-Request-Id")
		if !ok {
			requestID = "unknown"
		}
		return &APIError{Status: res.Status, Code: "INTERNAL", Message: message, RequestID: requestID, Details: Undefined}
	}
	if res.Status < 200 || res.Status > 299 {
		if isJSON {
			if e, ok := get(parsed, "error"); ok && jsjson.Truthy(e) {
				return nil, newAPIError(res.Status, e)
			}
			return nil, fallback("HTTP " + strconv.Itoa(res.Status))
		}
		return nil, fallback("HTTP " + strconv.Itoa(res.Status) + "; the response is not a Varlatch API error (" + contentType(res) + ")")
	}
	if !isJSON {
		return nil, fallback("HTTP " + strconv.Itoa(res.Status) + "; the response is not JSON (" + contentType(res) + ")")
	}
	return parsed, nil
}

// contentType is a response's media type for a diagnostic, without
// parameters.
func contentType(res *Response) string {
	value, _ := res.Header("Content-Type")
	media, _, _ := strings.Cut(value, ";")
	if t := jsTrim(media); t != "" {
		return t
	}
	return "no content type"
}

// jsTrim is String.prototype.trim.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
			return true
		}
		return r >= 0x2000 && r <= 0x200a
	})
}

// get is v?.[key] for any JSON value, Undefined included.
func get(v any, key string) (any, bool) {
	if v == nil || v == Undefined {
		return nil, false
	}
	return jsval.Get(v, key)
}

// HeaderRefused is the SDK's refusedHeader: whether fetch would refuse the
// header value (not a ByteString, or a NUL, CR or LF in it).
func HeaderRefused(name, value string) bool {
	_, err := headerValue(name, value)
	return err != nil
}
