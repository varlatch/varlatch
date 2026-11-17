// SPDX-License-Identifier: Apache-2.0

package apiclient

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// APIError is the SDK's VarlatchApiError: an error answer from the server,
// or an answer the client could not read as one (a proxy's HTML page, a
// body that is not JSON). Code, RequestID and Details are the answer's
// values as JavaScript holds them (a server may send any JSON there, or
// none: Undefined), and Message is what `new Error(body.message)` makes of
// its message.
type APIError struct {
	Status    int
	Code      any
	Message   string
	RequestID any
	Details   any
}

func (e *APIError) Error() string { return e.Message }

// CodeIs is err.code === code.
func (e *APIError) CodeIs(code string) bool {
	s, ok := e.Code.(string)
	return ok && s == code
}

// newAPIError is `new VarlatchApiError(status, body)` for a body that is
// any JSON value the answer's "error" held.
func newAPIError(status int, body any) *APIError {
	field := func(key string) any {
		if v, ok := get(body, key); ok {
			return v
		}
		return Undefined
	}
	e := &APIError{Status: status, Code: field("code"), RequestID: field("requestId"), Details: field("details")}
	if message, ok := get(body, "message"); ok {
		e.Message = jsjson.String(message) // Error's ToString of a message that is not undefined
	}
	return e
}

// FetchError is the TypeError fetch rejects with. Message is its text:
// "fetch failed" when the request never reached the server, or fetch's own
// refusal of the request ("Failed to parse URL from ..."). Code is
// exitCodes.ts's networkFailure: the network error's code ("ECONNREFUSED",
// "ENOTFOUND", ...) or "network error" for a request that never reached the
// server, "" for a refusal (which the TypeScript CLI lets escape).
type FetchError struct {
	Message string
	Code    string
	Cause   error
}

func (e *FetchError) Error() string { return e.Message }
func (e *FetchError) Unwrap() error { return e.Cause }

func fetchFailed(code string, cause error) *FetchError {
	return &FetchError{Message: "fetch failed", Code: code, Cause: cause}
}

// BodyError is the TypeError reading an answer's body rejects with when
// the connection ends before the body does: "terminated". It is not a
// network failure to exitCodes.ts (its message is not "fetch failed").
type BodyError struct{ Message string }

func (e *BodyError) Error() string { return e.Message }

// NetworkFailure is exitCodes.ts's networkFailure: the code when err is a
// request that never reached the server, "" for anything else.
func NetworkFailure(err error) string {
	var f *FetchError
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// networkCode is the code Node.js would give the error that kept a
// request from reaching the server.
func networkCode(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		switch {
		case dns.IsNotFound:
			return "ENOTFOUND"
		case dns.IsTemporary, dns.IsTimeout:
			return "EAI_AGAIN"
		}
		return "ENOTFOUND"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" && op.Timeout() {
		return "UND_ERR_CONNECT_TIMEOUT"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		if op != nil && op.Op == "dial" {
			return "UND_ERR_CONNECT_TIMEOUT"
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if code, ok := errnoCode(errno); ok {
			return code
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		// The server closed the connection before answering: undici's
		// SocketError, "other side closed".
		return "UND_ERR_SOCKET"
	}
	if isTLSHandshakeTimeout(err) {
		return "UND_ERR_CONNECT_TIMEOUT"
	}
	return "network error"
}

// isTLSHandshakeTimeout: undici's connect timeout covers the handshake.
func isTLSHandshakeTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	var t timeout
	return errors.As(err, &t) && t.Timeout() && strings.Contains(err.Error(), "TLS handshake timeout")
}
