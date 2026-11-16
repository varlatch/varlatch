// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"syscall"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// AccessStatus is an access check's outcome (ADR-0031, amendment
// 2026-10-09).
type AccessStatus string

const (
	StatusOK                 AccessStatus = "ok"
	StatusCredentialRejected AccessStatus = "credential-rejected"
	StatusPermissionMissing  AccessStatus = "permission-missing"
	StatusNotFound           AccessStatus = "not-found"
	StatusUnreachable        AccessStatus = "unreachable"
	StatusFailed             AccessStatus = "failed"
)

// Where is what an outcome is about.
type Where string

const (
	WhereConnection  Where = "connection"
	WhereDestination Where = "destination"
)

// AccessCheck is a read-only access check's outcome.
type AccessCheck struct {
	Status AccessStatus
	Where  Where
	// Message is one sentence for the person who fixes it, written by
	// Varlatch: never platform text, a value or credential material.
	Message string
	// HTTPStatus is the platform's HTTP status when it answered, else 0.
	HTTPStatus int
	// CredentialExpiresAt is when the credential expires, if the platform
	// said (ISO 8601), else "".
	CredentialExpiresAt string
}

// MarshalJSON writes the check as the TypeScript objects are built:
// status, where, httpStatus, message, credentialExpiresAt.
func (c AccessCheck) MarshalJSON() ([]byte, error) {
	return stringify(c.object()), nil
}

func (c AccessCheck) object() Object {
	o := Object{{"status", string(c.Status)}, {"where", string(c.Where)}}
	if c.HTTPStatus != 0 {
		o = append(o, Member{"httpStatus", float64(c.HTTPStatus)})
	}
	o = append(o, Member{"message", c.Message})
	if c.CredentialExpiresAt != "" {
		o = append(o, Member{"credentialExpiresAt", c.CredentialExpiresAt})
	}
	return o
}

// DestinationOption is one destination a credential can see, as a picker
// offers it.
type DestinationOption struct {
	Destination Fields
	// Label is the repository or application name.
	Label string
	// Detail is a second line, "" for none.
	Detail string
}

// DestinationListing is what a credential can see on its base identity.
// Check is ok when the listing ran; otherwise it says why not, and Items
// is empty.
type DestinationListing struct {
	Check AccessCheck
	Items []DestinationOption
	// Truncated is true when the adapter stopped reading, so more may exist.
	Truncated bool
}

// MarshalJSON writes the listing as the TypeScript object is built.
func (l DestinationListing) MarshalJSON() ([]byte, error) {
	items := make([]any, len(l.Items))
	for i, it := range l.Items {
		o := Object{{"destination", it.Destination.object()}, {"label", it.Label}}
		if it.Detail != "" {
			o = append(o, Member{"detail", it.Detail})
		}
		items[i] = o
	}
	return stringify(Object{{"check", l.Check.object()}, {"items", items}, {"truncated", l.Truncated}}), nil
}

func (f Fields) object() Object {
	o := make(Object, len(f))
	for i, x := range f {
		o[i] = Member{x.Key, x.Value}
	}
	return o
}

// MaxDestinations is how many destinations a listing reads at most.
const MaxDestinations = 1000

func listingFailed(c AccessCheck) DestinationListing {
	return DestinationListing{Check: c, Items: []DestinationOption{}}
}

// shortText is a platform-supplied name, trimmed and bounded to max UTF-16
// code units; "" when it is not a non-empty string.
func shortText(v any, max int) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return sliceUnits(whatwg.Trim(s), max)
}

// sliceUnits is s.slice(0, max): a surrogate pair cut in two leaves its
// high half, in WTF-8.
func sliceUnits(s string, max int) string {
	n := 0
	for i := 0; i < len(s); {
		if _, ok := surrogateAt(s, i); ok {
			if n+1 > max {
				return s[:i]
			}
			n++
			i += 3
			continue
		}
		r, size := decodeRune(s[i:])
		units := 1
		if r >= 0x10000 {
			units = 2
		}
		if n+units > max {
			if units == 2 && n+1 == max {
				hi, _ := utf16.EncodeRune(r)
				return string(appendWTF8([]byte(s[:i]), hi))
			}
			return s[:i]
		}
		n += units
		i += size
	}
	return s
}

// OutboundRefusedCode is the code of the error a host's outbound policy
// raises when it refuses a destination (varlatchd, ADR-0057).
const OutboundRefusedCode = "VARLATCH_OUTBOUND_REFUSED"

// PolicyRefusal is the outbound policy's refusal behind err: an error in
// its chain with Code() == OutboundRefusedCode, whose Error() is the
// host's own fixed wording. ok is false when there is none.
func PolicyRefusal(err error) (message string, ok bool) {
	var coded interface{ Code() string }
	for e := err; e != nil; {
		if !errors.As(e, &coded) {
			return "", false
		}
		if coded.Code() == OutboundRefusedCode {
			return coded.(error).Error(), true
		}
		e = errors.Unwrap(coded.(error))
	}
	return "", false
}

// errRedirect is the client's refusal to follow a redirect.
var errRedirect = errors.New("unexpected redirect")

type problem int

const (
	problemNone problem = iota
	problemTimeout
	problemRedirect
	problemDNS
	problemRefused
	problemTLS
	problemPolicy
)

// transportProblem is the transport problem behind an adapter's request
// error.
func transportProblem(err error) problem {
	ae, ok := err.(*AdapterError)
	if !ok {
		return problemNone
	}
	if _, ok := PolicyRefusal(err); ok {
		return problemPolicy
	}
	if ae.Message == "TimeoutError" {
		return problemTimeout
	}
	cause := ae.Cause
	if cause == nil {
		return problemNone
	}
	var dns *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	switch {
	case errors.Is(cause, errRedirect):
		return problemRedirect
	case errors.As(cause, &dns):
		return problemDNS
	case errors.Is(cause, syscall.ECONNREFUSED):
		return problemRefused
	case errors.As(cause, &unknownCA), errors.As(cause, &invalid), errors.As(cause, &hostname),
		errors.As(cause, &verify), errors.As(cause, &record), errors.As(cause, &alert):
		return problemTLS
	}
	return problemNone
}

// unreachable is a request that never got an answer: DNS, TLS, a refused
// redirect, a timeout, or the host's outbound policy (in the host's words).
func unreachable(host string, err error, where Where) AccessCheck {
	p := transportProblem(err)
	if p == problemPolicy {
		message, _ := PolicyRefusal(err)
		return AccessCheck{Status: StatusUnreachable, Where: where, Message: message}
	}
	message := "Varlatch could not reach " + host + ". Check the address, and that this server can reach it."
	switch p {
	case problemTimeout:
		message = host + " did not answer in time. Try again in a moment."
	case problemRedirect:
		message = host + " answered with a redirect, which Varlatch does not follow. Enter the address it leads to, or let Varlatch past a sign-in page in front of it."
	case problemDNS:
		message = "No address was found for " + host + ". Check the spelling, and that this server can resolve it."
	case problemRefused:
		message = host + " refused the connection. Check the address and port."
	case problemTLS:
		message = "This server does not trust the certificate of " + host + ": it is self-signed, expired, or made for another name."
	}
	return AccessCheck{Status: StatusUnreachable, Where: where, Message: message}
}

// unexpected is an answer the adapter has no specific reading for.
func unexpected(platform string, status int, where Where) AccessCheck {
	if status == 429 {
		return AccessCheck{Status: StatusUnreachable, Where: where, HTTPStatus: status,
			Message: platform + " is limiting requests right now. Try again in a few minutes."}
	}
	if status >= 500 {
		return AccessCheck{Status: StatusUnreachable, Where: where, HTTPStatus: status,
			Message: platform + " answered with a server error (HTTP " + strconv.Itoa(status) + "). Try again later."}
	}
	return AccessCheck{Status: StatusFailed, Where: where, HTTPStatus: status,
		Message: platform + " refused the request (HTTP " + strconv.Itoa(status) + ")."}
}

// foreign is an answer at a user-supplied base address that is not the
// platform's API.
func foreign(platform, kind, host string, status int) AccessCheck {
	if status == 429 || status >= 500 {
		return unexpected(platform, status, WhereConnection)
	}
	return AccessCheck{Status: StatusFailed, Where: WhereConnection, HTTPStatus: status,
		Message: host + " does not answer like a " + platform + " " + kind + " (HTTP " + strconv.Itoa(status) + "). Check the address."}
}

// transportName is the name of the error fetch would have rejected with,
// which the TypeScript adapters put in their AdapterError's message.
func transportName(parent context.Context, err error) string {
	if _, ok := PolicyRefusal(err); ok {
		return "OutboundRefusedError"
	}
	if parent.Err() != nil {
		return "AbortError"
	}
	var timeout interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "TimeoutError"
	}
	return "TypeError"
}
