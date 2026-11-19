// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Output that comes from a server, made safe to print (ADR-0058 Decision 2),
// a port of apps/cli/src/safeText.ts: an error code only when the protocol
// defines it, text with every control character escaped, fields with a
// known shape only when they have it, and free text with every credential
// and value this CLI knows of masked (issue #119).

// ErrorCodes are packages/protocol's ERROR_CODES, in its order.
var ErrorCodes = []string{
	"AUTHENTICATION_REQUIRED", "INVALID_CREDENTIAL", "PERMISSION_DENIED", "RESOURCE_NOT_FOUND", "VALIDATION_FAILED",
	"VERSION_CONFLICT", "ROTATION_IN_PROGRESS", "IDEMPOTENCY_CONFLICT", "CONTRACT_INVALID", "CONTRACT_DRIFT",
	"CONTRACT_MAPPING_UNRESOLVED", "ENVIRONMENT_EXPIRED", "TAILNET_CONTEXT_REQUIRED", "TAILNET_CONTEXT_UNAVAILABLE",
	"RATE_LIMITED", "MAINTENANCE", "INTERNAL", "STATE_CHANGED", "AUTHORIZATION_PENDING", "SLOW_DOWN", "ACCESS_DENIED",
	"EXPIRED", "CONSUMED", "ORGANIZATION_DELETING", "ORGANIZATION_DELETED", "STEP_UP_REQUIRED", "APPROVAL_INVALID",
	"CONTROL_MODE_UNAVAILABLE", "CREDENTIAL_LIFETIME_EXCEEDED", "ORGANIZATION_FROZEN", "PASSKEY_VERIFICATION_REQUIRED",
}

// SafeAPICode is an API error's code when the protocol defines it, a fixed
// word otherwise.
func SafeAPICode(code string) string {
	if slices.Contains(ErrorCodes, code) {
		return code
	}
	return "UNRECOGNIZED_ERROR"
}

// Printable escapes C0, DEL and C1 controls and the bidirectional
// overrides and isolates as \uXXXX.
func Printable(text string) string {
	var b strings.Builder
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteByte(text[i]) // a lone surrogate's WTF-8, or a byte that is not UTF-8: kept
			i++
			continue
		}
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.WriteString(text[i : i+size])
		}
		i += size
	}
	return b.String()
}

// The fixed phrases said in place of a field that does not have its shape.
const (
	UnrecognizedTime    = "an unrecognized time"
	UnrecognizedVersion = "an unrecognized version"
)

var isoTime = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(?:Z|([+-])(\d{2}):(\d{2}))$`)

// SafeTime is safeText.ts's safeTime for a string: the timestamp normalized
// as new Date(value).toISOString() does, or UnrecognizedTime. Callers keep
// their own words for a missing one (null), as TypeScript callers do.
func SafeTime(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	s, ok := value.(string)
	if !ok {
		return UnrecognizedTime, true
	}
	m := isoTime.FindStringSubmatch(s)
	if m == nil {
		return UnrecognizedTime, true
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	year, month, day, hour, minute := n(1), n(2), n(3), n(4), n(5)
	second, ms := 0, 0
	if m[6] != "" {
		second = n(6)
	}
	if m[7] != "" {
		ms, _ = strconv.Atoi((m[7] + "00")[:3]) // V8 keeps milliseconds and drops further digits
	}
	// V8's ISO date parser: a day of 1 to 31 in any month (an overflow rolls
	// into the next month), hour 24 only at midnight exactly, no leap second.
	if month < 1 || month > 12 || day < 1 || day > 31 || minute > 59 || second > 59 {
		return UnrecognizedTime, true
	}
	// Hour 24 needs the whole fraction zero, every digit V8 read, not just
	// the milliseconds it keeps: 24:00:00.0001 is refused.
	if hour > 24 || hour == 24 && (minute != 0 || second != 0 || strings.Trim(m[7], "0") != "") {
		return UnrecognizedTime, true
	}
	offset := 0
	if m[8] != "" {
		oh, om := n(9), n(10)
		if oh > 23 || om > 59 {
			return UnrecognizedTime, true
		}
		offset = oh*60 + om
		if m[8] == "-" {
			offset = -offset
		}
	}
	t := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).
		AddDate(0, 0, day-1).
		Add(time.Duration(hour)*time.Hour + time.Duration(minute-offset)*time.Minute + time.Duration(second)*time.Second + time.Duration(ms)*time.Millisecond)
	return isoString(t), true
}

// isoString is Date.prototype.toISOString: a six-digit signed year outside 0 to 9999.
func isoString(t time.Time) string {
	y := t.Year()
	var year string
	switch {
	case y >= 0 && y <= 9999:
		year = fmt.Sprintf("%04d", y)
	case y < 0:
		year = fmt.Sprintf("-%06d", -y)
	default:
		year = fmt.Sprintf("+%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1e6)
}

// semver.org's pattern, anchored.
var semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// SafeVersion is a server's version when it is a semantic version of at
// most 64 characters holding nothing this CLI knows as secret,
// UnrecognizedVersion otherwise; false when it is missing.
func (s *Secrets) SafeVersion(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	v, ok := value.(string)
	if !ok || utf16Len(v) > 64 || !semver.MatchString(v) || s.Mask(v) != v {
		return UnrecognizedVersion, true
	}
	return v, true
}

// SafeAPIMajor is the API major version when it is a whole number from 0 to 999.
func SafeAPIMajor(value any) (int, bool) {
	f, ok := value.(float64)
	if !ok || math.IsNaN(f) || f != math.Trunc(f) || f < 0 || f >= 1000 {
		return 0, false
	}
	return int(f), true
}

// The request id varlatchd generates (services/varlatchd/src/http/support.ts).
var requestID = regexp.MustCompile(`^req_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SafeRequestID is the request id when it has the server's format.
func (s *Secrets) SafeRequestID(value any) (string, bool) {
	v, ok := value.(string)
	if !ok || !requestID.MatchString(v) || s.Mask(v) != v {
		return "", false
	}
	return v, true
}

// MinMaskedLength: shorter strings are not masked; they would match ordinary words.
const MinMaskedLength = 8

// Redacted is shown in place of a masked secret.
const Redacted = "[redacted]"

// Secrets is the secret material a run holds, for masking a server's free
// text: what it registered (the bearer of each request, every value and key
// it sends), VARLATCH_TOKEN, and the stored credentials. Never printed,
// written or sent anywhere.
type Secrets struct {
	known []string
	// Token is VARLATCH_TOKEN's value, "" when unset.
	Token string
	// Stored lists the stored credentials' tokens; nil until the credential
	// store is read (slice 5.1b), and an unreadable store adds nothing.
	Stored func() []string
}

// Remember registers a credential or value the run uses or sends.
func (s *Secrets) Remember(value string) {
	if utf16Len(value) >= MinMaskedLength && !slices.Contains(s.known, value) {
		s.known = append(s.known, value)
	}
}

// Varlatch's own token formats, `vlt_<kind>_<random>`.
var varlatchToken = regexp.MustCompile(`vlt_[a-z]+_[A-Za-z0-9_-]+`)

// Mask is safeText.ts's maskSecrets: every exact occurrence of a secret the
// run knows replaced by Redacted, longest first, and anything in a
// Varlatch token format too.
func (s *Secrets) Mask(text string) string {
	return varlatchToken.ReplaceAllLiteralString(s.maskHeld(text), Redacted)
}

// maskHeld is Mask without the token formats: every exact occurrence of a
// secret the run knows (registered, VARLATCH_TOKEN, a stored credential)
// replaced by Redacted, longest first. maskHeld(text) == text says text
// holds none of them.
func (s *Secrets) maskHeld(text string) string {
	all := slices.Clone(s.known)
	held := []string{}
	if s.Token != "" {
		held = append(held, s.Token)
	}
	if s.Stored != nil {
		held = append(held, s.Stored()...)
	}
	for _, h := range held {
		if !slices.Contains(all, h) {
			all = append(all, h)
		}
	}
	secrets := slices.DeleteFunc(all, func(v string) bool { return utf16Len(v) < MinMaskedLength })
	slices.SortStableFunc(secrets, func(a, b string) int { return utf16Len(b) - utf16Len(a) })
	out := text
	for _, secret := range secrets {
		out = strings.ReplaceAll(out, secret, Redacted)
	}
	return out
}

// ServerMessage is a server's free text as shown: secrets masked, then
// controls escaped.
func (s *Secrets) ServerMessage(text string) string { return Printable(s.Mask(text)) }
