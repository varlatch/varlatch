// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// Docs is OUTBOUND_POLICY_DOCS.
const Docs = "https://docs.varlatch.com/reference/outbound-policy/"

// RefusedCode is OUTBOUND_REFUSED_CODE (@varlatch/sync), which a refused
// check carries.
const RefusedCode = "VARLATCH_OUTBOUND_REFUSED"

// The refusals in words (@varlatch/protocol outbound.ts): they name the
// class of address, never the address.
var (
	// Sentences is OUTBOUND_REFUSAL_MESSAGES.
	Sentences = map[Reason]string{
		PrivateAddress:  "This address is on a private network, which this installation does not let Organizations reach. The host operator can allow it with outbound_allow in varlatchd.conf.",
		HostOnlyAddress: "This address is a loopback or link-local address, which Organizations cannot use.",
		NeverAddress:    "This address is unspecified, multicast or reserved, and can never be used.",
		MixedAnswers:    "This name has several addresses and one of them is not allowed.",
		Scheme:          "Plain http is allowed only to destinations the host operator allowed. Use https.",
		PortReason:      "The host operator allowed this destination on another port only. The host operator can allow this port with outbound_allow in varlatchd.conf.",
	}
	// Labels is OUTBOUND_REFUSAL_LABELS.
	Labels = map[Reason]string{
		PrivateAddress:  "private network address",
		HostOnlyAddress: "loopback or link-local address",
		NeverAddress:    "reserved address",
		MixedAnswers:    "one of its addresses is not allowed",
		Scheme:          "plain http",
		PortReason:      "port not allowed",
	}
)

// RefusedGeneric is OUTBOUND_REFUSED_GENERIC: for a stored refusal without
// a reason (a webhook's last_status).
const RefusedGeneric = "This installation's outbound policy refuses this destination, so deliveries wait. " +
	"Depending on the address, the host operator may be able to allow it with outbound_allow in varlatchd.conf; some addresses can never be used."

// HostNote is OUTBOUND_HOST_NOTE.
const HostNote = "Private destinations are allowed by the host operator, with outbound_allow in varlatchd.conf on the host, not in Varlatch. " +
	"Nothing waiting is lost: once the host operator allows a destination and restarts varlatchd, what waited for it is delivered."

// Message is outboundRefusalMessage: the sentence and the docs link.
func Message(r Reason) string { return Sentences[r] + " See " + Docs }

// RefusedError is OutboundRefusedError: a request the policy refused.
// Error() is the fixed wording, safe to show to the Organization; the
// addresses are for the operator's log only.
type RefusedError struct {
	Reason      Reason
	Destination Destination
	Addresses   []string
}

func (e *RefusedError) Error() string { return Message(e.Reason) }

// Code is RefusedCode.
func (e *RefusedError) Code() string { return RefusedCode }

// RefusalOf is outboundRefusalOf: the policy refusal behind err, through
// any wrapping; nil when there is none.
func RefusalOf(err error) *RefusedError {
	var r *RefusedError
	if errors.As(err, &r) {
		return r
	}
	return nil
}

// LastStatusRefused is a webhook's last_status after a refusal (no reason
// stored), and ReasonOfStatus reads a stored refusal state
// (outboundRefusalOfStatus): a Sync Target's "outbound_refused: <reason>"
// or a webhook's "outbound_refused".
const LastStatusRefused = "outbound_refused"

// ReasonOfStatus is the stored refusal's reason, "unknown" when none is
// stored, or "" when text is not a refusal.
func ReasonOfStatus(text string) Reason {
	rest, ok := strings.CutPrefix(text, "outbound_refused")
	if !ok {
		return ""
	}
	if r, ok := strings.CutPrefix(rest, ":"); ok {
		r = strings.TrimLeft(r, " \t\n\r\f\v")
		end := strings.IndexFunc(r, func(c rune) bool { return !(c >= 'a' && c <= 'z' || c == '_') })
		if end >= 0 {
			r = r[:end]
		}
		if _, known := Sentences[Reason(r)]; known {
			return Reason(r)
		}
	}
	return "unknown"
}

// Limiter is RefusalAuditLimiter (ADR-0057 Decision 8): at most one
// connection-phase event per key per hour, at most ProcessCap an hour in
// all; what is held back is counted, and the next recorded event carries
// the count. A key's entry lives PerKey; at most MaxKeys are held, and a
// new key beyond that counts toward the cap instead of getting an entry.
type Limiter struct {
	PerKey     time.Duration
	ProcessCap int
	MaxKeys    int

	now          func() time.Time
	mu           sync.Mutex
	keys         map[string]time.Time
	order        []string // insertion order is expiry order
	windowStart  time.Time
	windowCount  int
	suppressed   int
	windowActive bool
}

// NewLimiter is the limiter with the TypeScript bounds: an hour, 100 an
// hour, 10,000 keys.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{PerKey: time.Hour, ProcessCap: 100, MaxKeys: 10_000, now: now, keys: map[string]time.Time{}}
}

func (l *Limiter) sweep(now time.Time) {
	for len(l.order) > 0 {
		k := l.order[0]
		if l.keys[k].After(now) {
			break
		}
		delete(l.keys, k)
		l.order = l.order[1:]
	}
}

// Size is how many keys are held.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// Admit is whether to record an event for key now, and how many were held
// back since the last one.
func (l *Limiter) Admit(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	if !l.windowActive || now.Sub(l.windowStart) >= l.PerKey {
		l.windowStart, l.windowCount, l.windowActive = now, 0, true
	}
	if _, held := l.keys[key]; held || l.windowCount >= l.ProcessCap {
		l.suppressed++
		return false, 0
	}
	if len(l.keys) < l.MaxKeys {
		l.keys[key] = now.Add(l.PerKey)
		l.order = append(l.order, key)
	}
	l.windowCount++
	s := l.suppressed
	l.suppressed = 0
	return true, s
}

// Always is for configuration-phase events, which are always recorded and
// carry what was held back.
func (l *Limiter) Always() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.suppressed
	l.suppressed = 0
	return s
}
