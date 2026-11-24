// SPDX-License-Identifier: AGPL-3.0-or-later

// Package limits is what an OIDC binding limits its exchanges to
// (ADR-0060), and how a binding's row says so.
//
// The limits are kept in the binding's claims column, under one reserved
// claim no caller may name. To a server that does not know it (an earlier
// varlatchd after a rollback, the TypeScript server after a reverse
// migration) it is one more claim the token must carry, which none does: the
// binding exchanges nothing there, rather than exchanging without its
// limits. So does, here, a limit a later release adds.
package limits

import (
	"strings"

	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// ReservedPrefix starts the claim names a binding's caller may not use.
const ReservedPrefix = "varlatch:"

const claim = ReservedPrefix + "limits"

// MaxRunID bounds a run id, as a Capability's runId is bounded.
const MaxRunID = 200

// Limits are a binding's. The zero value limits nothing.
type Limits struct {
	// ExerciseOnly makes the exchanged credential one that exercises its
	// Broker's Capabilities and nothing else.
	ExerciseOnly bool
	// RunIDClaim, when set, names the token's claim whose value is the one
	// run whose Capabilities the credential exercises.
	RunIDClaim string
	// SingleExchange makes a token exchange once.
	SingleExchange bool
}

// Any reports whether l limits anything.
func (l Limits) Any() bool { return l != Limits{} }

// JS is the limits' members as the API and an approval give them: only the
// ones set, so a binding without limits reads as it always did.
func (l Limits) JS() jsvalue.Object {
	var o jsvalue.Object
	if l.ExerciseOnly {
		o = append(o, jsvalue.Member{Key: "exerciseOnly", Value: true})
	}
	if l.RunIDClaim != "" {
		o = append(o, jsvalue.Member{Key: "runIdClaim", Value: l.RunIDClaim})
	}
	if l.SingleExchange {
		o = append(o, jsvalue.Member{Key: "singleExchange", Value: true})
	}
	return o
}

func invalid(msg string) error { return domainerr.New("VALIDATION_FAILED", msg) }

// New is the limits of a binding about to be created, checked. An
// exercise-only binding always takes each token once: singleExchange, when
// given, may not say otherwise.
func New(exerciseOnly bool, runIDClaim *string, singleExchange *bool) (Limits, error) {
	l := Limits{ExerciseOnly: exerciseOnly, SingleExchange: exerciseOnly}
	if singleExchange != nil {
		if exerciseOnly && !*singleExchange {
			return Limits{}, invalid("singleExchange: an exercise-only binding exchanges each token once")
		}
		l.SingleExchange = *singleExchange
	}
	if runIDClaim != nil {
		if !exerciseOnly {
			return Limits{}, invalid("runIdClaim: only an exercise-only binding ties its credentials to a run")
		}
		l.RunIDClaim = *runIDClaim
	}
	return l, nil
}

// CheckClaims refuses a caller's claims that name the reserved one.
func CheckClaims(claims jsvalue.Object) error {
	for _, m := range claims {
		if strings.HasPrefix(m.Key, ReservedPrefix) {
			return invalid("claims: names that start with " + ReservedPrefix + " are reserved")
		}
	}
	return nil
}

// Join is the claims a binding's row holds: the caller's and, when l limits
// anything, the reserved one. nil for none.
func Join(claims jsvalue.Object, l Limits) jsvalue.Object {
	if !l.Any() {
		return claims
	}
	out := append(jsvalue.Object{}, claims...)
	return append(out, jsvalue.Member{Key: claim, Value: string(jsvalue.Stringify(append(jsvalue.Object{{Key: "v", Value: 1}}, l.JS()...)))})
}

// Split reads a row's claims: the caller's (nil for none) and the limits. A
// reserved claim it does not understand is left among the claims, where no
// token matches it.
func Split(claims jsvalue.Object) (jsvalue.Object, Limits) {
	v, ok := claims.Get(claim)
	if !ok {
		return claims, Limits{}
	}
	text, _ := v.(string)
	l, ok := parse(text)
	if !ok {
		return claims, Limits{}
	}
	var out jsvalue.Object
	for _, m := range claims {
		if m.Key != claim {
			out = append(out, m)
		}
	}
	return out, l
}

// parse reads the reserved claim's value, strictly: exactly what Join
// writes.
func parse(text string) (Limits, bool) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return Limits{}, false
	}
	o, _ := v.(jsvalue.Object)
	var l Limits
	for _, m := range o {
		ok := true
		switch m.Key {
		case "v":
			n, isNumber := m.Value.(float64)
			ok = isNumber && n == 1
		case "exerciseOnly":
			l.ExerciseOnly, ok = m.Value.(bool)
		case "runIdClaim":
			l.RunIDClaim, ok = m.Value.(string)
		case "singleExchange":
			l.SingleExchange, ok = m.Value.(bool)
		default:
			ok = false
		}
		if !ok {
			return Limits{}, false
		}
	}
	want := string(jsvalue.Stringify(append(jsvalue.Object{{Key: "v", Value: 1}}, l.JS()...)))
	if !l.Any() || text != want || l.RunIDClaim != "" && !l.ExerciseOnly || l.ExerciseOnly && !l.SingleExchange {
		return Limits{}, false
	}
	return l, true
}

// IsLimited reports whether a binding's stored claims hold a limit, one a
// later release wrote included.
func IsLimited(claims jsvalue.Object) bool {
	_, ok := claims.Get(claim)
	return ok
}

// Combine is the limits of a token that matches several bindings of one
// identity: all of them together. ok is false when they tie the credential
// to different claims, which no one run can satisfy.
func Combine(a, b Limits) (l Limits, ok bool) {
	if a.RunIDClaim != "" && b.RunIDClaim != "" && a.RunIDClaim != b.RunIDClaim {
		return Limits{}, false
	}
	l = Limits{ExerciseOnly: a.ExerciseOnly || b.ExerciseOnly, RunIDClaim: a.RunIDClaim, SingleExchange: a.SingleExchange || b.SingleExchange}
	if l.RunIDClaim == "" {
		l.RunIDClaim = b.RunIDClaim
	}
	return l, true
}
