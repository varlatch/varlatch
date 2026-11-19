// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
)

// Destination matching against the Capability's canonical selectors
// (host:port, *.suffix:port, [v6]:port, as returned at issuance), broker.ts.
// varlatchd stays authoritative; this decides only local routing.

// Selector is one destination selector: a host, or with Wildcard every
// name under it, and a port (JavaScript's Number of what follows the
// colon, so any number).
type Selector struct {
	Host     string
	Wildcard bool
	Port     float64
}

// jsSlice is String.prototype.slice in UTF-16 units, negative indexes
// counted from the end.
func jsSlice(s string, start, end int) string {
	u := jsval.UTF16(s)
	clamp := func(k int) int {
		if k < 0 {
			k += len(u)
		}
		return max(0, min(k, len(u)))
	}
	a, b := clamp(start), clamp(end)
	if a >= b {
		return ""
	}
	return jsval.FromUTF16(u[a:b])
}

var (
	jsDecimal = regexp.MustCompile(`^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$`)
	jsRadix   = regexp.MustCompile(`^0([xXoObB])([0-9a-fA-F]+)$`)
)

// jsNumber is Number(text) for a string.
func jsNumber(text string) float64 {
	t := jsTrim(text)
	switch {
	case t == "":
		return 0
	case jsDecimal.MatchString(t):
		f, _ := strconv.ParseFloat(t, 64)
		return f
	case t == "Infinity" || t == "+Infinity":
		return math.Inf(1)
	case t == "-Infinity":
		return math.Inf(-1)
	}
	if m := jsRadix.FindStringSubmatch(t); m != nil {
		base := map[byte]int{'x': 16, 'X': 16, 'o': 8, 'O': 8, 'b': 2, 'B': 2}[m[1][0]]
		if v, err := strconv.ParseUint(m[2], base, 64); err == nil {
			return float64(v)
		}
	}
	return math.NaN()
}

func isInteger(f float64) bool { return !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) }

// jsLower is String.prototype.toLowerCase, which keeps the dot of a
// capital I with a dot above.
func jsLower(s string) string { return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇")) }

// ParseSelectors is parseSelectors.
func ParseSelectors(raw []string) []Selector {
	var out []Selector
	for _, entry := range raw {
		wildcard := strings.HasPrefix(entry, "*.")
		rest := entry
		if wildcard {
			rest = entry[2:]
		}
		var host string
		var port float64
		if strings.HasPrefix(rest, "[") {
			closing := indexUTF16(rest, "]")
			host = jsSlice(rest, 1, closing)
			port = jsNumber(jsSlice(rest, closing+2, math.MaxInt32))
		} else {
			colon := lastIndexUTF16(rest, ":")
			host = jsSlice(rest, 0, colon)
			port = jsNumber(jsSlice(rest, colon+1, math.MaxInt32))
		}
		if host != "" && isInteger(port) {
			out = append(out, Selector{jsLower(host), wildcard, port})
		}
	}
	return out
}

func indexUTF16(s, sub string) int {
	i := strings.Index(s, sub)
	if i < 0 {
		return -1
	}
	return len(jsval.UTF16(s[:i]))
}

func lastIndexUTF16(s, sub string) int {
	i := strings.LastIndex(s, sub)
	if i < 0 {
		return -1
	}
	return len(jsval.UTF16(s[:i]))
}

// canonicalHost is canonicalHost: lower-cased, without a trailing dot or
// an IPv6 literal's brackets.
func canonicalHost(raw string) string {
	host := jsLower(raw)
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		host = host[1 : len(host)-1]
	}
	return host
}

// isIP is net.isIP: an IPv4 address in dotted decimal or an IPv6 address
// (a zone included).
func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// MatchesSelectors is matchesSelectors: a wildcard matches names under its
// suffix only, never an address.
func MatchesSelectors(selectors []Selector, host string, port float64) bool {
	h := canonicalHost(host)
	return slices.ContainsFunc(selectors, func(sel Selector) bool {
		if sel.Port != port {
			return false
		}
		if sel.Wildcard {
			return !isIP(h) && strings.HasSuffix(h, "."+sel.Host)
		}
		return h == sel.Host
	})
}

// SameTargets is sameTargets: equal target sets, whatever the order.
func SameTargets(a, b map[string][]string) bool {
	canonical := func(t map[string][]string) [][]string {
		items := make([]string, 0, len(t))
		for item := range t {
			items = append(items, item)
		}
		slices.SortFunc(items, jsval.CompareUTF16)
		out := make([][]string, len(items))
		for k, item := range items {
			list := slices.Clone(t[item])
			slices.SortFunc(list, jsval.CompareUTF16)
			out[k] = append([]string{item}, list...)
		}
		return out
	}
	return slices.EqualFunc(canonical(a), canonical(b), slices.Equal[[]string])
}
