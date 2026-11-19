// SPDX-License-Identifier: Apache-2.0

// Package matcher is packages/matcher in Go (slice 5.4a of internal
// docs/design/go-cli.md, decision 10): the forms of a secret value, the
// byte-level Aho-Corasick automaton with its hold-back, the streaming
// matcher that replaces each overlap region once (ADR-0039 Decisions 17 to
// 19), the scanner that reports occurrences, the whole-input references
// they are checked against, and apps/cli/src/redact.ts's OutputRedaction,
// which relays a child's output through the matcher.
//
// Values arrive as the CLI holds JSON strings: UTF-8, with a lone UTF-16
// surrogate kept as its WTF-8 bytes (lib/jsjson).
package matcher

import (
	"encoding/base64"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// MinLength is MIN_LENGTH: values, and derived forms, shorter than this
// many bytes are never registered.
const MinLength = 8

// FormName is a form's name as scanning reports it: raw (as written), json
// (either JSON escaping), percent (either hex case), base64 or base64url.
// When two forms have the same bytes, the earlier name in that order is
// reported.
type FormName string

const (
	Raw       FormName = "raw"
	JSON      FormName = "json"
	Percent   FormName = "percent"
	Base64    FormName = "base64"
	Base64URL FormName = "base64url"
)

// LabelledForm is one registered form of a value and its name.
type LabelledForm struct {
	Form  FormName
	Bytes []byte
}

// DeliveredText is deliveredText: a value as UTF-8 carries it, each
// unpaired surrogate as U+FFFD (an environment variable, a header,
// percent-encoding and a terminal all carry it so).
func DeliveredText(value string) string { return jsval.NodeText(value) }

// jsonBody is JSON.stringify(s).slice(1, -1).
func jsonBody(s string) string {
	q := string(jsjson.Stringify(s))
	return q[1 : len(q)-1]
}

// encodeURIComponent is encodeURIComponent for well-formed text: every
// byte but the unreserved ASCII ones as %XX, upper-case hex.
func encodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// lowerPercent is the percent form with lower-case hex
// (/%[0-9A-F]{2}/g, each to lower case).
func lowerPercent(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' && isUpperHex(b[i+1]) && isUpperHex(b[i+2]) {
			b[i+1], b[i+2] = lowerHex(b[i+1]), lowerHex(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func isUpperHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' }

func lowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// base64Core is base64Core: the value encoded after `alignment` filler
// bytes, keeping only the characters whose six bits all come from the
// value, the same whatever surrounds the value in a longer string.
func base64Core(value []byte, alignment int, url bool) string {
	buf := make([]byte, alignment+len(value))
	copy(buf[alignment:], value)
	encoded := strings.TrimRight(base64.StdEncoding.EncodeToString(buf), "=")
	first := (8*alignment + 5) / 6
	last := 8 * (alignment + len(value)) / 6
	if last > len(encoded) {
		last = len(encoded)
	}
	if first > last {
		return ""
	}
	encoded = encoded[first:last]
	if url {
		encoded = strings.NewReplacer("+", "-", "/", "_").Replace(encoded)
	}
	return encoded
}

// LabelledFormsOf is labelledFormsOf: every registered form of a stored
// value with its name, deduplicated, each at least MinLength bytes, in
// formsOf's order; none for a value shorter than MinLength bytes.
func LabelledFormsOf(stored string) []LabelledForm {
	value := DeliveredText(stored)
	raw := []byte(value)
	if len(raw) < MinLength {
		return nil
	}
	// JSON keeps an unpaired surrogate as a \udXXX escape: a JSON body
	// carrying the stored value holds the stored value's escaping. Both
	// are registered; for a well-formed value they are the same form.
	storedJSON := jsonBody(stored)
	deliveredJSON := jsonBody(value)
	percent := encodeURIComponent(value)
	type candidate struct {
		form FormName
		text string
	}
	candidates := []candidate{
		{Raw, value},
		{JSON, storedJSON},
		{JSON, strings.ReplaceAll(storedJSON, "/", `\/`)},
		{JSON, deliveredJSON},
		{JSON, strings.ReplaceAll(deliveredJSON, "/", `\/`)},
		{Percent, percent},
		{Percent, lowerPercent(percent)},
	}
	for _, alignment := range []int{0, 1, 2} {
		candidates = append(candidates, candidate{Base64, base64Core(raw, alignment, false)}, candidate{Base64URL, base64Core(raw, alignment, true)})
	}
	seen := map[string]bool{}
	var forms []LabelledForm
	for _, c := range candidates {
		if len(c.text) < MinLength || seen[c.text] {
			continue
		}
		seen[c.text] = true
		forms = append(forms, LabelledForm{Form: c.form, Bytes: []byte(c.text)})
	}
	return forms
}

// FormsOf is formsOf: the bytes of LabelledFormsOf, in its order.
func FormsOf(value string) [][]byte {
	labelled := LabelledFormsOf(value)
	out := make([][]byte, len(labelled))
	for i, f := range labelled {
		out[i] = f.Bytes
	}
	return out
}
