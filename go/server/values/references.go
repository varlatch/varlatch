// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"regexp"
	"sort"

	"github.com/varlatch/varlatch/go/server/domainerr"
)

// Value references (domain/references.ts): a value may embed ${NAME} to
// reuse another Config Item's value from the same Effective Configuration.
// Expansion never expands authority: a reference is substituted only when
// the caller receives the referenced value through the same operation;
// otherwise it stays literal. $${NAME} escapes to a literal ${NAME}.

var token = regexp.MustCompile(`\$\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// MaxReferenceDepth bounds chains, so cycles terminate (left literal).
const MaxReferenceDepth = 8

// MaxExpandedBytes is the most UTF-8 bytes one expanded value may have.
const MaxExpandedBytes = 1024 * 1024

const maxWork = 10_000

// ReferencedNames are the names one raw value references (escapes excluded),
// in order, repeats included.
func ReferencedNames(raw string) []string {
	var names []string
	for _, m := range token.FindAllStringSubmatchIndex(raw, -1) {
		if m[4] >= 0 {
			names = append(names, raw[m[4]:m[5]])
		}
	}
	return names
}

// ExpansionError is ReferenceExpansionError: VALIDATION_FAILED for a value
// whose expansion is too large or too much work.
func expansionError(message string) error {
	return domainerr.New("VALIDATION_FAILED", message)
}

// ExpandReferences is expandReferences in lenient mode: references the
// lookup cannot resolve, cyclic or too deep stay literal, and onUnexpanded
// (if set) is called with each such name. Plaintext is valid UTF-8 here
// (decode), so a byte length is Buffer.byteLength's.
func ExpandReferences(raw string, lookup func(string) (string, bool), onUnexpanded func(string)) (string, error) {
	remaining := MaxExpandedBytes
	out := make([]byte, 0, len(raw))
	work := 0
	appendText := func(text string) error {
		remaining -= len(text)
		if remaining < 0 {
			return expansionError("expanded value exceeds 1 MiB")
		}
		out = append(out, text...)
		return nil
	}
	var visit func(text string, path []string) error
	visit = func(text string, path []string) error {
		offset := 0
		for _, m := range token.FindAllStringSubmatchIndex(text, -1) {
			work++
			if work > maxWork {
				return expansionError("reference expansion exceeds work limit")
			}
			if err := appendText(text[offset:m[0]]); err != nil {
				return err
			}
			offset = m[1]
			if m[2] >= 0 {
				if err := appendText("${" + text[m[2]:m[3]] + "}"); err != nil {
					return err
				}
				continue
			}
			name := text[m[4]:m[5]]
			value, ok := lookup(name)
			if !ok || contains(path, name) || len(path) >= MaxReferenceDepth {
				if onUnexpanded != nil {
					onUnexpanded(name)
				}
				if err := appendText(text[m[0]:m[1]]); err != nil {
					return err
				}
				continue
			}
			if err := visit(value, append(append([]string(nil), path...), name)); err != nil {
				return err
			}
		}
		return appendText(text[offset:])
	}
	if err := visit(raw, nil); err != nil {
		return "", err
	}
	return string(out), nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// literalSet collects unexpanded names; sorted gives [...set].sort().
type literalSet map[string]bool

func (s literalSet) add(name string) { s[name] = true }

func (s literalSet) sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return utf16Less(out[i], out[j]) })
	return out
}
