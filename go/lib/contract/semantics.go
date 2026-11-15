// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Contract Semantics (packages/contract semantics.ts): what an item means
// for a value in an Environment. Versions never change once released;
// packages/contract/test/vectors pins each one, and the Go tests run them.
// JavaScript's regular expressions are reproduced exactly: \d is ASCII,
// /i without the u flag folds ASCII letters only, \s is JavaScript's set,
// $ is the end of the text.

// Environment is what requiredness depends on: the root Environment's ID
// (the Environment itself when it has no parent) and its tier.
type Environment struct {
	RootID string
	Tier   string
}

// Semantics is one Contract Semantics version's rules.
type Semantics struct{ version int }

// UnsupportedVersionError is UnsupportedSemanticsVersionError.
type UnsupportedVersionError struct{ Version int }

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("Contract semantics version %d is not supported (supported: 1, 2, 3)", e.Version)
}

// SemanticsFor is semanticsFor: unknown versions fail closed.
func SemanticsFor(version int) (Semantics, error) {
	if !slices.Contains(SemanticsVersions, version) {
		return Semantics{}, &UnsupportedVersionError{version}
	}
	return Semantics{version}, nil
}

// Version is the rules' version.
func (s Semantics) Version() int { return s.version }

// RequiredApplies is whether the item is required in the Environment.
func (s Semantics) RequiredApplies(it Item, env Environment) bool {
	switch it.Required.Kind {
	case "always":
		return true
	case "selector":
		sel := it.Required.Selector
		if sel == nil {
			return false
		}
		if sel.Kind == "tier" {
			return sel.Tier == env.Tier
		}
		return slices.Contains(sel.EnvironmentIDs, env.RootID)
	}
	return false
}

// MissingWhenAbsent is whether an item with no value in the Environment is
// reported missing: required there and without a Contract default.
func (s Semantics) MissingWhenAbsent(it Item, env Environment) bool {
	return s.RequiredApplies(it, env) && it.DefaultValue == nil
}

// Converted is a value converted by Parse: one of String, Number, Bool,
// by Kind ("string", "number" or "boolean").
type Converted struct {
	Kind   string
	String string
	Number float64
	Bool   bool
}

// HasParse is whether the version defines conversion (from version 2).
func (s Semantics) HasParse() bool { return s.version >= 2 }

// Validate is why value is invalid for the item, or "" when it is valid.
// The reason never holds the value.
func (s Semantics) Validate(it Item, value string) string {
	if s.version == 1 {
		return validateV1(it, value)
	}
	_, reason := s.Parse(it, value)
	return reason
}

// Parse validates and converts (version 2 and later): the converted value,
// or the reason the value is invalid.
func (s Semantics) Parse(it Item, value string) (Converted, string) {
	if s.version >= 3 && it.Type == "integer" {
		return parseIntegerV3(value)
	}
	switch it.Type {
	case "number":
		return parseNumberV2(value)
	case "integer":
		return Converted{}, beforeInteger
	}
	if reason := validateV1(it, value); reason != "" {
		return Converted{}, reason
	}
	if it.Type == "boolean" {
		v := asciiLower(value)
		return Converted{Kind: "boolean", Bool: v == "true" || v == "1"}, ""
	}
	return Converted{Kind: "string", String: value}, ""
}

const beforeInteger = "has a type this Contract Semantics version does not define (integer needs version 3)"

var (
	numberV1  = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)
	numberV2  = regexp.MustCompile(`^-?([0-9]+)(?:\.([0-9]+))?$`)
	integerV3 = regexp.MustCompile(`^-?([0-9]+)$`)
)

// asciiLower lowercases ASCII letters only, as a JavaScript /i pattern
// without the u flag compares them.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, s)
}

// isJSSpace is JavaScript's \s: WhiteSpace and LineTerminator.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// validEmail is /^[^\s@]+@[^\s@]+\.[^\s@]+$/: no white space, one @ with
// something before it, and after it a dot with something on both sides.
func validEmail(v string) bool {
	if strings.ContainsFunc(v, isJSSpace) || strings.Count(v, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(v, "@")
	if local == "" {
		return false
	}
	for i := 1; i < len(domain)-1; i++ {
		if domain[i] == '.' {
			return true
		}
	}
	return false
}

func validateV1(it Item, value string) string {
	switch it.Type {
	case "string":
		return ""
	case "number":
		if numberV1.MatchString(value) {
			return ""
		}
		return "must be a number"
	case "boolean":
		switch asciiLower(value) {
		case "true", "false", "1", "0":
			return ""
		}
		return "must be a boolean"
	case "url":
		// `new URL(value)` succeeds, as Node.js parses it (ada).
		if _, ok := whatwg.ParseURL(value); ok {
			return ""
		}
		return "must be a valid URL"
	case "email":
		if validEmail(value) {
			return ""
		}
		return "must be an email address"
	case "enum":
		if slices.Contains(it.EnumValues, value) {
			return ""
		}
		return "must be one of: " + strings.Join(it.EnumValues, ", ")
	case "integer":
		return beforeInteger
	}
	return beforeInteger
}

// maxExact is 2^53 - 1, the largest integer a double holds exactly.
const maxExact = "9007199254740991"

func stripZeros(digits string) string {
	t := strings.TrimLeft(digits, "0")
	if t == "" {
		return "0"
	}
	return t
}

func parseNumberV2(value string) (Converted, string) {
	m := numberV2.FindStringSubmatch(value)
	if m == nil {
		return Converted{}, "must be a number"
	}
	integer := stripZeros(m[1])
	fractionNonZero := strings.ContainsAny(m[2], "123456789")
	tooLarge := len(integer) > len(maxExact) ||
		(len(integer) == len(maxExact) && (integer > maxExact || (integer == maxExact && fractionNonZero)))
	if tooLarge {
		return Converted{}, "must be a number no larger in magnitude than 2^53 - 1"
	}
	f, _ := strconv.ParseFloat(value, 64)
	return Converted{Kind: "number", Number: f}, ""
}

func parseIntegerV3(value string) (Converted, string) {
	m := integerV3.FindStringSubmatch(value)
	if m == nil {
		return Converted{}, "must be a whole number"
	}
	digits := stripZeros(m[1])
	if len(digits) > len(maxExact) || (len(digits) == len(maxExact) && digits > maxExact) {
		return Converted{}, "must be a whole number no larger in magnitude than 2^53 - 1"
	}
	f, _ := strconv.ParseFloat(value, 64)
	if f == 0 {
		f = 0 // -0 converts to 0
	}
	return Converted{Kind: "number", Number: f}, ""
}
