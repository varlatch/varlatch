// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"regexp"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
)

// Strict option parsing for commands that write files (ADR-0043 Decision
// 10), a port of apps/cli/src/options.ts: an unknown option, a missing
// value, a repeated single-value option, or an extra argument is a usage
// error, found before the command reads or writes anything. A typo such as
// `--chek` must not run the command as if the option were absent.

// OptionsError is options.ts's OptionsError: its message names the problem.
// Rejected is "unknown" for an unknown option and "unexpected" for an
// argument beyond the positionals, with Index its place in the arguments
// (from 0), so a command whose arguments may hold a Secret can name the
// place without the argument.
type OptionsError struct {
	Message  string
	Rejected string
	Index    int
}

func (e *OptionsError) Error() string { return e.Message }

// OptionSpec is options.ts's OptionSpec.
type OptionSpec struct {
	// Values take one value, given at most once.
	Values []string `json:"values,omitempty"`
	// Lists take one value, repeatable.
	Lists []string `json:"lists,omitempty"`
	// Booleans take no value.
	Booleans []string `json:"booleans,omitempty"`
	// OnceBooleans: a boolean given twice is a usage error too.
	OnceBooleans bool `json:"onceBooleans,omitempty"`
	// Positionals is how many positional arguments the command takes.
	Positionals int `json:"positionals,omitempty"`
	// Aliases are other names for an option ("-e": "--environment"), in the
	// order the TypeScript object literal gives them.
	Aliases []Alias `json:"-"`
	// EndOfOptions: `--` ends the options, so a positional argument may begin with "-".
	EndOfOptions bool `json:"endOfOptions,omitempty"`
}

// shownArgument is an argument as a usage error echoes it. An option
// written with its value attached, `--name=value` or a short option such
// as `-Hvalue`, is shown without the value (`--name=[redacted]`,
// `-H[redacted]`), whatever the option: the value may be a credential
// (go/README.md, "Diagnostics never print credential values"). Otherwise a
// URL's user name and password are masked (MaskURLInValue), and any text in
// Varlatch's token format is shown as [redacted]. Run.finish's fail-safe
// redacts tokens again, so correctness never depends on this; it keeps the
// wording precise.
func shownArgument(arg string) string {
	if strings.HasPrefix(arg, "--") {
		if name, _, ok := strings.Cut(arg, "="); ok {
			return name + "=" + Redacted
		}
	} else if strings.HasPrefix(arg, "-") && len(arg) > 2 {
		return arg[:2] + Redacted
	}
	return varlatchToken.ReplaceAllLiteralString(clientctx.MaskURLInValue(arg), Redacted)
}

// unknownWithValue is an unknown-option message whose option carries an
// attached value, as the TypeScript CLI words it.
var unknownWithValue = regexp.MustCompile(`unknown option (--[^=\s]+=|-[^-\s])[^\s]*`)

// OptionValueDifference is a TypeScript usage message as the Go CLI words
// it: an unknown option's attached value as [redacted] (shownArgument).
// The transcripts and vectors apply it where they record the TypeScript
// CLI echoing one.
func OptionValueDifference(message string) string {
	return unknownWithValue.ReplaceAllStringFunc(message, func(m string) string {
		arg := strings.TrimPrefix(m, "unknown option ")
		if !strings.HasPrefix(arg, "--") && len(arg) <= 2 {
			return m
		}
		return "unknown option " + shownArgument(arg)
	})
}

// Alias is one other name for an option.
type Alias struct{ From, To string }

// ParsedOptions is options.ts's ParsedOptions, with each map's keys in
// insertion order where it matters.
type ParsedOptions struct {
	Values      map[string]string
	ValueOrder  []string
	Lists       map[string][]string
	ListOrder   []string
	Booleans    []string
	Positionals []string
}

// Has is whether the boolean option was given.
func (p *ParsedOptions) Has(name string) bool { return slices.Contains(p.Booleans, name) }

// Value is the single-value option's value and whether it was given.
func (p *ParsedOptions) Value(name string) (string, bool) {
	v, ok := p.Values[name]
	return v, ok
}

// ParseOptions is options.ts's parseOptions.
func ParseOptions(args []string, spec OptionSpec) (*ParsedOptions, error) {
	parsed := &ParsedOptions{Values: map[string]string{}, Lists: map[string][]string{}}
	positional := func(arg string, index int) error {
		if len(parsed.Positionals) >= spec.Positionals {
			shown := shownArgument(arg)
			if clientctx.HasAtSign(shown) {
				return &OptionsError{Message: shown + ": unexpected argument", Rejected: "unexpected", Index: index} // the explanation follows the URL
			}
			return &OptionsError{Message: "unexpected argument " + shown, Rejected: "unexpected", Index: index}
		}
		parsed.Positionals = append(parsed.Positionals, arg)
		return nil
	}
	// "--environment (or -e)": an option named with its aliases.
	named := func(option string) string {
		var others []string
		for _, a := range spec.Aliases {
			if a.To == option {
				others = append(others, a.From)
			}
		}
		if len(others) > 0 {
			return option + " (or " + strings.Join(others, ", ") + ")"
		}
		return option
	}
	for i := 0; i < len(args); i++ {
		if spec.EndOfOptions && args[i] == "--" {
			for j, rest := range args[i+1:] {
				if err := positional(rest, i+1+j); err != nil {
					return nil, err
				}
			}
			break
		}
		arg := args[i]
		for _, a := range spec.Aliases {
			if a.From == args[i] {
				arg = a.To
				break
			}
		}
		if slices.Contains(spec.Booleans, arg) {
			if spec.OnceBooleans && parsed.Has(arg) {
				return nil, &OptionsError{Message: named(arg) + " given twice"}
			}
			if !parsed.Has(arg) {
				parsed.Booleans = append(parsed.Booleans, arg)
			}
			continue
		}
		single := slices.Contains(spec.Values, arg)
		if single || slices.Contains(spec.Lists, arg) {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "-") {
				return nil, &OptionsError{Message: arg + " needs a value"}
			}
			value := args[i]
			if single {
				if _, ok := parsed.Values[arg]; ok {
					return nil, &OptionsError{Message: named(arg) + " given twice"}
				}
				parsed.Values[arg] = value
				parsed.ValueOrder = append(parsed.ValueOrder, arg)
			} else {
				if _, ok := parsed.Lists[arg]; !ok {
					parsed.ListOrder = append(parsed.ListOrder, arg)
				}
				parsed.Lists[arg] = append(parsed.Lists[arg], value)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			hint := ""
			if spec.EndOfOptions {
				hint = ` (a value that begins with "-" goes after --)`
			}
			shown := shownArgument(arg)
			if clientctx.HasAtSign(shown) {
				return nil, &OptionsError{Message: shown + ": unknown option" + hint, Rejected: "unknown", Index: i} // the explanation follows the URL
			}
			return nil, &OptionsError{Message: "unknown option " + shown + hint, Rejected: "unknown", Index: i}
		}
		if err := positional(arg, i); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}
