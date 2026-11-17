// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"strings"
)

// Strict option parsing for commands that write files (ADR-0043 Decision
// 10), a port of apps/cli/src/options.ts: an unknown option, a missing
// value, a repeated single-value option, or an extra argument is a usage
// error, found before the command reads or writes anything. A typo such as
// `--chek` must not run the command as if the option were absent.

// OptionsError is options.ts's OptionsError: its message names the problem.
type OptionsError struct{ Message string }

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
	positional := func(arg string) error {
		if len(parsed.Positionals) >= spec.Positionals {
			return &OptionsError{"unexpected argument " + arg}
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
			for _, rest := range args[i+1:] {
				if err := positional(rest); err != nil {
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
				return nil, &OptionsError{named(arg) + " given twice"}
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
				return nil, &OptionsError{arg + " needs a value"}
			}
			value := args[i]
			if single {
				if _, ok := parsed.Values[arg]; ok {
					return nil, &OptionsError{named(arg) + " given twice"}
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
			return nil, &OptionsError{"unknown option " + arg + hint}
		}
		if err := positional(arg); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}
