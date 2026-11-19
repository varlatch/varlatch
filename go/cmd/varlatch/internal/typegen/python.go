// SPDX-License-Identifier: Apache-2.0

package typegen

import (
	"math"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/lib/contract"
)

func hex(cp rune, width int) string {
	h := strconv.FormatInt(int64(cp), 16)
	return strings.Repeat("0", max(0, width-len(h))) + h
}

// pyString is typegenPython.ts's pyString: a Python string literal in
// printable ASCII, every other code point escaped.
func pyString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	runes(value, func(cp rune, raw string) {
		switch {
		case cp == '\\':
			b.WriteString(`\\`)
		case cp == '"':
			b.WriteString(`\"`)
		case cp >= 0x20 && cp <= 0x7e:
			b.WriteRune(cp)
		case cp <= 0xff:
			b.WriteString(`\x` + hex(cp, 2))
		case cp <= 0xffff:
			b.WriteString(`\u` + hex(cp, 4))
		default:
			b.WriteString(`\U` + hex(cp, 8))
		}
	})
	b.WriteByte('"')
	return b.String()
}

// pyLiteral is typegenPython.ts's pyLiteral: a JSON-shaped value as a
// Python literal.
func pyLiteral(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return pyString(x), nil
	case float64:
		if x == math.Trunc(x) && math.Abs(x) <= 1<<53-1 {
			return strconv.FormatFloat(x+0, 'f', -1, 64), nil // +0: String(-0) is "0"
		}
	case bool:
		if x {
			return "True", nil
		}
		return "False", nil
	case nil:
		return "None", nil
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			s, err := pyLiteral(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case contract.Object:
		parts := make([]string, len(x))
		for i, m := range x {
			s, err := pyLiteral(m.Value)
			if err != nil {
				return "", err
			}
			parts[i] = pyString(m.Key) + ": " + s
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	}
	return "", fail("the Contract holds a value the Python generator cannot write")
}

// docEscape escapes backslashes and quotes, so a docstring cannot end.
func docEscape(line string) string {
	return strings.ReplaceAll(strings.ReplaceAll(line, `\`, `\\`), `"`, `\"`)
}

// docstring is a docstring at indent, from lines that are already clean.
func docstring(lines []string, indent string) []string {
	body := make([]string, len(lines))
	for i, l := range lines {
		body[i] = docEscape(l)
	}
	if len(body) == 1 {
		return []string{indent + `"""` + body[0] + `"""`}
	}
	out := []string{indent + `"""` + body[0]}
	for _, l := range body[1:] {
		if l == "" {
			out = append(out, "")
		} else {
			out = append(out, indent+l)
		}
	}
	return append(out, indent+`"""`)
}

func annotation(it contract.Item) string {
	switch it.Type {
	case "number":
		return "float"
	case "integer":
		return "int"
	case "boolean":
		return "bool"
	case "enum":
		parts := make([]string, len(it.EnumValues))
		for i, v := range it.EnumValues {
			parts[i] = pyString(v)
		}
		return "_typing.Literal[" + strings.Join(parts, ", ") + "]"
	}
	return "str"
}

func itemDoc(it contract.Item) []string {
	var lines []string
	if it.Description != nil {
		lines = append(append(lines, cleanLines(*it.Description)...), "")
	}
	lines = append(lines, cleanLines(requirednessLine(it))...)
	if it.Type == "number" {
		lines = append(lines, "", "A whole number is an int; a number with a fraction is a float.")
	}
	if it.Type == "integer" {
		lines = append(lines, "", "A whole number.")
	}
	if it.Example != nil {
		example := cleanLines(*it.Example)
		first, rest := "", []string(nil)
		if len(example) > 0 {
			first, rest = example[0], example[1:]
		}
		lines = append(append(lines, "", trimEnd("Example: "+first)), rest...)
	}
	if it.DefaultValue != nil {
		lines = append(lines, "", "Default: "+pyString(*it.DefaultValue))
	}
	if it.Sensitive {
		lines = append(lines, "", "Sensitive: kept out of repr().")
	}
	return lines
}

func field(it contract.Item, withRepr bool) string {
	optional := isOptional(it)
	typ := annotation(it)
	if optional {
		typ += " | None"
	}
	hidden := withRepr && it.Sensitive
	value := ""
	switch {
	case optional && hidden:
		value = " = _dataclasses.field(default=None, repr=False)"
	case optional:
		value = " = None"
	case hidden:
		value = " = _dataclasses.field(repr=False)"
	}
	return "    " + it.Name + ": " + typ + value
}

func dataclass(name string, doc []string, items []contract.Item, hideSensitive bool, extra []string) []string {
	out := append([]string{"@_dataclasses.dataclass(frozen=True, slots=True, kw_only=True)", "class " + name + ":"}, docstring(doc, "    ")...)
	for _, it := range items {
		out = append(append(out, "", field(it, hideSensitive)), docstring(itemDoc(it), "    ")...)
	}
	if len(extra) > 0 {
		out = append(append(out, ""), extra...)
	}
	return out
}

// Python is generatePythonModule: the generated Python module, byte for
// byte, or an *Error when no types can be generated.
func Python(r Revision, generatorVersion string) (string, error) {
	if !ValidGeneratorVersion(generatorVersion) {
		return "", fail("the generator version is not printable")
	}
	c, err := checkRevision(r, runtimes.PythonSemanticsVersions)
	if err != nil {
		return "", err
	}
	v := strconv.Itoa(c.version)
	generator := "varlatch " + generatorVersion
	var public []contract.Item
	for _, it := range c.items {
		if !it.Sensitive {
			public = append(public, it)
		}
	}

	out := []string{
		"# Generated by `varlatch types` from a Varlatch Contract Revision. Do not edit",
		"# this file: regenerate it with `varlatch types`, and check that it is current",
		"# with `varlatch types --check`.",
		"#",
		"# Contract Revision:          " + c.id,
		"# Content hash:               " + c.hash,
		"# Contract Semantics version: " + v,
		"# Generator:                  " + generator,
		"#",
		"# It holds Contract metadata only: names, types, descriptions, examples,",
		"# defaults, and requiredness, never values. The Typed Accessor at the end",
		"# reads os.environ, converts each value with the Contract Semantics version",
		"# above, and never writes to os.environ. It needs Python 3.10 or later and",
		"# the standard library only; with the ada-url package installed, it also",
		"# validates URLs with internationalized host names.",
		"#",
		"# ruff: noqa",
		"# mypy: ignore-errors",
		"# fmt: off",
		"from __future__ import annotations",
		"",
		"import dataclasses as _dataclasses",
		"import types as _types",
		"import typing as _typing",
		"",
		"__all__ = [",
		`    "Config",`,
		`    "ConfigError",`,
		`    "ConfigIssue",`,
		`    "GENERATED_FROM",`,
		`    "LoadResult",`,
		`    "PublicConfig",`,
		`    "VarlatchWarning",`,
		`    "load_config",`,
		"]",
		"",
		"# The Contract Revision this file was generated from.",
		"GENERATED_FROM: _typing.Mapping[str, _typing.Any] = _types.MappingProxyType({",
		`    "revision_id": ` + pyString(c.id) + ",",
		`    "content_hash": ` + pyString(c.hash) + ",",
		`    "semantics_version": ` + v + ",",
		`    "generator": ` + pyString(generator) + ",",
		"})",
		"",
		"",
	}
	out = append(out, dataclass("Config", []string{
		"Every Contract item, converted.",
		"",
		"Integers become int; numbers become int (whole numbers) or float;",
		"booleans become bool, and enums their values; URLs are validated and",
		"stay str. An item is optional (None when absent) unless the Contract",
		"requires it in every environment without a default: a default is",
		"applied only by `varlatch run --strict`, or by",
		"load_config(apply_defaults=True), and never replaces a withheld value.",
		"Read-only; sensitive items are kept out of repr().",
	}, c.items, true, []string{
		"    def public(self) -> PublicConfig:",
		`        """Only the non-sensitive items."""`,
		"        return PublicConfig(**{name: getattr(self, name) for name in _VARLATCH_PUBLIC})",
	})...)
	out = append(out, "", "")
	out = append(out, dataclass("PublicConfig", []string{"Only the non-sensitive Contract items."}, public, false, nil)...)
	out = append(out,
		"",
		"",
		"@_dataclasses.dataclass(frozen=True, slots=True, kw_only=True)",
		"class LoadResult:",
		`    """What load_config() read."""`,
		"",
		"    config: Config",
		`    """The converted configuration. Read-only."""`,
		"    defaulted: tuple[str, ...]",
		`    """Items filled with their Contract default by apply_defaults."""`,
		"    not_evaluated: tuple[str, ...]",
		`    """Absent items required only in some environments, unchecked without a run context."""`,
		`    context: _typing.Literal["strict", "exported"] | None`,
		`    """The run context's mode, or None when the application was started without one."""`,
		"    warnings: tuple[str, ...]",
		`    """Warnings raised while loading, such as stale types."""`,
		"",
		"",
		"def load_config(",
		"    *,",
		"    env: _typing.Mapping[str, str] | None = None,",
		"    apply_defaults: bool = False,",
		`    stale_types: _typing.Literal["warn", "raise"] = "warn",`,
		"    require_context: bool = False,",
		"    on_warning: _typing.Callable[[str], None] | None = None,",
		") -> LoadResult:",
		`    """Read and convert every item now.`,
		"",
		"    Raises one ConfigError that lists every problem by name and reason, never",
		"    by value.",
		"",
		"    env: where values are read. Default: os.environ. Never written to.",
		"    apply_defaults: fill absent items with their Contract defaults, and report",
		"        them in `defaulted`. Applies without a run context or under one from",
		"        `varlatch run --export-context`, never to an item the server withheld,",
		"        and has no effect after `varlatch run --strict`, which already applied",
		"        defaults.",
		`    stale_types: when the run context names a different Contract: "warn"`,
		`        (default) or "raise".`,
		"    require_context: raise when VARLATCH_RUN_CONTEXT is not set.",
		"    on_warning: receives warnings. Default: warnings.warn with VarlatchWarning.",
		`    """`,
		"    options = {",
		`        "env": env,`,
		`        "apply_defaults": apply_defaults,`,
		`        "stale_types": stale_types,`,
		`        "require_context": require_context,`,
		`        "on_warning": on_warning,`,
		"    }",
		"    # The environment travels in `options` only, and is taken out of it before",
		"    # anything is read: no frame that raises ConfigError holds it.",
		"    del env",
		"    return _load(_VARLATCH_SCHEMA, Config, LoadResult, options)",
		"",
		"",
		"# The configuration from os.environ, read and checked on first use with the",
		"# default options. If it is invalid, every use raises a ConfigError.",
		"config: Config",
		"",
		"",
		"def __getattr__(name: str) -> _typing.Any:",
		`    if name == "config":`,
		"        return _lazy(_VARLATCH_SCHEMA, Config, LoadResult)",
		`    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")`,
		"",
		"",
	)
	names := make([]string, len(public))
	for i, it := range public {
		names[i] = pyString(it.Name) + ","
	}
	out = append(out,
		"_VARLATCH_PUBLIC = ("+strings.Join(names, " ")+")",
		"",
		"_VARLATCH_SCHEMA = {",
		`    "format": 1,`,
		`    "revisionId": `+pyString(c.id)+",",
		`    "contentHash": `+pyString(c.hash)+",",
		`    "semanticsVersion": `+v+",",
		`    "generator": `+pyString(generator)+",",
		`    "items": [`,
	)
	for i, it := range c.items {
		s, err := pyLiteral(schemaItem(it, c.values[i]))
		if err != nil {
			return "", err
		}
		out = append(out, "        "+s+",")
	}
	out = append(out,
		"    ],",
		"}",
		"",
		"",
		"# Varlatch Typed Accessor for Python. Copyright 2026 Robotsson. SPDX-License-Identifier: Apache-2.0",
		trimEnd(pythonRuntimeSource),
		"",
	)
	return strings.Join(out, "\n"), nil
}
