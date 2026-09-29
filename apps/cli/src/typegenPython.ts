// SPDX-License-Identifier: Apache-2.0
import type { ContractItem } from "@varlatch/contract";
import { PYTHON_IMPLEMENTED_SEMANTICS_VERSIONS, PYTHON_RUNTIME_SOURCE } from "@varlatch/accessor-python/embedded";
import {
  TypesError,
  VERSION,
  checkRevision,
  cleanLines,
  isOptional,
  requirednessLine,
  type GenerateOptions,
  type RevisionInput,
} from "./typegen.js";

/**
 * `varlatch types --out <file>.py`: one deterministic Python module from a
 * Contract Revision (ADR-0041). The module carries the Python Typed Accessor
 * runtime inline, so an application needs only this file and the standard
 * library. The output depends on the revision and the generator version
 * only: never on an Environment, a value, the clock, or the machine.
 *
 * Every string literal generated from Contract data is printable ASCII with
 * escapes, and docstrings escape backslashes and quotes, so no Contract text
 * can end a literal, a docstring, or hide in the file.
 */

const hex = (cp: number, width: number) => cp.toString(16).padStart(width, "0");

/** A Python string literal in printable ASCII: every other character is escaped. */
export function pyString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const cp = ch.codePointAt(0) as number;
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (cp >= 0x20 && cp <= 0x7e) out += ch;
    else if (cp <= 0xff) out += `\\x${hex(cp, 2)}`;
    else if (cp <= 0xffff) out += `\\u${hex(cp, 4)}`;
    else out += `\\U${hex(cp, 8)}`;
  }
  return `${out}"`;
}

/** A JSON-shaped value as a Python literal. */
function pyLiteral(value: unknown): string {
  if (typeof value === "string") return pyString(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (typeof value === "boolean") return value ? "True" : "False";
  if (value === null) return "None";
  if (Array.isArray(value)) return `[${value.map(pyLiteral).join(", ")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${pyString(k)}: ${pyLiteral(v)}`)
      .join(", ")}}`;
  }
  throw new TypesError("the Contract holds a value the Python generator cannot write");
}

/** Docstring text: backslashes and quotes escaped, so it can never end the docstring. */
const docEscape = (line: string) => line.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

/** A docstring at the given indentation, from lines that are already clean. */
function docstring(lines: string[], indent: string): string[] {
  const body = lines.map(docEscape);
  if (body.length === 1) return [`${indent}"""${body[0]}"""`];
  return [`${indent}"""${body[0]}`, ...body.slice(1).map((l) => (l === "" ? "" : `${indent}${l}`)), `${indent}"""`];
}

function annotation(item: ContractItem): string {
  switch (item.type) {
    case "number":
      return "float";
    case "boolean":
      return "bool";
    case "enum":
      return `_typing.Literal[${(item.enumValues ?? []).map(pyString).join(", ")}]`;
    default:
      return "str";
  }
}

function itemDoc(item: ContractItem): string[] {
  const lines: string[] = [];
  if (item.description !== undefined) lines.push(...cleanLines(item.description), "");
  lines.push(...cleanLines(requirednessLine(item)));
  if (item.type === "number") {
    lines.push("", "A whole number is an int; a number with a fraction is a float.");
  }
  if (item.example !== undefined) {
    const [first = "", ...rest] = cleanLines(item.example);
    lines.push("", `Example: ${first}`.trimEnd(), ...rest);
  }
  if (item.defaultValue !== undefined) lines.push("", `Default: ${pyString(item.defaultValue)}`);
  if (item.sensitive) lines.push("", "Sensitive: kept out of repr().");
  return lines;
}

function field(item: ContractItem, withRepr: boolean): string {
  const optional = isOptional(item);
  const type = optional ? `${annotation(item)} | None` : annotation(item);
  const hidden = withRepr && item.sensitive;
  let value = "";
  if (optional && hidden) value = " = _dataclasses.field(default=None, repr=False)";
  else if (optional) value = " = None";
  else if (hidden) value = " = _dataclasses.field(repr=False)";
  return `    ${item.name}: ${type}${value}`;
}

function dataclass(name: string, doc: string[], items: ContractItem[], hideSensitive: boolean, extra: string[] = []): string[] {
  const out = ["@_dataclasses.dataclass(frozen=True, slots=True, kw_only=True)", `class ${name}:`, ...docstring(doc, "    ")];
  for (const item of items) out.push("", field(item, hideSensitive), ...docstring(itemDoc(item), "    "));
  if (extra.length > 0) out.push("", ...extra);
  return out;
}

/** The generated Python module, byte for byte. Throws TypesError when no types can be generated. */
export function generatePythonModule(revision: RevisionInput, opts: GenerateOptions): string {
  if (!VERSION.test(opts.generatorVersion)) throw new TypesError("the generator version is not printable");
  const items = checkRevision(revision, PYTHON_IMPLEMENTED_SEMANTICS_VERSIONS);
  const version = revision.semanticsVersion;
  const generator = `varlatch ${opts.generatorVersion}`;
  const publicItems = items.filter((i) => !i.sensitive);

  const out: string[] = [
    "# Generated by `varlatch types` from a Varlatch Contract Revision. Do not edit",
    "# this file: regenerate it with `varlatch types`, and check that it is current",
    "# with `varlatch types --check`.",
    "#",
    `# Contract Revision:          ${revision.id}`,
    `# Content hash:               ${revision.contentHash}`,
    `# Contract Semantics version: ${version}`,
    `# Generator:                  ${generator}`,
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
    '    "Config",',
    '    "ConfigError",',
    '    "ConfigIssue",',
    '    "GENERATED_FROM",',
    '    "LoadResult",',
    '    "PublicConfig",',
    '    "VarlatchWarning",',
    '    "load_config",',
    "]",
    "",
    "# The Contract Revision this file was generated from.",
    "GENERATED_FROM: _typing.Mapping[str, _typing.Any] = _types.MappingProxyType({",
    `    "revision_id": ${pyString(revision.id)},`,
    `    "content_hash": ${pyString(revision.contentHash)},`,
    `    "semantics_version": ${version},`,
    `    "generator": ${pyString(generator)},`,
    "})",
    "",
    "",
    ...dataclass(
      "Config",
      [
        "Every Contract item, converted.",
        "",
        "Numbers become int (whole numbers) or float, booleans become bool, and",
        "enums their values; URLs are validated and stay str. An item is optional",
        "(None when absent) unless the Contract requires it in every environment",
        "without a default: a default is applied only by `varlatch run --strict`,",
        "or by load_config(apply_defaults=True), and never replaces a withheld",
        "value. Read-only; sensitive items are kept out of repr().",
      ],
      items,
      true,
      [
        "    def public(self) -> PublicConfig:",
        '        """Only the non-sensitive items."""',
        "        return PublicConfig(**{name: getattr(self, name) for name in _VARLATCH_PUBLIC})",
      ],
    ),
    "",
    "",
    ...dataclass("PublicConfig", ["Only the non-sensitive Contract items."], publicItems, false),
    "",
    "",
    "@_dataclasses.dataclass(frozen=True, slots=True, kw_only=True)",
    "class LoadResult:",
    '    """What load_config() read."""',
    "",
    "    config: Config",
    '    """The converted configuration. Read-only."""',
    "    defaulted: tuple[str, ...]",
    '    """Items filled with their Contract default by apply_defaults."""',
    "    not_evaluated: tuple[str, ...]",
    '    """Absent items required only in some environments, unchecked without a run context."""',
    '    context: _typing.Literal["strict", "exported"] | None',
    '    """The run context\'s mode, or None when the application was started without one."""',
    "    warnings: tuple[str, ...]",
    '    """Warnings raised while loading, such as stale types."""',
    "",
    "",
    "def load_config(",
    "    *,",
    "    env: _typing.Mapping[str, str] | None = None,",
    "    apply_defaults: bool = False,",
    '    stale_types: _typing.Literal["warn", "raise"] = "warn",',
    "    require_context: bool = False,",
    "    on_warning: _typing.Callable[[str], None] | None = None,",
    ") -> LoadResult:",
    '    """Read and convert every item now.',
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
    '    stale_types: when the run context names a different Contract: "warn"',
    '        (default) or "raise".',
    "    require_context: raise when VARLATCH_RUN_CONTEXT is not set.",
    "    on_warning: receives warnings. Default: warnings.warn with VarlatchWarning.",
    '    """',
    "    options = {",
    '        "env": env,',
    '        "apply_defaults": apply_defaults,',
    '        "stale_types": stale_types,',
    '        "require_context": require_context,',
    '        "on_warning": on_warning,',
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
    '    if name == "config":',
    "        return _lazy(_VARLATCH_SCHEMA, Config, LoadResult)",
    '    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")',
    "",
    "",
    `_VARLATCH_PUBLIC = (${publicItems.map((i) => `${pyString(i.name)},`).join(" ")})`,
    "",
    "_VARLATCH_SCHEMA = {",
    '    "format": 1,',
    `    "revisionId": ${pyString(revision.id)},`,
    `    "contentHash": ${pyString(revision.contentHash)},`,
    `    "semanticsVersion": ${version},`,
    `    "generator": ${pyString(generator)},`,
    '    "items": [',
    ...items.map(
      (item) =>
        `        ${pyLiteral({
          name: item.name,
          type: item.type,
          required: item.required,
          ...(item.enumValues !== undefined ? { enumValues: item.enumValues } : {}),
          ...(item.defaultValue !== undefined ? { defaultValue: item.defaultValue } : {}),
        })},`,
    ),
    "    ],",
    "}",
    "",
    "",
    "# Varlatch Typed Accessor for Python. Copyright 2026 Robotsson. SPDX-License-Identifier: Apache-2.0",
    PYTHON_RUNTIME_SOURCE.trimEnd(),
    "",
  ];
  return out.join("\n");
}
