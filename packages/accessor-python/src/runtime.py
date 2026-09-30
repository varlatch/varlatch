# SPDX-License-Identifier: Apache-2.0
# The Varlatch Typed Accessor for Python. Every module `varlatch types`
# generates for Python carries this runtime inline, after the URL parser in
# whatwg_url.py, so an application needs nothing but the generated file and
# the standard library.
#
# It reads the environment (os.environ by default), converts each value with
# Contract Semantics version 2, and never writes to the environment. It is a
# second implementation of the rules in @varlatch/contract, held to the same
# golden vectors (ADR-0041). No message it produces contains a value, and the
# frames that raise ConfigError hold no value and no environment mapping.
#
# Names that start with an underscore are internal: the generated module
# exports only ConfigError, ConfigIssue, VarlatchWarning, and its own classes.
import json as _json
import math as _math
import os as _os
import re as _re
import typing as _typing
import warnings as _warnings

from whatwg_url import _url_verdict  # varlatch: embed-drop

_RUN_CONTEXT = "VARLATCH_RUN_CONTEXT"
# The schema format generated modules embed. A change old runtimes cannot
# read bumps it.
_SCHEMA_FORMAT = 1
# Every version the Contract Semantics define, and those this runtime
# implements: only versions that define conversion.
_SEMANTICS_VERSIONS = (1, 2, 3)
_IMPLEMENTED_VERSIONS = (2, 3)
_TIERS = ("development", "staging", "production")
_SERVER_STATUSES = ("delivered", "withheld", "notStored")
_DELIVERIES = ("varlatch", "inherited", "default", "absent")


class ConfigIssue(_typing.NamedTuple):
    """One problem with the configuration: an item name and a reason, never a value."""

    name: str
    reason: str


def _format_issues(issues: "tuple[ConfigIssue, ...]") -> str:
    count = f"{len(issues)} {'problem' if len(issues) == 1 else 'problems'}"
    return "\n".join([f"Varlatch configuration is invalid ({count}):", *(f"  {i.name}: {i.reason}" for i in issues)])


class ConfigError(Exception):
    """Every problem found, by item name and reason. It never contains a value."""

    def __init__(self, issues: "_typing.Iterable[ConfigIssue]") -> None:
        self.issues: "tuple[ConfigIssue, ...]" = tuple(ConfigIssue(str(i[0]), str(i[1])) for i in issues)
        super().__init__(_format_issues(self.issues))


class VarlatchWarning(UserWarning):
    """A warning from the Typed Accessor, such as types generated from another Contract."""


# Contract Semantics version 2 --------------------------------------------
#
# Every pattern is ASCII-only and matched against the whole string: Python's
# defaults differ from the reference implementation's (`\d` matches non-ASCII
# digits, IGNORECASE folds U+017F to s, `$` matches before a final newline,
# and `\s` is a different set), and the portability vectors pin each case.

_NUMBER = _re.compile(r"-?([0-9]+)(?:\.([0-9]+))?")
# Version 3 integers: an optional "-" and ASCII digits only, never a fraction.
_INTEGER = _re.compile(r"-?([0-9]+)")
_BOOLEAN = _re.compile(r"true|false|1|0", _re.IGNORECASE | _re.ASCII)
# JavaScript's \s: WhiteSpace and LineTerminator, including U+FEFF, and not
# U+001C..U+001F or U+0085, which Python's \s includes.
_JS_SPACE = "\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_EMAIL = _re.compile(f"[^{_JS_SPACE}@]+@[^{_JS_SPACE}@]+\\.[^{_JS_SPACE}@]+")
# 2^53 - 1: the largest integer a double represents exactly.
_MAX_EXACT = "9007199254740991"

_IDN_REASON = "is an internationalized URL; install the ada-url package to validate it"

_UNSET = object()
_ada_module: "object" = _UNSET


def _ada_verdict(value: str) -> "bool | None":
    """The ada-url package's verdict (the parser Node uses), or None without it."""
    global _ada_module
    if _ada_module is _UNSET:
        try:
            import ada_url as module
        except Exception:
            module = None
        _ada_module = module
    if _ada_module is None:
        return None
    try:
        return bool(_ada_module.check_url(value))  # type: ignore[attr-defined]
    except Exception:
        return None


def _whole(value: str, digits: str) -> int:
    # int() converts the digits without their leading zeros, which the bound
    # check already measured: the text itself may carry more zeros than
    # int()'s limit on digits in a string. int has no negative zero, so -0 is 0.
    number = int(digits)
    return -number if value.startswith("-") else number


def _parse_number(value: str) -> "tuple[bool, object]":
    match = _NUMBER.fullmatch(value)
    if match is None:
        return (False, "must be a number")
    integer = match.group(1).lstrip("0") or "0"
    fraction = match.group(2)
    fraction_nonzero = fraction is not None and fraction.strip("0") != ""
    too_large = len(integer) > len(_MAX_EXACT) or (
        len(integer) == len(_MAX_EXACT) and (integer > _MAX_EXACT or (integer == _MAX_EXACT and fraction_nonzero))
    )
    if too_large:
        return (False, "must be a number no larger in magnitude than 2^53 - 1")
    # Integral text converts to int, so counts, sizes, and ports work with
    # slicing and range(); a fraction converts to the nearest double.
    if fraction is None:
        return (True, _whole(value, integer))
    return (True, float(value))


def _parse_integer(value: str) -> "tuple[bool, object]":
    match = _INTEGER.fullmatch(value)
    if match is None:
        return (False, "must be a whole number")
    digits = match.group(1).lstrip("0") or "0"
    if len(digits) > len(_MAX_EXACT) or (len(digits) == len(_MAX_EXACT) and digits > _MAX_EXACT):
        return (False, "must be a whole number no larger in magnitude than 2^53 - 1")
    return (True, _whole(value, digits))


# An evaluator before version 3 that meets an integer item fails closed, as
# the reference implementation does.
_BEFORE_INTEGER = "has a type this Contract Semantics version does not define (integer needs version 3)"


def _parse_url(value: str) -> "tuple[bool, object]":
    verdict = _url_verdict(value)
    if verdict is None:
        # An internationalized host needs UTS #46, which only ada-url has
        # here. Without it the value is rejected, never guessed.
        verdict = _ada_verdict(value)
        if verdict is None:
            return (False, _IDN_REASON)
    return (True, value) if verdict else (False, "must be a valid URL")


def _parse(item: "dict[str, object]", value: str, version: int = 3) -> "tuple[bool, object]":
    """Validation and conversion as one step, at a semantics version that
    defines conversion: (True, value) or (False, reason)."""
    kind = item["type"]
    if kind == "number":
        return _parse_number(value)
    if kind == "integer":
        return _parse_integer(value) if version >= 3 else (False, _BEFORE_INTEGER)
    if kind == "string":
        return (True, value)
    if kind == "boolean":
        if _BOOLEAN.fullmatch(value) is None:
            return (False, "must be a boolean")
        return (True, value.lower() in ("true", "1"))
    if kind == "url":
        return _parse_url(value)
    if kind == "email":
        return (True, value) if _EMAIL.fullmatch(value) is not None else (False, "must be an email address")
    if kind == "enum":
        allowed = _typing.cast("list[str]", item.get("enumValues") or [])
        # Exact membership: no case folding and no Unicode normalization.
        return (True, value) if value in allowed else (False, "must be one of: " + ", ".join(allowed))
    return (False, "has a type this accessor does not know; regenerate the types with varlatch types")


def _required_applies(item: "dict[str, object]", environment: "dict[str, str]") -> bool:
    required = _typing.cast("dict[str, object]", item["required"])
    kind = required["kind"]
    if kind == "always":
        return True
    if kind == "never":
        return False
    selector = _typing.cast("dict[str, object]", required["selector"])
    if selector["kind"] == "tier":
        return selector["tier"] == environment["tier"]
    return environment["rootId"] in _typing.cast("list[str]", selector["environmentIds"])


def _missing_when_absent(item: "dict[str, object]", environment: "dict[str, str]") -> bool:
    # A default, even an empty string, satisfies requiredness.
    return _required_applies(item, environment) and "defaultValue" not in item


# The run context ------------------------------------------------------------

_IDENTIFIER = _re.compile(r"[A-Za-z0-9_-]{1,128}")
_CONTENT_HASH = _re.compile(r"sha256:[0-9a-f]{64}")


class _RunContext(_typing.NamedTuple):
    mode: str
    contract_revision_id: str
    contract_hash: str
    semantics_version: int
    environment: "dict[str, str]"
    items: "dict[str, tuple[str, str]]"


def _is_json_number(value: object) -> bool:
    # JSON numbers only: a boolean is never a number here, unlike isinstance.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _json_integer(value: object) -> "int | None":
    """The value as an integer when JSON's number reading makes it one: 2, 2.0, and 2e0 are 2."""
    if not _is_json_number(value):
        return None
    number = _typing.cast("int | float", value)
    if isinstance(number, float) and (not _math.isfinite(number) or not number.is_integer()):
        return None
    return int(number)


def _reject_constant(name: str) -> object:
    # NaN, Infinity, and -Infinity are not JSON.
    raise ValueError("not JSON")


def _parse_run_context(raw: str) -> "_RunContext | str":
    """The parsed context, or the reason it cannot be read. Nothing from the context is echoed."""
    try:
        data = _json.loads(raw, parse_constant=_reject_constant)
        readable = True
    except (ValueError, RecursionError):
        readable = False
    # Decided outside the except block, so no parser error (which holds the
    # text) is ever chained to what the caller sees.
    if not readable:
        return "is not valid JSON"
    if not isinstance(data, dict):
        return "is not a JSON object"
    version = data.get("v")
    if not (_is_json_number(version) and version == 1):
        return "has a version this accessor does not read (it reads v 1); regenerate the types with the varlatch CLI that starts the application"
    mode = data.get("mode")
    if not isinstance(mode, str) or mode not in ("strict", "exported"):
        return "is malformed: mode"
    revision = data.get("contractRevisionId")
    if not isinstance(revision, str) or _IDENTIFIER.fullmatch(revision) is None:
        return "is malformed: contractRevisionId"
    content_hash = data.get("contractHash")
    if not isinstance(content_hash, str) or _CONTENT_HASH.fullmatch(content_hash) is None:
        return "is malformed: contractHash"
    semantics_version = _json_integer(data.get("semanticsVersion"))
    if semantics_version is None:
        return "is malformed: semanticsVersion"
    environment = data.get("environment")
    if (
        not isinstance(environment, dict)
        or not isinstance(environment.get("rootId"), str)
        or not isinstance(environment.get("tier"), str)
        or environment["tier"] not in _TIERS
    ):
        return "is malformed: environment"
    entries = data.get("items")
    if not isinstance(entries, dict):
        return "is malformed: items"
    items: "dict[str, tuple[str, str]]" = {}
    for name, entry in entries.items():
        server = entry.get("server") if isinstance(entry, dict) else None
        delivery = entry.get("delivery") if isinstance(entry, dict) else None
        if not (isinstance(server, str) and server in _SERVER_STATUSES) or not (
            isinstance(delivery, str) and delivery in _DELIVERIES
        ):
            return "is malformed: an entry in items"
        items[name] = (server, delivery)
    return _RunContext(
        mode=mode,
        contract_revision_id=revision,
        contract_hash=content_hash,
        semantics_version=semantics_version,
        environment={"rootId": environment["rootId"], "tier": environment["tier"]},
        items=items,
    )


# Loading ----------------------------------------------------------------------


class _Outcome(_typing.NamedTuple):
    values: "dict[str, object]"
    issues: "tuple[ConfigIssue, ...]"
    defaulted: "tuple[str, ...]"
    not_evaluated: "tuple[str, ...]"
    context: "str | None"
    warnings: "tuple[str, ...]"


def _problem(name: str, reason: str) -> _Outcome:
    return _Outcome({}, (ConfigIssue(name, reason),), (), (), None, ())


def _absent_reason(recorded: "tuple[str, str] | None") -> str:
    if recorded is not None and recorded[0] == "withheld":
        return "required in this environment, withheld by the server, and absent"
    if recorded is not None and recorded[1] != "absent":
        return "required in this environment; the run context records it as delivered, but it is absent from the environment"
    return "required in this environment and absent"


def _is_text(value: str) -> bool:
    # On POSIX, bytes that are not UTF-8 arrive as lone surrogates.
    return not any("\ud800" <= c <= "\udfff" for c in value)


def _evaluate(
    schema: "dict[str, object]",
    source: "_typing.Mapping[str, object]",
    options: "dict[str, object]",
    warn: "_typing.Callable[[str], None]",
) -> _Outcome:
    """Read and convert every item. Returns problems rather than raising, so no
    frame that raises ever holds a value or the environment mapping."""
    if not isinstance(schema, dict) or schema.get("format") != _SCHEMA_FORMAT or not isinstance(schema.get("items"), list):
        return _problem("generated types", "are in a format this accessor does not read; regenerate them with varlatch types")
    version = schema.get("semanticsVersion")
    implemented = ", ".join(str(v) for v in _IMPLEMENTED_VERSIONS)
    if _json_integer(version) not in _SEMANTICS_VERSIONS:
        return _problem(
            "generated types",
            f"use Contract Semantics version {version}, which this accessor does not implement (it implements {implemented}); regenerate them with varlatch types",
        )
    if _json_integer(version) not in _IMPLEMENTED_VERSIONS:
        return _problem(
            "generated types",
            f"use Contract Semantics version {version}, which defines no conversion; activate a revision at version {' or '.join(str(v) for v in _IMPLEMENTED_VERSIONS)} and regenerate them with varlatch types",
        )
    semantics = _typing.cast(int, _json_integer(version))

    warnings: "list[str]" = []

    def emit(message: str) -> None:
        warnings.append(message)
        warn(message)

    raw_context = source.get(_RUN_CONTEXT)
    context: "_RunContext | None" = None
    if raw_context is not None:
        if not isinstance(raw_context, str):
            return _problem(_RUN_CONTEXT, "is not a string")
        parsed = _parse_run_context(raw_context)
        if isinstance(parsed, str):
            return _problem(_RUN_CONTEXT, parsed)
        context = parsed
        if context.semantics_version != version:
            return _problem(
                _RUN_CONTEXT,
                f"names Contract Semantics version {context.semantics_version}, but these types use version {version}; regenerate them with varlatch types",
            )
        # The content hash, not the revision ID: an identical Contract
        # activated again as a new revision is not stale.
        if context.contract_hash != schema.get("contentHash"):
            message = (
                f"the types are stale: they were generated from the Contract with content hash {schema.get('contentHash')}, "
                f"and this run uses {context.contract_hash} (revision {context.contract_revision_id}); regenerate them with varlatch types"
            )
            if options.get("stale_types") == "raise":
                return _problem(_RUN_CONTEXT, message)
            emit(message)
    elif options.get("require_context") is True:
        return _problem(
            _RUN_CONTEXT,
            "is not set, and require_context is on: start the application with varlatch run --strict or varlatch run --export-context",
        )

    issues: "list[ConfigIssue]" = []
    values: "dict[str, object]" = {}
    defaulted: "list[str]" = []
    not_evaluated: "list[str]" = []
    for item in _typing.cast("list[dict[str, object]]", schema["items"]):
        name = _typing.cast(str, item["name"])
        raw = source.get(name)
        # Presence comes from the environment: a present item is read and
        # validated whatever the run context says about how it got there.
        if raw is not None:
            if not isinstance(raw, str):
                issues.append(ConfigIssue(name, "is not a string in the environment"))
                continue
            if not _is_text(raw):
                issues.append(ConfigIssue(name, "is not valid UTF-8 in the environment"))
                continue
            ok, result = _parse(item, raw, semantics)
            if ok:
                values[name] = result
            else:
                issues.append(ConfigIssue(name, _typing.cast(str, result)))
            continue

        recorded = context.items.get(name) if context is not None else None
        if context is not None and context.mode == "strict":
            # Strict startup already applied defaults where they belong.
            if _required_applies(item, context.environment):
                issues.append(ConfigIssue(name, _absent_reason(recorded)))
            continue
        withheld = recorded is not None and recorded[0] == "withheld"
        # A default never stands in for a value the server withheld.
        if options.get("apply_defaults") is True and "defaultValue" in item and not withheld:
            ok, result = _parse(item, _typing.cast(str, item["defaultValue"]), semantics)
            if ok:
                values[name] = result
                defaulted.append(name)
            else:
                issues.append(ConfigIssue(name, f"the Contract default {result}"))
            continue
        if context is not None:
            missing = (
                _required_applies(item, context.environment)
                if withheld
                else _missing_when_absent(item, context.environment)
            )
            if missing:
                issues.append(ConfigIssue(name, _absent_reason(recorded)))
        elif _typing.cast("dict[str, object]", item["required"])["kind"] == "selector":
            # Requiredness depends on the Environment, which only a run
            # context names.
            if "defaultValue" not in item:
                not_evaluated.append(name)
        elif _missing_when_absent(item, {"rootId": "", "tier": "production"}):
            # "always" and "never" do not depend on the Environment.
            issues.append(ConfigIssue(name, "required in every environment and absent"))
    if issues:
        return _Outcome({}, tuple(issues), (), (), None, ())
    return _Outcome(
        values,
        (),
        tuple(defaulted),
        tuple(not_evaluated),
        context.mode if context is not None else None,
        tuple(warnings),
    )


def _default_warning(message: str) -> None:
    _warnings.warn(message, VarlatchWarning, stacklevel=2)


def _check_options(options: "dict[str, object]") -> None:
    unknown = sorted(set(options) - {"apply_defaults", "stale_types", "require_context", "on_warning"})
    if unknown:
        raise TypeError(f"load_config() got unexpected options: {', '.join(unknown)}")
    if options.get("stale_types", "warn") not in ("warn", "raise"):
        raise ValueError('stale_types must be "warn" or "raise"')
    on_warning = options.get("on_warning")
    if on_warning is not None and not callable(on_warning):
        raise TypeError("on_warning must be callable")


def _load(schema: "dict[str, object]", config_class: type, result_class: type, options: "dict[str, object]") -> object:
    """Read, convert, and check everything now; raise one ConfigError listing every problem.

    `options` may carry the environment under "env"; it is taken out before
    anything is evaluated, so no frame that raises holds it.
    """
    source = options.pop("env", None)
    _check_options(options)
    if source is None:
        source = _os.environ
    warn = _typing.cast("_typing.Callable[[str], None]", options.get("on_warning") or _default_warning)
    outcome = _evaluate(schema, _typing.cast("_typing.Mapping[str, object]", source), options, warn)
    source = None
    if outcome.issues:
        issues = outcome.issues
        outcome = None
        raise ConfigError(issues)
    config = config_class(**outcome.values)
    return result_class(
        config=config,
        defaulted=outcome.defaulted,
        not_evaluated=outcome.not_evaluated,
        context=outcome.context,
        warnings=outcome.warnings,
    )


_lazy_outcomes: "dict[int, tuple[bool, object]]" = {}


def _lazy(schema: "dict[str, object]", config_class: type, result_class: type) -> object:
    """The configuration with the default options, loaded on first use and
    cached. A failed load raises a ConfigError with the same issues on every
    later use, so no use ever sees a partial configuration."""
    key = id(schema)
    cached = _lazy_outcomes.get(key)
    if cached is None:
        try:
            result = _load(schema, config_class, result_class, {})
            cached = (True, getattr(result, "config"))
        except ConfigError as error:
            cached = (False, error.issues)
        _lazy_outcomes[key] = cached
    if cached[0]:
        return cached[1]
    raise ConfigError(_typing.cast("tuple[ConfigIssue, ...]", cached[1]))
