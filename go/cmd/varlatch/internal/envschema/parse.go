// SPDX-License-Identifier: Apache-2.0

// Package envschema is `varlatch contract push --schema`'s .env.schema
// parser (internal docs/design/go-cli.md, decision 8; ADR-0059 amendment 7),
// a port of packages/env-schema, which stays in TypeScript for the apps that
// import it. Both read one vector file (testdata/vectors/envschema.json,
// written from the package by apps/cli/test/go-vectors-envschema.test.ts).
//
// The format, as docs/reference/env-schema.md documents it:
//
//	Root decorators:  @defaultSensitive=true|false   @defaultRequired=true|false|infer
//	Item decorators:  @required  @optional
//	                  @required=env(name, ...)   root Environments, by name
//	                  @required=tier(development|staging|production)
//	                  @sensitive  @sensitive=false  @public
//	                  @type=string|number|integer|boolean|url|email|enum(a,b,...)
//	                  @example=... / @example="..."
//	                  @rotationGrace=<seconds>   1 to 2592000, once per item
//	                  @rotationHint=... / @rotationHint="..."   one line, once per item
//	Items:            NAME=            (no default)
//	                  NAME=literal     (defaultValue)
//	                  NAME=fn(...)     (dynamic resolver; no defaultValue)
//
// Anything decorator-shaped but unrecognized fails loudly (ADR-0013 §12).
//
// One difference from the package, on purpose: an error never quotes the
// file. The package's messages repeat part of a line it cannot read (an
// unrecognized line, text after a value, an unsupported form); here they
// name the line and the problem only, since a file given as --schema by
// mistake may be a .env holding values (go/README.md, "No message holds a
// value").
package envschema

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/contract"
)

// Required is DraftRequired: Kind "always", "never", "environments" (Names)
// or "tier" (Tier).
type Required struct {
	Kind  string
	Names []string
	Tier  string
}

// Item is DraftItem. Required and Sensitive are nil when the item does not
// say (the defaults apply).
type Item struct {
	Name                 string
	Required             *Required
	Sensitive            *bool
	Type                 string
	EnumValues           []string
	DefaultValue         *string
	Description          *string
	Example              *string
	RotationGraceSeconds *int64
	RotationHint         *string
}

// Draft is ContractDraft.
type Draft struct {
	DefaultSensitive bool
	DefaultRequired  Required
	Items            []Item
	// EnvironmentNames: every distinct name env(...) references, sorted.
	EnvironmentNames []string
}

// ParseError is EnvSchemaParseError: ".env.schema line <n>: <message>".
type ParseError struct {
	Line    int
	Message string
}

func (e *ParseError) Error() string { return formatMessage(e.Line, e.Message) }

// formatMessage is the package's ".env.schema line <n>: <reason>", or,
// when the CLI's fail-safe would read the line's colon and an at-sign
// after it as a URL's user name and password (a decorator such as
// "@rotationGrace" in the reason), "<reason> (.env.schema line <n>)": the
// Go CLI's failures put what holds an at-sign first and the explanation
// after it (go/README.md, "Diagnostics never print credential values").
func formatMessage(line int, reason string) string {
	m := ".env.schema line " + strconv.Itoa(line) + ": " + reason
	if clientctx.MaskUserinfoInText(m) != m {
		return reason + " (.env.schema line " + strconv.Itoa(line) + ")"
	}
	return m
}

// packageMessage is a packages/env-schema message, ".env.schema line <n>:
// <reason>".
var packageMessage = regexp.MustCompile(`(?s)^\.env\.schema line ([0-9]+): (.*)$`)

// valueFreeReasons are the package's reasons that quote part of the file,
// and the Go parser's words for them.
var valueFreeReasons = []struct {
	pattern *regexp.Regexp
	words   string
}{
	{regexp.MustCompile(`(?s)^Unrecognized line: .*$`), "Unrecognized line (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^Unexpected text after the value: .*$`), "Unexpected text after the value (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^Malformed decorator: .*$`), "Malformed decorator (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^Unsupported @required form: .*$`), "Unsupported @required form (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^Unsupported @sensitive form: .*$`), "Unsupported @sensitive form (not shown, since it may hold a value)"},
	{regexp.MustCompile(`(?s)^Unsupported @type: .*$`), "Unsupported @type (not shown, since it may hold a value)"},
}

// GoWording is a packages/env-schema message as the Go parser words it: a
// reason that quotes the file without the quotation, the two reasons whose
// colon precedes a decorator reworded ("as in"), and the order
// formatMessage gives. The vectors and the transcripts compare through it.
func GoWording(message string) string {
	m := packageMessage.FindStringSubmatch(message)
	if m == nil {
		return message
	}
	line, _ := strconv.Atoi(m[1])
	reason := m[2]
	for _, v := range valueFreeReasons {
		if v.pattern.MatchString(reason) {
			reason = v.words
			break
		}
	}
	reason = strings.Replace(reason, rotationHintNeedsValuePackage, rotationHintNeedsValue, 1)
	reason = strings.Replace(reason, forEnvRemovedPackage, forEnvRemoved, 1)
	return formatMessage(line, reason)
}

func fail(line int, message string) error { return &ParseError{Line: line, Message: message} }

// jsSpace is JavaScript's WhiteSpace and LineTerminator, what \s matches and
// trim() removes (the byte order mark included).
const jsSpace = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// notTerminator is what JavaScript's "." matches: anything but a line
// terminator.
const notTerminator = `[^\n\r\x{2028}\x{2029}]`

var (
	itemLine      = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)[` + jsSpace + `]*=(` + notTerminator + `*)$`)
	decorator     = regexp.MustCompile(`^@([A-Za-z][A-Za-z0-9]*)(?:=(` + notTerminator + `*)|(\(` + notTerminator + `*\)))?$`)
	functionValue = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\(` + notTerminator + `*\)$`)
	commentMark   = regexp.MustCompile(`^#+[` + jsSpace + `]?`)
	forEnv        = regexp.MustCompile(`^forEnv[` + jsSpace + `]*\(`)
	envForm       = regexp.MustCompile(`^env\(` + notTerminator + `*\)$`)
	tierForm      = regexp.MustCompile(`^tier\(` + notTerminator + `*\)$`)
	enumForm      = regexp.MustCompile(`^enum\((` + notTerminator + `*)\)$`)
	digits        = regexp.MustCompile(`^[0-9]+$`)
	lineBreak     = regexp.MustCompile(`\r?\n`)
)

func isSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func trim(s string) string      { return strings.TrimFunc(s, isSpace) }
func trimStart(s string) string { return strings.TrimLeftFunc(s, isSpace) }

// stripQuotes is the package's stripQuotes: trimmed, and one pair of
// matching quotes removed.
func stripQuotes(v string) string {
	t := trim(v)
	if len(t) >= 2 && (t[0] == '"' && t[len(t)-1] == '"' || t[0] == '\'' && t[len(t)-1] == '\'') {
		return t[1 : len(t)-1]
	}
	if t == `"` || t == `'` {
		// "\"".startsWith('"') && "\"".endsWith('"'): slice(1, -1) is empty.
		return ""
	}
	return t
}

const (
	forEnvRemoved = "forEnv(...) is not supported. Name this project's Varlatch environments instead, " +
		"for example @required=env(production, staging), or name a tier, as in @required=tier(production)"
	forEnvRemovedPackage = "forEnv(...) is not supported. Name this project's Varlatch environments instead, " +
		"for example @required=env(production, staging), or name a tier: @required=tier(production)"
	rotationHintNeedsValue        = "@rotationHint needs a value, as in @rotationHint=How to rotate it"
	rotationHintNeedsValuePackage = "@rotationHint needs a value: @rotationHint=How to rotate it"
)

// valueOf is the package's valueOf: an item's right-hand side without its
// trailing comment (a "#" after whitespace, outside quotes). A trailing
// decorator is an error: decorators go on their own line.
func valueOf(rhs string, line int) (string, error) {
	t := trimStart(rhs)
	if strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "'") {
		quote := t[0]
		closing := -1
		for i := 1; i < len(t); i++ {
			if t[i] == '\\' && quote == '"' {
				i++ // escapes are kept verbatim, but an escaped quote does not close
				continue
			}
			if t[i] == quote {
				closing = i
				break
			}
		}
		if closing < 0 {
			return "", fail(line, "Unterminated quoted value")
		}
		if err := trailing(t[closing+1:], line); err != nil {
			return "", err
		}
		return t[:closing+1], nil
	}
	// The search starts at the last whitespace before the value, so a value
	// that begins with "#" after whitespace is a comment.
	from := 0
	if lead := rhs[:len(rhs)-len(t)]; lead != "" {
		_, size := utf8.DecodeLastRuneInString(lead)
		from = len(lead) - size
	}
	at := -1
	for i, r := range rhs[from:] {
		if isSpace(r) {
			next := from + i + utf8.RuneLen(r)
			if next < len(rhs) && rhs[next] == '#' {
				at = from + i
				break
			}
		}
	}
	if at < 0 {
		return strings.TrimRightFunc(t, isSpace), nil
	}
	if err := trailing(rhs[at:], line); err != nil {
		return "", err
	}
	return trim(rhs[:at]), nil
}

func trailing(rest string, line int) error {
	t := trim(rest)
	if t == "" {
		return nil
	}
	if !strings.HasPrefix(t, "#") {
		return fail(line, "Unexpected text after the value (not shown, since it may hold a value)")
	}
	if strings.HasPrefix(trim(commentMark.ReplaceAllString(t, "")), "@") {
		return fail(line, "A decorator must be on its own comment line above the item, not after its value")
	}
	return nil
}

func parseList(inner string) []string {
	var out []string
	for _, s := range strings.Split(inner, ",") {
		if v := stripQuotes(trim(s)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

type pending struct {
	name     string
	value    string
	hasValue bool
	line     int
	raw      string
}

// Parse is parseEnvSchema.
func Parse(source string) (*Draft, error) {
	d := &Draft{DefaultSensitive: true, DefaultRequired: Required{Kind: "never"}}
	names := map[string]bool{}
	var decorators []pending
	var description []string
	sawItem := false
	for i, raw := range lineBreak.Split(source, -1) {
		lineNo := i + 1
		line := trim(raw)
		if line == "" {
			decorators, description = nil, nil
			continue
		}
		if strings.HasPrefix(line, "#") {
			comment := trim(commentMark.ReplaceAllString(line, ""))
			if m := decorator.FindStringSubmatchIndex(comment); m != nil {
				p := pending{name: comment[m[2]:m[3]], line: lineNo, raw: raw}
				switch {
				case m[4] >= 0:
					p.value, p.hasValue = comment[m[4]:m[5]], true
				case m[6] >= 0:
					p.value, p.hasValue = comment[m[6]:m[7]], true
				}
				// Root decorators apply at once while no item has been seen:
				// blank lines between the header block and the items keep them.
				if !sawItem && (p.name == "defaultSensitive" || p.name == "defaultRequired") {
					if err := d.applyRoot(p); err != nil {
						return nil, err
					}
				} else {
					decorators = append(decorators, p)
				}
			} else if strings.HasPrefix(comment, "@") {
				return nil, fail(lineNo, "Malformed decorator (not shown, since it may hold a value)")
			} else if comment != "" && !strings.HasPrefix(comment, "---") {
				description = append(description, comment)
			}
			continue
		}
		m := itemLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fail(lineNo, "Unrecognized line (not shown, since it may hold a value)")
		}
		sawItem = true
		value, err := valueOf(m[2], lineNo)
		if err != nil {
			return nil, err
		}
		item, err := buildItem(m[1], value, decorators, description, names)
		if err != nil {
			return nil, err
		}
		d.Items = append(d.Items, item)
		decorators, description = nil, nil
	}
	for n := range names {
		d.EnvironmentNames = append(d.EnvironmentNames, n)
	}
	sort.Slice(d.EnvironmentNames, func(i, j int) bool { return utf16Less(d.EnvironmentNames[i], d.EnvironmentNames[j]) })
	return d, nil
}

func (d *Draft) applyRoot(p pending) error {
	if p.name == "defaultSensitive" {
		if !p.hasValue || p.value != "true" && p.value != "false" {
			return fail(p.line, "@defaultSensitive must be true or false")
		}
		d.DefaultSensitive = p.value == "true"
		return nil
	}
	switch {
	case p.hasValue && p.value == "true":
		d.DefaultRequired = Required{Kind: "always"}
	case !p.hasValue || p.value == "false" || p.value == "infer":
		d.DefaultRequired = Required{Kind: "never"}
	default:
		return fail(p.line, "@defaultRequired must be true, false, or infer")
	}
	return nil
}

func buildItem(name, value string, decorators []pending, description []string, names map[string]bool) (Item, error) {
	item := Item{Name: name, Type: "string"}
	if len(description) > 0 {
		s := strings.Join(description, " ")
		item.Description = &s
	}
	if value != "" && !functionValue.MatchString(value) {
		s := stripQuotes(value)
		item.DefaultValue = &s
	}
	yes, no := true, false
	for _, d := range decorators {
		switch d.name {
		case "required":
			v := trim(d.value)
			switch {
			case !d.hasValue || v == "true":
				item.Required = &Required{Kind: "always"}
			case v == "false":
				item.Required = &Required{Kind: "never"}
			case forEnv.MatchString(v):
				return item, fail(d.line, forEnvRemoved)
			case envForm.MatchString(v):
				var list []string
				for _, n := range parseList(v[4 : len(v)-1]) {
					if !slices.Contains(list, n) {
						list = append(list, n)
					}
				}
				if len(list) == 0 {
					return item, fail(d.line, "env() needs at least one environment name")
				}
				for _, n := range list {
					names[n] = true
				}
				item.Required = &Required{Kind: "environments", Names: list}
			case tierForm.MatchString(v):
				tier := trim(v[5 : len(v)-1])
				if !slices.Contains(contract.Tiers, tier) {
					return item, fail(d.line, "tier() takes one of: "+strings.Join(contract.Tiers, ", "))
				}
				item.Required = &Required{Kind: "tier", Tier: tier}
			default:
				return item, fail(d.line, "Unsupported @required form (not shown, since it may hold a value)")
			}
		case "optional":
			item.Required = &Required{Kind: "never"}
		case "sensitive":
			switch {
			case !d.hasValue || d.value == "true":
				item.Sensitive = &yes
			case d.value == "false":
				item.Sensitive = &no
			default:
				return item, fail(d.line, "Unsupported @sensitive form (not shown, since it may hold a value)")
			}
		case "public":
			item.Sensitive = &no
		case "type":
			v := trim(d.value)
			if m := enumForm.FindStringSubmatch(v); m != nil {
				item.Type = "enum"
				item.EnumValues = parseList(m[1])
				if len(item.EnumValues) == 0 {
					return item, fail(d.line, "enum() needs at least one value")
				}
			} else if slices.Contains([]string{"string", "number", "integer", "boolean", "url", "email"}, v) {
				item.Type = v
			} else {
				return item, fail(d.line, "Unsupported @type (not shown, since it may hold a value)")
			}
		case "example":
			s := stripQuotes(d.value)
			item.Example = &s
		case "rotationGrace":
			// One physical line each, and never twice (ADR-0053).
			if item.RotationGraceSeconds != nil {
				return item, fail(d.line, "@rotationGrace appears twice for this item")
			}
			v := stripQuotes(d.value)
			seconds, err := strconv.ParseInt(v, 10, 64)
			if !digits.MatchString(v) || err != nil || seconds < 1 || seconds > 2_592_000 {
				return item, fail(d.line, "@rotationGrace takes whole seconds from 1 to 2592000 (30 days)")
			}
			item.RotationGraceSeconds = &seconds
		case "rotationHint":
			if item.RotationHint != nil {
				return item, fail(d.line, "@rotationHint appears twice for this item")
			}
			// Validated on the line as written: only ordinary spaces around the
			// value, and one pair of quotes, go (ADR-0053).
			at := strings.Index(d.raw, "@rotationHint=")
			if !d.hasValue || at < 0 {
				return item, fail(d.line, rotationHintNeedsValue)
			}
			payload := strings.Trim(d.raw[at+len("@rotationHint="):], " ")
			hint := payload
			if len(payload) >= 2 && (payload[0] == '"' || payload[0] == '\'') && payload[len(payload)-1] == payload[0] {
				hint = payload[1 : len(payload)-1]
			}
			if problem := contract.RotationHintProblem(hint); problem != "" {
				return item, fail(d.line, "@rotationHint: "+problem)
			}
			item.RotationHint = &hint
		case "docs", "icon", "tag":
			// Presentation-only decorators: not part of the Contract.
		default:
			return item, fail(d.line, "Unsupported decorator @"+d.name+": unknown decorators fail loudly rather than being dropped")
		}
	}
	return item, nil
}

// utf16Less is JavaScript's default sort order.
func utf16Less(a, b string) bool {
	ua, ub := utf16Units(a), utf16Units(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func utf16Units(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}
