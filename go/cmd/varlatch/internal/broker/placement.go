// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/matcher"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/targets"
)

// Where the Broker may substitute a Placeholder (ADR-0039 Decisions 1 to
// 5), apps/cli/src/placement.ts. Plan decides everything that can be
// decided from the request as the Agent sent it, before anything is
// exercised: which Placeholders sit at one of their item's targets, which
// are strays, and whether the request must be blocked. Apply then builds
// the substituted request from the exercised values; its failures happen
// after exercise. Nothing here opens a connection.
//
// Strings follow JavaScript's: a header value is the text Node.js reads
// (one character per byte of the wire), a value may hold a lone surrogate
// (lib/jsjson's WTF-8). The query and form offsets are bytes of the same
// texts TypeScript indexes in UTF-16 units, so every edit lands on the same
// characters.

// BodyLimit is BODY_LIMIT: a request body, as sent and as substituted.
const BodyLimit = 2 * 1024 * 1024

// maxJSONDepth is MAX_JSON_DEPTH.
const maxJSONDepth = 256

// token is TOKEN: a Placeholder's shape.
var token = regexp.MustCompile(`vlch_ph_v1_[0-9a-f]{32}`)

// Pair is one header as sent: its name and value.
type Pair struct{ Name, Value string }

// Request is RequestParts: the header pairs as sent, in order, without the
// hop-by-hop and proxy headers; the raw query without "?" (nil for none);
// the body.
type Request struct {
	Headers []Pair
	Query   *string
	Body    []byte
}

// Target is one substitution target: its kind (header, query, json or
// form) and location.
type Target struct{ Kind, Location string }

// ParseTarget is parseTarget.
func ParseTarget(raw string) (Target, error) {
	canonical, err := targets.Parse(raw)
	if err != nil {
		return Target{}, err
	}
	kind, location, _ := strings.Cut(canonical, ":")
	return Target{kind, location}, nil
}

// Placement is one Placeholder at one of its item's targets.
type Placement struct{ Item, Target string }

// Stray is a Placeholder in a surface where its item has no target.
type Stray struct{ Item, Surface string }

// Plan is PlacementPlan: Kind "pass" (with Strays), "block" (Status,
// Rule, Message) or "substitute" (Placements, Strays, and Apply).
type Plan struct {
	Kind       string
	Status     int
	Rule       string
	Message    string
	Placements []Placement
	Strays     []Stray
	apply      func(values map[string]string) Applied
}

// Applied is ApplyResult: the substituted request, or the rule and message
// it failed with.
type Applied struct {
	OK      bool
	Rule    string
	Message string
	Headers []Pair
	Query   *string
	Body    []byte
}

// Apply builds the substituted request from the exercised values.
func (p Plan) Apply(values map[string]string) Applied { return p.apply(values) }

// blocked is Blocked: names and pointers come from the Agent's request, so
// a Placeholder, or anything shaped like one, is never echoed.
type blocked struct{ rule, message string }

func block(rule, message string) blocked {
	return blocked{rule, token.ReplaceAllLiteralString(message, "<placeholder>")}
}

// PercentEncode is percentEncode: RFC 3986 percent-encoding of UTF-8, an
// unpaired surrogate as U+FFFD.
func PercentEncode(value string) string {
	encoded := apiclient.EncodeURIComponent(matcher.DeliveredText(value))
	var b strings.Builder
	for i := 0; i < len(encoded); i++ {
		switch c := encoded[i]; c {
		case '!', '\'', '(', ')', '*':
			b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c), 16)))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	pctByte = regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	uEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

// charOf is String.fromCharCode(code) for finding Placeholders: a code a
// Placeholder never holds stays out of one.
func charOf(code int64) string {
	if code >= 0xd800 && code <= 0xdfff {
		return "�"
	}
	return string(rune(code))
}

// lenientDecode is lenientDecode: every decoding a destination might
// apply, one pass after another, to find encoded Placeholders.
func lenientDecode(text string) string {
	text = strings.ReplaceAll(text, "+", " ")
	text = pctByte.ReplaceAllStringFunc(text, func(m string) string {
		code, _ := strconv.ParseInt(m[1:], 16, 32)
		return charOf(code)
	})
	return uEscape.ReplaceAllStringFunc(text, func(m string) string {
		code, _ := strconv.ParseInt(m[2:], 16, 32)
		return charOf(code)
	})
}

// latin1 is a buffer read as latin1: one character per byte.
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// decodeURIComponent is JavaScript's decodeURIComponent: false where it
// throws (a "%" without two hex digits, or escaped bytes that are not one
// UTF-8 character, a surrogate's included).
func decodeURIComponent(s string) (string, bool) {
	var b strings.Builder
	// unhex is the byte the escape at i ("%" and two hex digits) gives.
	unhex := func(i int) (byte, bool) {
		if i+2 >= len(s) {
			return 0, false
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		return byte(v), err == nil
	}
	for i := 0; i < len(s); {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		lead, ok := unhex(i)
		if !ok {
			return "", false
		}
		i += 3
		if lead < 0x80 {
			b.WriteByte(lead)
			continue
		}
		n := 0
		switch {
		case lead&0xe0 == 0xc0:
			n = 2
		case lead&0xf0 == 0xe0:
			n = 3
		case lead&0xf8 == 0xf0:
			n = 4
		default:
			return "", false
		}
		seq := []byte{lead}
		for len(seq) < n {
			if i >= len(s) || s[i] != '%' {
				return "", false
			}
			c, ok := unhex(i)
			if !ok || c&0xc0 != 0x80 {
				return "", false
			}
			seq = append(seq, c)
			i += 3
		}
		if !utf8.Valid(seq) {
			return "", false
		}
		b.Write(seq)
	}
	return b.String(), true
}

// tokenAt is one Placeholder of this run in a text, and where it starts.
type tokenAt struct {
	token string
	index int
}

// param is one name=value of a query or form body.
type param struct {
	name                   string
	rawValue               *string
	start, valueStart, end int
}

func decodeForm(raw, where string) string {
	decoded, ok := decodeURIComponent(strings.ReplaceAll(raw, "+", " "))
	if !ok {
		panic(block("invalid-body", "malformed percent-encoding in the "+where))
	}
	return decoded
}

func parseParams(text, where string) []param {
	var params []param
	at := 0
	for _, part := range strings.Split(text, "&") {
		eq := strings.IndexByte(part, '=')
		p := param{start: at, end: at + len(part)}
		if eq < 0 {
			p.name = decodeForm(part, where)
			p.valueStart = at + len(part)
		} else {
			p.name = decodeForm(part[:eq], where)
			v := part[eq+1:]
			p.rawValue = &v
			p.valueStart = at + eq + 1
		}
		params = append(params, p)
		at += len(part) + 1
	}
	return params
}

// jsonString is one string of a JSON body: the offsets of its quotes
// (inclusive start, exclusive end), its value, its pointer, and whether it
// is a key.
type jsonString struct {
	start, end int
	value      string
	pointer    string
	isKey      bool
}

var jsonLiteral = regexp.MustCompile(`^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)`)

func escapeToken(t string) string {
	return strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1")
}

// parseJSON is parseJson: a strict JSON parser that records every string's
// span and pointer, and refuses a duplicate key anywhere.
func parseJSON(text string) []jsonString {
	var strs []jsonString
	i := 0
	fail := func(rule, why string) {
		panic(block(rule, "the JSON body "+why))
	}
	ws := func() {
		for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
			i++
		}
	}
	at := func(k int) byte {
		if k < len(text) {
			return text[k]
		}
		return 0
	}
	parseString := func(pointer string, isKey bool) string {
		start := i
		i++
		var units []uint16
		for {
			if i >= len(text) {
				fail("invalid-body", "has an unterminated string")
			}
			c := text[i]
			if c == '"' {
				break
			}
			if c < ' ' {
				fail("invalid-body", "has a control character in a string")
			}
			if c != '\\' {
				r, size := utf8.DecodeRuneInString(text[i:])
				units = utf16.AppendRune(units, r)
				i += size
				continue
			}
			switch e := at(i + 1); e {
			case '"', '\\', '/':
				units = append(units, uint16(e))
				i += 2
			case 'b':
				units, i = append(units, '\b'), i+2
			case 'f':
				units, i = append(units, '\f'), i+2
			case 'n':
				units, i = append(units, '\n'), i+2
			case 'r':
				units, i = append(units, '\r'), i+2
			case 't':
				units, i = append(units, '\t'), i+2
			case 'u':
				if i+6 <= len(text) {
					if v, err := strconv.ParseUint(text[i+2:i+6], 16, 16); err == nil && !strings.ContainsAny(text[i+2:i+6], "+-") {
						units = append(units, uint16(v))
						i += 6
						continue
					}
				}
				fail("invalid-body", "has an invalid escape")
			default:
				fail("invalid-body", "has an invalid escape")
			}
		}
		i++
		value := jsval.FromUTF16(units)
		strs = append(strs, jsonString{start: start, end: i, value: value, pointer: pointer, isKey: isKey})
		return value
	}
	var parseValue func(pointer string, depth int)
	parseValue = func(pointer string, depth int) {
		if depth > maxJSONDepth {
			fail("invalid-body", "nests deeper than "+strconv.Itoa(maxJSONDepth)+" levels")
		}
		ws()
		switch at(i) {
		case '{':
			i++
			keys := map[string]bool{}
			ws()
			if at(i) == '}' {
				i++
				return
			}
			for {
				ws()
				if at(i) != '"' {
					fail("invalid-body", "has an object key that is not a string")
				}
				key := parseString(pointer, true)
				// A destination may keep the first or the last: never guess.
				if keys[key] {
					p := pointer
					if p == "" {
						p = "/"
					}
					fail("duplicate-key", `repeats the key "`+key+`" at "`+p+`"`)
				}
				keys[key] = true
				ws()
				if at(i) != ':' {
					fail("invalid-body", "is missing a colon")
				}
				i++
				parseValue(pointer+"/"+escapeToken(key), depth+1)
				ws()
				if at(i) == ',' {
					i++
					continue
				}
				if at(i) == '}' {
					i++
					return
				}
				fail("invalid-body", "has an unterminated object")
			}
		case '[':
			i++
			ws()
			if at(i) == ']' {
				i++
				return
			}
			for index := 0; ; index++ {
				parseValue(pointer+"/"+strconv.Itoa(index), depth+1)
				ws()
				if at(i) == ',' {
					i++
					continue
				}
				if at(i) == ']' {
					i++
					return
				}
				fail("invalid-body", "has an unterminated array")
			}
		case '"':
			parseString(pointer, false)
			return
		}
		m := jsonLiteral.FindString(text[i:])
		if m == "" {
			fail("invalid-body", "is not valid JSON")
		}
		i += len(m)
	}
	parseValue("", 0)
	ws()
	if i != len(text) {
		fail("invalid-body", "has trailing content")
	}
	return strs
}

// occurrence is one Placeholder of this run in the request.
type occurrence struct {
	item, surface, location string
	// target is the target it sits at, "" for none.
	target string
	apply  func(value string, out *output)
}

// output is one application's result, built fresh on every call.
type output struct {
	headers     []Pair
	query, body []edit
}

type edit struct {
	start, end int
	text       string
}

func splice(text string, edits []edit) string {
	sorted := slices.Clone(edits)
	slices.SortStableFunc(sorted, func(a, b edit) int { return b.start - a.start })
	out := text
	for _, e := range sorted {
		out = out[:e.start] + e.text + out[e.end:]
	}
	return out
}

func sameTokens(a, b []tokenAt) bool {
	if len(a) != len(b) {
		return false
	}
	x := make([]string, len(a))
	y := make([]string, len(b))
	for i := range a {
		x[i], y[i] = a[i].token, b[i].token
	}
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

var surfaceKinds = map[string][]string{"headers": {"header"}, "query": {"query"}, "body": {"json", "form"}}

// PlanPlacement is planPlacement: what to do with a request to an
// allowlisted destination. placeholders maps this run's Placeholders to
// their items; tgts are the ones varlatchd recorded on the Capability.
func PlanPlacement(req Request, placeholders map[string]string, tgts map[string][]Target) (plan Plan) {
	defer func() {
		if r := recover(); r != nil {
			b, ok := r.(blocked)
			if !ok {
				panic(r)
			}
			plan = Plan{Kind: "block", Status: 403, Rule: b.rule, Message: b.message}
		}
	}()
	return planPlacement(req, placeholders, tgts)
}

func planPlacement(req Request, placeholders map[string]string, tgts map[string][]Target) Plan {
	// Only this run's Placeholders count; any other lookalike is ordinary text.
	ours := func(text string) []tokenAt {
		var out []tokenAt
		for _, m := range token.FindAllStringIndex(text, -1) {
			if t := text[m[0]:m[1]]; placeholders[t] != "" {
				out = append(out, tokenAt{t, m[0]})
			}
		}
		return out
	}
	bodyLatin1 := latin1(req.Body)
	headerValues := make([]string, len(req.Headers))
	for i, h := range req.Headers {
		headerValues[i] = h.Value
	}
	query := ""
	if req.Query != nil {
		query = *req.Query
	}
	surfaces := [][2]string{{"headers", strings.Join(headerValues, "\n")}, {"query", query}, {"body", bodyLatin1}}

	// Items present anywhere, as written or visible only after decoding, in
	// the order a JavaScript Set keeps them.
	var present []string
	for _, s := range surfaces {
		for _, t := range append(ours(s[1]), ours(lenientDecode(s[1]))...) {
			if item := placeholders[t.token]; !slices.Contains(present, item) {
				present = append(present, item)
			}
		}
	}
	if len(present) == 0 {
		return Plan{Kind: "pass"}
	}

	targetsIn := func(item, surface string) []Target {
		var out []Target
		for _, t := range tgts[item] {
			if slices.Contains(surfaceKinds[surface], t.Kind) {
				out = append(out, t)
			}
		}
		return out
	}
	// targetedBy is the first present item that makes surface targeted.
	targetedBy := func(surface string) (string, bool) {
		sorted := slices.Clone(present)
		slices.SortFunc(sorted, jsval.CompareUTF16)
		for _, item := range sorted {
			if len(targetsIn(item, surface)) > 0 {
				return item, true
			}
		}
		return "", false
	}

	var occurrences []occurrence
	var bodyText *string

	// --- headers
	if _, ok := targetedBy("headers"); ok {
		for _, item := range present {
			for _, t := range targetsIn(item, "headers") {
				var same []Pair
				for _, h := range req.Headers {
					if strings.ToLower(h.Name) == t.Location {
						same = append(same, h)
					}
				}
				if len(same) > 1 {
					panic(block("repeated-header", item+`: the target header "`+t.Location+`" appears more than once`))
				}
				for _, h := range same {
					if strings.ContainsAny(h.Value, "\r\n") {
						panic(block("folded-header", item+`: the target header "`+t.Location+`" is line-folded`))
					}
				}
			}
		}
	}
	for index, h := range req.Headers {
		for _, tk := range ours(h.Value) {
			item := placeholders[tk.token]
			lower := strings.ToLower(h.Name)
			target := ""
			for _, t := range targetsIn(item, "headers") {
				if t.Location == lower {
					target = "header:" + t.Location
					break
				}
			}
			index, name, placeholder := index, h.Name, tk.token
			occurrences = append(occurrences, occurrence{
				item: item, surface: "headers", location: `header "` + lower + `"`, target: target,
				apply: func(secret string, out *output) {
					if strings.ContainsAny(secret, "\r\n\x00") {
						panic(block("unsafe-header-value", item+`: the value contains CR, LF, or NUL and cannot be carried in header "`+lower+`"`))
					}
					out.headers[index] = Pair{name, strings.Replace(out.headers[index].Value, placeholder, secret, 1)}
				},
			})
		}
	}

	// --- query strings and form bodies
	params := func(text, surface, kind, by string, edits string) {
		what, label := "query", "query parameter"
		if kind == "form" {
			what, label = "form body", "form field"
		}
		if strings.Contains(text, ";") {
			panic(block("separator", by+`: a ";" in the targeted `+what+", which some servers treat as a separator"))
		}
		list := parseParams(text, what)
		if !sameTokens(ours(text), ours(decodeForm(text, what))) {
			panic(block("encoded-placeholder", by+": an encoded placeholder in the targeted "+what))
		}
		for _, item := range present {
			for _, t := range targetsIn(item, surface) {
				if t.Kind != kind {
					continue
				}
				n := 0
				for _, p := range list {
					if p.name == t.Location {
						n++
					}
				}
				if n > 1 {
					panic(block("repeated-name", item+": the target "+label+` "`+t.Location+`" appears more than once`))
				}
			}
		}
		for _, tk := range ours(text) {
			item := placeholders[tk.token]
			var p *param
			for k := range list {
				if tk.index >= list[k].start && tk.index < list[k].end {
					p = &list[k]
					break
				}
			}
			exact := p != nil && tk.index >= p.valueStart && p.rawValue != nil && *p.rawValue == tk.token
			target := ""
			if exact {
				for _, t := range targetsIn(item, surface) {
					if t.Kind == kind && t.Location == p.name {
						target = kind + ":" + t.Location
						break
					}
				}
			}
			location := "the " + what
			if p != nil {
				location = label + ` "` + p.name + `"`
			}
			param := p
			occurrences = append(occurrences, occurrence{
				item: item, surface: surface, location: location, target: target,
				apply: func(secret string, out *output) {
					e := edit{param.valueStart, param.end, PercentEncode(secret)}
					if edits == "query" {
						out.query = append(out.query, e)
					} else {
						out.body = append(out.body, e)
					}
				},
			})
		}
	}
	inert := func(text, surface, location string) {
		for _, tk := range ours(text) {
			occurrences = append(occurrences, occurrence{item: placeholders[tk.token], surface: surface, location: location, apply: func(string, *output) {}})
		}
	}

	if queryBy, ok := targetedBy("query"); req.Query != nil && ok {
		params(*req.Query, "query", "query", queryBy, "query")
	} else {
		inert(query, "query", "the query")
	}

	// --- body
	if bodyBy, ok := targetedBy("body"); len(req.Body) > 0 && ok {
		for _, h := range req.Headers {
			if strings.ToLower(h.Name) == "content-encoding" && strings.ToLower(jsTrim(h.Value)) != "identity" {
				panic(block("content-encoding", bodyBy+": the body is targeted and has a Content-Encoding"))
			}
		}
		var types []string
		for _, h := range req.Headers {
			if strings.ToLower(h.Name) == "content-type" {
				types = append(types, h.Value)
			}
		}
		declaredType := ""
		if len(types) == 1 {
			declaredType = types[0]
		}
		parts := strings.Split(declaredType, ";")
		for k := range parts {
			parts[k] = jsTrim(parts[k])
		}
		media, mediaParams := strings.ToLower(parts[0]), parts[1:]
		kinds := map[string]bool{}
		for _, item := range present {
			for _, t := range targetsIn(item, "body") {
				kinds[t.Kind] = true
			}
		}
		matching := media == "application/json" && kinds["json"] || media == "application/x-www-form-urlencoded" && kinds["form"]
		if len(types) != 1 || !matching {
			declared := declaredType
			switch {
			case len(types) == 0:
				declared = "none"
			case len(types) > 1:
				declared = "repeated"
			}
			panic(block("content-type", bodyBy+": the body is targeted, and its Content-Type ("+declared+") does not match the target"))
		}
		for _, p := range mediaParams {
			if strings.HasPrefix(strings.ToLower(p), "charset=") {
				if !utf8Charset.MatchString(p) {
					panic(block("content-type", bodyBy+": the targeted body declares a charset other than UTF-8"))
				}
				break
			}
		}
		if !utf8.Valid(req.Body) {
			panic(block("invalid-body", bodyBy+": the targeted body is not valid UTF-8"))
		}
		text := string(req.Body)
		bodyText = &text
		if media == "application/json" {
			strs := parseJSON(text)
			var decoded []tokenAt
			for _, s := range strs {
				decoded = append(decoded, ours(s.value)...)
			}
			if !sameTokens(ours(text), decoded) {
				panic(block("encoded-placeholder", bodyBy+": an escaped placeholder in the targeted JSON body"))
			}
			for _, tk := range ours(text) {
				item := placeholders[tk.token]
				// Outside strings a Placeholder is not valid JSON, so one contains it.
				var s jsonString
				for _, x := range strs {
					if tk.index > x.start && tk.index < x.end {
						s = x
						break
					}
				}
				exact := !s.isKey && s.start == tk.index-1 && s.end == tk.index+len(tk.token)+1
				target := ""
				if exact {
					for _, t := range targetsIn(item, "body") {
						if t.Kind == "json" && t.Location == s.pointer {
							target = "json:" + t.Location
							break
						}
					}
				}
				pointer := s.pointer
				if pointer == "" {
					pointer = "/"
				}
				location := `JSON body at "` + pointer + `"`
				if s.isKey {
					location = `a JSON key in "` + pointer + `"`
				}
				start, end := tk.index, tk.index+len(tk.token)
				occurrences = append(occurrences, occurrence{
					item: item, surface: "body", location: location, target: target,
					apply: func(secret string, out *output) {
						quoted := jsjson.Stringify(secret)
						out.body = append(out.body, edit{start, end, string(quoted[1 : len(quoted)-1])})
					},
				})
			}
		} else {
			params(text, "body", "form", bodyBy, "body")
		}
	} else {
		inert(bodyLatin1, "body", "the body")
	}

	// --- the placement rules (Decision 3)
	var strays []Stray
	used := map[string]bool{}
	var placed []occurrence
	for _, o := range occurrences {
		if len(targetsIn(o.item, o.surface)) == 0 {
			strays = append(strays, Stray{o.item, o.surface})
			continue
		}
		if o.target == "" {
			panic(block("outside-target", o.item+": placeholder at "+o.location+", which is not a target"))
		}
		key := o.item + "\x00" + o.target
		if used[key] {
			panic(block("second-occurrence", o.item+": a second placeholder at "+o.target+"; each target is substituted at most once"))
		}
		used[key] = true
		placed = append(placed, o)
	}
	if len(placed) == 0 {
		return Plan{Kind: "pass", Strays: strays}
	}
	placements := make([]Placement, len(placed))
	for k, o := range placed {
		placements[k] = Placement{o.item, o.target}
	}
	return Plan{
		Kind:       "substitute",
		Strays:     strays,
		Placements: placements,
		apply: func(values map[string]string) (result Applied) {
			defer func() {
				if r := recover(); r != nil {
					b, ok := r.(blocked)
					if !ok {
						panic(r)
					}
					result = Applied{Rule: b.rule, Message: b.message}
				}
			}()
			out := &output{headers: slices.Clone(req.Headers)}
			for _, o := range placed {
				value, ok := values[o.item]
				if !ok {
					panic(block("missing-value", o.item+": the exercise did not return it"))
				}
				o.apply(value, out)
			}
			q := req.Query
			if req.Query != nil && len(out.query) > 0 {
				s := splice(*req.Query, out.query)
				q = &s
			}
			body := req.Body
			if bodyText != nil && len(out.body) > 0 {
				body = []byte(splice(*bodyText, out.body))
			}
			if len(body) > BodyLimit {
				panic(block("body-limit", "the substituted body exceeds the "+strconv.Itoa(BodyLimit)+"-byte limit"))
			}
			return Applied{OK: true, Headers: out.headers, Query: q, Body: body}
		},
	}
}

var utf8Charset = regexp.MustCompile(`(?i)^charset="?utf-8"?$`)

// jsTrim is String.prototype.trim: JavaScript's whitespace and line
// terminators at both ends.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
			return true
		}
		return r >= 0x2000 && r <= 0x200a
	})
}
