// SPDX-License-Identifier: AGPL-3.0-or-later

// Package openapicheck checks /v1 exchanges against the OpenAPI document
// (packages/protocol/openapi.yaml) in varlatchd's Go tests, as the
// TypeScript server's tests check theirs (services/varlatchd/test/helpers/
// openapi-check.ts; step 4 decision 3): the status is documented for the
// operation, the content type is one it lists, a JSON body validates
// against its schema with every object closed (a member the document does
// not name is a mismatch), errors included; and, when asked, a request body
// the server accepted (2xx) validates against the operation's. ALLOWED
// lists the mismatches excused, each with its reason (the TypeScript
// list's). Test support only: nothing in a build imports it.
package openapicheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var printer = message.NewPrinter(language.English)

// Mismatch is one way an exchange differs from the document.
type Mismatch struct {
	Kind      string // the TypeScript check's MismatchKind
	Operation string // "METHOD /v1/template", or the concrete path
	Status    int
	Detail    string
}

func (m Mismatch) String() string {
	return fmt.Sprintf("%s %d %s: %s", m.Operation, m.Status, m.Kind, m.Detail)
}

// Exchange is one request and its response.
type Exchange struct {
	Method, Path        string
	RequestContentType  string
	RequestBody         []byte // nil: none
	Status              int
	ResponseContentType string
	ResponseBody        []byte
}

// Allowance excuses a mismatch, with its reason; with Field (a JSON
// pointer) only that undocumented member.
type Allowance struct {
	Kind, Operation string
	Status          int
	Field           string
	Reason          string
}

// ALLOWED is the TypeScript check's list.
var ALLOWED = []Allowance{{
	Kind: "request-undocumented-field", Operation: "PATCH /v1/organizations/{org}", Status: 200, Field: "/slug",
	Reason: "a test sends slug on purpose to prove a rename never changes it; the server drops unknown fields",
}}

type operation struct {
	method, template string
	segments         []string
	op               map[string]any
}

type state struct {
	spec     map[string]any
	ops      []operation
	compiler *jsonschema.Compiler
	compiled map[string]*jsonschema.Schema
	mu       sync.Mutex
}

var (
	loaded  *state
	loadErr error
	once    sync.Once
)

const specURL = "file:///openapi.json"

// SpecPath is the OpenAPI document.
func SpecPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "packages", "protocol", "openapi.yaml")
}

func load() (*state, error) {
	once.Do(func() {
		raw, err := os.ReadFile(SpecPath())
		if err != nil {
			loadErr = err
			return
		}
		var y any
		if err := yaml.Unmarshal(raw, &y); err != nil {
			loadErr = err
			return
		}
		b, err := json.Marshal(y)
		if err != nil {
			loadErr = err
			return
		}
		var spec map[string]any
		if err := json.Unmarshal(b, &spec); err != nil {
			loadErr = err
			return
		}
		s := &state{spec: spec, compiled: map[string]*jsonschema.Schema{}}
		paths, _ := spec["paths"].(map[string]any)
		for p, item := range paths {
			for _, m := range []string{"get", "post", "put", "patch", "delete"} {
				op, ok := item.(map[string]any)[m].(map[string]any)
				if !ok {
					continue
				}
				t := "/v1" + p
				s.ops = append(s.ops, operation{method: strings.ToUpper(m), template: t, segments: strings.Split(t, "/"), op: op})
			}
		}
		sort.Slice(s.ops, func(i, j int) bool { return s.ops[i].template+s.ops[i].method < s.ops[j].template+s.ops[j].method })
		closed, err := jsonschema.UnmarshalJSON(bytes.NewReader(mustJSON(closeWorld(spec))))
		if err != nil {
			loadErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.AssertFormat()
		for _, f := range formats() {
			c.RegisterFormat(f)
		}
		if err := c.AddResource(specURL, closed); err != nil {
			loadErr = err
			return
		}
		s.compiler = c
		loaded = s
	})
	return loaded, loadErr
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	}
	return 0, false
}

// formats are the OpenAPI formats the TypeScript check adds to ajv's.
func formats() []*jsonschema.Format {
	integer := func(lo, hi float64) func(any) error {
		return func(v any) error {
			f, ok := number(v)
			if !ok {
				return nil
			}
			if f != math.Trunc(f) || f < lo || f >= hi {
				return errors.New("not an integer in range")
			}
			return nil
		}
	}
	accept := func(any) error { return nil }
	b64 := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return []*jsonschema.Format{
		{Name: "int32", Validate: integer(-(1 << 31), 1<<31)},
		{Name: "int64", Validate: integer(math.Inf(-1), math.Inf(1))},
		{Name: "float", Validate: accept}, {Name: "double", Validate: accept}, {Name: "password", Validate: accept}, {Name: "binary", Validate: accept},
		{Name: "byte", Validate: func(v any) error {
			if s, ok := v.(string); ok && !b64.MatchString(s) {
				return errors.New("not base64")
			}
			return nil
		}},
	}
}

// closeWorld is the TypeScript check's: every object schema closed where
// it is used (unevaluatedProperties: false), never on a direct allOf
// member, a schema the document leaves open on purpose kept open.
func closeWorld(spec map[string]any) map[string]any {
	var cp map[string]any
	_ = json.Unmarshal(mustJSON(spec), &cp)
	visited := map[string]bool{}
	var close func(node any, inAllOf bool, path string)
	close = func(node any, inAllOf bool, path string) {
		n, ok := node.(map[string]any)
		if !ok {
			return
		}
		_, ap := n["additionalProperties"]
		_, up := n["unevaluatedProperties"]
		_, ref := n["$ref"].(string)
		_, props := n["properties"]
		_, all := n["allOf"]
		_, one := n["oneOf"]
		_, anyOf := n["anyOf"]
		if !inAllOf && !ap && !up && (ref || props || all || one || anyOf) {
			n["unevaluatedProperties"] = false
		}
		if visited[path] {
			return
		}
		visited[path] = true
		if p, ok := n["properties"].(map[string]any); ok {
			for k, c := range p {
				close(c, false, path+"/properties/"+k)
			}
		}
		for _, key := range []string{"patternProperties", "$defs"} {
			if p, ok := n[key].(map[string]any); ok {
				for k, c := range p {
					close(c, false, path+"/"+key+"/"+k)
				}
			}
		}
		close(n["items"], false, path+"/items")
		if a, ok := n["additionalProperties"].(map[string]any); ok {
			close(a, false, path+"/additionalProperties")
		}
		for i, c := range list(n["prefixItems"]) {
			close(c, false, fmt.Sprintf("%s/prefixItems/%d", path, i))
		}
		for i, c := range list(n["allOf"]) {
			close(c, true, fmt.Sprintf("%s/allOf/%d", path, i))
		}
		for _, key := range []string{"oneOf", "anyOf"} {
			for i, c := range list(n[key]) {
				close(c, false, fmt.Sprintf("%s/%s/%d", path, key, i))
			}
		}
	}
	components, _ := cp["components"].(map[string]any)
	if schemas, ok := components["schemas"].(map[string]any); ok {
		for k, s := range schemas {
			close(s, true, "#/components/schemas/"+k)
		}
	}
	contents := func(holder any, path string) {
		h, _ := holder.(map[string]any)
		c, _ := h["content"].(map[string]any)
		for k, media := range c {
			m, _ := media.(map[string]any)
			close(m["schema"], false, path+"/content/"+k)
		}
	}
	for _, key := range []string{"responses", "requestBodies"} {
		if rs, ok := components[key].(map[string]any); ok {
			for k, r := range rs {
				contents(r, "#/components/"+key+"/"+k)
			}
		}
	}
	paths, _ := cp["paths"].(map[string]any)
	for p, item := range paths {
		for _, m := range []string{"get", "post", "put", "patch", "delete"} {
			op, ok := item.(map[string]any)[m].(map[string]any)
			if !ok {
				continue
			}
			contents(op["requestBody"], p+m+"/requestBody")
			if rs, ok := op["responses"].(map[string]any); ok {
				for k, r := range rs {
					contents(r, p+m+"/responses/"+k)
				}
			}
		}
	}
	return cp
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

// match is matchOperation: the operation a concrete path matches, the most
// literal first.
func (s *state) match(method, path string) *operation {
	parts := strings.Split(path, "/")
	var best *operation
	var bestScore []int
	for i := range s.ops {
		op := &s.ops[i]
		if op.method != method || len(op.segments) != len(parts) {
			continue
		}
		score := make([]int, 0, len(parts))
		ok := true
		for j, seg := range op.segments {
			switch {
			case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
				ok = parts[j] != ""
				score = append(score, 0)
			case seg == parts[j]:
				score = append(score, 1)
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && (best == nil || greater(score, bestScore)) {
			best, bestScore = op, score
		}
	}
	return best
}

func greater(a, b []int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func pointer(parts ...string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.ReplaceAll(strings.ReplaceAll(p, "~", "~0"), "/", "~1")
	}
	return strings.Join(out, "/")
}

func (s *state) deref(node any) map[string]any {
	cur, _ := node.(map[string]any)
	for i := 0; cur != nil && i < 10; i++ {
		ref, ok := cur["$ref"].(string)
		if !ok {
			return cur
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil
		}
		var target any = s.spec
		for _, raw := range strings.Split(ref[2:], "/") {
			m, _ := target.(map[string]any)
			target = m[strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")]
		}
		cur, _ = target.(map[string]any)
	}
	return cur
}

func (s *state) validator(ptr string) (*jsonschema.Schema, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.compiled[ptr]; ok {
		return v, nil
	}
	v, err := s.compiler.Compile(specURL + "#" + ptr)
	if err != nil {
		return nil, err
	}
	s.compiled[ptr] = v
	return v, nil
}

func mediaType(h string) string {
	if h == "" {
		return ""
	}
	t, _, _ := strings.Cut(h, ";")
	return strings.ToLower(strings.TrimSpace(t))
}

func isJSON(t string) bool { return t == "application/json" || strings.HasSuffix(t, "+json") }

func contentFor(content map[string]any, t string) string {
	if content == nil || t == "" {
		return ""
	}
	if _, ok := content[t]; ok {
		return t
	}
	major, _, _ := strings.Cut(t, "/")
	if _, ok := content[major+"/*"]; ok {
		return major + "/*"
	}
	if _, ok := content["*/*"]; ok {
		return "*/*"
	}
	return ""
}

// Options are what Check judges besides the response.
type Options struct {
	// Requests also judges a 2xx request's body. Off for fixtures that send
	// bodies outside the document on purpose, as the TypeScript fixtures
	// run the unchecked app.
	Requests bool
}

// Check judges one exchange.
func Check(e Exchange, opts Options) ([]Mismatch, error) {
	if e.Path != "/v1" && !strings.HasPrefix(e.Path, "/v1/") || e.Method == http.MethodOptions {
		return nil, nil
	}
	s, err := load()
	if err != nil {
		return nil, err
	}
	matched := s.match(e.Method, e.Path)
	if matched == nil {
		if e.Status >= 300 {
			return nil, nil
		}
		return []Mismatch{{Kind: "undocumented-operation", Operation: e.Method + " " + e.Path, Status: e.Status, Detail: "served with a 2xx but not in the spec"}}, nil
	}
	operation := matched.method + " " + matched.template
	var out []Mismatch
	allowed := func(kind string) []Allowance {
		var a []Allowance
		for _, x := range ALLOWED {
			if x.Kind == kind && x.Operation == operation && x.Status == e.Status {
				a = append(a, x)
			}
		}
		return a
	}
	add := func(kind, detail string) {
		for _, a := range allowed(kind) {
			if a.Field == "" {
				return
			}
		}
		out = append(out, Mismatch{Kind: kind, Operation: operation, Status: e.Status, Detail: detail})
	}
	validate := func(ptr string, body []byte, fieldKind, otherKind string) error {
		v, err := s.validator(ptr)
		if err != nil {
			return err
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err != nil {
			return err
		}
		verr := v.Validate(inst)
		if verr == nil {
			return nil
		}
		var ve *jsonschema.ValidationError
		if !errors.As(verr, &ve) {
			return verr
		}
		fieldOnly := true
		var details []string
		excused := map[string]bool{}
		for _, a := range allowed(fieldKind) {
			excused[a.Field] = true
		}
		var walk func(e *jsonschema.ValidationError)
		walk = func(e *jsonschema.ValidationError) {
			if len(e.Causes) > 0 {
				for _, c := range e.Causes {
					walk(c)
				}
				return
			}
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			if _, undocumented := e.ErrorKind.(*kind.FalseSchema); undocumented {
				// A member unevaluatedProperties: false refused.
				if excused[loc] {
					return
				}
				details = append(details, loc+" is not in the document")
				return
			}
			fieldOnly = false
			details = append(details, loc+" "+e.ErrorKind.LocalizedString(printer))
		}
		walk(ve)
		if len(details) == 0 {
			return nil
		}
		if len(details) > 6 {
			details = details[:6]
		}
		kind := otherKind
		if fieldOnly {
			kind = fieldKind
		}
		add(kind, strings.Join(details, "; "))
		return nil
	}
	opPtr := pointer("", "paths", strings.TrimPrefix(matched.template, "/v1"), strings.ToLower(matched.method))

	responses, _ := matched.op["responses"].(map[string]any)
	statusKey := ""
	for _, k := range []string{fmt.Sprint(e.Status), fmt.Sprintf("%dXX", e.Status/100), "default"} {
		if _, ok := responses[k]; ok {
			statusKey = k
			break
		}
	}
	if statusKey == "" {
		keys := make([]string, 0, len(responses))
		for k := range responses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		add("undocumented-status", "documented: "+strings.Join(keys, ", "))
	} else {
		resp := s.deref(responses[statusKey])
		content, _ := resp["content"].(map[string]any)
		t := mediaType(e.ResponseContentType)
		empty := len(e.ResponseBody) == 0
		switch {
		case len(content) == 0:
			if !empty {
				add("undocumented-response-body", t+" body, spec documents none")
			}
		case empty:
			add("missing-response-body", "spec documents a body")
		default:
			key := contentFor(content, t)
			switch {
			case key == "":
				add("response-content-type", t+", spec documents another")
			case isJSON(t):
				if !json.Valid(e.ResponseBody) {
					add("response-not-json", "body is not JSON")
				} else if media, _ := content[key].(map[string]any); media["schema"] != nil {
					base := opPtr + "/responses/" + pointer(statusKey)
					if raw, _ := responses[statusKey].(map[string]any); raw != nil {
						if ref, ok := raw["$ref"].(string); ok {
							base = ref[1:]
						}
					}
					if err := validate(base+"/content/"+pointer(key)+"/schema", e.ResponseBody, "response-undocumented-field", "response-schema"); err != nil {
						return out, err
					}
				}
			}
		}
	}

	if opts.Requests && e.Status >= 200 && e.Status < 300 && e.Method != http.MethodGet && e.Method != http.MethodHead {
		rb := s.deref(matched.op["requestBody"])
		has := len(e.RequestBody) > 0
		t := mediaType(e.RequestContentType)
		switch {
		case rb == nil:
			if has && strings.TrimSpace(string(e.RequestBody)) != "{}" {
				add("undocumented-request-body", t+" body, spec documents none")
			}
		case !has:
			if rb["required"] == true {
				add("missing-request-body", "requestBody is required")
			}
		default:
			content, _ := rb["content"].(map[string]any)
			key := contentFor(content, t)
			switch {
			case key == "":
				add("request-content-type", t+", spec documents another")
			case isJSON(t):
				if !json.Valid(e.RequestBody) {
					add("request-not-json", t+" body that does not parse as JSON")
				} else if media, _ := content[key].(map[string]any); media["schema"] != nil {
					base := opPtr + "/requestBody"
					if raw, _ := matched.op["requestBody"].(map[string]any); raw != nil {
						if ref, ok := raw["$ref"].(string); ok {
							base = ref[1:]
						}
					}
					if err := validate(base+"/content/"+pointer(key)+"/schema", e.RequestBody, "request-undocumented-field", "request-schema"); err != nil {
						return out, err
					}
				}
			}
		}
	}
	return out, nil
}

// Recorder checks every exchange a test makes through it.
type Recorder struct {
	T    testing.TB
	Opts Options
}

// Exchange judges a request (with the body it sent) and its recorded
// response, failing the test on a mismatch.
func (c Recorder) Exchange(req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
	c.T.Helper()
	ms, err := Check(Exchange{
		// The path as sent (new URL(...).pathname keeps %2F encoded).
		Method: req.Method, Path: req.URL.EscapedPath(), RequestContentType: req.Header.Get("Content-Type"), RequestBody: body,
		Status: rec.Code, ResponseContentType: rec.Header().Get("Content-Type"), ResponseBody: rec.Body.Bytes(),
	}, c.Opts)
	if err != nil {
		c.T.Fatalf("openapicheck: %v", err)
	}
	for _, m := range ms {
		c.T.Errorf("openapicheck: %s", m)
	}
}
