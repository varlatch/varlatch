// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// The TypeScript adapters' recorded exchanges (packages/sync/test/
// go-vectors.test.ts): every case replays here with the recorded answers
// and must send the same requests and give the same result.

type vectors struct {
	cases  []Object
	seal   []any
	base64 []any
}

// sealSecrets are the recipients' secret keys the recording opens sealed
// values with (SEAL_SECRETS), set by loadVectors.
var sealSecrets [][]byte

func loadVectors(t *testing.T) vectors {
	t.Helper()
	text, err := os.ReadFile("testdata/ts-exchanges.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := parseJSON(text)
	if err != nil {
		t.Fatal(err)
	}
	root := v.(Object)
	var table []string
	for _, s := range root.get("strings").([]any) {
		table = append(table, expandRuns(s))
	}
	var cases []Object
	for _, c := range root.get("cases").([]any) {
		cases = append(cases, unpack(c, table).(Object))
	}
	sealSecrets = nil
	for _, h := range root.get("sealSecrets").([]any) {
		sealSecrets = append(sealSecrets, hexBytes(t, h.(string)))
	}
	return vectors{cases: cases, seal: root.get("seal").([]any), base64: root.get("base64").([]any)}
}

func expandRuns(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	var b strings.Builder
	for _, part := range v.(Object).get("$cat").([]any) {
		if s, ok := part.(string); ok {
			b.WriteString(s)
			continue
		}
		rep := part.(Object).get("$rep").([]any)
		b.WriteString(strings.Repeat(rep[0].(string), int(rep[1].(float64))))
	}
	return b.String()
}

func unpack(v any, table []string) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = unpack(e, table)
		}
		return out
	case Object:
		if i, ok := x.get("$s").(float64); ok && len(x) == 1 {
			return table[int(i)]
		}
		out := make(Object, len(x))
		for i, m := range x {
			out[i] = Member{m.Key, unpack(m.Value, table)}
		}
		return out
	}
	return v
}

// ---------------------------------------------------------------------------
// The recording's encoding of JavaScript values.

func isUndefined(v any) bool {
	o, ok := v.(Object)
	return ok && len(o) == 1 && o[0].Key == "$undefined"
}

func encNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func encStrings(list []string) any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func encOutcomes(list []NameOutcome) any {
	out := make([]any, len(list))
	for i, o := range list {
		obj := Object{{"name", o.Name}, {"ok", o.OK}}
		if !o.OK {
			obj = append(obj, Member{"error", o.Error})
		}
		out[i] = obj
	}
	return out
}

func encUsage(u NameUsage) Object {
	o := Object{}
	if u.Owned {
		o = append(o, Member{"owned", true})
	}
	if u.Referenced {
		o = append(o, Member{"referenced", true})
	}
	if u.GeneratedOnce {
		o = append(o, Member{"generatedOnce", true})
	}
	if u.CopiedIntoCompose {
		o = append(o, Member{"copiedIntoCompose", true})
	}
	if len(u.ShadowedIn) > 0 {
		o = append(o, Member{"shadowedIn", encStrings(u.ShadowedIn)})
	}
	if len(u.UnknownIn) > 0 {
		o = append(o, Member{"unknownIn", encStrings(u.UnknownIn)})
	}
	if len(u.NotDeliveredTo) > 0 {
		o = append(o, Member{"notDeliveredTo", encStrings(u.NotDeliveredTo)})
	}
	return o
}

func encReport(r *UsageReport) any {
	if r == nil {
		return nil
	}
	o := Object{{"checked", r.Checked}}
	if r.Reason != "" {
		o = append(o, Member{"reason", r.Reason})
	}
	entries := make([]any, len(r.Names))
	for i, n := range r.Names {
		entries[i] = []any{n.Name, encUsage(n.Usage)}
	}
	return append(o, Member{"names", Object{{"$map", entries}}})
}

// encValues is a values Map, its entries sorted (a Go map has no order);
// a value that is not a string reads as null.
func encValues(m map[string]*string) any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	entries := make([]any, len(keys))
	for i, k := range keys {
		var v any
		if m[k] != nil {
			v = *m[k]
		}
		entries[i] = []any{k, v}
	}
	return Object{{"$map", entries}}
}

// recordedValues is a recorded values Map in encValues's form.
func recordedValues(v any) any {
	entries := v.(Object).get("$map").([]any)
	byKey := map[string]*string{}
	for _, e := range entries {
		pair := e.([]any)
		k, ok := pair[0].(string)
		if !ok {
			continue // a key that is not a string never matches a name
		}
		if s, ok := pair[1].(string); ok {
			byKey[k] = &s
		} else {
			byKey[k] = nil
		}
	}
	return encValues(byKey)
}

func encSet(set map[string]bool) any {
	keys := make([]any, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	return Object{{"$set", keys}}
}

func recordedSet(v any) any {
	set := map[string]bool{}
	for _, k := range v.(Object).get("$set").([]any) {
		if s, ok := k.(string); ok {
			set[s] = true
		}
	}
	return encSet(set)
}

func encListing(l DestinationListing) any {
	v, _ := parseJSON(stringify(listingObject(l)))
	return v
}

func listingObject(l DestinationListing) Object {
	b, _ := l.MarshalJSON()
	v, _ := parseJSON(b)
	return v.(Object)
}

func encCheck(c AccessCheck) any {
	return c.object()
}

func encThrow(err error) any {
	var ae *AdapterError
	if errors.As(err, &ae) && ae == err {
		return Object{{"name", "AdapterError"}, {"message", ae.Message}, {"retryable", ae.Retryable}}
	}
	var se *ScriptError
	if errors.As(err, &se) {
		return Object{{"name", se.Name}}
	}
	return Object{{"name", "Go:" + err.Error()}}
}

func decodeFields(v any) Fields {
	o, _ := v.(Object)
	f := Fields{}
	for _, m := range o {
		if isUndefined(m.Value) {
			continue
		}
		f = append(f, Field{m.Key, jsString(m.Value)})
	}
	return f
}

func decodeUsage(v any) *UsageReport {
	o, ok := v.(Object)
	if !ok || isUndefined(v) {
		return nil
	}
	r := &UsageReport{Checked: o.get("checked") == true}
	r.Reason, _ = o.get("reason").(string)
	if names, ok := o.get("names").(Object); ok {
		for _, e := range names.get("$map").([]any) {
			pair := e.([]any)
			u := pair[1].(Object)
			strs := func(key string) []string {
				var out []string
				list, _ := u.get(key).([]any)
				for _, s := range list {
					out = append(out, s.(string))
				}
				return out
			}
			r.set(pair[0].(string), NameUsage{
				Owned: u.get("owned") == true, Referenced: u.get("referenced") == true,
				GeneratedOnce: u.get("generatedOnce") == true, CopiedIntoCompose: u.get("copiedIntoCompose") == true,
				ShadowedIn: strs("shadowedIn"), UnknownIn: strs("unknownIn"), NotDeliveredTo: strs("notDeliveredTo"),
			})
		}
	}
	return r
}

func decodeNumber(v any) (*float64, bool) {
	switch x := v.(type) {
	case float64:
		return &x, true
	case Object:
		if s, ok := x.get("$number").(string); ok {
			f := map[string]float64{"NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1)}[s]
			return &f, true
		}
	}
	return nil, false
}

func optString(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// ---------------------------------------------------------------------------
// The scripted fake service.

type wire struct {
	method, url string
	headers     map[string]string
	body        any
}

func (w wire) object() Object {
	keys := make([]string, 0, len(w.headers))
	for k := range w.headers {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := Object{}
	for _, k := range keys {
		h = append(h, Member{k, w.headers[k]})
	}
	return Object{{"method", w.method}, {"url", w.url}, {"headers", h}, {"body", w.body}}
}

func recordedWire(v any) Object {
	o := v.(Object)
	h := o.get("headers").(Object)
	headers := map[string]string{}
	for _, m := range h {
		headers[m.Key] = m.Value.(string)
	}
	return wire{o.get("method").(string), o.get("url").(string), headers, o.get("body")}.object()
}

var sealedValue = regexp.MustCompile(`"encrypted_value":"([^"]*)"`)

// normalizeBody is the recording's: a sealed value as its length, and one
// sealed to a recipient of sealSecrets also as the hex of what it opens to.
func normalizeBody(body string) string {
	return sealedValue.ReplaceAllStringFunc(body, func(m string) string {
		sealed := nodeBase64(sealedValue.FindStringSubmatch(m)[1])
		for _, secret := range sealSecrets {
			public, err := curve25519.X25519(secret, curve25519.Basepoint)
			if err != nil {
				panic(err)
			}
			if opened, ok := SealedBoxOpen(sealed, public, secret); ok {
				return `"encrypted_value":"<sealed:` + strconv.Itoa(len(sealed)) + ":" + hex.EncodeToString(opened) + `>"`
			}
		}
		return `"encrypted_value":"<sealed:` + strconv.Itoa(len(sealed)) + `>"`
	})
}

type refusal struct{ message string }

func (r *refusal) Error() string { return r.message }
func (r *refusal) Code() string  { return OutboundRefusedCode }

// errorChain is a recorded rejection: the thrown error and its causes.
type errorChain struct {
	name, message, code string
	cause               *errorChain
}

func readChain(v any) *errorChain {
	o, ok := v.(Object)
	if !ok {
		return nil
	}
	e := &errorChain{}
	e.name, _ = o.get("name").(string)
	e.message, _ = o.get("message").(string)
	e.code, _ = o.get("code").(string)
	e.cause = readChain(o.get("cause"))
	return e
}

var tlsCode = regexp.MustCompile(`CERT|SELF_SIGNED|SIGNATURE|TLS|SSL`)
var redirectText = regexp.MustCompile(`(?i)redirect`)

// goFailure is what the Go transport fails with where fetch rejected as
// recorded, by the same reading the TypeScript adapters give the
// rejection: the policy's refusal anywhere in it, a timeout by name, and
// the transport problem on the cause. A redirect is a redirect answer.
func goFailure(e *errorChain) (error, bool) {
	for c, depth := e, 0; c != nil && depth < 8; c, depth = c.cause, depth+1 {
		if c.code == OutboundRefusedCode {
			return &refusal{c.message}, false
		}
	}
	if e.name == "TimeoutError" {
		return context.DeadlineExceeded, false
	}
	if inner := e.cause; inner != nil {
		switch {
		case redirectText.MatchString(inner.message):
			return nil, true
		case inner.code == "ENOTFOUND" || inner.code == "EAI_AGAIN":
			return &net.DNSError{Err: "no such host", Name: "host", IsNotFound: true}, false
		case inner.code == "ECONNREFUSED":
			return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, false
		case tlsCode.MatchString(inner.code):
			return x509.UnknownAuthorityError{}, false
		}
	}
	return errors.New("connection reset by peer"), false
}

type scripted struct {
	script []Object
	got    []any
	err    error
}

func (s *scripted) RoundTrip(r *http.Request) (*http.Response, error) {
	headers := map[string]string{}
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	var body any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = normalizeBody(string(b))
	}
	w := wire{r.Method, r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI(), headers, body}
	if len(s.script) == 0 {
		s.got = append(s.got, Object{{"request", w.object()}, {"unrecorded", true}})
		return nil, errors.New("unrecorded request")
	}
	next := s.script[0]
	s.script = s.script[1:]
	if e, has := next.Get("error"); has {
		s.got = append(s.got, Object{{"request", w.object()}, {"error", e}})
		failure, redirect := goFailure(readChain(e))
		if redirect {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://elsewhere.example/"}},
				Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		return nil, failure
	}
	answer := next.get("response").(Object)
	s.got = append(s.got, Object{{"request", w.object()}, {"response", answer}})
	header := http.Header{}
	for _, h := range answer.get("headers").([]any) {
		pair := h.([]any)
		header.Add(pair[0].(string), pair[1].(string))
	}
	return &http.Response{StatusCode: int(answer.get("status").(float64)), Header: header,
		Body: io.NopCloser(strings.NewReader(answer.get("body").(string))), Request: r}, nil
}

// ---------------------------------------------------------------------------
// Replaying a case.

func adapterOf(platform string) Adapter {
	a, err := GetAdapter(platform)
	if err != nil {
		panic(err)
	}
	return a
}

type replayed struct {
	exchanges []any
	aborts    []any
	expiry    []any
	result    any
	throws    any
}

func replayCase(t *testing.T, c Object) replayed {
	args, _ := c.get("args").([]any)
	arg := func(i int) any {
		if i < len(args) && !isUndefined(args[i]) {
			return args[i]
		}
		return nil
	}
	var out replayed
	fail := func(err error) { out.throws = encThrow(err) }

	if fn, ok := c.get("fn").(string); ok {
		switch fn {
		case "classifyComposeUsage":
			version, _ := decodeNumber(arg(2))
			var names []string
			for _, n := range arg(3).([]any) {
				names = append(names, n.(string))
			}
			out.result = encReport(ClassifyComposeUsage(optString(arg(0)), optString(arg(1)), version, names))
		case "parseTokenExpiration":
			s, ok := arg(0).(string)
			out.result = encNull(ParseTokenExpiration(s, ok))
		}
		return out
	}

	adapter := adapterOf(c.get("platform").(string))
	method := c.get("method").(string)
	request, isRequest := c.get("request").(Object)
	if !isRequest {
		str := func(i int) string { s, _ := arg(i).(string); return s }
		var dest Fields
		if o, ok := arg(1).(Object); ok {
			dest = decodeFields(o)
		}
		switch method {
		case "canonicalizeBaseIdentity":
			if v, err := adapter.CanonicalizeBaseIdentity(str(0)); err != nil {
				fail(err)
			} else {
				out.result = v
			}
		case "canonicalizeDestination":
			raw, _ := arg(0).(Object)
			if d, err := adapter.CanonicalizeDestination(raw); err != nil {
				fail(err)
			} else {
				out.result = Object{{"destination", d.Fields.object()}, {"key", d.Key}}
			}
		case "validateName":
			out.result = encNull(adapter.ValidateName(str(0), dest))
		case "canonicalizeName":
			out.result = adapter.CanonicalizeName(str(0))
		case "valueProblem":
			out.result = encNull(adapter.(ValueChecker).ValueProblem(decodeFields(arg(0)), str(1), str(2), decodeUsage(arg(3))))
		case "heldFix":
			out.result = encNull(adapter.(ValueChecker).HeldFix(decodeFields(arg(0)), str(1), str(2)))
		default:
			t.Fatalf("unknown method %s", method)
		}
		return out
	}

	transport := &scripted{}
	if list, ok := c.get("exchanges").([]any); ok {
		for _, e := range list {
			transport.script = append(transport.script, e.(Object))
		}
	}
	answers, _ := c.get("aborts").([]any)
	req := &Request{
		BaseIdentity:   request.get("baseIdentity").(string),
		Destination:    decodeFields(request.get("destination")),
		Credential:     request.get("credential").(string),
		CredentialKind: CredentialKind(jsStringIf(request.get("credentialKind"))),
		Usage:          decodeUsage(request.get("usage")),
	}
	if request.get("fetchImpl") == true {
		req.Client = &http.Client{Transport: transport}
	}
	if ms, ok := request.get("timeoutMs").(float64); ok {
		req.Timeout = time.Duration(ms) * time.Millisecond
	}
	out.aborts, out.expiry = []any{}, []any{}
	if request.get("shouldAbort") == true {
		req.ShouldAbort = func(context.Context) (bool, error) {
			a := false
			if len(answers) > 0 {
				a, answers = answers[0] == true, answers[1:]
			}
			out.aborts = append(out.aborts, a)
			return a, nil
		}
	}
	if request.get("onCredentialExpiry") == true {
		req.OnCredentialExpiry = func(at string) { out.expiry = append(out.expiry, at) }
	}
	ctx := context.Background()
	var items []SyncItem
	var names []string
	if list, ok := arg(0).([]any); ok {
		for _, e := range list {
			if o, ok := e.(Object); ok {
				items = append(items, SyncItem{o.get("name").(string), o.get("value").(string)})
			} else if s, ok := e.(string); ok {
				names = append(names, s)
			}
		}
	}
	switch method {
	case "writeValues":
		if r, err := adapter.WriteValues(ctx, req, items); err != nil {
			fail(err)
		} else {
			out.result = encOutcomes(r)
		}
	case "deleteNames":
		if r, err := adapter.DeleteNames(ctx, req, names); err != nil {
			fail(err)
		} else {
			out.result = encOutcomes(r)
		}
	case "readValues":
		if r, err := adapter.(ValueReader).ReadValues(ctx, req); err != nil {
			fail(err)
		} else {
			out.result = encValues(r)
		}
	case "readRemote":
		if r, err := adapter.(RemoteReader).ReadRemote(ctx, req); err != nil {
			fail(err)
		} else {
			out.result = Object{{"values", encValues(r.Values)}, {"rewrite", encSet(r.Rewrite)}}
		}
	case "checkAccess":
		out.result = encCheck(adapter.CheckAccess(ctx, req))
	case "listDestinations":
		out.result = encListing(adapter.(DestinationLister).ListDestinations(ctx, req))
	case "inspectUsage":
		out.result = encReport(adapter.(UsageInspector).InspectUsage(ctx, req, names))
	case "triggerRedeploy":
		if r, err := adapter.(Redeployer).TriggerRedeploy(ctx, req); err != nil {
			fail(err)
		} else {
			out.result = r
		}
	default:
		t.Fatalf("unknown method %s", method)
	}
	out.exchanges = transport.got
	return out
}

func jsStringIf(v any) string {
	s, _ := v.(string)
	return s
}

// recordedResult is the case's result as the replay encodes it.
func recordedResult(c Object) any {
	result := c.get("result")
	switch c.get("method") {
	case "readValues":
		return recordedValues(result)
	case "readRemote":
		o := result.(Object)
		return Object{{"values", recordedValues(o.get("values"))}, {"rewrite", recordedSet(o.get("rewrite"))}}
	}
	return result
}

func recordedExchanges(c Object) []any {
	list, _ := c.get("exchanges").([]any)
	out := []any{}
	for _, e := range list {
		o := e.(Object)
		x := Object{{"request", recordedWire(o.get("request"))}}
		if v, has := o.Get("error"); has {
			x = append(x, Member{"error", v})
		} else {
			x = append(x, Member{"response", o.get("response")})
		}
		out = append(out, x)
	}
	return out
}

func same(a, b any) bool { return bytes.Equal(stringify(a), stringify(b)) }

// knownDifferences are recorded cases whose answer Go gives otherwise,
// with why. Every other case must match.
var knownDifferences = map[string]string{}

func TestTypeScriptExchanges(t *testing.T) {
	v := loadVectors(t)
	if len(v.cases) < 600 {
		t.Fatalf("only %d cases", len(v.cases))
	}
	failures := 0
	for i, c := range v.cases {
		name := c.get("test").(string)
		got := replayCase(t, c)
		label := strconv.Itoa(i) + " " + name + " (" + jsString(c.get("platform")) + jsString(c.get("fn")) + " " + jsString(c.get("method")) + ")"
		if strings.Contains(name, "divergence:") {
			// Go reads the file as unreadable; TypeScript reads it.
			want := encReport(unknownUsage("the service's compose file is too large or could not be read", namesOf(c)))
			if !same(got.result, want) {
				t.Errorf("%s: got %s, want the unreadable report", label, stringify(got.result))
			}
			continue
		}
		if why, ok := knownDifferences[name]; ok {
			t.Logf("%s: known difference: %s", label, why)
			continue
		}
		problems := []string{}
		if _, has := c.Get("request"); has {
			if want := recordedExchanges(c); !same(got.exchanges, want) {
				problems = append(problems, "exchanges:\n   got  "+string(stringify(got.exchanges))+"\n   want "+string(stringify(want)))
			}
			if want := c.get("aborts"); !same(got.aborts, want) {
				problems = append(problems, "aborts: got "+string(stringify(got.aborts))+" want "+string(stringify(want)))
			}
			if want := c.get("expiry"); !same(got.expiry, want) {
				problems = append(problems, "expiry: got "+string(stringify(got.expiry))+" want "+string(stringify(want)))
			}
		}
		if throws, has := c.Get("throws"); has {
			if !same(got.throws, throws) {
				problems = append(problems, "throws: got "+string(stringify(got.throws))+" want "+string(stringify(throws)))
			}
		} else if want := recordedResult(c); got.throws != nil || !same(got.result, want) {
			problems = append(problems, "result:\n   got  "+string(stringify(got.result))+" (throws "+string(stringify(got.throws))+")\n   want "+string(stringify(want)))
		}
		if len(problems) > 0 {
			failures++
			if failures <= 40 {
				t.Errorf("%s:\n  %s", label, strings.Join(problems, "\n  "))
			}
		}
	}
	if failures > 0 {
		t.Errorf("%d of %d cases differ", failures, len(v.cases))
	}
}

func namesOf(c Object) []string {
	args := c.get("args").([]any)
	var names []string
	for _, n := range args[3].([]any) {
		names = append(names, n.(string))
	}
	return names
}

// fixedReader is a fixed ephemeral key.
type fixedReader []byte

func (f fixedReader) Read(p []byte) (int, error) { return copy(p, f), nil }

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		n, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		b[i] = byte(n)
	}
	return b
}

func TestSealedBoxAsTypeScript(t *testing.T) {
	v := loadVectors(t)
	for i, e := range v.seal {
		o := e.(Object)
		esk := hexBytes(t, o.get("ephemeralSecret").(string))
		recipient := hexBytes(t, o.get("recipient").(string))
		message := hexBytes(t, o.get("message").(string))
		want := hexBytes(t, o.get("sealed").(string))
		got, err := sealWith(fixedReader(esk), message, recipient)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("seal %d: got %x (%v), want %x", i, got, err, want)
		}
	}
	if len(v.seal) == 0 {
		t.Fatal("no seal vectors")
	}
}

func TestNodeBase64(t *testing.T) {
	v := loadVectors(t)
	for _, e := range v.base64 {
		o := e.(Object)
		input := o.get("input").(string)
		want := hexBytes(t, o.get("bytes").(string))
		if got := nodeBase64(input); !bytes.Equal(got, want) {
			t.Errorf("Buffer.from(%q, base64): got %x, want %x", input, got, want)
		}
	}
}
