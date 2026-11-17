// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The framework vectors (../../testdata/vectors/framework.json), written by
// apps/cli/test/go-vectors-framework.test.ts from the TypeScript CLI's own
// code: the Go framework must answer every one as TypeScript did.

const frameworkVectors = "../../testdata/vectors/framework.json"

type frameworkFile struct {
	Usage       string
	CommandHelp []struct {
		Topic string
		Help  *string
	}
	Options []struct {
		Spec   string
		Args   []string
		Result struct {
			Error       *string
			Values      map[string]string
			Lists       map[string][]string
			Booleans    []string
			Positionals []string
		}
	}
	Printable []struct{ Text, Printable, ServerMessage string }
	SafeTime  []struct {
		Value  any
		Result *string
	}
	SafeVersion []struct {
		Value  any
		Result *string
	}
	SafeAPIMajor []struct {
		Value  any
		Result *float64
	} `json:"safeApiMajor"`
	SafeRequestID []struct {
		Value  any
		Result *string
	} `json:"safeRequestId"`
	MaskSecrets []struct {
		Known  []string
		Token  *string
		Stored []string
		Text   string
		Result string
	}
	Assisted []struct {
		Env       map[string]string
		Given     bool
		On        bool
		Source    *string
		Marker    *string
		Described string
	}
	AgentMarkers  []string
	GlobalOptions []struct {
		Argv     []string
		Assisted bool
		Rest     []string
		Approval *string
		Error    *string
	}
	UserAgents []struct {
		Kind, Version, Platform, Arch, UserAgent string
		Assisted                                 bool
	}
	Exit         map[string]int
	APIErrorExit []struct {
		Status int
		Code   string
		Exit   int
	} `json:"apiErrorExit"`
	ErrorCodes []string
}

func loadFramework(t *testing.T) (*frameworkFile, []byte) {
	t.Helper()
	data, err := os.ReadFile(frameworkVectors)
	if err != nil {
		t.Fatal(err)
	}
	var f frameworkFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f, data
}

func TestUsageIsTypeScripts(t *testing.T) {
	f, _ := loadFramework(t)
	if Usage != f.Usage {
		t.Fatal("usage.txt differs from the TypeScript CLI's USAGE: copy it from framework.json's usage")
	}
	for _, c := range f.CommandHelp {
		got, ok := CommandHelp(c.Topic)
		if (c.Help == nil) == ok || c.Help != nil && got != *c.Help {
			t.Errorf("CommandHelp(%q) = %q, %v; want %v", c.Topic, got, ok, c.Help)
		}
	}
}

// specs reads the vectors' option specs with jsjson, so the aliases keep
// the order the TypeScript object literal gives them.
func specs(t *testing.T, data []byte) map[string]OptionSpec {
	t.Helper()
	root, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]OptionSpec{}
	for _, m := range root.(jsjson.Object).Value("specs").(jsjson.Object) {
		o := m.Value.(jsjson.Object)
		strs := func(key string) []string {
			var s []string
			for _, v := range asSlice(o.Value(key)) {
				s = append(s, v.(string))
			}
			return s
		}
		spec := OptionSpec{Values: strs("values"), Lists: strs("lists"), Booleans: strs("booleans")}
		spec.OnceBooleans = o.Value("onceBooleans") == true
		spec.EndOfOptions = o.Value("endOfOptions") == true
		if p, ok := o.Value("positionals").(float64); ok {
			spec.Positionals = int(p)
		}
		if a, ok := o.Value("aliases").(jsjson.Object); ok {
			for _, am := range a {
				spec.Aliases = append(spec.Aliases, Alias{From: am.Key, To: am.Value.(string)})
			}
		}
		out[m.Key] = spec
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func TestOptionsVectors(t *testing.T) {
	f, data := loadFramework(t)
	all := specs(t, data)
	for _, c := range f.Options {
		got, err := ParseOptions(c.Args, all[c.Spec])
		if c.Result.Error != nil {
			if err == nil || err.Error() != *c.Result.Error {
				t.Errorf("%s %q: error %v, want %q", c.Spec, c.Args, err, *c.Result.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %q: %v", c.Spec, c.Args, err)
			continue
		}
		want := c.Result
		if !reflect.DeepEqual(nonNilMap(got.Values), nonNilMap(want.Values)) ||
			!reflect.DeepEqual(nonNilLists(got.Lists), nonNilLists(want.Lists)) ||
			!slices.Equal(got.Booleans, want.Booleans) || !slices.Equal(got.Positionals, want.Positionals) {
			t.Errorf("%s %q: got %+v, want %+v", c.Spec, c.Args, got, want)
		}
	}
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNilLists(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}

func TestTextVectors(t *testing.T) {
	f, _ := loadFramework(t)
	s := &Secrets{}
	for _, c := range f.Printable {
		if got := Printable(c.Text); got != c.Printable {
			t.Errorf("Printable(%q) = %q, want %q", c.Text, got, c.Printable)
		}
		if got := s.ServerMessage(c.Text); got != c.ServerMessage {
			t.Errorf("ServerMessage(%q) = %q, want %q", c.Text, got, c.ServerMessage)
		}
	}
	missing := func(v any) any {
		if v == "<undefined>" || v == "<NaN>" {
			if v == "<NaN>" {
				return math.NaN()
			}
			return nil
		}
		return v
	}
	for _, c := range f.SafeTime {
		got, ok := SafeTime(missing(c.Value))
		if (c.Result == nil) == ok || c.Result != nil && got != *c.Result {
			t.Errorf("SafeTime(%v) = %q, %v; want %v", c.Value, got, ok, deref(c.Result))
		}
	}
	for _, c := range f.SafeVersion {
		got, ok := s.SafeVersion(missing(c.Value))
		if (c.Result == nil) == ok || c.Result != nil && got != *c.Result {
			t.Errorf("SafeVersion(%v) = %q, %v; want %v", c.Value, got, ok, deref(c.Result))
		}
	}
	for _, c := range f.SafeAPIMajor {
		got, ok := SafeAPIMajor(missing(c.Value))
		if (c.Result == nil) == ok || c.Result != nil && float64(got) != *c.Result {
			t.Errorf("SafeAPIMajor(%v) = %d, %v; want %v", c.Value, got, ok, c.Result)
		}
	}
	for _, c := range f.SafeRequestID {
		got, ok := s.SafeRequestID(c.Value)
		if (c.Result == nil) == ok || c.Result != nil && got != *c.Result {
			t.Errorf("SafeRequestID(%v) = %q, %v; want %v", c.Value, got, ok, deref(c.Result))
		}
	}
	for _, c := range f.MaskSecrets {
		m := &Secrets{Stored: func() []string { return c.Stored }}
		if c.Token != nil {
			m.Token = *c.Token
		}
		for _, k := range c.Known {
			m.Remember(k)
		}
		if got := m.Mask(c.Text); got != c.Result {
			t.Errorf("Mask(%q) with %+v = %q, want %q", c.Text, c, got, c.Result)
		}
	}
	if !slices.Equal(ErrorCodes, f.ErrorCodes) {
		t.Errorf("ErrorCodes differ from packages/protocol's:\n got %q\nwant %q", ErrorCodes, f.ErrorCodes)
	}
}

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func TestAssistedVectors(t *testing.T) {
	f, _ := loadFramework(t)
	if !slices.Equal(AgentMarkers, f.AgentMarkers) {
		t.Fatalf("AgentMarkers %q, want %q", AgentMarkers, f.AgentMarkers)
	}
	for _, c := range f.Assisted {
		got := ResolveAssisted(c.Given, MapEnv(c.Env))
		want := AssistedMode{On: c.On}
		if c.Source != nil {
			want.Source = *c.Source
		}
		if c.Marker != nil {
			want.Marker = *c.Marker
		}
		if got != want || DescribeAssisted(got) != c.Described {
			t.Errorf("ResolveAssisted(%v, %q) = %+v (%s), want %+v (%s)", c.Given, c.Env, got, DescribeAssisted(got), want, c.Described)
		}
	}
	for _, c := range f.GlobalOptions {
		taken, given := TakeAssistedOption(c.Argv)
		rest, approval, problem := TakeApprovalOption(taken)
		if given != c.Assisted || !slices.Equal(rest, nonNilSlice(c.Rest)) || approval != deref2(c.Approval) || problem != deref2(c.Error) {
			t.Errorf("%q: assisted %v, rest %q, approval %q, problem %q; want %v %q %v %v", c.Argv, given, rest, approval, problem, c.Assisted, c.Rest, deref(c.Approval), deref(c.Error))
		}
	}
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func deref2(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestUserAgentAndExitVectors(t *testing.T) {
	f, _ := loadFramework(t)
	for _, c := range f.UserAgents {
		var got string
		if c.Kind == "mcp" {
			got = FormatMCPUserAgent(c.Version, c.Platform, c.Arch)
		} else {
			got = FormatUserAgent(c.Version, c.Assisted, c.Platform, c.Arch)
		}
		if got != c.UserAgent {
			t.Errorf("%+v: %q", c, got)
		}
	}
	for goos, want := range map[string]string{"linux": "linux", "darwin": "darwin", "windows": "win32"} {
		if got := nodePlatform(goos); got != want {
			t.Errorf("nodePlatform(%s) = %s, want %s", goos, got, want)
		}
	}
	for goarch, want := range map[string]string{"amd64": "x64", "arm64": "arm64", "386": "ia32"} {
		if got := nodeArch(goarch); got != want {
			t.Errorf("nodeArch(%s) = %s, want %s", goarch, got, want)
		}
	}
	codes := map[string]int{"ok": ExitOK, "failure": ExitFailure, "usage": ExitUsage, "unavailable": ExitUnavailable, "tempfail": ExitTempfail, "denied": ExitDenied, "config": ExitConfig, "interrupted": ExitInterrupted}
	if !reflect.DeepEqual(codes, f.Exit) {
		t.Errorf("exit statuses %v, want %v", codes, f.Exit)
	}
	for _, c := range f.APIErrorExit {
		if got := APIErrorExit(c.Status, c.Code); got != c.Exit {
			t.Errorf("APIErrorExit(%d, %s) = %d, want %d", c.Status, c.Code, got, c.Exit)
		}
	}
}

// A positional argument that names a property of Object.prototype makes the
// TypeScript parser throw a TypeError for a command whose options have
// aliases (`spec.aliases[arg]` reads the prototype): an availability defect,
// not reproduced (go/README.md, Known TypeScript defects).
func TestPrototypeNamesAreOrdinaryArguments(t *testing.T) {
	spec := OptionSpec{Values: []string{"--environment"}, Positionals: 1, Aliases: []Alias{{"-e", "--environment"}}}
	for _, name := range []string{"constructor", "toString", "__proto__", "hasOwnProperty"} {
		got, err := ParseOptions([]string{name}, spec)
		if err != nil || !slices.Equal(got.Positionals, []string{name}) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}
