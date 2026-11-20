// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors of testdata/vectors/guided-init.json (recorded by
// apps/cli/test/go-vectors-guided-init.test.ts from guidedInit.ts with
// guided-init.test.ts's fake): each case run through Go's guided init with
// a port of that fake and a scripted prompter, and everything compared.

// scriptedPrompter answers as the recorder's does: each question must match
// the next answer's pattern; an answer is given as it is (no default
// applied); a question may write files first.
type scriptedPrompter struct {
	dir                string
	answers            []any
	asked, shown, said []string
	problems           []string
}

func (p *scriptedPrompter) next(question string) (any, error) {
	p.asked = append(p.asked, question)
	if len(p.answers) == 0 {
		p.problems = append(p.problems, "unexpected question: "+question)
		return nil, errors.New(p.problems[len(p.problems)-1])
	}
	answer := p.answers[0].(jsjson.Object)
	p.answers = p.answers[1:]
	if !regexp.MustCompile(answer.Value("q").(string)).MatchString(question) {
		p.problems = append(p.problems, fmt.Sprintf("expected a question matching %s, got: %s", answer.Value("q"), question))
		return nil, errors.New(p.problems[len(p.problems)-1])
	}
	for _, m := range jsonObject(answer.Value("write")) {
		if err := os.WriteFile(filepath.Join(p.dir, m.Key), []byte(m.Value.(string)), 0o644); err != nil {
			return nil, err
		}
	}
	return answer.Value("a"), nil
}

func (p *scriptedPrompter) choose(question string, options []string, _ int) (int, error) {
	p.shown = append(p.shown, options...)
	a, err := p.next(question)
	if err != nil {
		return 0, err
	}
	return int(a.(float64)), nil
}

func (p *scriptedPrompter) confirm(question string, _ bool) (bool, error) {
	a, err := p.next(question)
	if err != nil {
		return false, err
	}
	return a.(bool), nil
}

func (p *scriptedPrompter) text(question, _ string) (string, error) {
	a, err := p.next(question)
	if err != nil {
		return "", err
	}
	return a.(string), nil
}

func (p *scriptedPrompter) say(line string) error {
	p.said = append(p.said, line)
	return nil
}

func jsonObject(v any) jsjson.Object { o, _ := v.(jsjson.Object); return o }
func jsonList(v any) []any           { l, _ := v.([]any); return l }

// guidedFake is guided-init.test.ts's fake, with every call logged as the
// recorder logs it.
type guidedFake struct {
	init       jsjson.Object
	orgs       []any
	projects   []any
	envs       []any
	values     map[string]jsjson.Object
	valueOrder []string // a Map's insertion order of environments
	sensitive  map[string]bool
	revisions  []jsjson.Object
	calls      []any
	failCode   string
}

func newGuidedFake(init jsjson.Object) *guidedFake {
	clone := func(v any) []any {
		out, _ := jsjson.Parse(jsjson.Stringify(v))
		l, _ := out.([]any)
		return l
	}
	f := &guidedFake{init: init, values: map[string]jsjson.Object{}, sensitive: map[string]bool{}, failCode: "VALIDATION_FAILED"}
	f.orgs = []any{jsjson.Object{{Key: "slug", Value: "acme"}, {Key: "name", Value: "Acme"}}}
	if v, ok := init.Get("orgs"); ok {
		f.orgs = clone(v)
	}
	f.projects = []any{jsjson.Object{{Key: "slug", Value: "api"}, {Key: "name", Value: "API"}, {Key: "contractAuthority", Value: "git"}}}
	if v, ok := init.Get("projects"); ok {
		f.projects = clone(v)
	}
	f.envs = []any{
		jsjson.Object{{Key: "name", Value: "development"}, {Key: "tier", Value: "development"}, {Key: "kind", Value: "shared"}},
		jsjson.Object{{Key: "name", Value: "production"}, {Key: "tier", Value: "production"}, {Key: "kind", Value: "shared"}},
	}
	if v, ok := init.Get("envs"); ok {
		f.envs = clone(v)
	}
	for _, m := range jsonObject(init.Value("values")) {
		f.values[m.Key] = append(jsjson.Object{}, jsonObject(m.Value)...)
		f.valueOrder = append(f.valueOrder, m.Key)
	}
	for _, s := range jsonList(init.Value("sensitive")) {
		f.sensitive[s.(string)] = true
	}
	if c, ok := init.Value("failCode").(string); ok {
		f.failCode = c
	}
	f.revisions = []jsjson.Object{{{Key: "id", Value: "rev_0"}, {Key: "items", Value: []any{jsjson.Object{{Key: "name", Value: "PORT"}, {Key: "type", Value: "integer"}, {Key: "sensitive", Value: false}}}}, {Key: "active", Value: true}}}
	return f
}

func (f *guidedFake) log(args ...any) {
	cloned, _ := jsjson.Parse(jsjson.Stringify(args))
	f.calls = append(f.calls, cloned)
}

func (f *guidedFake) failing(call string) bool {
	return slices.ContainsFunc(jsonList(f.init.Value("failing")), func(v any) bool { return v == call })
}

func (f *guidedFake) echo(status int, code string) error {
	return &apiclient.APIError{Status: status, Code: code, Message: "rejected dev-canary-5d1f3a9e7b prod-canary-0c4e8b2a61", RequestID: "r"}
}

func page(items []any) jsjson.Object {
	return jsjson.Object{{Key: "items", Value: append([]any{}, items...)}, {Key: "nextCursor", Value: nil}}
}

func (f *guidedFake) ListOrganizations(context.Context) (any, error) {
	f.log("listOrganizations")
	return page(f.orgs), nil
}

func (f *guidedFake) CreateOrganization(_ context.Context, slug, name string) (any, error) {
	input := jsjson.Object{{Key: "slug", Value: slug}, {Key: "name", Value: name}}
	f.log("createOrganization", input)
	f.orgs = append(f.orgs, input)
	return input, nil
}

func (f *guidedFake) ListProjects(_ context.Context, org string) (any, error) {
	f.log("listProjects", org)
	return page(f.projects), nil
}

func (f *guidedFake) CreateProject(_ context.Context, org, slug, name, contractAuthority string) (any, error) {
	input := jsjson.Object{{Key: "slug", Value: slug}, {Key: "name", Value: name}, {Key: "contractAuthority", Value: contractAuthority}}
	f.log("createProject", org, input)
	f.projects = append(f.projects, input)
	return input, nil
}

func (f *guidedFake) ListEnvironments(_ context.Context, org, project string) (any, error) {
	f.log("listEnvironments", org, project)
	return page(f.envs), nil
}

func (f *guidedFake) CreateEnvironment(_ context.Context, org, project string, body jsjson.Object) (any, error) {
	f.log("createEnvironment", org, project, body)
	env := append(append(jsjson.Object{}, body...), jsjson.Member{Key: "kind", Value: "shared"})
	f.envs = append(f.envs, env)
	return env, nil
}

func (f *guidedFake) GetActiveContract(_ context.Context, org, project string) (any, error) {
	f.log("getActiveContract", org, project)
	if f.init.Value("contractForbidden") == true {
		return nil, &apiclient.APIError{Status: 403, Code: "FORBIDDEN", Message: "no", RequestID: "r"}
	}
	for _, r := range f.revisions {
		if r.Value("active") == true {
			var items []any
			for _, i := range jsonList(r.Value("items")) {
				items = append(items, append(append(jsjson.Object{}, jsonObject(i)...), jsjson.Member{Key: "required", Value: jsjson.Object{{Key: "kind", Value: "never"}}}))
			}
			return jsjson.Object{{Key: "id", Value: r.Value("id")}, {Key: "contract", Value: jsjson.Object{
				{Key: "schemaVersion", Value: float64(1)}, {Key: "semanticsVersion", Value: float64(3)}, {Key: "items", Value: items},
			}}}, nil
		}
	}
	return nil, &apiclient.APIError{Status: 404, Code: "RESOURCE_NOT_FOUND", Message: "none", RequestID: "r"}
}

func (f *guidedFake) PushContractRevision(_ context.Context, org, project string, body jsjson.Object) (any, error) {
	f.log("pushContractRevision", org, project, body)
	if f.failing("push") {
		return nil, f.echo(422, f.failCode)
	}
	active := f.init.Value("pushActive") == true
	id := fmt.Sprintf("rev_%d", len(f.revisions))
	if active {
		for i := range f.revisions {
			f.revisions[i] = f.revisions[i].Set("active", false)
		}
	}
	items, _ := jsjson.Parse(jsjson.Stringify(jsonObject(body.Value("contract")).Value("items")))
	f.revisions = append(f.revisions, jsjson.Object{{Key: "id", Value: id}, {Key: "items", Value: items}, {Key: "active", Value: active}})
	return jsjson.Object{{Key: "id", Value: id}, {Key: "contentHash", Value: "h"}, {Key: "active", Value: active}}, nil
}

func (f *guidedFake) ActivateContractRevision(_ context.Context, org, project, id string) (any, error) {
	f.log("activateContractRevision", org, project, id)
	if f.failing("activate") {
		return nil, f.echo(409, f.failCode)
	}
	for i := range f.revisions {
		f.revisions[i] = f.revisions[i].Set("active", f.revisions[i].Value("id") == id)
	}
	return jsjson.Object{}, nil
}

func (f *guidedFake) EffectiveConfiguration(_ context.Context, org, project, environment string, includeValues bool) (any, error) {
	f.log("effectiveConfiguration", org, project, environment, jsjson.Object{{Key: "includeValues", Value: includeValues}})
	if slices.ContainsFunc(jsonList(f.init.Value("unreadable")), func(v any) bool { return v == environment }) {
		return nil, &apiclient.APIError{Status: 403, Code: "FORBIDDEN", Message: "no", RequestID: "r"}
	}
	if f.failing("read") {
		return nil, f.echo(500, f.failCode)
	}
	items := []any{}
	for _, m := range f.values[environment] {
		var v any = m.Value
		if f.sensitive[m.Key] {
			v = nil
		}
		items = append(items, jsjson.Object{{Key: "name", Value: m.Key}, {Key: "sensitive", Value: f.sensitive[m.Key]}, {Key: "value", Value: v}, {Key: "rawValue", Value: v}})
	}
	return jsjson.Object{{Key: "items", Value: items}}, nil
}

func (f *guidedFake) SetValue(_ context.Context, org, project, environment, item, value string) (any, error) {
	f.log("setValue", org, project, environment, item, jsjson.Object{{Key: "value", Value: value}})
	if f.init.Value("failOn") == item {
		code := f.failCode
		if code == "VALIDATION_FAILED" {
			code = "INTERNAL"
		}
		return nil, &apiclient.APIError{Status: 500, Code: code, Message: "boom", RequestID: "r"}
	}
	if _, ok := f.values[environment]; !ok {
		f.valueOrder = append(f.valueOrder, environment)
	}
	f.values[environment] = f.values[environment].Set(item, value)
	return jsjson.Object{}, nil
}

func (f *guidedFake) state() jsjson.Object {
	values := jsjson.Object{}
	for _, env := range f.valueOrder {
		values = append(values, jsjson.Member{Key: env, Value: f.values[env]})
	}
	revisions := []any{}
	for _, r := range f.revisions {
		revisions = append(revisions, r)
	}
	return jsjson.Object{{Key: "orgs", Value: f.orgs}, {Key: "projects", Value: f.projects}, {Key: "envs", Value: f.envs}, {Key: "values", Value: values}, {Key: "revisions", Value: revisions}}
}

func strs(l []string) []any {
	out := []any{}
	for _, s := range l {
		out = append(out, s)
	}
	return out
}

// TestGuidedInitVectors: Go's guided init gives each recorded case's exit
// status, lines, questions, options, configuration, API calls, server state
// and files, as guidedInit.ts does.
func TestGuidedInitVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/guided-init.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cases := jsonList(doc.(jsjson.Object).Value("cases"))
	if len(cases) < 35 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		t.Run(c.Value("id").(string), func(t *testing.T) {
			dir := t.TempDir()
			for _, m := range jsonObject(c.Value("files")) {
				if err := os.WriteFile(filepath.Join(dir, m.Key), []byte(m.Value.(string)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			fake := newGuidedFake(jsonObject(c.Value("fake")))
			prompt := &scriptedPrompter{dir: dir, answers: jsonList(c.Value("answers"))}
			var out, errs []string
			written := []any{}
			server := "https://vault.example.com"
			if v, ok := c.Get("server"); ok {
				server, _ = v.(string) // null: asked for
			}
			validate, _ := c.Value("validate").(string)
			extra := jsonObject(c.Value("extra"))
			flag := func(key string) string { s, _ := extra.Value(key).(string); return s }
			code, err := guidedInit(guidedDeps{
				cwd:    dir,
				prompt: prompt,
				out:    func(l string) error { out = append(out, l); return nil },
				err:    func(l string) error { errs = append(errs, l); return nil },
				server: server,
				validateServer: func(raw string) (string, error) {
					if validate == "no-query" && strings.Contains(raw, "?") {
						return "", errors.New("Use an origin without path or query: " + raw)
					}
					return raw, nil
				},
				signIn: func(string) (guidedAPI, error) { return fake, nil },
				writeRepository: func(config repoConfig) error {
					written = append(written, jsjson.Object{{Key: "server", Value: config.server}, {Key: "organization", Value: config.organization},
						{Key: "project", Value: config.project}, {Key: "defaultEnvironment", Value: config.defaultEnvironment}})
					return nil
				},
				holdValue:          func(string) {},
				organization:       flag("organization"),
				project:            flag("project"),
				defaultEnvironment: flag("defaultEnvironment"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(prompt.problems) > 0 || len(prompt.answers) > 0 {
				t.Fatalf("questions: %v; %d answer(s) never asked for; asked %q", prompt.problems, len(prompt.answers), prompt.asked)
			}
			files := jsjson.Object{}
			names, _ := os.ReadDir(dir)
			var sorted []string
			for _, e := range names {
				sorted = append(sorted, e.Name())
			}
			sort.Strings(sorted)
			for _, name := range sorted {
				b, _ := os.ReadFile(filepath.Join(dir, name))
				files = append(files, jsjson.Member{Key: name, Value: string(b)})
			}
			deleted := []any{}
			for _, m := range jsonObject(c.Value("files")) {
				if _, err := os.Stat(filepath.Join(dir, m.Key)); err != nil {
					deleted = append(deleted, m.Key)
				}
			}
			got := jsjson.Object{
				{Key: "code", Value: float64(code)}, {Key: "out", Value: strs(out)}, {Key: "err", Value: strs(errs)},
				{Key: "asked", Value: strs(prompt.asked)}, {Key: "shown", Value: strs(prompt.shown)}, {Key: "said", Value: strs(prompt.said)},
				{Key: "written", Value: written}, {Key: "calls", Value: append([]any{}, fake.calls...)}, {Key: "state", Value: fake.state()},
				{Key: "files", Value: files}, {Key: "deleted", Value: deleted},
			}
			want := c.Value("expect").(jsjson.Object)
			for _, m := range want {
				g, _ := got.Get(m.Key)
				if a, b := string(jsjson.Stringify(g)), string(jsjson.Stringify(m.Value)); a != b {
					t.Errorf("%s\n got %s\nwant %s", m.Key, a, b)
				}
			}
		})
	}
}

// TestPrompterVectors: the terminal prompter writes what prompt.ts writes,
// byte for byte, and reads each answer as it does (line ends, trimming,
// defaults, numbers, the end of the input).
func TestPrompterVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/guided-init.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cases := jsonList(doc.(jsjson.Object).Value("prompter"))
	if len(cases) < 10 {
		t.Fatalf("only %d prompter cases", len(cases))
	}
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		t.Run(c.Value("id").(string), func(t *testing.T) {
			var stdout, stderr strings.Builder
			r := &Run{IO: IO{Stdin: strings.NewReader(c.Value("input").(string)), Stdout: &stdout, Stderr: &stderr}, Env: MapEnv{}, Secrets: &Secrets{}}
			p := newTerminalPrompter(r)
			results := []any{}
			var failure any
			for _, rawOp := range jsonList(c.Value("ops")) {
				op := rawOp.(jsjson.Object)
				var result any
				var err error
				switch {
				case op.Value("select") != nil:
					options := []string{}
					for _, o := range jsonList(op.Value("options")) {
						options = append(options, o.(string))
					}
					pre := 0
					if v, ok := op.Value("preselected").(float64); ok {
						pre = int(v)
					}
					var n int
					n, err = p.choose(op.Value("select").(string), options, pre)
					result = float64(n)
				case op.Value("confirm") != nil:
					result, err = p.confirm(op.Value("confirm").(string), op.Value("defaultYes") == true)
				case op.Value("text") != nil:
					def, _ := op.Value("defaultValue").(string)
					result, err = p.text(op.Value("text").(string), def)
				default:
					err = p.say(op.Value("say").(string))
				}
				if err != nil {
					failure = err.Error()
					break
				}
				results = append(results, result)
			}
			got := jsjson.Object{{Key: "results", Value: results}, {Key: "error", Value: failure}, {Key: "written", Value: stdout.String()}}
			if a, b := string(jsjson.Stringify(got)), string(jsjson.Stringify(c.Value("expect"))); a != b {
				t.Errorf("\n got %s\nwant %s", a, b)
			}
		})
	}
}
