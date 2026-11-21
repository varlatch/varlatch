// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
)

// The comparison must fail on each kind of mismatch, never pass one over
// (internal docs/design/go-cli.md, decision 3).

func base() Outcome {
	return Outcome{
		Status: 0, Stdout: "out\n", Stderr: "",
		Requests: []Request{{Method: "GET", Path: "/v1/meta", Headers: map[string]string{"user-agent": "ua"}, Body: json.RawMessage("null")}},
		Files:    map[string]FileState{"config/credentials.json": {Mode: "0600", Content: "{}\n"}},
	}
}

func TestCompareAgreesWithItself(t *testing.T) {
	if p := Compare(base(), base()); p != nil {
		t.Fatalf("%q", p)
	}
}

func TestCompareFailsOnEveryMismatch(t *testing.T) {
	cases := map[string]struct {
		change func(*Outcome)
		want   string
	}{
		"status":             {func(o *Outcome) { o.Status = 64 }, "exit status 64, want 0"},
		"stdout":             {func(o *Outcome) { o.Stdout = "out" }, "stdout differs"},
		"stderr":             {func(o *Outcome) { o.Stderr = "x\n" }, "stderr differs"},
		"unexpected request": {func(o *Outcome) { o.Requests = append(o.Requests, Request{Method: "POST", Path: "/v1/x"}) }, "unexpected request 2: POST /v1/x"},
		"missing request":    {func(o *Outcome) { o.Requests = nil }, "expected request 1 (GET /v1/meta) was never sent"},
		"request path":       {func(o *Outcome) { o.Requests[0].Path = "/v1/other" }, "request 1: GET /v1/other, want GET /v1/meta"},
		"request header":     {func(o *Outcome) { o.Requests[0].Headers = map[string]string{"user-agent": "other"} }, "request 1: headers"},
		"request body":       {func(o *Outcome) { o.Requests[0].Body = json.RawMessage(`{"a":1}`) }, "request 1: body"},
		"unexpected file":    {func(o *Outcome) { o.Files["config/settings.json"] = FileState{Mode: "0600", Content: "{}"} }, "config/settings.json is there afterwards, but the case has no such entry"},
		"missing file":       {func(o *Outcome) { delete(o.Files, "config/credentials.json") }, "config/credentials.json is missing afterwards"},
		"file content":       {func(o *Outcome) { o.Files["config/credentials.json"] = FileState{Mode: "0600", Content: "{ }\n"} }, "config/credentials.json differs"},
	}
	if runtime.GOOS != "windows" {
		cases["file mode"] = struct {
			change func(*Outcome)
			want   string
		}{func(o *Outcome) { o.Files["config/credentials.json"] = FileState{Mode: "0644", Content: "{}\n"} }, "config/credentials.json has mode 0644, want 0600"}
	}
	for name, c := range cases {
		got := base()
		got.Requests = append([]Request(nil), got.Requests...)
		got.Files = map[string]FileState{"config/credentials.json": base().Files["config/credentials.json"]}
		c.change(&got)
		problems := Compare(base(), got)
		if len(problems) != 1 || !strings.Contains(problems[0], c.want) {
			t.Errorf("%s: %q, want one problem containing %q", name, problems, c.want)
		}
	}
}

// Request bodies are compared as JSON values: member order and spacing do
// not matter, a value does.
func TestCompareBodiesAsValues(t *testing.T) {
	want, got := base(), base()
	want.Requests[0].Body = json.RawMessage(`{"a":1,"b":[1,2]}`)
	got.Requests[0].Body = json.RawMessage(`{ "b": [1, 2], "a": 1 }`)
	if p := Compare(want, got); p != nil {
		t.Fatalf("%q", p)
	}
	got.Requests[0].Body = json.RawMessage(`{"b":[2,1],"a":1}`)
	if p := Compare(want, got); len(p) != 1 {
		t.Fatalf("%q", p)
	}
}

// A replay of a case whose script the program does not follow fails on the
// requests: `sh` (or cmd) stands in for a CLI that sends nothing.
func TestReplayReportsAnUnsentRequest(t *testing.T) {
	shell, flag := "sh", "-c"
	if runtime.GOOS == "windows" {
		shell, flag = "cmd", "/c"
	}
	c := Case{
		ID:     "unsent",
		Args:   []string{"echo out"},
		Server: []Exchange{{Method: "GET", Path: "/v1/meta", Status: 200, Answer: json.RawMessage(`{}`)}},
		Expect: Outcome{Stdout: "out\n", Requests: []Request{{Method: "GET", Path: "/v1/meta", Headers: map[string]string{}, Body: json.RawMessage("null")}}, Files: map[string]FileState{}},
	}
	_, problems, err := Replay(c, func(args []string) *exec.Cmd { return exec.Command(shell, append([]string{flag}, args...)...) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range problems {
		found = found || strings.Contains(p, "was never sent")
	}
	if !found {
		t.Fatalf("%q", problems)
	}
}

// TestUnfillDir: the directory is {{dir}} as printed and inside a JSON
// string, its separators kept (a path below it stays a Windows path).
func TestUnfillDir(t *testing.T) {
	dir := `C:\Users\RUNNER~1\AppData\Local\Temp\varlatch-transcript-x`
	for in, want := range map[string]string{
		`No varlatch.toml found from ` + dir + ` upward.`:                                              `No varlatch.toml found from {{dir}} upward.`,
		`{"offline": "No varlatch.toml found from ` + strings.ReplaceAll(dir, `\`, `\\`) + ` upward"}`: `{"offline": "No varlatch.toml found from {{dir}} upward"}`,
		`{"root": "` + strings.ReplaceAll(dir, `\`, `\\`) + `\\repo"}`:                                 `{"root": "{{dir}}\\repo"}`,
		dir + `\repo`: `{{dir}}\repo`,
	} {
		if got := UnfillDir(in, dir); got != want {
			t.Errorf("UnfillDir(%q) = %q, want %q", in, got, want)
		}
	}
	if got := UnfillDir("/tmp/x/repo and /tmp/x", "/tmp/x"); got != "{{dir}}/repo and {{dir}}" {
		t.Errorf("POSIX: %q", got)
	}
}

func TestLoadRefusesAnotherSchema(t *testing.T) {
	p := t.TempDir() + "/x.json"
	if err := os.WriteFile(p, []byte(`{"schema":3,"cases":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("loaded schema 2")
	}
}

// Request bodies keep lone surrogates: \ud800 and \ud801 are different
// strings, though encoding/json would read both as U+FFFD.
func TestCompareKeepsLoneSurrogates(t *testing.T) {
	want, got := base(), base()
	want.Requests[0].Body = json.RawMessage(`{"value":"\ud800"}`)
	got.Requests[0].Body = json.RawMessage(`{"value":"\ud801"}`)
	if p := Compare(want, got); len(p) != 1 || !strings.Contains(p[0], "body") {
		t.Fatalf("%q", p)
	}
	got.Requests[0].Body = json.RawMessage(`{ "value" : "\ud800" }`)
	if p := Compare(want, got); p != nil {
		t.Fatalf("%q", p)
	}
	got.Requests[0].Body = json.RawMessage(`{"value":"\ufffd"}`)
	if p := Compare(want, got); len(p) != 1 {
		t.Fatalf("U+FFFD equals a lone surrogate: %q", p)
	}
}

// On Windows only the owner's write bit of a mode counts (the read-only
// attribute); elsewhere the whole mode.
func TestSameMode(t *testing.T) {
	cases := []struct {
		want, got, goos string
		same            bool
	}{
		{"0600", "0600", "linux", true},
		{"0600", "0644", "linux", false},
		{"0600", "0666", "windows", true},
		{"0644", "0444", "windows", false},
		{"link", "0666", "windows", false},
	}
	for _, c := range cases {
		if got := sameMode(c.want, c.got, c.goos); got != c.same {
			t.Errorf("sameMode(%s, %s, %s) = %v", c.want, c.got, c.goos, got)
		}
	}
}

// The whole final tree is compared, inputs included: a program that deletes
// an input, changes its mode or content, or adds a directory or a link,
// fails a case whose recording left the tree as it was (Sol's round 1 on
// #247 reproduced the first two).
func TestReplayCatchesChangedInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	untouched := Outcome{Files: map[string]FileState{"input": {Mode: "0644", Content: "x"}, "home/": {Mode: "0755"}}}
	for script, want := range map[string]string{
		"true":                 "",
		"rm ../input":          "input is missing afterwards",
		"chmod 777 ../input":   "input has mode 0777, want 0644",
		"echo y >> ../input":   "input differs",
		"mkdir ../made":        "made/ is there afterwards",
		"ln -s input ../alias": "alias is there afterwards",
	} {
		c := Case{ID: script, Args: []string{script}, Files: map[string]string{"input": "x"}, Cwd: "home", Expect: untouched}
		_, problems, err := Replay(c, func(args []string) *exec.Cmd { return exec.Command("sh", append([]string{"-c"}, args...)...) }, nil)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(problems, "\n")
		if want == "" && len(problems) != 0 || want != "" && !strings.Contains(joined, want) {
			t.Errorf("%s: %q, want %q", script, problems, want)
		}
	}
}

// TestGeneratedPatternIsExact: the "generated" pattern records a value of
// exactly its generator's shape by the spec, and anything else by a note
// that never holds the value.
func TestGeneratedPatternIsExact(t *testing.T) {
	body := func(v string) json.RawMessage { b, _ := json.Marshal(map[string]string{"value": v}); return b }
	for spec, cases := range map[string]map[string]bool{
		"hex:32":       {strings.Repeat("a1", 32): true, strings.Repeat("a", 63): false, strings.Repeat("A", 64): false},
		"base64:32":    {strings.Repeat("A+/", 14) + "a=": true, strings.Repeat("A", 44): false},
		"base64:16":    {strings.Repeat("Ab", 11) + "==": true, strings.Repeat("A", 23) + "=": false},
		"base64url:24": {strings.Repeat("a-_B", 8): true, strings.Repeat("a+", 16): false},
		"alnum:30":     {strings.Repeat("aZ9", 10): true, strings.Repeat("a", 29): false, strings.Repeat("a-", 15): false},
	} {
		for value, accepted := range cases {
			got := GeneratedPattern([]string{"values", "set", "K", "--generate", spec}, []Request{{Body: body(value)}}, "K set\n")
			want := `{"value":"{{generated ` + spec + `}}"}`
			if (string(got[0].Body) == want) != accepted || strings.Contains(string(got[0].Body), value) {
				t.Errorf("%s %q: recorded %s", spec, value, got[0].Body)
			}
		}
	}
	value := strings.Repeat("ab", 32)
	got := GeneratedPattern([]string{"--generate", "hex:32"}, []Request{{Body: body(value)}}, "shown: "+value+"\n")
	if string(got[0].Body) != `{"value":"{{generated value shown in the output}}"}` {
		t.Errorf("a value shown on stdout: recorded %s", got[0].Body)
	}
}

// TestAgentRunPattern: the "agent-run" pattern names exactly a run's
// identifier, a Placeholder and a loopback port, as goKit.ts's does.
func TestAgentRunPattern(t *testing.T) {
	for in, want := range map[string]string{
		"agent-safe run run_0123456789abcdef \u2014 broker on 127.0.0.1:41234": "agent-safe run run_{{id}} \u2014 broker on 127.0.0.1:{{port}}",
		`{"runId":"run_0123456789abcdef"}`:                                     `{"runId":"run_{{id}}"}`,
		"run_0123456789abcdef0":                                                "run_0123456789abcdef0",
		"run_0123456789ABCDEF":                                                 "run_0123456789ABCDEF",
		"API_KEY=vlch_ph_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":                  "API_KEY={{placeholder}}",
		"vlch_ph_v1_short":                                                     "vlch_ph_v1_short",
		"http://10.0.0.1:8080":                                                 "http://10.0.0.1:8080",
	} {
		if got := AgentRunPattern(in); got != want {
			t.Errorf("AgentRunPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPlatformKeyPair: the fake GitHub's public key is its secret key's, as
// goKit.ts gives it, and a value sealed to it opens as {{sealed <value>}}.
func TestPlatformKeyPair(t *testing.T) {
	public, err := curve25519.X25519(PlatformSecretKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(public); got != PlatformPublicKey {
		t.Fatalf("public key %s, want %s", got, PlatformPublicKey)
	}
	sealed, err := vsync.SealedBox([]byte("s3cr3t"), public)
	if err != nil {
		t.Fatal(err)
	}
	body := jsjson.Object{{Key: "encrypted_value", Value: base64.StdEncoding.EncodeToString(sealed)}, {Key: "key_id", Value: "k1"}}
	if got := string(jsjson.Stringify(openSealed(body))); got != `{"encrypted_value":"{{sealed s3cr3t}}","key_id":"k1"}` {
		t.Errorf("opened %s", got)
	}
	if got := string(jsjson.Stringify(openSealed(jsjson.Object{{Key: "encrypted_value", Value: "AAAA"}}))); got != `{"encrypted_value":"{{sealed, not opened}}"}` {
		t.Errorf("not a box: %s", got)
	}
}
