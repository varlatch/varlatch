// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
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
		"unexpected file":    {func(o *Outcome) { o.Files["config/settings.json"] = FileState{Mode: "0600", Content: "{}"} }, "unexpected file config/settings.json was written"},
		"missing file":       {func(o *Outcome) { delete(o.Files, "config/credentials.json") }, "expected file config/credentials.json was not written"},
		"file content":       {func(o *Outcome) { o.Files["config/credentials.json"] = FileState{Mode: "0600", Content: "{ }\n"} }, "file config/credentials.json differs"},
	}
	if runtime.GOOS != "windows" {
		cases["file mode"] = struct {
			change func(*Outcome)
			want   string
		}{func(o *Outcome) { o.Files["config/credentials.json"] = FileState{Mode: "0644", Content: "{}\n"} }, "has mode 0644, want 0600"}
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

func TestLoadRefusesAnotherSchema(t *testing.T) {
	p := t.TempDir() + "/x.json"
	if err := os.WriteFile(p, []byte(`{"schema":2,"cases":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("loaded schema 2")
	}
}
