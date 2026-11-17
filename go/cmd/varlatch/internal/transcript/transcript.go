// SPDX-License-Identifier: Apache-2.0

// Package transcript replays the Go CLI's transcripts (internal
// docs/design/go-cli.md, decision 3): cases recorded from the TypeScript CLI
// by apps/cli/test/go-transcripts.test.ts (its recorder, goKit.ts), run
// again against the Go CLI with the same arguments, environment, files,
// standard input and fake server, and compared byte for byte.
//
// The comparison is strict in both directions: a request the case does not
// expect, an expected request never sent, a file written that the case does
// not list, and a listed file not written each fail the case. It is test
// infrastructure: only tests import it.
package transcript

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Schema is the transcript files' format version, goKit.ts's TRANSCRIPT_SCHEMA.
const Schema = 1

// RecordedHeaders are the request headers a recording keeps (goKit.ts).
var RecordedHeaders = []string{"authorization", "user-agent", "content-type", "accept", "idempotency-key"}

// File is one area's recording.
type File struct {
	Schema  int    `json:"schema"`
	Comment string `json:"comment"`
	Area    string `json:"area"`
	Cases   []Case `json:"cases"`
}

// Case is one recorded case.
type Case struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env,omitempty"`
	Stdin       string            `json:"stdin,omitempty"`
	Files       map[string]string `json:"files,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Server      []Exchange        `json:"server,omitempty"`
	Differences []string          `json:"differences,omitempty"`
	Expect      Outcome           `json:"expect"`
}

// Exchange is one request the fake server expects, in order, and its answer.
type Exchange struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Answer  json.RawMessage   `json:"answer,omitempty"`
}

// Outcome is what a run did.
type Outcome struct {
	Status   int                  `json:"status"`
	Stdout   string               `json:"stdout"`
	Stderr   string               `json:"stderr"`
	Requests []Request            `json:"requests"`
	Files    map[string]FileState `json:"files"`
}

// Request is one request the fake server received.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// FileState is a file under the case directory after the run.
type FileState struct {
	Mode    string `json:"mode"`
	Content string `json:"content"`
}

// Load reads an area's recording.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != Schema {
		return nil, fmt.Errorf("%s: schema %d, want %d", path, f.Schema, Schema)
	}
	return &f, nil
}

// Command starts the CLI under test with args; the replay sets its
// directory, environment and streams.
type Command func(args []string) *exec.Cmd

// Difference rewrites a recording's expectation where the Go CLI differs on
// purpose (go/README.md, the Go CLI's accepted differences).
type Difference func(*Outcome)

// Replay runs c against the CLI and returns what it did and every way that
// differs from the recording.
func Replay(c Case, start Command, differences map[string]Difference) (Outcome, []string, error) {
	dir, err := os.MkdirTemp("", "varlatch-transcript-")
	if err != nil {
		return Outcome{}, nil, err
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return Outcome{}, nil, err
	}
	srv, err := newServer(c.Server, dir)
	if err != nil {
		return Outcome{}, nil, err
	}
	defer srv.close()
	fill := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "{{server}}", srv.origin), "{{dir}}", dir)
	}
	initial := map[string]string{}
	for rel, content := range c.Files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return Outcome{}, nil, err
		}
		initial[rel] = fill(content)
		if err := os.WriteFile(p, []byte(initial[rel]), 0o644); err != nil {
			return Outcome{}, nil, err
		}
	}
	cwd := filepath.Join(dir, filepath.FromSlash(c.Cwd))
	for _, d := range []string{cwd, filepath.Join(dir, "home")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return Outcome{}, nil, err
		}
	}
	env := map[string]string{
		"PATH":                os.Getenv("PATH"),
		"HOME":                filepath.Join(dir, "home"),
		"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"),
		"VARLATCH_NODE_CHECK": "off",
	}
	if runtime.GOOS == "windows" {
		env["USERPROFILE"] = env["HOME"]
		env["SYSTEMROOT"] = os.Getenv("SYSTEMROOT")
	}
	for k, v := range c.Env {
		env[k] = fill(v)
	}
	args := make([]string, len(c.Args))
	for i, a := range c.Args {
		args[i] = fill(a)
	}
	cmd := start(args)
	cmd.Dir = cwd
	cmd.Env = nil
	for _, k := range slices.Sorted(mapKeys(env)) {
		cmd.Env = append(cmd.Env, k+"="+env[k])
	}
	cmd.Stdin = strings.NewReader(c.Stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return Outcome{}, nil, err
	}
	timer := time.AfterFunc(60*time.Second, func() { _ = cmd.Process.Kill() })
	err = cmd.Wait()
	timer.Stop()
	status := 0
	if err != nil {
		var exit *exec.ExitError
		if !asExit(err, &exit) {
			return Outcome{}, nil, err
		}
		status = exit.ExitCode()
	}
	unfill := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, srv.origin, "{{server}}"), dir, "{{dir}}")
	}
	got := Outcome{Status: status, Stdout: unfill(stdout.String()), Stderr: unfill(stderr.String()), Files: map[string]FileState{}}
	for _, r := range srv.received() {
		r.Path = unfill(r.Path)
		for k, v := range r.Headers {
			r.Headers[k] = unfill(v)
		}
		r.Body = json.RawMessage(unfill(string(r.Body)))
		got.Requests = append(got.Requests, r)
	}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if want, ok := initial[rel]; ok && want == string(data) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		got.Files[rel] = FileState{Mode: fmt.Sprintf("%04o", info.Mode().Perm()), Content: unfill(string(data))}
		return nil
	})
	if err != nil {
		return got, nil, err
	}
	want := c.Expect
	for _, name := range c.Differences {
		d, ok := differences[name]
		if !ok {
			return got, nil, fmt.Errorf("case %s: no accepted difference %q", c.ID, name)
		}
		want = clone(want)
		d(&want)
	}
	return got, Compare(want, got), nil
}

func asExit(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func clone(o Outcome) Outcome {
	c := o
	c.Requests = slices.Clone(o.Requests)
	c.Files = map[string]FileState{}
	for k, v := range o.Files {
		c.Files[k] = v
	}
	return c
}

// Compare lists every way got differs from want; nil when they agree.
// File modes are not compared on Windows (decision 4: Node's chmod sets
// only the read-only bit there).
func Compare(want, got Outcome) []string {
	var problems []string
	if want.Status != got.Status {
		problems = append(problems, fmt.Sprintf("exit status %d, want %d", got.Status, want.Status))
	}
	if want.Stdout != got.Stdout {
		problems = append(problems, "stdout differs:\n"+diff(want.Stdout, got.Stdout))
	}
	if want.Stderr != got.Stderr {
		problems = append(problems, "stderr differs:\n"+diff(want.Stderr, got.Stderr))
	}
	for i := 0; i < max(len(want.Requests), len(got.Requests)); i++ {
		switch {
		case i >= len(got.Requests):
			problems = append(problems, fmt.Sprintf("expected request %d (%s %s) was never sent", i+1, want.Requests[i].Method, want.Requests[i].Path))
		case i >= len(want.Requests):
			problems = append(problems, fmt.Sprintf("unexpected request %d: %s %s", i+1, got.Requests[i].Method, got.Requests[i].Path))
		default:
			if p := compareRequest(want.Requests[i], got.Requests[i]); p != "" {
				problems = append(problems, fmt.Sprintf("request %d: %s", i+1, p))
			}
		}
	}
	names := map[string]bool{}
	for k := range want.Files {
		names[k] = true
	}
	for k := range got.Files {
		names[k] = true
	}
	sorted := make([]string, 0, len(names))
	for k := range names {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		w, inWant := want.Files[name]
		g, inGot := got.Files[name]
		switch {
		case !inGot:
			problems = append(problems, "expected file "+name+" was not written")
		case !inWant:
			problems = append(problems, "unexpected file "+name+" was written")
		case w.Content != g.Content:
			problems = append(problems, "file "+name+" differs:\n"+diff(w.Content, g.Content))
		case w.Mode != g.Mode && runtime.GOOS != "windows":
			problems = append(problems, fmt.Sprintf("file %s has mode %s, want %s", name, g.Mode, w.Mode))
		}
	}
	return problems
}

func compareRequest(want, got Request) string {
	if want.Method != got.Method || want.Path != got.Path {
		return fmt.Sprintf("%s %s, want %s %s", got.Method, got.Path, want.Method, want.Path)
	}
	if !reflect.DeepEqual(nonNil(want.Headers), nonNil(got.Headers)) {
		return fmt.Sprintf("headers %v, want %v", got.Headers, want.Headers)
	}
	var wb, gb any
	if json.Unmarshal(orNull(want.Body), &wb) != nil || json.Unmarshal(orNull(got.Body), &gb) != nil || !reflect.DeepEqual(wb, gb) {
		return fmt.Sprintf("body %s, want %s", got.Body, want.Body)
	}
	return ""
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func orNull(b json.RawMessage) []byte {
	if len(bytes.TrimSpace(b)) == 0 {
		return []byte("null")
	}
	return b
}

// diff shows the first line where want and got part.
func diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl || i >= len(w) || i >= len(g) {
			return fmt.Sprintf("  line %d: got  %q\n  line %d: want %q", i+1, gl, i+1, wl)
		}
	}
	return "  (the same lines; different line ends)"
}

// server is the fake varlatchd: it answers the case's script in order and
// records every request it receives, as goKit.ts's does.
type server struct {
	origin string
	ln     net.Listener
	srv    *http.Server
	mu     sync.Mutex
	script []Exchange
	got    []Request
}

func newServer(script []Exchange, dir string) (*server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &server{ln: ln, origin: "http://" + ln.Addr().String(), script: slices.Clone(script)}
	escapedDir, _ := json.Marshal(dir)
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		headers := map[string]string{}
		for _, name := range RecordedHeaders {
			if v := r.Header.Values(name); len(v) > 0 {
				headers[name] = strings.Join(v, ", ")
			}
		}
		recorded := json.RawMessage("null")
		if len(body) > 0 {
			if v, err := jsjson.Parse(body); err == nil {
				recorded = jsjson.Stringify(v)
			} else {
				quoted, _ := json.Marshal(string(body))
				recorded = quoted
			}
		}
		s.mu.Lock()
		s.got = append(s.got, Request{Method: r.Method, Path: r.URL.RequestURI(), Headers: headers, Body: recorded})
		var next *Exchange
		if len(s.script) > 0 {
			next = &s.script[0]
			s.script = s.script[1:]
		}
		s.mu.Unlock()
		fill := func(t string) string {
			t = strings.ReplaceAll(t, "{{server}}", s.origin)
			return strings.ReplaceAll(t, "{{dir}}", string(escapedDir[1:len(escapedDir)-1]))
		}
		if next == nil || next.Method != r.Method || fill(next.Path) != r.URL.RequestURI() {
			w.Header().Set("content-type", "text/plain")
			w.WriteHeader(599)
			_, _ = io.WriteString(w, "unexpected request")
			return
		}
		if next.Headers == nil {
			w.Header().Set("content-type", "application/json")
		}
		for k, v := range next.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(next.Status)
		if len(next.Answer) == 0 {
			return
		}
		var text string
		if json.Unmarshal(next.Answer, &text) == nil {
			_, _ = io.WriteString(w, text) // an answer given as text is sent as it is
			return
		}
		v, err := jsjson.Parse([]byte(fill(string(next.Answer))))
		if err != nil {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(jsjson.Stringify(v))
	})}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *server) received() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

func (s *server) close() { _ = s.srv.Close() }
