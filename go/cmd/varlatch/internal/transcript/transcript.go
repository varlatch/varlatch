// SPDX-License-Identifier: Apache-2.0

// Package transcript replays the Go CLI's transcripts (internal
// docs/design/go-cli.md, decision 3): cases recorded from the TypeScript CLI
// by apps/cli/test/go-transcripts.test.ts (its recorder, goKit.ts), run
// again against the Go CLI with the same arguments, environment, files,
// standard input and fake server, and compared byte for byte.
//
// The comparison is strict in both directions: a request the case does not
// expect, an expected request never sent, and any difference in the case
// directory's final tree (a file or directory added, deleted, changed, or
// given another mode) each fail the case. It is test infrastructure: only
// tests import it.
package transcript

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Schema is the transcript files' format version, goKit.ts's
// TRANSCRIPT_SCHEMA. 2: the whole final tree is recorded, inputs and
// directories included.
const Schema = 2

// RecordedHeaders are the request headers a recording keeps (goKit.ts).
var RecordedHeaders = []string{"authorization", "user-agent", "content-type", "accept", "idempotency-key", "varlatch-approval"}

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
	Unset       []string          `json:"unset,omitempty"`
	Stdin       string            `json:"stdin,omitempty"`
	Files       map[string]string `json:"files,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	Server      []Exchange        `json:"server,omitempty"`
	Differences []string          `json:"differences,omitempty"`
	Patterns    []string          `json:"patterns,omitempty"`
	// Callback answers the browser sign-in's loopback callback as the
	// sign-in page does: once stdout holds the printed address, Body is
	// POSTed to the callback it names, Times times (1 when 0), each on a
	// connection of its own.
	Callback *Callback `json:"callback,omitempty"`
	// Signal sends Ctrl-C once stderr holds After.
	Signal *Signal `json:"signal,omitempty"`
	// Terminal runs the CLI on a pseudo-terminal, its controlling terminal
	// and stdin, and its "stdout", "stderr" or "both" (onTerminal);
	// Expect.Terminal is what the terminal displayed. Not replayed where
	// there is no pseudo-terminal (Windows).
	Terminal string `json:"terminal,omitempty"`
	// Platform is the fake platforms' script (platform.go).
	Platform []Exchange `json:"platform,omitempty"`
	Expect   Outcome    `json:"expect"`
}

// Callback is a case's browser sign-in callback.
type Callback struct {
	Body  string `json:"body"`
	Times int    `json:"times,omitempty"`
}

// Signal is a case's Ctrl-C.
type Signal struct {
	After string `json:"after"`
}

// ErrUnsupported is a case this platform cannot replay (Ctrl-C on Windows).
var ErrUnsupported = errors.New("the case cannot be replayed on this platform")

// Exchange is one request the fake server expects, in order, and its answer.
type Exchange struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	// Answer is the body: nil for none, and the JSON null ("null") sent as
	// that, as the recorder sends an answer that is null.
	Answer json.RawMessage `json:"answer,omitempty"`
}

// UnmarshalJSON keeps an answer that is null, which encoding/json would
// read as no answer.
func (e *Exchange) UnmarshalJSON(data []byte) error {
	type plain Exchange
	if err := json.Unmarshal(data, (*plain)(e)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if answer, ok := fields["answer"]; ok {
		e.Answer = answer
	}
	return nil
}

// Outcome is what a run did.
type Outcome struct {
	Status   int                  `json:"status"`
	Stdout   string               `json:"stdout"`
	Stderr   string               `json:"stderr"`
	Requests []Request            `json:"requests"`
	Files    map[string]FileState `json:"files"`
	// Callbacks is what each callback POST got: its status, or "refused".
	Callbacks []string `json:"callbacks,omitempty"`
	// PlatformRequests is every request the fake platforms received, when
	// the case gives them a script.
	PlatformRequests []PlatformRequest `json:"platformRequests,omitempty"`
	// Terminal is what a terminal case's terminal displayed (Case.Terminal).
	Terminal string `json:"terminal,omitempty"`
}

// Request is one request the fake server received.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// FileState is one entry of the case directory's final tree: a file (its
// UTF-8 content), a directory (its path ends in "/", no content) or a
// symbolic link (mode "link", content its target), with its POSIX mode.
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

// caseDirLetters are the letters a case directory's name is drawn from:
// consonants only, so a name holds no digit and spells no word.
const caseDirLetters = "bcdfghjklmnpqrstvwxz"

// maskableLength is the shortest value a run's masking replaces wherever
// it occurs: matcher.MinLength, the redaction engine's, and
// cli.MinMaskedLength, the stored Secrets'.
const maskableLength = 8

// CaseValues are the texts a case gives the CLI that it may treat as
// values: values are its variables, its stdin and its arguments (a value in
// flight, such as `values set PORT 8080`'s, is masked whatever its
// length); maskable are its variables and stdin of maskableLength bytes or
// more, which masking replaces wherever they occur. A PORT=8080 case once
// ran in a directory whose random name held 8080, and masking the value
// rewrote the path.
func CaseValues(c Case) (values, maskable []string) {
	add := func(v string, from bool) {
		if len(v) < 2 || strings.Contains(v, "{{") {
			return
		}
		values = append(values, v)
		if from && len(v) >= maskableLength {
			maskable = append(maskable, v)
		}
	}
	for _, v := range c.Env {
		add(v, true)
	}
	add(c.Stdin, true)
	for _, a := range c.Args {
		add(a, false)
	}
	return values, maskable
}

// CaseDir makes a new directory in base for one case, named
// varlatch-transcript- and sixteen random consonants (no digit, no word),
// and gives its real path (macOS's temporary directory is behind a
// symbolic link). Only the random name is the harness's: one that any of
// the case's values overlaps is discarded and another drawn. The rest of
// the path is the system's (C:\Users\runneradmin\AppData\Local\Temp on a
// Windows runner holds "run" and "admin"): it fails only when it holds a
// maskable value, which would rewrite it on every run.
func CaseDir(base string, values, maskable []string) (string, error) {
	for range 100 {
		name := make([]byte, 16)
		for i := range name {
			name[i] = caseDirLetters[rand.IntN(len(caseDirLetters))]
		}
		dir := filepath.Join(base, "varlatch-transcript-"+string(name))
		if err := os.Mkdir(dir, 0o700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", err
		}
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
		if slices.ContainsFunc(maskable, func(v string) bool { return strings.Contains(real, v) }) {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("the temporary directory %s holds one of the case's variables or its stdin", base)
		}
		if !slices.ContainsFunc(values, func(v string) bool { return overlapsEnd(real, v, len(name)) }) {
			return real, nil
		}
		_ = os.RemoveAll(dir)
	}
	return "", fmt.Errorf("no name in %s that none of the case's values overlaps", base)
}

// overlapsEnd is whether v occurs in path in a place that takes in any of
// its last n bytes.
func overlapsEnd(path, v string, n int) bool {
	from := max(0, len(path)-n-len(v)+1)
	return strings.Contains(path[from:], v)
}

// Difference rewrites a recording's expectation where the Go CLI differs on
// purpose (go/README.md, the Go CLI's accepted differences), given what the
// Go CLI did.
type Difference func(want *Outcome, got Outcome)

// Replay runs c against the CLI and returns what it did and every way that
// differs from the recording.
func Replay(c Case, start Command, differences map[string]Difference) (Outcome, []string, error) {
	values, maskable := CaseValues(c)
	dir, err := CaseDir(os.TempDir(), values, maskable)
	if err != nil {
		return Outcome{}, nil, err
	}
	defer os.RemoveAll(dir)
	srv, err := newServer(c.Server, dir)
	if err != nil {
		return Outcome{}, nil, err
	}
	defer srv.close()
	var platforms *platformServer
	if c.Platform != nil {
		if platforms, err = newPlatformServer(c.Platform); err != nil {
			return Outcome{}, nil, err
		}
		defer platforms.close()
	}
	fill := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "{{server}}", srv.origin), "{{dir}}", dir)
	}
	release := slices.Contains(c.Patterns, "release")
	// Inputs get Node.js's default modes (0666 and 0777, less the umask), as
	// the recorder's writeFileSync and mkdirSync give them.
	for rel, content := range c.Files {
		if release {
			content = ReleaseFill(content)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o777); err != nil {
			return Outcome{}, nil, err
		}
		if err := os.WriteFile(p, []byte(fill(content)), 0o666); err != nil {
			return Outcome{}, nil, err
		}
	}
	cwd := filepath.Join(dir, filepath.FromSlash(c.Cwd))
	for _, d := range []string{cwd, filepath.Join(dir, "home")} {
		if err := os.MkdirAll(d, 0o777); err != nil {
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
	for _, k := range c.Unset {
		delete(env, k)
	}
	for k, v := range c.Env {
		env[k] = fill(v)
	}
	// Not part of the case's environment: how the CLI under test reaches the fake platforms.
	if platforms != nil {
		env[PlatformEnv] = platforms.addr
		env["NODE_EXTRA_CA_CERTS"] = platforms.cert
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
	for _, name := range c.Patterns {
		if _, err := ApplyPatterns([]string{name}, "", 0, 0); err != nil {
			return Outcome{}, nil, fmt.Errorf("case %s: %w", c.ID, err)
		}
	}
	if c.Signal != nil && runtime.GOOS == "windows" {
		return Outcome{}, nil, ErrUnsupported
	}
	if c.Terminal != "" && (c.Signal != nil || c.Callback != nil || c.Stdin != "") {
		return Outcome{}, nil, fmt.Errorf("case %s: a terminal case has no signal, callback or stdin", c.ID)
	}
	var status int
	var stdout, stderr, shown string
	var callbacks []string
	var began, end int64
	if c.Terminal != "" {
		began = time.Now().UnixMilli()
		if status, stdout, stderr, shown, err = onTerminal(cmd, c.Terminal); err != nil {
			return Outcome{}, nil, err
		}
		end = time.Now().UnixMilli()
	} else if status, stdout, stderr, callbacks, began, end, err = run(cmd, c); err != nil {
		return Outcome{}, nil, err
	}
	unfill := func(s string) string {
		s = UnfillDir(strings.ReplaceAll(s, srv.origin, "{{server}}"), dir)
		s, _ = ApplyPatterns(c.Patterns, s, began, end)
		return s
	}
	got := Outcome{Status: status, Stdout: unfill(stdout), Stderr: unfill(stderr), Files: map[string]FileState{}, Callbacks: callbacks, Terminal: unfill(shown)}
	for _, r := range srv.received() {
		r.Path = unfill(r.Path)
		for k, v := range r.Headers {
			r.Headers[k] = unfill(v)
		}
		r.Body = json.RawMessage(unfill(string(r.Body)))
		got.Requests = append(got.Requests, r)
	}
	if slices.Contains(c.Patterns, "generated") {
		got.Requests = GeneratedPattern(c.Args, got.Requests, stdout+stderr)
	}
	if platforms != nil {
		got.PlatformRequests = []PlatformRequest{}
		for _, r := range platforms.received() {
			r.Path = unfill(r.Path)
			r.Body = json.RawMessage(unfill(string(r.Body)))
			got.PlatformRequests = append(got.PlatformRequests, r)
		}
	}
	if got.Files, err = Tree(dir, unfill); err != nil {
		return got, nil, err
	}
	want := c.Expect
	for _, name := range c.Differences {
		d, ok := differences[name]
		if !ok {
			return got, nil, fmt.Errorf("case %s: no accepted difference %q", c.ID, name)
		}
		want = clone(want)
		d(&want, got)
	}
	return got, Compare(want, got), nil
}

// run runs cmd with pipes, acting on what it writes as the case says (the
// callback, Ctrl-C).
func run(cmd *exec.Cmd, c Case) (status int, stdout, stderr string, callbacks []string, began, end int64, err error) {
	watch := &watcher{c: c}
	cmd.Stdout, cmd.Stderr = watch.stream(&watch.stdout), watch.stream(&watch.stderr)
	began = time.Now().UnixMilli()
	if err := cmd.Start(); err != nil {
		return 0, "", "", nil, 0, 0, err
	}
	watch.mu.Lock()
	watch.process = cmd.Process
	watch.react() // what the run wrote before the process was known
	watch.mu.Unlock()
	timer := time.AfterFunc(60*time.Second, func() { _ = cmd.Process.Kill() })
	waited := cmd.Wait()
	timer.Stop()
	if waited != nil {
		var exit *exec.ExitError
		if !asExit(waited, &exit) {
			return 0, "", "", nil, 0, 0, waited
		}
		status = exitStatus(exit)
	}
	callbacks = watch.callbacksDone()
	end = time.Now().UnixMilli()
	stdout, stderr = watch.text()
	return status, stdout, stderr, callbacks, began, end, nil
}

// UnfillDir is goKit.ts's unfillDir: the case directory as {{dir}}, both as
// it is printed and as a JSON string holds it (each backslash doubled, so
// on Windows `C:\\Users\\...` in a --json document or a file the CLI wrote
// as JSON is the directory too). On Linux and macOS a directory holds no
// backslash, so the two forms are the same.
func UnfillDir(s, dir string) string {
	if escaped := strings.ReplaceAll(dir, `\`, `\\`); escaped != dir {
		s = strings.ReplaceAll(s, escaped, "{{dir}}")
	}
	return strings.ReplaceAll(s, dir, "{{dir}}")
}

// GeneratedPattern is goKit.ts's generatedPattern, the "generated" pattern:
// a value `--generate` made is random, so each request body's string
// "value" becomes `{{generated <spec>}}` (the spec args give) when it has
// exactly the alphabet and length the spec gives and appears nowhere in
// output, and a value-free note of what is wrong with it otherwise: no
// recording, comparison or failure ever holds the value.
func GeneratedPattern(args []string, requests []Request, output string) []Request {
	spec := ""
	if i := slices.Index(args, "--generate"); i >= 0 && i+1 < len(args) {
		spec = args[i+1]
	}
	out := make([]Request, len(requests))
	for i, r := range requests {
		out[i] = r
		body, err := jsjson.Parse(r.Body)
		if err != nil {
			continue
		}
		o, ok := body.(jsjson.Object)
		if !ok {
			continue
		}
		value, ok := o.Value("value").(string)
		if !ok {
			continue
		}
		note := "{{generated " + spec + "}}"
		switch {
		case !GeneratedBy(spec, value):
			note = "{{generated value of another shape}}"
		case strings.Contains(output, value):
			note = "{{generated value shown in the output}}"
		}
		o = append(jsjson.Object(nil), o...).Set("value", note)
		out[i].Body = json.RawMessage(jsjson.Stringify(o))
	}
	return out
}

// GeneratedBy is whether value has the alphabet and length the generator
// spec (secretInput.ts's --generate) gives: hex of 2n digits, base64 with
// its padding, base64url without, alnum of n characters.
func GeneratedBy(spec, value string) bool {
	m := generatorSpec.FindStringSubmatch(spec)
	if m == nil {
		return false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return false
	}
	var pattern string
	switch m[1] {
	case "hex":
		pattern = fmt.Sprintf(`^[0-9a-f]{%d}$`, 2*n)
	case "base64":
		pattern = fmt.Sprintf(`^[A-Za-z0-9+/]{%d}={%d}$`, (4*n+2)/3, (3-n%3)%3)
	case "base64url":
		pattern = fmt.Sprintf(`^[A-Za-z0-9_-]{%d}$`, (4*n+2)/3)
	default:
		pattern = fmt.Sprintf(`^[A-Za-z0-9]{%d}$`, n)
	}
	return regexp.MustCompile(pattern).MatchString(value)
}

var generatorSpec = regexp.MustCompile(`^(hex|base64|base64url|alnum):([0-9]+)$`)

// isoTimestamp is Date.prototype.toISOString's form.
var isoTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z`)

// ReleaseFill and ReleaseUnfill are goKit.ts's releasePattern, the
// "release" pattern, for this build's release: `{{release}}` in a case's
// files is the version, and `varlatch <version>` in what the CLI did is
// `varlatch {{release}}`. Another release a case names stays as it is.
func ReleaseFill(text string) string {
	return strings.ReplaceAll(text, "{{release}}", buildinfo.Version)
}

// ReleaseUnfill is the "release" pattern on what the CLI did.
func ReleaseUnfill(text string) string {
	return strings.ReplaceAll(text, "varlatch "+buildinfo.Version, "varlatch {{release}}")
}

// NowPattern is goKit.ts's nowPattern, the "now" pattern: each ISO 8601
// timestamp with milliseconds from start to end (Unix milliseconds) as
// {{now}}. A case lists the patterns it needs; a timestamp outside the
// run's own window is compared as it is.
func NowPattern(text string, start, end int64) string {
	return isoTimestamp.ReplaceAllStringFunc(text, func(t string) string {
		at, err := time.Parse("2006-01-02T15:04:05.000Z", t)
		if err != nil {
			return t
		}
		if ms := at.UnixMilli(); ms >= start && ms <= end {
			return "{{now}}"
		}
		return t
	})
}

// LaterPattern is goKit.ts's laterPattern, the "now+<s>" pattern: each
// timestamp from start to end plus seconds, as {{now+<s>}}.
func LaterPattern(text string, start, end int64, seconds int64) string {
	return isoTimestamp.ReplaceAllStringFunc(text, func(t string) string {
		at, err := time.Parse("2006-01-02T15:04:05.000Z", t)
		if err != nil {
			return t
		}
		if ms := at.UnixMilli() - seconds*1000; ms >= start && ms <= end {
			return "{{now+" + strconv.FormatInt(seconds, 10) + "}}"
		}
		return t
	})
}

// callbackPort is the loopback callback's port in a printed sign-in address.
var callbackPort = regexp.MustCompile(`(callback=http%3A%2F%2F127\.0\.0\.1%3A)\d+(%2F)`)

// laterName is a "now+<s>" pattern's name.
var laterName = regexp.MustCompile(`^now\+(\d+)$`)

// ApplyPatterns is goKit.ts's applyPatterns: the patterns a case names,
// in order: "now", "now+<s>", "callback" (the loopback port as {{port}})
// and "release" (ReleaseUnfill); "generated" applies to request bodies
// (GeneratedPattern).
func ApplyPatterns(patterns []string, text string, start, end int64) (string, error) {
	for _, name := range patterns {
		switch m := laterName.FindStringSubmatch(name); {
		case name == "now":
			text = NowPattern(text, start, end)
		case m != nil:
			seconds, _ := strconv.ParseInt(m[1], 10, 64)
			text = LaterPattern(text, start, end, seconds)
		case name == "callback":
			text = callbackPort.ReplaceAllString(text, "${1}{{port}}${2}")
		case name == "release":
			text = ReleaseUnfill(text)
		case name == "generated":
			// Applies to request bodies (GeneratedPattern), not to text.
		default:
			return text, fmt.Errorf("no pattern %q", name)
		}
	}
	return text, nil
}

// watcher collects a run's output as it comes, and acts on it: the
// callback once stdout prints the address, Ctrl-C once stderr says the
// case's text.
type watcher struct {
	c              Case
	mu             sync.Mutex
	stdout, stderr bytes.Buffer
	process        *os.Process
	called         bool
	signalled      bool
	done           chan []string
}

type watchedStream struct {
	w   *watcher
	buf *bytes.Buffer
}

func (s watchedStream) Write(p []byte) (int, error) {
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	s.buf.Write(p)
	s.w.react()
	return len(p), nil
}

func (w *watcher) stream(buf *bytes.Buffer) io.Writer { return watchedStream{w, buf} }

// callbackAddress is the callback a printed sign-in address names.
var callbackAddress = regexp.MustCompile(`callback=(\S+)\n`)

// react runs with the lock held, after each write.
func (w *watcher) react() {
	if cb := w.c.Callback; cb != nil && !w.called {
		if m := callbackAddress.FindStringSubmatch(w.stdout.String()); m != nil {
			w.called = true
			target, err := url.QueryUnescape(m[1])
			times := max(cb.Times, 1)
			w.done = make(chan []string, 1)
			go func() {
				var got []string
				for range times {
					if err != nil {
						got = append(got, "refused")
						continue
					}
					got = append(got, postOnce(target, cb.Body))
				}
				w.done <- got
			}()
		}
	}
	if sig := w.c.Signal; sig != nil && !w.signalled && w.process != nil && strings.Contains(w.stderr.String(), sig.After) {
		w.signalled = true
		_ = w.process.Signal(os.Interrupt)
	}
}

// callbacksDone waits for the callbacks' answers, if any were made.
func (w *watcher) callbacksDone() []string {
	w.mu.Lock()
	done := w.done
	w.mu.Unlock()
	if w.c.Callback == nil {
		return nil
	}
	if done == nil {
		return []string{}
	}
	select {
	case got := <-done:
		return got
	case <-time.After(5 * time.Second):
		return []string{"no answer"}
	}
}

func (w *watcher) text() (string, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stdout.String(), w.stderr.String()
}

// postOnce POSTs body to target on a connection of its own: the status, or
// "refused".
func postOnce(target, body string) string {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	res, err := client.Post(target, "application/json", strings.NewReader(body))
	if err != nil {
		return "refused"
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return strconv.Itoa(res.StatusCode)
}

// exitStatus is a run's status as a shell reports it: 128 plus the signal
// for a process a signal ended (130 for Ctrl-C).
func exitStatus(exit *exec.ExitError) int {
	if code := exit.ExitCode(); code >= 0 {
		return code
	}
	return signalStatus(exit)
}

// Tree is the final state of everything under dir, dir itself excepted,
// as goKit.ts's listTree records it: every file with its content, every
// directory (its path ends in "/"), every symbolic link with its target
// (never followed), each with its permission bits.
func Tree(dir string, unfill func(string) string) (map[string]FileState, error) {
	out := map[string]FileState{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := fmt.Sprintf("%04o", info.Mode().Perm())
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = FileState{Mode: "link", Content: unfill(filepath.ToSlash(target))}
		case info.IsDir():
			out[rel+"/"] = FileState{Mode: mode}
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = FileState{Mode: mode, Content: unfill(string(data))}
		}
		return nil
	})
	return out, err
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
	c.PlatformRequests = slices.Clone(o.PlatformRequests)
	c.Files = map[string]FileState{}
	for k, v := range o.Files {
		c.Files[k] = v
	}
	return c
}

// Compare lists every way got differs from want; nil when they agree.
// On Windows only the owner's write bit of a mode is compared: the
// read-only attribute is all Node.js's chmod sets there (decision 4).
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
	if want.Terminal != got.Terminal {
		problems = append(problems, "the terminal differs:\n"+diff(want.Terminal, got.Terminal))
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
	problems = append(problems, comparePlatform(want.PlatformRequests, got.PlatformRequests)...)
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
	if !slices.Equal(want.Callbacks, got.Callbacks) {
		problems = append(problems, fmt.Sprintf("the callbacks got %q, want %q", got.Callbacks, want.Callbacks))
	}
	for _, name := range sorted {
		w, inWant := want.Files[name]
		g, inGot := got.Files[name]
		switch {
		case !inGot:
			problems = append(problems, name+" is missing afterwards (deleted, or never written)")
		case !inWant:
			problems = append(problems, name+" is there afterwards, but the case has no such entry")
		case w.Content != g.Content:
			problems = append(problems, name+" differs:\n"+diff(w.Content, g.Content))
		case !sameMode(w.Mode, g.Mode, runtime.GOOS):
			problems = append(problems, fmt.Sprintf("%s has mode %s, want %s", name, g.Mode, w.Mode))
		}
	}
	return problems
}

// sameMode compares two recorded modes: exactly, except on Windows, where
// only the owner's write bit (the read-only attribute) means anything.
func sameMode(want, got, goos string) bool {
	if want == got {
		return true
	}
	if goos != "windows" || want == "link" || got == "link" {
		return false
	}
	w, err1 := strconv.ParseUint(want, 8, 32)
	g, err2 := strconv.ParseUint(got, 8, 32)
	return err1 == nil && err2 == nil && w&0o200 == g&0o200
}

func compareRequest(want, got Request) string {
	if want.Method != got.Method || want.Path != got.Path {
		return fmt.Sprintf("%s %s, want %s %s", got.Method, got.Path, want.Method, want.Path)
	}
	if !reflect.DeepEqual(nonNil(want.Headers), nonNil(got.Headers)) {
		return fmt.Sprintf("headers %v, want %v", got.Headers, want.Headers)
	}
	// Through jsjson, which keeps lone surrogates as they are: encoding/json
	// would turn \ud800 and \ud801 both into U+FFFD and call them equal.
	wb, err1 := jsjson.Parse(orNull(want.Body))
	gb, err2 := jsjson.Parse(orNull(got.Body))
	if err1 != nil || err2 != nil || !SameJSON(wb, gb) {
		return fmt.Sprintf("body %s, want %s", got.Body, want.Body)
	}
	return ""
}

// SameJSON is whether two jsjson values are equal as JSON values: object
// members in any order, strings byte for byte (lone surrogates included),
// numbers by value.
func SameJSON(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool, float64, string:
		return a == b
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !SameJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case jsjson.Object:
		y, ok := b.(jsjson.Object)
		if !ok || len(x) != len(y) {
			return false
		}
		for _, m := range x {
			v, ok := y.Get(m.Key)
			if !ok || !SameJSON(m.Value, v) {
				return false
			}
		}
		return true
	}
	return false
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
				headers[name] = latin1(strings.Join(v, ", "))
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
		if next.Answer[0] == '"' && json.Unmarshal(next.Answer, &text) == nil {
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

// latin1 is a header value as Node.js's HTTP server gives it to the
// recorder: each byte one character.
func latin1(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(rune(s[i]))
	}
	return b.String()
}

func (s *server) received() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

func (s *server) close() { _ = s.srv.Close() }
