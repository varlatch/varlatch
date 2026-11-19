// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The test binary is also the CLI under test: run with this variable set,
// it is `varlatch` (main's run), so the transcripts run the CLI as a
// process without a second build.
const asCLI = "VARLATCH_TEST_AS_CLI"

func TestMain(m *testing.M) {
	if os.Getenv(asCLI) == "1" {
		os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	setTranscriptUmask()
	os.Exit(m.Run())
}

// versionLine is the TypeScript CLI's --version: `varlatch <version>
// (migration <n>)`.
var versionLine = regexp.MustCompile(`^varlatch \S+ \(migration \d+\)\n$`)

// differences are the Go CLI's accepted differences (go/README.md), by the
// name a recorded case gives.
var differences = map[string]transcript.Difference{
	// Decision 6: `varlatch <version>`, without the migration number.
	"version": func(o *transcript.Outcome, _ transcript.Outcome) {
		if versionLine.MatchString(o.Stdout) {
			o.Stdout = "varlatch " + buildinfo.Version + "\n"
		}
	},
	// The User-Agent names the CLI's own version and the platform it runs
	// on: the recording's, made by TypeScript 0.22.0 on the recorder's
	// machine, becomes this build's, on this machine, with the same
	// assisted token (decision 2: the format is kept, the values are the
	// running CLI's).
	"user-agent": func(o *transcript.Outcome, _ transcript.Outcome) {
		for i := range o.Requests {
			ua, ok := o.Requests[i].Headers["user-agent"]
			if !ok {
				continue
			}
			m := recordedUserAgent.FindStringSubmatch(ua)
			if m == nil {
				continue
			}
			headers := map[string]string{}
			for k, v := range o.Requests[i].Headers {
				headers[k] = v
			}
			headers["user-agent"] = cli.FormatUserAgent(buildinfo.Version, m[1] != "", cli.NodePlatform(), cli.NodeArch())
			o.Requests[i].Headers = headers
		}
	},
	// The skill files `agents install` writes name the CLI that wrote them
	// (SKILL.md's metadata, each reference's first line): the recording's
	// TypeScript version becomes this build's. TestTranscripts does the
	// same to the case's inputs, so files installed "by this CLI" are.
	"skill-version": func(o *transcript.Outcome, _ transcript.Outcome) {
		files := map[string]transcript.FileState{}
		for path, f := range o.Files {
			f.Content = withSkillVersion(path, f.Content)
			files[path] = f
		}
		o.Files = files
	},
	// init writes each value of varlatch.toml as an escaped TOML basic
	// string, so the file reads back as what was given; the TypeScript CLI
	// writes the value verbatim between quotes. The recording's lines
	// become the escaped form of the same values.
	"toml-escaped": func(o *transcript.Outcome, _ transcript.Outcome) {
		files := map[string]transcript.FileState{}
		for path, f := range o.Files {
			if strings.HasSuffix(path, "varlatch.toml") {
				lines := strings.Split(f.Content, "\n")
				for i, line := range lines {
					if m := verbatimTOMLLine.FindStringSubmatch(line); m != nil {
						lines[i] = m[1] + " = " + cli.TOMLString(m[2])
					}
				}
				f.Content = strings.Join(lines, "\n")
			}
			files[path] = f
		}
		o.Files = files
	},
	// An unknown option given with its value attached (`--name=value`,
	// `-Xvalue`): the TypeScript CLI echoes the value, the Go CLI shows it
	// as [redacted] (go/README.md, "Diagnostics never print credential
	// values"). The rest of stderr, the status and stdout are compared as
	// recorded.
	"option-value": func(o *transcript.Outcome, _ transcript.Outcome) {
		o.Stderr = cli.OptionValueDifference(o.Stderr)
	},
	// A --json document's fields the API defines as scalars: an object or
	// array a server sent there is left out by the Go CLI (go/README.md,
	// "--json documents hold only scalars where the API defines them"), so
	// the recording's document is compared with those values removed:
	// env list's name, tier and kind, and status --probe's identity and
	// organization fields.
	"json-scalars": func(o *transcript.Outcome, _ transcript.Outcome) {
		doc, err := jsjson.Parse([]byte(o.Stdout))
		top, isObject := doc.(jsjson.Object)
		if err != nil || !isObject {
			return
		}
		if list, ok := top.Value("environments").([]any); ok {
			out := make([]any, len(list))
			for i, e := range list {
				out[i] = withoutNonScalars(e, "name", "tier", "kind")
			}
			top = top.Set("environments", out)
		}
		if list, ok := top.Value("servers").([]any); ok {
			out := make([]any, len(list))
			for i, srv := range list {
				out[i] = srv
				s, ok := srv.(jsjson.Object)
				if !ok {
					continue
				}
				p, ok := s.Value("probe").(jsjson.Object)
				if !ok {
					continue
				}
				if _, has := p.Get("identity"); has {
					p = p.Set("identity", withoutNonScalars(p.Value("identity"), "id", "name", "kind"))
				}
				if _, has := p.Get("organization"); has {
					p = p.Set("organization", withoutNonScalars(p.Value("organization"), "id", "slug", "name"))
				}
				out[i] = s.Set("probe", p)
			}
			top = top.Set("servers", out)
		}
		o.Stdout = string(jsjson.StringifyIndent(top, 2)) + "\n"
	},
	// An error the TypeScript CLI lets escape (recorded as {{uncaught ...}}):
	// Node.js prints a stack and exits 1; the Go CLI exits 1 too, with one
	// line saying what went wrong. Only that stderr is accepted; the status
	// and everything else are compared as recorded.
	"uncaught": func(o *transcript.Outcome, got transcript.Outcome) {
		if strings.HasPrefix(o.Stderr, "{{uncaught") && o.Status == 1 && goFailure.MatchString(got.Stderr) {
			o.Stderr = got.Stderr
		}
	},
	// Every server URL the Go CLI shows goes through clientctx.DisplayServer
	// (go/README.md, "server-display"): its scheme, host and port, and its
	// path when allow-listed, with markers for what it leaves out, and
	// "[unrecognised server URL]" for a value it cannot read as a URL.
	// TypeScript shows the value with its user name and password masked.
	// Accepted only where Go's stdout and stderr are the recording with each
	// fixture server, where TypeScript shows it, shown through DisplayServer
	// instead (serverDisplayFixtures).
	"server-display": func(o *transcript.Outcome, got transcript.Outcome) {
		stdout, stderr := o.Stdout, o.Stderr
		for _, f := range serverDisplayFixtures {
			shown := make([]any, len(f.raw))
			for i, raw := range f.raw {
				shown[i] = clientctx.DisplayServer(raw)
			}
			goText := fmt.Sprintf(f.goText, shown...)
			stdout = strings.ReplaceAll(stdout, f.recorded, goText)
			stderr = strings.ReplaceAll(stderr, f.recorded, goText)
		}
		if stdout == got.Stdout && stderr == got.Stderr {
			o.Stdout, o.Stderr = got.Stdout, got.Stderr
		}
	},
}

// withoutNonScalars is v without the named members whose value is an
// object or an array, when v is an object; anything else as it is.
func withoutNonScalars(v any, keys ...string) any {
	o, ok := v.(jsjson.Object)
	if !ok {
		return v
	}
	out := jsjson.Object{}
	for _, m := range o {
		switch m.Value.(type) {
		case jsjson.Object, []any:
			if slices.Contains(keys, m.Key) {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// skillVersion is the version a skill file names.
var skillVersion = regexp.MustCompile(`(generator: varlatch |<!-- Generated by varlatch )[0-9A-Za-z.+-]+`)

// withSkillVersion is a skill file's content naming this build's version.
func withSkillVersion(path, content string) string {
	if !strings.Contains(path, "skills/varlatch/") {
		return content
	}
	return skillVersion.ReplaceAllString(content, "${1}"+buildinfo.Version)
}

// serverDisplayFixtures are the servers of the server-display cases: the
// text that shows them in the TypeScript recording, and the same text with
// each server (raw, as the case stores or gives it) shown through
// DisplayServer (goText, a format with one %[n]s per server).
var serverDisplayFixtures = []struct {
	recorded, goText string
	raw              []string
}{
	{`"server": "0",`, `"server": "%[1]s",`, []string{"0"}},
	{`"server": "1",`, `"server": "%[1]s",`, []string{"1"}},
	{`"server": "https://a.example/\ud800",`, `"server": "%[1]s",`, []string{"https://a.example/\uFFFD"}},
	{"https://a.example/\uFFFD  (", "%[1]s  (", []string{"https://a.example/\uFFFD"}},
	{`"url": "x"`, `"url": "%[1]s"`, []string{"x"}},
	{`"https://[redacted]@segment"`, `"%[1]s"`, []string{`https://example.com\path@segment`}},
	{"not a URL: b.example\n", "not a URL: %[1]s\n", []string{"b.example"}},
	{"\"a\",\n    \"b\"\n", "\"%[1]s\",\n    \"%[2]s\"\n", []string{"a", "b"}},
	{"Server        a,b\n", "Server        %[1]s,%[2]s\n", []string{"a", "b"}},
	{`"server": "not a url",`, `"server": "%[1]s",`, []string{"not a url"}},
	{`"detail": "Failed to parse URL from not a url/v1/meta"`, `"detail": "Failed to parse URL from %[1]s"`, []string{"not a url/v1/meta"}},
	{"for https://x.example/p q. Commit", "for %[1]s. Commit", []string{"https://x.example/p q"}},
}

// verbatimTOMLLine is a line init writes, `key = "<value as given>"`.
var verbatimTOMLLine = regexp.MustCompile(`^([a-z_]+) = "(.*)"$`)

// recordedUserAgent is the TypeScript CLI's User-Agent in a recording.
var recordedUserAgent = regexp.MustCompile(`^varlatch-cli/[0-9A-Za-z.+-]+ \([a-z0-9]+; [a-z0-9]+(; assisted)?\)$`)

// goFailure is one line of the Go CLI's own failure.
var goFailure = regexp.MustCompile(`^varlatch: [^\n]+\n$`)

// transcriptParallelism bounds how many cases replay at once: each case
// runs the CLI as a process (this test binary, race-instrumented under
// -race), so the bound keeps memory sane on a hosted runner while the cases
// no longer run one after another.
const transcriptParallelism = 4

// TestTranscripts replays every recorded case (testdata/transcripts). The
// cases run in parallel, at most transcriptParallelism at once: each has
// its own directory, fake server and environment (transcript.Replay gives
// the child its environment explicitly), and nothing here is shared but
// read-only tables, so no case can see another.
func TestTranscripts(t *testing.T) {
	files, err := filepath.Glob("testdata/transcripts/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no transcripts: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(args []string) *exec.Cmd { return exec.Command(exe, args...) }
	slots := make(chan struct{}, transcriptParallelism)
	for _, path := range files {
		f, err := transcript.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			t.Run(f.Area+"/"+c.ID, func(t *testing.T) {
				// Skipped before it joins the parallel cases or takes a
				// slot: on Windows, a case whose outcome names a path below
				// its directory is not compared until step 5.9.
				if runtime.GOOS == "windows" && expectsPath(t, c) {
					t.Skip(windowsPathSkip)
				}
				t.Parallel()
				slots <- struct{}{}
				defer func() { <-slots }()
				c.Env = withMarker(c.Env)
				if slices.Contains(c.Differences, "skill-version") {
					files := map[string]string{}
					for path, content := range c.Files {
						files[path] = withSkillVersion(path, content)
					}
					c.Files = files
				}
				_, problems, err := transcript.Replay(c, start, differences)
				if err != nil {
					t.Fatal(err)
				}
				if len(problems) > 0 {
					t.Errorf("%s (%s):\n%s", c.ID, c.Title, strings.Join(problems, "\n"))
				}
			})
		}
	}
}

// windowsPathSkip is why a case that expects a path is skipped on Windows
// (internal docs/design/go-cli.md, step 5.9).
const windowsPathSkip = "path separators: Windows expectations not recorded yet (step 5.9)"

// expectsPath reports whether a case's recorded outcome names a path below
// its directory: the directory's placeholder followed by a separator
// (pathBelowDir). TypeScript recorded it on Linux; on Windows both CLIs
// join such a path with backslashes, so until Windows outcomes are recorded
// (step 5.9) such a case is not compared there. Every other case, the
// directory itself named alone included, still replays byte for byte.
func expectsPath(t *testing.T, c transcript.Case) bool {
	t.Helper()
	b, err := json.Marshal(c.Expect)
	if err != nil {
		t.Fatal(err)
	}
	return pathBelowDir.Match(b)
}

// pathBelowDir matches a path below a placeholder directory. {{dir}} is the
// only one the recorder writes today; {{home}} is matched too, so a
// recorder that adds it is covered.
var pathBelowDir = regexp.MustCompile(`\{\{(dir|home)\}\}[/\\]`)

func withMarker(env map[string]string) map[string]string {
	out := map[string]string{asCLI: "1"}
	for k, v := range env {
		out[k] = v
	}
	return out
}

// TestServerDisplayDifferenceIsExact: server-display accepts Go's output
// only where it is the recording with the fixture server shown through
// DisplayServer; the raw value, the TypeScript form, another server or any
// other change fails.
func TestServerDisplayDifferenceIsExact(t *testing.T) {
	recorded := `{"server": "https://[redacted]@segment"}` + "\n"
	for got, accepted := range map[string]bool{
		`{"server": "[unrecognised server URL]"}` + "\n":         true,
		`{"server": "https://example.com\\path@segment"}` + "\n": false,
		`{"server": "https://example.com/[redacted]"}` + "\n":    false,
		`{"server": "[unrecognised server URL]", "x": 1}` + "\n": false,
	} {
		want := transcript.Outcome{Stdout: recorded}
		differences["server-display"](&want, transcript.Outcome{Stdout: got})
		if (want.Stdout == got) != accepted {
			t.Errorf("%q: accepted %v, want %v", got, want.Stdout == got, accepted)
		}
	}
	// On stderr too, and both streams must match.
	want := transcript.Outcome{Stderr: "varlatch server use: not a URL: b.example\n"}
	differences["server-display"](&want, transcript.Outcome{Stderr: "varlatch server use: not a URL: b.example\n", Stdout: "x"})
	if want.Stdout == "x" {
		t.Error("accepted a stdout the recording does not have")
	}
}

// TestWindowsPathSkipIsNarrow: on Windows only a recorded outcome that names
// a path below the case's directory is skipped; the directory alone, or any
// other placeholder, is still compared.
func TestWindowsPathSkipIsNarrow(t *testing.T) {
	for text, skipped := range map[string]bool{
		`"repoRoot": "{{dir}}/repo"`:  true,
		`"root": "{{dir}}\\project"`:  true,
		`"home": "{{home}}/.config"`:  true,
		`outside {{dir}}, so nothing`: false,
		`"root": "{{dir}}"`:           false,
		`{{server}}/v1/whoami`:        false,
		`{{skill}}/SKILL.md`:          false,
	} {
		if got := pathBelowDir.MatchString(text); got != skipped {
			t.Errorf("%s: skipped %v, want %v", text, got, skipped)
		}
	}
}
