// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
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
	// An error the TypeScript CLI lets escape (recorded as {{uncaught ...}}):
	// Node.js prints a stack and exits 1; the Go CLI exits 1 too, with one
	// line saying what went wrong. Only that stderr is accepted; the status
	// and everything else are compared as recorded.
	"uncaught": func(o *transcript.Outcome, got transcript.Outcome) {
		if strings.HasPrefix(o.Stderr, "{{uncaught") && o.Status == 1 && goFailure.MatchString(got.Stderr) {
			o.Stderr = got.Stderr
		}
	},
	// TypeScript (0.22.2 on) masks a special scheme's URL from its authority
	// to the last at-sign before "/", "?" or "#", reading through a
	// backslash, so the fixture https://example.com\path@segment, which has
	// no user name or password (the backslash starts the path), is shown as
	// https://[redacted]@segment. Go reads the authority WHATWG parses and
	// shows that URL as it is (go/README.md, "Diagnostics never print
	// credential values"). Accepted only where Go's stdout, with the fixture
	// URL (as JSON writes it) shown as TypeScript shows it, is the recording.
	"backslash-path": func(o *transcript.Outcome, got transcript.Outcome) {
		if strings.ReplaceAll(got.Stdout, backslashPathFixture, "https://[redacted]@segment") == o.Stdout {
			o.Stdout = got.Stdout
		}
	},
	// Not a difference: a value `--generate` makes is random in both CLIs,
	// so the recording holds its generator, `{{generated <spec>}}`
	// (goKit.ts). Each such request takes the value Go sent, which must have
	// exactly the alphabet and length the spec gives and must not appear on
	// stdout or stderr; every other field is compared as recorded.
	"generated-value": func(o *transcript.Outcome, got transcript.Outcome) {
		for i := range o.Requests {
			if i >= len(got.Requests) {
				break
			}
			body, want, ok := generatedBody(o.Requests[i].Body)
			_, have, haveOK := generatedBody(got.Requests[i].Body)
			m := generatedPlaceholder.FindStringSubmatch(want)
			if !ok || !haveOK || m == nil || !generatedBy(m[1], have) || strings.Contains(got.Stdout, have) || strings.Contains(got.Stderr, have) {
				continue
			}
			body["value"] = have
			o.Requests[i].Body, _ = json.Marshal(body)
		}
	},
	// The Go CLI does not echo an argument `values set` or `values rotate`
	// refuses, unless it looks like an option: it may be a value, or part
	// of one (go/README.md, "No message holds a value"). Accepted only where
	// Go's stderr is the recording with the refusal's words in place of the
	// echo, and holds no part of the refused argument.
	"value-free-usage": func(o *transcript.Outcome, got transcript.Outcome) {
		m := echoedRefusal.FindStringSubmatchIndex(o.Stderr)
		if m == nil {
			return
		}
		argument := o.Stderr[m[4]:m[5]]
		var words string
		if o.Stderr[m[2]:m[3]] == "unknown option " {
			words = `an unknown option, not shown since it may be a value (a value that begins with "-" goes after --)`
		} else {
			words = "one argument too many, not shown since it may be part of a value (a value with spaces goes in quotes)"
		}
		accepted := o.Stderr[:m[2]] + words + o.Stderr[m[1]:]
		if got.Stderr == accepted && !strings.Contains(got.Stderr, argument) {
			o.Stderr = accepted
		}
	},
}

// echoedRefusal is the TypeScript parser's refusal of an argument, as
// `values set` and `values rotate` print it: the words, the argument, and
// for an unknown option the hint.
var echoedRefusal = regexp.MustCompile(`(unknown option |unexpected argument )(\S+)(?: \(a value that begins with "-" goes after --\))?`)

// generatedBody is a request body holding a string "value".
func generatedBody(raw json.RawMessage) (map[string]any, string, bool) {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil, "", false
	}
	value, ok := body["value"].(string)
	return body, value, ok
}

// generatedPlaceholder is a generated value as a recording holds it.
var generatedPlaceholder = regexp.MustCompile(`^\{\{generated ((?:hex|base64|base64url|alnum):[0-9]+)\}\}$`)

// generatedBy is whether value has the shape the generator spec gives:
// hex of 2n digits, base64 with padding, base64url without, alnum of n
// characters.
func generatedBy(spec, value string) bool {
	encoding, size, _ := strings.Cut(spec, ":")
	n, err := strconv.Atoi(size)
	if err != nil {
		return false
	}
	var pattern string
	switch encoding {
	case "hex":
		pattern = fmt.Sprintf(`^[0-9a-f]{%d}$`, 2*n)
	case "base64":
		pattern = fmt.Sprintf(`^[A-Za-z0-9+/]{%d}={%d}$`, (4*n+2)/3, (3-n%3)%3)
	case "base64url":
		pattern = fmt.Sprintf(`^[A-Za-z0-9_-]{%d}$`, (4*n+2)/3)
	case "alnum":
		pattern = fmt.Sprintf(`^[A-Za-z0-9]{%d}$`, n)
	default:
		return false
	}
	return regexp.MustCompile(pattern).MatchString(value)
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

// backslashPathFixture is the backslash-path cases' server, as a JSON
// string holds it.
const backslashPathFixture = `https://example.com\\path@segment`

// verbatimTOMLLine is a line init writes, `key = "<value as given>"`.
var verbatimTOMLLine = regexp.MustCompile(`^([a-z_]+) = "(.*)"$`)

// recordedUserAgent is the TypeScript CLI's User-Agent in a recording.
var recordedUserAgent = regexp.MustCompile(`^varlatch-cli/[0-9A-Za-z.+-]+ \([a-z0-9]+; [a-z0-9]+(; assisted)?\)$`)

// goFailure is one line of the Go CLI's own failure.
var goFailure = regexp.MustCompile(`^varlatch: [^\n]+\n$`)

// TestTranscripts replays every recorded case (testdata/transcripts).
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
	for _, path := range files {
		f, err := transcript.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			t.Run(f.Area+"/"+c.ID, func(t *testing.T) {
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

func withMarker(env map[string]string) map[string]string {
	out := map[string]string{asCLI: "1"}
	for k, v := range env {
		out[k] = v
	}
	return out
}

// TestBackslashPathDifferenceIsExact: backslash-path accepts Go's stdout
// only where it differs from the recording by the fixture URL alone; any
// other host, path or output fails (Sol, #265 round 5).
func TestBackslashPathDifferenceIsExact(t *testing.T) {
	recorded := `{"server": "https://[redacted]@segment"}` + "\n"
	for got, accepted := range map[string]bool{
		`{"server": "https://example.com\\path@segment"}` + "\n":         true,
		`{"server": "https://other.example\\path@segment"}` + "\n":       false,
		`{"server": "https://example.com\\other@segment"}` + "\n":        false,
		`{"server": "https://other.example\\other@segment"}` + "\n":      false,
		`{"server": "https://example.com\\path@segment", "x": 1}` + "\n": false,
		`{"server": "https://example.com/path@segment"}` + "\n":          false,
	} {
		want := transcript.Outcome{Stdout: recorded}
		differences["backslash-path"](&want, transcript.Outcome{Stdout: got})
		if (want.Stdout == got) != accepted {
			t.Errorf("%q: accepted %v, want %v", got, want.Stdout == got, accepted)
		}
	}
}

// TestGeneratedValuePatternIsExact: generated-value accepts only a value of
// the alphabet and length its generator gives, never shown.
func TestGeneratedValuePatternIsExact(t *testing.T) {
	for spec, cases := range map[string]map[string]bool{
		"hex:32":       {strings.Repeat("a1", 32): true, strings.Repeat("a", 63): false, strings.Repeat("A", 64): false},
		"base64:32":    {strings.Repeat("A+/", 14) + "a=": true, strings.Repeat("A", 44): false},
		"base64:16":    {strings.Repeat("Ab", 11) + "==": true, strings.Repeat("A", 23) + "=": false},
		"base64url:24": {strings.Repeat("a-_B", 8): true, strings.Repeat("a+", 16): false},
		"alnum:30":     {strings.Repeat("aZ9", 10): true, strings.Repeat("a", 29): false, strings.Repeat("a-", 15): false},
	} {
		for value, accepted := range cases {
			if generatedBy(spec, value) != accepted {
				t.Errorf("%s %q: accepted %v, want %v", spec, value, !accepted, accepted)
			}
			body, _ := json.Marshal(map[string]string{"value": "{{generated " + spec + "}}"})
			sent, _ := json.Marshal(map[string]string{"value": value})
			want := transcript.Outcome{Requests: []transcript.Request{{Body: body}}}
			differences["generated-value"](&want, transcript.Outcome{Requests: []transcript.Request{{Body: sent}}, Stdout: "set (version 1)\n"})
			if (string(want.Requests[0].Body) == string(sent)) != accepted {
				t.Errorf("%s %q: replay accepted %v", spec, value, !accepted)
			}
		}
	}
	// A value shown on stdout is never accepted.
	value := strings.Repeat("ab", 32)
	body, _ := json.Marshal(map[string]string{"value": "{{generated hex:32}}"})
	sent, _ := json.Marshal(map[string]string{"value": value})
	want := transcript.Outcome{Requests: []transcript.Request{{Body: body}}}
	differences["generated-value"](&want, transcript.Outcome{Requests: []transcript.Request{{Body: sent}}, Stdout: value + "\n"})
	if string(want.Requests[0].Body) == string(sent) {
		t.Error("a value shown on stdout was accepted")
	}
}
