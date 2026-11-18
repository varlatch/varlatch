// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/cli"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/secretinput"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/transcript"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// The test binary is also the CLI under test: run with this variable set,
// it is `varlatch` (main's run), so the transcripts run the CLI as a
// process without a second build.
const asCLI = "VARLATCH_TEST_AS_CLI"

// promptPause names the hidden prompt's stage at which the CLI under test
// pauses (secretinput.Hook).
const promptPause = "VARLATCH_TEST_PROMPT_PAUSE"

func TestMain(m *testing.M) {
	if os.Getenv(asCLI) == "1" {
		// The pseudo-terminal tests stop the hidden prompt at a stage before
		// its question, to send a signal in that window.
		if stage := os.Getenv(promptPause); stage != "" {
			secretinput.Hook = func(at string) {
				if at == stage {
					fmt.Fprintf(os.Stderr, "PAUSED %s\n", at)
					time.Sleep(5 * time.Second)
				}
			}
		}
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
	// `values set` and `values rotate` never repeat an argument they
	// refuse, whatever its spelling: it may be the value or part of it
	// (go/README.md, "No message holds a value"). The message names its
	// place among the command's arguments instead. Accepted only where Go's
	// first line of stderr is the refusal's own words for the same command
	// and holds no part of the refused argument, and every other line,
	// the status and stdout are as recorded.
	"value-free-usage": func(o *transcript.Outcome, got transcript.Outcome) {
		wantFirst, wantRest, _ := strings.Cut(o.Stderr, "\n")
		gotFirst, gotRest, _ := strings.Cut(got.Stderr, "\n")
		if wantRest != gotRest {
			return
		}
		for _, form := range valueFreeForms {
			m := form.ts.FindStringSubmatch(wantFirst)
			if m == nil {
				continue
			}
			argument := ""
			for _, part := range m[2:] {
				if part != "" {
					argument = part
				}
			}
			g := form.goWords.FindStringSubmatch(gotFirst)
			if g != nil && g[1] == m[1] && argument != "" && !strings.Contains(got.Stderr, argument) {
				o.Stderr = got.Stderr
			}
			return
		}
	},
	// A server's identifier that does not have the server's shape (a
	// prefix and 26 characters of lower-case base32) is shown as "an
	// unrecognized id" (go/README.md, "No message holds a value").
	"unrecognized-id": func(o *transcript.Outcome, got transcript.Outcome) {
		if m := recordedVersion.FindStringSubmatchIndex(o.Stdout); m != nil {
			if accepted := o.Stdout[:m[2]] + cli.UnrecognizedID + o.Stdout[m[3]:]; accepted == got.Stdout {
				o.Stdout = accepted
			}
		}
	},
}

// recordedVersion is the version a recorded `values set` names.
var recordedVersion = regexp.MustCompile(` set \(version (.*)\)\.\n$`)

// valueFreeForms are the refusals `values set` and `values rotate` word
// without the argument: the TypeScript words (the command, the argument)
// and the Go words (the command).
var valueFreeForms = []struct{ ts, goWords *regexp.Regexp }{
	{
		regexp.MustCompile(`^varlatch (values set|values rotate): (?:unknown option (\S+)(?: \(a value that begins with "-" goes after --\))?|(\S+): unknown option.*)$`),
		regexp.MustCompile(`^varlatch (values set|values rotate): unknown option at argument [0-9]+, not shown since it may be a value \(a value that begins with "-" goes after --\)$`),
	},
	{
		regexp.MustCompile(`^varlatch (values set|values rotate): (?:unexpected argument (\S+)|(\S+): unexpected argument)$`),
		regexp.MustCompile(`^varlatch (values set|values rotate): unexpected argument [0-9]+, not shown since it may be part of a value \(a value with spaces goes in quotes\)$`),
	},
	{
		regexp.MustCompile(`^varlatch (values rotate): --grace needs a whole number of seconds, not (.+)$`),
		regexp.MustCompile(`^varlatch (values rotate): --grace needs a whole number of seconds$`),
	},
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

// TestValueFreeUsageIsExact: value-free-usage accepts only Go's own words
// for the same refusal, never a message that holds the argument.
func TestValueFreeUsageIsExact(t *testing.T) {
	const usage = "\nUsage: varlatch values set <ITEM>\n"
	recorded := `varlatch values set: unknown option -s3cr3t (a value that begins with "-" goes after --)` + usage
	for got, accepted := range map[string]bool{
		`varlatch values set: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + usage:    true,
		`varlatch values rotate: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + usage: false,
		`varlatch values set: unknown option at argument 2, not shown since it may be a value -s3cr3t` + usage:                                         false,
		`varlatch values set: unknown option at argument 2, not shown since it may be a value (a value that begins with "-" goes after --)` + "\n":     false,
	} {
		want := transcript.Outcome{Stderr: recorded}
		differences["value-free-usage"](&want, transcript.Outcome{Stderr: got})
		if (want.Stderr == got) != accepted {
			t.Errorf("%q: accepted %v, want %v", got, want.Stderr == got, accepted)
		}
	}
}
