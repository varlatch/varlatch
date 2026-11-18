// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	// backslash, so https://example.com\path@segment, which has no user name
	// or password (the backslash starts the path), is shown as
	// https://[redacted]@segment. Go reads the authority WHATWG parses and
	// shows that URL as it is (go/README.md, "Diagnostics never print
	// credential values"). Accepted only where masking Go's stdout that way
	// gives the recording.
	"backslash-path": func(o *transcript.Outcome, got transcript.Outcome) {
		if backslashPath.ReplaceAllString(got.Stdout, "://[redacted]@") == o.Stdout {
			o.Stdout = got.Stdout
		}
	},
}

// backslashPath is, in JSON text, a URL's host, a backslash (escaped) and
// the path up to an at-sign: what TypeScript masks and Go shows.
var backslashPath = regexp.MustCompile(`://[^/\\"\s@?#]+\\\\[^/?#"\s@]*@`)

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
