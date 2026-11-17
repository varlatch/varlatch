// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
	os.Exit(m.Run())
}

// versionLine is the TypeScript CLI's --version: `varlatch <version>
// (migration <n>)`.
var versionLine = regexp.MustCompile(`^varlatch \S+ \(migration \d+\)\n$`)

// differences are the Go CLI's accepted differences (go/README.md), by the
// name a recorded case gives.
var differences = map[string]transcript.Difference{
	// Decision 6: `varlatch <version>`, without the migration number.
	"version": func(o *transcript.Outcome) {
		if versionLine.MatchString(o.Stdout) {
			o.Stdout = "varlatch " + buildinfo.Version + "\n"
		}
	},
}

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
