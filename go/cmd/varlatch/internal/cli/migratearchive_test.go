// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// `varlatch migrate --from-archive` is its own mode: its usage, and the
// command lines it refuses before anything runs (the conversion's own
// refusals are internal/migrate's TestArchiveRefusesBeforeAnyProgram).
func TestMigrateFromArchiveCommand(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Main(args, MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut})
		return code, out.String(), errOut.String()
	}
	if code, out, _ := run("migrate", "--from-archive", "a.vltbak", "--help"); code != 0 || !strings.Contains(out, "--ts-image <name@sha256:digest>") {
		t.Fatalf("--help: %d %q", code, out)
	}
	if code, out, _ := run("migrate", "--help"); code != 0 || !strings.Contains(out, "varlatch migrate --from-archive <archive>") {
		t.Fatalf("migrate --help does not name the converter: %d %q", code, out)
	}
	keys := []string{"--kek-file", "/k", "--bek-file", "/b", "--out", "/o"}
	for _, c := range []struct {
		args []string
		why  string
	}{
		{[]string{"migrate", "--from-archive", "a.vltbak"}, "give --from-archive, --kek-file, --bek-file and --out"},
		{append([]string{"migrate", "--from-archive", "a.vltbak", "--config", "/c"}, keys...), "--config is the live migration's"},
		{append([]string{"migrate", "--from-archive", "a.vltbak", "--resume"}, keys...), "--resume is the live migration's"},
		{append([]string{"migrate", "--from-archive=a.vltbak", "--dry-run"}, keys...), "--dry-run is the live migration's"},
		{append([]string{"migrate", "--from-archive", "a.vltbak", "--out", "/p"}, keys...), "--out is given twice"},
		{append([]string{"migrate", "--from-archive", "a.vltbak", "--ts-imag", "x"}, keys...), "unknown option --ts-imag"},
		{[]string{"migrate", "--from-archive"}, "--from-archive needs a value"},
	} {
		if code, _, errOut := run(c.args...); code != ExitUsage || !strings.Contains(errOut, c.why) {
			t.Errorf("%q: %d %q, want %q", c.args, code, errOut, c.why)
		}
	}
}
