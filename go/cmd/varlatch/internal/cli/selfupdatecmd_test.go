// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

// --allow-unverified, which the TypeScript CLI's self-update reads, changes
// nothing in the Go CLI: one line on stderr says so, and the run is
// otherwise the same, its status included (here a development build's
// refusal, reached before any request).
func TestSelfUpdateAllowUnverifiedChangesNothing(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		return code, stdout.String(), stderr.String()
	}
	code, out, errs := run("self-update", "--yes")
	codeU, outU, errsU := run("self-update", "--yes", "--allow-unverified")
	const notice = "varlatch self-update: --allow-unverified changes nothing: every release is verified\n"
	if codeU != code || outU != out || errsU != notice+errs {
		t.Fatalf("without: %d %q %q\nwith:    %d %q %q", code, out, errs, codeU, outU, errsU)
	}
	if code != ExitFailure || !strings.Contains(errs, "development build") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}
