// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLookCommandAsLibuv: on Windows a command is found as libuv finds it
// without a shell (decision 4): a name without an extension as .com or
// .exe only, never through PATHEXT; a .bat or .cmd file is refused
// (Node's EINVAL, CVE-2024-27980).
func TestLookCommandAsLibuv(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tool.exe", "script.bat", "other.cmd", "plain"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := lookCommand("tool", dir); err != nil || got != filepath.Join(dir, "tool.exe") {
		t.Errorf("tool: %q, %v", got, err)
	}
	for _, name := range []string{"script.bat", "other.cmd"} {
		if _, err := lookCommand(name, dir); !errors.Is(err, errBatchFile) {
			t.Errorf("%s: %v, want the batch-file refusal", name, err)
		}
	}
	if _, err := lookCommand("script", dir); !errors.Is(err, errNotFound) {
		t.Errorf("script (only a .bat): %v, want not found", err)
	}
	if _, err := lookCommand("plain", dir); !errors.Is(err, errNotFound) {
		t.Errorf("plain (no .com or .exe): %v, want not found", err)
	}
	if err := spawnError("script.bat", errBatchFile); err.Error() != "spawn script.bat EINVAL" {
		t.Errorf("%v", err)
	}
}
