// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRedactOutputShowingKeepsOnlyTheShownToken: invite's writer lets
// exactly its one enrollment token through; any other token and every
// value in flight is redacted as RedactOutput redacts it.
func TestRedactOutputShowingKeepsOnlyTheShownToken(t *testing.T) {
	shown := "vlt_invite_canaryTOKEN"
	line := "  https://v.example/enroll#" + shown + " vlt_cli_otherTOKEN s3cr3t-value\n"
	got := RedactOutputShowing(line, shown, "s3cr3t-value")
	want := "  https://v.example/enroll#" + shown + " [redacted] [redacted]\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A longer token that starts with the shown one is another token.
	if got := RedactOutputShowing("vlt_invite_canaryTOKENmore", shown); got != "[redacted]" {
		t.Errorf("a longer token was kept: %q", got)
	}
	// Nothing shown: RedactOutput's bytes.
	if got, want := RedactOutputShowing(line, "", "s3cr3t-value"), RedactOutput(line, "s3cr3t-value"); got != want {
		t.Errorf("with nothing shown: %q, RedactOutput %q", got, want)
	}
	// A value in flight equal to the shown token is still redacted.
	if got := RedactOutputShowing("#"+shown, shown, shown); got != "#[redacted]" {
		t.Errorf("a value in flight was shown: %q", got)
	}
}

// TestCredentialIssueNeverFollowsALink: --out naming a symbolic link,
// dangling or not, is refused before anything is issued, and nothing is
// written through it.
func TestCredentialIssueNeverFollowsALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	for _, existing := range []bool{false, true} {
		if existing {
			if err := os.WriteFile(target, []byte("kept\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		link := filepath.Join(dir, "link")
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := checkOutPath(link)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("existing target %v: %v", existing, err)
		}
		// The exclusive create refuses it too, whatever checked before.
		f, err := os.OpenFile(link, os.O_WRONLY|os.O_CREATE|os.O_EXCL|createNoFollow, 0o600)
		if err == nil {
			_ = f.Close()
			t.Fatalf("existing target %v: created through the link", existing)
		}
		if existing {
			data, _ := os.ReadFile(target)
			if string(data) != "kept\n" {
				t.Fatalf("the link's target changed: %q", data)
			}
		} else if _, err := os.Lstat(target); err == nil {
			t.Fatal("a file was created at the dangling link's target")
		}
	}
}

// TestNodeDirname: path.dirname's POSIX answers, which credential issue's
// "the directory ... does not exist" names.
func TestNodeDirname(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	for in, want := range map[string]string{
		"token.txt":         ".",
		"missing/token.txt": "missing",
		"a/b/":              "a",
		"/token":            "/",
		"//x":               "//",
		"a//b":              "a/",
		"a/b//":             "a",
		"":                  ".",
	} {
		if got := nodeDirname(in); got != want {
			t.Errorf("nodeDirname(%q) = %q, want %q", in, got, want)
		}
	}
}
