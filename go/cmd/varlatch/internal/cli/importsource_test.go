// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// import --delete-source removes only the regular file it read, named
// directly: never through a symbolic link, never a directory, never a file
// put in its place while importing, and says it deleted the file only when
// the path that held the values is gone.
func TestDeleteSourceRemovesOnlyTheFileRead(t *testing.T) {
	const content = "API_KEY=s3cr3t-delete-me\n"
	type check func(t *testing.T, repo string, code int, stdout, stderr string)
	gone := func(t *testing.T, repo string) {
		if _, err := os.Lstat(filepath.Join(repo, ".env")); !os.IsNotExist(err) {
			t.Errorf(".env is still there: %v", err)
		}
	}
	deleted := func(t *testing.T, stdout string) bool {
		var doc struct{ Deleted bool }
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("not one document: %q", stdout)
		}
		return doc.Deleted
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, repo string, s *valuesServer)
		check check
	}{
		{"a regular file is deleted", func(t *testing.T, repo string, s *valuesServer) {
			write(t, filepath.Join(repo, ".env"), content)
		}, func(t *testing.T, repo string, code int, stdout, _ string) {
			if code != 0 || !deleted(t, stdout) {
				t.Errorf("status %d, %q", code, stdout)
			}
			gone(t, repo)
		}},
		{"a symbolic link is refused, before anything is sent", func(t *testing.T, repo string, s *valuesServer) {
			write(t, filepath.Join(repo, "real.env"), content)
			if err := os.Symlink("real.env", filepath.Join(repo, ".env")); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, repo string, code int, stdout, stderr string) {
			if code != 1 || !strings.Contains(stderr, "is a symbolic link") || stdout != "" {
				t.Errorf("status %d, %q %q", code, stdout, stderr)
			}
			for _, f := range []string{".env", "real.env"} {
				if _, err := os.Lstat(filepath.Join(repo, f)); err != nil {
					t.Errorf("%s: %v", f, err)
				}
			}
		}},
		{"a directory is refused", func(t *testing.T, repo string, s *valuesServer) {
			if err := os.Mkdir(filepath.Join(repo, ".env"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, repo string, code int, _, stderr string) {
			if code != 1 || !strings.Contains(stderr, "is not a regular file") {
				t.Errorf("status %d, %q", code, stderr)
			}
			if info, err := os.Lstat(filepath.Join(repo, ".env")); err != nil || !info.IsDir() {
				t.Errorf("the directory is gone: %v", err)
			}
		}},
		{"a pipe is refused", func(t *testing.T, repo string, s *valuesServer) {
			if err := syscall.Mkfifo(filepath.Join(repo, ".env"), 0o600); err != nil {
				t.Skip(err)
			}
		}, func(t *testing.T, repo string, code int, _, stderr string) {
			if code != 1 || !strings.Contains(stderr, "is not a regular file") {
				t.Errorf("status %d, %q", code, stderr)
			}
		}},
		{"a file put in its place while importing is kept", func(t *testing.T, repo string, s *valuesServer) {
			write(t, filepath.Join(repo, ".env"), content)
			write(t, filepath.Join(repo, "other"), content) // the same bytes, another file
			s.onPut = func() { _ = os.Rename(filepath.Join(repo, "other"), filepath.Join(repo, ".env")) }
		}, func(t *testing.T, repo string, code int, stdout, stderr string) {
			if code != 1 || deleted(t, stdout) || !strings.Contains(stderr, "it was not deleted") {
				t.Errorf("status %d, %q %q", code, stdout, stderr)
			}
			if b, err := os.ReadFile(filepath.Join(repo, ".env")); err != nil || string(b) != content {
				t.Errorf("the replacement was removed: %v", err)
			}
		}},
		{"a file changed while importing is kept", func(t *testing.T, repo string, s *valuesServer) {
			write(t, filepath.Join(repo, ".env"), content)
			s.onPut = func() { write(t, filepath.Join(repo, ".env"), content+"MORE=1\n") }
		}, func(t *testing.T, repo string, code int, stdout, _ string) {
			if code != 1 || deleted(t, stdout) {
				t.Errorf("status %d, %q", code, stdout)
			}
			if _, err := os.Lstat(filepath.Join(repo, ".env")); err != nil {
				t.Errorf("the changed file was removed: %v", err)
			}
		}},
		{"a file removed while importing: not reported deleted", func(t *testing.T, repo string, s *valuesServer) {
			write(t, filepath.Join(repo, ".env"), content)
			s.onPut = func() { _ = os.Remove(filepath.Join(repo, ".env")) }
		}, func(t *testing.T, repo string, code int, stdout, _ string) {
			if code != 1 || deleted(t, stdout) {
				t.Errorf("status %d, %q", code, stdout)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newValuesServer(t)
			s.answer("GET", "/v1/organizations/acme/projects/web/contract", 404, `{"error": {"code": "NOT_FOUND", "message": "none"}}`)
			var repo string
			setup := c.setup
			code, stdout, stderr := runInWith(t, s, nil, func(dir string) { repo = dir; setup(t, dir, s) }, "import", ".env", "--delete-source", "--json")
			c.check(t, repo, code, stdout, stderr)
		})
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
