// SPDX-License-Identifier: Apache-2.0

//go:build windows

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// hold opens path as a virus scanner does: others may read it, not rename
// it, until the handle is closed.
func hold(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func files(t *testing.T) (staged, target string) {
	t.Helper()
	dir := t.TempDir()
	staged, target = filepath.Join(dir, ".varlatch-self-update-1.exe"), filepath.Join(dir, "varlatch.exe")
	for path, content := range map[string]string{staged: "new", target: "old"} {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return staged, target
}

func content(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A file another process holds for a moment is waited for.
func TestReplaceWaitsForAHeldFile(t *testing.T) {
	for _, name := range []string{"the new file", "the old file"} {
		t.Run(name, func(t *testing.T) {
			staged, target := files(t)
			held := staged
			if name == "the old file" {
				held = target
			}
			h := hold(t, held)
			// The hold stops a rename, as what self-update tries again.
			if err := os.Rename(held, held+".moved"); err == nil || !isHeld(err) {
				_ = windows.CloseHandle(h)
				t.Fatalf("renaming a held file: %v", err)
			}
			released := make(chan struct{})
			go func() {
				defer close(released)
				time.Sleep(300 * time.Millisecond)
				_ = windows.CloseHandle(h)
			}()
			err := replace(context.Background(), staged, target)
			<-released
			if err != nil {
				t.Fatal(err)
			}
			if got := content(t, target); got != "new" {
				t.Fatalf("%q", got)
			}
			if _, err := os.Stat(staged); !os.IsNotExist(err) {
				t.Fatalf("the new file is still at its first name: %v", err)
			}
		})
	}
}

// Held for as long as it waits (none here): the failure, and the old file
// in its place.
func TestReplaceLeavesTheOldFile(t *testing.T) {
	staged, target := files(t)
	h := hold(t, staged)
	defer windows.CloseHandle(h)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := replace(ctx, staged, target)
	if err == nil || !isHeld(err) {
		t.Fatalf("%v", err)
	}
	if got := content(t, target); got != "old" {
		t.Fatalf("%q", got)
	}
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		if said := writeError(err, target, "0.50.0").Error(); !strings.HasSuffix(said, "; it was left as it was") {
			t.Fatalf("%s", said)
		}
	}
}
