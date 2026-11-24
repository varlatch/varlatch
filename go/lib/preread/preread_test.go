// SPDX-License-Identifier: Apache-2.0

package preread

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestKept(t *testing.T) {
	dir := t.TempDir()
	// Before the directory goes: Windows removes no open file.
	t.Cleanup(Forget)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := Kept(path); ok {
		t.Fatal("kept before Keep")
	}
	if b, err := ReadFile(path); err != nil || string(b) != "first" {
		t.Fatalf("not kept: %q %v", b, err)
	}
	Keep(path, nil)
	Keep("", nil)
	if runtime.GOOS != "windows" {
		// Another file in its place, or none: the kept one is read, as often
		// as it is asked for.
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if b, err := ReadFile(path); err != nil || string(b) != "first" {
			t.Fatalf("kept: %q %v", b, err)
		}
		f, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil || string(b) != "first" {
			t.Fatalf("opened: %q %v", b, err)
		}
		f.Close()
	}
}

// What Keep's open refused is refused as it was, whatever is there since.
func TestKeptRefusal(t *testing.T) {
	t.Cleanup(Forget)
	path := filepath.Join(t.TempDir(), "secret")
	refused := errors.New("is open to others")
	Keep(path, func(string) (*os.File, error) { return nil, refused })
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	Keep(path, nil)
	if _, err := ReadFile(path); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if _, err, ok := Kept(path); !ok || !errors.Is(err, refused) {
		t.Fatal(err, ok)
	}
}

// A pipe's content is read once and kept.
func TestKeptPipe(t *testing.T) {
	t.Cleanup(Forget)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("piped"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	Keep("the pipe", func(string) (*os.File, error) { return r, nil })
	for range 2 {
		if b, err := ReadFile("the pipe"); err != nil || string(b) != "piped" {
			t.Fatalf("%q %v", b, err)
		}
	}
}
