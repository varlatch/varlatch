// SPDX-License-Identifier: Apache-2.0

// Package preread keeps files open across a process's change of user: a
// host command run as root opens what only root reads (key files, an
// archive, a credential) with Keep, becomes the user whose directory it
// works in, and the code that reads those files by their paths goes on
// doing so with ReadFile and Open, which answer from what is kept. A path
// not kept is opened as os does.
package preread

import (
	"io"
	"os"
	"sync"
)

type entry struct {
	f   *os.File
	err error
	// read is the content of a file that cannot be read twice (a pipe).
	read []byte
	once bool
}

var (
	mu   sync.Mutex
	kept = map[string]*entry{}
)

// Keep opens path with open (os.Open when nil) and keeps it, or the error
// that gave. A path already kept stays as it is; "" is none.
func Keep(path string, open func(string) (*os.File, error)) {
	if path == "" {
		return
	}
	if open == nil {
		open = os.Open
	}
	mu.Lock()
	there := kept[path] != nil
	mu.Unlock()
	if there {
		return
	}
	// Opened with the lock free: open may ask for a kept file itself.
	f, err := open(path)
	mu.Lock()
	defer mu.Unlock()
	if kept[path] != nil {
		if f != nil {
			f.Close()
		}
		return
	}
	kept[path] = &entry{f: f, err: err}
}

// Open is os.Open, or a kept file from its start; what Keep's open refused
// is refused as it was. The caller closes it; it stays kept.
func Open(path string) (*os.File, error) {
	if f, err, ok := Kept(path); ok {
		return f, err
	}
	return os.Open(path)
}

// Kept is a kept file, from its start, or the error Keep met; ok is false
// for a path not kept.
func Kept(path string) (f *os.File, err error, ok bool) {
	mu.Lock()
	defer mu.Unlock()
	e := kept[path]
	if e == nil {
		return nil, nil, false
	}
	if e.err != nil {
		return nil, e.err, true
	}
	f, err = dup(e.f)
	if err != nil {
		return nil, err, true
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err, true
	}
	return f, nil, true
}

// ReadFile is os.ReadFile, or a kept file's content, read afresh; a pipe's
// is read once and kept.
func ReadFile(path string) ([]byte, error) {
	mu.Lock()
	e := kept[path]
	if e == nil {
		mu.Unlock()
		return os.ReadFile(path)
	}
	defer mu.Unlock()
	if e.err != nil {
		return nil, e.err
	}
	if e.once {
		return append([]byte(nil), e.read...), nil
	}
	if _, err := e.f.Seek(0, io.SeekStart); err != nil {
		b, err := io.ReadAll(e.f)
		if err != nil {
			return nil, err
		}
		e.read, e.once = b, true
		return append([]byte(nil), b...), nil
	}
	return io.ReadAll(e.f)
}

// Forget closes every kept file (the tests').
func Forget() {
	mu.Lock()
	defer mu.Unlock()
	for _, e := range kept {
		if e.f != nil {
			e.f.Close()
		}
		clear(e.read)
	}
	kept = map[string]*entry{}
}
