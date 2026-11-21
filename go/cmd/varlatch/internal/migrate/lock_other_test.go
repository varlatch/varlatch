// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package migrate

import (
	"context"
	"os"
	"testing"
)

// dirOnly is a source that knows only its directory: every entry point
// refuses before it asks anything else (its other methods would panic).
type dirOnly struct {
	Source
	dir string
}

func (d dirOnly) Dir() string { return d.dir }

// Off Linux, varlatch migrate refuses at every entry point, with the one
// message, before it reads or writes anything: the source's directory is
// left exactly as it was.
func TestOffLinuxMigrateRefuses(t *testing.T) {
	const want = "varlatch migrate runs on the Linux host of the installation it migrates"
	ctx := context.Background()
	dir := t.TempDir()
	e := &Engine{Source: dirOnly{dir: dir}}
	for name, run := range map[string]func() (*Journal, error){
		"run":      func() (*Journal, error) { return e.Run(ctx, false) },
		"dry run":  func() (*Journal, error) { return e.Run(ctx, true) },
		"resume":   func() (*Journal, error) { return e.Resume(ctx) },
		"abort":    func() (*Journal, error) { return e.Abort(ctx) },
		"finish":   func() (*Journal, error) { return e.Finish(ctx, true) },
		"rollback": func() (*Journal, error) { return e.Rollback(ctx) },
	} {
		j, err := run()
		if j != nil || err == nil || err.Error() != want {
			t.Errorf("%s: %+v %v, want %q", name, j, err, want)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the source's directory after the refusals: %v %v", entries, err)
	}
}
