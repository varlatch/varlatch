// SPDX-License-Identifier: Apache-2.0

//go:build linux

package diskprobe

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestUnnamedLeavesTheDirectoryAlone: with Unnamed, the probe writes and
// syncs files without a name: the directory has no entry before, during
// or after, and its modification time does not change. A filesystem that
// cannot make one gets ErrUnnamed, and nothing is written.
func TestUnnamedLeavesTheDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	res, err := Run(context.Background(), Options{Dir: dir, Duration: 3 * time.Second, Unnamed: true, OnSample: func(Kind, time.Time, time.Duration) {
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			seen++
		}
	}})
	if errors.Is(err, ErrUnnamed) {
		t.Skipf("this filesystem cannot make a file without a name: %v", err)
	}
	// Too few samples (a slow or busy disk) still wrote and synced the
	// files: what this test is about holds or not all the same.
	if err != nil && !errors.Is(err, ErrTooFewSamples) {
		t.Fatalf("%+v %v", res, err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if seen != 0 || len(entries) != 0 || !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the directory changed: %d samples saw an entry, %d entries after, mtime %v -> %v", seen, len(entries), before.ModTime(), after.ModTime())
	}
}
