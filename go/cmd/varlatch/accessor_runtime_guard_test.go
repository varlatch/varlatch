// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoAccessorRuntimeCopyYet holds a gap open in plain sight. The Go CLI
// will embed the exact Typed Accessor runtimes the TypeScript CLI embeds,
// copied by a generator, and go.yml must fail when a copy is stale
// (internal docs/design/go-cli.md, decision 7). Slice 5.3c checks the copies
// in together with that staleness check (and the accessor sources in go.yml's
// path filter). Until then no copy may appear under go/cmd/varlatch outside
// test data: this test fails on one, so a copy cannot land without its
// check. 5.3c removes this test in the same pull request.
func TestNoAccessorRuntimeCopyYet(t *testing.T) {
	// Built from parts, so this file does not match itself.
	markers := []string{
		"function " + "varlatchAccessorRuntime",   // the TypeScript runtime's declaration
		"class " + "VarlatchWarning(UserWarning)", // the Python runtime's warning class
	}
	if _, err := os.Stat(filepath.Join("internal", "typegen", "embedded")); err == nil {
		t.Errorf("internal/typegen/embedded exists, but go.yml has no accessor-runtime staleness check yet: add it (slice 5.3c), then remove this test")
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range markers {
			if strings.Contains(string(data), m) {
				t.Errorf("%s holds an accessor runtime (%q), but go.yml has no accessor-runtime staleness check yet: add it (slice 5.3c), then remove this test", path, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
