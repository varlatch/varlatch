// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryWriteGoesThroughTheFailSafe walks every Go file of the CLI
// (go/cmd/varlatch, tests, generators and the transcript replayer, which
// only tests use, excepted) and fails on any write to stdout or stderr, any
// use of the standard log package, and any JSON document serialised for
// stdout, that does not go through the fail-safe: cli.RedactDiagnostic on
// stderr, cli.RedactOutput on stdout, and printJSON (cli.RedactValue) for
// --json documents. Only the allow-listed sites below may write.
func TestEveryWriteGoesThroughTheFailSafe(t *testing.T) {
	writes := regexp.MustCompile(`\b(Fprint\w*|WriteString|Write)\(\s*(r\.)?(Stdout|Stderr|stdout|stderr|os\.Stdout|os\.Stderr)\b|\b(r\.)?(Stdout|Stderr)\.Write|\blog\.(Print|Fatal|Panic)|"log"`)
	serialises := regexp.MustCompile(`jsjson\.StringifyIndent\(`)
	// file: what an allowed line must hold.
	allowed := map[string][]string{
		"internal/cli/cli.go": {"RedactDiagnostic(", "RedactOutput("},
		"verify_release.go":   {"cli.RedactDiagnostic(", "cli.RedactOutput("},
	}
	// The files that serialise JSON on purpose, none of it for stdout: the
	// stores (files on disk), the agent files, and printJSON itself.
	serialisers := map[string]bool{
		"internal/clientctx/store.go":   true,
		"internal/clientctx/context.go": true,
		"internal/agents/files.go":      true,
		"internal/cli/contextcmds.go":   true, // printJSON, through RedactValue
	}
	sites := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == "internal/transcript" || path == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		if strings.Contains(text, "//go:build ignore") {
			return nil // a generator, never part of the CLI
		}
		path = filepath.ToSlash(path)
		for i, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if writes.MatchString(line) {
				ok := false
				for _, need := range allowed[path] {
					ok = ok || strings.Contains(line, need)
				}
				// main.go hands the process's streams to the CLI.
				ok = ok || path == "main.go" && strings.Contains(line, "os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))")
				if !ok {
					t.Errorf("%s:%d writes without the fail-safe: %s", path, i+1, strings.TrimSpace(line))
				}
				sites++
			}
			if serialises.MatchString(line) && !serialisers[path] {
				t.Errorf("%s:%d serialises JSON outside printJSON: %s", path, i+1, strings.TrimSpace(line))
			}
			if path == "internal/cli/contextcmds.go" && serialises.MatchString(line) && !strings.Contains(line, "RedactValue(") {
				t.Errorf("%s:%d printJSON serialises without RedactValue: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sites == 0 {
		t.Fatal("found no write at all: the scan is broken")
	}
}
