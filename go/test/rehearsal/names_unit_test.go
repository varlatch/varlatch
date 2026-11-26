// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNamesOfTheCopy(t *testing.T) {
	defer func(of, left map[string]bool) { copyNames.of, copyNames.left = of, left }(copyNames.of, copyNames.left)
	copyNames.of, copyNames.left = nil, nil
	host := "hooks." + "quuxley" + ".example"
	addNames([]string{"Quuxley " + "Works", "https://" + host + "/x?y", "production", "Dev", "", "run 17", "zqx" + "j", "someone@" + host})
	var got []string
	for n := range copyNames.of {
		got = append(got, n)
	}
	slices.Sort(got)
	if want := []string{host, "quuxley " + "works", "someone@" + host, "zqx" + "j"}; !slices.Equal(got, want) {
		t.Errorf("names %q, want %q", got, want)
	}
	if !copyNames.left["production"] || !copyNames.left["run 17"] {
		t.Errorf("left %v", copyNames.left)
	}
	for _, c := range []struct {
		text, name string
		want       bool
	}{
		{"an organization abcd, read", "abcd", true}, {"abcde", "abcd", false}, {"xabcd abcd", "abcd", true}, {`{"name":"abcd"}`, "abcd", true},
		{"abcd", "abcd", true}, {"abcd.example", "abcd", true}, {"", "abcd", false}, {"_abcd", "abcd", false},
	} {
		if got := named(c.text, c.name); got != c.want {
			t.Errorf("named(%q, %q) = %v", c.text, c.name, got)
		}
	}
	if !strings.Contains(strings.Join(nameColumns, "\n"), "organizations") || !ownWords()["varlatch"] {
		t.Error("the harness's own words")
	}
}

func TestScanReportDir(t *testing.T) {
	root := t.TempDir()
	repDir := filepath.Join(root, "report")
	work := filepath.Join(root, "work")
	bin := filepath.Join(root, "bin")
	cache := filepath.Join(root, "cache", "mod")
	for _, d := range []string{repDir, work, bin, cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	nameA := "quuxley" + " works"
	nameB := "hooks." + "quuxley" + ".example"
	want := map[string]bool{nameA: true, nameB: true}

	// Sibling directories under $root hold the harness's own names file,
	// binaries and Go caches; none of them is part of reportDir.
	if err := os.WriteFile(filepath.Join(work, namesFile), []byte(nameA+"\n"+nameB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "rehearsal.test"), []byte("embedded "+nameA+" "+nameB), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "modfile"), []byte("cached "+nameA), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repDir, "test.log"), []byte("=== RUN TestRehearsal\nPASS\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Clean report JSON + clean reportDir: 2 texts (report JSON + test.log), 0 found.
	texts, found, err := scanReportDir(repDir, []byte(`{"checks":[{"name":"ok"}]}`), want)
	if err != nil || texts != 2 || found != 0 {
		t.Fatalf("clean reportDir: texts=%d found=%d err=%v, want 2, 0, nil", texts, found, err)
	}

	// Leak in report JSON is caught.
	texts, found, err = scanReportDir(repDir, []byte(`{"detail":"org `+nameA+`"}`), want)
	if err != nil || texts != 2 || found != 1 {
		t.Fatalf("leak in report JSON: texts=%d found=%d err=%v, want 2, 1, nil", texts, found, err)
	}

	// Leak in test.log inside reportDir is caught.
	if err := os.WriteFile(filepath.Join(repDir, "test.log"), []byte("webhook "+nameB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	texts, found, err = scanReportDir(repDir, []byte(`{"checks":[]}`), want)
	if err != nil || texts != 2 || found != 1 {
		t.Fatalf("leak in test.log: texts=%d found=%d err=%v, want 2, 1, nil", texts, found, err)
	}

	// Symlinked reportDir is followed so leaks in it are still caught.
	link := filepath.Join(root, "report-link")
	if err := os.Symlink(repDir, link); err != nil {
		t.Fatal(err)
	}
	texts, found, err = scanReportDir(link, []byte(`{"checks":[]}`), want)
	if err != nil || texts != 2 || found != 1 {
		t.Fatalf("symlinked reportDir: texts=%d found=%d err=%v, want 2, 1, nil", texts, found, err)
	}

	// Missing reportDir returns an error (fails closed).
	if _, _, err := scanReportDir(filepath.Join(root, "missing"), []byte(`{}`), want); err == nil {
		t.Error("missing reportDir returned nil error")
	}
}
