// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseCheckRecord(t *testing.T) {
	dir := t.TempDir()
	if rc, err := ReadReleaseCheck(dir); rc != nil || err != nil {
		t.Fatalf("no record: %+v, %v", rc, err)
	}
	at := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	published := "2026-11-19T16:12:41Z"
	rc, err := RecordReleaseCheck(dir, CheckOutcome{Repo: "varlatch/varlatch", Latest: &Latest{Version: "0.50.0-rc.2", PublishedAt: &published}, ReleaseSet: true}, at)
	if err != nil || rc.LastSuccess == nil || rc.LastAttempt.Failed != nil || rc.LastAttempt.CheckedAt != "2026-11-20T08:00:00.000Z" {
		t.Fatalf("found: %+v, %v", rc, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, ReleaseCheckFile))
	want := `{"lastAttempt":{"checkedAt":"2026-11-20T08:00:00.000Z","repo":"varlatch/varlatch","failed":null},"lastSuccess":{"checkedAt":"2026-11-20T08:00:00.000Z","repo":"varlatch/varlatch","latest":{"version":"0.50.0-rc.2","publishedAt":"2026-11-19T16:12:41Z"},"releaseSet":true}}` + "\n"
	if string(raw) != want {
		t.Fatalf("the record, as the TypeScript line writes it:\n%s", raw)
	}
	if info, err := os.Stat(filepath.Join(dir, ReleaseCheckFile)); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v, %v", info, err)
	}

	// A failure keeps the last success.
	rc, err = RecordReleaseCheck(dir, CheckOutcome{Repo: "varlatch/varlatch", Failed: "unreachable"}, at.Add(time.Hour))
	if err != nil || rc.LastAttempt.Failed == nil || *rc.LastAttempt.Failed != "unreachable" || rc.LastSuccess == nil || rc.LastSuccess.Latest.Version != "0.50.0-rc.2" {
		t.Fatalf("failed: %+v, %v", rc, err)
	}
	back, err := ReadReleaseCheck(dir)
	if err != nil || back.LastSuccess.CheckedAt != "2026-11-20T08:00:00.000Z" || back.LastAttempt.CheckedAt != "2026-11-20T09:00:00.000Z" {
		t.Fatalf("read back: %+v, %v", back, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}

	// An unreadable record is an error to read, and replaced by the next.
	if err := os.WriteFile(filepath.Join(dir, ReleaseCheckFile), []byte(`{"lastAttempt":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReleaseCheck(dir); err == nil {
		t.Fatal("an unreadable record was read")
	}
	if rc, err := RecordReleaseCheck(dir, CheckOutcome{Repo: "varlatch/varlatch", Failed: "not-found"}, at); err != nil || rc.LastSuccess != nil {
		t.Fatalf("replacing an unreadable record: %+v, %v", rc, err)
	}
}

func TestReleaseCheckRefuses(t *testing.T) {
	bad := "yesterday"
	for _, c := range []struct {
		name string
		o    CheckOutcome
		want string
	}{
		{"no repository", CheckOutcome{Latest: &Latest{Version: "1.0.0"}}, "not a repository"},
		{"a repository named ..", CheckOutcome{Repo: "varlatch/..", Latest: &Latest{Version: "1.0.0"}}, "not a repository"},
		{"a version with a v", CheckOutcome{Repo: "a/b", Latest: &Latest{Version: "v1.0.0"}}, "not a release version"},
		{"a date that is not one", CheckOutcome{Repo: "a/b", Latest: &Latest{Version: "1.0.0", PublishedAt: &bad}}, "not a date and time"},
		{"an unknown failure", CheckOutcome{Repo: "a/b", Failed: "timeout"}, "not a failure the record knows"},
		{"both", CheckOutcome{Repo: "a/b", Latest: &Latest{Version: "1.0.0"}, Failed: "unreachable"}, "one of them"},
		{"neither", CheckOutcome{Repo: "a/b"}, "one of them"},
	} {
		if _, err := RecordReleaseCheck(t.TempDir(), c.o, time.Now()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if u, err := ReleaseURL("varlatch/varlatch", "0.50.0-rc.2"); err != nil || u != "https://github.com/varlatch/varlatch/releases/tag/v0.50.0-rc.2" {
		t.Fatalf("%q, %v", u, err)
	}
	if _, err := ReleaseURL("varlatch/varlatch", "0.50.0/../x"); err == nil {
		t.Fatal("a URL from a version that is not one")
	}
}
