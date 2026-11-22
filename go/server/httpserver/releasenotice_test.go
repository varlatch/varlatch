// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
)

// GET /v1/installation/release reads the host's release check
// (`varlatch upgrade --check`, ADR-0049) as releaseNotice.ts does: newer
// against this server's version at read time, the link built from the
// record's fields, a failed attempt beside the last success, and an
// unreadable record said, not an error.
func TestInstallationReleaseReadsTheReleaseCheck(t *testing.T) {
	dir := t.TempDir()
	s, _, _, _, ta := newTestServerAuth(t, func(o *Options) { o.ReleaseCheckDir = dir; o.Version = "0.50.0-rc.1" })
	get := func() map[string]any {
		t.Helper()
		w := do(s, "GET", "/v1/installation/release", "", map[string]string{"Authorization": "Bearer " + ta.tokens["valid"]})
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	if doc := get(); doc["running"] != "0.50.0-rc.1" || doc["newer"] != nil || doc["latest"] != nil || doc["lastAttempt"] != nil || doc["unreadable"] != false {
		t.Fatalf("no record: %v", doc)
	}

	at := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	if _, err := release.RecordReleaseCheck(dir, release.CheckOutcome{Repo: "varlatch/varlatch", Latest: &release.Latest{Version: "0.50.0-rc.2"}, ReleaseSet: true}, at); err != nil {
		t.Fatal(err)
	}
	doc := get()
	latest, _ := doc["latest"].(map[string]any)
	if doc["newer"] != true || latest["version"] != "0.50.0-rc.2" || latest["url"] != "https://github.com/varlatch/varlatch/releases/tag/v0.50.0-rc.2" ||
		latest["publishedAt"] != nil || latest["releaseSet"] != true || latest["checkedAt"] != "2026-11-20T08:00:00.000Z" {
		t.Fatalf("a newer release found: %v", doc)
	}

	// A failed attempt keeps the success; a server at that release sees
	// nothing newer.
	if _, err := release.RecordReleaseCheck(dir, release.CheckOutcome{Repo: "varlatch/varlatch", Failed: "rate-limited"}, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s2, _, _, _, ta2 := newTestServerAuth(t, func(o *Options) { o.ReleaseCheckDir = dir; o.Version = "0.50.0-rc.2" })
	w := do(s2, "GET", "/v1/installation/release", "", map[string]string{"Authorization": "Bearer " + ta2.tokens["valid"]})
	var at2 map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &at2)
	attempt, _ := at2["lastAttempt"].(map[string]any)
	if at2["newer"] != false || attempt["failed"] != "rate-limited" || at2["latest"] == nil {
		t.Fatalf("after the upgrade, a failed attempt: %v", at2)
	}

	if err := os.WriteFile(filepath.Join(dir, release.ReleaseCheckFile), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if doc := get(); doc["unreadable"] != true || doc["latest"] != nil || doc["newer"] != nil {
		t.Fatalf("an unreadable record: %v", doc)
	}
}
