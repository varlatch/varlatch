// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
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

// With the host's facts (ADR-0065 phase 1), the release also says how
// varlatchd runs, the verified target of the newer release, whether it is
// rollback-safe for this one, and the pre-flight; without them (the
// TypeScript fixtures' replay) it answers exactly as before.
func TestInstallationReleasePreflight(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	host := upgradecheck.Host{Deployment: upgradecheck.Image, Schema: 7}
	s, _, _, _, ta := newTestServerAuth(t, func(o *Options) {
		o.ReleaseCheckDir, o.Version = dir, "0.51.0"
		o.UpgradeHost = func(context.Context) upgradecheck.Host { return host }
	})
	get := func() map[string]any {
		t.Helper()
		w := do(s, "GET", "/v1/installation/release", "", map[string]string{"Authorization": "Bearer " + ta.tokens["valid"]})
		var doc map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &doc) != nil {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return doc
	}
	if doc := get(); doc["deployment"] != "image" || doc["schemaVersion"] != float64(7) || doc["target"] != nil || doc["rollbackSafe"] != nil || doc["preflight"] != nil {
		t.Fatalf("nothing checked: %v", doc)
	}
	if _, err := release.RecordReleaseCheck(dir, release.CheckOutcome{Repo: "varlatch/varlatch", Latest: &release.Latest{Version: "0.52.0"}, ReleaseSet: true}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	image := "ghcr.io/varlatch/varlatchd:0.52.0@sha256:" + strings.Repeat("0123456789abcdef", 4)
	if _, err := release.RecordReleaseTarget(dir, release.Target{Version: "0.52.0", Verified: &release.VerifiedTarget{SchemaVersion: 8, CompatibleFrom: 7, RollbackSafe: true,
		Previous: &release.Previous{Version: "0.51.1", SchemaVersion: 7}, Image: image}}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	doc := get()
	target, _ := doc["target"].(map[string]any)
	verified, _ := target["verified"].(map[string]any)
	lines, _ := doc["preflight"].([]any)
	if target["version"] != "0.52.0" || verified["image"] != image || doc["rollbackSafe"] != false || len(lines) != 6 {
		t.Fatalf("a jump, verified: %v", doc)
	}
	var safety map[string]any
	for _, l := range lines {
		if m := l.(map[string]any); m["id"] == "rollback-safe" {
			safety = m
		}
	}
	if safety["status"] != "fail" || safety["detail"] != "0.52.0 was checked against 0.51.1, not 0.51.0: upgrade one release at a time." {
		t.Errorf("the rollback-safe line: %v", safety)
	}

	plain, _, _, _, tp := newTestServerAuth(t, func(o *Options) { o.ReleaseCheckDir, o.Version = dir, "0.51.0" })
	w := do(plain, "GET", "/v1/installation/release", "", map[string]string{"Authorization": "Bearer " + tp.tokens["valid"]})
	var bare map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &bare)
	if _, has := bare["preflight"]; has || len(bare) != 5 {
		t.Errorf("without the host: %v", bare)
	}
}
