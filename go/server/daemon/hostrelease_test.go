// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
)

// admin status is a running varlatchd's answer, or nothing's: it never
// opens the database or takes the lock.
func TestAdminStatus(t *testing.T) {
	in := newInstall(t, "")
	code, out, errOut := runAdmin(t, "status", "--json", "--config", in.conf)
	if code != ExitFailure || out != "" || !strings.Contains(errOut, "it is not running") {
		t.Fatalf("not running: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("status opened the database: %v", err)
	}
	r := start(t, in)
	code, out, errOut = runAdmin(t, "status", "--json", "--config", in.conf)
	var st statusJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil {
		t.Fatalf("running: %d %q %q", code, out, errOut)
	}
	if st.Version != buildinfo.Version || st.SchemaVersion != db.SchemaVersion || !st.Serving || !st.Ready.Schema || !st.Ready.RootKEK || !st.Ready.Installation {
		t.Fatalf("status: %+v", st)
	}
	if code, out, _ = runAdmin(t, "status", "--config", in.conf); code != ExitOK || !strings.Contains(out, "is running; serving: true") {
		t.Fatalf("text: %d %q", code, out)
	}
	r.stop(t)
	for _, args := range [][]string{{"status", "--json", "--json"}, {"status", "--wait"}} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, statusUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

// admin release-check record writes the record GET /v1/installation/release
// reads, beside a running varlatchd or not.
func TestAdminReleaseCheck(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	code, out, errOut := runAdmin(t, "release-check", "record", "--repo", "varlatch/varlatch", "--version", "0.50.0-rc.2", "--published-at", "2026-11-19T16:12:41Z", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"version":"0.50.0-rc.2"`) {
		t.Fatalf("found: %d %q %q", code, out, errOut)
	}
	r.stop(t)
	code, _, errOut = runAdmin(t, "release-check", "record", "--repo", "varlatch/varlatch", "--failed", "unreachable", "--config", in.conf)
	if code != ExitOK {
		t.Fatalf("failed: %d %q", code, errOut)
	}
	rc, err := release.ReadReleaseCheck(in.data)
	if err != nil || rc.LastSuccess == nil || rc.LastSuccess.Latest.Version != "0.50.0-rc.2" || *rc.LastAttempt.Failed != "unreachable" {
		t.Fatalf("the record: %+v, %v", rc, err)
	}
	for _, args := range [][]string{
		{"release-check"}, {"release-check", "record"}, {"release-check", "record", "--repo", "a/b"},
		{"release-check", "record", "--repo", "a/b", "--version", "1.0.0", "--failed", "unreachable"},
		{"release-check", "record", "--repo", "a/b", "--failed", "unreachable", "--published-at", "2026-11-19T16:12:41Z"},
		{"release-check", "record", "--repo", "a/b", "--version", "1.0.0", "--version", "1.0.1"},
	} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, releaseCheckUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if code, _, errOut := runAdmin(t, "release-check", "record", "--repo", "a/b", "--failed", "timeout", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "nothing was written") {
		t.Errorf("an unknown failure: %d %q", code, errOut)
	}
}

// admin schema upgrade --database upgrades a copy, beside a running
// varlatchd too; the live database under another name is not a copy.
func TestAdminSchemaUpgradeOfACopy(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	code, out, _ := runAdmin(t, "schema", "status", "--json", "--config", in.conf)
	var st struct {
		DataDir string `json:"dataDir"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil || st.DataDir != in.data {
		t.Fatalf("status names the data directory: %d %q", code, out)
	}
	r.stop(t)
	raw, err := os.ReadFile(filepath.Join(in.data, "varlatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	copyPath := filepath.Join(work, "varlatch.db")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r = start(t, in)
	code, out, errOut := runAdmin(t, "schema", "upgrade", "--json", "--database", copyPath, "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"changed":false`) {
		t.Fatalf("a copy beside a running varlatchd: %d %q %q", code, out, errOut)
	}
	// The live database through a link is the live database: refused while
	// varlatchd runs.
	link := filepath.Join(work, "live.db")
	if err := os.Symlink(filepath.Join(in.data, "varlatch.db"), link); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = runAdmin(t, "schema", "upgrade", "--database", link, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Fatalf("the live database by another name: %d %q", code, errOut)
	}
	r.stop(t)
	if code, _, errOut = runAdmin(t, "schema", "upgrade", "--database", filepath.Join(work, "missing.db"), "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "the database copy") {
		t.Fatalf("a missing copy: %d %q", code, errOut)
	}
	if code, _, errOut = runAdmin(t, "schema", "status", "--database", copyPath, "--config", in.conf); code != 64 {
		t.Fatalf("--database with status: %d %q", code, errOut)
	}
}

// admin changes lists the audit events since a time, read-only, beside a
// running varlatchd: by type, the newest first, never a value.
func TestAdminChanges(t *testing.T) {
	in := newInstall(t, "")
	before := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	r := start(t, in)
	if code, _, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf); code != ExitOK {
		t.Fatalf("bootstrap: %d %q", code, errOut)
	}
	code, out, errOut := runAdmin(t, "changes", "--since", before, "--json", "--config", in.conf)
	var doc changesJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.Total == 0 || len(doc.Latest) == 0 || doc.Total != sum(doc.ByType) {
		t.Fatalf("changes: %d %q %q", code, out, errOut)
	}
	r.stop(t)
	// A revocation since then, made by the write path the server's routes
	// use (auth.RevokeCredential, behind DELETE /v1/me/credentials/{id} and
	// identity and credential revocation), with the decision it records:
	// listed first, with its resource.
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	var credentialID, identityID string
	if err := s.Write(context.Background(), func(tx *storage.Tx) error {
		if err := tx.QueryRowContext(context.Background(), "SELECT id, identity_id FROM credentials WHERE revoked_at IS NULL ORDER BY created_at LIMIT 1").Scan(&credentialID, &identityID); err != nil {
			return err
		}
		return auth.RevokeCredential(context.Background(), tx, time.Now().UnixMicro(), credentialID, identityID, nil)
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	code, out, _ = runAdmin(t, "changes", "--since", before, "--json", "--config", in.conf)
	var withRevocation changesJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &withRevocation) != nil || withRevocation.RevocationsTotal != 1 || len(withRevocation.Revocations) != 1 ||
		withRevocation.Revocations[0].EventType != "credential.revoked" || withRevocation.Revocations[0].Resource == nil || !strings.Contains(*withRevocation.Revocations[0].Resource, identityID) {
		t.Fatalf("a revocation: %d %q", code, out)
	}
	if code, out, _ = runAdmin(t, "changes", "--since", before, "--config", in.conf); code != ExitOK || !strings.Contains(out, ", 1 of them revocations, removals, rotations, replacements, deletions and freezes.") {
		t.Fatalf("the revocation counted: %d %q", code, out)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if code, out, _ = runAdmin(t, "changes", "--since", future, "--config", in.conf); code != ExitOK || !strings.HasPrefix(out, "0 audit events since") {
		t.Fatalf("none since: %d %q", code, out)
	}
	for _, args := range [][]string{{"changes"}, {"changes", "--since", "yesterday"}, {"changes", "--since", before, "--json", "--json"}} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, changesUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

func sum(m map[string]int64) (n int64) {
	for _, v := range m {
		n += v
	}
	return n
}

// Every audit event type whose name says it revokes, removes, deletes,
// retires, disables, freezes, rotates or replaces something is either one
// a snapshot restore undoes to the host's harm (restoreUndoes, listed
// first by admin changes), or named here with why not.
func TestRestoreUndoesCoversEveryRevocation(t *testing.T) {
	notHarmful := map[string]string{
		"organization.unfrozen":             "the restore re-freezes: no access comes back",
		"organization.deletion_cancelled":   "the restore re-schedules a deletion: no access comes back",
		"organization.deletion_approved":    "an approval step, the deletion itself is organization.deleted",
		"value.rotation_started":            "the rotation's end is value.rotation_completed",
		"security_control.reset":            "the restore turns controls back on: no access comes back",
		"security_control.would_block":      "a report, nothing changed",
		"authentication.device_code_locked": "the restore unlocks a device sign-in code that has expired by then",
		"exposure.revocation_confirmed":     "the revocation at the provider stands whatever the restore takes back",
	}
	in := map[string]bool{}
	for _, e := range restoreUndoes {
		in[e] = true
	}
	known := map[string]bool{}
	for _, e := range audit.EventTypes {
		known[e] = true
	}
	words := regexp.MustCompile(`revok|revoc|remov|delet|retir|disabl|froz|rotat|replac|lock`)
	for _, e := range audit.EventTypes {
		if !words.MatchString(e) {
			continue
		}
		if !in[e] && notHarmful[e] == "" {
			t.Errorf("%s: neither in restoreUndoes nor named as harmless to undo", e)
		}
	}
	for _, e := range restoreUndoes {
		if !known[e] {
			t.Errorf("restoreUndoes names %s, which is no audit event type", e)
		}
	}
	for e := range notHarmful {
		if !known[e] {
			t.Errorf("the exclusions name %s, which is no audit event type", e)
		}
	}
}
