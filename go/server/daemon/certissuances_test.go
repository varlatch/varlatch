// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The count across a migration of a tailnet name (go-step7 decision 11):
// `admin certificate record` writes attempts made elsewhere, each once by
// name and start, through a running varlatchd or offline; `admin
// certificate issuances --all --json` lists every attempt kept,
// read-only, whether varlatchd runs or not. A refused form writes nothing.
func TestCertificateAttemptsAreRecordedAndListed(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	end := at.Add(30 * time.Second)
	attempts := fmt.Sprintf(`[{"name":"vault.corp.ts.net","startedAt":%q,"outcome":"issued","endedAt":%q},{"name":"vault-vl-abcdefghij-n.corp.ts.net","startedAt":%q,"outcome":"started"}]`,
		at.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), at.Add(-time.Minute).Format(time.RFC3339Nano))
	if code, out, errOut := runAdmin(t, "certificate", "record", "--attempts", attempts, "--config", in.conf); code != ExitOK || out != "Recorded 2 certificate attempts (2 given).\n" {
		t.Fatalf("record, running: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runAdmin(t, "certificate", "record", "--attempts", attempts, "--config", in.conf); code != ExitOK || out != "Recorded 0 certificate attempts (2 given).\n" {
		t.Fatalf("record again: %d %q %q", code, out, errOut)
	}
	list := func() []recordedAttempt {
		t.Helper()
		code, out, errOut := runAdmin(t, "certificate", "issuances", "--all", "--json", "--config", in.conf)
		var doc struct {
			Attempts []recordedAttempt `json:"attempts"`
		}
		if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil {
			t.Fatalf("issuances --all: %d %q %q", code, out, errOut)
		}
		return doc.Attempts
	}
	got := list()
	if len(got) != 2 || got[0].Name != "vault-vl-abcdefghij-n.corp.ts.net" || got[0].Outcome != "started" || got[0].EndedAt != nil ||
		got[1].Name != "vault.corp.ts.net" || !got[1].StartedAt.Equal(at) || got[1].EndedAt == nil || !got[1].EndedAt.Equal(end) {
		t.Fatalf("listed %+v", got)
	}
	r.stop(t)
	// Offline: one more, and one past the count's keep (not recorded).
	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	more := fmt.Sprintf(`[{"name":"vault.corp.ts.net","startedAt":%q,"outcome":"refused"},{"name":"vault.corp.ts.net","startedAt":%q,"outcome":"issued"}]`,
		at.Add(time.Minute).Format(time.RFC3339Nano), old.Format(time.RFC3339Nano))
	if code, out, errOut := runAdmin(t, "certificate", "record", "--attempts", more, "--config", in.conf); code != ExitOK || out != "Recorded 1 certificate attempts (2 given).\n" {
		t.Fatalf("record, offline: %d %q %q", code, out, errOut)
	}
	if got := list(); len(got) != 3 || got[2].Outcome != "refused" {
		t.Fatalf("listed offline %+v", got)
	}
	for _, c := range []struct{ args, want string }{
		{`record --attempts [{"name":"Vault.corp.ts.net","startedAt":"2026-11-21T00:00:00Z","outcome":"issued"}]`, "is not a certificate's name"},
		{`record --attempts [{"name":"vault.corp.ts.net","startedAt":"2026-11-21T00:00:00Z","outcome":"maybe"}]`, "is not started, issued or refused"},
		{`record --attempts [{"name":"vault.corp.ts.net","outcome":"issued"}]`, "has no start"},
		{`record --attempts nope`, "is not a JSON array"},
		{`record`, "Usage: varlatchd admin certificate"},
		{`issuances --all`, "Usage: varlatchd admin certificate"},
	} {
		args := append([]string{"certificate"}, strings.SplitN(c.args, " ", 3)...)
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: %d %q", c.args, code, errOut)
		}
	}
	if got := list(); len(got) != 3 {
		t.Fatalf("a refused form wrote: %+v", got)
	}
}
