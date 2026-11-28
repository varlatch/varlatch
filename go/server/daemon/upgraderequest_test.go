// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/upgraderequest"
)

// admin upgrade-request record and heartbeat write the helper's records in
// the data directory, whole, and refuse anything that is not one.
func TestAdminUpgradeRequestRecord(t *testing.T) {
	in := newInstall(t, "")
	id := "upr_" + strings.Repeat("a", 26)
	if code, out, errOut := runAdmin(t, "upgrade-request", "record", "--request", id, "--phase", "refused", "--version", "0.52.0", "--reason", "undone", "--config", in.conf); code != ExitOK || !strings.Contains(out, `"phase":"refused"`) {
		t.Fatalf("record: %d %q %q", code, out, errOut)
	}
	s, err := upgraderequest.ReadStatus(in.data)
	if err != nil || s == nil || s.RequestID != id || s.Phase != upgraderequest.Refused || s.Reason != "undone" || s.Version != "0.52.0" {
		t.Fatalf("the status: %+v, %v", s, err)
	}
	if code, _, errOut := runAdmin(t, "upgrade-request", "record", "--request", id, "--phase", "backing-up", "--journal", "0123456789abcdef", "--config", in.conf); code != ExitOK {
		t.Fatalf("record a journal: %d %q", code, errOut)
	}
	if s, err := upgraderequest.ReadStatus(in.data); err != nil || s.JournalID != "0123456789abcdef" || s.Reason != "" {
		t.Fatalf("the status with a journal: %+v, %v", s, err)
	}
	if code, _, errOut := runAdmin(t, "upgrade-request", "heartbeat", "--helper-version", "0.52.0", "--enabled", "true", "--config", in.conf); code != ExitOK {
		t.Fatalf("heartbeat: %d %q", code, errOut)
	}
	if h, err := upgraderequest.ReadHelper(in.data); err != nil || h == nil || !h.Enabled || h.Version != "0.52.0" || h.Heartbeat().IsZero() || h.Problem != "" {
		t.Fatalf("the helper record: %+v, %v", h, err)
	}
	// A run that could not take a request says so, by class; the next
	// heartbeat without one clears it.
	if code, _, errOut := runAdmin(t, "upgrade-request", "heartbeat", "--helper-version", "0.52.0", "--enabled", "true", "--problem", "take", "--config", in.conf); code != ExitOK {
		t.Fatalf("heartbeat with a problem: %d %q", code, errOut)
	}
	if h, err := upgraderequest.ReadHelper(in.data); err != nil || h == nil || h.Problem != "take" {
		t.Fatalf("the helper record with a problem: %+v, %v", h, err)
	}
	if code, _, errOut := runAdmin(t, "upgrade-request", "heartbeat", "--enabled", "true", "--helper-version", "0.52.0", "--config", in.conf); code != ExitOK {
		t.Fatalf("heartbeat: %d %q", code, errOut)
	}
	if h, err := upgraderequest.ReadHelper(in.data); err != nil || h == nil || h.Problem != "" {
		t.Fatalf("the problem was not cleared: %+v, %v", h, err)
	}
	for _, args := range [][]string{
		{"upgrade-request"},
		{"upgrade-request", "record", "--request", id},
		{"upgrade-request", "record", "--request", "upr_x", "--phase", "taken"},
		{"upgrade-request", "record", "--request", id, "--phase", "refused"},
		{"upgrade-request", "record", "--request", id, "--phase", "refused", "--reason", "because I said so"},
		{"upgrade-request", "record", "--request", id, "--phase", "taken", "--reason", "undone"},
		{"upgrade-request", "record", "--request", id, "--phase", "elsewhere"},
		{"upgrade-request", "record", "--request", id, "--phase", "taken", "--journal", "../../etc"},
		{"upgrade-request", "heartbeat", "--helper-version", "0.52.0"},
		{"upgrade-request", "heartbeat", "--helper-version", "latest", "--enabled", "true"},
		{"upgrade-request", "heartbeat", "--helper-version", "0.52.0", "--enabled", "yes"},
		{"upgrade-request", "heartbeat", "--helper-version", "0.52.0", "--enabled", "true", "--problem", "it broke"},
		{"upgrade-request", "heartbeat", "--enabled", "true", "--problem", "take"},
	} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, "Usage: varlatchd admin upgrade-request") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}
