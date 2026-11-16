// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/config"
)

// `admin outbound check`: read-only, in this process; the report with its
// exit code (0 allowed, 1 refused), a candidate allow list with --allow,
// one Organization with --org, JSON with --json. Literal addresses only:
// no lookup leaves the test.
func TestAdminOutboundCheck(t *testing.T) {
	in := newInstall(t, "backup_interval = off\noutbound_allow = 192.168.0.0/16\n")
	run := func(args ...string) (int, string, string) {
		t.Helper()
		return runAdmin(t, append(append([]string{"outbound"}, args...), "--config", in.conf)...)
	}
	// Before there is a database.
	if code, out, errOut := run("check"); code != ExitOK || !strings.Contains(out, "VARLATCH_OUTBOUND_ALLOW: 192.168.0.0/16\n\nNo destinations configured.") {
		t.Fatalf("no database: %d %q %q", code, out, errOut)
	}
	r := start(t, in)
	r.stop(t)
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(context.Background(), func(tx *storage.Tx) error {
		for _, q := range []string{
			`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}'), ('org_b', 'beta', 'Beta', '{}')`,
			`INSERT INTO webhooks (id, organization_id, url, secret_envelope, created_at, cursor_occurred_at) VALUES
				('whk_1', 'org_a', 'https://10.0.0.9/x', '{}', 1, 0), ('whk_2', 'org_b', 'https://192.168.1.1/y', '{}', 2, 0)`,
		} {
			if _, err := tx.ExecContext(context.Background(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	code, out, _ := run("check")
	if code != ExitFailure || !strings.Contains(out, "acme  webhook  whk_1  https://10.0.0.9:443  [10.0.0.9]  REFUSED (private_address)") ||
		!strings.Contains(out, "beta  webhook  whk_2  https://192.168.1.1:443  [192.168.1.1]  allowed by 192.168.0.0/16") {
		t.Errorf("check: %d %q", code, out)
	}
	if code, out, _ := run("check", "--org", "beta"); code != ExitOK || strings.Contains(out, "whk_1") || !strings.Contains(out, "Every destination is allowed.") {
		t.Errorf("--org beta: %d %q", code, out)
	}
	code, out, _ = run("check", "--allow", "10.0.0.9/32,192.168.1.1", "--json")
	var report struct {
		Allow        []string `json:"allow"`
		Destinations []struct {
			ID, Verdict string
			Entries     []string
		} `json:"destinations"`
		ExitCode int `json:"exitCode"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &report) != nil || report.ExitCode != 0 || len(report.Destinations) != 2 ||
		report.Destinations[0].Verdict != "allowed" || report.Destinations[0].Entries[0] != "10.0.0.9/32" || strings.Join(report.Allow, ",") != "10.0.0.9/32,192.168.1.1" {
		t.Errorf("--allow --json: %d %q", code, out)
	}
	if code, _, errOut := run("check", "--allow", "10.0.0.0/33"); code != ExitFailure || errOut != "VARLATCH_OUTBOUND_ALLOW: 10.0.0.0/33 is not a valid CIDR range\n" {
		t.Errorf("an invalid --allow: %d %q", code, errOut)
	}
	for _, args := range [][]string{{}, {"list"}, {"check", "--bogus"}, {"check", "--org"}} {
		if code, _, errOut := run(args...); code != 64 || !strings.HasPrefix(errOut, outboundUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}
