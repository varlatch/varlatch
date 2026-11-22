// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestBootstrapStatus: `admin bootstrap-status` reads, never writes, what
// setup waits for: no installation yet; created, not bootstrapped;
// bootstrapped headless (an admin without a passkey); and an admin with a
// passkey, read offline beside no daemon.
func TestBootstrapStatus(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	status := func(want BootstrapStatus) {
		t.Helper()
		code, out, errOut := runAdmin(t, "bootstrap-status", "--config", in.conf)
		var got BootstrapStatus
		if code != ExitOK || json.Unmarshal([]byte(out), &got) != nil {
			t.Fatalf("bootstrap-status: %d %q %q", code, out, errOut)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			t.Errorf("bootstrap-status: %s, want %s", a, b)
		}
	}
	status(BootstrapStatus{Admins: []BootstrapStatusAdmin{}})
	if dbs, _ := filepath.Glob(filepath.Join(in.data, "*.db")); len(dbs) != 0 {
		t.Errorf("bootstrap-status made a database: %v", dbs)
	}
	r := start(t, in)
	status(BootstrapStatus{Initialized: true, Admins: []BootstrapStatusAdmin{}})
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	admin := m[1]
	status(BootstrapStatus{Initialized: true, Bootstrapped: true, Admins: []BootstrapStatusAdmin{{ID: admin, Enabled: true}}})
	r.stop(t)

	// A passkey on the admin's sign-in user, as an enrollment leaves it.
	db, err := sql.Open("sqlite", filepath.Join(in.data, "varlatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO auth_users (id, name, email) VALUES ('usr_status', 'Admin', 'admin@varlatch.test')`,
		`INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES ('usr_status', '` + admin + `')`,
		`INSERT INTO passkeys (id, public_key, user_id, credential_id, counter, device_type, backed_up) VALUES ('pk_status', 'public', 'usr_status', 'credential', 0, 'singleDevice', 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	status(BootstrapStatus{Initialized: true, Bootstrapped: true, Admins: []BootstrapStatusAdmin{{ID: admin, Enabled: true, HasPasskey: true}}})

	if code, _, errOut := runAdmin(t, "bootstrap-status", "extra", "--config", in.conf); code != 64 || errOut != "Usage: varlatchd admin bootstrap-status [--config <file>]\n" {
		t.Errorf("an argument: %d %q", code, errOut)
	}
}
