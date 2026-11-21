// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The certificate issuance count survives a backup and a restore onto a
// fresh host (step 6 decision 16): it is in the database, so the restored
// installation counts what the old one asked for, a refused attempt aside.
func TestIssuanceCountSurvivesARestore(t *testing.T) {
	in, bek, _ := backupInstall(t, t.TempDir(), 0)
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, config.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, outcome := range []string{"issued", "issued", "started", "refused"} {
		at := now.Add(-time.Duration(i+1) * time.Hour).UnixMicro()
		if _, err := conn.Exec(`INSERT INTO certificate_issuances (name, started_at, outcome) VALUES ('vault.varlatch.test', ?, ?)`, at, outcome); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()

	r := start(t, in)
	code, out, errOut := runAdmin(t, "backup", "run", "--config", in.conf)
	m := archiveCreated.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("backup run: %d %q %q", code, out, errOut)
	}
	r.stop(t)

	host := t.TempDir()
	target := install{dir: host, conf: filepath.Join(host, "varlatchd.conf"), kekFile: filepath.Join(host, "root-kek"),
		data: filepath.Join(host, "data"), accessLog: filepath.Join(host, "access.log")}
	if err := os.MkdirAll(target.data, 0o700); err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{in.kekFile: target.kekFile, bek: filepath.Join(host, "bek"), m[1]: filepath.Join(host, "archive.vltbak")} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target.write(t, "backup_key_file = "+filepath.Join(host, "bek")+"\nbackup_interval = off\n")
	if code, out, errOut := runAdmin(t, "backup", "restore", "--in", filepath.Join(host, "archive.vltbak"), "--config", target.conf); code != ExitOK || !strings.HasPrefix(out, "Restore completed for inst_") {
		t.Fatalf("restore: %d %q %q", code, out, errOut)
	}
	restored, err := sql.Open("sqlite", "file:"+filepath.Join(target.data, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	row, err := query.New(restored).CountCertificateIssuances(context.Background(), query.CountCertificateIssuancesParams{Name: "vault.varlatch.test", StartedAt: now.Add(-7 * 24 * time.Hour).UnixMicro()})
	if err != nil || row.N != 3 || row.Oldest != now.Add(-3*time.Hour).UnixMicro() {
		t.Fatalf("the restored count: %+v %v, want 3 from %s", row, err, fmt.Sprint(now.Add(-3*time.Hour)))
	}
}
