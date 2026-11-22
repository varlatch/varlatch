// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
)

// `varlatch migrate` is a Go-only command (outside the parity table): its
// usage, its refusals, and --status on a directory without a migration.
func TestMigrateCommand(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Main(args, MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut})
		return code, out.String(), errOut.String()
	}
	if code, out, _ := run("migrate", "--help"); code != 0 || !strings.Contains(out, "varlatch migrate --resume") || !strings.Contains(out, "varlatch migrate --rollback") {
		t.Fatalf("--help: %d %q", code, out)
	}
	for _, c := range []struct {
		args []string
		why  string
	}{
		{[]string{"migrate"}, "--ingress is public, proxy or coolify"},
		{[]string{"migrate", "--ingress", "public"}, "give the target (--config, or --to-data"},
		{[]string{"migrate", "--ingress", "public", "--config", "/c", "--to-data", "/d"}, "give one of them"},
		{[]string{"migrate", "--ingress", "public", "--to-data", "/d"}, "all of them"},
		{[]string{"migrate", "--ingress", "public", "--to-data", "/d", "--to-keys", "/k", "--to-config", "/c", "--to-image", "i", "--to-service", "s", "--unit", "u"}, "--unit is a host install's"},
		{[]string{"migrate", "--resume", "--abort", "--config", "/c", "--bek-file", "/b", "--backup-destination", "d", "--read-credentials-file", "/r"}, "not both"},
		{[]string{"migrate", "--status", "--config", "/x"}, "--status takes --from and --json only"},
		{[]string{"migrate", "--resume", "--dry-run", "--config", "/c", "--bek-file", "/b", "--backup-destination", "d", "--read-credentials-file", "/r"}, "neither takes --dry-run"},
		{[]string{"migrate", "--max-downtime", "soon"}, "--max-downtime takes a duration"},
		{[]string{"migrate", "--frm", "/x"}, "unknown option --frm"},
		{[]string{"migrate", "--ingress", "public", "--unit", "--host=x"}, "--unit takes a systemd unit's name"},
		{[]string{"migrate", "--resume"}, "--resume and --abort need the target"},
		{[]string{"migrate", "--abort", "--bek-file", "/b"}, "--resume and --abort need the target"},
		{[]string{"migrate", "--rollback"}, "--rollback needs the target"},
		{[]string{"migrate", "--forget-target", "--config", "/c"}, "--forget-target goes with --abort and --config only"},
		{[]string{"migrate", "--abort", "--forget-target"}, "--forget-target goes with --abort and --config only"},
		{[]string{"migrate", "--abort", "--forget-target", "--to-data", "/d", "--to-keys", "/k", "--to-config", "/c", "--to-image", "i", "--to-service", "s"}, "--forget-target goes with --abort and --config only"},
		{[]string{"migrate", "--resume", "--forget-target", "--config", "/c"}, "--forget-target goes with --abort and --config only"},
		{[]string{"migrate", "--rollback", "--config", "/c", "--ingress", "proxy"}, "--rollback takes --from, the target"},
		{[]string{"migrate", "--rollback", "--config", "/c", "--bek-file", "/b"}, "--rollback takes --from, the target"},
		{[]string{"migrate", "--rollback", "--resume", "--config", "/c"}, "--rollback takes --from, the target"},
		{[]string{"migrate", "--rollback", "--dry-run", "--config", "/c"}, "--rollback takes --from, the target"},
		{[]string{"migrate", "--delete-old-data", "--config", "/c"}, "--delete-old-data goes with --finish only"},
		{[]string{"migrate", "--rollback", "--delete-old-data", "--config", "/c"}, "--delete-old-data goes with --finish only"},
		{[]string{"migrate", "--finish"}, "--finish needs the target"},
		{[]string{"migrate", "--finish", "--rollback", "--config", "/c"}, "--finish takes --from, the target"},
		{[]string{"migrate", "--finish", "--ingress", "proxy", "--config", "/c"}, "--finish takes --from, the target"},
		{[]string{"migrate", "--finish", "--yes", "--config", "/c"}, "unknown option --yes"},
		{[]string{"migrate", "--rollback", "--config", "/c", "--listen", "127.0.0.1:1"}, "the answers of a host target migrate makes"},
		{[]string{"migrate", "--ingress", "proxy", "--to-data", "/d", "--to-keys", "/k", "--to-config", "/c", "--to-image", "i", "--to-service", "s", "--accept-existing-user"}, "the answers of a host target migrate makes"},
		{[]string{"migrate", "--ingress", "public", "--config", "/c", "--accept-rollback-certificate"}, "--accept-rollback-certificate goes with --tailscale-oauth-client-file"},
		{[]string{"migrate", "--status", "--tailscale-oauth-client-file", "/o"}, "the tailnet's authority and --tailnet-auth-key-file go with a migration"},
		{[]string{"migrate", "--finish", "--config", "/c", "--headscale-cli", "/usr/bin/headscale"}, "the tailnet's authority and --tailnet-auth-key-file go with a migration"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "https://192.0.2.10"}, "--headscale-url and --headscale-api-key-file go together"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-api-key-file", "/k"}, "--headscale-url and --headscale-api-key-file go together"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "https://192.0.2.10", "--headscale-api-key-file", "/k", "--headscale-cli", "/usr/bin/headscale"}, "--headscale-url or --headscale-cli, not both"},
		{[]string{"migrate", "--resume", "--config", "/c", "--tailscale-oauth-client-file", "/o", "--headscale-cli", "/usr/bin/headscale"}, "one tailnet authority"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "https://headscale.example", "--headscale-api-key-file", "/k"}, "is given as https://<its IP address>[:port]"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "http://192.0.2.10", "--headscale-api-key-file", "/k"}, "is given as https://<its IP address>[:port]"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "https://[fe80::1%25eth0]", "--headscale-api-key-file", "/k"}, "a zoned address is not a control server's"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-url", "https://0.0.0.0", "--headscale-api-key-file", "/k"}, "not an address a control server listens on"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-cli", "headscale"}, "--headscale-cli is the headscale command's absolute path"},
		{[]string{"migrate", "--resume", "--config", "/c", "--headscale-cli", "/usr/bin/headscale", "--accept-rollback-certificate"}, "--accept-rollback-certificate goes with --tailscale-oauth-client-file"},
	} {
		if code, _, errOut := run(c.args...); code != ExitUsage || !strings.Contains(errOut, c.why) {
			t.Errorf("%q: %d %q, want %q", c.args, code, errOut, c.why)
		}
	}
	dir := t.TempDir()
	if code, out, errOut := run("migrate", "--status", "--from", dir); code != 0 || !strings.Contains(out, "No migration was started from "+dir) {
		t.Fatalf("--status: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("migrate", "--status", "--from", dir, "--json"); code != 0 || strings.TrimSpace(out) != "null" {
		t.Fatalf("--status --json: %d %q", code, out)
	}
	// An empty BEK file is refused before anything runs.
	empty := dir + "/bek"
	if err := writeEmpty(empty); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run("migrate", "--ingress", "proxy", "--config", "/c", "--bek-file", empty, "--backup-destination", "d", "--read-credentials-file", "/r", "--from", dir); code != ExitFailure || !strings.Contains(errOut, "is empty") {
		t.Fatalf("an empty BEK file: %d %q", code, errOut)
	}
	// Not in the parity table.
	if lookup("migrate") != nil {
		t.Fatal("migrate is in the parity table")
	}
}

func writeEmpty(path string) error { return os.WriteFile(path, []byte("\n"), 0o600) }

// A run killed before it closed its Headscale API key leaves a mark in
// the Compose directory (the key's prefix and when, never the key); the
// next run names the prefix to expire; a run that closed its key leaves
// none.
func TestAnUnclosedHeadscaleKeyIsNamed(t *testing.T) {
	dir := t.TempDir()
	if note := unclosedKeyNote(dir); note != "" {
		t.Fatalf("no mark: %q", note)
	}
	at := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	markKeyOpen(dir, "hskey-api-abcdefghijkl", at)
	if st, err := os.Stat(filepath.Join(dir, headscaleKeyMark)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the mark: %v %v", st, err)
	}
	note := unclosedKeyNote(dir)
	if !strings.Contains(note, "the Headscale API key hskey-api-abcdefghijkl at 2026-11-21T06:00:00Z and did not close it") ||
		!strings.Contains(note, "headscale apikeys expire --prefix hskey-api-abcdefghijkl") {
		t.Fatalf("the note: %q", note)
	}
	markKeyClosed(dir)
	if note := unclosedKeyNote(dir); note != "" {
		t.Fatalf("after close: %q", note)
	}
}

// migrate needs root for the host target at setup's place whenever it may
// change it: its configuration missing, or not readable (stat refused: it
// may be missing), or a journal recording a target migrate made and has
// not removed, before its switch (an --abort or --resume removes it, as
// root); a prepared target, one migrate made and removed again, or one
// past its switch (kept: the installation) needs none. The stat errors are
// built here, as no directory refuses its owner's stat on every platform.
func TestTargetNeedsRoot(t *testing.T) {
	conf := "/etc/varlatch/varlatchd.conf"
	missing := &fs.PathError{Op: "stat", Path: conf, Err: fs.ErrNotExist}
	denied := &fs.PathError{Op: "stat", Path: conf, Err: fs.ErrPermission}
	journal := func(p migrate.Phase, undone string) *migrate.Journal {
		return &migrate.Journal{ID: "m1", Phase: p, Created: &migrate.CreatedRecord{Made: []string{"user", "config"}, Undone: undone}}
	}
	for _, c := range []struct {
		name    string
		statErr error
		j       *migrate.Journal
		want    string
	}{
		{"missing", missing, nil, "does not exist"},
		{"stat refused", denied, nil, "cannot be read"},
		{"made, undone, not removed", nil, journal(migrate.Released, ""), "has not removed it"},
		{"made, before the barrier", nil, journal(migrate.DryRun, ""), "has not removed it"},
		{"prepared", nil, nil, ""},
		{"made, removed again", nil, journal(migrate.Released, "2026-11-22T00:00:00Z"), ""},
		{"made, open", nil, journal(migrate.Open, ""), ""},
		{"made, finished", nil, journal(migrate.Finished, ""), ""},
	} {
		got := targetNeedsRoot(c.statErr, c.j)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// --status of an undo whose removal of the made target is not done says
// so, and names each item's place, for removing it by hand.
func TestMigrateStatusRemovalPending(t *testing.T) {
	dir := t.TempDir()
	j := `{"format":1,"id":"mig_test","phase":"released","history":[],"created":{"made":["user","etc-dir","config"],"config":"/etc/varlatch/varlatchd.conf"}}`
	if err := os.WriteFile(filepath.Join(dir, migrate.JournalFile), []byte(j), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Main([]string{"migrate", "--status", "--from", dir}, MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut})
	if code != 0 || !strings.Contains(out.String(), "removal pending: varlatch migrate --abort removes it") ||
		!strings.Contains(out.String(), "  etc-dir: /etc/varlatch\n") || !strings.Contains(out.String(), "  config: /etc/varlatch/varlatchd.conf\n") {
		t.Errorf("--status: %d %q %q", code, out.String(), errOut.String())
	}
}
