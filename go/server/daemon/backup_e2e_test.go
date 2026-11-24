// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
)

// backupInstall is the read path's fixture installation (g7Install) with a
// Backup Encryption Key, no schedule, and fillerMiB of incompressible rows,
// so a paced backup takes a while; and alice's token.
func backupInstall(t *testing.T, dir string, fillerMiB int) (install, string, string) {
	t.Helper()
	in, f := g7Install(t, dir)
	bek := filepath.Join(dir, "bek")
	if err := os.WriteFile(bek, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in.write(t, "backup_key_file = "+bek+"\nbackup_interval = off\n")
	if fillerMiB > 0 {
		conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, config.DatabaseFile))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Exec("CREATE TABLE g7_filler (v BLOB) STRICT"); err != nil {
			t.Fatal(err)
		}
		for range fillerMiB {
			if _, err := conn.Exec("INSERT INTO g7_filler VALUES (randomblob(1048576))"); err != nil {
				t.Fatal(err)
			}
		}
	}
	return in, bek, f.Tokens["alice"]
}

// slowBackups paces a backup so a test can act while it runs.
func slowBackups(o *backups.Options) {
	o.SealRate = 4 << 20
	o.Snapshot = storage.SnapshotOptions{StepPages: 64, Pause: 50 * time.Millisecond}
}

// stalledIn paces a backup as slowBackups does, except its phase (snapshot
// or sealing), which it slows so that a kill made once the phase is
// reached lands in it, however fast the machine: the snapshot at a page
// every 200 ms, which does not end within a test's minutes; the sealing at
// 1 MiB/s. The manifest's hashing before the sealing goes at the same rate
// (the backup's one pace), so with killDuringBackup's 16 MiB filler the
// sealing starts after about 16 s and then lasts about as long.
func stalledIn(phase string) func(*backups.Options) {
	return func(o *backups.Options) {
		slowBackups(o)
		switch phase {
		case "snapshot":
			o.Snapshot = storage.SnapshotOptions{StepPages: 1, Pause: 200 * time.Millisecond}
		case "sealing":
			o.SealRate = 1 << 20
		}
	}
}

// damaged is the archive at good with the same identity, whose database
// has no installation: it opens and passes every check before the
// database is replaced, and fails after.
func damaged(t *testing.T, good, bekFile string) string {
	t.Helper()
	raw, _ := os.ReadFile(bekFile)
	material, err := backup.ParseKey(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	bek, _ := backup.KeyBEK(material)
	scratch := t.TempDir()
	o, err := backup.Open(good, bek, scratch)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	conn, err := sql.Open("sqlite", "file:"+o.Path(backup.ComponentDatabase))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec("DELETE FROM installation"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	m := o.Manifest
	for i, c := range m.Components {
		if m.Components[i], err = backup.Describe(c.Name, o.Path(c.Name)); err != nil {
			t.Fatal(err)
		}
	}
	manifest, _ := json.Marshal(m)
	out := filepath.Join(t.TempDir(), "damaged.vltbak")
	if err := backup.Seal(out, manifest, []string{o.Path(backup.ComponentDatabase), o.Path(backup.ComponentConfiguration)}, bek, backup.SealOptions{}); err != nil {
		t.Fatal(err)
	}
	return out
}

func status(t *testing.T, url string) int {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// The Go replacement of scripts/test-backup-e2e.mjs: a backup taken while
// varlatchd serves (ready throughout, and every disclosure during it
// answered, none held up),
// checked, then restored on a fresh host that holds only the
// configuration, the archive and the two keys; the restored installation
// serves the same values, records installation.restored, and a restore
// that fails after replacing the database stays isolated across a
// restart until running it again completes it.
func TestBackupRestoreEndToEnd(t *testing.T) {
	in, bek, fixture := backupInstall(t, t.TempDir(), 8)
	r := startWith(t, in, &hooks{backups: slowBackups})
	base := "http://" + r.addr
	client := &http.Client{Timeout: 10 * time.Second}

	var during []string
	done := make(chan struct{})
	var out, errOut string
	var code int
	go func() {
		defer close(done)
		code, out, errOut = runAdmin(t, "backup", "run", "--config", in.conf)
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			if res, err := client.Get(base + "/readyz"); err != nil {
				during = append(during, "readyz: "+err.Error())
			} else {
				res.Body.Close()
				if res.StatusCode != 200 {
					during = append(during, fmt.Sprint("readyz ", res.StatusCode))
				}
			}
			s, _, body, err := disclose(client, base, fixture)
			switch {
			case err != nil:
				during = append(during, err.Error())
			case s == 200 && strings.Contains(body, "hunter2-hunter2"):
				during = append(during, "disclosed")
			default:
				during = append(during, fmt.Sprint(s))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	m := archiveCreated.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("backup run: %d %q %q", code, out, errOut)
	}
	for _, d := range during {
		if d != "disclosed" {
			t.Fatalf("not ready, or a disclosure not answered, during the backup: %v", during)
		}
	}
	if len(during) < 5 {
		t.Fatalf("only %d disclosures during the backup", len(during))
	}
	archive, archiveID := m[1], m[2]
	r.stop(t)

	// A fresh host: the configuration, the archive and the two keys only.
	host := t.TempDir()
	target := install{dir: host, conf: filepath.Join(host, "varlatchd.conf"), kekFile: filepath.Join(host, "root-kek"),
		data: filepath.Join(host, "data"), accessLog: filepath.Join(host, "access.log")}
	os.MkdirAll(target.data, 0o700)
	copyTo := func(from, to string) {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(to, b, 0o600)
	}
	copyTo(in.kekFile, target.kekFile)
	copyTo(bek, filepath.Join(host, "bek"))
	copyTo(archive, filepath.Join(host, "archive.vltbak"))
	target.write(t, "backup_key_file = "+filepath.Join(host, "bek")+"\nbackup_interval = off\n")

	// A restore that fails after the database was replaced: isolated, and
	// still isolated after a restart.
	bad := damaged(t, archive, bek)
	if code, _, errOut := runAdmin(t, "backup", "restore", "--in", bad, "--config", target.conf); code != ExitFailure || !strings.Contains(errOut, "no installation") {
		t.Fatalf("the damaged restore: %d %q", code, errOut)
	}
	for i := 0; i < 2; i++ {
		tr := start(t, target)
		if s := status(t, "http://"+tr.addr+"/v1/meta"); s != 503 {
			t.Errorf("start %d after the failed restore: /v1/meta %d", i, s)
		}
		if s := status(t, "http://"+tr.addr+"/readyz"); s != 503 {
			t.Errorf("start %d after the failed restore: /readyz %d", i, s)
		}
		tr.stop(t)
	}

	// Running it again with the archive completes it.
	code, out, errOut = runAdmin(t, "backup", "restore", "--in", filepath.Join(host, "archive.vltbak"), "--config", target.conf)
	if code != ExitOK || !strings.HasPrefix(out, "Restore completed for inst_") || !strings.Contains(out, archiveID) {
		t.Fatalf("restore: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(out, "The installation is held") || !strings.Contains(out, "varlatchd admin restore resume") {
		t.Errorf("the restore does not say it holds: %q", out)
	}
	tr := start(t, target)
	s, _, body, err := disclose(client, "http://"+tr.addr, fixture)
	if err != nil || s != 200 || !strings.Contains(body, "hunter2-hunter2") {
		t.Fatalf("a disclosure on the restored host: %d %v %.200s", s, err, body)
	}
	// While it runs, a restore is refused.
	if code, _, errOut := runAdmin(t, "backup", "restore", "--in", filepath.Join(host, "archive.vltbak"), "--config", target.conf); code != ExitFailure || !strings.Contains(errOut, "stop it before a restore") {
		t.Errorf("a restore while varlatchd runs: %d %q", code, errOut)
	}
	tr.stop(t)
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(target.data, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var restored string
	if err := conn.QueryRow("SELECT json_extract(metadata, '$.archiveId') FROM audit_events WHERE event_type = 'installation.restored' ORDER BY event_order DESC LIMIT 1").Scan(&restored); err != nil || restored != archiveID {
		t.Errorf("installation.restored names %q (%v), want %s", restored, err, archiveID)
	}
}

// A completed restore holds the installation (backup.Hold): it serves, and
// an organization deletion that is due in the archive (cancelled since, say)
// does not run, across a restart, until `admin restore resume`, in the
// running varlatchd or on a stopped one's data directory; each resume is
// audited.
func TestRestoreHoldsWork(t *testing.T) {
	if testing.Short() {
		t.Skip("restores and restarts")
	}
	in, bek, _ := backupInstall(t, t.TempDir(), 0)
	path := filepath.Join(in.data, config.DatabaseFile)
	exec1 := func(q string) {
		t.Helper()
		conn, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	one := func(q string) (v string) {
		t.Helper()
		conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.QueryRow(q).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec1(`INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required)
		SELECT 'odl_aaaaaaaaaaaaaaaaaaaaaaaaaa', o.id, (SELECT id FROM identities LIMIT 1), 1000000, 2000000, 0 FROM organizations o WHERE o.slug = 'acme'`)
	const deleted = `SELECT completed_at IS NOT NULL FROM organization_deletions WHERE id = 'odl_aaaaaaaaaaaaaaaaaaaaaaaaaa'`
	const resumed = `SELECT count(*) FROM audit_events WHERE event_type = 'installation.restore_resumed'`
	admin := func(want int, args ...string) string {
		t.Helper()
		code, out, errOut := runAdmin(t, append(args, "--config", in.conf)...)
		if code != want {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
		return out + errOut
	}
	m := archiveCreated.FindStringSubmatch(admin(ExitOK, "backup", "run"))
	if m == nil {
		t.Fatal("no archive")
	}
	if out := admin(ExitOK, "restore", "status"); out != "{\"held\":false}\n" {
		t.Errorf("status before a restore: %q", out)
	}
	if out := admin(ExitFailure, "restore", "resume"); !strings.Contains(out, "not held") {
		t.Errorf("resume before a restore: %q", out)
	}
	admin(ExitOK, "backup", "restore", "--in", m[1], "--backup-key-file", bek)
	readyz := func(r *running) string {
		t.Helper()
		res, err := http.Get("http://" + r.addr + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Errorf("/readyz %d", res.StatusCode)
		}
		return string(b)
	}
	var r *running
	for range 2 {
		r = start(t, in)
		r.stopOnCleanup(t)
		// The deletion worker's first pass is at the start; it has long
		// been once this is over (the control below deletes within it).
		time.Sleep(1500 * time.Millisecond)
		if v := one(deleted); v != "0" {
			t.Fatal("the organization was deleted while held")
		}
		if b := readyz(r); !strings.HasSuffix(strings.TrimSpace(b), `,"held":true}`) {
			t.Errorf("/readyz while held: %s", b)
		}
		if out := admin(ExitOK, "restore", "status"); !strings.HasPrefix(out, `{"held":true,"archiveId":"`) {
			t.Errorf("status while held: %q", out)
		}
		if out := admin(ExitOK, "status"); !strings.Contains(out, "is held: varlatchd admin restore resume") {
			t.Errorf("admin status while held: %q", out)
		}
		// A backup is made while held.
		admin(ExitOK, "backup", "run")
		if !strings.Contains(r.stderr.String(), "was restored from an archive and is held") {
			t.Error("the log does not say it is held")
		}
		r.stop(t)
	}
	// Online.
	r = start(t, in)
	r.stopOnCleanup(t)
	admin(ExitOK, "restore", "resume")
	if b := readyz(r); strings.Contains(b, "held") {
		t.Errorf("/readyz once resumed: %s", b)
	}
	if v := one(resumed); v != "1" {
		t.Errorf("%s installation.restore_resumed events", v)
	}
	if v := one(`SELECT json_extract(metadata, '$.archiveId') IS NOT NULL AND actor_identity_id IS NULL FROM audit_events WHERE event_type = 'installation.restore_resumed'`); v != "1" {
		t.Error("the event does not name its archive")
	}
	r.stop(t)
	// Restored again, resumed with varlatchd stopped: the deletion that was
	// due then runs at the start (the control).
	admin(ExitOK, "backup", "restore", "--in", m[1], "--backup-key-file", bek)
	gate := filepath.Join(in.data, backup.GateFile)
	if err := os.WriteFile(gate, []byte(`{"id":"g","kind":"restore","phase":"paused","expiresAt":null,"archiveId":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := admin(ExitFailure, "restore", "resume"); !strings.Contains(out, MaintenanceRefusal) {
		t.Errorf("resume behind a restore's gate: %q", out)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	admin(ExitOK, "restore", "resume")
	r = start(t, in)
	r.stopOnCleanup(t)
	for deadline := time.Now().Add(1500 * time.Millisecond); one(deleted) != "1"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the due deletion did not run at the start of a resumed installation, so the checks above show nothing")
		}
	}
	r.stop(t)
}

// A restore's hold in a data directory without a database: an import is
// refused, naming it and how to clear it, and `restore resume` removes it
// without making a database; a dangling link is cleared the same way.
func TestStaleHold(t *testing.T) {
	in := newInstall(t, "")
	path := filepath.Join(in.data, backup.HoldFile)
	for _, c := range []struct {
		make func() error
		what string
	}{
		{func() error { return backup.WriteHold(in.data, backup.Hold{ArchiveID: "a", RestoredAt: "t"}) }, "the hold's file"},
		{func() error { return os.Symlink(filepath.Join(in.dir, "missing"), path) }, "a symbolic link"},
	} {
		if err := c.make(); err != nil {
			t.Fatal(err)
		}
		if err := importableDataDir(in.data); err == nil || !strings.Contains(err.Error(), backup.HoldFile) || !strings.Contains(err.Error(), "varlatchd admin restore resume") {
			t.Errorf("an import beside a hold: %v", err)
		}
		if code, out, _ := runAdmin(t, "restore", "status", "--config", in.conf); code != ExitOK || !strings.HasPrefix(out, `{"held":true`) {
			t.Errorf("status: %d %q", code, out)
		}
		if code, out, errOut := runAdmin(t, "restore", "resume", "--config", in.conf); code != ExitOK || !strings.Contains(out, "Removed the stale "+backup.HoldFile+" ("+c.what+")") {
			t.Errorf("resume: %d %q %q", code, out, errOut)
		}
		if _, err := os.Lstat(filepath.Join(in.data, config.DatabaseFile)); !os.IsNotExist(err) {
			t.Fatalf("a database was made: %v", err)
		}
		if err := importableDataDir(in.data); err != nil {
			t.Errorf("an import afterwards: %v", err)
		}
	}
	if code, _, errOut := runAdmin(t, "restore", "resume", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not held") {
		t.Errorf("nothing to clear: %d %q", code, errOut)
	}
	if _, err := os.Lstat(filepath.Join(in.data, config.DatabaseFile)); !os.IsNotExist(err) {
		t.Fatalf("a database was made: %v", err)
	}
}

// G7 during a backup: varlatchd (this test binary, serving) is killed with
// SIGKILL in the middle of a backup, once during the snapshot and once
// during the sealing, while clients ask for disclosures. Nothing committed
// is lost (every disclosure answered has its audit event; the database is
// consistent), and no partial archive is counted as a backup: there is no
// archive and no status record, and the next run removes what the killed
// one left and makes one.
func TestKillDuringBackup(t *testing.T) {
	if conf := os.Getenv("G7_BACKUP_SERVE_CONF"); conf != "" {
		os.Exit(serve(Options{ConfigPath: conf, Stderr: os.Stderr, Ready: func(a net.Addr) {
			fmt.Println("ready", a.String())
		}}, &hooks{backups: stalledIn(os.Getenv("G7_BACKUP_PHASE"))}))
	}
	for _, phase := range []string{"snapshot", "sealing"} {
		t.Run(phase, func(t *testing.T) { killDuringBackup(t, phase) })
	}
}

func killDuringBackup(t *testing.T, phase string) {
	in, _, token := backupInstall(t, t.TempDir(), 16)
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillDuringBackup$")
	cmd.Env = append(os.Environ(), "G7_BACKUP_SERVE_CONF="+in.conf, "G7_BACKUP_PHASE="+phase)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	defer func() {
		if !killed {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if a, ok := strings.CutPrefix(sc.Text(), "ready "); ok {
				addr <- a
			}
		}
	}()
	var base string
	select {
	case a := <-addr:
		base = "http://" + a
	case <-time.After(30 * time.Second):
		t.Fatalf("varlatchd did not serve: %s", stderr.String())
	}

	var mu sync.Mutex
	var disclosed []string
	var lastErr error
	var answered atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, id, body, err := disclose(client, base, token)
				if err != nil {
					// A transient failure under load (a client timeout) is
					// tried again; after the kill, stop ends the loop.
					mu.Lock()
					lastErr = err
					mu.Unlock()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if s == 200 && strings.Contains(body, "hunter2-hunter2") {
					mu.Lock()
					disclosed = append(disclosed, id)
					mu.Unlock()
					answered.Add(1)
				} else if s != 429 {
					t.Errorf("disclosure answered %d: %.200s", s, body)
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	// Disclosures are flowing before the backup starts (under the race
	// detector everything is slower).
	for deadline := time.Now().Add(60 * time.Second); answered.Load() < 5; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) || t.Failed() {
			mu.Lock()
			err := lastErr
			mu.Unlock()
			t.Fatalf("%d disclosures answered before the backup (the last client error: %v): %s", answered.Load(), err, stderr.String())
		}
	}
	backupDone := make(chan struct{})
	go func() {
		defer close(backupDone)
		runAdmin(t, "backup", "run", "--config", in.conf)
	}()
	dir := filepath.Join(in.data, backups.Dir)
	inPhase := func() bool {
		works, _ := filepath.Glob(filepath.Join(dir, ".work-*", backup.ComponentDatabase))
		partials, _ := filepath.Glob(filepath.Join(dir, ".work-*", "*.partial"))
		if phase == "snapshot" {
			return len(works) > 0 && len(partials) == 0
		}
		return len(partials) > 0
	}
	deadline := time.Now().Add(60 * time.Second)
	for !inPhase() {
		if time.Now().After(deadline) {
			t.Fatalf("the backup never reached its %s: %s", phase, stderr.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The phase has just begun, and stalledIn keeps it going for minutes:
	// the kill lands in it.
	time.Sleep(100 * time.Millisecond)
	if !inPhase() {
		t.Fatalf("the backup left its %s before the kill", phase)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	killed = true
	close(stop)
	wg.Wait()
	<-backupDone
	if answered.Load() == 0 {
		t.Fatal("no disclosure was answered before the kill")
	}

	// Nothing committed is lost.
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	reader := store.Reader()
	var check string
	if err := reader.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}
	mu.Lock()
	for _, id := range disclosed {
		var n int
		if err := reader.QueryRow(`SELECT count(*) FROM audit_events WHERE request_id = ? AND event_type = 'secret.disclosed'`, id).Scan(&n); err != nil || n != 1 {
			t.Fatalf("request %s received its values, but its secret.disclosed event is missing after the kill (%v)", id, err)
		}
	}
	mu.Unlock()
	store.Close()

	// No partial archive is counted as a backup.
	if archives, _ := filepath.Glob(filepath.Join(dir, "*.vltbak")); len(archives) != 0 {
		t.Errorf("an archive after the kill: %v", archives)
	}
	if records, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(records) != 0 {
		t.Errorf("a status record after the kill: %v", records)
	}
	left := listingOf(dir)
	r := start(t, in)
	code, out, _ := runAdmin(t, "backup", "status", "--config", in.conf)
	var st backup.Status
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil || len(st.Archives) != 0 {
		t.Errorf("status after the kill: %d %q", code, out)
	}
	code, out, errOut := runAdmin(t, "backup", "run", "--config", in.conf)
	m := archiveCreated.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("the next run: %d %q %q", code, out, errOut)
	}
	if got := listingOf(dir); got != m[2]+".json "+m[2]+".vltbak" {
		t.Errorf("after the next run the backups directory holds %q (the killed run left %q)", got, left)
	}
	r.stop(t)
	t.Logf("killed during the %s with %q left; %d disclosures answered, each audited", phase, left, len(disclosed))
}

func listingOf(dir string) string {
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, " ")
}
