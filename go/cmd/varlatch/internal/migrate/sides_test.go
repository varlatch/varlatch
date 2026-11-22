// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scripted is a Runner that answers each program and argument list from
// a table and records what it ran, with its stdin.
type scripted struct {
	t       *testing.T
	answers map[string]Ran
	ran     []string
	stdins  map[string][]byte
}

func (s *scripted) Run(_ context.Context, dir, name string, args []string, stdin []byte) (Ran, error) {
	key := name + " " + strings.Join(args, " ")
	s.ran = append(s.ran, key)
	if s.stdins == nil {
		s.stdins = map[string][]byte{}
	}
	s.stdins[key] = append([]byte(nil), stdin...)
	for prefix, r := range s.answers {
		if strings.HasPrefix(key, prefix) {
			return r, nil
		}
	}
	s.t.Fatalf("unexpected run: %s", key)
	return Ran{}, nil
}

// Stream is Run on streams: what stdin gives is recorded (read to its
// end), the answer goes to stdout, and only Said and Code come back.
func (s *scripted) Stream(ctx context.Context, dir, name string, args []string, in io.Reader, out io.Writer) (Ran, error) {
	var input []byte
	if in != nil {
		var err error
		if input, err = io.ReadAll(in); err != nil {
			return Ran{}, err
		}
	}
	r, err := s.Run(ctx, dir, name, args, input)
	if err != nil {
		return Ran{}, err
	}
	if _, err := out.Write(r.Answer); err != nil {
		return Ran{}, err
	}
	return Ran{Said: r.Said, Code: r.Code}, nil
}

// failingWriter fails once more than limit bytes were written to it.
type failingWriter struct{ n, limit int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n+len(p) > w.limit {
		return 0, errors.New("the disk is full (the test's)")
	}
	w.n += len(p)
	return len(p), nil
}

// ExecRunner.Stream, with real programs: the input is read to its end and
// closed, the output arrives whole, stderr's tail is kept; a program that
// writes more than the destination takes is killed, and Stream returns
// (never waits on a pipe nobody reads); one that refuses before reading
// its input is its exit status, not an error of the copy.
func TestExecRunnerStream(t *testing.T) {
	ctx := context.Background()
	var x ExecRunner
	input := randomBytes(3 << 20)
	var got bytes.Buffer
	r, err := x.Stream(ctx, t.TempDir(), "sh", []string{"-c", "cat; echo said >&2"}, bytes.NewReader(input), &got)
	if err != nil || r.Code != 0 || !bytes.Equal(got.Bytes(), input) || string(r.Said) != "said\n" || r.Answer != nil {
		t.Fatalf("cat: %d bytes, %+v, %v", got.Len(), r, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := x.Stream(ctx, t.TempDir(), "sh", []string{"-c", "while :; do printf '%065536d' 0; done"}, nil, &failingWriter{limit: 1 << 20})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "the disk is full") {
			t.Fatalf("a destination that fails: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Stream waited on a program whose output nobody reads")
	}
	r, err = x.Stream(ctx, t.TempDir(), "sh", []string{"-c", "echo refused >&2; exit 3"}, bytes.NewReader(input), io.Discard)
	if err != nil || r.Code != 3 || string(r.Said) != "refused\n" {
		t.Fatalf("a refusal before reading: %+v %v", r, err)
	}
}

// tail keeps exactly the last n bytes, however they were written.
func TestTail(t *testing.T) {
	all := randomBytes(10_000)
	for _, chunk := range []int{1, 7, 100, 999, 1000, 4000} {
		tl := &tail{n: 1000}
		for i := 0; i < len(all); i += chunk {
			_, _ = tl.Write(all[i:min(i+chunk, len(all))])
		}
		if !bytes.Equal(tl.bytes(), all[len(all)-1000:]) || len(tl.b) > 2000 {
			t.Errorf("chunk %d: kept %d bytes (held %d), not the last 1000", chunk, len(tl.bytes()), len(tl.b))
		}
	}
	short := &tail{n: 1000}
	_, _ = short.Write([]byte("abc"))
	if string(short.bytes()) != "abc" {
		t.Errorf("a short tail: %q", short.bytes())
	}
}

// The arguments never hold a key: the run key and the keys go on stdin.
func noKeyInArgs(t *testing.T, ran []string, keys ...[]byte) {
	t.Helper()
	for _, r := range ran {
		for _, k := range keys {
			for _, form := range []string{string(k), hexOf(k), base64.StdEncoding.EncodeToString(k)} {
				if strings.Contains(r, strings.TrimSpace(form)) {
					t.Fatalf("a key in the arguments: %s", r)
				}
			}
		}
	}
}

func TestComposeDiscover(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + hexOf(randomBytes(32))
	inspect, _ := json.Marshal(map[string]any{"RepoDigests": []string{"ghcr.io/varlatch/varlatchd@" + digest},
		"Config": map[string]any{"Labels": map[string]string{"org.opencontainers.image.version": "0.23.0"}}})
	run := &scripted{t: t, answers: map[string]Ran{
		"docker compose images --format json varlatchd":       {Answer: []byte(`[{"ContainerName":"x-varlatchd-1","Repository":"ghcr.io/varlatch/varlatchd","Tag":"0.23.0","ID":"sha256:abc"}]`)},
		"docker image inspect --format {{json .}} sha256:abc": {Answer: inspect},
	}}
	c := &Compose{Directory: dir, Run: run}
	info, err := c.Discover(context.Background())
	if err != nil || info.Release != "0.23.0" || info.Digest != digest || info.DigestRepository != "ghcr.io/varlatch/varlatchd" || info.Image != "ghcr.io/varlatch/varlatchd:0.23.0" {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := (&Compose{Directory: t.TempDir(), Run: run}).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "no docker-compose.yml") {
		t.Errorf("no Compose file: %v", err)
	}
}

// The digest an image is checked by, of the several Docker lists: the
// pinned image's when it is among them, whatever the order; else the
// pinned repository's first; else the running name's first; never another
// repository's.
func TestRepoDigest(t *testing.T) {
	pin := imagePin{Repository: "ghcr.io/varlatch/varlatchd", Digest: "sha256:" + strings.Repeat("a", 64)}
	platform := "sha256:" + strings.Repeat("b", 64)
	mirror := "sha256:" + strings.Repeat("c", 64)
	for _, c := range []struct {
		name         string
		digests      []string
		running      string
		digest, repo string
	}{
		{"the pin after a platform manifest", []string{pin.Repository + "@" + platform, pin.Repository + "@" + pin.Digest}, pin.Repository, pin.Digest, pin.Repository},
		{"the pin, run under a mirror's name", []string{"mirror.example.test/varlatchd@" + mirror, pin.Repository + "@" + pin.Digest}, "mirror.example.test/varlatchd", pin.Digest, pin.Repository},
		{"the pinned repository, another digest", []string{"mirror.example.test/varlatchd@" + mirror, pin.Repository + "@" + platform}, "mirror.example.test/varlatchd", platform, pin.Repository},
		{"only the running name's", []string{"mirror.example.test/varlatchd@" + mirror}, "mirror.example.test/varlatchd", mirror, "mirror.example.test/varlatchd"},
		{"only another repository's", []string{"someone.example.test/varlatchd@" + mirror}, pin.Repository, "", ""},
		{"not a digest", []string{pin.Repository + "@md5:00", "no-at-sign"}, pin.Repository, "", ""},
		{"none", nil, pin.Repository, "", ""},
	} {
		if d, r := repoDigest(c.digests, c.running, pin); d != c.digest || r != c.repo {
			t.Errorf("%s: %s %s, want %s %s", c.name, r, d, c.repo, c.digest)
		}
	}
}

func TestComposeKEKPath(t *testing.T) {
	dir := t.TempDir()
	c := &Compose{Directory: dir}
	if p, _ := c.kekPath(); p != filepath.Join(dir, "secrets", "varlatch-kek") {
		t.Errorf("the default: %s", p)
	}
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("VARLATCH_PUBLIC_URL=https://x\nVARLATCH_KEK_HOST_PATH=\"/srv/keys/kek\"\n"), 0o600)
	if p, _ := c.kekPath(); p != "/srv/keys/kek" {
		t.Errorf(".env's: %s", p)
	}
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("VARLATCH_KEK_HOST_PATH=keys/kek\n"), 0o600)
	if p, _ := c.kekPath(); p != filepath.Join(dir, "keys/kek") {
		t.Errorf(".env's relative: %s", p)
	}
	c.KEKFile = "/given"
	if p, _ := c.kekPath(); p != "/given" {
		t.Errorf("given: %s", p)
	}
}

// The source's commands: each `admin migration` in its varlatchd
// container, the backup through the TypeScript CLI; the run key only on the
// export's stdin; the bundle in the installation's backups directory.
func TestComposeCommands(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "backups"), 0o700)
	kek := []byte(hexOf(randomBytes(32)) + "\n")
	_ = os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "secrets", "varlatch-kek"), kek, 0o600)
	archive := "0f0e0d0c-0b0a-4908-8706-050403020100"
	exec := "docker compose exec -T varlatchd node dist/cli.js admin migration "
	bundleBytes := randomBytes(3 << 20)
	run := &scripted{t: t, answers: map[string]Ran{
		exec + "status":                     {Answer: []byte(`{"daemon":true,"gate":{"kind":"migration","id":"g1","phase":"frozen"}}` + "\n")},
		exec + "barrier --drain-seconds 90": {Answer: []byte(`{"gate":{"kind":"migration","id":"g1"},"drained":{"ms":1200,"waitedFor":{}},"frozen":{"auditPosition":"46","at":"2026-11-20T12:00:00.000Z","snapshot":"00000003-0000001B-1"}}` + "\n")},
		exec + "export":                     {Answer: bundleBytes, Said: []byte("exporting\n" + ExportSummaryPrefix + `{"frozenPoint":{},"bundle":{}}` + "\n")},
		exec + "release --id g1":            {Answer: []byte(`{"released":true}`)},
		exec + "mark-migrated-out --id g1":  {Answer: []byte(`{"gate":{"kind":"migrated-out"}}`)},
		"varlatch-ts admin backup create":   {Answer: []byte("Archive created: " + dir + "/backups/" + archive + ".vltbak (" + archive + ")\nUpload completed to offsite; remote retrieval has not been verified.\n")},
		"varlatch-ts admin backup verify":   {Answer: []byte(`{"archiveId":"` + archive + `","integrity":true,"compatibility":true,"keyMatch":true,"message":"checks passed"}` + "\n")},
	}}
	c := &Compose{Directory: dir, Run: run, BEKFile: "/keys/bek", Destination: "offsite", ReadCredentialsFile: "/keys/read.json"}
	ctx := context.Background()
	g, err := c.Gate(ctx)
	if err != nil || g == nil || g.Kind != "migration" || g.ID != "g1" {
		t.Fatalf("gate: %+v %v", g, err)
	}
	id, err := c.Backup(ctx)
	if err != nil || id != archive {
		t.Fatalf("backup: %s %v", id, err)
	}
	if err := c.VerifyBackup(ctx, archive); err != nil {
		t.Fatalf("verify: %v", err)
	}
	b, err := c.Barrier(ctx, 90*time.Second)
	if err != nil || b.GateID != "g1" || b.AuditPosition != "46" || b.Snapshot != "00000003-0000001B-1" {
		t.Fatalf("barrier: %+v %v", b, err)
	}
	runKey := randomBytes(32)
	path, err := c.Export(ctx, runKey, true)
	if err != nil || filepath.Dir(path) != filepath.Join(dir, "backups") {
		t.Fatalf("export: %s %v", path, err)
	}
	// The bundle came on the export's stdout, into a file of this host's:
	// all of it, mode 0600, and no .partial left.
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, bundleBytes) {
		t.Fatalf("the bundle on this host: %d bytes, %v", len(got), err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the bundle's mode: %v %v", st, err)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("the .partial after the export: %v", err)
	}
	var exportKey string
	for _, r := range run.ran {
		if strings.HasPrefix(r, exec+"export") {
			exportKey = r
		}
	}
	if exportKey != exec+"export --out - --digests --dry-run" || !bytes.Equal(run.stdins[exportKey], RunKeyText(runKey)) {
		t.Fatalf("the export: %q, stdin %q", exportKey, run.stdins[exportKey])
	}
	if err := c.Release(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkMigratedOut(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	k, err := c.RootKEK()
	if err != nil || !bytes.Equal(k, kek) {
		t.Fatalf("the Root KEK: %v", err)
	}
	for _, r := range run.ran {
		if strings.HasPrefix(r, "varlatch-ts admin backup") && !strings.Contains(r, "--kek-file "+filepath.Join(dir, "secrets", "varlatch-kek")) {
			t.Errorf("the backup is not given the KEK file's path: %s", r)
		}
	}
	noKeyInArgs(t, run.ran, runKey, bytes.TrimSpace(kek))
}

// An export that fails, or ends without its summary, leaves nothing in
// the backups directory: neither its bundle nor its .partial.
func TestComposeExportLeavesNothingWhenItFails(t *testing.T) {
	exec := "docker compose exec -T varlatchd node dist/cli.js admin migration export"
	for name, r := range map[string]Ran{
		"a failure":          {Code: 1, Answer: []byte("half a bundle"), Said: []byte("varlatchd admin migration export: EACCES open /tmp/x\n")},
		"no summary":         {Answer: []byte("a bundle"), Said: []byte("exporting\n")},
		"a summary not JSON": {Answer: []byte("a bundle"), Said: []byte(ExportSummaryPrefix + "{not json\n")},
		"a summary not last": {Answer: []byte("a bundle"), Said: []byte(ExportSummaryPrefix + "{}\nsomething after\n")},
	} {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, "backups"), 0o700)
		c := &Compose{Directory: dir, Run: &scripted{t: t, answers: map[string]Ran{exec: r}}}
		_, err := c.Export(context.Background(), randomBytes(32), false)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if name == "a failure" && (err == nil || !strings.Contains(err.Error(), "EACCES")) {
			t.Errorf("%s: %v does not say the export's own error", name, err)
		}
		if entries, _ := os.ReadDir(filepath.Join(dir, "backups")); len(entries) != 0 {
			t.Errorf("%s: left %v in backups", name, entries)
		}
	}
}

// The reverse import gets the bundle on its stdin (--in -), never as a
// copy in the backups directory; its answer is its stdout's last line, and
// a refusal (before it reads its input) is said with its own words.
func TestComposeImportReverseStreams(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "backups"), 0o700)
	bundle := filepath.Join(t.TempDir(), "reverse.jsonl")
	content := randomBytes(2 << 20)
	if err := os.WriteFile(bundle, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := "docker compose --profile varlatch-rollback run --rm -T varlatch-reverse-import admin migration import --in -"
	run := &scripted{t: t, answers: map[string]Ran{cmd: {Answer: []byte(`{"installationId":"inst_x","auditPosition":"48","migratedOutGate":"lifted"}` + "\n")}}}
	c := &Compose{Directory: dir, Run: run}
	rec, err := c.ImportReverse(context.Background(), bundle)
	if err != nil || rec.InstallationID != "inst_x" || rec.AuditPosition != "48" {
		t.Fatalf("import: %+v %v", rec, err)
	}
	if len(run.ran) != 1 || run.ran[0] != cmd || !bytes.Equal(run.stdins[cmd], content) {
		t.Fatalf("the import's command and stdin: %q, %d bytes", run.ran, len(run.stdins[cmd]))
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "backups")); len(entries) != 0 {
		t.Fatalf("a copy in backups: %v", entries)
	}
	run.answers[cmd] = Ran{Code: 1, Said: []byte("varlatchd admin migration import: varlatchd is running; stop it first\n")}
	if _, err := c.ImportReverse(context.Background(), bundle); err == nil || !strings.Contains(err.Error(), "varlatchd is running") {
		t.Fatalf("a refused import: %v", err)
	}
}

// What the source's answers must hold, or the step fails.
func TestComposeRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	exec := "docker compose exec -T varlatchd node dist/cli.js admin migration "
	run := &scripted{t: t, answers: map[string]Ran{
		exec + "barrier":                  {Answer: []byte(`{"gate":{"id":"g1"}}`)},
		"varlatch-ts admin backup create": {Answer: []byte("Archive created: /x (0f0e0d0c-0b0a-4908-8706-050403020100)\n")},
		"varlatch-ts admin backup verify": {Answer: []byte(`{"archiveId":"0f0e0d0c-0b0a-4908-8706-050403020100","integrity":true,"compatibility":false,"keyMatch":true}`)},
		exec + "status":                   {Code: 1, Said: []byte("varlatchd: no database\n")},
		exec + "export":                   {Answer: []byte("{}")},
	}}
	c := &Compose{Directory: dir, Run: run, BEKFile: "/b", Destination: "d", ReadCredentialsFile: "/r"}
	ctx := context.Background()
	if _, err := c.Barrier(ctx, time.Second); err == nil {
		t.Error("a barrier answer without its frozen point")
	}
	if _, err := c.Backup(ctx); err == nil || !strings.Contains(err.Error(), "created and uploaded") {
		t.Errorf("a backup not uploaded: %v", err)
	}
	if err := c.VerifyBackup(ctx, "0f0e0d0c-0b0a-4908-8706-050403020100"); err == nil {
		t.Error("a verification that failed a check")
	}
	if _, err := c.Gate(ctx); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Errorf("a failed status: %v", err)
	}
	if _, err := c.Export(ctx, randomBytes(32), false); err == nil {
		t.Error("an export that wrote no bundle")
	}
}

// The target's commands: `varlatchd admin migrate ... --config`, the keys
// as base64 JSON and the run key on stdin, the reports read.
func TestHostCommands(t *testing.T) {
	conf := "/etc/varlatch/varlatchd.conf"
	pre := "/usr/bin/varlatchd admin migrate "
	report := `{"passed":false,"bundle":{},"checks":[{"name":"rows","passed":false,"checked":902,"failures":[{"table":"grants","what":"row 2 differs from the source's in revoked_at"}],"more":0},{"name":"audit","passed":true,"checked":77,"failures":[],"more":0}]}`
	run := &scripted{t: t, answers: map[string]Ran{
		pre + "state --config": {Answer: []byte(`{"journal":{"format":1,"id":"mig_cccccccccccccccccccccccccc","phase":"preflight"},"database":false,"dataDir":"/var/lib/varlatch",` +
			`"release":"0.50.0","publicUrl":"https://v.example.test","listen":"127.0.0.1:8686","listenHttps":"","migrationGate":false,"running":false}`)},
		pre + "state --write": {Answer: []byte(`{}`)},
		pre + "keys":          {Answer: []byte(`{"rootKek":"written","bek":"unchanged"}`)},
		pre + "import":        {Answer: []byte(`{"installationId":"inst_x","direction":"forward","tables":58,"rows":902,"perTable":{},"sessionsEnded":1,"credentialsRevoked":1,"migratedPosition":48}`)},
		pre + "check":         {Code: 1, Answer: []byte(report)},
		pre + "discard --id":  {Answer: []byte(`{"removed":["varlatch.db"]}`)},
	}}
	h := &Host{Varlatchd: "/usr/bin/varlatchd", Config: conf, Run: run}
	ctx := context.Background()
	info, st, err := h.Describe(ctx)
	if err != nil || info.DataDir != "/var/lib/varlatch" || st.Journal == nil || st.Journal.Phase != Preflight || st.Database {
		t.Fatalf("describe: %+v %+v %v", info, st, err)
	}
	kek, bek := []byte(hexOf(randomBytes(32))+"\n"), []byte(hexOf(randomBytes(32))+"\n")
	k, b, err := h.Keys(ctx, kek, bek)
	if err != nil || k != "written" || b != "unchanged" {
		t.Fatalf("keys: %s %s %v", k, b, err)
	}
	var sent struct {
		RootKEK []byte `json:"rootKek"`
		BEK     []byte `json:"bek"`
	}
	if err := json.Unmarshal(run.stdins[pre+"keys --config "+conf], &sent); err != nil || !bytes.Equal(sent.RootKEK, kek) || !bytes.Equal(sent.BEK, bek) {
		t.Fatalf("the keys' stdin: %v", err)
	}
	cp, err := h.Import(ctx, "/srv/b.jsonl", "/tmp/scratch")
	if err != nil || cp.InstallationID != "inst_x" || cp.Rows != 902 || cp.CredsRevoked != 1 {
		t.Fatalf("import: %+v %v", cp, err)
	}
	runKey := randomBytes(32)
	sum, err := h.Check(ctx, "/srv/b.jsonl", "", runKey)
	if err != nil || sum.Passed || len(sum.Checks) != 2 || len(sum.Faults) != 1 || sum.Faults[0] != "rows: grants: row 2 differs from the source's in revoked_at" {
		t.Fatalf("check: %+v %v", sum, err)
	}
	if !bytes.Equal(run.stdins[pre+"check --in /srv/b.jsonl --json --config "+conf], RunKeyText(runKey)) {
		t.Fatal("the run key is not the check's stdin")
	}
	if err := h.Discard(ctx, "mig_cccccccccccccccccccccccccc"); err != nil {
		t.Fatal(err)
	}
	j := &Journal{Format: 1, ID: "mig_cccccccccccccccccccccccccc", Phase: Open, History: []Step{}}
	if err := h.WriteJournal(ctx, j); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(run.stdins[pre+"state --write --config "+conf], []byte(`"phase": "open"`)) {
		t.Fatal("the journal is not state --write's stdin")
	}
	want := []string{pre + "state --config " + conf, pre + "keys --config " + conf,
		pre + "import --in /srv/b.jsonl --json --scratch /tmp/scratch --config " + conf,
		pre + "check --in /srv/b.jsonl --json --config " + conf, pre + "discard --id mig_cccccccccccccccccccccccccc --config " + conf,
		pre + "state --write --config " + conf}
	if strings.Join(run.ran, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ran:\n%s\nwant:\n%s", strings.Join(run.ran, "\n"), strings.Join(want, "\n"))
	}
	noKeyInArgs(t, run.ran, runKey, bytes.TrimSpace(kek), bytes.TrimSpace(bek))
}

// The source's ingress, as its .env and Compose files have it, and the
// services the transfer stops and starts.
func TestComposeIngress(t *testing.T) {
	dir := t.TempDir()
	running := func(env string) *scripted {
		return &scripted{t: t, answers: map[string]Ran{
			"docker compose ps -q varlatchd":                  {Answer: []byte("c1\n")},
			"docker inspect --format {{json .Config.Env}} c1": {Answer: []byte(env)},
		}}
	}
	ing, err := (&Compose{Directory: dir, Run: running(`["PATH=/bin"]`)}).Ingress(context.Background())
	if err != nil || ing.PublicURL != "" || ing.Caddy || ing.WebAddress != "127.0.0.1:8787" || ing.OutboundAllow != "" || ing.OutboundAllowFromConfig {
		t.Fatalf("no .env: %+v %v", ing, err)
	}
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("# the installation\nVARLATCH_PUBLIC_URL=\"https://vault.example.test\"\n"+
		"COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\nVARLATCH_WEB_PORT=9000\nBIND_ADDRESS=0.0.0.0\n"+
		"VARLATCH_OUTBOUND_ALLOW=not.what.compose.gave\n"), 0o600)
	// The allow list is the container's, not .env's line.
	ing, err = (&Compose{Directory: dir, Run: running(`["VARLATCH_OUTBOUND_ALLOW= coolify.lan, 10.0.0.0/8:8000 "]`)}).Ingress(context.Background())
	if err != nil || ing.PublicURL != "https://vault.example.test" || !ing.Caddy || ing.WebAddress != "0.0.0.0:9000" || ing.OutboundAllow != "coolify.lan, 10.0.0.0/8:8000" {
		t.Fatalf(".env: %+v %v", ing, err)
	}
	run := &scripted{t: t, answers: map[string]Ran{"docker compose": {}}}
	c := &Compose{Directory: dir, Run: run}
	ctx := context.Background()
	for _, c2 := range []struct {
		kind Ingress
		want []string
	}{{Public, []string{"docker compose stop caddy", "docker compose ps -a -q caddy", "docker compose up -d --no-deps --force-recreate caddy"}},
		{Proxy, []string{"docker compose stop varlatch-web", "docker compose ps -a -q varlatch-web", "docker compose up -d --no-deps --force-recreate varlatch-web"}}} {
		run.ran = nil
		if err := c.StopIngress(ctx, c2.kind); err != nil {
			t.Fatal(err)
		}
		if err := c.StartIngress(ctx, c2.kind, false); err != nil {
			t.Fatal(err)
		}
		if strings.Join(run.ran, "|") != strings.Join(c2.want, "|") {
			t.Fatalf("%s: %q", c2.kind, run.ran)
		}
	}
	if err := c.StopIngress(ctx, Coolify); err == nil {
		t.Fatal("the Coolify shape has nothing here to stop")
	}
	// A container that serves (a retry after it came up) is started again
	// without being recreated, so a dashboard still starting is not killed
	// nor Caddy's connections dropped. Anything else is recreated: running
	// with no network (Caddy answers 502 so), restarting, caught running
	// in a crash loop, not one container, or with recreate (an undo whose
	// wait for the source timed out).
	for _, c2 := range []struct {
		name      string
		ids, info string
		recreate  bool
		want      string
	}{
		{"serves", "c1\n", "running false 0 1\n", false, "ps|inspect|up"},
		{"no network", "c1\n", "running false 0 0\n", false, "ps|inspect|recreate"},
		{"restarting", "c1\n", "restarting true 4 1\n", false, "ps|inspect|recreate"},
		{"caught running between restarts", "c1\n", "running false 4 1\n", false, "ps|inspect|recreate"},
		{"exited", "c1\n", "exited false 0 0\n", false, "ps|inspect|recreate"},
		{"no container", "", "", false, "ps|recreate"},
		{"two containers", "c1\nc2\n", "", false, "ps|recreate"},
		{"recreate", "c1\n", "running false 0 1\n", true, "recreate"},
	} {
		for _, k := range []Ingress{Public, Proxy} {
			svc, _ := ingressService(k)
			up := &scripted{t: t, answers: map[string]Ran{
				"docker compose ps -a -q " + svc:                     {Answer: []byte(c2.ids)},
				"docker inspect --format " + containerFormat + " c1": {Answer: []byte(c2.info)},
				"docker compose up -d --no-deps ":                    {},
			}}
			cu := &Compose{Directory: dir, Run: up}
			if err := cu.StartIngress(ctx, k, c2.recreate); err != nil {
				t.Fatal(err)
			}
			names := map[string]string{
				"docker compose ps -a -q " + svc: "ps", "docker inspect --format " + containerFormat + " c1": "inspect",
				"docker compose up -d --no-deps " + svc: "up", "docker compose up -d --no-deps --force-recreate " + svc: "recreate",
			}
			var got []string
			for _, r := range up.ran {
				got = append(got, names[r])
			}
			if strings.Join(got, "|") != c2.want {
				t.Errorf("%s, %s: %q", c2.name, k, up.ran)
			}
		}
	}
}

// The target's service and what its state says of its address.
func TestHostServiceAndAddress(t *testing.T) {
	run := &scripted{t: t, answers: map[string]Ran{
		"systemctl": {},
		"/usr/bin/varlatchd admin migrate state": {Answer: []byte(`{"journal":null,"database":false,"dataDir":"/var/lib/varlatch","release":"0.50.0",` +
			`"publicUrl":"https://vault.example.test/","listen":"127.0.0.1:8686","listenHttps":":443","migrationGate":false,"running":false}`)},
	}}
	h := &Host{Varlatchd: "/usr/bin/varlatchd", Config: "/etc/varlatch/varlatchd.conf", Run: run, Unit: "varlatchd-go"}
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, _, err := h.Describe(context.Background())
	if err != nil || info.Release != "0.50.0" || info.PublicURL != "https://vault.example.test/" || info.ListenHTTPS != ":443" || info.Listen != "127.0.0.1:8686" {
		t.Fatalf("%+v %v", info, err)
	}
	// An older varlatchd: its state names no release or gate.
	old := &Host{Varlatchd: "/usr/bin/varlatchd-old", Run: &scripted{t: t, answers: map[string]Ran{
		"/usr/bin/varlatchd-old admin migrate state": {Answer: []byte(`{"journal":null,"database":false,"dataDir":"/var/lib/varlatch"}`)}}}}
	if _, _, err := old.Describe(context.Background()); err == nil || !strings.Contains(err.Error(), "older than this varlatch") {
		t.Fatalf("an older varlatchd: %v", err)
	}
	if err := (&Host{Run: run, Unit: "--host=x"}).Start(context.Background()); err == nil {
		t.Fatal("an option as the unit")
	}
	if run.ran[0] != "systemctl start varlatchd-go" || run.ran[1] != "systemctl stop varlatchd-go" {
		t.Fatalf("%q", run.ran)
	}
}

// The public URL's probe, end to end against a local server: GET
// /v1/meta, asked past any cache, its installationId and serverVersion;
// anything else an error.
func TestHTTPProber(t *testing.T) {
	status, body := http.StatusOK, `{"apiMajor":1,"serverVersion":"0.50.0","capabilities":[],"installationId":"inst_x"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/meta" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// A proxy or CDN in front must not answer from its cache.
		if r.Header.Get("Cache-Control") != "no-cache" || r.Header.Get("Pragma") != "no-cache" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := HTTPProber{}
	id, version, err := p.Probe(context.Background(), srv.URL)
	if err != nil || id != "inst_x" || version != "0.50.0" {
		t.Fatalf("%s %s %v", id, version, err)
	}
	status, body = http.StatusServiceUnavailable, `{"error":{"code":"MAINTENANCE"}}`
	if _, _, err := p.Probe(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a 503: %v", err)
	}
	status, body = http.StatusOK, "<html>"
	if _, _, err := p.Probe(context.Background(), srv.URL); err == nil {
		t.Error("not JSON")
	}
	srv.Close()
	if _, _, err := p.Probe(context.Background(), srv.URL); err == nil {
		t.Error("nothing listening")
	}
}

// The origin a migration keeps.
func TestOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Vault.Example.test":       "https://vault.example.test",
		"https://vault.example.test:443/x": "https://vault.example.test",
		"https://vault.example.test:8443":  "https://vault.example.test:8443",
		"http://127.0.0.1:80":              "http://127.0.0.1",
		"http://[::1]:8686":                "http://[::1]:8686",
	} {
		if got, _, err := origin(raw); err != nil || got != want {
			t.Errorf("%s: %s %v, want %s", raw, got, err, want)
		}
	}
	for _, bad := range []string{"", "vault.example.test", "ftp://x", "https://"} {
		if _, _, err := origin(bad); err == nil {
			t.Errorf("%q", bad)
		}
	}
}

// The source's outbound allow list is the value Compose gave varlatchd:
// the running container's environment (an overlay's value, the shell's,
// .env's with its quotes and an inline comment taken as Compose takes
// them); with the service not running, docker compose config's, said
// so. Only that variable is read: an error carries no other value.
func TestComposeOutboundAllow(t *testing.T) {
	const ps, inspect, config = "docker compose ps -q varlatchd", "docker inspect --format {{json .Config.Env}} c1", "docker compose config --format json"
	stopped := func(fixture string) *scripted {
		b, err := os.ReadFile(filepath.Join("testdata", "compose-config", fixture))
		if err != nil {
			t.Fatal(err)
		}
		return &scripted{t: t, answers: map[string]Ran{ps: {}, config: {Answer: b}}}
	}
	for _, c := range []struct {
		name       string
		run        *scripted
		want       string
		fromConfig bool
	}{
		{"running", &scripted{t: t, answers: map[string]Ran{ps: {Answer: []byte("c1\n")},
			inspect: {Answer: []byte(`["VARLATCH_PUBLIC_URL=https://vault.example.test","VARLATCH_OUTBOUND_ALLOW=old.lan","VARLATCH_OUTBOUND_ALLOW=coolify.lan"]`)}}}, "coolify.lan", false},
		{"running, not set", &scripted{t: t, answers: map[string]Ran{ps: {Answer: []byte("c1\n")}, inspect: {Answer: []byte(`["VARLATCH_OUTBOUND_ALLOW="]`)}}}, "", false},
		// docker compose config's own output (testdata/compose-config:
		// outbound-docker-compose.yml, outbound-override.yml).
		{"stopped, .env's inline comment", stopped("outbound-comment.json"), "coolify.lan,10.0.0.0/8:8000", true},
		{"stopped, .env's quoted value", stopped("outbound-quoted.json"), "coolify.lan, 10.0.0.0/8:8000", true},
		{"stopped, an overlay's value", stopped("outbound-overlay.json"), "convex.lan:3210", true},
		{"stopped, the shell's value", stopped("outbound-process-env.json"), "from.shell.lan", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, fromConfig, err := (&Compose{Directory: t.TempDir(), Run: c.run}).outboundAllow(context.Background())
			if err != nil || v != c.want || fromConfig != c.fromConfig {
				t.Fatalf("%q %v %v, want %q %v", v, fromConfig, err, c.want, c.fromConfig)
			}
		})
	}
	secret := `["VARLATCH_PUBLIC_URL=https://vault.example.test",`
	for name, run := range map[string]*scripted{
		"inspect fails":    {t: t, answers: map[string]Ran{ps: {Answer: []byte("c1\n")}, inspect: {Code: 1, Said: []byte("Error: no such object")}}},
		"inspect not JSON": {t: t, answers: map[string]Ran{ps: {Answer: []byte("c1\n")}, inspect: {Answer: []byte(secret)}}},
		"config fails":     {t: t, answers: map[string]Ran{ps: {}, config: {Code: 1, Said: []byte("invalid interpolation format")}}},
		"config not JSON":  {t: t, answers: map[string]Ran{ps: {}, config: {Answer: []byte(`{"name":"p","services":` + secret)}}},
	} {
		if _, _, err := (&Compose{Directory: t.TempDir(), Run: run}).outboundAllow(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "VARLATCH_OUTBOUND_ALLOW cannot be read") || strings.Contains(err.Error(), "vault.example.test") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
