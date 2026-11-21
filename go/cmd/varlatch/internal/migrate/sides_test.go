// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
func (s *scripted) Stream(ctx context.Context, dir, name string, args []string, stdin io.Reader, stdout io.Writer) (Ran, error) {
	var in []byte
	if stdin != nil {
		var err error
		if in, err = io.ReadAll(stdin); err != nil {
			return Ran{}, err
		}
	}
	r, err := s.Run(ctx, dir, name, args, in)
	if err != nil {
		return Ran{}, err
	}
	if _, err := stdout.Write(r.Answer); err != nil {
		return Ran{}, err
	}
	return Ran{Said: r.Said, Code: r.Code}, nil
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
	if err != nil || info.Release != "0.23.0" || info.Digest != digest || info.Image != "ghcr.io/varlatch/varlatchd:0.23.0" {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := (&Compose{Directory: t.TempDir(), Run: run}).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "no docker-compose.yml") {
		t.Errorf("no Compose file: %v", err)
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
	cmd := "docker compose --profile varlatch-rollback run --rm -T varlatch-reverse-import node dist/cli.js admin migration import --in -"
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
	run := &scripted{t: t, answers: map[string]Ran{"docker compose": {}}}
	c := &Compose{Directory: dir, Run: run}
	ing, err := c.Ingress(context.Background())
	if err != nil || ing.PublicURL != "" || ing.Caddy || ing.WebAddress != "127.0.0.1:8787" {
		t.Fatalf("no .env: %+v %v", ing, err)
	}
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("# the installation\nVARLATCH_PUBLIC_URL=\"https://vault.example.test\"\n"+
		"COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\nVARLATCH_WEB_PORT=9000\nBIND_ADDRESS=0.0.0.0\n"), 0o600)
	ing, err = c.Ingress(context.Background())
	if err != nil || ing.PublicURL != "https://vault.example.test" || !ing.Caddy || ing.WebAddress != "0.0.0.0:9000" {
		t.Fatalf(".env: %+v %v", ing, err)
	}
	ctx := context.Background()
	for _, c2 := range []struct {
		kind Ingress
		want []string
	}{{Public, []string{"docker compose stop caddy", "docker compose start caddy"}}, {Proxy, []string{"docker compose stop varlatch-web", "docker compose start varlatch-web"}}} {
		run.ran = nil
		if err := c.StopIngress(ctx, c2.kind); err != nil {
			t.Fatal(err)
		}
		if err := c.StartIngress(ctx, c2.kind); err != nil {
			t.Fatal(err)
		}
		if strings.Join(run.ran, "|") != strings.Join(c2.want, "|") {
			t.Fatalf("%s: %q", c2.kind, run.ran)
		}
	}
	if err := c.StopIngress(ctx, Coolify); err == nil {
		t.Fatal("the Coolify shape has nothing here to stop")
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
// /v1/meta's installationId and serverVersion; anything else an error.
func TestHTTPProber(t *testing.T) {
	status, body := http.StatusOK, `{"apiMajor":1,"serverVersion":"0.50.0","capabilities":[],"installationId":"inst_x"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/meta" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
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
