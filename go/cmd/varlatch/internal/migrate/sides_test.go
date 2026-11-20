// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	run := &scripted{t: t, answers: map[string]Ran{
		exec + "status":                     {Answer: []byte(`{"daemon":true,"gate":{"kind":"migration","id":"g1","phase":"frozen"}}` + "\n")},
		exec + "barrier --drain-seconds 90": {Answer: []byte(`{"gate":{"kind":"migration","id":"g1"},"drained":{"ms":1200,"waitedFor":{}},"frozen":{"auditPosition":"46","at":"2026-11-20T12:00:00.000Z","snapshot":"00000003-0000001B-1"}}` + "\n")},
		exec + "export":                     {Answer: []byte(`{"frozenPoint":{},"bundle":{}}` + "\n")},
		exec + "release --id g1":            {Answer: []byte(`{"released":true}`)},
		exec + "mark-migrated-out --id g1":  {Answer: []byte(`{"gate":{"kind":"migrated-out"}}`)},
		"varlatch-ts admin backup create":   {Answer: []byte("Archive created: " + dir + "/backups/" + archive + ".vltbak (" + archive + ")\nUpload completed to offsite; remote retrieval has not been verified.\n")},
		"varlatch-ts admin backup verify":   {Answer: []byte(`{"archiveId":"` + archive + `","integrity":true,"compatibility":true,"keyMatch":true,"message":"checks passed"}` + "\n")},
	}}
	c := &Compose{Directory: dir, Run: run, BEKFile: "/keys/bek", Destination: "offsite", ReadCredentialsFile: "/keys/read.json"}
	// The export's bundle appears where its --out names it, in backups/.
	exportPath := func(key string) string {
		i := strings.Index(key, "/backups/")
		name := key[i+len("/backups/"):]
		return filepath.Join(dir, "backups", strings.Fields(name)[0])
	}
	runWithBundle := &bundleRunner{scripted: run, at: exportPath}
	c.Run = runWithBundle
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
	var exportKey string
	for _, r := range run.ran {
		if strings.HasPrefix(r, exec+"export") {
			exportKey = r
		}
	}
	if !strings.HasSuffix(exportKey, " --digests --dry-run") || !bytes.Equal(run.stdins[exportKey], RunKeyText(runKey)) {
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

// bundleRunner leaves the export's bundle where its --out names it.
type bundleRunner struct {
	*scripted
	at func(string) string
}

func (b *bundleRunner) Run(ctx context.Context, dir, name string, args []string, stdin []byte) (Ran, error) {
	r, err := b.scripted.Run(ctx, dir, name, args, stdin)
	key := name + " " + strings.Join(args, " ")
	if strings.Contains(key, "migration export --out ") {
		_ = os.WriteFile(b.at(key), []byte("bundle"), 0o600)
	}
	return r, err
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
		pre + "state --config": {Answer: []byte(`{"journal":{"format":1,"id":"mig_cccccccccccccccccccccccccc","phase":"preflight"},"database":false,"dataDir":"/var/lib/varlatch"}`)},
		pre + "state --write":  {Answer: []byte(`{}`)},
		pre + "keys":           {Answer: []byte(`{"rootKek":"written","bek":"unchanged"}`)},
		pre + "import":         {Answer: []byte(`{"installationId":"inst_x","direction":"forward","tables":58,"rows":902,"perTable":{},"sessionsEnded":1,"credentialsRevoked":1,"migratedPosition":48}`)},
		pre + "check":          {Code: 1, Answer: []byte(report)},
		pre + "discard --id":   {Answer: []byte(`{"removed":["varlatch.db"]}`)},
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
