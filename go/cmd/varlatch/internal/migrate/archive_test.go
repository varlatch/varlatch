// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// tsVector is one of lib/backup's TypeScript-made archives (format 2), with
// its keys, written to files here.
type tsVector struct {
	archive, kekFile, bekFile string
	passphrase                bool
	installationID            string
}

func loadVectors(t *testing.T) []tsVector {
	t.Helper()
	raw, err := os.ReadFile("../../../../lib/backup/testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Archives []struct {
			Name string `json:"name"`
			BEK  struct {
				Kind     string `json:"kind"`
				Material string `json:"material"`
			} `json:"bek"`
			RootKEK  string          `json:"rootKek"`
			Archive  string          `json:"archive"`
			Manifest json.RawMessage `json:"manifest"`
		} `json:"archives"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var out []tsVector
	for i, a := range v.Archives {
		data, _ := base64.StdEncoding.DecodeString(a.Archive)
		vec := tsVector{archive: filepath.Join(dir, fmt.Sprintf("a%d.vltbak", i)), kekFile: filepath.Join(dir, fmt.Sprintf("kek%d", i)),
			bekFile: filepath.Join(dir, fmt.Sprintf("bek%d", i)), passphrase: a.BEK.Kind == "passphrase"}
		write(t, vec.archive, data)
		write(t, vec.kekFile, []byte(a.RootKEK+"\n"))
		write(t, vec.bekFile, []byte(a.BEK.Material+"\n"))
		var m struct {
			InstallationID string `json:"installationId"`
		}
		var text string
		if json.Unmarshal(a.Manifest, &text) == nil {
			_ = json.Unmarshal([]byte(text), &m)
		} else {
			_ = json.Unmarshal(a.Manifest, &m)
		}
		vec.installationID = m.InstallationID
		out = append(out, vec)
	}
	return out
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func randomHex(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return []byte(hex.EncodeToString(b) + "\n")
}

// call is one program a conversion ran.
type call struct {
	name  string
	args  []string
	stdin []byte
}

// fakeRunner records what runs, and answers through answer.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []call
	answer func(c call) Ran
}

func (f *fakeRunner) Run(_ context.Context, _ string, name string, args []string, stdin []byte) (Ran, error) {
	c := call{name: name, args: slices.Clone(args), stdin: bytes.Clone(stdin)}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.answer == nil {
		return Ran{}, nil
	}
	return f.answer(c), nil
}

// A conversion refuses, before any program runs and with nothing written,
// what it cannot convert: no image or one not pinned by digest, an output
// that exists, a Root KEK that is not this installation's, a wrong BEK, a
// passphrase BEK with no key file for the output, a Go archive.
func TestArchiveRefusesBeforeAnyProgram(t *testing.T) {
	vectors := loadVectors(t)
	keyVec, passVec := vectors[0], vectors[1]
	if keyVec.passphrase || !passVec.passphrase {
		t.Fatalf("vectors: %+v", vectors)
	}
	dir := t.TempDir()
	image := "ghcr.io/varlatch/varlatchd@sha256:" + strings.Repeat("ab", 32)
	wrongKEK := filepath.Join(dir, "wrong-kek")
	write(t, wrongKEK, randomHex(t))
	wrongBEK := filepath.Join(dir, "wrong-bek")
	write(t, wrongBEK, randomHex(t))
	exists := filepath.Join(dir, "exists.vltbak")
	write(t, exists, []byte("an archive already here"))
	goArchive := goFormatArchive(t, dir, keyVec)

	for _, c := range []struct {
		name string
		mod  func(*ArchiveOptions)
		want string
	}{
		{"no image", func(o *ArchiveOptions) { o.TSImage = "" }, "give --ts-image"},
		{"an image by tag", func(o *ArchiveOptions) { o.TSImage = "ghcr.io/varlatch/varlatchd:0.23.0" }, "is not pinned by digest"},
		{"an output that exists", func(o *ArchiveOptions) { o.Out = exists }, "exists: the converter writes a new archive"},
		{"another installation's Root KEK", func(o *ArchiveOptions) { o.KEKFile = wrongKEK }, "does not open the archive's canaries"},
		{"a wrong BEK", func(o *ArchiveOptions) { o.BEKFile = wrongBEK }, "Archive integrity check failed (wrong BEK, corruption, or truncation)"},
		{"a passphrase BEK, no key for the output", func(o *ArchiveOptions) {
			o.Archive, o.KEKFile, o.BEKFile = passVec.archive, passVec.kekFile, passVec.bekFile
		}, "give --out-bek-file"},
		{"a Go archive", func(o *ArchiveOptions) { o.Archive = goArchive }, "is a varlatchd archive (format 3)"},
		{"a BEK that is the Root KEK", func(o *ArchiveOptions) { o.BEKFile = keyVec.kekFile }, "must be independent of the Root KEK"},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := &fakeRunner{}
			scratch := t.TempDir()
			o := ArchiveOptions{Archive: keyVec.archive, Out: filepath.Join(dir, "out-"+strings.ReplaceAll(c.name, " ", "-")+".vltbak"),
				KEKFile: keyVec.kekFile, BEKFile: keyVec.bekFile, TSImage: image, Varlatchd: "varlatchd", Scratch: scratch, Run: run}
			c.mod(&o)
			_, err := ConvertArchive(context.Background(), o)
			var refused *ErrArchive
			if !errors.As(err, &refused) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal with %q", err, c.want)
			}
			if len(run.calls) != 0 {
				t.Errorf("ran %+v before refusing", run.calls)
			}
			if o.Out != exists {
				if _, err := os.Lstat(o.Out); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: %v", o.Out, err)
				}
			}
			if left, _ := os.ReadDir(scratch); len(left) != 0 {
				t.Errorf("left in the scratch directory: %v", left)
			}
		})
	}
}

// goFormatArchive is a format 3 archive of the vector's installation, under
// its keys.
func goFormatArchive(t *testing.T, dir string, v tsVector) string {
	t.Helper()
	kekText, _ := os.ReadFile(v.kekFile)
	root, err := envelope.ParseRootKEK(string(kekText))
	if err != nil {
		t.Fatal(err)
	}
	canary, err := envelope.NewCanary(root, v.installationID)
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "varlatch.db")
	conf := filepath.Join(dir, "configuration.json")
	write(t, db, []byte("not a database: the converter refuses before reading it"))
	write(t, conf, []byte(`{"formatVersion":1,"settings":{}}`))
	var comps []backup.Component
	for _, p := range []string{db, conf} {
		c, err := backup.Describe(filepath.Base(p), p)
		if err != nil {
			t.Fatal(err)
		}
		comps = append(comps, c)
	}
	m := backup.Manifest{FormatVersion: backup.FormatGo, ArchiveID: "00000000-0000-4000-8000-000000000077", InstallationID: v.installationID,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Release: json.RawMessage(`{"version":"0.50.0","apiMajor":1,"databaseSchema":1}`),
		RequiredKeyVersions: []int{1}, Canaries: []backup.Canary{backup.CanaryOf(1, canary)}, Components: comps}
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	bekText, _ := os.ReadFile(v.bekFile)
	key, err := backup.ParseKey(string(bekText))
	if err != nil {
		t.Fatal(err)
	}
	bek, _ := backup.KeyBEK(key)
	out := filepath.Join(dir, "go.vltbak")
	if err := backup.Seal(out, manifest, []string{db, conf}, bek, backup.SealOptions{}); err != nil {
		t.Fatal(err)
	}
	return out
}

// The conversion's programs, in order, with fakes: the isolated
// PostgreSQL with no network, the restore, the TypeScript release's
// migrate, backfill and export in its namespace (read-only, no
// capability, the run key on the export's stdin only), both removed;
// then varlatchd's import, check and backup, whose archive is the output.
// The daemon of neither line runs.
func TestArchiveConversionSequence(t *testing.T) {
	v := loadVectors(t)[0]
	dir := t.TempDir()
	out := filepath.Join(dir, "converted.vltbak")
	var exportStdin []byte
	run := &fakeRunner{}
	run.answer = func(c call) Ran {
		switch {
		case c.name == "docker" && len(c.args) > 3 && c.args[0] == "exec" && slices.Contains(c.args, "SELECT 1"):
			return Ran{Answer: []byte("1\n")}
		case c.name == "docker" && c.args[0] == "run" && slices.Contains(c.args, "export"):
			exportStdin = c.stdin
			for i, a := range c.args {
				if a == "-v" && strings.HasSuffix(c.args[i+1], ":/out") {
					write(t, filepath.Join(strings.TrimSuffix(c.args[i+1], ":/out"), "bundle.jsonl"), []byte("a bundle\n"))
				}
			}
		case c.name == "varlatchd" && slices.Equal(c.args[:3], []string{"admin", "migrate", "import"}):
			return Ran{Answer: []byte(`{"installationId":"` + v.installationID + `","tables":58,"rows":3}`)}
		case c.name == "varlatchd" && slices.Equal(c.args[:3], []string{"admin", "migrate", "check"}):
			return Ran{Answer: []byte(`{"passed":true,"checks":[{"name":"rows","passed":true,"checked":3,"failures":[],"more":0}]}`)}
		case c.name == "varlatchd" && slices.Equal(c.args[:3], []string{"admin", "backup", "run"}):
			conf, _ := os.ReadFile(c.args[len(c.args)-1])
			var data string
			for _, l := range strings.Split(string(conf), "\n") {
				if v, ok := strings.CutPrefix(l, "data_dir = "); ok {
					data = v
				}
			}
			id := "00000000-0000-4000-8000-0000000000c3"
			backups := filepath.Join(data, "backups")
			_ = os.MkdirAll(backups, 0o700)
			write(t, filepath.Join(backups, id+".vltbak"), []byte("a format 3 archive"))
			rec, _ := json.Marshal(backup.StatusRecord{ArchiveID: id, InstallationID: v.installationID, CreatedAt: "2026-11-20T12:00:00.000Z",
				Release: "0.50.0", RequiredKeyVersions: []int{1}})
			write(t, filepath.Join(backups, id+".json"), rec)
			return Ran{Answer: []byte(`{"archiveId":"` + id + `","path":"` + filepath.Join(backups, id+".vltbak") + `","bytes":18}`)}
		}
		return Ran{}
	}
	image := "ghcr.io/varlatch/varlatchd@sha256:" + strings.Repeat("cd", 32)
	res, err := ConvertArchive(context.Background(), ArchiveOptions{Archive: v.archive, Out: out, KEKFile: v.kekFile, BEKFile: v.bekFile,
		TSImage: image, Varlatchd: "varlatchd", Scratch: dir, Run: run, User: "1000:1000"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "a format 3 archive" || res.Output.Path != out || res.Source.InstallationID != v.installationID || res.Source.Format != 2 {
		t.Errorf("%+v, %q", res, got)
	}

	var steps []string
	var pg string
	var names []string
	for _, c := range run.calls {
		if c.name == "docker" {
			if c.args[0] == "exec" && slices.Contains(c.args, "SELECT 1") {
				continue
			}
			steps = append(steps, "docker "+c.args[0])
		} else {
			steps = append(steps, "varlatchd "+strings.Join(c.args[:3], " "))
		}
		if c.name == "docker" && c.args[0] == "run" {
			names = append(names, c.args[slices.Index(c.args, "--name")+1])
			if slices.Contains(c.args, "-d") {
				pg = c.args[slices.Index(c.args, "--name")+1]
				if c.args[slices.Index(c.args, "--network")+1] != "none" {
					t.Errorf("PostgreSQL has a network: %v", c.args)
				}
				continue
			}
			for _, want := range []string{"--network", "container:" + pg, "--read-only", "--cap-drop", "ALL", "--user", "1000:1000", image} {
				if !slices.Contains(c.args, want) {
					t.Errorf("%v lacks %s", c.args, want)
				}
			}
		}
		if slices.Contains(c.args, "serve") {
			t.Errorf("a daemon ran: %v", c.args)
		}
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, hex.EncodeToString(exportStdin[:8])) {
			t.Errorf("the run key in an argument: %v", c.args)
		}
	}
	want := []string{"docker run", "docker exec", "docker cp", "docker exec", "docker exec", "docker run", "docker run", "docker run", "docker rm",
		"varlatchd admin migrate import", "varlatchd admin migrate check", "varlatchd admin backup run"}
	if !slices.Equal(steps, want) {
		t.Errorf("steps\n%q\nwant\n%q", steps, want)
	}
	last := run.calls[slices.IndexFunc(run.calls, func(c call) bool { return c.name == "docker" && c.args[0] == "rm" })]
	if !slices.Equal(last.args[2:], names) || last.args[1] != "-fv" {
		t.Errorf("removed %v, started %v", last.args, names)
	}
	if len(exportStdin) != 65 || exportStdin[64] != '\n' {
		t.Errorf("the export's stdin is not a run key: %d bytes", len(exportStdin))
	}
	for _, c := range run.calls {
		if c.name == "varlatchd" && c.args[2] == "check" && !bytes.Equal(c.stdin, exportStdin) {
			t.Error("the check's run key is not the export's")
		}
	}
	// The working directory is gone: only the output is left.
	left, _ := os.ReadDir(dir)
	var leftNames []string
	for _, e := range left {
		leftNames = append(leftNames, e.Name())
	}
	if !slices.Equal(leftNames, []string{"converted.vltbak"}) {
		t.Errorf("left: %v", leftNames)
	}
}

// The converter's isolation, with Docker (per pull request in go.yml with
// VARLATCH_REQUIRE_DOCKER=1; skipped elsewhere without Docker): in the
// throwaway PostgreSQL's namespace, a process reaches PostgreSQL on the
// loopback and nothing else, by address or by name.
func TestArchiveIsolationHasNoNetwork(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil || exec.Command("docker", "info").Run() != nil {
		if os.Getenv("VARLATCH_REQUIRE_DOCKER") != "" {
			t.Fatal("VARLATCH_REQUIRE_DOCKER is set and Docker is not available")
		}
		t.Skip("no Docker")
	}
	iso := &isolation{docker: "docker", run: ExecRunner{}, pgImage: PostgresImage, user: "0:0", say: func(string) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var started []string
	defer func() { iso.removeAll(started) }()
	pg, err := iso.startPostgres(ctx, &started)
	if err != nil {
		t.Fatal(err)
	}
	// The probe runs where the TypeScript release would, with its
	// arguments; the PostgreSQL image stands in for it (it has a shell
	// and psql).
	probe := `psql -h 127.0.0.1 -U postgres -Atc 'SELECT 1' >/dev/null || { echo "no loopback"; exit 2; }
for target in 1.1.1.1/53 8.8.8.8/443 172.17.0.1/2375; do
  if timeout 5 bash -c "exec 3<>/dev/tcp/$target" 2>/dev/null; then echo "reached $target"; exit 3; fi
done
if getent hosts example.com >/dev/null 2>&1; then echo "resolved a name"; exit 4; fi
ip -o link 2>/dev/null | grep -v ' lo:' && { echo "an interface besides lo"; exit 5; }
echo isolated`
	r, err := iso.inNamespace(ctx, pg, PostgresImage, "probe", &started, nil, []string{"bash", "-c", probe}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Code != 0 || strings.TrimSpace(string(r.Answer)) != "isolated" {
		t.Fatalf("exit %d: %s %s", r.Code, r.Answer, r.Said)
	}
}

// The conversions themselves (go-step7 7.7): every archive the TypeScript
// generator made (services/varlatchd's converter-archives on
// release/0.22: format 1 and 2 of the seeded installation, and a 0.7.0
// installation's) converts with every check passing, and the format 3
// archive restores into a fresh data directory with varlatchd's own
// restore. Opt-in, with Docker, the TypeScript release's image and a
// varlatchd built from this tree (the nightly run sets
// VARLATCH_REQUIRE_CONVERTER=1):
//
//	VARLATCH_TEST_CONVERTER_DIR  the generator's directory (cases.json)
//	VARLATCH_TEST_TS_IMAGE       the TypeScript image, by digest or local ID
//	VARLATCH_TEST_VARLATCHD      the varlatchd program
func TestConvertArchives(t *testing.T) {
	dir, image, varlatchd := os.Getenv("VARLATCH_TEST_CONVERTER_DIR"), os.Getenv("VARLATCH_TEST_TS_IMAGE"), os.Getenv("VARLATCH_TEST_VARLATCHD")
	if dir == "" || image == "" || varlatchd == "" {
		if os.Getenv("VARLATCH_REQUIRE_CONVERTER") != "" {
			t.Fatal("VARLATCH_REQUIRE_CONVERTER is set without VARLATCH_TEST_CONVERTER_DIR, VARLATCH_TEST_TS_IMAGE and VARLATCH_TEST_VARLATCHD")
		}
		t.Skip("set VARLATCH_TEST_CONVERTER_DIR, VARLATCH_TEST_TS_IMAGE and VARLATCH_TEST_VARLATCHD")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name           string `json:"name"`
		Archive        string `json:"archive"`
		KEKFile        string `json:"kekFile"`
		BEKFile        string `json:"bekFile"`
		OutBEKFile     string `json:"outBekFile"`
		Format         int    `json:"format"`
		Release        string `json:"release"`
		InstallationID string `json:"installationId"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("cases.json: %v", err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			at := func(p string) string {
				if p == "" || filepath.IsAbs(p) {
					return p
				}
				return filepath.Join(dir, p)
			}
			work := t.TempDir()
			out := filepath.Join(work, "converted.vltbak")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			res, err := ConvertArchive(ctx, ArchiveOptions{Archive: at(c.Archive), Out: out, KEKFile: at(c.KEKFile), BEKFile: at(c.BEKFile),
				OutBEKFile: at(c.OutBEKFile), TSImage: image, Varlatchd: varlatchd, Scratch: work, Run: ExecRunner{},
				Say: func(s string) { t.Log(s) }})
			if err != nil {
				t.Fatal(err)
			}
			if res.Source.Format != c.Format || res.Source.Release != c.Release || res.Source.InstallationID != c.InstallationID || res.Copy.InstallationID != c.InstallationID {
				t.Errorf("%+v", res)
			}
			if !res.Checks.Passed || len(res.Checks.Checks) < 5 {
				t.Errorf("checks %+v", res.Checks)
			}
			for _, ch := range res.Checks.Checks {
				if !ch.Passed {
					t.Errorf("check %s failed", ch.Name)
				}
			}
			// The format 3 archive restores with varlatchd's own restore.
			data := filepath.Join(work, "restored")
			if err := os.Mkdir(data, 0o700); err != nil {
				t.Fatal(err)
			}
			outBEK := at(c.OutBEKFile)
			if outBEK == "" {
				outBEK = at(c.BEKFile)
			}
			kek, _ := filepath.Abs(at(c.KEKFile))
			conf := filepath.Join(work, "restore.conf")
			write(t, conf, []byte(fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_interval = off\n", data, kek)))
			cmd := exec.CommandContext(ctx, varlatchd, "admin", "backup", "restore", "--in", out, "--backup-key-file", outBEK, "--config", conf)
			if said, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("varlatchd admin backup restore: %v\n%s", err, said)
			}
			if left, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=varlatch.convert").Output(); len(bytes.TrimSpace(left)) != 0 {
				t.Errorf("containers left: %s", left)
			}
		})
	}
}
