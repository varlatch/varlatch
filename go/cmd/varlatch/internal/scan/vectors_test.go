// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors of testdata/vectors/scan.json (recorded by
// apps/cli/test/go-vectors-scan.test.ts from scan.ts, scanSources.ts and
// scanCommand.ts). internal/cli's tests replay the args and hooks.

func loadVectors(t *testing.T) jsjson.Object {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/scan.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(jsjson.Object)
}

func str(v any) string        { s, _ := v.(string); return s }
func num(v any) int64         { f, _ := v.(float64); return int64(f) }
func list(v any) []any        { a, _ := v.([]any); return a }
func obj(v any) jsjson.Object { o, _ := v.(jsjson.Object); return o }

func json(v any) string { return string(jsjson.Stringify(v)) }

func secretsOf(v any) []Secret {
	var out []Secret
	for _, s := range list(v) {
		o := obj(s)
		out = append(out, Secret{Item: str(o.Value("item")), VersionID: str(o.Value("versionId")), Retiring: o.Value("retiring") == true, Value: str(o.Value("value"))})
	}
	return out
}

func limitsOf(v any, fallback Limits) Limits {
	o, ok := v.(jsjson.Object)
	if !ok {
		return fallback
	}
	return Limits{MaxFileSize: num(o.Value("maxFileSize")), MaxTotalSize: num(o.Value("maxTotalSize"))}
}

func baselineOf(v any) []BaselineEntry {
	var out []BaselineEntry
	for _, e := range list(v) {
		o := obj(e)
		out = append(out, BaselineEntry{str(o.Value("path")), str(o.Value("item")), str(o.Value("versionId"))})
	}
	return out
}

func strings_(v any) []string {
	out := []string{}
	for _, s := range list(v) {
		out = append(out, str(s))
	}
	return out
}

// engineCase is a case's files through an engine, each pushed in chunks of
// size (0: whole).
func engineCase(c jsjson.Object, chunk int) *Report {
	e := NewEngine(secretsOf(c.Value("secrets")), limitsOf(c.Value("limits"), DefaultLimits), baselineOf(c.Value("baseline")))
	for _, f := range list(c.Value("files")) {
		pair := list(f)
		data, _ := base64.StdEncoding.DecodeString(str(pair[1]))
		path := str(pair[0])
		if !e.Admit(path, int64(len(data)), 0) {
			continue
		}
		scan := e.Begin(path)
		size := chunk
		if size == 0 {
			size = max(1, len(data))
		}
		ok := true
		for at := 0; at < len(data) && ok; at += size {
			ok = scan.Push(data[at:min(at+size, len(data))])
		}
		if ok {
			scan.End()
		} else {
			scan.Fail("grew past the per-file bound while being read")
		}
	}
	return e.Result()
}

// TestEngineVectors: each case's report, as --json holds it, its human
// lines in both modes, its notices, exit status and baseline, as
// TypeScript gives them; and the same report for every chunk size up to
// 97 bytes.
func TestEngineVectors(t *testing.T) {
	cases := list(loadVectors(t).Value("engine"))
	if len(cases) < 30 {
		t.Fatalf("only %d engine cases", len(cases))
	}
	for _, raw := range cases {
		c := obj(raw)
		t.Run(str(c.Value("id")), func(t *testing.T) {
			want := obj(c.Value("expect"))
			report := engineCase(c, 0)
			if got := json(report.JSON()); got != json(want.Value("report")) {
				t.Fatalf("report\n got %s\nwant %s", got, json(want.Value("report")))
			}
			if got := report.ExitCode(); int64(got) != num(want.Value("exitCode")) {
				t.Errorf("exit %d, want %d", got, num(want.Value("exitCode")))
			}
			notices := report.Notices()
			if notices == nil {
				notices = []string{}
			}
			if !slices.Equal(notices, strings_(want.Value("notices"))) {
				t.Errorf("notices %q, want %q", notices, strings_(want.Value("notices")))
			}
			human := obj(want.Value("human"))
			for _, mode := range []string{"paths", "staged"} {
				if got := report.Human("production", mode); !slices.Equal(got, strings_(human.Value(mode))) {
					t.Errorf("%s lines\n got %q\nwant %q", mode, got, strings_(human.Value(mode)))
				}
			}
			if got := FormatBaseline(report.BaselineEntries()); got != str(want.Value("baseline")) {
				t.Errorf("baseline\n got %q\nwant %q", got, str(want.Value("baseline")))
			}
			longest := 0
			for _, f := range list(c.Value("files")) {
				data, _ := base64.StdEncoding.DecodeString(str(list(f)[1]))
				longest = max(longest, len(data))
			}
			whole := json(report.JSON())
			for chunk := 1; chunk <= min(longest, 97); chunk++ {
				if got := json(engineCase(c, chunk).JSON()); got != whole {
					t.Fatalf("chunks of %d bytes give another report:\n%s", chunk, got)
				}
			}
		})
	}
}

// TestPureVectors: parseSize, formatBytes, parseBaseline and
// formatBaseline. A baseline that is not JSON is compared by its start
// (what follows is V8's wording; go/README.md, `baseline-json-syntax`).
func TestPureVectors(t *testing.T) {
	doc := loadVectors(t)
	for _, raw := range list(doc.Value("sizes")) {
		c := obj(raw)
		got, ok := ParseSize(str(c.Value("text")))
		want, wantOK := c.Value("size").(float64)
		if ok != wantOK || ok && got != int64(want) {
			t.Errorf("ParseSize(%q) = %d, %v; want %v", str(c.Value("text")), got, ok, c.Value("size"))
		}
	}
	for _, raw := range list(doc.Value("bytes")) {
		c := obj(raw)
		if got := FormatBytes(num(c.Value("n"))); got != str(c.Value("text")) {
			t.Errorf("FormatBytes(%d) = %q, want %q", num(c.Value("n")), got, str(c.Value("text")))
		}
	}
	for _, raw := range list(doc.Value("baselines")) {
		c := obj(raw)
		text, _ := base64.StdEncoding.DecodeString(str(c.Value("text")))
		entries, err := ParseBaseline(text)
		if want, isError := c.Get("error"); isError {
			switch {
			case err == nil:
				t.Errorf("ParseBaseline(%q) gave %v, want %q", text, entries, want)
			case c.Value("syntax") == true && !strings.HasPrefix(err.Error(), str(want)):
				t.Errorf("ParseBaseline(%q): %q, want it to start %q", text, err, want)
			case c.Value("syntax") != true && err.Error() != str(want):
				t.Errorf("ParseBaseline(%q): %q, want %q", text, err, want)
			}
			continue
		}
		if err != nil || !slices.Equal(entries, baselineOf(c.Value("entries"))) {
			t.Errorf("ParseBaseline(%q) = %v, %v; want %v", text, entries, err, c.Value("entries"))
		}
	}
	for _, raw := range list(doc.Value("formatBaselines")) {
		c := obj(raw)
		if got := FormatBaseline(baselineOf(c.Value("entries"))); got != str(c.Value("text")) {
			t.Errorf("FormatBaseline\n got %q\nwant %q", got, str(c.Value("text")))
		}
	}
}

// gitEnv is the trees' Git environment, as the recorder's.
func gitEnv() []string {
	return append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	if out, err := cmd.CombinedOutput(); err != nil && args[0] != "merge" {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

// buildTree makes a case's tree as the recorder does.
func buildTree(t *testing.T, dir string, tree jsjson.Object) {
	t.Helper()
	at := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(files jsjson.Object) {
		for _, m := range files {
			must(os.MkdirAll(filepath.Dir(at(m.Key)), 0o755))
			must(os.WriteFile(at(m.Key), []byte(str(m.Value)), 0o644))
		}
	}
	for _, r := range strings_(tree.Value("repos")) {
		must(os.MkdirAll(at(r), 0o755))
		runGit(t, at(r), "init", "-q", "-b", "main")
	}
	write(obj(tree.Value("files")))
	for _, raw := range list(tree.Value("rawFiles")) {
		pair := list(raw)
		name, _ := base64.StdEncoding.DecodeString(str(pair[0]))
		if slash := strings.LastIndexByte(string(name), '/'); slash >= 0 {
			must(os.MkdirAll(dir+"/"+string(name[:slash]), 0o755))
		}
		must(os.WriteFile(dir+"/"+string(name), []byte(str(pair[1])), 0o644))
	}
	for _, m := range obj(tree.Value("links")) {
		must(os.MkdirAll(filepath.Dir(at(m.Key)), 0o755))
		must(os.Symlink(str(m.Value), at(m.Key)))
	}
	for _, raw := range list(tree.Value("steps")) {
		step := obj(raw)
		switch {
		case step.Value("git") != nil:
			runGit(t, dir, strings_(step.Value("git"))...)
		case step.Value("write") != nil:
			write(obj(step.Value("write")))
		default:
			for _, p := range strings_(step.Value("remove")) {
				must(os.RemoveAll(at(p)))
			}
		}
	}
	for _, m := range obj(tree.Value("modes")) {
		must(os.Chmod(at(m.Key), os.FileMode(num(m.Value))))
	}
}

// differences are the accepted differences a source case can name
// (go/README.md): each turns the TypeScript recording into Go's answer.
var differences = map[string]func(report jsjson.Object, c jsjson.Object, limits Limits) jsjson.Object{
	// --staged: Go admits each staged file with the sizes of the files
	// admitted before it counted, so --max-total-size bounds the staged
	// content as a whole; TypeScript checks each file against the bound
	// alone (step 5 defect 34, not a security defect). The files
	// TypeScript admitted and Go does not are taken out of the report
	// (their findings, the files and bytes scanned) and named as over the
	// total size bound, in
	// the listing's order, where the admissions' entries stand. (A case
	// names this difference only when no file it takes out ends with the
	// start of a value, which the recording does not count per file.)
	"scan-staged-total": func(report, c jsjson.Object, limits Limits) jsjson.Object {
		listing := obj(c.Value("listing"))
		before := int(num(listing.Value("notScanned")))
		recorded := list(report.Value("notScanned"))
		var admissions []any
		dropped := map[string]bool{}
		files, bytes := num(report.Value("filesScanned")), num(report.Value("bytesScanned"))
		refusedByTS := 0
		total := int64(0)
		for _, raw := range list(listing.Value("files")) {
			f := obj(raw)
			path, size := str(f.Value("path")), num(f.Value("size"))
			tsAdmits := size <= limits.MaxFileSize && size <= limits.MaxTotalSize
			if !tsAdmits {
				refusedByTS++
			}
			switch {
			case size > limits.MaxFileSize:
				admissions = append(admissions, jsjson.Object{{Key: "path", Value: path}, {Key: "reason", Value: "larger than the per-file bound (" + FormatBytes(size) + " > " + FormatBytes(limits.MaxFileSize) + ")"}})
			case total+size > limits.MaxTotalSize:
				admissions = append(admissions, jsjson.Object{{Key: "path", Value: path}, {Key: "reason", Value: "over the total size bound of " + FormatBytes(limits.MaxTotalSize)}})
				if tsAdmits {
					dropped[path] = true
					files--
					bytes -= size
				}
			default:
				total += size
			}
		}
		notScanned := append(append(append([]any{}, recorded[:before]...), admissions...), recorded[before+refusedByTS:]...)
		keep := func(key string) []any {
			out := []any{}
			for _, x := range list(report.Value(key)) {
				if !dropped[str(obj(x).Value("path"))] {
					out = append(out, x)
				}
			}
			return out
		}
		out := slices.Clone(report)
		out = out.Set("findings", keep("findings")).Set("unlisted", keep("unlisted")).Set("allowed", keep("allowed")).Set("notScanned", notScanned)
		return out.Set("filesScanned", float64(files)).Set("bytesScanned", float64(bytes))
	},
}

// TestSourceVectors: each tree listed and scanned as --staged or as paths
// against the vectors' values, with the report or the error TypeScript
// gives (through a case's accepted difference). Skipped where the platform
// cannot hold the case: modes that do not hold for root, names that are
// not UTF-8 (Linux only), and on Windows every tree (its paths and Git's
// are compared from step 5.9).
func TestSourceVectors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("needs git")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows expectations of the trees are recorded in step 5.9")
	}
	doc := loadVectors(t)
	secrets := secretsOf(doc.Value("secrets"))
	defaults := limitsOf(doc.Value("defaultLimits"), DefaultLimits)
	cases := list(doc.Value("sources"))
	if len(cases) < 25 {
		t.Fatalf("only %d source cases", len(cases))
	}
	for _, raw := range cases {
		c := obj(raw)
		t.Run(str(c.Value("id")), func(t *testing.T) {
			switch {
			case c.Value("notRoot") == true && os.Geteuid() == 0:
				t.Skip("modes do not hold for root")
			case c.Value("rawNames") == true && runtime.GOOS != "linux":
				t.Skip("names that are not UTF-8 need Linux")
			}
			parent, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, "c")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			buildTree(t, dir, obj(c.Value("tree")))
			t.Cleanup(func() { _ = exec.Command("chmod", "-R", "u+rwx", dir).Run() })
			git := Git{Env: append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CEILING_DIRECTORIES="+parent)}
			cwd, project := filepath.Join(dir, str(c.Value("cwd"))), filepath.Join(dir, str(c.Value("project")))
			limits := limitsOf(c.Value("limits"), defaults)
			engine := NewEngine(secrets, limits, nil)
			unfill := func(s string) string { return strings.ReplaceAll(s, dir, "{{dir}}") }
			want := obj(c.Value("expect"))
			var scanErr error
			if c.Value("scan") == "staged" {
				var listing *StagedListing
				if listing, scanErr = ListStaged(git, cwd, project); scanErr == nil {
					for _, n := range listing.NotScanned {
						engine.NotScanned(n.Path, n.Reason)
					}
					scanErr = ScanStaged(engine, git, listing)
				}
			} else {
				var listing *PathListing
				if listing, scanErr = ListPaths(strings_(c.Value("scan")), cwd, project); scanErr == nil {
					for _, n := range listing.NotScanned {
						engine.NotScanned(n.Path, n.Reason)
					}
					ScanPaths(engine, listing)
				}
			}
			if wantErr, isError := want.Get("error"); isError {
				e, ok := scanErr.(*SourceError)
				if !ok || unfill(e.Message) != str(wantErr) {
					t.Fatalf("error %v, want %q", scanErr, wantErr)
				}
				return
			}
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			expected := obj(want.Value("report"))
			if name := str(c.Value("difference")); name != "" {
				expected = differences[name](expected, c, limits)
			}
			if got := unfill(json(engine.Result().JSON())); got != json(expected) {
				t.Errorf("report\n got %s\nwant %s", got, json(expected))
			}
		})
	}
}

// TestTheStagedTotalDifferenceApplies: the scan-staged-total case's
// recording is not what Go gives, so the difference does something: with
// --staged, the files past the total bound are not read.
func TestTheStagedTotalDifferenceApplies(t *testing.T) {
	for _, raw := range list(loadVectors(t).Value("sources")) {
		c := obj(raw)
		if str(c.Value("difference")) != "scan-staged-total" {
			continue
		}
		recorded := obj(obj(c.Value("expect")).Value("report"))
		applied := differences["scan-staged-total"](recorded, c, limitsOf(c.Value("limits"), DefaultLimits))
		if json(recorded) == json(applied) || !strings.Contains(json(applied.Value("notScanned")), "over the total size bound") {
			t.Fatalf("the difference changes nothing:\n%s", json(applied))
		}
		return
	}
	t.Fatal("no case names scan-staged-total")
}
