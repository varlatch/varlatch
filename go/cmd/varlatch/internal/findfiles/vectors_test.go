// SPDX-License-Identifier: Apache-2.0

package findfiles

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

// envMap is an environment of the test's own.
type envMap map[string]string

func (m envMap) LookupEnv(key string) (string, bool) { v, ok := m[key]; return v, ok }

// TestVectors replays testdata/vectors/findfiles.json (written by
// apps/cli/test/go-vectors-findfiles.test.ts from findFiles.ts's
// findCopies): each tree built as the recorder builds it, searched, and
// the report compared as `--json` and the human lines give it, or the
// error. Skipped where the platform cannot hold the case: names that are
// not UTF-8 (Linux only), names Windows does not allow, modes that do not
// hold for root, and on Windows links and absolute paths in files or
// answers (their separators are POSIX ones, step 5.9).
func TestVectors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("the cases need git")
	}
	data, err := os.ReadFile("../../testdata/vectors/findfiles.json")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	file := parsed.(jsjson.Object)
	cases := file.Value("cases").([]any)
	if len(cases) < 70 {
		t.Fatalf("only %d cases", len(cases))
	}
	defaults := file.Value("defaultLimits").(jsjson.Object)
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		id := c.Value("id").(string)
		t.Run(id, func(t *testing.T) {
			if why := platformSkip(c); why != "" {
				t.Skip(why)
			}
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			build(t, dir, c.Value("tree").(jsjson.Object))
			t.Cleanup(func() { _ = exec.Command("chmod", "-R", "u+rwx", dir).Run() })
			env := envMap{"HOME": filepath.Join(dir, "home")}
			if e, ok := c.Value("env").(jsjson.Object); ok {
				for _, m := range e {
					env[m.Key] = strings.ReplaceAll(m.Value.(string), "{{dir}}", dir)
				}
			}
			if runtime.GOOS == "windows" {
				// The recorder's home is HOME; on Windows, os.homedir() (and
				// clientctx.HomeDir) reads USERPROFILE.
				env["USERPROFILE"] = env["HOME"]
			}
			limits := limitsOf(defaults)
			if l, ok := c.Value("limits").(jsjson.Object); ok {
				limits = limitsOf(l)
			}
			// The directory as it is, and as a JSON string holds it (its
			// backslashes doubled on Windows).
			quoted := strings.Trim(string(jsjson.Stringify(dir)), `"`)
			unfill := func(s string) string {
				return strings.ReplaceAll(strings.ReplaceAll(s, dir, "{{dir}}"), quoted, "{{dir}}")
			}
			expect := c.Value("expect").(jsjson.Object)
			report, err := Find(env, c.Value("dir").(string), dir, limits)
			if want, isError := expect.Get("error"); isError {
				e, ok := err.(*Error)
				if !ok || unfill(e.Message) != want {
					t.Fatalf("error %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := report.ExitCode(), int(expect.Value("exitCode").(float64)); got != want {
				t.Errorf("exit code %d, want %d", got, want)
			}
			if got, want := unfill(string(jsjson.Stringify(report.JSON()))), string(jsjson.Stringify(expect.Value("json"))); got != want {
				t.Errorf("json\n got %s\nwant %s", got, want)
			}
			var want []string
			for _, l := range expect.Value("human").([]any) {
				want = append(want, l.(string))
			}
			got := report.Human(limits)
			for i := range got {
				got[i] = unfill(got[i])
			}
			if !slices.Equal(got, want) {
				t.Errorf("human\n got %q\nwant %q", got, want)
			}
		})
	}
}

func limitsOf(o jsjson.Object) Limits {
	return Limits{MaxEntries: int(o.Value("maxEntries").(float64)), MaxDepth: int(o.Value("maxDepth").(float64))}
}

// platformSkip is why this platform cannot hold the case, or "".
func platformSkip(c jsjson.Object) string {
	switch {
	case c.Value("notRoot") == true && os.Geteuid() == 0:
		return "modes do not hold for root"
	case c.Value("rawNames") == true && runtime.GOOS != "linux":
		return "names that are not UTF-8 need Linux"
	case c.Value("posixNames") == true && runtime.GOOS == "windows":
		return "names Windows does not allow"
	}
	if runtime.GOOS == "windows" {
		tree := c.Value("tree").(jsjson.Object)
		for _, k := range []string{"links", "hardLinks", "modes"} {
			if _, ok := tree.Get(k); ok {
				return "links and modes are POSIX ones here"
			}
		}
		text := string(jsjson.Stringify(c))
		if strings.Contains(text, "{{dir}}/") || strings.Contains(text, `{{dir}}\\`) {
			return "path separators: Windows expectations not recorded yet (step 5.9)"
		}
	}
	return ""
}

// build makes a case's tree as the recorder does.
func build(t *testing.T, dir string, tree jsjson.Object) {
	t.Helper()
	fill := func(s string) string { return strings.ReplaceAll(s, "{{dir}}", dir) }
	at := func(rel string) string { return filepath.Join(dir, filepath.FromSlash(rel)) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(at("home"), 0o755))
	list := func(key string) []string {
		var out []string
		if a, ok := tree.Value(key).([]any); ok {
			for _, x := range a {
				out = append(out, x.(string))
			}
		}
		return out
	}
	members := func(key string) jsjson.Object {
		o, _ := tree.Value(key).(jsjson.Object)
		return o
	}
	for _, r := range list("repos") {
		must(os.MkdirAll(at(r), 0o755))
		git := exec.Command("git", "init", "-q")
		git.Dir = at(r)
		git.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := git.CombinedOutput(); err != nil {
			t.Fatalf("git init: %v %s", err, out)
		}
	}
	for _, d := range list("dirs") {
		must(os.MkdirAll(at(d), 0o755))
	}
	for _, m := range members("files") {
		must(os.MkdirAll(filepath.Dir(at(m.Key)), 0o755))
		must(os.WriteFile(at(m.Key), []byte(fill(m.Value.(string))), 0o644))
	}
	for _, raw := range list("rawFiles") {
		b, err := base64.StdEncoding.DecodeString(raw)
		must(err)
		name := string(b)
		if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
			must(os.MkdirAll(dir+"/"+name[:slash], 0o755))
		}
		must(os.WriteFile(dir+"/"+name, nil, 0o644))
	}
	for _, m := range members("links") {
		must(os.MkdirAll(filepath.Dir(at(m.Key)), 0o755))
		_ = os.Remove(at(m.Key)) // in place of what git init wrote there
		must(os.Symlink(fill(m.Value.(string)), at(m.Key)))
	}
	for _, m := range members("hardLinks") {
		_ = os.Remove(at(m.Key))
		must(os.Link(at(m.Value.(string)), at(m.Key)))
	}
	for _, r := range list("remove") {
		must(os.RemoveAll(at(r)))
	}
	for _, m := range members("modes") {
		must(os.Chmod(at(m.Key), os.FileMode(m.Value.(float64))))
	}
}
