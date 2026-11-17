// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The context vectors (../../testdata/vectors/context.json), written by
// apps/cli/test/go-vectors-context.test.ts from packages/context itself:
// varlatch.toml as loadRepoConfig reads it, and the credential store,
// settings and local state as the TypeScript CLI reads and writes them
// (internal docs/design/go-cli.md, decision 11). The Go store must give
// the same results and leave the same files, byte for byte and mode for
// mode, so a sign-in made by either CLI works with the other.

const contextVectors = "../../testdata/vectors/context.json"

func loadVectors(t *testing.T) jsjson.Object {
	t.Helper()
	data, err := os.ReadFile(contextVectors)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return v.(jsjson.Object)
}

func same(a, b any) bool { return string(jsjson.Stringify(a)) == string(jsjson.Stringify(b)) }

func TestRepoConfigVectors(t *testing.T) {
	cases := loadVectors(t).Value("repoConfig").([]any)
	if len(cases) < 200 {
		t.Fatalf("only %d varlatch.toml vectors", len(cases))
	}
	dir := t.TempDir()
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		name, text := c.Value("name").(string), c.Value("toml").(string)
		if err := os.WriteFile(filepath.Join(dir, RepoConfigFile), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		want := c.Value("result").(jsjson.Object)
		config, err := LoadRepoConfig(dir)
		if message, ok := want.Get("error"); ok {
			got, isContext := IsContextError(err)
			if !isContext || got != message {
				t.Errorf("%s: error %v, want %q", name, err, message)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v, want %s", name, err, jsjson.Stringify(want.Value("config")))
			continue
		}
		got := jsjson.Object{{Key: "organization", Value: config.Organization}, {Key: "project", Value: config.Project}}
		if config.Server != "" {
			got = append(got, jsjson.Member{Key: "server", Value: config.Server})
		}
		if config.DefaultEnvironment != "" {
			got = append(got, jsjson.Member{Key: "defaultEnvironment", Value: config.DefaultEnvironment})
		}
		if !same(got, want.Value("config")) {
			t.Errorf("%s: %s, want %s", name, jsjson.Stringify(got), jsjson.Stringify(want.Value("config")))
		}
	}
}

type mapEnv map[string]string

func (m mapEnv) LookupEnv(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

func TestStoreVectors(t *testing.T) {
	for _, raw := range loadVectors(t).Value("store").([]any) {
		c := raw.(jsjson.Object)
		name := c.Value("name").(string)
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if files, ok := c.Value("files").(jsjson.Object); ok {
				for _, f := range files {
					path := filepath.Join(dir, filepath.FromSlash(f.Key))
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(f.Value.(string)), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			env := mapEnv{"XDG_CONFIG_HOME": filepath.Join(dir, "xdg"), "HOME": filepath.Join(dir, "home"), "USERPROFILE": filepath.Join(dir, "home")}
			agentRun, _ := c.Value("agentRun").(string)
			if agentRun != "default" {
				env["VARLATCH_CONFIG_DIR"] = filepath.Join(dir, "config")
			}
			if agentRun != "" {
				env["VARLATCH_AGENT_RUN"] = "run_1"
			}
			repo := filepath.Join(dir, "repo")
			results := c.Value("results").([]any)
			for i, rawOp := range c.Value("ops").([]any) {
				op := rawOp.(jsjson.Object)
				kind := op.Value("op").(string)
				server, _ := op.Value("server").(string)
				var got any
				var err error
				switch kind {
				case "list":
					var list []Entry
					list, err = ListCredentials(env)
					entries := []any{}
					for _, e := range list {
						entries = append(entries, jsjson.Object{{Key: "server", Value: e.Server}, {Key: "credential", Value: e.Credential}})
					}
					got = entries
				case "load":
					got, err = LoadCredential(server, env)
				case "save":
					err = SaveCredential(server, op.Value("credential").(jsjson.Object), env)
				case "delete":
					got, err = DeleteCredential(server, env)
				case "defaultServer":
					var def string
					def, err = DefaultServer(env)
					if def != "" {
						got = def
					}
				case "setDefault":
					s, set := op.Value("server").(string)
					err = SetDefaultServer(s, set, env)
				case "rememberIfUnset":
					got, err = RememberServerIfUnset(server, env)
				case "loadLocal":
					got = LoadLocalState(repo)
				case "saveLocal":
					err = SaveLocalState(repo, op.Value("state").(jsjson.Object))
				default:
					t.Fatalf("op %s", kind)
				}
				want := results[i].(jsjson.Object)
				if wantErr, ok := want.Value("error").(jsjson.Object); ok {
					switch wantErr.Value("name") {
					case "ContextError":
						if message, ok := IsContextError(err); !ok || message != wantErr.Value("message") {
							t.Errorf("op %d (%s): error %v, want ContextError %q", i, kind, err, wantErr.Value("message"))
						}
					case "TypeError":
						if !IsTypeError(err) {
							t.Errorf("op %d (%s): error %v, want a TypeError", i, kind, err)
						}
					}
					continue
				}
				if err != nil {
					t.Errorf("op %d (%s): %v", i, kind, err)
					continue
				}
				if !same(got, want.Value("value")) {
					t.Errorf("op %d (%s): %s, want %s", i, kind, jsjson.Stringify(got), jsjson.Stringify(want.Value("value")))
				}
			}
			after := map[string][2]string{}
			_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				info, _ := d.Info()
				data, _ := os.ReadFile(path)
				rel, _ := filepath.Rel(dir, path)
				after[filepath.ToSlash(rel)] = [2]string{modeString(info.Mode()), string(data)}
				return nil
			})
			want := c.Value("after").(jsjson.Object)
			for _, f := range want {
				w := f.Value.(jsjson.Object)
				g, ok := after[f.Key]
				if !ok {
					t.Errorf("%s was not left", f.Key)
					continue
				}
				if g[1] != w.Value("content") {
					t.Errorf("%s holds %q, want %q", f.Key, g[1], w.Value("content"))
				}
				if runtime.GOOS != "windows" && g[0] != w.Value("mode") {
					t.Errorf("%s has mode %s, want %s", f.Key, g[0], w.Value("mode"))
				}
				delete(after, f.Key)
			}
			for name := range after {
				t.Errorf("%s was left, which TypeScript does not leave", name)
			}
		})
	}
}

func modeString(m fs.FileMode) string {
	const digits = "01234567"
	p := m.Perm()
	return string([]byte{'0', digits[p>>6&7], digits[p>>3&7], digits[p&7]})
}
