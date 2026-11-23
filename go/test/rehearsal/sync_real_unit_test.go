// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// TestSyncReal: VL_RH_SYNC=real's parts that need no platform: the input
// refusals, the throwaway rules, the redaction of the tokens from every
// error, and the cleanup by the run's exact names.
func TestSyncReal(t *testing.T) {
	dir := t.TempDir()
	file := func(name, body string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	token := file("gh-token", "x-test-gh\n", 0o600)
	cool := file("cool-token", "x-test-cool\n", 0o600)
	open := file("open-token", "x-test\n", 0o644)
	twoLines := file("two-lines", "a\nb\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(token, link); err != nil {
		t.Fatal(err)
	}
	good := syncRealInputs{githubTokenFile: token, repo: "acme/vl-rh-sync", coolifyURL: "https://coolify.lab.example", coolifyTokenFile: cool, coolifyApp: "k8s0abc123"}
	with := func(f func(*syncRealInputs)) syncRealInputs { in := good; f(&in); return in }
	t.Run("the inputs", func(t *testing.T) {
		for name, c := range map[string]struct {
			in   syncRealInputs
			want string
		}{
			"all given":                {good, ""},
			"none given":               {syncRealInputs{}, "VL_RH_SYNC_GITHUB_TOKEN_FILE, VL_RH_SYNC_GITHUB_REPO, VL_RH_SYNC_COOLIFY_URL, VL_RH_SYNC_COOLIFY_TOKEN_FILE, VL_RH_SYNC_COOLIFY_APP"},
			"a repository not owner/x": {with(func(i *syncRealInputs) { i.repo = "vl-rh-sync" }), "owner/name"},
			"not a throwaway":          {with(func(i *syncRealInputs) { i.repo = "acme/api" }), "does not look like a throwaway"},
			"named by the owner":       {with(func(i *syncRealInputs) { i.repo, i.allowRepo = "acme/api", "acme/api" }), ""},
			"another name allowed":     {with(func(i *syncRealInputs) { i.repo, i.allowRepo = "acme/api", "acme/web" }), "does not look like a throwaway"},
			"Coolify over http":        {with(func(i *syncRealInputs) { i.coolifyURL = "http://coolify.lab.example" }), "https URL"},
			"Coolify with a path":      {with(func(i *syncRealInputs) { i.coolifyURL = "https://coolify.lab.example/api" }), "https URL"},
			"Coolify with credentials": {with(func(i *syncRealInputs) { i.coolifyURL = "https://u:p@coolify.lab.example" }), "https URL"},
			"an application name":      {with(func(i *syncRealInputs) { i.coolifyApp = "My App" }), "the application's UUID"},
			"a token others can read":  {with(func(i *syncRealInputs) { i.githubTokenFile = open }), "readable by others (mode 0644)"},
			"a token through a link":   {with(func(i *syncRealInputs) { i.coolifyTokenFile = link }), "not a regular file"},
			"a token of two lines":     {with(func(i *syncRealInputs) { i.githubTokenFile = twoLines }), "one non-empty line"},
			"a missing token file":     {with(func(i *syncRealInputs) { i.githubTokenFile = filepath.Join(dir, "missing") }), "no such file"},
		} {
			err := checkSyncReal(c.in)
			if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", name, err, c.want)
			}
		}
	})
	t.Run("the application's name", func(t *testing.T) {
		if !throwawayApp("vl-rh-sync", "k8s0abc123", "") || throwawayApp("api", "k8s0abc123", "") || !throwawayApp("api", "k8s0abc123", "k8s0abc123") || throwawayApp("api", "k8s0abc123", "other") {
			t.Error("the throwaway rule for applications")
		}
	})
	t.Run("the profile", func(t *testing.T) {
		set := func(kv map[string]string) {
			for k, v := range map[string]string{"VL_RH_PROFILE": "box", "VL_RH_INGRESS": "", "VL_RH_TARGET": "", "VL_RH_SOURCE": "", "VL_RH_KILL": "", "VL_RH_ONLY": "", "VL_RH_SYNC": "real",
				"VL_RH_SYNC_GITHUB_TOKEN_FILE": token, "VL_RH_SYNC_GITHUB_REPO": good.repo, "VL_RH_SYNC_COOLIFY_URL": good.coolifyURL,
				"VL_RH_SYNC_COOLIFY_TOKEN_FILE": cool, "VL_RH_SYNC_COOLIFY_APP": good.coolifyApp, "VL_RH_SYNC_ALLOW_REPO": "", "VL_RH_SYNC_ALLOW_APP": "",
				"VL_RH_TAILSCALE_OAUTH_FILE": "", "VL_RH_TAILSCALE_AUTH_KEY_FILE": "", "VL_RH_TAILSCALE_TAILNET": ""} {
				t.Setenv(k, v)
			}
			for k, v := range kv {
				t.Setenv(k, v)
			}
		}
		set(nil)
		if p, err := readProfile(0); err != nil || p.sync != "real" || p.syncReal.repo != good.repo {
			t.Errorf("the box with every input: %+v, %v", p.syncReal, err)
		}
		set(map[string]string{"VL_RH_ONLY": "sync"})
		if _, err := readProfile(0); err != nil {
			t.Errorf("VL_RH_ONLY=sync with VL_RH_SYNC=real: %v", err)
		}
		for name, c := range map[string]struct {
			kv   map[string]string
			want string
		}{
			"a workstation":         {map[string]string{"VL_RH_PROFILE": ""}, "owner's session on the box"},
			"public ingress":        {map[string]string{"VL_RH_INGRESS": "public", "VL_RH_PUBLIC_NAME": "rh.example", "VL_RH_PUBLIC_BIND": "127.0.0.1"}, "own proxy"},
			"a restored source":     {map[string]string{"VL_RH_SOURCE": "restore:/x"}, "seeded source"},
			"not a throwaway":       {map[string]string{"VL_RH_SYNC_GITHUB_REPO": "acme/api"}, "does not look like a throwaway"},
			"an unknown VL_RH_SYNC": {map[string]string{"VL_RH_SYNC": "github"}, "fakes (the platform stand-ins, a workstation) or real"},
		} {
			set(c.kv)
			if _, err := readProfile(0); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", name, err, c.want)
			}
		}
	})

	// A platform stand-in: GitHub's secrets and Coolify's variables, each
	// error echoing the request's Authorization header (as a careless
	// proxy might), and every DELETE recorded.
	var mu sync.Mutex
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/fail":
			http.Error(w, "refused for "+r.Header.Get("Authorization"), http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/vl-rh-sync/actions/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]string{{"name": "VLRH_AB_PORT", "updated_at": "t1"}, {"name": "OTHER", "updated_at": "t2"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/applications/k8s0abc123/envs":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"uuid": "e1", "key": "VLRH_AB_PORT", "value": "8080"}, {"uuid": "e2", "key": "OTHER", "value": "x"}})
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := &realPlatforms{owner: "acme", repo: "vl-rh-sync", ghToken: "x-test-gh", coolURL: srv.URL, coolToken: "x-test-cool", app: "k8s0abc123",
		http: srv.Client(), tokens: []string{"x-test-gh", "x-test-cool"}, githubBase: srv.URL}
	t.Run("no error carries a token", func(t *testing.T) {
		err := p.call(http.MethodGet, srv.URL+"/fail", p.ghToken, nil)
		if err == nil || strings.Contains(err.Error(), "x-test-gh") || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "[redacted]") {
			t.Errorf("%v", err)
		}
		secret("x-test-cool")
		if got := redact("a token x-test-cool in a report"); strings.Contains(got, "x-test-cool") {
			t.Errorf("the report keeps the token: %s", got)
		}
	})
	t.Run("the cleanup removes the run's names only", func(t *testing.T) {
		removed, failed := p.cleanup([]string{"VLRH_AB_PORT", "VLRH_AB_DEBUG"})
		mu.Lock()
		defer mu.Unlock()
		// VLRH_AB_DEBUG is on neither platform: nothing is sent for it.
		want := []string{"/repos/acme/vl-rh-sync/actions/secrets/VLRH_AB_PORT", "/api/v1/applications/k8s0abc123/envs/e1"}
		slices.Sort(want)
		slices.Sort(deleted)
		if !slices.Equal(deleted, want) || len(failed) != 0 {
			t.Errorf("deleted %v (want %v), failed %v", deleted, want, failed)
		}
		if strings.Join(removed, ",") != "GitHub VLRH_AB_PORT,Coolify VLRH_AB_PORT" {
			t.Errorf("removed %v", removed)
		}
	})
}
