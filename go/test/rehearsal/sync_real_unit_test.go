// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// A platform stand-in: GitHub's secrets (two pages, linked) and
	// Coolify's variables (a preview copy of each, real_value and
	// updated_at), decoys of other runs' names among them, each error
	// echoing the request's Authorization header (as a careless proxy
	// might), every write and DELETE recorded, and one DELETE answered
	// 404 (gone already).
	var mu sync.Mutex
	var deleted, written []string
	pub := make([]byte, 32)
	pub[0] = 9
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		secrets := "/repos/acme/vl-rh-sync/actions/secrets"
		switch {
		case r.URL.Path == "/fail":
			http.Error(w, "refused for "+r.Header.Get("Authorization"), http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == secrets && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", "<"+srv.URL+secrets+"?per_page=100&page=2>; rel=\"next\", <"+srv.URL+secrets+"?per_page=100&page=2>; rel=\"last\"")
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]string{{"name": "VLRH_AB_PORT", "updated_at": "t1"}, {"name": "VLRH_CD_PORT", "updated_at": "t2"}}})
		case r.Method == http.MethodGet && r.URL.Path == secrets:
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]string{{"name": "VLRH_AB_DEBUG", "updated_at": "t3"}, {"name": "VLRH_AB_PORT_X", "updated_at": "t4"}}})
		case r.Method == http.MethodGet && r.URL.Path == secrets+"/public-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "k1", "key": base64.StdEncoding.EncodeToString(pub)})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, secrets+"/"):
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			sealed, _ := base64.StdEncoding.DecodeString(b["encrypted_value"])
			written = append(written, fmt.Sprintf("PUT %s key %s sealed %d", r.URL.Path, b["key_id"], len(sealed)))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/applications/k8s0abc123":
			_ = json.NewEncoder(w).Encode(map[string]string{"uuid": "k8s0abc123", "name": "vl-rh-sync-app"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/applications/k8s0abc123/envs":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"uuid": "p1", "key": "VLRH_AB_PORT", "value": "stale", "is_preview": true, "updated_at": "u0"},
				{"uuid": "e1", "key": "VLRH_AB_PORT", "value": "masked", "real_value": "8080", "is_preview": false, "updated_at": "u1"},
				{"uuid": "e3", "key": "VLRH_AB_PORT_X", "value": "x", "is_preview": false},
				{"uuid": "e4", "key": "VLRH_CD_PORT", "value": "y", "is_preview": false},
				{"uuid": "e2", "key": "OTHER", "value": "x", "is_preview": false},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/applications/k8s0abc123/envs":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			written = append(written, fmt.Sprintf("PATCH %v=%v preview %v", b["key"], b["value"], b["is_preview"]))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == secrets+"/VLRH_AB_DEBUG":
			deleted = append(deleted, r.URL.Path)
			http.NotFound(w, r)
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
	t.Run("the reads", func(t *testing.T) {
		if name, err := p.appName(); err != nil || name != "vl-rh-sync-app" {
			t.Errorf("appName: %q, %v", name, err)
		}
		m, err := p.secretsUpdated()
		if err != nil || len(m) != 4 || m["VLRH_AB_DEBUG"] != "t3" {
			t.Errorf("both pages of secrets: %v, %v", m, err)
		}
		e, ok, err := p.env("VLRH_AB_PORT")
		if err != nil || !ok || e.UUID != "e1" || e.value() != "8080" || e.UpdatedAt != "u1" {
			t.Errorf("the non-preview row, its real value: %+v %v %v", e, ok, err)
		}
		if _, ok, _ := p.env("VLRH_AB_NONE"); ok {
			t.Error("a variable that is not there")
		}
	})
	t.Run("the calibration's writes", func(t *testing.T) {
		if err := p.putSecret("VLRH_AB_DEBUG", "false"); err != nil {
			t.Fatal(err)
		}
		if err := p.patchEnv("VLRH_AB_PORT", "8081"); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		// A sealed box: the ephemeral key (32), the box (16 + the value's 5).
		want := []string{"PUT /repos/acme/vl-rh-sync/actions/secrets/VLRH_AB_DEBUG key k1 sealed 53", "PATCH VLRH_AB_PORT=8081 preview false"}
		if !slices.Equal(written, want) {
			t.Errorf("written %v, want %v", written, want)
		}
	})
	t.Run("the cleanup removes the run's names only", func(t *testing.T) {
		removed, gone, failed := p.cleanup([]string{"VLRH_AB_PORT", "VLRH_AB_DEBUG", "VLRH_AB_API_KEY"})
		mu.Lock()
		defer mu.Unlock()
		// Not another run's VLRH_CD_PORT, not VLRH_AB_PORT_X, not OTHER;
		// the preview copy too; VLRH_AB_API_KEY is on neither platform.
		want := []string{"/repos/acme/vl-rh-sync/actions/secrets/VLRH_AB_PORT", "/repos/acme/vl-rh-sync/actions/secrets/VLRH_AB_DEBUG",
			"/api/v1/applications/k8s0abc123/envs/p1", "/api/v1/applications/k8s0abc123/envs/e1"}
		slices.Sort(want)
		slices.Sort(deleted)
		if !slices.Equal(deleted, want) || len(failed) != 0 {
			t.Errorf("deleted %v (want %v), failed %v", deleted, want, failed)
		}
		if strings.Join(removed, ",") != "GitHub VLRH_AB_PORT,Coolify VLRH_AB_PORT (preview),Coolify VLRH_AB_PORT" || strings.Join(gone, ",") != "GitHub VLRH_AB_DEBUG" {
			t.Errorf("removed %v, gone %v", removed, gone)
		}
	})
	t.Run("a listing's next page", func(t *testing.T) {
		h := http.Header{}
		h.Set("Link", `<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last"`)
		if got := nextLink(h); got != "https://api.github.com/x?page=2" {
			t.Errorf("next %q", got)
		}
		if got := nextLink(http.Header{}); got != "" {
			t.Errorf("no Link: %q", got)
		}
	})
}
