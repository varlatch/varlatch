// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The sync case against real destinations (VL_RH_SYNC=real; B5 of
// internal#221, the owner's session on the box): the fakes case's checks,
// read from the real platforms' APIs, against a throwaway GitHub
// repository and an application in the lab Coolify that the owner made
// for the run. Everything comes from files the owner wrote (mode 0600):
// a fine-grained GitHub token scoped to that one repository (Secrets: read
// and write), and a lab Coolify API token. The harness never prints them;
// they are registered as secrets, so no report or message carries them.
//
// What differs from the fakes:
//   - The values the run writes are named VLRH_<run's hex>_..., and its
//     Targets map them explicitly: nothing else in the repository or the
//     application is ever written, and the run deletes exactly those
//     names at the end (whatever passed).
//   - GitHub keeps sealed values only: its writes are read from each
//     secret's updated_at, Coolify's from its variables' values and
//     updated_at.
//   - A real platform's write cannot be held, so the barrier is opened
//     right after a change, and the check is that the change is delivered
//     across the barrier, not that the drain waited for it.
//   - The failing Target is a GitHub Target to a repository the token
//     cannot reach (vl-rh-missing-<hex>, which does not exist), made on Go.
//   - The application is not redeployed (redeploy off): the run writes its
//     variables only.

// syncRealInputs are VL_RH_SYNC=real's inputs, all given on the box.
type syncRealInputs struct {
	githubTokenFile, repo                    string // VL_RH_SYNC_GITHUB_TOKEN_FILE, VL_RH_SYNC_GITHUB_REPO (owner/name)
	coolifyURL, coolifyTokenFile, coolifyApp string // VL_RH_SYNC_COOLIFY_URL, _TOKEN_FILE, _APP (the application's UUID)
	allowRepo, allowApp                      string // VL_RH_SYNC_ALLOW_REPO, VL_RH_SYNC_ALLOW_APP: a throwaway without the vl-rh- prefix
}

// throwawayPrefix starts every name the owner makes for a rehearsal.
const throwawayPrefix = "vl-rh-"

// githubAPI is where every GitHub connection goes.
const githubAPI = "https://api.github.com"

var (
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	appPattern  = regexp.MustCompile(`^[a-z0-9]{6,64}$`)
)

// throwawayRepo is whether repo (owner/name) is one the run may write
// to: its name starts with vl-rh-, or the owner named it exactly.
func throwawayRepo(repo, allow string) bool {
	_, name, _ := strings.Cut(repo, "/")
	return strings.HasPrefix(name, throwawayPrefix) || (allow != "" && repo == allow)
}

// throwawayApp is whether the Coolify application (its name, its UUID) is
// one the run may write to.
func throwawayApp(name, uuid, allow string) bool {
	return strings.HasPrefix(name, throwawayPrefix) || (allow != "" && uuid == allow)
}

// checkSecretFile holds an input file to a secret's rules: a regular file
// (not a link), readable by its owner only, one non-empty line.
func checkSecretFile(what, path string) error {
	st, err := os.Lstat(path)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %v", what, err)
	case !st.Mode().IsRegular():
		return fmt.Errorf("%s %s is not a regular file", what, path)
	case st.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s %s is readable by others (mode %04o): write it with mode 0600", what, path, st.Mode().Perm())
	case st.Size() > 4096:
		return fmt.Errorf("%s %s is larger than a token", what, path)
	}
	if _, err := readSecretLine(path); err != nil {
		return fmt.Errorf("%s %s: %v", what, path, err)
	}
	return nil
}

// readSecretLine is a secret file's one line.
func readSecretLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" || strings.ContainsAny(v, "\r\n\x00") {
		return "", errors.New("it must hold one non-empty line")
	}
	return v, nil
}

// coolifyBase is the lab Coolify's URL as the case uses it: https, a
// host, no path, query or credentials.
func coolifyBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("VL_RH_SYNC_COOLIFY_URL is the lab Coolify's https URL (https://<host>[:port]), not %q", raw)
	}
	u.Path = ""
	return u, nil
}

// checkSyncReal checks VL_RH_SYNC=real's inputs before anything starts.
func checkSyncReal(in syncRealInputs) error {
	var missing []string
	for _, v := range []struct{ name, value string }{
		{"VL_RH_SYNC_GITHUB_TOKEN_FILE", in.githubTokenFile}, {"VL_RH_SYNC_GITHUB_REPO", in.repo},
		{"VL_RH_SYNC_COOLIFY_URL", in.coolifyURL}, {"VL_RH_SYNC_COOLIFY_TOKEN_FILE", in.coolifyTokenFile}, {"VL_RH_SYNC_COOLIFY_APP", in.coolifyApp},
	} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("VL_RH_SYNC=real needs %s (the owner's throwaway GitHub repository and lab Coolify application, the tokens in files of mode 0600)", strings.Join(missing, ", "))
	}
	if !repoPattern.MatchString(in.repo) {
		return fmt.Errorf("VL_RH_SYNC_GITHUB_REPO is owner/name, not %q", in.repo)
	}
	if !throwawayRepo(in.repo, in.allowRepo) {
		return fmt.Errorf("VL_RH_SYNC_GITHUB_REPO %s does not look like a throwaway repository: its name must start with %s, or VL_RH_SYNC_ALLOW_REPO must name it exactly", in.repo, throwawayPrefix)
	}
	if _, err := coolifyBase(in.coolifyURL); err != nil {
		return err
	}
	if !appPattern.MatchString(in.coolifyApp) {
		return fmt.Errorf("VL_RH_SYNC_COOLIFY_APP is the application's UUID (lower-case letters and digits), not %q", in.coolifyApp)
	}
	if err := checkSecretFile("VL_RH_SYNC_GITHUB_TOKEN_FILE", in.githubTokenFile); err != nil {
		return err
	}
	return checkSecretFile("VL_RH_SYNC_COOLIFY_TOKEN_FILE", in.coolifyTokenFile)
}

// realPlatforms reads and cleans the run's values on GitHub and Coolify.
type realPlatforms struct {
	owner, repo      string // the repository
	ghToken          string
	coolURL          string // https://<host>[:port]
	coolToken, app   string
	http             *http.Client
	tokens           []string
	githubBase       string // githubAPI; a test's server
	coolifyHostPorts string // the outbound allow list entry for the lab Coolify
}

// platformError is a platform's refusal: the request's method and path
// and the answer's status and start, never a header or a token.
type platformError struct {
	method, path string
	status       int
	body         string
}

func (e *platformError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.method, e.path, e.status, e.body)
}

// scrub removes the tokens from s.
func (p *realPlatforms) scrub(s string) string {
	for _, tok := range p.tokens {
		if tok != "" {
			s = strings.ReplaceAll(s, tok, "[redacted]")
		}
	}
	return s
}

func (p *realPlatforms) call(method, rawURL, token string, out any) error {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return fmt.Errorf("%s %s: %v", method, path, p.scrub(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if strings.HasPrefix(rawURL, p.githubBase) {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %v", method, path, p.scrub(err.Error()))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		body := p.scrub(strings.TrimSpace(string(b)))
		if len(body) > 200 {
			body = body[:200]
		}
		return &platformError{method: method, path: path, status: resp.StatusCode, body: body}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s %s: the answer is not the JSON expected: %v", method, path, err)
		}
	}
	return nil
}

// notFound is whether err is the platform's 404.
func notFound(err error) bool {
	var pe *platformError
	return errors.As(err, &pe) && pe.status == http.StatusNotFound
}

// secretsUpdated are the repository's Actions secrets: name to
// updated_at.
func (p *realPlatforms) secretsUpdated() (map[string]string, error) {
	var page struct {
		Secrets []struct {
			Name      string `json:"name"`
			UpdatedAt string `json:"updated_at"`
		} `json:"secrets"`
	}
	if err := p.call(http.MethodGet, p.githubBase+"/repos/"+p.owner+"/"+p.repo+"/actions/secrets?per_page=100", p.ghToken, &page); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, s := range page.Secrets {
		out[s.Name] = s.UpdatedAt
	}
	return out, nil
}

func (p *realPlatforms) deleteSecret(name string) error {
	err := p.call(http.MethodDelete, p.githubBase+"/repos/"+p.owner+"/"+p.repo+"/actions/secrets/"+url.PathEscape(name), p.ghToken, nil)
	if notFound(err) {
		return nil
	}
	return err
}

// coolifyEnv is one of the application's variables.
type coolifyEnv struct {
	UUID      string `json:"uuid"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	RealValue string `json:"real_value"`
	UpdatedAt string `json:"updated_at"`
}

func (e coolifyEnv) value() string {
	if e.RealValue != "" {
		return e.RealValue
	}
	return e.Value
}

func (p *realPlatforms) envs() ([]coolifyEnv, error) {
	var out []coolifyEnv
	err := p.call(http.MethodGet, p.coolURL+"/api/v1/applications/"+p.app+"/envs", p.coolToken, &out)
	return out, err
}

// env is the application's variable key (its first, Coolify may keep a
// preview copy too).
func (p *realPlatforms) env(key string) (coolifyEnv, bool) {
	all, err := p.envs()
	if err != nil {
		return coolifyEnv{}, false
	}
	for _, e := range all {
		if e.Key == key {
			return e, true
		}
	}
	return coolifyEnv{}, false
}

func (p *realPlatforms) appName() (string, error) {
	var app struct {
		Name string `json:"name"`
	}
	err := p.call(http.MethodGet, p.coolURL+"/api/v1/applications/"+p.app, p.coolToken, &app)
	return app.Name, err
}

// cleanup deletes the run's values from both platforms, by their exact
// names, and answers what it removed and what it could not.
func (p *realPlatforms) cleanup(names []string) (removed []string, failed []string) {
	have, err := p.secretsUpdated()
	if err != nil {
		failed = append(failed, "GitHub: "+err.Error())
	}
	for _, n := range names {
		if _, ok := have[n]; !ok && err == nil {
			continue
		}
		if err := p.deleteSecret(n); err != nil {
			failed = append(failed, "GitHub "+n+": "+err.Error())
		} else if _, ok := have[n]; ok {
			removed = append(removed, "GitHub "+n)
		}
	}
	envs, err := p.envs()
	if err != nil {
		failed = append(failed, "Coolify: "+err.Error())
	}
	for _, e := range envs {
		for _, n := range names {
			if e.Key != n || e.UUID == "" {
				continue
			}
			if err := p.call(http.MethodDelete, p.coolURL+"/api/v1/applications/"+p.app+"/envs/"+url.PathEscape(e.UUID), p.coolToken, nil); err != nil && !notFound(err) {
				failed = append(failed, "Coolify "+n+": "+err.Error())
			} else {
				removed = append(removed, "Coolify "+n)
			}
		}
	}
	return removed, failed
}

// loadRealPlatforms reads the inputs (checked by readProfile) and
// registers the tokens as secrets.
func loadRealPlatforms(t *testing.T, in syncRealInputs) *realPlatforms {
	t.Helper()
	gh, err := readSecretLine(in.githubTokenFile)
	if err != nil {
		t.Fatalf("VL_RH_SYNC_GITHUB_TOKEN_FILE: %v", err)
	}
	cool, err := readSecretLine(in.coolifyTokenFile)
	if err != nil {
		t.Fatalf("VL_RH_SYNC_COOLIFY_TOKEN_FILE: %v", err)
	}
	secret(gh)
	secret(cool)
	u, err := coolifyBase(in.coolifyURL)
	if err != nil {
		t.Fatal(err)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	owner, repo, _ := strings.Cut(in.repo, "/")
	return &realPlatforms{owner: owner, repo: repo, ghToken: gh, coolURL: u.String(), coolToken: cool, app: in.coolifyApp,
		http: &http.Client{Timeout: 30 * time.Second}, tokens: []string{gh, cool}, githubBase: githubAPI,
		coolifyHostPorts: net.JoinHostPort(u.Hostname(), port)}
}

func syncRealCase(t *testing.T, rel release, s3 *s3Server) {
	const item = syncItem
	in0 := prof.syncReal
	p := loadRealPlatforms(t, in0)
	// The application must look like a throwaway too, before anything is
	// written: its name starts with vl-rh-, or the owner named its UUID.
	name, err := p.appName()
	if err != nil {
		t.Fatalf("the lab Coolify's application %s: %v", p.app, err)
	}
	if !throwawayApp(name, p.app, in0.allowApp) {
		t.Fatalf("the Coolify application %s is named %q, which does not look like a throwaway: its name must start with %s, or VL_RH_SYNC_ALLOW_APP must name its UUID", p.app, name, throwawayPrefix)
	}
	measure("item 13 (real): the destinations", fmt.Sprintf("GitHub %s/%s; Coolify %s application %s (%s); the run's values only, deleted at the end", p.owner, p.repo, p.coolURL, p.app, name))
	measure("item 13 (real): what differs from the fakes", "a real platform's write cannot be held, so the barrier opens right after a change and the check is that the change is delivered across it, not that the drain waited for it; GitHub writes are read from each secret's updated_at; the application is not redeployed")
	hex := strings.ToUpper(hexBytes(3))
	prefix := "VLRH_" + hex + "_"
	apiKeyName, debugName, portName := prefix+"API_KEY", prefix+"DEBUG", prefix+"PORT"
	names := []string{apiKeyName, debugName, portName}
	// Registered before anything is written, so it runs whatever happens.
	t.Cleanup(func() {
		removed, failed := p.cleanup(names)
		measure("item 13 (real): the run's values removed", strings.Join(removed, ", "))
		record(t, item, "(real) the run's values are deleted from both platforms", len(failed) == 0, strings.Join(failed, "; "))
	})
	in := newInstallation(t, rel, s3, "sync-real", installExtra{
		env:  map[string]string{"VARLATCH_OUTBOUND_ALLOW": p.coolifyHostPorts},
		conf: "outbound_allow = " + p.coolifyHostPorts + "\n",
	})
	registerSecrets(in)
	c := adminClient(t, in)
	suffix := strings.ToLower(hex)
	slug := "sync-real-" + suffix
	base := "/v1/organizations/" + slug
	env := base + "/projects/api/environments/production"
	c.ok("POST", "/v1/organizations", map[string]any{"name": "Sync rehearsal (real)", "slug": slug})
	c.ok("POST", base+"/projects", map[string]any{"slug": "api", "name": "API", "contractAuthority": "managed"})
	c.ok("POST", base+"/projects/api/environments", map[string]any{"name": "production", "tier": "production"})
	var items []map[string]any
	for _, it := range []struct {
		name      string
		sensitive bool
	}{{apiKeyName, true}, {debugName, false}, {portName, false}} {
		items = append(items, map[string]any{"name": it.name, "required": map[string]any{"kind": "never"}, "sensitive": it.sensitive, "type": "string"})
	}
	revision := str(c.ok("POST", base+"/projects/api/contract/revisions", map[string]any{"contract": map[string]any{"schemaVersion": 1, "items": items}}), "id")
	c.ok("POST", base+"/projects/api/contract/revisions/"+revision+"/activate", map[string]any{})
	put := func(name, value string) { c.ok("PUT", env+"/values/"+name, map[string]any{"value": value}) }
	apiKey := secret("key-" + hexBytes(8))
	put(apiKeyName, apiKey)
	put(debugName, "false")
	put(portName, "8080")
	gh := str(c.ok("POST", base+"/platform-connections", map[string]any{"platform": "github-actions", "baseIdentity": p.owner, "name": "GitHub", "credential": p.ghToken}), "id")
	coolify := str(c.ok("POST", base+"/platform-connections", map[string]any{"platform": "coolify", "baseIdentity": p.coolURL, "name": "Coolify", "credential": p.coolToken}), "id")
	explicit := func(ns ...string) map[string]any {
		var it []map[string]any
		for _, n := range ns {
			it = append(it, map[string]any{"name": n})
		}
		return map[string]any{"kind": "explicit", "items": it}
	}
	tGh := str(c.ok("POST", env+"/sync-targets", map[string]any{"connectionId": gh, "destination": map[string]any{"repo": p.repo}, "mapping": explicit(names...)}), "id")
	tApp := str(c.ok("POST", env+"/sync-targets", map[string]any{"connectionId": coolify, "destination": map[string]any{"applicationUuid": p.app},
		"mapping": explicit(portName, apiKeyName), "redeploy": false}), "id")
	target := func(id string) syncTarget {
		code, out := c.send("GET", env+"/sync-targets/"+id, nil)
		var v syncTarget
		if code == 200 {
			b, _ := json.Marshal(out)
			_ = json.Unmarshal(b, &v)
		}
		return v
	}
	coolValue := func(key string) string {
		e, _ := p.env(key)
		return e.value()
	}
	ghUpdated := func() map[string]string {
		m, _ := p.secretsUpdated()
		return m
	}
	ours := func(m map[string]string) string {
		var out []string
		for _, n := range names {
			out = append(out, n+"@"+m[n])
		}
		return strings.Join(out, " ")
	}

	// 1. The source delivers.
	var gs map[string]string
	delivered := pollUntil(180*time.Second, 5*time.Second, func() bool {
		gs = ghUpdated()
		return gs[apiKeyName] != "" && gs[debugName] != "" && gs[portName] != "" && coolValue(portName) == "8080" && coolValue(apiKeyName) == apiKey && target(tGh).ok() && target(tApp).ok()
	})
	record(t, item, "(real) the source delivers to GitHub and the Coolify application", delivered,
		fmt.Sprintf("GitHub %s; GitHub Target %s; Coolify Target %s", ours(gs), target(tGh), target(tApp)))
	if !delivered {
		return
	}

	// 2. The barrier with a change due, then its release; the change is
	// delivered across it.
	before := gs[portName]
	put(portName, "8081")
	r := in.admin(nil, "migration", "barrier", "--drain-seconds", "20")
	var b barrierAnswer
	drained := r.code == 0 && json.Unmarshal([]byte(lastLine(r.stdout)), &b) == nil && b.Gate.Kind == "migration"
	record(t, item, "(real) the barrier opens and drains with a change due", drained, r.String())
	measure("item 13 (real): the barrier's drain", string(b.Drained))
	if drained {
		rl := in.admin(nil, "migration", "release", "--id", b.Gate.ID)
		code, _ := in.get("/v1/meta")
		record(t, item, "(real) release lifts the barrier", rl.code == 0 && code == 200, fmt.Sprintf("%s; /v1/meta %d", rl.String(), code))
	}
	across := pollUntil(180*time.Second, 5*time.Second, func() bool {
		gs = ghUpdated()
		return coolValue(portName) == "8081" && gs[portName] != "" && gs[portName] != before && target(tGh).ok() && target(tApp).ok()
	})
	record(t, item, "(real) the change made at the barrier is delivered across it", across,
		fmt.Sprintf("Coolify %s=%s; GitHub %s updated %s (was %s)", portName, coolValue(portName), portName, gs[portName], before))

	// 3. The migration, both Targets settled on the source.
	pollUntil(90*time.Second, 5*time.Second, func() bool { return target(tGh).settled() && target(tApp).settled() })
	ghBefore := ghUpdated()
	coolBefore := map[string]string{}
	for _, n := range []string{portName, apiKeyName} {
		e, _ := p.env(n)
		coolBefore[n] = e.UpdatedAt
	}
	r = in.migrateEnv(rel, true, rel.pin())
	record(t, item, "(real) the migration opens on the target", r.code == 0, r.String()+" "+lastLines(r.stdout, 4))
	if r.code != 0 {
		measure("item 13 (real): migrate's stdout", lastLines(r.stdout, 20))
		return
	}
	oc := run("", nil, nil, filepath.Join(binDir, "varlatchd"), "admin", "outbound", "check", "--config", in.conf)
	record(t, item, "(real) the target's outbound check allows both destinations", oc.code == 0, oc.String()+" "+lastLines(oc.stdout, 4))

	// 4. Go sends nothing the source delivered.
	pushedAt := time.Now()
	codes := []int{}
	pushOK := true
	for _, id := range []string{tGh, tApp} {
		code, _ := c.send("POST", env+"/sync-targets/"+id+"/push", map[string]any{})
		codes = append(codes, code)
		pushOK = pushOK && code >= 200 && code < 300
	}
	ranOnGo := func(id string) bool {
		v := target(id)
		at, err := time.Parse(time.RFC3339Nano, v.LastAttemptAt)
		return err == nil && at.After(pushedAt.Add(-time.Second)) && v.settled()
	}
	both := pollUntil(180*time.Second, 5*time.Second, func() bool { return ranOnGo(tGh) && ranOnGo(tApp) })
	time.Sleep(10 * time.Second)
	ghAfter := ghUpdated()
	same := ours(ghAfter) == ours(ghBefore)
	for n, at := range coolBefore {
		e, _ := p.env(n)
		same = same && e.UpdatedAt == at
	}
	record(t, item, "(real) after the migration, Go sends nothing the source delivered", pushOK && both && same && target(tGh).ok() && target(tApp).ok(),
		fmt.Sprintf("push answered %v; ran on Go and settled %v; GitHub %s then %s; Coolify %v; GitHub Target %s; Coolify Target %s",
			codes, both, ours(ghBefore), ours(ghAfter), coolBefore, target(tGh), target(tApp)))

	// 5. A change made on Go is pushed from Go, and only it.
	put(portName, "9090")
	pushed := pollUntil(180*time.Second, 5*time.Second, func() bool {
		gs = ghUpdated()
		return coolValue(portName) == "9090" && gs[portName] != ghAfter[portName] && gs[apiKeyName] == ghAfter[apiKeyName] && gs[debugName] == ghAfter[debugName]
	})
	record(t, item, "(real) a change on Go is pushed from Go, and only it", pushed,
		fmt.Sprintf("Coolify %s=%s; GitHub %s then %s", portName, coolValue(portName), ours(ghAfter), ours(gs)))

	// 6. A failing Target (#369): one to a repository the token cannot
	// reach; varlatchd keeps serving and the Coolify Target converges.
	// The server may refuse the Target when it is made (it checks the
	// destination), or make it and fail its runs: either way the refusal
	// stays the Target's own.
	mcode, mout := c.send("POST", env+"/sync-targets", map[string]any{"connectionId": gh, "destination": map[string]any{"repo": throwawayPrefix + "missing-" + suffix},
		"mapping": explicit(debugName)})
	if mcode >= 200 && mcode < 300 {
		tMissing := str(mout, "id")
		var failing syncTarget
		failed := pollUntil(180*time.Second, 5*time.Second, func() bool {
			failing = target(tMissing)
			return failing.FailureCount >= 1
		})
		record(t, item, "(real) a Target the platform refuses fails on its own", failed, failing.String())
	} else {
		mb, _ := json.Marshal(mout)
		record(t, item, "(real) a Target the platform refuses fails on its own", mcode >= 400 && mcode < 500, fmt.Sprintf("refused when made: %d %s", mcode, trim(string(mb))))
	}
	apiKey2 := secret("key-" + hexBytes(8))
	put(apiKeyName, apiKey2)
	converged := pollUntil(180*time.Second, 5*time.Second, func() bool { return coolValue(apiKeyName) == apiKey2 && target(tApp).ok() })
	code, ready := in.get("/readyz")
	active := run("", nil, nil, "systemctl", "is-active", "--quiet", in.unitName()).code == 0
	record(t, item, "(real) varlatchd keeps serving and the Coolify Target converges", converged && code == 200 && active,
		fmt.Sprintf("Coolify %s updated %v; /readyz %d %s; unit active %v; Coolify Target %s", apiKeyName, converged, code, trim(ready), active, target(tApp)))
}
