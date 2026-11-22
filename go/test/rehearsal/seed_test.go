// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The seed (must-cover 9a): the installation built through its own /v1
// API over the public URL, as the fixture kit's scenario builds a source
// (services/varlatchd/test/helpers/migration-seed.ts), here against the
// real server: two Organizations, Projects, Environments of three tiers,
// a Contract, Secret values with versions, machine identities (one with an
// OIDC binding, one retired), a Role, a Group, a Team and Grants, so the
// export's decision table and digests have real work. VL_RH_SEED_VALUES
// sets how many values the large Project gets (default 400, 2 versions
// each), for the kill mid-export and the downtime's size.
//
// Left out, since they reach outside the installation: webhooks, Platform
// Connections, a GitHub App and Sync Targets (the outbound policy refuses
// loopback stand-ins). The sync case (VL_RH_SYNC=fakes, sync_test.go)
// makes its own Connections and Targets against the platform stand-ins.

type apiClient struct {
	t      *testing.T
	base   string
	token  string
	http   *http.Client
	waited int // 429s waited out
}

func (c *apiClient) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.http
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// send is do, waiting out the server's rate limit (429, a second at a time)
// as any client must, for up to five minutes.
func (c *apiClient) send(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	for deadline := time.Now().Add(5 * time.Minute); ; {
		code, out := c.do(method, path, body)
		if code != http.StatusTooManyRequests || time.Now().After(deadline) {
			return code, out
		}
		c.waited++
		time.Sleep(time.Second)
	}
}

// ok is do, failing the seed on anything but a 2xx.
func (c *apiClient) ok(method, path string, body any) map[string]any {
	c.t.Helper()
	code, out := c.send(method, path, body)
	if code < 200 || code >= 300 {
		b, _ := json.Marshal(out)
		c.t.Fatalf("seed: %s %s: %d %s", method, path, code, redact(string(b)))
	}
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

type seeded struct {
	values, versions, rateLimited int
	took                          time.Duration
}

// adminClient bootstraps the installation's first admin with a CLI
// credential and answers a client of its /v1 at the public URL.
func adminClient(t *testing.T, in *installation) *apiClient {
	r := must(t, in.admin(nil, "bootstrap", "--cli-credential", "--name", "Rehearsal Admin"), "bootstrap")
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	token := strings.TrimSpace(lines[len(lines)-1])
	if !strings.HasPrefix(token, "vlt_") {
		t.Fatal("bootstrap printed no CLI credential")
	}
	secret(token)
	hc := &http.Client{Timeout: 60 * time.Second}
	if in.client != nil {
		hc.Transport = in.client.Transport
	}
	return &apiClient{t: t, base: in.publicURL, token: token, http: hc}
}

func seed(t *testing.T, in *installation) seeded {
	began := time.Now()
	c := adminClient(t, in)
	n := 400
	if v, err := strconv.Atoi(os.Getenv("VL_RH_SEED_VALUES")); err == nil && v > 0 {
		n = v
	}
	const acme = "/v1/organizations/acme"
	c.ok("POST", "/v1/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	c.ok("POST", "/v1/organizations", map[string]any{"name": "Beta", "slug": "beta"})
	project := str(c.ok("POST", acme+"/projects", map[string]any{"name": "API", "slug": "api", "contractAuthority": "managed"}), "id")
	c.ok("POST", acme+"/projects", map[string]any{"name": "Web", "slug": "web", "contractAuthority": "managed"})
	for _, e := range [][2]string{{"development", "development"}, {"staging", "staging"}, {"production", "production"}} {
		c.ok("POST", acme+"/projects/api/environments", map[string]any{"name": e[0], "tier": e[1]})
	}
	values, versions := 0, 0
	for i := range n {
		name := fmt.Sprintf("VALUE_%04d", i)
		env := []string{"development", "staging", "production"}[i%3]
		for range 2 {
			c.ok("PUT", fmt.Sprintf("%s/projects/api/environments/%s/values/%s", acme, env, name), map[string]any{"value": secret("rh-" + hexBytes(16))})
			versions++
		}
		values++
	}
	service := str(c.ok("POST", acme+"/identities", map[string]any{"name": "api-svc", "kind": "service"}), "id")
	ci := str(c.ok("POST", acme+"/identities", map[string]any{"name": "deploy", "kind": "ci"}), "id")
	c.ok("POST", acme+"/identities/"+ci+"/oidc-bindings", map[string]any{"issuer": "https://ci.example", "audience": "varlatch", "subject": "repo:acme/api:ref:refs/heads/main"})
	old := str(c.ok("POST", acme+"/identities", map[string]any{"name": "old-worker", "kind": "workload"}), "id")
	c.ok("POST", acme+"/identities/"+old+"/retire", nil)
	c.ok("POST", acme+"/roles", map[string]any{"name": "reader", "actions": []string{"config.value.read", "project.read"}})
	group := str(c.ok("POST", acme+"/groups", map[string]any{"name": "oncall"}), "id")
	c.ok("POST", acme+"/groups/"+group+"/members", map[string]any{"identityId": service})
	team := str(c.ok("POST", acme+"/teams", map[string]any{"name": "platform"}), "id")
	c.ok("POST", acme+"/teams/"+team+"/projects", map[string]any{"projectId": project})
	c.ok("POST", acme+"/grants", map[string]any{"subjectIdentityId": service, "scope": map[string]any{"kind": "project", "projectId": project}, "actions": []string{"project.read"}})
	c.ok("POST", acme+"/grants", map[string]any{"subjectIdentityId": ci, "scope": map[string]any{"kind": "organization"}, "actions": []string{"project.read"}})
	return seeded{values: values, versions: versions, rateLimited: c.waited, took: time.Since(began)}
}
