// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/security"
)

// stepUpReplays are the admin-step-up operations whose refusal without an
// approval is a request of a replay, by its fixture.
var stepUpReplays = map[string]string{
	"identity.create": "identities", "credential.issue": "identities", "identity.reactivate": "identities",
	"oidc_binding.create": "oidc", "oidc_binding.delete": "oidc",
	"grant.create": "access", "grant.replace": "access", "grant.revoke": "access",
	"role.create": "access", "role.update": "access", "role.delete": "access",
	"group.create": "access", "group.member_add": "access", "team.project_remove": "access",
	"member.invite_admin": "people", "member.promote": "people", "member.remove": "people",
	"webhook.create": "webhooks", "webhook.update": "webhooks", "webhook.delete": "webhooks",
	"connection.create": "connections", "connection.replace_credential": "connections", "connection.delete": "connections",
	"github_app.register": "github-app", "github_app.import": "github-app", "github_app.replace_key": "github-mint",
	"project.delete": "project-deletion", "organization.delete": "org-deletion", "secret.export": "security",
}

// Each of admin-step-up's operations asks for an approval while the control
// is enforced: the ones a replay holds (STEP_UP_REQUIRED, naming the
// operation, as the TypeScript server answered), and every other one here,
// refused over HTTP with nothing changed, a team reached through the groups
// routes included.
func TestEveryAdminStepUpOperationAsks(t *testing.T) {
	in := newInstall(t, "public_url = http://localhost:8686\n")
	r := start(t, in)
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	admin := m[2]
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+r.addr+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		return res.StatusCode, v
	}
	id := func(path, body string) string {
		t.Helper()
		code, v := call("POST", path, body)
		s, _ := v["id"].(string)
		if code != 201 || s == "" {
			t.Fatalf("POST %s: %d %v", path, code, v)
		}
		return s
	}
	org := id("/v1/organizations", `{"name":"Acme","slug":"acme"}`)
	project := id("/v1/organizations/acme/projects", `{"slug":"web","name":"Web","contractAuthority":"managed"}`)
	service := id("/v1/organizations/acme/identities", `{"name":"runner","kind":"service"}`)
	other := id("/v1/organizations/acme/identities", `{"name":"other","kind":"service"}`)
	group := id("/v1/organizations/acme/groups", `{"name":"devs"}`)
	team := id("/v1/organizations/acme/teams", `{"name":"backend"}`)
	for _, g := range []string{group, team} {
		if code, v := call("POST", "/v1/organizations/acme/groups/"+g+"/members", fmt.Sprintf(`{"identityId":%q}`, service)); code != 204 {
			t.Fatalf("a member of %s: %d %v", g, code, v)
		}
	}
	r.stop(t)

	// What the API makes only with other parties: a second admin and a
	// GitHub App, and the control, enforced.
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO identities (id, kind, name) VALUES ('idn_second', 'human', 'Second')`,
		`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES ('` + org + `', 'idn_second', 'admin')`,
		`INSERT INTO github_apps (id, organization_id, github_app_id, slug, client_id, owner_login, owner_id, owner_type, key_envelope) VALUES ('gha_test', '` + org + `', 1, 'app', 'client', 'acme', 1, 'organization', '{}')`,
		`INSERT INTO security_controls (organization_id, control, mode, version) VALUES ('` + org + `', 'admin-step-up', 'enforce', 1)`,
	} {
		if err := store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	state := func(s *storage.DB) string {
		var b strings.Builder
		for _, q := range []string{`SELECT id, name, kind, version, revoked_at FROM groups`, `SELECT group_id, identity_id FROM group_members`, `SELECT team_id, project_id FROM team_projects`,
			`SELECT identity_id, role, version, removed_at FROM org_memberships`, `SELECT id, removed_at, version FROM github_apps`} {
			fmt.Fprintln(&b, paritytest.Rows(t, s, q+" ORDER BY 1, 2"))
		}
		return b.String()
	}
	before := state(store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	r = start(t, in)

	const at = "/v1/organizations/acme"
	here := map[string][][3]string{
		"group.update":        {{"PATCH", "/groups/" + group, `{"expectedVersion":1,"name":"renamed"}`}},
		"group.delete":        {{"DELETE", "/groups/" + group, ""}},
		"group.member_remove": {{"DELETE", "/groups/" + group + "/members/" + service, ""}},
		"team.create":         {{"POST", "/teams", `{"name":"frontend"}`}},
		"team.update":         {{"PATCH", "/teams/" + team, `{"expectedVersion":1,"name":"renamed"}`}},
		"team.delete":         {{"DELETE", "/teams/" + team, ""}, {"DELETE", "/groups/" + team, ""}},
		"team.member_add":     {{"POST", "/teams/" + team + "/members", `{"identityId":"` + other + `"}`}, {"POST", "/groups/" + team + "/members", `{"identityId":"` + other + `"}`}},
		"team.member_remove":  {{"DELETE", "/teams/" + team + "/members/" + service, ""}, {"DELETE", "/groups/" + team + "/members/" + service, ""}},
		"team.project_add":    {{"POST", "/teams/" + team + "/projects", `{"projectId":"` + project + `"}`}},
		"member.demote":       {{"PATCH", "/members/idn_second", `{"role":"member"}`}},
		"github_app.remove":   {{"DELETE", "/github-app?appId=gha_test", ""}},
	}
	for op, requests := range here {
		for _, q := range requests {
			code, v := call(q[0], at+q[1], q[2])
			e, _ := v["error"].(map[string]any)
			details, _ := e["details"].(map[string]any)
			approval, _ := details["approval"].(map[string]any)
			if code != 403 || e["code"] != "STEP_UP_REQUIRED" || approval["operation"] != op {
				t.Errorf("%s: %s %s: %d %v, want STEP_UP_REQUIRED for it", op, q[0], q[1], code, v)
			}
			// At most five may be open for one credential.
			aid, _ := approval["id"].(string)
			if code, v := call("POST", "/v1/me/approvals/"+aid+"/cancel", ""); code >= 300 {
				t.Fatalf("cancelling %s: %d %v", op, code, v)
			}
		}
	}
	r.stop(t)
	store, err = storage.Open(ctx, storage.Options{Path: filepath.Join(in.data, "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if after := state(store); after != before {
		t.Errorf("a refused request changed something:\n%s\n%s", before, after)
	}

	// Together they are the control's operations, each once.
	var covered []string
	for op := range here {
		covered = append(covered, op)
	}
	fixtures := map[string]string{}
	for op, name := range stepUpReplays {
		covered = append(covered, op)
		if _, read := fixtures[name]; !read {
			f, err := paritytest.Read(paritytest.Path(name + "-v0.22.0.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range f.Requests {
				if strings.Contains(string(q.Expect.Body), "STEP_UP_REQUIRED") {
					fixtures[name] += string(q.Expect.Body)
				}
			}
		}
		if !strings.Contains(fixtures[name], `"operation":"`+op+`"`) {
			t.Errorf("replay %s holds no refusal of %s", name, op)
		}
	}
	slices.Sort(covered)
	want := slices.Sorted(slices.Values(security.AdminStepUpOperations))
	if !slices.Equal(covered, want) {
		t.Errorf("covered %v, want %v", covered, want)
	}
}
