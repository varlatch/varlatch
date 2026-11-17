// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

import (
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestCoolifyLiveExpands is scripts/test-coolify-live-expands.mjs on the
// Go adapter: names Coolify resolves (platformExpands, ADR-0031 amendment
// 2026-10-22) against the lab Coolify. It creates one project with
// project, environment, server and team shared variables holding canary
// sentinels (named with the run's prefix), and one Dockerfile application
// built from scripts/coolify-fixture at a pinned commit of this public
// repository (FIXTURE_REF, FIXTURE_SHA). Each reference is carried by two
// names: one written through the adapter with platformExpands, and a twin
// created through Coolify's API with Coolify's defaults. After one deploy,
// every pair must deliver exactly the sentinel (or the pinned commit for
// $SOURCE_COMMIT) at build time and at runtime; literal controls arrive as
// given or are refused. The shared variables are deleted as soon as the
// build and runtime records are read; then everything else.
//
// The application's own variable names (EXP_*, TWIN_*, LIT_COMMIT) are
// the fixture's build arguments at the pinned commit, so they carry no
// run prefix; they live on this run's application only.
func TestCoolifyLiveExpands(t *testing.T) {
	ref, sha := os.Getenv("FIXTURE_REF"), os.Getenv("FIXTURE_SHA")
	l := newLive(t)
	if ref == "" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) {
		t.Fatal("FIXTURE_REF and FIXTURE_SHA (40 hex, a commit on main with scripts/coolify-fixture) are required")
	}
	l.begin()
	defer l.finish()

	kinds := []string{"PROJECT", "ENVIRONMENT", "SERVER", "TEAM", "COMMIT"}
	keys := map[string]string{"PROJECT": l.name("P"), "ENVIRONMENT": l.name("E"), "SERVER": l.name("S"), "TEAM": l.name("T")}
	refs := map[string]string{
		"PROJECT": "{{project." + keys["PROJECT"] + "}}", "ENVIRONMENT": "{{environment." + keys["ENVIRONMENT"] + "}}",
		"SERVER": "{{server." + keys["SERVER"] + "}}", "TEAM": "{{team." + keys["TEAM"] + "}}", "COMMIT": "$SOURCE_COMMIT",
	}
	expected := map[string]string{"COMMIT": sha}
	for _, k := range kinds[:4] {
		expected[k] = strings.ToLower(k) + "-sentinel-" + l.run
	}

	t.Logf("instance version: %s", l.version())

	var project struct{ UUID string }
	l.intend("project", "varlatch-coolify-expands-"+l.run, "/projects")
	if code := l.json("POST", "/projects", map[string]any{"name": "varlatch-coolify-expands-" + l.run, "description": "Temporary Varlatch adapter live test " + l.run + ", deleted afterwards"}, &project); project.UUID == "" {
		t.Fatalf("project not created (HTTP %d)", code)
	}
	l.record("project", project.UUID, "/projects/"+project.UUID, "/projects/"+project.UUID)

	// The application first; the shared variables right before the writes
	// that use them, so that they live as short a time as they can.
	var app struct{ UUID string }
	l.intend("application", "varlatch-expands-probe-"+l.run, "/applications/public in project "+project.UUID)
	code := l.json("POST", "/applications/public", map[string]any{
		"project_uuid": project.UUID, "environment_name": "production", "server_uuid": l.server,
		"name": "varlatch-expands-probe-" + l.run, "git_repository": "https://github.com/varlatch/varlatch",
		"git_branch": ref, "git_commit_sha": sha, "build_pack": "dockerfile",
		"base_directory": "/scripts/coolify-fixture", "dockerfile_location": "/Dockerfile", "ports_exposes": "80",
		"health_check_enabled": false, "include_source_commit_in_build": true, "instant_deploy": false,
	}, &app)
	if app.UUID == "" {
		t.Fatalf("application not created (HTTP %d)", code)
	}
	l.record("application", app.UUID, "/applications/"+app.UUID+"?delete_configurations=true&delete_volumes=true&docker_cleanup=true&delete_connected_networks=true", "/applications/"+app.UUID)
	var shown struct {
		BuildPack string `json:"build_pack"`
		Settings  struct {
			IncludeSourceCommit any `json:"include_source_commit_in_build"`
		}
	}
	l.json("GET", "/applications/"+app.UUID, nil, &shown)
	l.check("source commit enabled for the build", shown.Settings.IncludeSourceCommit == true || shown.Settings.IncludeSourceCommit == float64(1), "")

	// Shared variables with canary sentinels, one per scope.
	shared := func(scope, path, key, value string) {
		var r struct {
			ID   any
			UUID string
		}
		l.intend("shared-"+scope, key, path)
		code := l.json("POST", path, map[string]any{"key": key, "value": value}, &r)
		id := r.UUID
		if f, ok := r.ID.(float64); ok && id == "" {
			id = itoaLive(int(f))
		}
		if (code != 201 && code != 200) || id == "" {
			t.Fatalf("%s shared variable not created (HTTP %d)", scope, code)
		}
		l.record("shared-"+scope, id, path+"/"+id, "")
	}
	shared("team", "/team/envs", keys["TEAM"], expected["TEAM"])
	shared("server", "/servers/"+l.server+"/envs", keys["SERVER"], expected["SERVER"])
	shared("project", "/projects/"+project.UUID+"/envs", keys["PROJECT"], expected["PROJECT"])
	shared("environment", "/projects/"+project.UUID+"/environments/production/envs", keys["ENVIRONMENT"], expected["ENVIRONMENT"])

	// EXP_VAULT is listed too: listing never admits {{vault.…}}.
	var listed []string
	for _, k := range kinds {
		listed = append(listed, "EXP_"+k)
	}
	listed = append(listed, "EXP_VAULT")
	dest, err := coolify{}.CanonicalizeDestination(Object{{Key: "applicationUuid", Value: app.UUID}, {Key: "buildTime", Value: "true"}, {Key: "platformExpands", Value: strings.Join(listed, ",")}})
	if err != nil {
		t.Fatal(err)
	}
	req := l.req(dest.Fields, nil)

	// Twins first, through Coolify's API with its defaults: the
	// operator's way.
	for _, k := range kinds {
		code, _ := l.do("POST", "/applications/"+app.UUID+"/envs", map[string]any{"key": "TWIN_" + k, "value": refs[k]})
		l.check("twin TWIN_"+k+" created with Coolify's defaults", code == 201 || code == 200, httpStatus(code))
	}

	// The adapter: listed names, then the literal controls.
	var items []SyncItem
	for _, k := range kinds {
		items = append(items, SyncItem{Name: "EXP_" + k, Value: refs[k]})
	}
	items = append(items, SyncItem{Name: "LIT_COMMIT", Value: "$SOURCE_COMMIT"}, SyncItem{Name: "LIT_TEAM", Value: refs["TEAM"]}, SyncItem{Name: "EXP_VAULT", Value: "{{vault.SOMETHING}}"})
	outcomes, err := coolify{}.WriteValues(liveCtx(), req, items)
	if err != nil {
		l.check("writes", false, err.Error())
	}
	for _, o := range outcomes {
		switch o.Name {
		case "LIT_TEAM":
			l.check("an unlisted {{team.X}} is refused and not sent", !o.OK && strings.Contains(o.Error, "shared variables"), o.Error)
		case "EXP_VAULT":
			l.check("a listed {{vault.X}} is refused and not sent", !o.OK && strings.Contains(o.Error, "secret manager"), o.Error)
		default:
			l.check("adapter wrote "+o.Name, o.OK, o.Error)
		}
	}
	type row struct {
		Key         string
		Value       *string
		IsPreview   bool `json:"is_preview"`
		IsLiteral   bool `json:"is_literal"`
		IsMultiline bool `json:"is_multiline"`
		IsBuildtime bool `json:"is_buildtime"`
		IsRuntime   bool `json:"is_runtime"`
	}
	var list []row
	l.json("GET", "/applications/"+app.UUID+"/envs", nil, &list)
	rows := map[string]row{}
	for _, r := range list {
		if !r.IsPreview {
			rows[r.Key] = r
		}
	}
	_, litTeam := rows["LIT_TEAM"]
	_, vault := rows["EXP_VAULT"]
	l.check("refused names were never created", !litTeam && !vault, "")
	for _, k := range kinds {
		r, ok := rows["EXP_"+k]
		l.check("EXP_"+k+" stored as Coolify's own variable", ok && !r.IsLiteral && !r.IsMultiline && r.IsBuildtime && r.IsRuntime, "")
		l.check("EXP_"+k+" stored as given", ok && eq(r.Value, refs[k]), "")
	}
	lit, ok := rows["LIT_COMMIT"]
	l.check("LIT_COMMIT stored literal", ok && lit.IsLiteral && lit.IsMultiline, "")
	remote, err := coolify{}.ReadRemote(liveCtx(), req)
	var rewrite []string
	for name := range remote.Rewrite {
		if strings.HasPrefix(name, "EXP_") || name == "LIT_COMMIT" {
			rewrite = append(rewrite, name)
		}
	}
	l.check("a repair would rewrite none of the adapter's rows", err == nil && len(rewrite) == 0, strings.Join(rewrite, ","))

	// Deploy once, then read what the build and the container got.
	var deploy struct {
		Deployments []struct {
			DeploymentUUID string `json:"deployment_uuid"`
		}
		DeploymentUUID string `json:"deployment_uuid"`
	}
	code = l.json("POST", "/applications/"+app.UUID+"/start?force=true", nil, &deploy)
	deployment := deploy.DeploymentUUID
	if len(deploy.Deployments) > 0 && deploy.Deployments[0].DeploymentUUID != "" {
		deployment = deploy.Deployments[0].DeploymentUUID
	}
	l.check("deploy queued", code == 200 && deployment != "", httpStatus(code))
	status := ""
	for i := 0; i < 120 && deployment != ""; i++ {
		var d struct{ Status string }
		l.json("GET", "/deployments/"+deployment, nil, &d)
		status = d.Status
		if status == "finished" || status == "failed" || status == "cancelled-by-user" || status == "cancelled" {
			break
		}
		time.Sleep(5 * time.Second)
	}
	l.check("deployment finished", status == "finished", status)
	var seen map[string]map[string]string
	for i := 0; i < 36; i++ {
		var lg struct{ Logs string }
		l.json("GET", "/applications/"+app.UUID+"/logs?lines=50", nil, &lg)
		seen = fixtureRecords(lg.Logs)
		if seen["BUILD"] != nil && seen["RUN"] != nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	l.check("fixture printed its build and runtime record", seen["BUILD"] != nil && seen["RUN"] != nil, "")

	// The shared variables have done their part: delete them now (the
	// rest goes in finish).
	var rest []liveResource
	var sharedVars []liveResource
	for _, r := range l.created {
		if strings.HasPrefix(r.Kind, "shared-") {
			sharedVars = append(sharedVars, r)
		} else {
			rest = append(rest, r)
		}
	}
	for _, r := range sharedVars {
		c, _ := l.do("DELETE", r.Delete, nil)
		l.check("shared variable ("+r.Kind+") deleted early", c == 200 || c == 204 || c == 404, httpStatus(c))
	}
	l.created = append(sharedVars, rest...) // finish deletes them again, already absent counting as done

	for _, phase := range []string{"BUILD", "RUN"} {
		env := seen[phase]
		p := strings.ToLower(phase)
		for _, k := range kinds {
			l.check(p+": EXP_"+k+" is exactly the expected value", env != nil && env["EXP_"+k] == expected[k], "")
			l.check(p+": TWIN_"+k+" is exactly the expected value", env != nil && env["TWIN_"+k] == expected[k], "")
		}
		l.check(p+": LIT_COMMIT arrives as text", env != nil && env["LIT_COMMIT"] == "$SOURCE_COMMIT", "")
	}
}

var fixtureLine = regexp.MustCompile(`(BUILD|RUN):([0-9a-f]*)\s*$`)

// fixtureRecords is the fixture's BUILD: and RUN: log lines, decoded into
// environment maps (canary values only).
func fixtureRecords(logs string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, line := range strings.Split(logs, "\n") {
		m := fixtureLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		b, err := hex.DecodeString(m[2])
		if err != nil {
			continue
		}
		env := map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && k != "" {
				env[k] = v
			}
		}
		out[m[1]] = env
	}
	return out
}
