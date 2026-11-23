// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The stand-in's Compose project, containers and volumes, as `varlatch
// migrate` (internal/migrate, compose_project.go) reads and names them.

// composeShape is a world's Compose project (its state's shape.json).
type composeShape struct {
	Project string   `json:"project"`
	Dir     string   `json:"dir"`
	Files   []string `json:"files"`
	// Prefix is put before each volume's key, as Coolify does.
	Prefix string `json:"prefix"`
}

func shape() composeShape {
	var s composeShape
	b, err := os.ReadFile(state("shape.json"))
	if err != nil || json.Unmarshal(b, &s) != nil {
		fmt.Fprintln(os.Stderr, "the stand-in has no shape.json")
		os.Exit(1)
	}
	return s
}

func (w *world) writeShape(s composeShape) {
	w.t.Helper()
	b, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(w.stateDir, "shape.json"), b, 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// coolifyApp is the application's id in Coolify's layout.
const coolifyApp = "abcdefghijklmnopqrstuvwx"

// coolifyLayout makes the installation's directory as Coolify's: the
// repository's docker-compose.yml, which names another project, Coolify's
// own file, and the one the containers run from, its volumes' keys
// prefixed with the application's id.
func (w *world) coolifyLayout() {
	w.t.Helper()
	const runs = "docker-compose.coolify-tailscale.yml"
	for name, text := range map[string]string{"docker-compose.yml": "name: varlatch\nservices: {}\n", "docker-compose.yaml": "services: {}\n", runs: "services: {}\n"} {
		if err := os.WriteFile(filepath.Join(w.compose, name), []byte(text), 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	w.writeShape(composeShape{Project: coolifyApp, Dir: w.compose, Files: []string{runs}, Prefix: coolifyApp + "_"})
}

// The formats migrate inspects with (internal/migrate: containersFormat,
// volumeFormat).
const (
	containersFormat = `{{json (index .Config.Labels "com.docker.compose.project")}} {{json (index .Config.Labels "com.docker.compose.service")}} ` +
		`{{json (index .Config.Labels "com.docker.compose.project.config_files")}} {{json (index .Config.Labels "com.docker.compose.project.working_dir")}} ` +
		`{{json (index .Config.Labels "com.docker.compose.oneoff")}} {{json .State.Status}} {{json .Mounts}}`
	volumeFormat = `{{json .Name}} {{json .CreatedAt}} {{json (index .Labels "com.docker.compose.project")}}`
)

const overrideFile = "docker-compose.varlatch-rollback.yml"

// withOverride is whether this compose command names migrate's file.
var withOverride bool

// composeArgs takes a compose command's project from it, refusing one that
// does not name the installation's own: never what plain `docker compose`
// finds in a directory.
func composeArgs(args []string) ([]string, error) {
	if len(args) == 0 || args[0] != "compose" {
		return args, nil
	}
	s := shape()
	var project, dir string
	var files []string
	rest := args[1:]
	for len(rest) > 0 {
		if strings.HasPrefix(rest[0], "-") && len(rest) == 1 {
			break
		}
		switch rest[0] {
		case "--project-name":
			project = rest[1]
		case "--project-directory":
			dir = rest[1]
		case "-f":
			files = append(files, rest[1])
		default:
			var want []string
			for _, f := range s.Files {
				want = append(want, filepath.Join(s.Dir, f))
			}
			if n := len(files); n > 0 && filepath.Base(files[n-1]) == overrideFile {
				if _, err := os.Stat(files[n-1]); err != nil {
					return nil, err
				}
				withOverride, files = true, files[:n-1]
			}
			if project != s.Project || dir != s.Dir || !slices.Equal(files, want) {
				return nil, fmt.Errorf("a compose command on the project %q of %q (%q), not the installation's %q of %q (%q)", project, dir, files, s.Project, s.Dir, want)
			}
			return append([]string{"compose"}, rest...), nil
		}
		rest = rest[2:]
	}
	return nil, errors.New("a compose command without a verb")
}

var dataTargets = map[string]string{"postgres": "/var/lib/postgresql/data", "convex-backend": "/convex/data", "varlatchd": "/var/lib/varlatch"}

func dataKey(svc string) string {
	return map[string]string{"postgres": "postgres-data", "convex-backend": "convex-data", "varlatchd": "varlatch-state"}[svc]
}

// ownVolume is the volume the installation's own Compose files give svc.
func ownVolume(svc string) string { return shape().Project + "_" + dataKey(svc) }

// configuredVolume is the one this command's files give it: migrate's
// file's, when they name it.
func configuredVolume(svc string) string {
	if withOverride {
		b, _ := os.ReadFile(filepath.Join(shape().Dir, overrideFile))
		lines := strings.Split(string(b), "\n")
		for i, l := range lines {
			if strings.TrimSpace(l) == shape().Prefix+dataKey(svc)+":" && i+1 < len(lines) {
				if n, ok := strings.CutPrefix(strings.TrimSpace(lines[i+1]), "name: "); ok {
					return n
				}
			}
		}
	}
	return ownVolume(svc)
}

// mounted is the volume svc's container was made with.
func mounted(svc string) string {
	if b, err := os.ReadFile(state("mount-" + svc)); err == nil {
		return string(b)
	}
	return ownVolume(svc)
}

// mountAsConfigured makes again, as `up -d` does, the data services' containers
// this command names (or, without --no-deps, varlatchd's dependencies).
func mountAsConfigured(args []string) error {
	if slices.Contains(args, "--no-recreate") {
		if _, err := os.Stat(state("down")); err != nil {
			return nil
		}
	}
	names := args
	if !slices.Contains(args, "--no-deps") && (slices.Contains(args, "varlatchd") || slices.Contains(args, "varlatch-web")) {
		names = append(slices.Clone(args), "postgres", "convex-backend")
	}
	for _, svc := range []string{"postgres", "convex-backend"} {
		if slices.Contains(names, svc) {
			if err := os.WriteFile(state("mount-"+svc), []byte(configuredVolume(svc)), 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// container is one of the host's Compose containers.
type container struct{ id, project, service, files, dir, status, mounts string }

func (c container) print() {
	for _, v := range []string{c.project, c.service, c.files, c.dir, "False", c.status} {
		b, _ := json.Marshal(v)
		fmt.Print(string(b), " ")
	}
	fmt.Println(c.mounts)
}

// containers are the installation's, and a stranger's of the same project
// made from another directory (stranger: its path).
func containers() []container {
	s := shape()
	var files []string
	for _, f := range s.Files {
		files = append(files, filepath.Join(s.Dir, f))
	}
	var out []container
	down := false
	if _, err := os.Stat(state("down")); err == nil {
		down = true
	}
	services := []string{"postgres", "varlatchd", "convex-backend", "varlatch-web"}
	if sharedNamespace() {
		services = append(services, "tailscale")
	}
	for _, svc := range services {
		c := container{id: "g5-" + svc + "-1", project: s.Project, service: svc, files: strings.Join(files, ","), dir: s.Dir, status: "running", mounts: "[]"}
		if stopped(svc) {
			if down {
				continue
			}
			c.status = "exited"
		}
		if t, ok := dataTargets[svc]; ok {
			c.mounts = fmt.Sprintf(`[{"Type":"bind","Source":"/x","Destination":"/x"},{"Type":"volume","Name":%q,"Destination":%q}]`, mounted(svc), t)
		}
		out = append(out, c)
	}
	if b, err := os.ReadFile(state("stranger")); err == nil {
		dir := string(b)
		out = append(out, container{"g5-stranger-1", s.Project, "postgres", filepath.Join(dir, "docker-compose.yml"), dir, "running", "[]"})
	}
	return out
}

// volumeUsers are the containers on a volume, running or not.
func volumeUsers(name string) []string {
	var out []string
	for _, c := range containers() {
		if dataTargets[c.service] != "" && c.mounts != "[]" && mounted(c.service) == name {
			out = append(out, c.id)
		}
	}
	return out
}

// volumeThere is the stand-in's Docker volumes: the project's own (its
// data, varlatch-state, Tailscale's and Caddy's), until removed, and the
// reverse's fresh ones, once made. Another project's are not there.
func volumeThere(name string) bool {
	if vols, _ := os.ReadFile(state("volumes")); slices.Contains(strings.Fields(string(vols)), name) {
		return true
	}
	removed, _ := os.ReadFile(state("removed-volumes"))
	base, ok := strings.CutPrefix(name, shape().Project+"_")
	return ok && !slices.Contains(strings.Fields(string(removed)), name) &&
		slices.Contains([]string{"postgres-data", "convex-data", "varlatch-state", "tailscale-state", "tailscale-socket", "caddy-data", "caddy-config"}, base)
}

// printConfig is `docker compose config --no-interpolate --format json`,
// what migrate reads of it: the project, the data services' volumes and
// their names, and more's services.
func printConfig(more map[string]map[string]any) {
	s := shape()
	services, volumes := map[string]any{}, map[string]any{}
	for svc, m := range more {
		services[svc] = m
	}
	for svc, target := range dataTargets {
		m := more[svc]
		if m == nil {
			m = map[string]any{}
		}
		key := s.Prefix + dataKey(svc)
		m["volumes"] = []any{map[string]any{"type": "volume", "source": key, "target": target, "volume": map[string]any{}}}
		services[svc] = m
		volumes[key] = map[string]any{"name": configuredVolume(svc)}
	}
	if s.Prefix != "" {
		services["varlatch-migrate"] = map[string]any{"networks": map[string]any{s.Project: nil}}
	}
	out, _ := json.Marshal(map[string]any{"name": s.Project, "services": services, "volumes": volumes})
	fmt.Println(string(out))
}

// redeploy is Coolify deploying the TypeScript application again: its
// containers made from its own file, .env without COMPOSE_FILE (the
// retained volumes, whose database answers as the same installation and
// release).
func (w *world) redeploy() {
	t := w.t
	t.Helper()
	w.useState()
	p := filepath.Join(w.compose, ".env")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, regexp.MustCompile(`(?m)^COMPOSE_FILE=.*\n`).ReplaceAll(b, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"postgres", "convex-backend"} {
		if err := os.WriteFile(filepath.Join(w.stateDir, "mount-"+svc), []byte(ownVolume(svc)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// recover does what migrate said: COMPOSE_FILE set, and the docker compose
// command, word for word.
func (w *world) recover(said string) {
	t := w.t
	t.Helper()
	m := regexp.MustCompile(`set (COMPOSE_FILE=\S+) in \S+; 2\. in \S+: docker (compose .*? up -d --no-deps postgres convex-backend varlatchd) `).FindStringSubmatch(said)
	if m == nil {
		t.Fatalf("no recovery said:\n%s", said)
	}
	f, err := os.OpenFile(filepath.Join(w.compose, ".env"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(m[1] + "\n")
	f.Close()
	// Not yet: .env names the file, the containers are as they were.
	if code := w.rollback("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "postgres runs on "+ownVolume("postgres")+", not on the fresh volume") {
		t.Fatalf("--resume with .env put back, the containers not: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	cmd := exec.Command(filepath.Join(shared.fakebin, "docker"), strings.Fields(m[2])...)
	cmd.Dir = w.compose
	cmd.Env = append(os.Environ(), "G5_STATE="+w.stateDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v\n%s", m[2], err, out)
	}
}

// Coolify's layout, the TypeScript application deployed again while the
// reverse waits for the domain: it answers at the address as the same
// installation and release, from the retained volumes. Each --resume
// refuses, Go running and isolated, nothing of either side changed; what
// migrate says puts it back on the fresh volumes, and the reverse
// finishes. Then --finish --delete-old-data: refused, before its archive,
// while the installation is not on them; it removes the recorded volumes,
// and Go's copy only after them.
func TestG5CoolifyRedeployed(t *testing.T) {
	w := migratedWorld(t, false, true)
	old := w.oldDB()
	if code := w.rollback("", "--rollback"); code != 75 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "do not Deploy or Redeploy the TypeScript application") {
		t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	waiting := rbState{"rollback-transfer", "rollback-transfer", "target-gated", "", true, true, true}
	w.expectReverse("waiting for the move", waiting)
	w.redeploy()
	if err := os.Remove(filepath.Join(w.stateDir, "web-stopped")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		before := len(w.calls("docker-calls"))
		if code := w.rollback("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "is not on the fresh volumes the reverse rebuilt it on") ||
			!strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go was not stopped") {
			t.Fatalf("--resume once deployed again: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		for _, c := range w.calls("docker-calls")[before:] {
			if !strings.HasPrefix(c, "ps ") && !strings.HasPrefix(c, "inspect ") && !strings.HasPrefix(c, "compose config ") {
				t.Errorf("ran %q", c)
			}
		}
		w.expectReverse("refused", rbState{"rollback-transfer", "rollback-transfer", "source", "", true, false, false})
	}
	w.recover(string(w.outputs[len(w.outputs)-1]))
	if code := w.rollback("", "--resume"); code != 0 {
		t.Fatalf("--resume on the fresh volumes: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expectReverse("rolled back", rolledBackState)
	if w.oldDB() != old {
		t.Error("the retained pre-migration database changed")
	}

	fresh, _ := w.volume()
	bucket := w.withRemote()
	w.redeploy()
	if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "give postgres the volume "+coolifyApp+"_postgres-data") ||
		!strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was done") {
		t.Fatalf("--delete-old-data once deployed again: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	// What it left: no archive, Go's copy, every volume.
	gone := func() bool { _, err := os.Stat(filepath.Join(w.data, "varlatch.db")); return os.IsNotExist(err) }
	if vols, _ := w.removed(); len(vols) != 0 || gone() || len(bucket.objects) != 0 {
		t.Errorf("after the refusal: removed %v, Go's copy gone %v, %d archives", vols, gone(), len(bucket.objects))
	}
	// Deployed again after the archive, between it and the removal: the
	// resume refuses, Go's copy kept.
	w.recoverFinish()
	if code := w.finish("finish archived", "--delete-old-data"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.redeploy()
	if code := w.finish("", "--delete-old-data"); code != 1 {
		t.Fatalf("--finish again: %d", code)
	}
	if vols, _ := w.removed(); len(vols) != 0 || gone() {
		t.Errorf("after the second refusal: removed %v, Go's copy gone %v", vols, gone())
	}
	w.recoverFinish()
	if code := w.finish("finish retained removed", "--delete-old-data"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	want := []string{coolifyApp + "_postgres-data", coolifyApp + "_convex-data"}
	if vols, _ := w.removed(); !slices.Equal(vols, want) || gone() {
		t.Errorf("the retained volumes first: removed %v, Go's copy gone %v", vols, gone())
	}
	if code := w.resumeFinish(); code != 0 {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if vols, _ := w.removed(); !slices.Equal(vols, want) || slices.Contains(vols, fresh) || !gone() {
		t.Errorf("finished: removed %v, Go's copy gone %v", vols, gone())
	}
	w.noSecrets()
}

// recoverFinish puts the installation back on the fresh volumes (the
// refusal's recovery, checked in recover).
func (w *world) recoverFinish() {
	t := w.t
	t.Helper()
	w.useState()
	if err := os.WriteFile(filepath.Join(w.compose, ".env"), append(mustRead(t, filepath.Join(w.compose, ".env")), []byte("COMPOSE_FILE="+shape().Files[0]+":"+overrideFile+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	withOverride = true
	defer func() { withOverride = false }()
	for _, svc := range []string{"postgres", "convex-backend"} {
		if err := os.WriteFile(filepath.Join(w.stateDir, "mount-"+svc), []byte(configuredVolume(svc)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Another directory's container of the same project on the host: every
// command refuses before it does anything, in a new migration, in a
// --resume and --abort of one held at its barrier, in a --rollback and in
// its --resume; once it is gone each goes on.
func TestG5AnotherInstallationOfTheProject(t *testing.T) {
	for _, coolify := range []bool{false, true} {
		w := newWorld(t, false)
		w.coolify = coolify
		if coolify {
			w.coolifyLayout()
		}
		w.useState()
		stranger := filepath.Join(w.stateDir, "stranger")
		refuses := func(what string, run func() int) {
			t.Helper()
			if err := os.WriteFile(stranger, []byte("/srv/live"), 0o600); err != nil {
				t.Fatal(err)
			}
			w.useState()
			before, runs := len(w.calls("docker-calls")), w.goRuns()
			src, tgt := w.phases()
			code := run()
			out := string(w.outputs[len(w.outputs)-1])
			if code != 1 || !strings.Contains(out, "has a postgres container made from /srv/live (files /srv/live/docker-compose.yml), not from "+w.compose) {
				t.Fatalf("%s: %d\n%s", what, code, out)
			}
			for _, c := range w.calls("docker-calls")[before:] {
				if !strings.HasPrefix(c, "ps ") && !strings.HasPrefix(c, "inspect ") {
					t.Errorf("%s: ran %q", what, c)
				}
			}
			if s, d := w.phases(); s != src || d != tgt || w.goRuns() != runs {
				t.Errorf("%s: the journals %s / %s, then %s / %s; Go runs %v, then %v", what, src, tgt, s, d, runs, w.goRuns())
			}
			if err := os.Remove(stranger); err != nil {
				t.Fatal(err)
			}
		}
		refuses("a new migration", func() int { return w.run("") })
		if code := w.run("barrier held"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		refuses("--resume at the barrier", func() int { return w.run("", "--resume") })
		refuses("--abort at the barrier", func() int { return w.run("", "--abort") })
		if code := w.run("", "--abort"); code != 0 {
			t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		code := w.run("")
		if coolify && code == 75 {
			refuses("--resume in the transfer", func() int { return w.run("", "--resume") })
			if err := os.WriteFile(filepath.Join(w.stateDir, "web-stopped"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			code = w.run("", "--resume")
		}
		if code != 0 {
			t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		refuses("--rollback", func() int { return w.rollback("", "--rollback") })
		if code := w.rollback("entered rollback-imported", "--rollback"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		refuses("--resume of the reverse", func() int { return w.rollback("", "--resume") })
		refuses("--abort of the reverse", func() int { return w.rollback("", "--abort") })
		if code := w.rollback("", "--abort"); code != 0 {
			t.Fatalf("--abort of the reverse: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("undone", undoneState)
		if res, err := http.Get(w.origin + "/v1/meta"); err == nil {
			res.Body.Close()
		}
		w.noSecrets()
	}
}
