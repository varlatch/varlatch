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
		`{{json (index .Config.Labels "com.docker.compose.oneoff")}} {{json .Name}} {{json .State.Status}} {{json .Mounts}}`
	volumeFormat = `{{json .Name}} {{json .CreatedAt}} {{json .Mountpoint}} {{json (index .Labels "com.docker.compose.project")}} {{json (index .Labels "com.docker.compose.volume")}} {{json (index .Labels "varlatch.migrate.id")}}`
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
type container struct {
	id, project, service, files, dir, status, mounts string
	volumes                                          []string
}

func (c container) print() {
	for _, v := range []string{c.project, c.service, c.files, c.dir, "False", "/" + c.id, c.status} {
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
	for _, svc := range []string{"postgres", "varlatchd", "convex-backend", "varlatch-web", "tailscale", "caddy"} {
		c := container{id: "g5-" + svc + "-1", project: s.Project, service: svc, files: strings.Join(files, ","), dir: s.Dir, status: "running", mounts: "[]"}
		if stopped(svc) {
			if down {
				continue
			}
			c.status = "exited"
		}
		mounts := []map[string]string{{"Type": "bind", "Source": "/x", "Destination": "/x"}}
		if t, ok := dataTargets[svc]; ok {
			c.volumes = []string{mounted(svc)}
			mounts = append(mounts, map[string]string{"Type": "volume", "Name": mounted(svc), "Destination": t})
		}
		for _, v := range map[string][]string{"tailscale": {"tailscale-state", "tailscale-socket"}, "caddy": {"caddy-data", "caddy-config"}}[svc] {
			c.volumes = append(c.volumes, s.Project+"_"+v)
			mounts = append(mounts, map[string]string{"Type": "volume", "Name": s.Project + "_" + v, "Destination": "/" + v})
		}
		b, _ := json.Marshal(mounts)
		c.mounts = string(b)
		out = append(out, c)
	}
	if b, err := os.ReadFile(state("stranger")); err == nil {
		dir := string(b)
		files := filepath.Join(dir, "docker-compose.yml")
		if dir == s.Dir {
			files = strings.Join([]string{filepath.Join(dir, s.Files[0]), filepath.Join(dir, "other.yml")}, ",")
		}
		out = append(out, container{id: "g5-stranger-1", project: s.Project, service: "postgres", files: files, dir: dir, status: "running", mounts: "[]"})
	}
	return out
}

// The dashboard's nginx resolves varlatchd once, at its start, and Docker
// gives a container that starts an address it may not have had: each start
// of varlatchd (of its sidecar, whose network it shares) is another, and a
// dashboard that resolved an earlier one answers 502.
func readdress(svc string) error {
	owner := "varlatchd"
	if sharedNamespace() {
		owner = "tailscale"
	}
	switch svc {
	case owner:
		f, err := os.OpenFile(state("varlatchd-address"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString("+")
		return err
	case "varlatch-web":
		b, _ := os.ReadFile(state("varlatchd-address"))
		return os.WriteFile(state("web-upstream"), b, 0o600)
	}
	return nil
}

// staleUpstream is whether the dashboard holds an earlier address.
func (w *world) staleUpstream() bool {
	now, _ := os.ReadFile(filepath.Join(w.stateDir, "varlatchd-address"))
	held, err := os.ReadFile(filepath.Join(w.stateDir, "web-upstream"))
	if err != nil {
		held = nil
	}
	return string(now) != string(held)
}

// containerGone is whether svc's container was removed (and not made again).
func containerGone(svc string) bool {
	return !slices.ContainsFunc(containers(), func(c container) bool { return c.service == svc })
}

// volumeUsers are the containers on a volume, running or not.
func volumeUsers(name string) []string {
	var out []string
	for _, c := range containers() {
		if slices.Contains(c.volumes, name) {
			out = append(out, c.id)
		}
	}
	return out
}

// readGateFile is the one-off container that reads the state volume's gate,
// asked for exactly so: never pulled, no network, the volume read only (as
// Docker, one that is not there is made, empty).
func readGateFile(args []string) int {
	volume, ok := strings.CutPrefix(args[12], "type=volume,source=")
	volume, ro := strings.CutSuffix(volume, ",target=/state,readonly,volume-nocopy")
	want := []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", args[12], "--entrypoint", "cat", args[15], "/state/maintenance.json"}
	if !ok || !ro || !slices.Equal(args, want) || args[15] != os.Getenv("VARLATCH_MIGRATE_PIN") {
		fmt.Fprintf(os.Stderr, "docker: unexpected %q\n", args)
		return 125
	}
	there := volumeThere(volume)
	if !there {
		_ = makeVolume(volume, nil)
	}
	g := readGate()
	if !there || g == nil || volume != ownVolume("varlatchd") {
		fmt.Fprintln(os.Stderr, "cat: /state/maintenance.json: No such file or directory")
		return 1
	}
	b, _ := json.Marshal(map[string]any{"id": g.ID, "kind": g.Kind, "phase": g.Phase, "expiresAt": nil, "archiveId": nil, "frozenPosition": "46"})
	fmt.Print(string(b))
	return 0
}

// printVolume is `docker volume inspect`'s answer (a volume made again by
// the test: another-<name>).
func printVolume(name string) {
	s := shape()
	key, _ := strings.CutPrefix(name, s.Project+"_")
	owner, _ := os.ReadFile(state("owner-" + name))
	at := "2026-01-01T00:00:00Z"
	if _, err := os.Stat(state("another-" + name)); err == nil {
		at = "2026-11-01T00:00:00Z"
	}
	for _, v := range []string{name, at, "/volumes/" + name, s.Project, key, string(owner)} {
		b, _ := json.Marshal(v)
		fmt.Print(string(b), " ")
	}
	fmt.Println()
}

// makeVolume is `docker volume create`: a name that is there is answered.
func makeVolume(name string, labels []string) error {
	if volumeThere(name) {
		return nil
	}
	f, err := os.OpenFile(state("volumes"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintln(f, name)
	for _, l := range labels {
		if v, ok := strings.CutPrefix(l, "varlatch.migrate.id="); ok {
			return os.WriteFile(state("owner-"+name), []byte(v), 0o600)
		}
	}
	return nil
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
		name := configuredVolume(svc)
		if b, err := os.ReadFile(state("renamed-" + svc)); err == nil {
			// The operator's change of the volume's name: in the files.
			name = string(b)
		}
		volumes[key] = map[string]any{"name": name}
	}
	services["varlatch-web"] = map[string]any{"container_name": "g5-varlatch-web-1"}
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
	for _, svc := range []string{"postgres", "convex-backend", "varlatchd", "varlatch-web"} {
		if err := setStopped(svc, false); err != nil {
			t.Fatal(err)
		}
	}
}

// recover does what migrate said: COMPOSE_FILE set, and the docker compose
// command, word for word.
func (w *world) recover(said string) {
	t := w.t
	t.Helper()
	m := regexp.MustCompile(`set (COMPOSE_FILE=\S+) in \S+; 2\. docker (compose .*? up -d --no-deps postgres convex-backend varlatchd) `).FindStringSubmatch(said)
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

// The operator's steps on Coolify's proxy. Both applications' containers
// keep the router their labels give them: while the TypeScript dashboard
// runs, the name may reach it, whatever Coolify's domain setting says.
// domainToGo is the domain set on the Go application and that deployed.
func (w *world) domainToGo() { w.flag("go-domain") }

// routeBack is the operator's route to the dashboard in the proxy, as
// migrate says it for the journal's migration (its id on every answer);
// routeAway removes it.
func (w *world) routeBack() {
	w.t.Helper()
	var j struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(mustRead(w.t, filepath.Join(w.compose, "migration.json")), &j); err != nil || j.ID == "" {
		w.t.Fatalf("no migration to route back: %v", err)
	}
	if err := os.WriteFile(filepath.Join(w.stateDir, "route-ts"), []byte(j.ID), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) routeAway() {
	w.t.Helper()
	if err := os.Remove(filepath.Join(w.stateDir, "route-ts")); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) flag(name string) {
	w.t.Helper()
	if err := os.WriteFile(filepath.Join(w.stateDir, name), nil, 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) has(name string) bool {
	_, err := os.Stat(filepath.Join(w.stateDir, name))
	return err == nil
}

// Coolify's layout, the TypeScript application deployed again while the
// reverse is in its transfer: it answers at the address as the same
// installation and release, from the retained volumes. Each --resume
// refuses, Go running and isolated, nothing of either side changed; what
// migrate says puts it back on the fresh volumes, and the reverse
// finishes. Then --finish --delete-old-data: refused, before its archive,
// while the installation is not on them; it removes the recorded volumes,
// and Go's copy only after them.
func TestG5CoolifyRedeployed(t *testing.T) {
	w := migratedWorld(t, false, true)
	old := w.oldDB()
	w.routeBack()
	if code := w.rollback("entered rollback-transfer", "--rollback"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expectReverse("killed in the transfer", rbState{"rollback-transfer", "rollback-transfer", "none", "", true, true, true})
	w.redeploy()
	for range 2 {
		before := len(w.calls("docker-calls"))
		if code := w.rollback("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "is not on the fresh volumes the reverse rebuilt it on") ||
			!strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go was not stopped") {
			t.Fatalf("--resume once deployed again: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		for _, c := range w.calls("docker-calls")[before:] {
			if !strings.HasPrefix(c, "ps ") && !strings.HasPrefix(c, "inspect ") && !strings.HasPrefix(c, "compose config ") && !strings.HasPrefix(c, "volume inspect ") {
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
		if err := os.WriteFile(filepath.Join(w.compose, "other.yml"), []byte("services: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		refusesOf := func(what, dir, want string, run func() int) {
			t.Helper()
			if err := os.WriteFile(stranger, []byte(dir), 0o600); err != nil {
				t.Fatal(err)
			}
			w.useState()
			before, runs := len(w.calls("docker-calls")), w.goRuns()
			src, tgt := w.phases()
			code := run()
			out := string(w.outputs[len(w.outputs)-1])
			if code != 1 || !strings.Contains(out, want) {
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
		refuses := func(what string, run func() int) {
			t.Helper()
			refusesOf(what, "/srv/live", "has a postgres container made from /srv/live (files /srv/live/docker-compose.yml), not from "+w.compose, run)
			// Of this directory, by another overlay.
			refusesOf(what+", another overlay", w.compose, filepath.Join(w.compose, "other.yml"), run)
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
			w.domainToGo()
			code = w.run("", "--resume")
		}
		if code != 0 {
			t.Fatalf("the migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		refuses("--rollback", func() int { return w.rollback("", "--rollback") })
		if coolify {
			w.routeBack()
		}
		if code := w.rollback("entered rollback-imported", "--rollback"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		refuses("--resume of the reverse", func() int { return w.rollback("", "--resume") })
		refuses("--abort of the reverse", func() int { return w.rollback("", "--abort") })
		if code := w.rollback("", "--abort"); code != 0 {
			t.Fatalf("--abort of the reverse: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if coolify {
			w.routeAway()
		}
		w.expectReverse("undone", undoneState)
		if res, err := http.Get(w.origin + "/v1/meta"); err == nil {
			res.Body.Close()
		}
		w.noSecrets()
	}
}

// removeContainers removes every container of the installation, as a prune
// or an orchestrator's Stop does: its volumes and its directory stay.
func (w *world) removeContainers() {
	w.t.Helper()
	w.useState()
	for _, svc := range []string{"varlatchd", "varlatch-web", "postgres", "convex-backend", "caddy", "tailscale"} {
		if svc == "tailscale" && sidecarPID() > 0 {
			if err := stopSidecar(); err != nil {
				w.t.Fatal(err)
			}
		}
		if err := setStopped(svc, true); err != nil {
			w.t.Fatal(err)
		}
	}
	w.flag("down")
}

// The old installation's containers, and its images, gone during the
// window: the journal, the Compose files and the volumes are what it is
// known by. --rollback makes it again and goes through, --resume undoes an
// interrupted one, --finish --delete-old-data archives and removes the
// recorded volumes; a volume that is not the recorded one is refused, as is
// an image that cannot be pulled, each before anything is done.
func TestG5ContainersGone(t *testing.T) {
	for _, coolify := range []bool{false, true} {
		name := map[bool]string{false: "stock", true: "coolify"}[coolify]
		project := map[bool]string{false: "g5-installation", true: coolifyApp}[coolify]
		gone := func(t *testing.T) *world {
			w := migratedWorld(t, false, coolify)
			w.removeContainers()
			if coolify {
				w.routeBack()
			}
			return w
		}
		refused := func(t *testing.T, w *world, why string) {
			t.Helper()
			before := len(w.calls("docker-calls"))
			code := w.rollback("", "--rollback")
			out := string(w.outputs[len(w.outputs)-1])
			if code != 1 || !strings.Contains(out, why) || !strings.Contains(out, "nothing was done") {
				t.Fatalf("--rollback: %d\n%s", code, out)
			}
			for _, c := range w.calls("docker-calls")[before:] {
				for _, p := range []string{"compose up", "compose start", "compose stop", "compose run", "volume create", "volume rm"} {
					if strings.HasPrefix(c, p) {
						t.Errorf("ran %q", c)
					}
				}
			}
			if s, d := w.phases(); s != "open" || d != "open" || !w.goRuns() {
				t.Errorf("the journals %s / %s, Go runs %v", s, d, w.goRuns())
			}
		}
		t.Run(name+" rollback", func(t *testing.T) {
			w := gone(t)
			old := w.oldDB()
			w.flag("images-gone")
			if code := w.rollback("", "--rollback"); code != 0 {
				t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.expectReverse("rolled back", rolledBackState)
			calls := w.calls("docker-calls")
			barrier, pulled := len(calls), slices.Index(calls, "pull -q ghcr.io/x/varlatch-web@sha256:bb")
			for i, c := range calls {
				if strings.HasPrefix(c, "volume create") {
					barrier = min(barrier, i)
				}
			}
			if pulled < 0 || pulled > barrier {
				t.Errorf("the images were pulled at %d, the rebuild began at %d", pulled, barrier)
			}
			if w.oldDB() != old {
				t.Error("the retained pre-migration database changed")
			}
			w.noSecrets()
			// The retained volumes are the migration's: --finish removes them.
			w.withRemote()
			if code := w.finish("", "--delete-old-data"); code != 0 {
				t.Fatalf("--finish --delete-old-data: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			if vols, _ := w.removed(); !slices.Equal(vols, []string{project + "_postgres-data", project + "_convex-data"}) {
				t.Errorf("removed %v", vols)
			}
		})
		t.Run(name+" refused", func(t *testing.T) {
			w := gone(t)
			w.flag("images-gone")
			w.flag("pull-fails")
			refused(t, w, "is not on this host and could not be pulled")
			for _, f := range []string{"images-gone", "pull-fails"} {
				if err := os.Remove(filepath.Join(w.stateDir, f)); err != nil {
					t.Fatal(err)
				}
			}
			another := filepath.Join(w.stateDir, "another-"+project+"_postgres-data")
			w.flag(filepath.Base(another))
			refused(t, w, "is not the one the migration read")
			if err := os.Remove(another); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(w.stateDir, "renamed-postgres"), []byte(project+"_other"), 0o600); err != nil {
				t.Fatal(err)
			}
			refused(t, w, "and the migration read the installation on "+project+"_postgres-data")
		})
		for _, point := range []string{"entered rollback", "rollback rebuilt", "entered rollback-checked"} {
			t.Run(name+" killed at "+point, func(t *testing.T) {
				w := migratedWorld(t, false, coolify)
				if coolify {
					w.routeBack()
				}
				if code := w.rollback(point, "--rollback"); code != -1 {
					t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.removeContainers()
				if code := w.rollback("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the reverse was undone") {
					t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				if coolify {
					w.routeAway()
				}
				w.expectReverse("undone", undoneState)
				w.noSecrets()
			})
		}
		t.Run(name+" finish", func(t *testing.T) {
			w := migratedWorld(t, false, coolify)
			w.removeContainers()
			code := w.finish("", "--delete-old-data")
			out := string(w.outputs[len(w.outputs)-1])
			if code != 0 || !slices.ContainsFunc(w.calls("ts-calls"), func(c string) bool { return strings.HasPrefix(c, "admin backup create") }) {
				t.Fatalf("--finish --delete-old-data: %d\n%s", code, out)
			}
			vols, _ := w.removed()
			if coolify {
				if len(vols) != 0 || !strings.Contains(out, "open the TypeScript application") {
					t.Errorf("removed %v\n%s", vols, out)
				}
			} else if !slices.Contains(vols, project+"_postgres-data") || !slices.Contains(vols, project+"_convex-data") {
				t.Errorf("removed %v", vols)
			}
		})
	}
}

// loseGate takes the TypeScript installation's gate away, its Postgres and
// Convex volumes kept: the whole state volume, that volume made again
// empty, or its file; or puts another gate there. The undo puts it back.
func (w *world) loseGate(how string) (undo func()) {
	w.t.Helper()
	w.useState()
	path := filepath.Join(w.stateDir, "gate.json")
	gate := mustRead(w.t, path)
	removed, another := filepath.Join(w.stateDir, "removed-volumes"), filepath.Join(w.stateDir, "another-"+ownVolume("varlatchd"))
	was, _ := os.ReadFile(removed)
	var err error
	switch how {
	case "volume", "volume made again":
		if err = os.Remove(path); err == nil && how == "volume" {
			err = os.WriteFile(removed, append(slices.Clone(was), []byte(ownVolume("varlatchd")+"\n")...), 0o600)
		} else if err == nil {
			err = os.WriteFile(another, nil, 0o600)
		}
	case "volume made again, the gate copied":
		err = os.WriteFile(another, nil, 0o600)
	case "file":
		err = os.Remove(path)
	case "another gate":
		err = os.WriteFile(path, []byte(`{"kind":"migrated-out","id":"gate-of-another","phase":"paused"}`), 0o600)
	case "the barrier":
		err = os.WriteFile(path, []byte(strings.Replace(string(gate), "migrated-out", "migration", 1)), 0o600)
	default:
		w.t.Fatal(how)
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return func() {
		for p, b := range map[string][]byte{path: gate, removed: was} {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				w.t.Fatal(err)
			}
		}
		_ = os.Remove(another)
	}
}

var gatesLost = []string{"volume", "volume made again", "volume made again, the gate copied", "file", "another gate", "the barrier"}

// startedNothing refuses calls since before that start, make or remove
// anything.
func (w *world) startedNothing(when string, before int) {
	w.t.Helper()
	for _, c := range w.calls("docker-calls")[before:] {
		for _, p := range []string{"compose up", "compose start", "compose restart", "compose run", "compose exec", "volume create", "volume rm"} {
			if strings.HasPrefix(c, p) {
				w.t.Errorf("%s: ran %q", when, c)
			}
		}
	}
}

// The TypeScript installation's gate lost in the window, Postgres and
// Convex kept (a server that finds no gate takes requests): the way back on
// Coolify, which starts that server before Go's barrier, refuses before it
// starts anything, with its containers gone or only stopped; Go serves on.
// With the gate back it goes through.
func TestG5TheGateLost(t *testing.T) {
	for _, how := range gatesLost {
		for _, gone := range []bool{true, false} {
			t.Run(how+map[bool]string{true: ", containers gone", false: ", containers there"}[gone], func(t *testing.T) {
				w := migratedWorld(t, false, true)
				if gone {
					w.removeContainers()
				} else {
					w.useState()
					for _, svc := range []string{"varlatchd", "postgres", "convex-backend"} {
						if err := setStopped(svc, true); err != nil {
							t.Fatal(err)
						}
					}
				}
				old := w.oldDB()
				w.routeBack()
				back := w.loseGate(how)
				before := len(w.calls("docker-calls"))
				code := w.rollback("", "--rollback")
				out := string(w.outputs[len(w.outputs)-1])
				if code != 1 || !strings.Contains(out, "nothing was started") || !strings.Contains(out, "Go serves on") {
					t.Fatalf("--rollback: %d\n%s", code, out)
				}
				w.startedNothing("refused", before)
				if s, d := w.phases(); s != "open" || d != "open" || !w.goRuns() || !w.stopped("varlatchd") || !w.stopped("postgres") || !w.has("web-stopped") || w.oldDB() != old {
					t.Fatalf("refused: the journals %s / %s, Go runs %v, the TypeScript side stopped %v %v %v", s, d, w.goRuns(), w.stopped("varlatchd"), w.stopped("postgres"), w.has("web-stopped"))
				}
				if how == "volume" && gone {
					w.useState()
					if volumeThere(ownVolume("varlatchd")) {
						t.Error("the state volume was made by looking for it")
					}
				}
				back()
				if code := w.rollback("", "--rollback"); code != 0 {
					t.Fatalf("--rollback, the gate back: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.expectReverse("rolled back", rolledBackState)
				w.noSecrets()
			})
		}
	}
	// Lost once its servers run, before the dashboard: not started, undone,
	// and those stopped again, on this run's own and on --resume and --abort
	// of one killed there.
	for _, how := range []string{"--resume", "--abort"} {
		for _, running := range []bool{false, true} {
			t.Run(fmt.Sprintf("killed, its servers started, %s, running before %v", how, running), func(t *testing.T) {
				w := migratedWorld(t, false, true)
				if !running {
					w.removeContainers()
				}
				w.routeBack()
				if code := w.rollback("rollback gated started", "--rollback"); code != -1 {
					t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				if w.stopped("varlatchd") || w.stopped("postgres") || !w.has("web-stopped") {
					t.Fatalf("killed with varlatchd stopped %v, postgres %v, the dashboard %v", w.stopped("varlatchd"), w.stopped("postgres"), w.has("web-stopped"))
				}
				if code := w.rollback("", how); (how == "--abort") != (code == 0) {
					t.Fatalf("%s: %d\n%s", how, code, w.outputs[len(w.outputs)-1])
				}
				w.routeAway()
				if s, d := w.phases(); s != "open" || d != "open" || !w.goRuns() || !w.has("web-stopped") || w.stopped("varlatchd") == running || w.stopped("postgres") == running || w.stopped("convex-backend") == running {
					t.Errorf("the journals %s / %s, Go runs %v, stopped: the dashboard %v, varlatchd %v, postgres %v, convex %v", s, d, w.goRuns(), w.has("web-stopped"), w.stopped("varlatchd"), w.stopped("postgres"), w.stopped("convex-backend"))
				}
				w.expect(how, "open", "open", "target-open", "migrated-out")
			})
		}
	}
	// The final archive's server.
	for _, how := range gatesLost {
		t.Run(how+", --finish", func(t *testing.T) {
			w := migratedWorld(t, false, true)
			w.removeContainers()
			back := w.loseGate(how)
			before := len(w.calls("docker-calls"))
			if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was removed") {
				t.Fatalf("--finish --delete-old-data: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.startedNothing("refused", before)
			if s, d := w.phases(); s != "open" || d != "open" || !w.stopped("varlatchd") || !w.stopped("postgres") {
				t.Errorf("the journals %s / %s", s, d)
			}
			back()
			if code := w.finish("", "--delete-old-data"); code != 0 {
				t.Fatalf("the gate back: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
		})
	}
}

// The gate an undone reverse made (its import had lifted the migration's)
// is the one the next reverse asks for.
func TestG5TheGateOfAnUndo(t *testing.T) {
	w := migratedWorld(t, false, true)
	w.useState()
	first := readGate().ID
	w.routeBack()
	if code := w.rollback("entered rollback-checked", "--rollback"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if code := w.rollback("", "--abort"); code != 0 {
		t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.useState()
	if g := readGate(); g == nil || g.Kind != "migrated-out" || g.ID == first {
		t.Fatalf("the gate after the undo: %+v, the migration's %s", g, first)
	}
	// Not the migration's own any more.
	made := mustRead(t, filepath.Join(w.stateDir, "gate.json"))
	if err := os.WriteFile(filepath.Join(w.stateDir, "gate.json"), []byte(strings.Replace(string(made), readGate().ID, first, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was started") {
		t.Fatalf("the first gate: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if err := os.WriteFile(filepath.Join(w.stateDir, "gate.json"), made, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("--rollback again: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expectReverse("rolled back", rolledBackState)
	w.noSecrets()
}

// A Docker Compose too old for the way back: a new migration and --rollback
// say so before anything.
func TestG5TheComposeVersion(t *testing.T) {
	const said = "Docker Compose 2.31.0 is too old: varlatch migrate needs 2.32.0 or later"
	for _, coolify := range []bool{false, true} {
		w := newWorld(t, false)
		w.coolify = coolify
		if coolify {
			w.coolifyLayout()
		}
		old := filepath.Join(w.stateDir, "compose-version")
		if err := os.WriteFile(old, []byte("2.31.0"), 0o600); err != nil {
			t.Fatal(err)
		}
		w.useState()
		if code := w.run(""); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), said) {
			t.Fatalf("a new migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.startedNothing("a new migration", 0)
		if err := os.Remove(old); err != nil {
			t.Fatal(err)
		}
		w = migratedWorld(t, false, coolify)
		if err := os.WriteFile(filepath.Join(w.stateDir, "compose-version"), []byte("2.31.0"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := len(w.calls("docker-calls"))
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), said) || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was done") {
			t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.startedNothing("--rollback", before)
		if s, d := w.phases(); s != "open" || d != "open" || !w.goRuns() {
			t.Errorf("the journals %s / %s", s, d)
		}
	}
}
