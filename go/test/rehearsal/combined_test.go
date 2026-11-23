// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The combined case (VL_RH_INGRESS=combined, B3 on production's topology):
// the lab Coolify and the tailscale sidecar together. The source is an app
// of the release's docker-compose.coolify-tailscale.yml (varlatchd in the
// sidecar's network), the target the Go app of infra/coolify's
// varlatchd.compose.yml. What differs from production, all of it recorded:
//
//   - the control server is the run's Headscale, not Tailscale's, published
//     on docker0's address, so the sidecar is given its login server and its
//     CA. A Coolify variable would reach it by env_file only, which migrate
//     does not read the control server from, and a CA for every service
//     stops Convex: so both are in a copy of the release's infra/, which the
//     run serves over Git (two settings and a mount, nothing else);
//   - the images are the run's, from its registry;
//   - no HTTPS certificate on the tailnet (Headscale issues none).
//
// The owner's steps in Coolify are pauses; the rest (the route in the
// proxy, the containers stopped and removed, the guard) the run does, as
// root, by the run's exact names.

const combinedItem = 15

// routePath is where migrate's route goes (internal/migrate, routePath).
const routePath = "/data/coolify/proxy/dynamic/varlatch-rollback.yaml"

// gitImage serves the run's repository (busybox's httpd).
const gitImage = "busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

const tailscaleCompose = "infra/compose/docker-compose.coolify-tailscale.yml"

var coolifyUUID = regexp.MustCompile(`^[a-z0-9]{20,32}$`)

// checkCombined refuses the combined case's missing inputs, before anything
// starts.
func checkCombined(prof profileConfig) error {
	if prof.target != "image" || prof.goImage == "" || prof.coolifySourceDir == "" || prof.publicName == "" || prof.coolifyTarget == "" || prof.gitName == "" {
		return errors.New("the combined case needs VL_RH_TARGET=image, VL_RH_GO_IMAGE (repository:<the run's varlatchd release>@sha256:...), VL_RH_COOLIFY_SOURCE_DIR, VL_RH_COOLIFY_TARGET (the Go app's UUID), VL_RH_PUBLIC_NAME, and VL_RH_GIT_NAME (a name that leads to the lab Coolify's proxy, for the run's Git repository)")
	}
	if prof.kill != "" || prof.sync != "" || prof.source != "seed" {
		return errors.New("VL_RH_INGRESS=combined runs its own cases, its interruptions among them: leave VL_RH_KILL and VL_RH_SYNC unset, and VL_RH_SOURCE=seed")
	}
	if !coolifyUUID.MatchString(prof.coolifyTarget) || !coolifyUUID.MatchString(filepath.Base(prof.coolifySourceDir)) || filepath.Base(prof.coolifySourceDir) == prof.coolifyTarget {
		return fmt.Errorf("VL_RH_COOLIFY_SOURCE_DIR (%s) ends in the source app's UUID, and VL_RH_COOLIFY_TARGET (%s) is the Go app's, another", prof.coolifySourceDir, prof.coolifyTarget)
	}
	if prof.publicName == prof.gitName {
		return errors.New("VL_RH_PUBLIC_NAME and VL_RH_GIT_NAME are two names")
	}
	if err := checkImageTarget(prof.goImage); err != nil {
		return err
	}
	for _, f := range []string{filepath.Join(releaseDir, "coolify-image-digests.env"), filepath.Join(tsCheckout, tailscaleCompose), filepath.Join(tsCheckout, "infra", "compose", "docker-compose.yml"), filepath.Join(tsCheckout, "infra", "coolify", "README.md")} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("the combined case needs %s: run images.sh again (it writes coolify-image-digests.env), from a checkout of 0.23.0; %v", f, err)
		}
	}
	return nil
}

// checkCombinedHost is the host's part of the preconditions: the tools, the
// proxy's directory without a route of another run, docker0's address and
// the port Headscale is published on.
func checkCombinedHost() (bridge string, err error) {
	for _, tool := range []string{"git", "jq", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			return "", fmt.Errorf("the combined case runs %s on this host: %v", tool, err)
		}
	}
	if fi, err := os.Stat(filepath.Dir(routePath)); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not the lab Coolify proxy's directory: %v", filepath.Dir(routePath), err)
	}
	if _, err := os.Lstat(routePath); !os.IsNotExist(err) {
		return "", fmt.Errorf("%s is there already (%v): another run's route, or the owner's; the run replaces none", routePath, err)
	}
	r := run("", nil, nil, "docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
	if bridge = strings.TrimSpace(r.stdout); r.code != 0 || net.ParseIP(bridge) == nil {
		return "", fmt.Errorf("docker0 has no address (docker network inspect bridge): %s", r)
	}
	l, err := net.Listen("tcp", net.JoinHostPort(bridge, publishedPort))
	if err != nil {
		return "", fmt.Errorf("%s:%s, which the run's Headscale is published on, is not free: %v", bridge, publishedPort, err)
	}
	return bridge, l.Close()
}

// sidecarEdit is the release's Compose file with the run's Headscale in the
// sidecar: its login server, its CA and that file's mount, each put after
// one line that is there once.
func sidecarEdit(text, url, ca string) (string, error) {
	for _, e := range [][2]string{
		{"      TS_SOCKET: /var/run/tailscale/tailscaled.sock\n", "      TS_EXTRA_ARGS: --login-server=" + url + "\n      SSL_CERT_FILE: /vl-rh-tailnet/ca.pem\n"},
		{"      - tailscale-state:/var/lib/tailscale\n", "      - " + ca + ":/vl-rh-tailnet/ca.pem:ro\n"},
	} {
		if n := strings.Count(text, e[0]); n != 1 {
			return "", fmt.Errorf("%s has %q %d times, not once: the run does not know where the sidecar's setting goes", tailscaleCompose, strings.TrimSpace(e[0]), n)
		}
		text = strings.Replace(text, e[0], e[0]+e[1], 1)
	}
	return text, nil
}

// serveGit serves a repository with the release's infra/, its sidecar edited
// (sidecarEdit), over Git's plain HTTP files behind the lab Coolify's proxy:
// its URL.
func serveGit(t *testing.T, base, url, ca string) string {
	t.Helper()
	src, www := filepath.Join(base, "git-src"), filepath.Join(base, "git")
	for _, d := range []string{src, www} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must(t, run("", nil, nil, "cp", "-a", filepath.Join(tsCheckout, "infra"), src), "copy the release's infra")
	file := filepath.Join(src, tailscaleCompose)
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text, err := sidecarEdit(string(b), url, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	git := func(dir string, args ...string) {
		t.Helper()
		must(t, run(dir, []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}, nil, "git", append([]string{"-c", "user.name=vl-rh", "-c", "user.email=vl-rh@example.test", "-c", "safe.directory=*", "-c", "init.defaultBranch=main"}, args...)...), "git "+args[0])
	}
	git(src, "init", "-q")
	git(src, "add", "infra")
	git(src, "commit", "-q", "-m", "0.23.0's infra, the rehearsal's control server")
	git(src, "clone", "-q", "--bare", src, filepath.Join(www, "app.git"))
	git(filepath.Join(www, "app.git"), "update-server-info")
	must(t, run("", nil, nil, "chmod", "-R", "a+rX", www), "open the repository's files")
	name := "vl-rh-" + runID + "-git"
	label := func(kv string) []string { return []string{"--label", kv} }
	must(t, run("", nil, nil, "docker", slices.Concat([]string{"run", "-d", "--name", name, "--network", "coolify", "-v", www + ":/www:ro"},
		label("traefik.enable=true"), label("traefik.http.routers."+name+".rule=Host(`"+prof.gitName+"`)"), label("traefik.http.routers."+name+".entrypoints=https"),
		label("traefik.http.routers."+name+".tls=true"), label("traefik.http.routers."+name+".tls.certresolver=letsencrypt"),
		label("traefik.http.services."+name+".loadbalancer.server.port=80"), []string{gitImage, "httpd", "-f", "-p", "80", "-h", "/www"})...), "serve the repository")
	t.Cleanup(func() { run("", nil, nil, "docker", "rm", "-fv", name) })
	repo := "https://" + prof.gitName + "/app.git"
	if !pollUntil(90*time.Second, 2*time.Second, func() bool { return run("", nil, nil, "git", "ls-remote", repo).code == 0 }) {
		t.Fatalf("the run's repository does not answer at %s", repo)
	}
	return repo
}

// container is what the case reads of one of a project's containers.
type combinedContainer struct {
	ID, Name, Service, State, Image, NetworkMode, Files, Type, Started string
	IPs                                                                []string
}

// containersOf are a Compose project's containers, by docker inspect.
func containersOf(project string) []combinedContainer {
	r := run("", nil, nil, "docker", "ps", "-aq", "--no-trunc", "--filter", "label=com.docker.compose.project="+project)
	ids := strings.Fields(r.stdout)
	if len(ids) == 0 {
		return nil
	}
	r = run("", nil, nil, "docker", append([]string{"inspect", "--type", "container", "--format",
		`{{json .Id}} {{json .Name}} {{json (index .Config.Labels "com.docker.compose.service")}} {{json .State.Status}} {{json .Config.Image}} {{json .HostConfig.NetworkMode}} {{json (index .Config.Labels "com.docker.compose.project.config_files")}} {{json (index .Config.Labels "coolify.type")}} {{json .State.StartedAt}} {{json .NetworkSettings.Networks}}`}, ids...)...)
	var out []combinedContainer
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	for {
		var c combinedContainer
		var nets map[string]struct{ IPAddress string }
		for i, f := range []any{&c.ID, &c.Name, &c.Service, &c.State, &c.Image, &c.NetworkMode, &c.Files, &c.Type, &c.Started, &nets} {
			if err := dec.Decode(f); err != nil {
				if i == 0 {
					return out
				}
				return nil
			}
		}
		c.Name = strings.TrimPrefix(c.Name, "/")
		for n, v := range nets {
			if v.IPAddress != "" {
				c.IPs = append(c.IPs, n+"="+v.IPAddress)
			}
		}
		slices.Sort(c.IPs)
		out = append(out, c)
	}
}

// serviceOf is a project's one container of a service (nil for none).
func serviceOf(project, svc string) *combinedContainer {
	for _, c := range containersOf(project) {
		if c.Service == svc {
			return &c
		}
	}
	return nil
}

func stateOf(project, svc string) string {
	if c := serviceOf(project, svc); c != nil {
		return c.State
	}
	return "gone"
}

// cleanupSelection is Coolify 4.7.6's container cleanup (CleanupDocker,
// buildContainerPruneCommand), its selection only, for one project: what it
// would remove.
func cleanupSelection(project string) ran {
	return run("", nil, nil, "sh", "-c", `docker ps -a --filter status=created --filter status=exited --filter status=dead --filter label=coolify.managed=true --filter "label=com.docker.compose.project=$1" --format '{{.ID}} coolify.proxy={{.Label "coolify.proxy"}} coolify.type={{.Label "coolify.type"}}' | `+
		`grep -v -E 'coolify\.proxy=true |coolify\.type=(database|application|service)$' | awk '{print $1}'`, "sh", project)
}

// routeText is the file migrate says to put in the proxy, and where.
func routeText(out string) (path, text string, err error) {
	m := regexp.MustCompile(`(?s)as (/\S+\.yaml) on the host.*?from then on:\n(http:\n.*?\n)Then run varlatch migrate --rollback again`).FindStringSubmatch(out)
	if m == nil {
		return "", "", errors.New("migrate said no route")
	}
	return m[1], m[2], nil
}

// putRoute puts migrate's own text in the proxy, as 5.B2 says.
func putRoute(out string) error {
	path, text, err := routeText(out)
	if err != nil {
		return err
	}
	if path != routePath {
		return fmt.Errorf("migrate's route goes to %s, not %s", path, routePath)
	}
	if !strings.Contains(text, "Host(`"+prof.publicName+"`)") {
		return fmt.Errorf("migrate's route is not for %s", prof.publicName)
	}
	if err := os.WriteFile(routePath+".new", []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(routePath+".new", routePath)
}

// markRetained is 5.R's guard, as the run sheet has it.
const markRetained = `(
set -eu
J=$COMPOSE_DIR/migration.json; IMG=postgres:17.6
PHASE=$(jq -r .phase "$J"); PROJECT=$(jq -r .source.project.name "$J"); FRESH=$(jq -r '.rollback.rebuild.volumes[0]' "$J")
RETAINED=$(jq -r '.rollback.rebuild.retained[0].name // ""' "$J"); MADE=$(jq -r '.rollback.rebuild.retained[0].createdAt // ""' "$J"); OWNER=$(jq -r '.rollback.rebuild.retained[0].project // ""' "$J")
stop() { echo "STOP: $*"; exit 1; }
[ "$PHASE" = rolled-back ] || stop "the phase is $PHASE, not rolled-back: nothing marked"
[ -n "$RETAINED" ] && [ -n "$MADE" ] && [ "$RETAINED" != "$FRESH" ] || stop "the journal records no retained volume apart from the rebuilt one: nothing marked"
case "$FRESH" in "${PROJECT}"_postgres-data-????????) ;; *) stop "the journal's rebuilt volume $FRESH is not ${PROJECT}_postgres-data-<8 letters>: nothing marked";; esac
docker volume inspect "$RETAINED" "$FRESH" >/dev/null || stop "a volume is not there: nothing marked"
IS=$(docker volume inspect --format '{{.CreatedAt}} {{index .Labels "com.docker.compose.project"}}' "$RETAINED")
[ "$IS" = "$MADE $OWNER" ] && [ "$OWNER" = "$PROJECT" ] || stop "$RETAINED is '$IS', not the recorded '$MADE $OWNER' of $PROJECT: nothing marked"
NOW=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" --filter label=com.docker.compose.service=postgres | xargs -r docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')
[ "$NOW" = "$FRESH" ] || stop "Postgres runs on '$NOW', not the rebuilt $FRESH: nothing marked"
USERS=$(docker ps -a --filter "volume=$RETAINED" --format '{{.Names}}')
[ -z "$USERS" ] || stop "$RETAINED is used by $USERS: nothing marked"
docker run --rm --pull never --network none --entrypoint sh -v "$RETAINED:/v" "$IMG" -c '
  if [ -e /v/PG_VERSION.retained-after-rollback ] && [ ! -e /v/PG_VERSION ]; then echo "marked already"; exit 0; fi
  mv /v/PG_VERSION /v/PG_VERSION.retained-after-rollback'
echo "MARKED $RETAINED (Postgres runs on $FRESH)"
)`

// combined is the case's state.
type combined struct {
	t               *testing.T
	rel             release
	w               *tailnetWorld
	f               coolifyFiles
	target          string
	conf            string
	source, machine string
	client          *http.Client
	roots           string
	tsBin           string
}

func (c *combined) record(name string, ok bool, detail string) bool {
	c.t.Helper()
	record(c.t, combinedItem, name, ok, detail)
	return ok
}

// get is the public URL's /v1/meta.
func (c *combined) get() (int, string) {
	resp, err := c.client.Get("https://" + prof.publicName + "/v1/meta")
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	var meta map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&meta)
	return resp.StatusCode, fmt.Sprint(meta["serverVersion"], " ", meta["installationId"])
}

// targetArgs are the target's options, in every command.
func (c *combined) targetArgs() []string {
	return []string{"--from", prof.coolifySourceDir, "--to-data", filepath.Join(c.target, "data"), "--to-keys", filepath.Join(c.target, "keys"),
		"--to-config", c.conf, "--to-image", prof.goImage, "--to-service", "varlatchd"}
}

// backupArgs are the backup's (forward, and --finish's final archive).
func (c *combined) backupArgs() []string {
	return []string{"--bek-file", c.f.bek, "--backup-destination", "offsite", "--destinations-file", c.f.destinations, "--read-credentials-file", c.f.readCreds, "--ts-cli", "varlatch-ts"}
}

func (c *combined) forwardArgs(extra ...string) []string {
	return slices.Concat([]string{"migrate", "--ingress", "coolify", "--transfer-timeout", "3m", "--drain", "10s"}, c.targetArgs(), c.backupArgs(), c.w.authority(), extra)
}

// reverseArgs are --rollback's options, and its --resume's and --abort's.
func (c *combined) reverseArgs(extra ...string) []string {
	return slices.Concat([]string{"migrate", "--transfer-timeout", "3m", "--drain", "10s"}, c.targetArgs(), c.w.authority(), extra)
}

func (c *combined) finishArgs(extra ...string) []string {
	return slices.Concat([]string{"migrate", "--finish"}, c.targetArgs(), c.backupArgs(), extra)
}

func (c *combined) env() []string {
	return []string{"VARLATCH_MIGRATE_PIN=" + c.rel.pin(), "PATH=" + c.tsBin + ":" + os.Getenv("PATH"), "TMPDIR=" + c.f.tmp, "SSL_CERT_FILE=" + c.roots}
}

// migrate runs varlatch migrate; what it printed is kept for the report
// when it fails.
func (c *combined) migrate(what string, args []string) ran {
	c.t.Helper()
	r := run(prof.coolifySourceDir, c.env(), nil, filepath.Join(binDir, "varlatch"), args...)
	measure("item 15: "+what, fmt.Sprintf("exit %d after %s", r.code, r.took.Round(time.Millisecond)))
	if r.code != 0 && r.code != 75 {
		measure("item 15: "+what+": the end of its output", redact(lastLines(r.stdout+"\n"+r.stderr, 8)))
	}
	return r
}

// killed runs varlatch migrate until the crash point, and kills it there.
func (c *combined) killed(point string, args []string) bool {
	c.t.Helper()
	log := filepath.Join(c.f.tmp, "crashpoints.log")
	_ = os.Remove(log)
	cmd := exec.Command(filepath.Join(binDir, "varlatch"), args...)
	cmd.Dir = prof.coolifySourceDir
	cmd.Env = append(append(os.Environ(), c.env()...), "VARLATCH_MIGRATE_LOG="+log, "VARLATCH_MIGRATE_PAUSE="+point)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	paused := func() bool {
		b, _ := os.ReadFile(log)
		return bytes.Contains(b, []byte("paused "+point+"\n"))
	}
	for deadline := time.Now().Add(15 * time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if paused() {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-done
			return c.record("killed at "+point, true, "")
		}
		select {
		case err := <-done:
			return c.record("killed at "+point, false, fmt.Sprintf("it ended (%v) before: %s", err, redact(lastLines(out.String(), 6))))
		default:
		}
	}
	_ = cmd.Process.Kill()
	<-done
	return c.record("killed at "+point, false, "not reached")
}

// timed runs do with a prober on the public URL, and records what clients
// saw: the longest stretch without a 200, and each.
func (c *combined) timed(what string, do func()) {
	c.t.Helper()
	stop, ended := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var gaps []string
	var longest time.Duration
	go func() {
		defer close(ended)
		probe("https://"+prof.publicName+"/v1/meta", c.client, stop, func(gap time.Duration, from, to string) {
			mu.Lock()
			defer mu.Unlock()
			gaps = append(gaps, fmt.Sprintf("%s (%s -> %s)", gap.Round(time.Millisecond), from, to))
			longest = max(longest, gap)
		})
	}()
	do()
	time.Sleep(2 * time.Second)
	close(stop)
	<-ended
	mu.Lock()
	defer mu.Unlock()
	measure("item 15: downtime, "+what+" (longest gap clients saw, the owner's steps included)", longest.Round(time.Millisecond).String())
	measure("item 15: gaps, "+what, strings.Join(gaps, "; "))
}

// journal is the source's.
func (c *combined) journal() map[string]any {
	b, _ := os.ReadFile(filepath.Join(prof.coolifySourceDir, "migration.json"))
	var j map[string]any
	_ = json.Unmarshal(b, &j)
	return j
}

func (c *combined) phase() string { s, _ := c.journal()["phase"].(string); return s }

// down is whether what the forward handoff stopped is stopped.
func (c *combined) down() (bool, string) {
	states := fmt.Sprintf("sidecar %s, varlatchd %s, dashboard %s", stateOf(c.source, "tailscale"), stateOf(c.source, "varlatchd"), stateOf(c.source, "varlatch-web"))
	return stateOf(c.source, "tailscale") != "running" && stateOf(c.source, "varlatch-web") != "running", states
}

// name checks who holds the tailnet name, and what it serves.
func (c *combined) name(what string, want func(version string) bool) {
	c.t.Helper()
	id, meta, ok := c.w.served(c.machine, 3*time.Minute, func(id, meta string) bool { return id != "" && want(metaVersion(meta)) })
	c.record(what, ok, fmt.Sprintf("the name's node %q; /v1/meta over the tailnet: %s; nodes: %s", id, trim(meta), c.w.nodeNames()))
}

func metaVersion(meta string) string {
	var m struct {
		ServerVersion string `json:"serverVersion"`
	}
	_ = json.Unmarshal([]byte(meta), &m)
	return m.ServerVersion
}

func isTS(v string) bool { return v == "0.23.0" }
func isGo(v string) bool { return v != "" && v != "0.23.0" }

// addresses are the project's services' addresses.
func (c *combined) addresses() string {
	var out []string
	for _, l := range containersOf(c.source) {
		if slices.Contains([]string{"tailscale", "varlatchd", "varlatch-web", "postgres"}, l.Service) {
			out = append(out, l.Service+" "+strings.Join(l.IPs, ","))
		}
	}
	slices.Sort(out)
	return strings.Join(out, "; ")
}

// takeAddress starts a container that takes the stopped sidecar's address in
// its network, so that the sidecar comes back at another: gone when the case
// ends.
func (c *combined) takeAddress() {
	name := "vl-rh-" + runID + "-address"
	run("", nil, nil, "docker", "rm", "-fv", name)
	l := serviceOf(c.source, "tailscale")
	if l == nil {
		return
	}
	r := run("", nil, nil, "docker", "inspect", "--format", `{{range $n, $v := .NetworkSettings.Networks}}{{println $n}}{{end}}`, l.ID)
	nets := strings.Fields(r.stdout)
	if len(nets) == 0 {
		return
	}
	run("", nil, nil, "docker", "run", "-d", "--name", name, "--network", nets[0], gitImage, "sleep", "86400")
	for _, n := range nets[1:] {
		run("", nil, nil, "docker", "network", "connect", n, name)
	}
}

// goContainers are the Go app's running containers.
func goContainers() []string {
	var out []string
	for _, l := range containersOf(prof.coolifyTarget) {
		if l.State == "running" {
			out = append(out, l.Name)
		}
	}
	return out
}

// stopGo stops the Go app's container, as its owner does when asked.
func (c *combined) stopGo() {
	c.t.Helper()
	for _, n := range goContainers() {
		must(c.t, run("", nil, nil, "docker", "stop", "-t", "20", n), "stop the Go app's container")
	}
}

// forward is the migration, with the owner's steps in Coolify.
func (c *combined) forward(step string) bool {
	c.t.Helper()
	ok := false
	c.timed("the migration ("+step+")", func() {
		r := c.migrate("the migration ("+step+")", c.forwardArgs())
		if !c.record(step+": the migration stops for the owner's steps (exit 75)", r.code == 75, r.String()) {
			return
		}
		out := r.stdout + r.stderr
		domain, deploy := strings.Index(out, "move the domain of https://"+prof.publicName), strings.Index(out, "Start the Go service")
		c.record(step+": the domain before the deploy, and the TypeScript app never deployed", domain >= 0 && deploy > domain && strings.Contains(out, "Do not Deploy, Restart or Stop the TypeScript application"), redact(lastLines(out, 10)))
		c.record(step+": the old dashboard is stopped for the transfer", stateOf(c.source, "varlatch-web") == "exited", stateOf(c.source, "varlatch-web"))
		pause(c.t, step, "varlatch migrate stopped for your steps (exit 75). In the lab Coolify, in this order:",
			"1. the domain https://"+prof.publicName+" off the source app (varlatch-web) and onto the Go app (varlatchd, port 8686): Save only, never Deploy the source app;",
			"2. Deploy the Go app ("+prof.coolifyTarget+");",
			"3. check that https://"+prof.publicName+"/v1/meta answers.")
		code, body := c.get()
		c.record(step+": /v1/meta by hand, before --resume", code == 200 && isGo(strings.Fields(body + " -")[0]), fmt.Sprintf("%d %s", code, body))
		r = c.migrate("--resume ("+step+")", c.forwardArgs("--resume"))
		ok = c.record(step+": --resume opens", r.code == 0, r.String()+" "+redact(lastLines(r.stdout, 4)))
	})
	if !ok {
		return false
	}
	code, body := c.get()
	c.record(step+": the public URL answers from Go", code == 200 && isGo(strings.Fields(body + " -")[0]), fmt.Sprintf("%d %s", code, body))
	down, states := c.down()
	c.record(step+": the sidecar and the dashboard are stopped", down, states)
	c.name(step+": the tailnet name is Go's", isGo)
	return true
}

// reversed is what a finished rollback leaves.
func (c *combined) reversed(step string) {
	c.t.Helper()
	code, body := c.get()
	c.record(step+": the public URL answers from 0.23.0", code == 200 && strings.HasPrefix(body, "0.23.0 "), fmt.Sprintf("%d %s", code, body))
	c.record(step+": the journal says rolled back", c.phase() == "rolled-back", c.phase())
	c.name(step+": the tailnet name is the sidecar's again", isTS)
	fresh, retained := "", ""
	if rb, _ := c.journal()["rollback"].(map[string]any); rb != nil {
		if b, _ := rb["rebuild"].(map[string]any); b != nil {
			if v, _ := b["volumes"].([]any); len(v) == 2 {
				fresh, _ = v[0].(string)
			}
			if v, _ := b["retained"].([]any); len(v) == 2 {
				if m, _ := v[0].(map[string]any); m != nil {
					retained, _ = m["name"].(string)
				}
			}
		}
	}
	r := run("", nil, nil, "sh", "-c", `docker ps -q --filter "label=com.docker.compose.project=$1" --filter label=com.docker.compose.service=postgres | xargs -r docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}'`, "sh", c.source)
	c.record(step+": Postgres runs on the fresh volume, the old one kept", fresh != "" && strings.TrimSpace(r.stdout) == fresh && retained != "" && run("", nil, nil, "docker", "volume", "inspect", retained).code == 0,
		fmt.Sprintf("on %s, the journal's %s; before it %s", strings.TrimSpace(r.stdout), fresh, retained))
	web, owner := serviceOf(c.source, "varlatch-web"), serviceOf(c.source, "tailscale")
	c.record(step+": the dashboard started after the sidecar it resolves varlatchd by", web != nil && owner != nil && web.Started > owner.Started, fmt.Sprintf("%+v %+v", web, owner))
	// The route is not needed once Go is stopped: the dashboard's own
	// router serves the name.
	if err := os.Remove(routePath); err != nil {
		c.record(step+": the route removed", false, err.Error())
		return
	}
	time.Sleep(5 * time.Second)
	code, body = c.get()
	c.record(step+": without the route, the public URL still answers from 0.23.0", code == 200 && strings.HasPrefix(body, "0.23.0 "), fmt.Sprintf("%d %s", code, body))
	pause(c.t, step+"-domain", "In the lab Coolify: the domain https://"+prof.publicName+" off the Go app and back onto the source app (varlatch-web): Save only. Do not deploy either.")
}

// ask is --rollback without a route: asked for it, nothing begun.
func (c *combined) ask(step string) (string, bool) {
	c.t.Helper()
	r := c.migrate("--rollback without a route ("+step+")", c.reverseArgs("--rollback"))
	out := r.stdout + r.stderr
	code, body := c.get()
	ok := c.record(step+": --rollback without a route asks for it and begins nothing", r.code == 75 && c.phase() == "open" && code == 200 && isGo(strings.Fields(body + " -")[0]), fmt.Sprintf("%s; phase %s; %d %s", r, c.phase(), code, body))
	return out, ok
}

// undone is a reverse undone: Go open, what it started stopped again, no
// volume of it left.
func (c *combined) undone(step string) {
	c.t.Helper()
	down, states := c.down()
	c.record(step+": the sidecar and the dashboard are stopped again", down, states)
	c.record(step+": the journal says open", c.phase() == "open", c.phase())
	r := run("", nil, nil, "docker", "volume", "ls", "-q", "--filter", "label=varlatch.migrate.id", "--filter", "label=com.docker.compose.project="+c.source)
	c.record(step+": no fresh volume of the reverse is left", len(strings.Fields(r.stdout)) == 0, r.stdout)
	c.record(step+": Go runs", len(goContainers()) == 1, fmt.Sprint(goContainers()))
}

// gateLost: without the migration's gate in the state volume, --rollback
// begins and starts nothing; the gate is then put back.
func (c *combined) gateLost(step string) {
	c.t.Helper()
	image := ""
	if l := serviceOf(c.source, "postgres"); l != nil {
		image = l.Image
	}
	state := func(cmd string) ran {
		return run("", nil, nil, "docker", "run", "--rm", "--pull", "never", "--network", "none", "-v", c.source+"_varlatch-state:/s", "--entrypoint", "sh", image, "-c", cmd)
	}
	if mv := state("mv /s/maintenance.json /s/maintenance.json.kept"); !c.record(step+": the source's gate is taken away", mv.code == 0, mv.String()) {
		return
	}
	before := fmt.Sprint(containersOf(c.source))
	r := c.migrate("--rollback without the source's gate ("+step+")", c.reverseArgs("--rollback"))
	out := r.stdout + r.stderr
	code, body := c.get()
	c.record(step+": --rollback without the source's gate starts nothing, and Go serves", r.code == 1 && strings.Contains(out, "holds no gate") && strings.Contains(out, "nothing was started") && c.phase() == "open" &&
		fmt.Sprint(containersOf(c.source)) == before && code == 200 && isGo(strings.Fields(body + " -")[0]), fmt.Sprintf("%s; phase %s; %d %s", r, c.phase(), code, body))
	if mv := state("mv /s/maintenance.json.kept /s/maintenance.json"); mv.code != 0 {
		c.t.Fatalf("putting the gate back: %s", mv)
	}
}

// removeStopped removes the source's stopped containers: their images.
func (c *combined) removeStopped() []string {
	c.t.Helper()
	var images []string
	for _, l := range containersOf(c.source) {
		if l.State != "running" {
			must(c.t, run("", nil, nil, "docker", "rm", l.ID), "remove the source's stopped "+l.Service)
			images = append(images, l.Image)
		}
	}
	slices.Sort(images)
	return slices.Compact(images)
}

// throughStop is a --rollback or --resume that stops for Go's stop (exit
// 75), then finishes.
func (c *combined) throughStop(step string, r ran) bool {
	c.t.Helper()
	code, body := c.get()
	if !c.record(step+": it stops for Go's stop (exit 75), the address answering from 0.23.0 already", r.code == 75 && code == 200 && strings.HasPrefix(body, "0.23.0 "), fmt.Sprintf("%s; %d %s", r, code, body)) {
		return false
	}
	c.stopGo()
	r = c.migrate("--resume after Go's stop ("+step+")", c.reverseArgs("--resume"))
	return c.record(step+": --resume finishes the rollback", r.code == 0, r.String()+" "+redact(lastLines(r.stdout, 4)))
}

func combinedCase(t *testing.T, rel release, s3 *s3Server) {
	bridge, err := checkCombinedHost()
	if err != nil {
		t.Fatal(err)
	}
	differs(combinedItem, "Tailscale's control server, the sidecar logged in with an auth key alone.",
		"the run's Headscale on docker0's address: the sidecar's TS_EXTRA_ARGS (--login-server), SSL_CERT_FILE and the CA's mount, in a copy of the release's infra/; no tailnet HTTPS certificate",
		"the tailnet handoff's certificate step is not rehearsed here (B4 on Tailscale is)")
	f := coolifyFilesFor(t, s3, "vl-rh-combined")
	w := startTailnetOn(t, bridge)
	c := &combined{t: t, rel: rel, w: w, f: f, source: filepath.Base(prof.coolifySourceDir), machine: w.machine("combined"), client: &http.Client{Timeout: 10 * time.Second}, target: filepath.Join(f.base, "go"), tsBin: filepath.Join(f.base, "bin")}
	t.Cleanup(func() {
		run("", nil, nil, "docker", "rm", "-fv", "vl-rh-"+runID+"-address")
		if b, err := os.ReadFile(routePath); err == nil && strings.Contains(string(b), "Host(`"+prof.publicName+"`)") {
			_ = os.Remove(routePath)
		}
	})
	// The CA where the sidecar's mount and the image's user reach it.
	caDir := filepath.Join(f.base, "tailnet")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, run("", nil, nil, "cp", filepath.Join(w.dir, "ca.pem"), filepath.Join(caDir, "ca.pem")), "copy the run's CA")
	if c.roots, err = goRoots(caDir, "/etc/ssl/certs/ca-certificates.crt"); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(w.nodeKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	authKey := filepath.Join(f.secrets, "tailscale-authkey")
	if err := os.WriteFile(authKey, key, 0o644); err != nil {
		t.Fatal(err)
	}
	digests, err := os.ReadFile(filepath.Join(releaseDir, "coolify-image-digests.env"))
	if err != nil {
		t.Fatal(err)
	}
	repo := serveGit(t, f.base, w.url, filepath.Join(caDir, "ca.pem"))
	pause(t, "source-app",
		"In the lab Coolify (never production's), in a throwaway project, deploy the source app "+c.source+" from "+repo+", branch main, build pack Docker Compose,",
		"shallow clone off, Base Directory /infra/compose, Docker Compose Location /docker-compose.coolify-tailscale.yml, Preserve Repository on, automatic deploys off,",
		"its domain https://"+prof.publicName+" on varlatch-web, and these variables (the run's images, the secrets as host files, paths only):",
		strings.TrimSpace(string(digests)), strings.Join(f.lines, "\n  "), "TS_AUTHKEY_HOST_PATH="+authKey,
		"VARLATCH_TAILNET_NAME="+w.suffix, "VARLATCH_TAILNET_MACHINE="+c.machine, "VARLATCH_PUBLIC_URL=https://"+prof.publicName, "CONVEX_CLOUD_ORIGIN=https://"+prof.publicName+"/convex",
		"Its resource directory must be "+prof.coolifySourceDir+".")

	// Production's layout.
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "docker-compose.coolify-tailscale.yml", ".env"} {
		_, err := os.Stat(filepath.Join(prof.coolifySourceDir, name))
		c.record("the source's directory holds "+name, err == nil, fmt.Sprint(err))
	}
	for _, l := range containersOf(c.source) {
		c.record("the source's "+l.Service+" is made from docker-compose.coolify-tailscale.yml, of an application", l.Files == filepath.Join(prof.coolifySourceDir, "docker-compose.coolify-tailscale.yml") && l.Type == "application", l.Files+" "+l.Type)
	}
	sidecar, daemon := serviceOf(c.source, "tailscale"), serviceOf(c.source, "varlatchd")
	if sidecar == nil || daemon == nil {
		c.record("the source runs", false, fmt.Sprint(containersOf(c.source)))
		return
	}
	c.record("varlatchd is in the sidecar's network", daemon.NetworkMode == "container:"+sidecar.ID, daemon.NetworkMode)
	if !pollUntil(5*time.Minute, 3*time.Second, func() bool { code, body := c.get(); return code == 200 && strings.HasPrefix(body, "0.23.0 ") }) {
		code, body := c.get()
		c.record("the source app serves 0.23.0 at the public URL", false, fmt.Sprintf("%d %s", code, body))
		return
	}
	_, before := c.get()
	c.record("the source app serves 0.23.0 at the public URL", true, before)
	c.name("the tailnet name is the sidecar's", isTS)

	// The target, in setup mode.
	for _, d := range []string{"data", "keys"} {
		if err := os.MkdirAll(filepath.Join(c.target, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(c.target, 0o711); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(c.target, "keys")
	roots, err := os.ReadFile(c.roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "go-roots.pem"), roots, 0o644); err != nil {
		t.Fatal(err)
	}
	// Go's own backup destination, for --finish's final archive of its copy.
	s3.createBucket(t, "vl-rh-combined-go")
	s3.writeDestination(t, filepath.Join(keys, "backup-destinations.json"), "vl-rh-combined-go", "write.json")
	for _, d := range []string{filepath.Join(c.target, "data"), keys} {
		must(t, run("", nil, nil, "chown", "-R", "65532:65532", d), "own the image's "+filepath.Base(d))
	}
	c.conf = filepath.Join(c.target, "varlatchd.conf")
	text := fmt.Sprintf("listen = 0.0.0.0:8686\npublic_url = https://%s\ntrusted_proxies = coolify-proxy\ndata_dir = /var/lib/varlatch\nroot_kek_file = /keys/root-kek\nbackup_key_file = /keys/backup-key\nbackup_interval = off\n"+
		"backup_destinations_file = /keys/backup-destinations.json\nbackup_destination = offsite\n%s", prof.publicName, strings.ReplaceAll(tailnetConf(c.machine, w.url), "{keys}", "/keys"))
	if err := os.WriteFile(c.conf, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.tsBin, 0o755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(releaseDir, "varlatch-cli-0.23.0.cjs")
	if err := os.WriteFile(filepath.Join(c.tsBin, "varlatch-ts"), []byte("#!/bin/sh\nexec node "+cli+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	repository, digest, _ := strings.Cut(prof.goImage, "@")
	pause(t, "target-app",
		"In the same project, make the Go app "+prof.coolifyTarget+" ready, from this checkout's infra/coolify/varlatchd.compose.yml (Base Directory /, no domain), in setup mode: do not deploy it. Its variables:",
		"VARLATCH_IMAGE_REGISTRY="+strings.TrimSuffix(repository[:strings.LastIndex(repository, ":")], "/varlatchd"), "VARLATCH_VARLATCHD_DIGEST="+digest,
		"VARLATCH_DATA_DIR="+filepath.Join(c.target, "data"), "VARLATCH_KEYS_DIR="+keys, "VARLATCH_CONFIG_FILE="+c.conf, "SSL_CERT_FILE=/keys/go-roots.pem")

	// The forward migration: killed once at its transfer, resumed.
	measure("item 15: the source's addresses before", c.addresses())
	if c.killed("entered transfer", c.forwardArgs()) {
		ab := c.migrate("--abort after the kill in the transfer", c.forwardArgs("--abort"))
		code, body := c.get()
		c.record("--abort after a kill in the transfer: the old installation answers", ab.code == 0 && code == 200 && strings.HasPrefix(body, "0.23.0 "), fmt.Sprintf("%s; %d %s", ab, code, body))
	}
	if !c.forward("migrate") {
		return
	}
	j, _ := json.Marshal(c.journal()["source"])
	c.record("the journal records the project of the labels and its volumes", strings.Contains(string(j), `"name":"`+c.source+`"`) && strings.Contains(string(j), "docker-compose.coolify-tailscale.yml") && strings.Contains(string(j), c.source+"_postgres-data"), trim(string(j)))

	// --finish --delete-old-data is refused in this topology, before its
	// archive, and changes nothing.
	fin := c.migrate("--finish --delete-old-data after the migration", c.finishArgs("--delete-old-data"))
	c.record("--finish --delete-old-data after the migration is refused before its archive", fin.code == 1 && strings.Contains(fin.stdout+fin.stderr, "would bring the old Tailscale node back") && c.phase() == "open", fin.String())

	// Coolify 4.7.6's cleanup: nothing of the source's is selected, and an
	// image of a stopped container is not removed.
	sel := cleanupSelection(c.source)
	c.record("Coolify's cleanup selects none of the source's containers", sel.code == 0 && len(strings.Fields(sel.stdout)) == 0, sel.stdout+sel.stderr)
	for _, l := range containersOf(c.source) {
		if l.State == "running" {
			continue
		}
		// Production's are pulled by digest alone; the run's were built
		// here, and have a tag too, which rmi of the digest would only
		// leave.
		if tags := strings.TrimSpace(run("", nil, nil, "docker", "image", "inspect", "--format", "{{len .RepoTags}}", l.Image).stdout); strings.Contains(l.Image, "@") && tags != "0" {
			measure("item 15: docker rmi of the stopped "+l.Service+"'s image", "not tried: the run built it, under "+tags+" tag(s) beside its digest")
			continue
		}
		rm := run("", nil, nil, "docker", "rmi", l.Image)
		c.record("docker rmi refuses the image of the stopped "+l.Service, rm.code != 0 && strings.Contains(rm.stderr, "is using its referenced image"), fmt.Sprintf("exit %d", rm.code))
	}

	// The rollback, with the containers there: asked for the route, killed at
	// the new steps, undone each time; then through.
	c.takeAddress()
	c.gateLost("rollback")
	out, ok := c.ask("rollback")
	if !ok {
		return
	}
	c.timed("the rollback, its interruptions included", func() {
		if err := putRoute(out); err != nil {
			c.record("rollback: migrate's route put in the proxy", false, err.Error())
			ok = false
			return
		}
		routed := pollUntil(20*time.Second, time.Second, func() bool {
			resp, err := c.client.Get("https://" + prof.publicName + "/readyz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 502 && resp.Header.Get("X-Varlatch-Rollback") != ""
		})
		c.record("rollback: the proxy answers 502 with the route's header, the dashboard stopped", routed, "")
		if c.killed("rollback gated started", c.reverseArgs("--rollback")) {
			c.record("the dashboard waits for the gate's second check", stateOf(c.source, "varlatchd") == "running" && stateOf(c.source, "varlatch-web") != "running", c.addresses())
			r := c.migrate("--resume after a kill once the servers started", c.reverseArgs("--resume"))
			c.record("--resume after a kill once the servers started undoes it", r.code == 1 && strings.Contains(r.stdout+r.stderr, "the reverse was undone"), r.String())
			c.undone("resumed once the servers started")
		}
		if c.killed("rollback route checked", c.reverseArgs("--rollback")) {
			c.record("the old sidecar and varlatchd ran for the check", stateOf(c.source, "tailscale") == "running" && stateOf(c.source, "varlatch-web") == "running", c.addresses())
			r := c.migrate("--abort after a kill once the route is checked", c.reverseArgs("--abort"))
			c.record("--abort after a kill once the route is checked", r.code == 0, r.String())
			c.undone("aborted once the route is checked")
		}
		if c.killed("rollback volumes made", c.reverseArgs("--rollback")) {
			r := c.migrate("--resume after a kill once the volumes are made", c.reverseArgs("--resume"))
			c.record("--resume after a kill once the volumes are made undoes it", r.code == 1 && strings.Contains(r.stdout+r.stderr, "the reverse was undone"), r.String())
			c.undone("resumed once the volumes are made")
		}
		if ok = c.killed("entered rollback-transfer", c.reverseArgs("--rollback")); !ok {
			return
		}
		c.record("in the transfer Go still runs", len(goContainers()) == 1, fmt.Sprint(goContainers()))
		ok = c.throughStop("rollback", c.migrate("--resume in the transfer", c.reverseArgs("--resume")))
	})
	if !ok {
		return
	}
	measure("item 15: the source's addresses after the rollback", c.addresses())
	c.reversed("rollback")

	// 5.R's guard, twice, then the finish that removes what it marked.
	for i, want := range []string{"MARKED " + c.source + "_postgres-data ", "marked already"} {
		g := run("", []string{"COMPOSE_DIR=" + prof.coolifySourceDir}, nil, "bash", "-c", markRetained)
		c.record(fmt.Sprintf("5.R's guard, run %d", i+1), g.code == 0 && strings.Contains(g.stdout, want), g.String()+" "+trim(g.stdout))
	}
	fin = c.migrate("--finish --delete-old-data after the rollback", c.finishArgs("--delete-old-data"))
	left := run("", nil, nil, "docker", "volume", "inspect", c.source+"_postgres-data", c.source+"_convex-data")
	if !c.record("--finish --delete-old-data after the rollback: archived, the retained volumes and Go's copy removed", fin.code == 0 && left.code != 0, fin.String()+" "+redact(lastLines(fin.stdout, 4))) {
		return
	}
	if _, err := os.Stat(filepath.Join(c.target, "data", "varlatch.db")); !os.IsNotExist(err) {
		c.record("Go's copy is discarded", false, fmt.Sprint(err))
	}
	_, body := c.get()
	c.record("after it the source still serves", strings.HasPrefix(body, "0.23.0 "), body)

	// A second migration, and its rollback with the stopped containers and
	// their images gone.
	if !c.forward("migrate-again") {
		return
	}
	images := c.removeStopped()
	for _, img := range images {
		run("", nil, nil, "docker", "rmi", img)
	}
	c.record("the old installation's stopped containers are gone", stateOf(c.source, "tailscale") == "gone" && stateOf(c.source, "varlatch-web") == "gone", c.addresses())
	measure("item 15: images removed with them", fmt.Sprintf("%d", len(images)))
	c.gateLost("rollback-gone")
	if out, ok = c.ask("rollback-gone"); !ok {
		return
	}
	c.timed("the rollback with the containers and images gone", func() {
		if err := putRoute(out); err != nil {
			c.record("rollback-gone: migrate's route put in the proxy", false, err.Error())
			ok = false
			return
		}
		// What the check made again is stopped by its undo, and gone again for
		// the rollback itself.
		if c.killed("rollback gated started", c.reverseArgs("--rollback")) {
			r := c.migrate("--abort after a kill once the servers were made again", c.reverseArgs("--abort"))
			c.record("--abort after a kill once the servers were made again", r.code == 0 && stateOf(c.source, "varlatchd") != "running", r.String()+" "+c.addresses())
			c.undone("aborted once the servers were made again")
			c.removeStopped()
		}
		ok = c.throughStop("rollback-gone", c.migrate("--rollback with the containers and images gone", c.reverseArgs("--rollback")))
	})
	if !ok {
		return
	}
	c.reversed("rollback-gone")
	fin = c.migrate("--finish after the second rollback", c.finishArgs())
	c.record("--finish after the second rollback", fin.code == 0, fin.String())
	pause(t, "cleanup", "In the lab Coolify, delete the two apps of this run ("+c.source+", "+prof.coolifyTarget+") and their volumes, and the throwaway project (docker_cleanup off).")
}
