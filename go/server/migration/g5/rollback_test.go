// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// G5's interrupted reverse (internal docs/design/go-step7.md decisions 14,
// 16 and 17, slice 7.6a): `varlatch migrate --rollback`, the real CLI built
// with -tags crashpoint, killed (SIGKILL) at every phase boundary of a
// reverse migration, held to the stated state there, then --resume and
// --abort taking it to its end. Go keeps running until the address moves
// back: an interruption before that leaves it running, and undone, serving
// again.
//
// Real, as in interrupt_test.go: the CLI, the target varlatchd (its
// barrier through the control socket, its journal, the reverse export from
// the frozen copy, the reverse checks beside it, its start rule after
// rolled back), the public URL check.
//
// Stood in, the docker stand-in extended (fakeDockerReverse), for the last
// TypeScript release's Compose installation:
//   - the host's Compose containers, with the labels and mounts migrate
//     reads; every compose command must name the project, its directory
//     and its files (compose.go), and one that does not is refused;
//   - Compose's services stopped, started and made (`compose stop|start|up
//     -d`), a state file each; Postgres and Convex are on the volume their
//     container was made with (up, from the files that command names:
//     migrate's docker-compose.varlatch-rollback.yml or not): source.json
//     is the retained pre-migration volume's database, db-<volume>.json a
//     fresh volume's;
//   - the import's one-off service (`compose --profile varlatch-rollback
//     run ... varlatch-reverse-import ... admin migration import`), as 7.2c
//     does it: refused unless Postgres's volume is fresh (an empty
//     database) and varlatchd is stopped, the bundle verified and loaded
//     verbatim (migrationtest.FromReverse), the migrated-out gate lifted;
//   - the TypeScript CLI in a one-off container (`compose run --rm -T
//     --no-deps varlatchd ... admin migration status|barrier|
//     mark-migrated-out|export --dry-run --digests`), its export's
//     decision table evaluated on an import of the rebuilt rows;
//   - `convex-deploy`, and `docker volume rm`.
// What the real TypeScript release and Docker do with these commands (the
// image's entry point, its secrets, its Convex reset) is 7.8's rehearsal,
// on a real 0.23.0 source; a public ingress with Pebble and a real Coolify
// too.

// stopped is whether a Compose service of the stand-in is stopped.
func stopped(svc string) bool {
	name := "stopped-" + svc
	if svc == "varlatch-web" {
		name = "web-stopped"
	}
	_, err := os.Stat(state(name))
	return err == nil
}

func setStopped(svc string, yes bool) error {
	name := "stopped-" + svc
	if svc == "varlatch-web" {
		name = "web-stopped"
	}
	if yes {
		return os.WriteFile(state(name), nil, 0o600)
	}
	if err := os.Remove(state(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// postgresVolume is the volume Postgres's container is on: "postgres-data"
// for the installation's own.
func postgresVolume() string {
	if v := mounted("postgres"); v != ownVolume("postgres") {
		return v
	}
	return "postgres-data"
}

// currentDB is the database Postgres serves from its volume now.
func currentDB() string {
	if os.Getenv("G5_STATE") == "" {
		return ""
	}
	if v := postgresVolume(); v != "postgres-data" {
		return state("db-" + v + ".json")
	}
	return state("source.json")
}

// decideOn is the TypeScript evaluator's decision table on a database:
// its rows imported into a scratch directory, and every eighth tuple
// evaluated there.
func decideOn(s migrationtest.Source) ([]bundle.Decision, error) {
	dir, err := os.MkdirTemp("", "g5-decide-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	b := migrationtest.Bundle(stdTB{}, s, migrationtest.Options{})
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.RootKEK, Release: "0.50.0-g5"}); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "varlatch.db")+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var out []bundle.Decision
	for _, d := range migrationtest.Tuples(stdTB{}, db, 8) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			return nil, err
		}
		out = append(out, got)
	}
	return out, nil
}

// logCall records a stand-in command, for the tests' assertions.
func logCall(j string) {
	if f, err := os.OpenFile(state("docker-calls"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
		fmt.Fprintln(f, j)
		f.Close()
	}
}

// webLate: as a real dashboard, started it listens a little later
// (G5_WEB_LATE requests answered 502 first).
func webLate() error {
	if late := os.Getenv("G5_WEB_LATE"); late != "" {
		return os.WriteFile(state("web-late"), []byte(late), 0o600)
	}
	return nil
}

// containerFormat is what varlatch migrate inspects of an ingress
// container (internal/migrate, containerServes).
const containerFormat = "{{.State.Status}} {{.State.Restarting}} {{.RestartCount}} {{len .NetworkSettings.Networks}}"

// brokenContainer names the state files of a service's container left
// without a network and in a crash loop: the dashboard's web-netless and
// web-restarting, <svc>-netless and <svc>-restarting otherwise.
func brokenContainer(svc string) [2]string {
	if svc == "varlatch-web" {
		svc = "web"
	}
	return [2]string{svc + "-netless", svc + "-restarting"}
}

// migrateRunsAgain reports whether `docker compose start|up` of these
// services runs the one-off varlatch-migrate again: each of varlatchd,
// the dashboard (on varlatchd) and Caddy (on the dashboard) depends on it
// (infra/compose's depends_on), unless --no-deps.
func migrateRunsAgain(args []string) bool {
	if slices.Contains(args, "--no-deps") {
		return false
	}
	for _, svc := range args {
		if slices.Contains([]string{"varlatchd", "varlatch-web", "caddy"}, svc) {
			return true
		}
	}
	return false
}

// sharedNamespace is whether varlatchd runs in the Tailscale sidecar's
// network: the shared-namespace topology (G5_SHARED_NAMESPACE), and every
// tailnet world (G5_TAILNET), whose sidecar the handoff stops and starts.
func sharedNamespace() bool {
	return os.Getenv("G5_SHARED_NAMESPACE") != "" || os.Getenv("G5_TAILNET") != ""
}

// sharedNetworkDown reports whether these docker arguments start varlatchd,
// or a one-off container of its, without its dependencies while it runs in
// the Tailscale sidecar's network (sharedNamespace) and the sidecar is
// stopped.
func sharedNetworkDown(args []string) bool {
	if !sharedNamespace() || !stopped("tailscale") || len(args) < 3 || args[0] != "compose" || !slices.Contains(args, "--no-deps") {
		return false
	}
	return (args[1] == "run" || args[1] == "up" && !slices.Contains(args, "--no-start")) && slices.Contains(args, "varlatchd")
}

// fakeDockerReverse answers the commands a reverse migration gives; ok is
// false for the others (fakeDocker's).
func fakeDockerReverse(args []string) (int, bool) {
	fail := func(f string, a ...any) (int, bool) { fmt.Fprintf(os.Stderr, f+"\n", a...); return 1, true }
	j := strings.Join(args, " ")
	logCall(j)
	if code, ok := dockerByID(args); ok {
		return code, true
	}
	if sharedNetworkDown(args) {
		// As Docker: a container in a stopped container's network
		// namespace does not start.
		return fail("Error response from daemon: cannot join network namespace of a non running container: g5-installation-tailscale-1")
	}
	switch {
	case len(args) >= 3 && args[0] == "compose" && (args[1] == "start" || args[1] == "up") && migrateRunsAgain(args[2:]) && readGate() != nil:
		// As the real Compose: starting a service that depends on the
		// one-off varlatch-migrate (service_completed_successfully) runs it
		// again, and the TypeScript migrate refuses behind any gate
		// (services/varlatchd/src/cli.ts, migrateCommand), so the service
		// does not start (run r8 of the 7.8b rehearsal).
		return fail("Migration refused during installation maintenance\nOperator command failed; check configuration and maintenance status.\n" +
			"service \"varlatch-migrate\" didn't complete successfully: exit 1")
	case len(args) == 3 && args[0] == "compose" && args[1] == "restart" && args[2] != "tailscale":
		if containerGone(args[2]) {
			return fail("no container to restart: %s", args[2])
		}
		if err := setStopped(args[2], false); err != nil {
			return fail("%v", err)
		}
		return okOr(readdress(args[2])), true
	case len(args) >= 5 && args[0] == "compose" && args[1] == "up" && args[2] == "--no-start" && args[len(args)-1] == "varlatchd":
		// As Compose: a volume that is not there is made, empty; a container
		// that is there, and did not change, is left as it is.
		if err := makeVolume(ownVolume("varlatchd"), nil); err != nil {
			return fail("%v", err)
		}
		_ = os.Remove(state("sidecar-remade"))
		if stopped("varlatchd") && containerGone("varlatchd") {
			_ = os.Remove(state("gone-varlatchd"))
			return okOr(os.WriteFile(state("created-varlatchd"), nil, 0o600)), true
		}
		return 0, true
	case len(args) >= 19 && args[0] == "run":
		return ownRun(args), true
	case j == "compose --profile deploy config --images":
		fmt.Println("postgres:17.6\nghcr.io/x/varlatch-web@sha256:bb\npostgres:17.6")
		return 0, true
	case len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[3] == "{{.Id}}":
		if _, err := os.Stat(state("images-gone")); err == nil {
			return fail("Error response from daemon: No such image: %s", args[4])
		}
		fmt.Println("sha256:x")
		return 0, true
	case len(args) == 3 && args[0] == "pull" && args[1] == "-q":
		if _, err := os.Stat(state("pull-fails")); err == nil {
			return fail("Error response from daemon: denied")
		}
		return 0, true
	case len(args) == 3 && args[0] == "compose" && args[1] == "start" && containerGone(args[2]):
		// As Compose: nothing to start, exit 0.
		fmt.Fprintf(os.Stderr, "service %q has no container to start\n", args[2])
		return 0, true
	case len(args) >= 3 && args[0] == "compose" && (args[1] == "stop" || args[1] == "start"):
		for _, svc := range args[2:] {
			if err := setStopped(svc, args[1] == "stop"); err != nil {
				return fail("%v", err)
			}
			if args[1] == "start" {
				if err := readdress(svc); err != nil {
					return fail("%v", err)
				}
			}
			// `start` reuses the stopped container: one a failed start
			// left without a network (web-netless) stays so.
			if svc == "varlatch-web" && args[1] == "start" {
				if err := webLate(); err != nil {
					return fail("%v", err)
				}
			}
		}
		return 0, true
	case len(args) >= 4 && args[0] == "compose" && args[1] == "up" && args[2] == "-d":
		if err := mountAsConfigured(args[3:]); err != nil {
			return fail("%v", err)
		}
		for _, svc := range args[3:] {
			if strings.HasPrefix(svc, "--") {
				continue
			}
			if svc == "postgres" {
				// A fresh volume is made empty: no database file yet.
				for _, s := range []string{"postgres", "convex-backend"} {
					if v := configuredVolume(s); v != ownVolume(s) {
						if err := makeVolume(v, nil); err != nil {
							return fail("%v", err)
						}
					}
				}
			}
			if svc == "varlatchd" {
				// As Compose: a volume that is not there is made, empty.
				if err := makeVolume(ownVolume(svc), nil); err != nil {
					return fail("%v", err)
				}
			}
			// A container that runs, and did not change, is left as it is.
			again := stopped(svc) || slices.Contains(args, "--force-recreate") || svc == "varlatchd"
			if err := setStopped(svc, false); err != nil {
				return fail("%v", err)
			}
			if again {
				if err := readdress(svc); err != nil {
					return fail("%v", err)
				}
			}
			if slices.Contains(args, "--force-recreate") {
				// A new container: its network attached again, its crash
				// loop (and restart count) gone.
				for _, f := range brokenContainer(svc) {
					if err := os.Remove(state(f)); err != nil && !errors.Is(err, os.ErrNotExist) {
						return fail("%v", err)
					}
				}
			}
			if svc == "varlatch-web" {
				if err := webLate(); err != nil {
					return fail("%v", err)
				}
			}
		}
		return 0, true
	case j == "compose down":
		for _, svc := range []string{"varlatchd", "varlatch-web", "postgres", "convex-backend", "caddy", "tailscale"} {
			if err := setStopped(svc, true); err != nil {
				return fail("%v", err)
			}
		}
		return okOr(os.WriteFile(state("down"), nil, 0o600)), true
	case len(args) == 5 && args[0] == "volume" && args[1] == "inspect" && args[2] == "--format" && args[3] == volumeFormat:
		if !volumeThere(args[4]) {
			return fail("Error response from daemon: get %s: no such volume", args[4])
		}
		printVolume(args[4])
		return 0, true
	case (len(args) == 9 || len(args) == 7) && args[0] == "volume" && args[1] == "create":
		name := args[len(args)-1]
		if err := makeVolume(name, args[2:len(args)-1]); err != nil {
			return fail("%v", err)
		}
		fmt.Println(name)
		return 0, true
	case j == "ps -a -q --no-trunc --filter label=com.docker.compose.project":
		for _, c := range containers() {
			fmt.Println(c.id)
		}
		return 0, true
	case len(args) > 5 && args[0] == "inspect" && args[1] == "--type" && args[2] == "container" && args[3] == "--format" && args[4] == containersFormat:
		for _, id := range args[5:] {
			i := slices.IndexFunc(containers(), func(c container) bool { return c.id == id })
			if i < 0 {
				return fail("Error response from daemon: No such container: %s", id)
			}
			containers()[i].print()
		}
		return 0, true
	case len(args) == 3 && args[0] == "volume" && args[1] == "rm", len(args) == 4 && args[0] == "volume" && args[1] == "rm" && args[2] == "-f":
		// rm -f is quiet of a volume not there; rm is not.
		name := args[len(args)-1]
		if !volumeThere(name) {
			if len(args) == 4 {
				return 0, true
			}
			return fail("Error response from daemon: get %s: no such volume", name)
		}
		if len(volumeUsers(name)) > 0 {
			return fail("Error response from daemon: remove %s: volume is in use", name)
		}
		if f, err := os.OpenFile(state("removed-volumes"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
			fmt.Fprintln(f, name)
			f.Close()
		}
		if err := os.Remove(state("db-" + name + ".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail("%v", err)
		}
		vols, _ := os.ReadFile(state("volumes"))
		_ = os.WriteFile(state("volumes"), bytes.ReplaceAll(vols, []byte(name+"\n"), nil), 0o600)
		return 0, true
	case len(args) == 6 && args[0] == "ps" && args[1] == "-a" && args[2] == "--filter" && strings.HasPrefix(args[3], "volume=") && args[4] == "--format":
		// The containers using a volume (a stopped container keeps its
		// volume).
		v := strings.TrimPrefix(args[3], "volume=")
		for _, c := range volumeUsers(v) {
			fmt.Println(c)
		}
		// A container of the test's still holding a reverse's fresh volume.
		if vols, _ := os.ReadFile(state("volumes")); v != postgresVolume() && slices.Contains(strings.Fields(string(vols)), v) {
			if _, err := os.Stat(state("fresh-in-use")); err == nil {
				fmt.Println("g5-stray-1")
			}
		}
		return 0, true
	case len(args) == 5 && args[0] == "compose" && args[1] == "ps" && args[2] == "-a" && args[3] == "-q":
		// A service's one container, running or not.
		fmt.Println("g5-" + args[4] + "-1")
		return 0, true
	case len(args) == 4 && args[0] == "inspect" && args[1] == "--format" && args[2] == containerFormat:
		// As Docker: a container a failed start left without a network
		// (<svc>-netless) runs with none, and one in a crash loop
		// (<svc>-restarting) is caught running, its restart count up.
		svc := strings.TrimSuffix(strings.TrimPrefix(args[3], "g5-"), "-1")
		status, networks, restarts := "running", 1, 0
		if stopped(svc) {
			status = "exited"
		}
		files := brokenContainer(svc)
		if _, err := os.Stat(state(files[0])); err == nil {
			networks = 0
		}
		if _, err := os.Stat(state(files[1])); err == nil {
			restarts = 7
		}
		fmt.Printf("%s false %d %d\n", status, restarts, networks)
		return 0, true
	case j == "compose ps --status running --services":
		services := []string{"postgres", "varlatchd", "convex-backend", "varlatch-web"}
		if sharedNamespace() {
			// The Tailscale topology: the sidecar varlatchd shares.
			services = append(services, "tailscale")
		}
		if env, _ := os.ReadFile(".env"); bytes.Contains(env, []byte("docker-compose.caddy.yml")) {
			// The public-ingress topology: Caddy in front.
			services = append(services, "caddy")
		}
		for _, svc := range services {
			if !stopped(svc) {
				fmt.Println(svc)
			}
		}
		return 0, true
	case j == "compose config --no-interpolate --format json":
		varlatchd := map[string]any{}
		if os.Getenv("G5_SHARED_NAMESPACE") != "" {
			varlatchd["network_mode"] = "service:tailscale"
		}
		printConfig(map[string]map[string]any{"varlatchd": varlatchd})
		return 0, true
	case j == "compose --profile deploy run --rm -T convex-deploy":
		if stopped("convex-backend") {
			return fail("convex-backend is not running")
		}
		return 0, true
	}
	importArgs := []string{"compose", "--profile", "varlatch-rollback", "run", "--rm", "-T", "varlatch-reverse-import", "admin", "migration", "import", "--in", "-"}
	if slices.Equal(args, importArgs) {
		return tsImport(), true
	}
	oneOff := []string{"compose", "run", "--rm", "-T", "--no-deps", "varlatchd", "admin", "migration"}
	if len(args) > len(oneOff) && slices.Equal(args[:len(oneOff)], oneOff) {
		return tsMigration(args[len(oneOff)], args[len(oneOff)+1:]), true
	}
	// compose run keeps 0.23.0's entrypoint (node dist/cli.js): a command
	// that names node again reaches its CLI as a command, which refuses it
	// (rehearsal r16d).
	if i := slices.Index(args, "run"); i >= 0 && slices.Contains(args[i:], "node") {
		fmt.Fprintln(os.Stderr, "Unknown command: node; Commands: serve | migrate | admin.")
		return 1, true
	}
	return 0, false
}

// tsImport is 0.23.0's `admin migration import --in -`: its refusals
// before it reads its input (varlatch migrate's copy then meets a closed
// pipe), the reverse bundle on its standard input, read to its end, and
// its answer on its standard output.
func tsImport() int {
	fail := func(f string, a ...any) int {
		fmt.Fprintf(os.Stderr, "varlatchd admin migration import: "+f+"\n", a...)
		return 1
	}
	if !stopped("varlatchd") {
		return fail("varlatchd is running; stop it first: the import builds the database it starts on")
	}
	g := readGate()
	if g != nil && g.Kind != "migrated-out" {
		return fail("a %s gate is open; the import runs on an installation that migrated out, or a new one", g.Kind)
	}
	db := currentDB()
	if db == state("source.json") {
		return fail("the database is not empty: it holds relations of another schema; the import builds a fresh database")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fail("%v", err)
	}
	if _, err := os.Stat(db); err == nil {
		return fail("the database is not empty: it holds rows; the import builds a fresh database")
	}
	kek, err := os.ReadFile(filepath.Join("secrets", "varlatch-kek"))
	if err != nil {
		return fail("%v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(kek)))
	if err != nil {
		return fail("the Root KEK file")
	}
	s := migrationtest.FromReverse(stdTB{}, b, key)
	if _, err := os.Stat(state("corrupt-import")); err == nil {
		// A faulty import, for the checks to catch: a webhook lost.
		s.Rows["webhooks"] = s.Rows["webhooks"][1:]
	}
	if err := saveSource(s, db); err != nil {
		return fail("%v", err)
	}
	gate := "none"
	if g != nil {
		if err := writeGate(nil); err != nil {
			return fail("%v", err)
		}
		gate = "lifted"
	}
	r, _ := bundle.NewReader(bytes.NewReader(b), migrationtest.Manifest(stdTB{}))
	out, _ := json.Marshal(map[string]any{"installationId": rowValue(s.Rows["installation"][0], "id"), "release": r.Header().Release,
		"auditPosition": fmt.Sprint(s.AuditPosition), "tables": len(s.Rows), "rows": 0, "sha256": "", "alreadyImported": false, "migratedOutGate": gate})
	fmt.Println(string(out))
	return 0
}

// --- the tests ---

// rollbackArgs are --rollback's options (and its --resume's, --abort's).
func (w *world) rollbackArgs(extra ...string) []string {
	a := []string{"migrate", "--from", w.compose, "--drain", "5s", "--transfer-timeout", "20s"}
	if w.image {
		a = append(a, "--to-data", w.data, "--to-keys", w.keys, "--to-config", w.serviceConf, "--to-image",
			"ghcr.io/varlatch/varlatchd:0.50.0-dev@sha256:"+hex.EncodeToString(randomBytes(32)), "--to-service", "varlatch-go")
	} else {
		a = append(a, "--config", w.conf)
	}
	return append(append(a, w.extraArgs...), extra...)
}

func (w *world) rollback(pause string, extra ...string) int {
	w.t.Helper()
	return w.runArgs(pause, w.rollbackArgs(extra...))
}

// migrated is a world migrated forward to open.
func migratedWorld(t *testing.T, image, coolify bool) *world {
	t.Helper()
	w := newWorld(t, image)
	w.coolify = coolify
	if coolify {
		w.coolifyLayout()
	}
	w.useState()
	code := w.run("")
	if image && code == 75 {
		w.startImageService()
		code = w.run("", "--resume")
	}
	if coolify && code == 75 {
		// The operator sets the domain on the Go application, and deploys it.
		w.domainToGo()
		code = w.run("", "--resume")
	}
	if code != 0 {
		t.Fatalf("the forward migration: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("migrated", "open", "open", "target-open", "migrated-out")
	return w
}

// oldDB is the retained pre-migration database's hash: a reverse never
// changes it.
func (w *world) oldDB() string {
	b, err := os.ReadFile(filepath.Join(w.stateDir, "source.json"))
	if err != nil {
		w.t.Fatal(err)
	}
	return hex.EncodeToString(b[:min(len(b), 64)]) + fmt.Sprint(len(b))
}

// goRuns is whether the target's varlatchd process runs.
func (w *world) goRuns() bool {
	w.useState()
	pid := readPID()
	return pid > 0 && alive(pid)
}

// volume is the volume the stand-in's Postgres runs on now, and whether
// its database holds the rebuild.
func (w *world) volume() (string, bool) {
	t := w.t
	t.Helper()
	cwd, _ := os.Getwd()
	if err := os.Chdir(w.compose); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	w.useState()
	v := postgresVolume()
	_, err := os.Stat(currentDB())
	return v, err == nil && v != "postgres-data"
}

// rbState is the reverse's stated state: the journals, who answers the
// public URL, the TypeScript side's gate, whether Go runs, and whether
// the TypeScript side runs on the fresh volume (and holds the rebuild).
type rbState struct {
	src, tgt, answers, gate string
	goRuns, fresh, rebuilt  bool
}

func (w *world) expectReverse(when string, want rbState) {
	t := w.t
	t.Helper()
	w.expect(when, want.src, want.tgt, want.answers, want.gate)
	if r := w.goRuns(); r != want.goRuns {
		t.Errorf("%s: Go runs %v, want %v", when, r, want.goRuns)
	}
	v, rebuilt := w.volume()
	if fresh := v != "postgres-data"; fresh != want.fresh || rebuilt != want.rebuilt {
		t.Errorf("%s: Postgres on %s (rebuilt %v), want fresh %v rebuilt %v", when, v, rebuilt, want.fresh, want.rebuilt)
	}
}

var (
	// Undone: Go open and serving, the TypeScript side as the forward
	// migration left it.
	undoneState = rbState{"open", "open", "target-open", "migrated-out", true, false, false}
	// Rolled back: the TypeScript release serves on the fresh volume, Go
	// stopped.
	rolledBackState = rbState{"rolled-back", "rolled-back", "source", "", false, true, true}
)

// goRefuses is whether varlatchd refuses to start on the target's data
// directory, saying the migration was reversed.
func (w *world) goRefuses() bool {
	w.useState()
	err := startService(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), filepath.Join(w.stateDir, "service.conf"))
	if err == nil {
		_ = stopService()
		return false
	}
	b, _ := os.ReadFile(filepath.Join(w.stateDir, "service.log"))
	return bytes.Contains(b, []byte("was reversed"))
}

// G5, the interrupted reverse: --rollback killed at each phase boundary,
// the stated state held there (Go running until the address moves), a
// plain --rollback refused over it, then --resume (undone before the
// transfer, finished in it) and --abort (undone, but once rolled back)
// taking it to its end; a second --resume changes nothing. The retained
// pre-migration database is never changed; the fresh volume is removed
// when undone; nothing secret is printed.
func TestG5Rollback(t *testing.T) {
	for _, c := range []struct {
		point string
		at    rbState
		// Where --resume takes it: undone, or rolled back.
		resumed rbState
		abort   bool
	}{
		{"entered rollback", rbState{"rollback", "rollback", "target-open", "migrated-out", true, false, false}, undoneState, true},
		{"rollback barrier held", rbState{"rollback", "rollback", "target-gated", "migrated-out", true, false, false}, undoneState, true},
		{"entered rollback-exported", rbState{"rollback-exported", "rollback-exported", "target-gated", "migrated-out", true, false, false}, undoneState, true},
		{"rollback rebuilt", rbState{"rollback-exported", "rollback-exported", "target-gated", "migrated-out", true, true, false}, undoneState, true},
		{"entered rollback-imported", rbState{"rollback-imported", "rollback-imported", "target-gated", "", true, true, true}, undoneState, true},
		{"entered rollback-checked", rbState{"rollback-checked", "rollback-checked", "target-gated", "", true, true, true}, undoneState, true},
		{"entered rollback-transfer", rbState{"rollback-transfer", "rollback-transfer", "target-gated", "", true, true, true}, rolledBackState, true},
		{"rollback go stopped", rbState{"rollback-transfer", "rollback-transfer", "none", "", false, true, true}, rolledBackState, true},
		{"rollback transfer started", rbState{"rollback-transfer", "rollback-transfer", "source", "", false, true, true}, rolledBackState, true},
		{"entered rolled-back", rbState{"rolled-back", "rolled-back", "source", "", false, true, true}, rolledBackState, false},
	} {
		for _, abort := range []bool{false, true} {
			if abort && !c.abort {
				continue
			}
			name := c.point + map[bool]string{false: ", resumed", true: ", aborted"}[abort]
			t.Run(name, func(t *testing.T) {
				w := migratedWorld(t, false, false)
				old := w.oldDB()
				if code := w.rollback(c.point, "--rollback"); code != -1 {
					t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.expectReverse("killed at "+c.point, c.at)
				if c.point != "entered rolled-back" {
					if code := w.rollback("", "--rollback"); code != 1 {
						t.Errorf("a --rollback over the interrupted reverse: %d", code)
					}
				}
				final := c.resumed
				if abort {
					final = undoneState
					if code := w.rollback("", "--abort"); code != 0 {
						t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
				} else {
					if code := w.rollback("", "--resume"); (final == undoneState) != (code == 1) {
						t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
					}
				}
				if !c.abort {
					if code := w.rollback("", "--abort"); code != 1 {
						t.Fatalf("--abort once rolled back: %d", code)
					}
				}
				w.expectReverse("finished", final)
				if final == rolledBackState && !w.goRefuses() {
					t.Error("varlatchd starts on the reversed data directory")
				}
				if final == undoneState {
					// The fresh volume is gone; the old volume, the
					// installation's Compose files are as they were.
					w.useState()
					if b, _ := os.ReadFile(filepath.Join(w.stateDir, "volumes")); len(bytes.TrimSpace(b)) != 0 {
						t.Errorf("fresh volumes left: %q", b)
					}
					if _, err := os.Stat(filepath.Join(w.compose, "docker-compose.varlatch-rollback.yml")); !os.IsNotExist(err) {
						t.Errorf("migrate's Compose file left: %v", err)
					}
				}
				if w.oldDB() != old {
					t.Error("the retained pre-migration database changed")
				}
				// --resume again changes nothing.
				if code := w.rollback("", "--resume"); code != 0 {
					t.Errorf("a second --resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				w.expectReverse("after a second --resume", final)
				w.noSecrets()
			})
		}
	}
}

// undoneReleased is the source journal's record of an undone reverse:
// whether there is one, and whether it says the barrier was lifted.
func (w *world) undoneReleased() (released, ok bool) {
	w.t.Helper()
	var j struct {
		Rollback *struct {
			Undone *struct {
				Released bool `json:"barrierReleased"`
			} `json:"undone"`
		} `json:"rollback"`
	}
	b, err := os.ReadFile(filepath.Join(w.compose, "migration.json"))
	if err != nil || json.Unmarshal(b, &j) != nil {
		w.t.Fatalf("the source's journal: %v", err)
	}
	if j.Rollback == nil || j.Rollback.Undone == nil {
		return false, false
	}
	return j.Rollback.Undone.Released, true
}

// The whole reverse, uninterrupted: the TypeScript release serves the
// installation on its fresh volume, migrate's Compose file names the fresh
// volumes and the release's pinned image, Go never starts on its copy
// again, and a forward migration run again is refused until --finish.
// Then the reverse checks failing (a faulty import) undo it: Go serves.
func TestG5RollbackWhole(t *testing.T) {
	// Go obtained a certificate while the migration was open (its
	// issuance count, certificate_issuances, holds rows): the reverse
	// checks run on Go's copy, which an import never wrote, and the
	// rollback goes through (the count is carried apart from the bundle).
	t.Run("after an issuance", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		w.useState()
		if err := stopService(); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", "file:"+filepath.Join(w.data, "varlatch.db"))
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UnixMilli()
		_, err = db.Exec("INSERT INTO certificate_issuances (name, started_at, outcome, ended_at) VALUES (?, ?, 'issued', ?), (?, ?, 'refused', ?)",
			"varlatch.example.test", now-60_000, now-50_000, "varlatch.example.test", now-40_000, now-30_000)
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := startService(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), filepath.Join(w.stateDir, "service.conf")); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--rollback"); code != 0 {
			t.Fatalf("--rollback after an issuance: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("rolled back", rolledBackState)
		w.noSecrets()
	})
	t.Run("rolled back", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		old := w.oldDB()
		// What a killed run left on this host: an export's .partial in the
		// backups directory (the reverse checks' re-export streams there),
		// an export's directory in the source's.
		leftovers := []string{filepath.Join(w.compose, "backups", "migration-0123456789ab.jsonl.partial"), filepath.Join(w.compose, ".dry-run-123")}
		if err := os.WriteFile(leftovers[0], []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(leftovers[1], 0o700); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--rollback"); code != 0 {
			t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("rolled back", rolledBackState)
		for _, p := range leftovers {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("a leftover is still there: %s", filepath.Base(p))
			}
		}
		ov, err := os.ReadFile(filepath.Join(w.compose, "docker-compose.varlatch-rollback.yml"))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := w.volume()
		if !strings.HasPrefix(v, "g5-installation_postgres-data-") {
			t.Errorf("the fresh volume %s is not named by the Compose project (g5-installation)", v)
		}
		if !bytes.Contains(ov, []byte("name: "+v)) || !bytes.Contains(ov, []byte("image: "+shared.pin)) || bytes.Contains(ov, []byte("PASSWORD=")) {
			t.Errorf("migrate's Compose file:\n%s", ov)
		}
		env, _ := os.ReadFile(filepath.Join(w.compose, ".env"))
		if !bytes.Contains(env, []byte("COMPOSE_FILE=docker-compose.yml:docker-compose.varlatch-rollback.yml\n")) {
			t.Errorf(".env: %s", env)
		}
		if !w.goRefuses() {
			t.Error("varlatchd starts on the reversed data directory")
		}
		if w.oldDB() != old {
			t.Error("the retained pre-migration database changed")
		}
		if code := w.run(""); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "was rolled back") {
			t.Errorf("a forward migration after the reverse: %d", code)
		}
		w.noSecrets()
	})
	t.Run("the reverse checks fail", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if err := os.WriteFile(filepath.Join(w.stateDir, "corrupt-import"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the reverse checks failed") {
			t.Fatalf("--rollback with a faulty import: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		// The undo completed beside the running varlatchd, and journalled
		// the barrier lifted (the source's journal; Go's says open).
		if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "the reverse was undone: Go serves again") || strings.Contains(out, "could not record it") {
			t.Errorf("the undo's end:\n%s", out)
		}
		if released, ok := w.undoneReleased(); !ok || !released {
			t.Errorf("the journal: undone %v, barrier released %v", ok, released)
		}
		w.expectReverse("undone", undoneState)
		w.noSecrets()
	})
	// varlatchd in the Tailscale sidecar's network (network_mode:
	// service:tailscale), its one-off commands too. With the sidecar
	// running, a reverse whose checks fail is undone as anywhere else
	// (the TypeScript varlatchd started without its dependencies). With
	// it stopped and no tailnet handoff (these worlds have none: the
	// sidecar is the operator's), --rollback is refused before anything,
	// with the step to take: no barrier, no one-off container, no start.
	// After a tailnet handoff, which stopped the sidecar itself, the
	// reverse starts it (TestG5TailnetWhole and the tailnet matrix).
	t.Run("shared ns, the sidecar running", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		t.Setenv("G5_SHARED_NAMESPACE", "1")
		if err := os.WriteFile(filepath.Join(w.stateDir, "corrupt-import"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the reverse was undone: Go serves again") {
			t.Fatalf("--rollback with a faulty import: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if !slices.Contains(w.calls("docker-calls"), "compose up --no-start --no-deps varlatchd") || !slices.Contains(w.calls("docker-calls"), "start g5-varlatchd-1") {
			t.Errorf("the TypeScript varlatchd was not started without its dependencies: %v", w.calls("docker-calls"))
		}
		w.expectReverse("undone", undoneState)
		w.noSecrets()
	})
	t.Run("shared ns, the sidecar stopped", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		t.Setenv("G5_SHARED_NAMESPACE", "1")
		if err := os.WriteFile(filepath.Join(w.stateDir, "stopped-tailscale"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		before := len(w.calls("docker-calls"))
		code := w.rollback("", "--rollback")
		out := string(w.outputs[len(w.outputs)-1])
		if code != 1 || !strings.Contains(out, "start it by hand (docker compose ") || !strings.Contains(out, " up -d --no-deps tailscale") || !strings.Contains(out, "then varlatch migrate --rollback again") {
			t.Fatalf("--rollback with the sidecar stopped: %d\n%s", code, out)
		}
		for _, c := range w.calls("docker-calls")[before:] {
			if strings.HasPrefix(c, "compose run") || strings.HasPrefix(c, "compose up") || strings.HasPrefix(c, "compose start") || strings.HasPrefix(c, "compose stop") {
				t.Errorf("ran %q", c)
			}
		}
		if !w.stopped("tailscale") {
			t.Error("the old node was started")
		}
		w.expect("refused", "open", "open", "target-open", "migrated-out")
	})
	// The undo puts the installation back on its own volumes, then asks
	// Docker who uses each fresh one: a container still holding one (not
	// the installation's) leaves it, said, and Go serves meanwhile (its
	// outage does not wait for that); --resume finishes the undo once it is
	// free.
	t.Run("fresh volume in use", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		for _, m := range []string{"corrupt-import", "fresh-in-use"} {
			if err := os.WriteFile(filepath.Join(w.stateDir, m), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "is still used by g5-stray-1: left as it is") {
			t.Fatalf("--rollback, a fresh volume in use: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		fresh, _ := os.ReadFile(filepath.Join(w.stateDir, "volumes"))
		removed, _ := os.ReadFile(filepath.Join(w.stateDir, "removed-volumes"))
		if len(strings.Fields(string(fresh))) == 0 || len(strings.TrimSpace(string(removed))) != 0 {
			t.Fatalf("the fresh volume: kept %q, removed %q", fresh, removed)
		}
		if s, d := w.phases(); s != "open" || d != "open" || !w.goRuns() || !w.stopped("varlatchd") || w.answers() != "target-open" {
			t.Fatalf("meanwhile: the journals %s / %s, Go runs %v, varlatchd stopped %v, the address answers %s", s, d, w.goRuns(), w.stopped("varlatchd"), w.answers())
		}
		if err := os.Remove(filepath.Join(w.stateDir, "fresh-in-use")); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--resume"); code != 0 {
			t.Fatalf("--resume once the volume is free: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("undone", undoneState)
		if b, _ := os.ReadFile(filepath.Join(w.stateDir, "volumes")); len(strings.TrimSpace(string(b))) != 0 {
			t.Errorf("fresh volumes left after the undo: %q", b)
		}
	})
	t.Run("undo killed before the release", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.rollback("rollback barrier held", "--rollback"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		// An export's .partial, as a run killed in the reverse checks'
		// re-export leaves it: the undo removes it.
		bundle := filepath.Join(w.compose, "backups", "migration-0123456789ab.jsonl.partial")
		if err := os.WriteFile(bundle, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("rollback undone open", "--abort"); code != -1 {
			t.Fatalf("the undo not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if _, err := os.Stat(bundle); !os.IsNotExist(err) {
			t.Errorf("the bundle's copy after the undo: %v", err)
		}
		// Killed before the release: the journal does not say released.
		if released, ok := w.undoneReleased(); !ok || released {
			t.Errorf("at the kill: undone %v, barrier released %v", ok, released)
		}
		// Go's journal says open, its barrier stands; then Go stops.
		w.useState()
		if err := stopService(); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--resume"); code != 0 {
			t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go's barrier stands: it is lifted") {
			t.Errorf("the barrier was not lifted:\n%s", w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("finished", undoneState)
		if released, ok := w.undoneReleased(); !ok || !released {
			t.Errorf("after the resume: undone %v, barrier released %v", ok, released)
		}
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(w.stateDir, "service.log"))
			t.Logf("--resume:\n%s\nservice.log (end):\n%s", w.outputs[len(w.outputs)-1], log[max(0, len(log)-3000):])
		}
	})
	t.Run("outside the window", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		p := filepath.Join(w.compose, "migration.json")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var j map[string]any
		if err := json.Unmarshal(b, &j); err != nil {
			t.Fatal(err)
		}
		for _, s := range j["history"].([]any) {
			if step := s.(map[string]any); step["phase"] == "switched" {
				step["at"] = time.Now().Add(-31 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
			}
		}
		b, _ = json.MarshalIndent(j, "", "  ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "rollback window is over") {
			t.Fatalf("--rollback after 31 days: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("refused", undoneState)
	})
	// An upgrade to a release that ends the window recorded it in Go's
	// journal (varlatch upgrade, beside the running varlatchd: open over
	// open, no transfer gate): --rollback refuses, nothing changed.
	t.Run("ended by an upgrade", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		b, err := os.ReadFile(filepath.Join(w.data, "migration.json"))
		if err != nil {
			t.Fatal(err)
		}
		var j map[string]any
		if err := json.Unmarshal(b, &j); err != nil {
			t.Fatal(err)
		}
		j["windowEnded"] = map[string]any{"release": "0.50.1", "at": time.Now().UTC().Format(time.RFC3339Nano)}
		b, _ = json.Marshal(j)
		cmd := exec.Command(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), "admin", "migrate", "state", "--write", "--config", w.conf)
		cmd.Stdin = bytes.NewReader(b)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("the window's end written beside the running varlatchd: %v\n%s", err, out)
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "rollback window ended when varlatchd 0.50.1 was installed") {
			t.Fatalf("--rollback once an upgrade ended the window: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("refused", undoneState)
	})
}

// The image's service: Go's stop is the operator's (exit 75), so is its
// start when an abort gives the address back.
func TestG5RollbackImage(t *testing.T) {
	t.Run("the operator's stop", func(t *testing.T) {
		w := migratedWorld(t, true, false)
		if code := w.rollback("", "--rollback"); code != 75 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Stop the Go service varlatch-go") {
			t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("waiting for the stop", rbState{"rollback-transfer", "rollback-transfer", "target-gated", "", true, true, true})
		_ = stopService()
		if code := w.rollback("", "--resume"); code != 0 {
			t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("rolled back", rolledBackState)
		w.noSecrets()
	})
	t.Run("an abort after the stop", func(t *testing.T) {
		w := migratedWorld(t, true, false)
		if code := w.rollback("", "--rollback"); code != 75 {
			t.Fatalf("--rollback: %d", code)
		}
		_ = stopService()
		if code := w.rollback("rollback transfer started", "--resume"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if code := w.rollback("", "--abort"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Start the Go service varlatch-go") {
			t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.startImageService()
		if code := w.rollback("", "--resume"); code != 1 {
			t.Fatalf("the undo resumed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expectReverse("undone", undoneState)
		w.noSecrets()
	})
}

// The Coolify shape: nothing begins until the operator's route leads the
// name to the TypeScript installation (exit 75, Go serving); with it the
// reverse runs to its end, Go stopping once the TypeScript release answers
// at the address.
func TestG5RollbackCoolify(t *testing.T) {
	w := migratedWorld(t, false, true)
	for range 2 {
		before := len(w.calls("docker-calls"))
		code := w.rollback("", "--rollback")
		out := string(w.outputs[len(w.outputs)-1])
		if code != 75 || !strings.Contains(out, "the address answers by no route of this migration") || !strings.Contains(out, "/data/coolify/proxy/dynamic/varlatch-rollback.yaml") ||
			!strings.Contains(out, "url: \"http://g5-varlatch-web-1:80\"") || !strings.Contains(out, "X-Varlatch-Rollback: \"mig_") || !strings.Contains(out, "do not Deploy, Restart or Stop the TypeScript application") {
			t.Fatalf("--rollback without a route: %d\n%s", code, out)
		}
		for _, c := range w.calls("docker-calls")[before:] {
			if strings.HasPrefix(c, "compose up") || strings.HasPrefix(c, "compose run") || strings.HasPrefix(c, "volume create") {
				t.Errorf("ran %q", c)
			}
		}
		w.expectReverse("no route", undoneState)
	}
	w.routeBack()
	if code := w.rollback("", "--rollback"); code != 0 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the way back works") {
		t.Fatalf("--rollback with the route: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expectReverse("rolled back", rolledBackState)
	// The route is not needed any more.
	w.routeAway()
	w.expectReverse("the route removed", rolledBackState)
	w.noSecrets()

	// Aborted, or interrupted: the dashboard stops again, the operator is
	// told to remove the route, and Go serves.
	for _, how := range []string{"--abort", "--resume"} {
		w = migratedWorld(t, false, true)
		w.routeBack()
		if code := w.rollback("entered rollback-checked", "--rollback"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if code := w.rollback("", how); (how == "--abort") != (code == 0) {
			t.Fatalf("%s: %d\n%s", how, code, w.outputs[len(w.outputs)-1])
		}
		if !strings.Contains(string(w.outputs[len(w.outputs)-1]), "remove the route put in the proxy before the reverse") || !w.has("web-stopped") {
			t.Errorf("%s: the dashboard stopped %v:\n%s", how, w.has("web-stopped"), w.outputs[len(w.outputs)-1])
		}
		w.routeAway()
		w.expectReverse("undone by "+how, undoneState)
	}
	// Volumes of the names the reverse planned, made by another while it was
	// killed before it made its own: its undo leaves them.
	w = migratedWorld(t, false, true)
	w.routeBack()
	if code := w.rollback("entered rollback-exported", "--rollback"); code != -1 {
		t.Fatalf("not killed: %d", code)
	}
	if code := w.rollback("", "--abort"); code != 0 {
		t.Fatalf("--abort: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if code := w.rollback("rollback volumes made", "--rollback"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	b, _ := os.ReadFile(filepath.Join(w.stateDir, "volumes"))
	fresh := strings.Fields(string(b))
	if len(fresh) != 2 {
		t.Fatalf("the volumes made: %q", b)
	}
	// One is another's now; the killed run's own other one goes.
	if err := os.WriteFile(filepath.Join(w.stateDir, "owner-"+fresh[0]), []byte("mig_another"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.rollback("", "--resume"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the reverse was undone") {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if b, _ := os.ReadFile(filepath.Join(w.stateDir, "volumes")); strings.TrimSpace(string(b)) != fresh[0] {
		t.Errorf("volumes left: %q, want %s", b, fresh[0])
	}
	// And the next reverse takes another name.
	w.routeAway()
	w.routeBack()
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if v, _ := w.volume(); v == fresh[0] || !strings.HasPrefix(v, coolifyApp+"_postgres-data-") {
		t.Errorf("the reverse took %s", v)
	}
	w.noSecrets()
}
