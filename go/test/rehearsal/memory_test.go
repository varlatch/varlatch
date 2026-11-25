// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// VL_RH_MEMORY=1 (a restored copy only): what the copy holds stays in
// memory, or on an encrypted disk whose key is in memory only (disk_test.go).
// Its files (the run's work directory, the target's, the archive
// and the keys, TMPDIR) are on a tmpfs the operator mounted, which is
// checked, never mounted here. Docker's part (the volumes Postgres, Convex
// and varlatchd's state are on, migrate's fresh ones, the containers' own
// layers and logs, the local S3 archive) is the run's own docker
// (dockerShim), first on PATH for everything the harness starts: every
// volume is a directory of that tmpfs (a plain tmpfs volume is empty again
// once its last container stops), no container has a log, and what a
// container wrote in its own layer is looked at before it is removed.
//
// What it does not cover is in run.sh's comment.

const tmpfsMagic = 0x01021994

// memoryMargin is what must be available beside the copy's data, for the
// processes (VL_RH_MEMORY_MARGIN_MIB gives another, never less than
// memoryLeast). memoryBase and memoryFactor are the data: what a copy of
// next to nothing takes (measured: 164 MiB at the most in the whole restore
// case, and what the converter's PostgreSQL and MinIO have of their own),
// and how many times the archive's size the rest is, an estimate: a
// compressed dump, its tables and indexes, twice, and Go's copies.
const (
	memoryMargin = 2 << 30
	memoryLeast  = 1 << 30
	memoryBase   = 320 << 20
	memoryFactor = 40
)

// memoryNeed is what a run on an archive of that size needs: room for the
// data, and memory, the data in it unless it is on the crypt disk.
func memoryNeed(archive, margin int64, disk bool) (data, total int64) {
	data = memoryBase + memoryFactor*archive
	if disk {
		return data, margin
	}
	return data, data + margin
}

// marginOf is VL_RH_MEMORY_MARGIN_MIB's margin.
func marginOf(v string) (int64, error) {
	if v == "" {
		return memoryMargin, nil
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n<<20 < memoryLeast {
		return 0, fmt.Errorf("VL_RH_MEMORY_MARGIN_MIB is a number of MiB, %d or more, not %q", memoryLeast>>20, v)
	}
	return n << 20, nil
}

type memoryRun struct {
	dir     string // the shim's link and its records
	volumes string // the volumes' directories
	roots   []string
	before  []string // others' files in the temporary directories
	stop    chan struct{}
	done    sync.WaitGroup
	most    int64
	// disk: the volumes and what else is large are on the crypt disk.
	disk bool
}

var memory *memoryRun

// onTmpfs is whether path (or the nearest directory above it) is on a tmpfs.
func onTmpfs(path string) (bool, error) {
	for {
		var st syscall.Statfs_t
		err := syscall.Statfs(path, &st)
		if err == nil {
			return st.Type == tmpfsMagic, nil
		}
		if !errors.Is(err, syscall.ENOENT) || path == "/" {
			return false, err
		}
		path = filepath.Dir(path)
	}
}

// startMemory checks and prepares a run in memory, before anything of the
// copy's is anywhere.
func startMemory(t *testing.T) {
	t.Helper()
	if !prof.memory {
		return
	}
	targetRoot := os.Getenv("VL_RH_TARGET_ROOT")
	if targetRoot == "" {
		targetRoot = workDir
	}
	m := &memoryRun{dir: filepath.Join(workDir, "memory"), roots: []string{workDir, targetRoot}, stop: make(chan struct{})}
	m.volumes = filepath.Join(m.dir, "volumes")
	places := map[string][]string{}
	for what, p := range map[string]string{"the run's work directory (VL_RH_WORK)": workDir, "the target's directory (VL_RH_TARGET_ROOT)": targetRoot,
		"TMPDIR": os.TempDir(), "HOME": os.Getenv("HOME"), "the archive": prof.restore, "VL_RH_RESTORE_BEK": prof.restoreBEK, "VL_RH_RESTORE_KEK": prof.restoreKEK} {
		place, err := memoryPlace(p, prof.box)
		if err != nil {
			t.Fatalf("VL_RH_MEMORY=1: %s, %s, is neither on a tmpfs nor on the crypt disk (%v): mount one there first (the B6 kit's b6-env.sh does), noswap where the kernel has it", what, p, err)
		}
		places[place] = append(places[place], what)
		m.disk = m.disk || p == workDir && place == "crypt"
	}
	for _, place := range slices.Sorted(maps.Keys(places)) {
		slices.Sort(places[place])
		measure("memory: on "+map[string]string{"tmpfs": "a tmpfs", "crypt": "the crypt disk"}[place], strings.Join(places[place], ", "))
	}
	st, err := os.Stat(prof.restore)
	if err != nil {
		t.Fatal(err)
	}
	margin, err := marginOf(os.Getenv("VL_RH_MEMORY_MARGIN_MIB"))
	if err != nil {
		t.Fatal(err)
	}
	data, total := memoryNeed(st.Size(), margin, m.disk)
	available := memAvailable()
	free, err := tmpfsFree(workDir)
	if err != nil {
		t.Fatal(err)
	}
	said := fmt.Sprintf("the archive is %s: %s for the copy's data (%s and %d times the archive), free there %s; memory, %s beside the data (which is on the crypt disk: %v): %s, available %s",
		mib(st.Size()), mib(data), mib(memoryBase), memoryFactor, mib(free), mib(margin), m.disk, mib(total), mib(available))
	t.Logf("VL_RH_MEMORY=1: %s", said)
	measure("memory: what it needs", said)
	if available < total {
		t.Fatalf("VL_RH_MEMORY=1: not enough memory: %s", said)
	}
	if free < data {
		t.Fatalf("VL_RH_MEMORY=1: too little room for the copy's data: %s", said)
	}
	swaps, safe := swapState("/")
	measure("memory: swap", swaps)
	if prof.box && !safe {
		t.Fatalf("VL_RH_MEMORY=1: %s: a process's memory (a key, a value) could be written there; swapoff it, or have it encrypted", swaps)
	}
	// A dump of a process's memory is a file.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{m.volumes, filepath.Join(m.dir, "bin")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	if err := os.Symlink(self, filepath.Join(m.dir, "bin", "docker")); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"VL_RH_DOCKER": docker, "VL_RH_MEMORY_DIR": m.dir, "VL_RH_MEMORY_ON": map[bool]string{true: "crypt", false: "tmpfs"}[m.disk], "PATH": filepath.Join(m.dir, "bin") + ":" + os.Getenv("PATH")} {
		if err := os.Setenv(k, v); err != nil {
			t.Fatal(err)
		}
	}
	m.before = temporaryFiles()
	m.sample()
	memory = m
	// Registered before anything the cases register, so it runs after
	// every removal.
	t.Cleanup(func() { m.finish(t) })
}

// mib is n in MiB, rounded up.
func mib(n int64) string { return fmt.Sprintf("%d MiB", (n+1<<20-1)>>20) }

func memAvailable() int64 {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "MemAvailable:" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n << 10
		}
	}
	return 0
}

func tmpfsFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * st.Bsize, nil
}

// temporaryFiles are the files that Varlatch's programs would have left in
// the host's own temporary directories.
func temporaryFiles() []string {
	var out []string
	for _, d := range []string{"/tmp", "/var/tmp"} {
		f, _ := filepath.Glob(filepath.Join(d, "varlatch*"))
		out = append(out, f...)
	}
	return out
}

// sample keeps what the tmpfs holds at the most, of this run's.
func (m *memoryRun) sample() {
	m.done.Add(1)
	go func() {
		defer m.done.Done()
		for {
			var n int64
			for i, r := range m.roots {
				if i > 0 && strings.HasPrefix(r+"/", m.roots[0]+"/") {
					continue
				}
				n += bytesUnder(r)
			}
			m.most = max(m.most, n)
			select {
			case <-m.stop:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
}

func bytesUnder(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				n += st.Blocks * 512
			}
		}
		return nil
	})
	return n
}

// --- swap ---

// swapState says where the host's swap is, and whether what is swapped
// stays in memory or encrypted. root is "/" (a test's own tree).
func swapState(root string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(root, "proc/swaps"))
	if err != nil {
		return err.Error(), false
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return "no swap", true
	}
	safe := true
	var said []string
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		how, ok := swapOn(root, f[0], f[1])
		safe = safe && ok
		said = append(said, f[0]+": "+how)
	}
	return "swap is on (" + strings.Join(said, "; ") + ")", safe
}

func swapOn(root, name, kind string) (string, bool) {
	read := func(p string) string {
		b, _ := os.ReadFile(filepath.Join(root, p))
		return strings.TrimSpace(string(b))
	}
	if kind != "partition" {
		return "a swap file, whose device is not looked up", false
	}
	base := filepath.Base(name)
	if p, err := filepath.EvalSymlinks(filepath.Join(root, name)); err == nil {
		base = filepath.Base(p)
	}
	if strings.HasPrefix(base, "zram") {
		if d := read("sys/block/" + base + "/backing_dev"); d != "none" {
			return "zram that writes back to " + d, false
		}
		return "zram, in memory", true
	}
	if id := read("sys/class/block/" + base + "/dm/uuid"); strings.HasPrefix(id, "CRYPT-") {
		return "encrypted", true
	}
	return "not encrypted", false
}

// --- the installation's part ---

// memoryServices are the release's Compose services, each with the paths it
// may write beside its volumes; nothing else of its layer, which is read
// only. The dashboard alone keeps its own layer (its entrypoint writes its
// configuration beside the files it serves): what it wrote there is looked
// at, and what it buffers of requests and answers is in /var/cache/nginx.
var memoryServices = map[string][]string{
	"postgres":         {"/tmp", "/run"},
	"varlatch-migrate": {"/tmp"},
	"varlatchd":        {"/tmp"},
	"varlatch-web":     {"/tmp", "/run", "/var/cache/nginx"},
	"convex-backend":   {"/tmp"},
	"convex-deploy":    {"/tmp"},
}

// memoryImport is the service migrate --rollback adds for its import, in a
// file of its own after this one.
const memoryImport = "varlatch-reverse-import"

// memoryExtra is a copy's Compose file in memory: no container has a log, a
// layer to write in, or dumps its memory.
func memoryExtra() installExtra {
	var b strings.Builder
	b.WriteString("# Written by the rehearsal harness (VL_RH_MEMORY=1): nothing on disk.\nservices:\n")
	service := func(name string, paths []string) {
		fmt.Fprintf(&b, "  %s:\n    logging:\n      driver: none\n    ulimits:\n      core: 0\n    read_only: %v\n    tmpfs:\n", name, name != memoryWritable)
		for _, p := range paths {
			fmt.Fprintf(&b, "      - %s\n", p)
		}
	}
	for _, s := range slices.Sorted(maps.Keys(memoryServices)) {
		service(s, memoryServices[s])
	}
	service(memoryImport, []string{"/tmp"})
	b.WriteString("    profiles: [varlatch-rollback]\n")
	return installExtra{composeFile: "docker-compose.memory.yml", composeText: b.String()}
}

const memoryWritable = "varlatch-web"

// memoryVolumes makes the project's volumes before Compose would: with its
// labels, so they are its own, and through the shim, so they are in memory.
func (in *installation) memoryVolumes() error {
	r := in.compose("--profile", "deploy", "config", "--format", "json")
	var cfg struct {
		Volumes map[string]struct {
			Name string `json:"name"`
		} `json:"volumes"`
		Services map[string]struct {
			ReadOnly bool `json:"read_only"`
			Logging  struct {
				Driver string `json:"driver"`
			} `json:"logging"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &cfg); err != nil || r.code != 0 {
		return fmt.Errorf("docker compose config: %s (%v)", r, err)
	}
	if got, want := slices.Sorted(maps.Keys(cfg.Services)), slices.Sorted(maps.Keys(memoryServices)); !slices.Equal(got, want) {
		return fmt.Errorf("the Compose file's services are %v, not %v", got, want)
	}
	for name, s := range cfg.Services {
		if s.Logging.Driver != "none" || s.ReadOnly != (name != memoryWritable) {
			return fmt.Errorf("the service %s logs with %q, read only %v", name, s.Logging.Driver, s.ReadOnly)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(cfg.Volumes)) {
		if r := run("", nil, nil, "docker", "volume", "create", "--label", "com.docker.compose.project="+in.project, "--label", "com.docker.compose.volume="+key, cfg.Volumes[key].Name); r.code != 0 {
			return fmt.Errorf("docker volume create %s: %s", cfg.Volumes[key].Name, r)
		}
	}
	return nil
}

// --- the run's own docker ---

// shimPlan is what the shim makes of a docker command.
type shimPlan struct {
	args []string
	// mkdir is the directory of the volume the command makes; dirs are those
	// its container has in place of what would be large in memory.
	mkdir string
	mode  os.FileMode
	dirs  []string
	// look says which containers to look at before: the run's ("*"), or
	// those named.
	look []string
	// oneOff is the name of the container to look at and remove after (its
	// own --rm taken away), when there is one.
	oneOff string
}

// The options with a value of the commands the programs use; another is
// refused, so that none is misread.
var (
	composeValues = []string{"-f", "--file", "-p", "--project-name", "--project-directory", "--profile", "--env-file", "--ansi", "--progress", "--parallel"}
	composeFlags  = []string{"--compatibility", "--all-resources"}
	onceValues    = []string{"--entrypoint", "-e", "--env", "--env-from-file", "-l", "--label", "--name", "-p", "--publish", "-u", "--user", "-v", "--volume", "-w", "--workdir", "--pull", "--cap-add", "--cap-drop"}
	onceFlags     = []string{"--rm", "-T", "--no-TTY", "--no-deps", "-i", "--interactive", "--remove-orphans", "--service-ports", "-P", "--use-aliases", "--quiet-pull", "-q", "--quiet"}
	runValues     = []string{"--name", "--network", "--network-alias", "-l", "--label", "-e", "--env", "--env-file", "--tmpfs", "-u", "--user", "--cap-add", "--cap-drop", "--security-opt", "--mount", "-v", "--volume", "--entrypoint", "-p", "--publish", "--pull", "-w", "--workdir", "--add-host", "--hostname", "--memory", "--cpus"}
	runFlags      = []string{"--rm", "-d", "--detach", "-i", "--interactive", "--read-only", "--init"}
)

// options reads args' options (each with its value) up to the first
// argument that is none.
func options(args, values, flags []string) (opts [][]string, rest []string, err error) {
	for len(args) > 0 {
		a := args[0]
		name, _, joined := strings.Cut(a, "=")
		switch {
		case !strings.HasPrefix(a, "-"):
			return opts, args, nil
		case joined && slices.Contains(values, name), slices.Contains(flags, a):
			opts, args = append(opts, args[:1]), args[1:]
		case slices.Contains(values, a) && len(args) > 1:
			opts, args = append(opts, args[:2]), args[2:]
		default:
			return nil, nil, fmt.Errorf("the option %s is not one this run's docker knows", a)
		}
	}
	return opts, nil, nil
}

// value is an option's value, and whether it is there.
func value(opts [][]string, names ...string) (string, bool) {
	for _, o := range opts {
		name, v, joined := strings.Cut(o[0], "=")
		if slices.Contains(names, name) {
			if joined {
				return v, true
			}
			return o[len(o)-1], true
		}
	}
	return "", false
}

func without(opts [][]string, name string) []string {
	var out []string
	for _, o := range opts {
		if o[0] != name {
			out = append(out, o...)
		}
	}
	return out
}

// targets are the paths a docker run mounts something on.
func targets(opts [][]string) []string {
	var out []string
	for _, o := range opts {
		name, v, joined := strings.Cut(o[0], "=")
		if !joined {
			v = o[len(o)-1]
		}
		switch name {
		case "--tmpfs":
			out = append(out, strings.SplitN(v, ":", 2)[0])
		case "-v", "--volume":
			if p := strings.Split(v, ":"); len(p) > 1 {
				out = append(out, p[1])
			}
		case "--mount":
			for _, kv := range strings.Split(v, ",") {
				if k, t, _ := strings.Cut(kv, "="); k == "target" || k == "dst" || k == "destination" {
					out = append(out, t)
				}
			}
		}
	}
	return out
}

// planDocker is the shim's: args are docker's, volumes the directory the
// volumes are made in, once a name for a one-off container, declared the
// volumes an image declares, disk whether the volumes' directory is on the crypt
// disk (what an image declares is then a directory there, not a tmpfs).
func planDocker(args []string, volumes, once string, disk bool, declared func(string) ([]string, error)) (shimPlan, error) {
	plan := shimPlan{args: args}
	if len(args) == 0 {
		return plan, nil
	}
	switch args[0] {
	case "volume":
		if len(args) < 2 || args[1] != "create" {
			return plan, nil
		}
		opts, rest, err := options(args[2:], []string{"--label"}, nil)
		if err != nil {
			return plan, err
		}
		if len(rest) != 1 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(rest[0]) {
			return plan, fmt.Errorf("docker volume create without one plain name: %q", rest)
		}
		plan.mkdir = filepath.Join(volumes, rest[0])
		plan.args = append([]string{"volume", "create", "--driver", "local", "--opt", "type=none", "--opt", "o=bind", "--opt", "device=" + plan.mkdir}, append(without(opts, ""), rest...)...)
		return plan, nil
	case "run":
		opts, rest, err := options(args[1:], runValues, runFlags)
		if err != nil || len(rest) == 0 {
			return plan, fmt.Errorf("docker run: %v", err)
		}
		paths, err := declared(rest[0])
		if err != nil {
			return plan, err
		}
		out := append([]string{"run", "--log-driver", "none", "--ulimit", "core=0"}, without(opts, "--rm")...)
		if _, ro := value(opts, "--read-only"); !ro {
			out = append(out, "--read-only")
		}
		have := targets(opts)
		for _, p := range append(paths, "/run") {
			switch who, named := value(opts, "--name"); {
			case slices.Contains(have, p):
			case disk && p != "/run":
				if !named {
					who = once
				}
				d := filepath.Join(volumes, who+strings.ReplaceAll(p, "/", "-"))
				plan.dirs = append(plan.dirs, d)
				out = append(out, "-v", d+":"+p)
			default:
				out = append(out, "--tmpfs", p)
			}
		}
		if name, named := value(opts, "--name"); !slices.Contains(have, "/tmp") && named {
			// A directory, not a tmpfs of its own: docker cp writes under
			// the latter, in the layer.
			plan.mkdir = filepath.Join(volumes, name+"-tmp")
			plan.mode = 0o777 | os.ModeSticky
			out = append(out, "-v", plan.mkdir+":/tmp")
		} else if !slices.Contains(have, "/tmp") {
			out = append(out, "--tmpfs", "/tmp")
		}
		_, rm := value(opts, "--rm")
		if name, named := value(opts, "--name"); rm && named {
			plan.oneOff = name
		} else if rm {
			plan.oneOff = once
			out = append(out, "--name", once)
		}
		plan.args = append(out, rest...)
		return plan, nil
	case "rm":
		for _, a := range args[1:] {
			if !strings.HasPrefix(a, "-") {
				plan.look = append(plan.look, a)
			}
		}
		return plan, nil
	case "cp":
		// A container's file to the standard output, or the converter's dump
		// into the /tmp the run gave its container.
		if len(args) == 3 && args[2] == "-" {
			return plan, nil
		}
		if len(args) != 3 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*:/tmp/[A-Za-z0-9_.-]+$`).MatchString(args[2]) {
			return plan, fmt.Errorf("docker cp to anything but a container's /tmp: %q", args[1:])
		}
		return plan, nil
	case "create", "system", "build", "buildx", "builder", "commit", "save", "export":
		return plan, fmt.Errorf("docker %s is not one this run's docker knows", args[0])
	case "compose":
		opts, rest, err := options(args[1:], composeValues, composeFlags)
		if err != nil {
			return plan, err
		}
		if len(rest) == 0 {
			return plan, nil
		}
		switch rest[0] {
		case "down", "rm", "up", "create":
			// up makes a changed container again.
			plan.look = []string{"*"}
		case "run":
			sub, command, err := options(rest[1:], onceValues, onceFlags)
			if err != nil {
				return plan, err
			}
			if _, rm := value(sub, "--rm"); !rm || len(command) == 0 {
				return plan, errors.New("docker compose run without --rm")
			}
			if _, named := value(sub, "--name"); named {
				return plan, errors.New("docker compose run --name")
			}
			plan.oneOff = once
			plan.args = append(append(append(append([]string{"compose"}, without(opts, "")...), "run", "--name", once), without(sub, "--rm")...), command...)
		}
		return plan, nil
	}
	return plan, nil
}

// looked is what a container held when it was looked at.
type looked struct {
	Container string   `json:"container"`
	Image     string   `json:"image"`
	Service   string   `json:"service"`
	Log       string   `json:"log"`      // its log driver
	LogBytes  int      `json:"logBytes"` // in it, when it has one
	ReadOnly  bool     `json:"readOnly"`
	Wrote     []string `json:"wrote"`   // in its own layer: docker diff
	Outside   []string `json:"outside"` // mounts that are not in memory
	Error     string   `json:"error,omitempty"`
}

// dockerShim is this binary as docker, for everything a run in memory
// starts.
func dockerShim(args []string) int {
	real, dir := os.Getenv("VL_RH_DOCKER"), os.Getenv("VL_RH_MEMORY_DIR")
	if real == "" || dir == "" {
		fmt.Fprintln(os.Stderr, "the rehearsal's docker: VL_RH_DOCKER and VL_RH_MEMORY_DIR are not set")
		return 125
	}
	out := func(args ...string) ([]byte, error) { return exec.Command(real, args...).Output() }
	plan, err := planDocker(args, filepath.Join(dir, "volumes"), fmt.Sprintf("vl-rh-%s-once-%d-%d", runID, os.Getpid(), time.Now().UnixNano()), os.Getenv("VL_RH_MEMORY_ON") == "crypt", func(image string) ([]string, error) {
		b, err := out("image", "inspect", "--format", "{{json .Config.Volumes}}", image)
		if err != nil {
			return nil, fmt.Errorf("docker image inspect %s: %v (pull it first)", image, err)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		return slices.Sorted(maps.Keys(v)), nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
		return 125
	}
	if plan.mkdir != "" {
		err := os.MkdirAll(plan.mkdir, 0o755)
		if err == nil && plan.mode != 0 {
			err = os.Chmod(plan.mkdir, plan.mode)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
			return 125
		}
	}
	for _, d := range plan.dirs {
		if err := errors.Join(os.MkdirAll(d, 0o755), os.Chmod(d, 0o777|os.ModeSticky)); err != nil {
			fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
			return 125
		}
	}
	look(out, dir, plan.look)
	if plan.oneOff == "" {
		err := syscall.Exec(real, append([]string{"docker"}, plan.args...), os.Environ())
		fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
		return 125
	}
	// As the real one's process would: its own streams, its signals, and
	// not outliving a kill.
	runtime.LockOSThread()
	cmd := exec.Command(real, plan.args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
		return 125
	}
	go func() {
		for s := range signals {
			_ = cmd.Process.Signal(s)
		}
	}()
	code := exitCode(cmd.Wait())
	look(out, dir, []string{plan.oneOff})
	_, _ = out("rm", "-fv", plan.oneOff)
	return code
}

// memoryRunner is the container a workstation's run is in itself.
func memoryRunner() string { return "vl-rh-" + runID + "-test" }

// look notes what the containers named (the run's, for "*") hold outside
// memory, in the run's record.
func look(out func(...string) ([]byte, error), dir string, names []string) {
	if slices.Contains(names, "*") {
		b, _ := out("ps", "-a", "--filter", "name=^vl-rh-"+runID+"-", "--format", "{{.Names}}")
		names = strings.Fields(string(b))
	}
	for _, n := range names {
		if n == memoryRunner() {
			continue
		}
		b, err := out("container", "inspect", n)
		if err != nil {
			continue // not there: nothing of it is
		}
		var c []struct {
			Config struct {
				Image  string
				Labels map[string]string
			}
			HostConfig struct {
				LogConfig      struct{ Type string }
				ReadonlyRootfs bool
			}
			Mounts []struct {
				Type, Name, Source, Destination string
				RW                              bool
			}
		}
		l := looked{Container: n}
		if err := json.Unmarshal(b, &c); err != nil || len(c) != 1 {
			l.Error = fmt.Sprintf("docker container inspect: %v", err)
		} else {
			l.Image, l.Service = c[0].Config.Image, c[0].Config.Labels["com.docker.compose.service"]
			l.Log, l.ReadOnly = c[0].HostConfig.LogConfig.Type, c[0].HostConfig.ReadonlyRootfs
			if l.Log != "none" {
				logs, err := exec.Command(os.Getenv("VL_RH_DOCKER"), "logs", n).CombinedOutput()
				l.LogBytes = len(logs)
				if err != nil {
					l.Error = fmt.Sprintf("docker logs: %v", err)
				}
			}
			for _, m := range c[0].Mounts {
				switch {
				case m.Type == "volume":
					v, err := out("volume", "inspect", "--format", `{{.Driver}} {{index .Options "type"}} {{index .Options "o"}} {{index .Options "device"}}`, m.Name)
					if want := "local none bind " + filepath.Join(dir, "volumes", m.Name); err != nil || strings.TrimSpace(string(v)) != want {
						l.Outside = append(l.Outside, fmt.Sprintf("the volume %s on %s", m.Name, m.Destination))
					}
				case m.Type == "bind" && m.RW && m.Source != "/dev/null" && !strings.HasPrefix(m.Source, filepath.Dir(dir)+"/"):
					l.Outside = append(l.Outside, fmt.Sprintf("%s on %s", m.Source, m.Destination))
				}
			}
			d, err := out("container", "diff", n)
			if err != nil {
				l.Error = fmt.Sprintf("docker diff: %v", err)
			}
			for _, s := range strings.Split(strings.TrimSpace(string(d)), "\n") {
				if s != "" {
					l.Wrote = append(l.Wrote, s)
				}
			}
		}
		line, _ := json.Marshal(l)
		f, err := os.OpenFile(filepath.Join(dir, "looked.jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "the rehearsal's docker:", err)
			continue
		}
		_, _ = f.Write(append(line, '\n'))
		f.Close()
	}
}

// --- the end ---

// plain are the paths the dashboard may write in its own layer: what its
// entrypoint makes of its own environment.
var plain = regexp.MustCompile(`^(/etc/nginx/conf\.d/default\.conf|/etc/nginx/varlatch/csp\.conf|/usr/share/nginx/html/varlatch-config\.js)$`)

// layerFindings are what the looked-at containers kept outside memory.
func layerFindings(ls []looked) []string {
	var bad []string
	for _, l := range ls {
		who := l.Container
		if l.Service != "" {
			who = l.Service + " (" + l.Container + ")"
		}
		if l.Error != "" {
			bad = append(bad, who+": "+l.Error)
		}
		if !l.ReadOnly && l.Service != memoryWritable {
			bad = append(bad, who+": its layer is not read only")
		}
		if l.Log != "none" && l.LogBytes > 0 {
			bad = append(bad, fmt.Sprintf("%s: %d bytes in its %s log", who, l.LogBytes, l.Log))
		}
		for _, o := range l.Outside {
			bad = append(bad, who+": "+o)
		}
		var paths []string
		for _, w := range l.Wrote {
			_, p, _ := strings.Cut(w, " ")
			paths = append(paths, p)
		}
		for i, w := range l.Wrote {
			if l.ReadOnly {
				break // Docker's own: the mounts' places
			}
			// A directory above what was written is changed with it.
			above := slices.ContainsFunc(paths, func(q string) bool { return strings.HasPrefix(q, paths[i]+"/") })
			if !above && !strings.HasPrefix(w, "D ") && !plain.MatchString(paths[i]) {
				bad = append(bad, who+" wrote "+w)
			}
		}
	}
	slices.Sort(bad)
	return slices.Compact(bad)
}

// finish checks, once everything of the run's is removed, that nothing of
// the copy was outside memory.
func (m *memoryRun) finish(t *testing.T) {
	const item = memoryItem
	b, err := os.ReadFile(filepath.Join(m.dir, "looked.jsonl"))
	var ls []looked
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var l looked
		if jerr := json.Unmarshal(sc.Bytes(), &l); jerr != nil {
			err = errors.Join(err, jerr)
			continue
		}
		ls = append(ls, l)
	}
	err = errors.Join(err, sc.Err())
	bad := layerFindings(ls)
	if err != nil {
		bad = append(bad, err.Error())
	}
	services := map[string]int{}
	for _, l := range ls {
		services[cmpOr(l.Service, "other")]++
	}
	record(t, item, "no container kept anything of the copy outside memory", len(bad) == 0 && len(ls) > 0,
		fmt.Sprintf("%d looks at containers before they were removed %v; %s", len(ls), services, cmpOr(strings.Join(bad, "; "), "volumes on the tmpfs or the crypt disk, no logs, nothing of data in their own layers")))
	left := strings.Fields(run("", nil, nil, "docker", "volume", "ls", "-q", "--filter", "name=vl-rh-"+runID+"-").stdout +
		run("", nil, nil, "docker", "ps", "-a", "--filter", "name=^vl-rh-"+runID+"-", "--format", "{{.Names}}").stdout)
	left = slices.DeleteFunc(left, func(n string) bool { return n == memoryRunner() })
	record(t, item, "no volume or container of the run is left", len(left) == 0, strings.Join(left, ", "))
	var made []string
	for _, f := range temporaryFiles() {
		if !slices.Contains(m.before, f) {
			made = append(made, f)
		}
	}
	record(t, item, "nothing of Varlatch's is left in the host's /tmp and /var/tmp", len(made) == 0, strings.Join(made, ", "))
	close(m.stop)
	m.done.Wait()
	measure("memory: the run's files, the volumes included, at the most", mib(m.most))
	if err := os.RemoveAll(m.volumes); err != nil {
		record(t, item, "the volumes' directories are removed", false, err.Error())
	}
}

const memoryItem = 16

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
