// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// labelled is a host with Compose containers, and volumes.
type labelled struct {
	containers []composeContainer
	volumes    map[string]VolumeRecord
	users      map[string]string // the containers that mount a volume
	removed    []string
	// inspected is called before a volume is inspected, created once one is.
	inspected func(name string)
	made      []string
	// seen is called before each listing of the containers.
	seen func()
	// gates are the volumes' maintenance.json, each read counted.
	gates map[string]string
	reads int
	// tars answer docker cp instead, and inspects a container's mounts, by
	// the container's id.
	tars     map[string][]byte
	inspects map[string]string
	// stdin is the command's; writes are the gates written, by volume; runErr
	// answers the containers of migrate's own.
	stdin  []byte
	writes []string
	runErr func(write bool) *Ran
	// acted is called after a container was started, stopped or removed.
	acted func(verb, id string)
}

// ids gives each container an id.
func (h *labelled) ids() []string {
	var out []string
	for i := range h.containers {
		if h.containers[i].id == "" {
			h.containers[i].id = fmt.Sprintf("c-%s-%d", h.containers[i].service, i)
			for _, l := range h.containers[:i] {
				if l.id == h.containers[i].id {
					h.containers[i].id += "x"
				}
			}
		}
		out = append(out, h.containers[i].id)
	}
	return out
}

func (h *labelled) byID(id string) int {
	h.ids()
	return slices.IndexFunc(h.containers, func(l composeContainer) bool { return l.id == id })
}

// tarOf is docker cp's answer.
func tarOf(name, text string, typ byte) []byte {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	hd := &tar.Header{Name: name, Typeflag: typ, Mode: 0o644, Size: int64(len(text))}
	if typ == tar.TypeSymlink {
		hd.Size, hd.Linkname, text = 0, "/elsewhere", ""
	}
	_ = w.WriteHeader(hd)
	_, _ = w.Write([]byte(text))
	_ = w.Close()
	return b.Bytes()
}

// gateRun and gateWrite are the arguments that read and write a volume's gate.
func gateRun(volume string) []string {
	return append(ownRun("type=volume,source="+volume+",target=/state,readonly,volume-nocopy"), gate1.Image, "-c", readGateScript)
}
func gateWrite(volume string, how ...string) []string {
	return append(append(ownRun("type=volume,source="+volume+",target=/var/lib/varlatch"), gate1.Image, "-c", writeGateScript, "sh"), how...)
}

const gateText = `{"id":"gate-1","kind":"migrated-out","phase":"paused","expiresAt":null,"archiveId":null,"frozenPosition":"46"}`

// stateVol is the stock installation's state volume.
var stateVol = VolumeRecord{Name: "varlatch_varlatch-state", CreatedAt: "2026-01-01T00:00:00Z", Mountpoint: "/v/state", Project: "varlatch", Key: "varlatch-state"}

// gatedHost is a host whose state volume carries the gate gate-1.
func gatedHost() *labelled {
	return &labelled{volumes: map[string]VolumeRecord{stateVol.Name: stateVol}, gates: map[string]string{stateVol.Name: gateText}}
}

var gate1 = GateRef{ID: "gate-1", State: &stateVol, Image: "x@sha256:y"}

func (h *labelled) byActs(args []string) bool {
	return len(args) > 1 && slices.Contains([]string{"start", "restart", "stop", "rm"}, args[0])
}

func (h *labelled) answer(args []string) (Ran, bool) {
	if h.seen != nil && args[0] == "ps" && slices.Contains(args, "label="+labelProject) {
		h.seen()
	}
	switch {
	case args[0] == "image" && args[1] == "inspect" && h.gates != nil && len(args) == 5 && args[4] == gate1.Image:
		return Ran{}, true
	case args[0] == "cp" && len(args) == 3 && args[2] == "-":
		id, file, _ := strings.Cut(args[1], ":")
		i := h.byID(id)
		if i < 0 || file != "/var/lib/varlatch/maintenance.json" {
			return Ran{Code: 1, Said: []byte("Error response from daemon: No such container: " + args[1])}, true
		}
		h.reads++
		if b, ok := h.tars[id]; ok {
			return Ran{Answer: b}, true
		}
		text := h.gates[h.containers[i].volumeAt(stateTarget)]
		if text == "" {
			return Ran{Code: 1, Said: []byte("Error response from daemon: Could not find the file " + file + " in container " + id)}, true
		}
		return Ran{Answer: tarOf("maintenance.json", text, tar.TypeReg)}, true
	case len(args) == 6 && args[0] == "inspect" && args[4] == mountsFormat:
		i := h.byID(args[5])
		if i < 0 {
			return Ran{Code: 1, Said: []byte("No such container")}, true
		}
		if text, ok := h.inspects[args[5]]; ok {
			return Ran{Answer: []byte(text)}, true
		}
		var mounts []map[string]any
		for _, m := range h.containers[i].mounts {
			mounts = append(mounts, map[string]any{"Type": m.Type, "Name": m.Name, "Destination": m.Destination, "Driver": "local", "RW": true})
		}
		b, _ := json.Marshal(mounts)
		return Ran{Answer: []byte(`["PATH=/x","VARLATCH_STATE_DIR=/var/lib/varlatch"] ` + string(b) + " null null\n")}, true
	case h.byActs(args):
		for _, id := range args[1:] {
			i := h.byID(id)
			if i < 0 {
				return Ran{Code: 1, Said: []byte("Error response from daemon: No such container: " + id)}, true
			}
			switch args[0] {
			case "start", "restart":
				h.containers[i].status = "running"
			case "stop":
				h.containers[i].status = "exited"
			case "rm":
				if s := h.containers[i].status; s == "" || s == "running" {
					return Ran{Code: 1, Said: []byte("cannot remove a running container")}, true
				}
				h.containers = slices.Delete(slices.Clone(h.containers), i, i+1)
			}
			if h.acted != nil {
				h.acted(args[0], id)
			}
		}
		return Ran{}, true
	case args[0] == "run":
		for name := range h.volumes {
			how := args[min(len(args), len(gateWrite(name))):]
			write := slices.Equal(args, gateWrite(name, how...)) && (slices.Equal(how, []string{"new"}) || len(how) == 2 && how[0] == "replace")
			if !write && !slices.Equal(args, gateRun(name)) {
				continue
			}
			if h.runErr != nil {
				if r := h.runErr(write); r != nil {
					return *r, true
				}
			}
			switch text := h.gates[name]; {
			case write && text != "" && args[len(args)-1] == "new":
				return Ran{Code: 1, Said: []byte("ln: maintenance.json: File exists")}, true
			case write:
				h.gates[name] = string(h.stdin)
				h.writes = append(h.writes, name+" "+strings.Join(how, " "))
				return Ran{}, true
			case text == "":
				h.reads++
				return Ran{Code: gateNone}, true
			case text == "link":
				return Ran{Code: gateNotPlain}, true
			default:
				h.reads++
				return Ran{Answer: []byte(text)}, true
			}
		}
		return Ran{Code: 125, Said: []byte("unexpected " + strings.Join(args, " "))}, true
	case len(args) == 5 && args[0] == "volume" && args[1] == "inspect" && args[3] == volumeFormat:
		if h.inspected != nil {
			h.inspected(args[4])
		}
		v, ok := h.volumes[args[4]]
		if !ok {
			return Ran{Code: 1, Said: []byte("Error response from daemon: get " + args[4] + ": no such volume")}, true
		}
		var out strings.Builder
		for _, f := range []string{v.Name, v.CreatedAt, v.Mountpoint, v.Project, v.Key, v.Owner} {
			b, _ := json.Marshal(f)
			out.Write(append(b, ' '))
		}
		return Ran{Answer: []byte(out.String())}, true
	case h.volumes != nil && len(args) >= 7 && args[0] == "volume" && args[1] == "create":
		// As Docker: a name that is there is answered, not made again.
		if _, ok := h.volumes[args[len(args)-1]]; !ok {
			v := VolumeRecord{Name: args[len(args)-1], CreatedAt: "2026-11-09T09:09:09Z", Mountpoint: "/v/" + args[len(args)-1]}
			for i, f := range []*string{&v.Project, &v.Key, &v.Owner} {
				if 3+2*i < len(args)-1 {
					_, *f, _ = strings.Cut(args[3+2*i], "=")
				}
			}
			h.volumes[v.Name] = v
			h.made = append(h.made, v.Name)
		}
		return Ran{Answer: []byte(args[len(args)-1] + "\n")}, true
	case h.volumes != nil && len(args) >= 3 && args[0] == "volume" && args[1] == "rm":
		name := args[len(args)-1]
		delete(h.volumes, name)
		h.removed = append(h.removed, name)
		return Ran{}, true
	case h.volumes != nil && args[0] == "ps" && len(args) == 6 && strings.HasPrefix(args[3], "volume="):
		return Ran{Answer: []byte(h.users[strings.TrimPrefix(args[3], "volume=")])}, true
	case len(args) > 2 && args[0] == "ps" && args[1] == "-a" && args[2] == "-q" && slices.Contains(args, "label="+labelProject):
		return Ran{Answer: []byte(strings.Join(h.ids(), "\n"))}, true
	case len(args) > 4 && args[0] == "inspect" && slices.Contains(args, containersFormat):
		var b strings.Builder
		for _, l := range h.containers {
			for _, v := range []string{l.project, l.service, l.files, l.dir, l.oneOff, "/" + l.name} {
				q, _ := json.Marshal(v)
				b.Write(q)
				b.WriteByte(' ')
			}
			status := l.status
			if status == "" {
				status = "running"
			}
			m, _ := json.Marshal(l.mounts)
			b.WriteString(`"` + status + `" ` + string(m) + ` "` + l.id + "\"\n")
		}
		return Ran{Answer: []byte(b.String())}, true
	}
	return Ran{}, false
}

// stockVolumes are the stock installation's data volumes, as a journal
// records them where the test has no containers to tell them by.
var stockVolumes = []VolumeRecord{{Name: "varlatch_postgres-data"}, {Name: "varlatch_convex-data"}}

func ctr(project, service, files, dir, oneOff string) composeContainer {
	return composeContainer{project: project, service: service, files: files, dir: dir, oneOff: oneOff}
}

// installationDir is a directory with files of those names.
func installationDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// coolifyDir is Coolify's directory of the TypeScript application, as
// production's and the lab's are: the repository's Compose files (its
// docker-compose.yml names the project varlatch), Coolify's own
// docker-compose.yaml, and the file the containers run from.
func coolifyDir(t *testing.T) string {
	return installationDir(t, map[string]string{
		"docker-compose.yml":                   "name: varlatch\nservices: {}\n",
		"docker-compose.yaml":                  "services: {}\n",
		"docker-compose.coolify-tailscale.yml": "services: {}\n",
		"docker-compose.caddy.yml":             "services: {}\n",
		".env":                                 "VARLATCH_PUBLIC_URL=https://vault.example.test\nVARLATCH_VARLATCHD_DIGEST=sha256:" + strings.Repeat("a", 64) + "\n",
	})
}

const appID = "abcdefghijklmnopqrstuvwx"

func TestComposeProject(t *testing.T) {
	const stock = "docker-compose.yml"
	one := map[string]string{stock: "services: {}\n"}
	at := func(project, service, dir string, files ...string) composeContainer {
		var abs []string
		for _, f := range files {
			if !filepath.IsAbs(f) {
				f = filepath.Join(dir, f)
			}
			abs = append(abs, f)
		}
		return ctr(project, service, strings.Join(abs, ","), dir, "False")
	}
	for _, c := range []struct {
		name       string
		dir        func(t *testing.T) string
		containers func(dir string) []composeContainer
		env        func(dir string) []string
		project    string
		files      []string
		refused    []string
	}{
		{"Coolify's directory: the labels, not the files there", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", d, "docker-compose.coolify-tailscale.yml"),
					at("another", "varlatchd", "/data/coolify/applications/another", "docker-compose.coolify.yml")}
			}, nil, appID, []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"the shell agrees, as the backup job's configuration does", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string {
				return []string{"COMPOSE_FILE=docker-compose.coolify-tailscale.yml", "COMPOSE_PROJECT_NAME=" + appID}
			}, appID, []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"the shell's files differ", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string { return []string{"COMPOSE_FILE=docker-compose.yml"} }, "", nil,
			[]string{"COMPOSE_FILE in the environment names", "docker-compose.yml", "docker-compose.coolify-tailscale.yml"}},
		{"the shell's project differs", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml")}
			},
			func(d string) []string { return []string{"COMPOSE_PROJECT_NAME=varlatch"} }, "", nil,
			[]string{"COMPOSE_PROJECT_NAME in the environment is varlatch", appID}},
		{".env's project differs", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", ".env": "COMPOSE_PROJECT_NAME=other\n"})
		}, func(d string) []composeContainer { return []composeContainer{at("varlatch", "varlatchd", d, stock)} }, nil, "", nil,
			[]string{"COMPOSE_PROJECT_NAME in", "is other", "varlatch"}},
		{"Coolify's directory without containers", coolifyDir, nil, nil, "", nil,
			[]string{"several Compose files", "docker-compose.yml, docker-compose.yaml", "COMPOSE_FILE"}},
		{"Coolify's directory without containers, COMPOSE_FILE given", coolifyDir, nil,
			func(d string) []string { return []string{"COMPOSE_FILE=docker-compose.coolify-tailscale.yml"} }, "asked", []string{"docker-compose.coolify-tailscale.yml"}, nil},
		{"one docker-compose.yaml", func(t *testing.T) string {
			return installationDir(t, map[string]string{"docker-compose.yaml": "services: {}\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at(appID, "varlatchd", d, "docker-compose.yaml")}
		}, nil, appID, []string{"docker-compose.yaml"}, nil},
		{"one docker-compose.yaml, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{"docker-compose.yaml": "services: {}\n"})
		}, nil, nil, "asked", []string{"docker-compose.yaml"}, nil},
		{"the stock file", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeContainer {
				return []composeContainer{at("varlatch", "varlatchd", d, stock), at("another", "varlatchd", "/elsewhere", stock), ctr("varlatch", "varlatchd", filepath.Join(d, stock), d, "True")}
			}, nil, "varlatch", []string{stock}, nil},
		{"the project is another directory's too", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeContainer {
				return []composeContainer{at("varlatch", "varlatchd", d, stock), at("varlatch", "postgres", "/elsewhere", "x.yml")}
			}, nil, "", nil, []string{"the Compose project varlatch has a postgres container made from /elsewhere (files /elsewhere/x.yml)", "nothing was done"}},
		{"the project is another directory's one-off's too", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeContainer {
				return []composeContainer{at("varlatch", "varlatchd", d, stock), ctr("varlatch", "varlatchd", "/elsewhere/x.yml", "/elsewhere", "True")}
			}, nil, "", nil, []string{"made from /elsewhere"}},
		{"no containers here: the files' project is another directory's", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeContainer {
				return []composeContainer{at("asked", "varlatchd", "/srv/live", stock), at("other", "x", "/srv/other", stock)}
			}, nil, "", nil, []string{"the Compose project asked has a varlatchd container made from /srv/live (files /srv/live/docker-compose.yml), not from "}},
		{"no containers here: the project's other container names no directory", func(t *testing.T) string { return installationDir(t, one) },
			func(d string) []composeContainer {
				return []composeContainer{ctr("asked", "varlatchd", "", "", "False")}
			}, nil, "", nil, []string{"a directory it does not name"}},
		{"a one-off of the project from this directory, of files none of which are the project's", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), ctr(appID, "x", filepath.Join(d, stock), d, "True")}
			}, nil, "", nil, []string{"and its files are", "would act on both"}},
		{"a container of a file since renamed", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, stock), at("varlatch", "postgres", d, "compose.old.yml")}
		}, nil, "", nil, []string{"made from different files"}},
		{"the stock file and its override, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.override.yml": "services: {}\n"})
		}, nil, nil, "asked", []string{stock, "docker-compose.override.yml"}, nil},
		{"two overrides, no containers", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.override.yml": "services: {}\n", "compose.override.yml": "services: {}\n"})
		}, nil, nil, "", nil, []string{"several Compose files", "docker-compose.override.yml"}},
		{"a file added to .env since: varlatchd's label is the old list", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.caddy.yml": "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, stock), at("varlatch", "caddy", d, stock, "docker-compose.caddy.yml")}
		}, nil, "", nil, []string{"made from different files: varlatchd from ", "caddy from ", "docker-compose.caddy.yml", "--force-recreate"}},
		{"another overlay of the project", func(t *testing.T) string {
			return installationDir(t, map[string]string{"base.yml": "", "prod.yml": "", "other.yml": "", ".env": "COMPOSE_FILE=base.yml:prod.yml\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, "base.yml", "prod.yml"), at("varlatch", "postgres", d, "base.yml", "other.yml")}
		}, nil, "", nil, []string{"base.yml", "prod.yml", "other.yml"}},
		{"another overlay of the project, a one-off", func(t *testing.T) string {
			return installationDir(t, map[string]string{"base.yml": "", "prod.yml": "", "other.yml": "", ".env": "COMPOSE_FILE=base.yml:prod.yml\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, "base.yml", "prod.yml"), ctr("varlatch", "x", filepath.Join(d, "base.yml")+","+filepath.Join(d, "other.yml"), d, "True")}
		}, nil, "", nil, []string{"has a x container made from", "other.yml", "prod.yml"}},
		{"the same files in another order", func(t *testing.T) string {
			return installationDir(t, map[string]string{"base.yml": "", "prod.yml": "", ".env": "COMPOSE_FILE=base.yml:prod.yml\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, "base.yml", "prod.yml"), at("varlatch", "postgres", d, "prod.yml", "base.yml")}
		}, nil, "", nil, []string{"made from different files"}},
		{"a relative label, a link in it: the same file", func(t *testing.T) string {
			d := installationDir(t, map[string]string{"base.yml": ""})
			if err := os.Symlink("base.yml", filepath.Join(d, "link.yml")); err != nil {
				t.Fatal(err)
			}
			return d
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, "base.yml"), ctr("varlatch", "postgres", "link.yml", d, "False")}
		}, nil, "varlatch", []string{"base.yml"}, nil},
		{"containers of different files, the directory names neither", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", d, "docker-compose.yaml")}
			}, nil, "", nil, []string{"made from different files", "docker-compose.coolify-tailscale.yml", "docker-compose.yaml"}},
		{".env names other files than any container's", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", "docker-compose.caddy.yml": "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:docker-compose.caddy.yml\n"})
		}, func(d string) []composeContainer { return []composeContainer{at("varlatch", "varlatchd", d, stock)} }, nil, "", nil,
			[]string{"COMPOSE_FILE names the Compose files", "docker-compose.caddy.yml", "were made from"}},
		{"two projects", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at("varlatch", "varlatchd", d, stock)}
			}, nil, "", nil, []string{"2 Compose projects", appID, "varlatch"}},
		{"one project from two directories", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify-tailscale.yml"), at(appID, "postgres", "/elsewhere", "docker-compose.yml")}
			}, nil, "", nil, []string{"a postgres container made from /elsewhere"}},
		{"this directory's files, another project directory", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{ctr(appID, "varlatchd", filepath.Join(d, stock), "/elsewhere", "False")}
			}, nil, "", nil, []string{"its project directory is /elsewhere"}},
		{"a label's file that is gone", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "docker-compose.coolify.yml")}
			}, nil, "", nil, []string{"docker-compose.coolify.yml", "which is not there"}},
		{"a file of another directory first", coolifyDir,
			func(d string) []composeContainer {
				return []composeContainer{at(appID, "varlatchd", d, "/artifacts/x/docker-compose.yml")}
			}, nil, "", nil, []string{"/artifacts/x/docker-compose.yml"}},
		{"a label without files", coolifyDir,
			func(d string) []composeContainer { return []composeContainer{ctr(appID, "varlatchd", "", d, "False")} }, nil, "", nil,
			[]string{"names no Compose file it was made from"}},
		{"migrate's own file, which no journal records", func(t *testing.T) string {
			return installationDir(t, map[string]string{stock: "services: {}\n", OverrideFile: "services: {}\n", ".env": "COMPOSE_FILE=docker-compose.yml:" + OverrideFile + "\n"})
		}, func(d string) []composeContainer {
			return []composeContainer{at("varlatch", "varlatchd", d, stock), at("varlatch", "postgres", d, stock, OverrideFile)}
		}, nil, "", nil, []string{"made from different files", OverrideFile}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := c.dir(t)
			host := &labelled{}
			if c.containers != nil {
				host.containers = c.containers(dir)
			}
			run := &scripted{t: t, host: host, nameless: true, answers: map[string]Ran{
				"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"asked","services":{}}`)}}}
			cmp := &Compose{Directory: dir, Run: run}
			if c.env != nil {
				cmp.Env = c.env(dir)
			}
			p, err := cmp.project(context.Background())
			if len(c.refused) > 0 {
				for _, w := range c.refused {
					if err == nil || !strings.Contains(err.Error(), w) {
						t.Errorf("%v (%v), want %q", p, err, w)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for _, f := range c.files {
				want = append(want, filepath.Join(dir, f))
			}
			if p.Name != c.project || p.Dir != dir || !slices.Equal(p.Files, want) {
				t.Errorf("%v, want %s of %v", p, c.project, want)
			}
		})
	}
}

// migrate's own file, the last of a container's, is not the installation's
// where a journal records the reverse that wrote it; only that very file.
func TestComposeProjectReversed(t *testing.T) {
	for _, c := range []struct {
		name, file string
		reversed   bool
		refused    string
	}{
		{"journalled", OverrideFile, true, ""},
		{"not journalled", OverrideFile, false, "made from different files"},
		{"another directory's", "x/" + OverrideFile, true, "made from different files"},
	} {
		dir := installationDir(t, map[string]string{"docker-compose.yml": "", OverrideFile: "", ".env": "COMPOSE_FILE=docker-compose.yml:" + OverrideFile + "\n"})
		if err := os.Mkdir(filepath.Join(dir, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x", OverrideFile), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "docker-compose.yml")
		host := &labelled{containers: []composeContainer{ctr("varlatch", "varlatch-web", base, dir, "False"), ctr("varlatch", "postgres", base+","+filepath.Join(dir, c.file), dir, "False")}}
		cmp := &Compose{Directory: dir, Run: &scripted{t: t, host: host}}
		cmp.KeepProject(nil, c.reversed)
		p, err := cmp.project(t.Context())
		if (err == nil) != (c.refused == "") || err != nil && !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%s: %v %v", c.name, p, err)
		}
		if err == nil && (!p.Reversed || !slices.Equal(p.Files, []string{base})) {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
}

// A comma in a path, where Compose joins paths with commas.
func TestLabelPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a,b")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"one.yml", "two,three.yml"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		files string
		want  []string
	}{
		{filepath.Join(dir, "one.yml") + "," + filepath.Join(dir, "two,three.yml"), []string{filepath.Join(dir, "one.yml"), filepath.Join(dir, "two,three.yml")}},
		{"one.yml,two,three.yml", []string{filepath.Join(dir, "one.yml"), filepath.Join(dir, "two,three.yml")}},
		{"gone.yml,one.yml", []string{filepath.Join(dir, "gone.yml"), filepath.Join(dir, "one.yml")}},
		{"", nil},
	} {
		if got := labelPaths(composeContainer{files: c.files, dir: dir}); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.files, got, c.want)
		}
	}
}

// A linked --from: the project's directory and files stay as the labels
// name them, so that Compose makes the same containers from them.
func TestComposeProjectLinkedDirectory(t *testing.T) {
	dir := coolifyDir(t)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{dir, link}, {link, dir}} {
		labels, from := c[0], c[1]
		host := &labelled{containers: []composeContainer{ctr(appID, "varlatchd", filepath.Join(labels, "docker-compose.coolify-tailscale.yml"), labels, "False")}}
		p, err := (&Compose{Directory: from, Run: &scripted{t: t, host: host}}).project(t.Context())
		if err != nil || p.Dir != labels || p.Files[0] != filepath.Join(labels, "docker-compose.coolify-tailscale.yml") {
			t.Errorf("labels %s, --from %s: %v %v", labels, from, p, err)
		}
	}
}

// What the journal records is used, and refused when the containers are
// of another project, or its files are gone; without containers it holds.
func TestComposeProjectJournalled(t *testing.T) {
	dir := coolifyDir(t)
	kept := &ComposeProject{Name: appID, Dir: dir, Files: []string{filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}}
	for _, c := range []struct {
		name, project, file, refused string
		none                         bool
	}{
		{"the same", appID, "docker-compose.coolify-tailscale.yml", "", false},
		{"no containers", "", "", "", true},
		{"another project", "varlatch", "docker-compose.coolify-tailscale.yml", "the migration's journal records the Compose project " + appID, false},
		{"other files", appID, "docker-compose.yaml", "are now of", false},
	} {
		host := &labelled{containers: []composeContainer{ctr(c.project, "varlatchd", filepath.Join(dir, c.file), dir, "False")}}
		if c.none {
			host.containers = nil
		}
		cmp := &Compose{Directory: dir, Run: &scripted{t: t, host: host}}
		cmp.KeepProject(kept, false)
		err := cmp.CheckProject(t.Context())
		if (c.refused == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%s: %v, want %q", c.name, err, c.refused)
		}
	}
	if err := os.Remove(kept.Files[0]); err != nil {
		t.Fatal(err)
	}
	cmp := &Compose{Directory: dir, Run: &scripted{t: t, host: &labelled{}}}
	cmp.KeepProject(kept, false)
	if err := cmp.CheckProject(t.Context()); err == nil || !strings.Contains(err.Error(), "which is not there") {
		t.Errorf("a file gone: %v", err)
	}
}

// Every docker compose command names the project, its directory and its
// files, with migrate's own file while .env names it; the TypeScript CLI
// is given the same in its environment; other docker commands are as they
// were.
func TestComposeCommandsNameTheProject(t *testing.T) {
	dir := coolifyDir(t)
	file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
	named := []string{"compose", "--project-name", appID, "--project-directory", dir, "-f", file}
	run := &scripted{t: t, answers: map[string]Ran{"docker ": {}, "varlatch-ts ": {Answer: []byte("Archive created: /x (11111111-2222-3333-4444-555555555555)\nUpload completed to offsite\n")}}}
	c := &Compose{Directory: dir, Run: run, BEKFile: "/b", Destination: "d", resolved: &ComposeProject{Name: appID, Dir: dir, Files: []string{file}}}
	ctx := t.Context()
	_, _ = c.Gate(ctx)
	_ = c.Release(ctx, "g")
	_ = c.MarkMigratedOut(ctx, "g")
	_, _ = c.Export(ctx, []byte("k"), true)
	_ = c.StopIngress(ctx, Proxy)
	_ = c.StartIngress(ctx, Public, true)
	_ = c.StopTailnet(ctx)
	_ = c.StartTailnet(ctx)
	_ = c.StopStarted(ctx, []string{"postgres"})
	_ = c.ResetConvex(ctx)
	_ = c.StartServing(ctx, Coolify)
	_ = c.StopServing(ctx, Coolify)
	_, _ = c.running(ctx)
	_, _, _ = c.TailnetCertExpiry(ctx, "a.example.ts.net")
	if len(run.argv) < 12 {
		t.Fatalf("%d compose commands", len(run.argv))
	}
	for _, a := range run.argv {
		if len(a) <= len(named) || !slices.Equal(a[:len(named)], named) {
			t.Errorf("ran %q, want it to start %q", a, named)
		}
	}
	if got, err := c.argv(ctx, []string{"volume", "rm", "x"}); err != nil || !slices.Equal(got, []string{"volume", "rm", "x"}) {
		t.Errorf("another docker command: %q %v", got, err)
	}
	if _, err := c.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	for key, env := range run.envs {
		if want := []string{"COMPOSE_PROJECT_NAME=" + appID, "COMPOSE_FILE=" + file, "COMPOSE_PATH_SEPARATOR=:"}; !strings.HasPrefix(key, "varlatch-ts admin backup create") || !slices.Equal(env, want) {
			t.Errorf("%s: %q, want %q", key, env, want)
		}
	}
	if len(run.envs) != 1 {
		t.Errorf("%d programs with an environment", len(run.envs))
	}
	if said := c.byHand("ps"); !strings.Contains(said, "--project-name "+appID) {
		t.Errorf("by hand: %s", said)
	}
	// A reverse's database in use.
	c.reversed = true
	f := "docker-compose.coolify-tailscale.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &f, ""); err != nil {
		t.Fatal(err)
	}
	got, err := c.argv(ctx, []string{"compose", "up"})
	if want := append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up"); err != nil || !slices.Equal(got, want) {
		t.Errorf("%q %v, want %q", got, err, want)
	}
	stock := installationDir(t, map[string]string{"docker-compose.yml": "services: {}\n"})
	if said := (&Compose{Directory: stock, resolved: testProject(stock)}).byHand("ps"); said != "docker compose ps" {
		t.Errorf("by hand, stock: %s", said)
	}
}

// The reverse's Compose file, by the names the installation's files give:
// the stock installation's file is as it was; Coolify's rendered file
// prefixes its volumes and puts its services on the application's network.
// testdata/compose-config/coolify-tailscale.json is Compose 5.6.1's
// answer for a file Coolify 4.7.6 rendered.
func TestReverseOverrideNames(t *testing.T) {
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	plan := func(config []byte, dir string) RebuildRecord {
		t.Helper()
		cfg, err := parseConfig(Ran{Answer: config})
		if err != nil {
			t.Fatal(err)
		}
		names, err := (&Compose{}).dataNames(cfg)
		if err != nil {
			t.Fatal(err)
		}
		j.Source.Volumes = []VolumeRecord{{Name: names[0]}, {Name: names[1]}}
		run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: config}}}
		p, err := (&Compose{Directory: dir, Run: run, resolved: testProject(dir)}).RebuildPlan(t.Context(), j)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	stock := plan([]byte(stockConfig), t.TempDir())
	if stock.Keys != nil || stock.Networks != nil || !strings.Contains(override(stock), "volumes:\n  postgres-data:\n    name: varlatch_postgres-data-abcdefgh\n  convex-data:\n") ||
		!strings.Contains(override(stock), "      - varlatch-state:/var/lib/varlatch\n") || strings.Contains(override(stock), "networks:") {
		t.Errorf("stock: %+v\n%s", stock, override(stock))
	}
	b, err := os.ReadFile(filepath.Join("testdata", "compose-config", "coolify-tailscale.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cool := plan(b, dir)
	text := override(cool)
	for _, w := range []string{"  " + appID + "_postgres-data:\n    name: " + appID + "_postgres-data-abcdefgh\n", "  " + appID + "_convex-data:\n    name: " + appID + "_convex-data-abcdefgh\n",
		"      - " + appID + "_varlatch-state:/var/lib/varlatch\n", "    networks:\n      - " + appID + "\n"} {
		if !strings.Contains(text, w) {
			t.Errorf("no %q in\n%s", w, text)
		}
	}
	// A file whose Postgres mounts no named volume cannot be given a fresh
	// one.
	run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"varlatch","services":{"postgres":{"volumes":["/data:/var/lib/postgresql/data"]}}}`)}}}
	if _, err := (&Compose{Directory: dir, Run: run, resolved: testProject(dir)}).RebuildPlan(t.Context(), j); err == nil || !strings.Contains(err.Error(), "mounts no named volume") {
		t.Errorf("no named volume: %v", err)
	}
	// COMPOSE_FILE keeps the installation's own names.
	for _, c := range []struct{ file, want string }{{"docker-compose.yml", "docker-compose.yml:" + OverrideFile}, {"docker-compose.coolify-tailscale.yml", "docker-compose.coolify-tailscale.yml:" + OverrideFile}} {
		d := t.TempDir()
		cmp := &Compose{Directory: d, resolved: &ComposeProject{Name: "p", Dir: d, Files: []string{filepath.Join(d, c.file)}}}
		if got, err := cmp.composeFiles(cmp.resolved, RebuildRecord{}); err != nil || got != c.want {
			t.Errorf("%s: %s %v", c.file, got, err)
		}
	}
}

// On a real Docker (VARLATCH_MIGRATE_TEST_DOCKER=1, with an image that is
// there as VARLATCH_MIGRATE_TEST_IMAGE): a directory shaped as Coolify's,
// its containers made from the third file under the application's id (a
// short sleep, for the reverse's part). Plain docker compose reads the repository's file there;
// migrate reads the containers', and its commands reach them.
func TestComposeProjectOnDocker(t *testing.T) {
	image := os.Getenv("VARLATCH_MIGRATE_TEST_IMAGE")
	if os.Getenv("VARLATCH_MIGRATE_TEST_DOCKER") != "1" || image == "" {
		t.Skip("VARLATCH_MIGRATE_TEST_DOCKER is not 1")
	}
	dir := coolifyDir(t)
	const project = "vl-migrate-test-coolify"
	svc := func(name, vol, target, more string) string {
		return "  " + name + ":\n    image: " + image + "\n    command: [\"sleep\", \"600\"]\n    stop_grace_period: 1s\n    networks: [" + project + "]\n    volumes: [\"" + project + "_" + vol + ":" + target + "\"]\n" + more
	}
	rendered := "services:\n" + svc("varlatchd", "varlatch-state", "/var/lib/varlatch", "    labels:\n      digest: ${VARLATCH_VARLATCHD_DIGEST:?set it}\n") +
		svc("varlatch-migrate", "varlatch-state", "/var/lib/varlatch", "") + svc("postgres", "postgres-data", "/var/lib/postgresql/data", "") + svc("convex-backend", "convex-data", "/convex/data", "") +
		"networks:\n  " + project + ": {}\nvolumes:\n"
	for _, v := range []string{"varlatch-state", "postgres-data", "convex-data"} {
		rendered += "  " + project + "_" + v + ":\n    name: " + project + "_" + v + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.coolify-tailscale.yml"), []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("name: vl-migrate-test-decoy\nservices:\n  varlatchd:\n    image: "+image+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var x ExecRunner
	ctx := t.Context()
	docker := func(args ...string) Ran {
		t.Helper()
		r, err := x.Run(ctx, dir, "docker", args, nil)
		if err != nil || r.Code != 0 {
			t.Fatalf("docker %v: %v %s", args, err, r.Said)
		}
		return r
	}
	named := []string{"compose", "--project-name", project, "--project-directory", dir, "-f", filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}
	t.Cleanup(func() {
		_, _ = x.Run(context.Background(), dir, "docker", append(slices.Clone(named), "down", "-v", "--remove-orphans", "--timeout", "1"), nil)
		for _, v := range []string{"postgres-data-abcdefgh", "convex-data-abcdefgh", "unrelated"} {
			_, _ = x.Run(context.Background(), dir, "docker", []string{"volume", "rm", "-f", project + "_" + v}, nil)
		}
	})
	docker(append(slices.Clone(named), "create", "--pull", "never")...)
	c := &Compose{Directory: dir, Run: x}
	p, err := c.project(ctx)
	if err != nil || p.Name != project || p.Dir != dir || !slices.Equal(p.Files, []string{filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}) {
		t.Fatalf("%v %v", p, err)
	}
	ps := []string{"compose", "ps", "-a", "-q", service}
	r, err := c.docker(ctx, ps, nil)
	if err != nil || r.Code != 0 || len(strings.Fields(string(r.Answer))) != 1 {
		t.Errorf("migrate's %v: %v %s%s", ps, err, r.Answer, r.Said)
	}
	if plain, _ := x.Run(ctx, dir, "docker", ps, nil); len(strings.Fields(string(plain.Answer))) != 0 {
		t.Errorf("plain %v finds %s: the directory does not show the difference", ps, plain.Answer)
	}
	// .env is the project directory's: the digest is interpolated from it.
	cfg, err := c.docker(ctx, []string{"compose", "config", "--format", "json"}, nil)
	if err != nil || cfg.Code != 0 || !strings.Contains(string(cfg.Answer), "sha256:"+strings.Repeat("a", 64)) {
		t.Errorf("config: %v %d %s", err, cfg.Code, cfg.Said)
	}
	// The reverse's rebuild: Postgres on the fresh volume, checked on the
	// container; an override by the stock names is refused before Postgres
	// starts, and a container on the retained volume before an import.
	plan, err := c.RebuildPlan(ctx, &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}})
	if err != nil {
		t.Fatal(err)
	}
	// The same without a container to look at, by what was recorded; and,
	// with nothing recorded, refused.
	source := plan.Retained
	docker(append(slices.Clone(named), "rm", "-sf")...)
	bare := &Compose{Directory: dir, Run: x}
	bare.KeepProject(&ComposeProject{Name: p.Name, Dir: p.Dir, Files: p.Files}, false)
	again, err := bare.RebuildPlan(ctx, &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Volumes: source, Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}})
	if err != nil || !slices.Equal(again.Retained, source) {
		t.Errorf("without containers: %+v %v, want %+v", again.Retained, err, source)
	}
	if _, err := bare.RebuildPlan(ctx, &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}); err == nil || !strings.Contains(err.Error(), "does not record which volume") {
		t.Errorf("without containers or a record: %v", err)
	}
	// The gate, read from the state volume without a container of the
	// installation's: there, its file gone, the volume gone (not made by
	// the reading), another of its name.
	gateVol := project + "_" + stateKey
	state, _, err := bare.stateVolume(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gate := GateRef{ID: "gate-1", State: state, Image: image}
	write := func(sh string) {
		docker("run", "--rm", "--pull", "never", "--network", "none", "-v", gateVol+":/s", "--entrypoint", "sh", image, "-c", sh)
	}
	check := func(want string) {
		t.Helper()
		if err := bare.CheckGate(ctx, gate); (err == nil) != (want == "") || err != nil && !strings.Contains(err.Error(), want) {
			t.Errorf("the gate: %v, want %q", err, want)
		}
	}
	check("holds no gate")
	write("printf '%s' '" + gateText + "' > /s/maintenance.json")
	check("")
	write("sed -i s/gate-1/gate-2/ /s/maintenance.json")
	check("is migrated-out gate-2")
	write("rm /s/maintenance.json")
	check("holds no gate")
	docker("volume", "rm", gateVol)
	check("is not there")
	if v, err := bare.volume(ctx, gateVol); v != nil || err != nil {
		t.Errorf("the state volume after it was looked for: %+v %v", v, err)
	}
	time.Sleep(1100 * time.Millisecond)
	docker("volume", "create", "--label", labelProject+"="+project, "--label", labelVolume+"="+gateVol, gateVol)
	check("is not the one that carried the gate")
	docker("volume", "rm", gateVol)
	docker("volume", "create", "--label", labelProject+"="+project, "--label", labelVolume+"="+gateVol, gateVol)
	if gate.State, _, err = bare.stateVolume(ctx); err != nil {
		t.Fatal(err)
	}
	// Through varlatchd's own container, made and not started; the very one
	// is started, by its id.
	docker(append(slices.Clone(named), "up", "--no-start", "--no-deps", "--pull", "never", service)...)
	check("holds no gate")
	if err := bare.startGated(ctx, gate, false); err == nil || !strings.Contains(err.Error(), "holds no gate") {
		t.Errorf("started without its gate: %v", err)
	}
	write("ln -s /etc/hostname /s/maintenance.json")
	check("is not a plain file")
	write("rm /s/maintenance.json; printf '%s' '" + gateText + "' > /s/maintenance.json; mkdir /s/part; cp /s/maintenance.json /s/part/")
	check("")
	status := func() (id, status string) {
		t.Helper()
		_, l, err := bare.stateVolume(ctx)
		if err != nil || l == nil {
			t.Fatalf("%+v %v", l, err)
		}
		return l.id, l.status
	}
	if id, s := status(); s != "created" {
		t.Errorf("%s is %s", id, s)
	}
	made, _ := status()
	if err := bare.startGated(ctx, gate, false); err != nil {
		t.Errorf("behind its gate: %v", err)
	}
	if id, s := status(); id != made || s != "running" {
		t.Errorf("%s is %s, made %s", id, s, made)
	}
	check("")
	if err := bare.startGated(ctx, gate, false); err != nil {
		t.Errorf("again: %v", err)
	}
	// Lifted, and held again as it was; a barrier in its place replaced; a
	// volume that is gone made again, its gate in it.
	write("rm /s/maintenance.json")
	for _, there := range []string{"", strings.Replace(gateText, "migrated-out", "migration", 1)} {
		if there != "" {
			write("printf '%s' '" + there + "' > /s/maintenance.json")
		}
		held, err := bare.HoldGate(ctx, gate, "46")
		if err != nil || held.ID != gate.ID || *held.State != *gate.State {
			t.Errorf("held: %+v %v", held, err)
		}
		if err := bare.CheckHeld(ctx, held); err != nil {
			t.Errorf("held: %v", err)
		}
		check("")
	}
	write("rm /s/maintenance.json; mkdir /s/maintenance.json")
	if _, err := bare.HoldGate(ctx, gate, "46"); err == nil || !strings.Contains(err.Error(), "is not a plain file") {
		t.Errorf("a directory: %v", err)
	}
	write("rmdir /s/maintenance.json; printf '%s' '" + gateText + "' > /s/maintenance.json")
	// A part of the volume, which has the same file: another container, and
	// not the whole.
	part := filepath.Join(dir, "part.yml")
	if err := os.WriteFile(part, []byte("services:\n  varlatchd:\n    volumes:\n      - {type: volume, source: "+gateVol+", target: /var/lib/varlatch, volume: {subpath: part}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inPart := &Compose{Directory: dir, Run: x, resolved: &ComposeProject{Name: p.Name, Dir: p.Dir, Files: append(slices.Clone(p.Files), part)}}
	docker("rm", "-f", made)
	if err := inPart.startGated(ctx, gate, true); err == nil || !strings.Contains(err.Error(), "a part of it") {
		t.Errorf("a part of the volume: %v", err)
	}
	docker(append(slices.Clone(named), "-f", part, "rm", "-sf")...)
	docker("volume", "rm", gateVol)
	if held, err := bare.HoldGate(ctx, gate, "46"); err != nil || held.State.Project != project || held.State.CreatedAt == "" || bare.CheckHeld(ctx, held) != nil {
		t.Errorf("the volume gone: %+v %v", held, err)
	}
	docker("volume", "rm", gateVol)
	if data, _, err := bare.MountedVolumes(ctx, source); err != nil || !slices.Equal(data, source) {
		t.Errorf("--finish without containers: %+v %v", data, err)
	}
	if _, text, err := bare.RouteFile(ctx, "https://vault.example.test", "mig_x"); err == nil || !strings.Contains(err.Error(), "varlatch-web") {
		t.Errorf("a route to a dashboard the files do not have: %s %v", text, err)
	}
	docker(append(slices.Clone(named), "create", "--pull", "never")...)
	for i, v := range []string{"postgres-data", "convex-data"} {
		if r := plan.Retained[i]; r.Name != project+"_"+v || r.Project != project || r.CreatedAt == "" {
			t.Errorf("retained: %+v", r)
		}
	}
	if _, err := c.MakeVolumes(ctx, RebuildRecord{Volumes: []string{project + "_postgres-data"}, Owner: plan.Owner}); err == nil || !strings.Contains(err.Error(), "is not this migration's") {
		t.Errorf("a volume that is there, taken for a fresh one: %v", err)
	}
	if plan.Made, err = c.MakeVolumes(ctx, plan); err != nil || plan.Made[0].Owner != plan.Owner || plan.Made[0].Mountpoint == "" {
		t.Fatalf("the fresh volumes: %+v %v", plan.Made, err)
	}
	if again, err := c.RebuildPlan(ctx, &Journal{ID: plan.Owner, Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}); err != nil || again.Volumes[0] == plan.Volumes[0] {
		t.Errorf("a name that is taken: %v %v", again.Volumes, err)
	}
	docker(append(slices.Clone(named), "up", "-d", "--no-deps", "postgres")...)
	if err := c.CheckRebuilt(ctx, plan, false); err == nil || !strings.Contains(err.Error(), "give postgres the volume "+project+"_postgres-data,") || !strings.Contains(err.Error(), plan.Volumes[0]) {
		t.Errorf("on the retained volume: %v", err)
	}
	stock := plan
	stock.Keys = nil
	if err := c.Rebuild(ctx, stock); err == nil || !strings.Contains(err.Error(), "it was not started") {
		t.Errorf("an override by the stock names: %v", err)
	}
	if err := c.Rebuild(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRebuilt(ctx, plan, false); err != nil {
		t.Errorf("rebuilt: %v", err)
	}
	docker(append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up", "-d", "--no-deps", "convex-backend")...)
	if err := c.CheckRebuilt(ctx, plan, true); err != nil {
		t.Errorf("rebuilt, Convex too: %v", err)
	}
	// The containers gone (a prune): known by the journal, the files and
	// the volumes alone; made again where they were.
	journalled := &Compose{Directory: dir, Run: x}
	journalled.KeepProject(&ComposeProject{Name: p.Name, Dir: p.Dir, Files: p.Files}, true)
	docker(append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "rm", "-sf")...)
	if err := journalled.CheckProject(ctx); err != nil {
		t.Errorf("the project without containers: %v", err)
	}
	if err := journalled.CheckRebuilt(ctx, plan, true); err == nil || !strings.Contains(err.Error(), "0 postgres containers") || !strings.Contains(err.Error(), "up -d --no-deps postgres convex-backend") {
		t.Errorf("rebuilt, without containers: %v", err)
	}
	docker(append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up", "-d", "--no-deps", "postgres", "convex-backend", service)...)
	if err := journalled.CheckRebuilt(ctx, plan, true); err != nil {
		t.Errorf("made again: %v", err)
	}
	// Deployed again from the orchestrator's own file, .env without
	// COMPOSE_FILE: on the retained volumes, refused; refused too once .env
	// names migrate's file again, until the command said is run.
	deployed, _, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.setEnv("COMPOSE_FILE", nil, ""); err != nil {
		t.Fatal(err)
	}
	docker(append(slices.Clone(named), "up", "-d", "--no-deps", "postgres", "convex-backend")...)
	err = c.CheckRebuilt(ctx, plan, true)
	if err == nil || !strings.Contains(err.Error(), "give postgres the volume "+project+"_postgres-data,") || !strings.Contains(err.Error(), "set COMPOSE_FILE="+deployed+" in ") {
		t.Errorf("deployed again: %v", err)
	}
	none := Removals{Intend: func(string) error { return nil }, Removed: func(string) error { return nil }}
	if err := c.RemoveRetained(ctx, plan, none); err == nil || !strings.Contains(err.Error(), "left as they are") {
		t.Errorf("removing while deployed again: %v", err)
	}
	if err := c.setEnv("COMPOSE_FILE", &deployed, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckRebuilt(ctx, plan, true); err == nil || !strings.Contains(err.Error(), "postgres runs on "+project+"_postgres-data,") {
		t.Errorf("deployed again, .env put back: %v", err)
	}
	docker(append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up", "-d", "--no-deps", "postgres", "convex-backend", service)...)
	if err := c.CheckRebuilt(ctx, plan, true); err != nil {
		t.Errorf("recovered: %v", err)
	}
	// Another directory's container of the same project, stopped: nothing
	// more is done, and the retained volumes stay.
	other := installationDir(t, map[string]string{"compose.yml": "services:\n  elsewhere:\n    image: " + image + "\n    network_mode: none\n"})
	stranger := []string{"compose", "--project-name", project, "--project-directory", other, "-f", filepath.Join(other, "compose.yml")}
	docker(append(slices.Clone(stranger), "create", "--pull", "never")...)
	for name, do := range map[string]func() error{
		"check":  func() error { return c.CheckProject(ctx) },
		"stop":   func() error { return c.StopServing(ctx, Coolify) },
		"remove": func() error { return c.RemoveRetained(ctx, plan, none) },
		"empty": func() error {
			return (&Compose{Directory: t.TempDir(), Run: x, resolved: &ComposeProject{Name: p.Name, Dir: other, Files: []string{filepath.Join(other, "compose.yml")}}}).CheckProject(ctx)
		},
	} {
		if err := do(); err == nil || !strings.Contains(err.Error(), "container made from ") {
			t.Errorf("%s, with another directory's container: %v", name, err)
		}
	}
	docker(append(slices.Clone(stranger), "rm", "-f", "elsewhere")...)
	// The retained ones by the journal's record, unused, removed; the
	// fresh ones stay. One of the same name made since is not removed.
	remade := plan
	remade.Retained = slices.Clone(plan.Retained)
	remade.Retained[1].CreatedAt = "2020-01-01T00:00:00Z"
	if err := c.RemoveRetained(ctx, remade, none); err == nil || !strings.Contains(err.Error(), "is not the one the journal records") {
		t.Errorf("a volume made since: %v", err)
	}
	if err := c.CheckData(ctx, Coolify, &plan, nil, none); err != nil {
		t.Errorf("before the removal: %v", err)
	}
	if err := c.RemoveRetained(ctx, plan, none); err != nil {
		t.Errorf("removing the retained volumes: %v", err)
	}
	for i, v := range []string{plan.Retained[0].Name, plan.Retained[1].Name, plan.Volumes[0], plan.Volumes[1]} {
		if there, err := c.volume(ctx, v); err != nil || (there != nil) != (i > 1) {
			t.Errorf("%s after: %v %v", v, there, err)
		}
	}
	if err := c.CheckRebuilt(ctx, plan, true); err != nil {
		t.Errorf("at the end: %v", err)
	}
	// A forward --finish: what the containers mount, held against the
	// files; another name in them since (the containers as they were) is
	// refused, before and after they are down, and neither is removed.
	data, others, err := c.MountedVolumes(ctx, nil)
	if err != nil || data[0].Name != plan.Volumes[0] || data[1].Name != plan.Volumes[1] || len(others) != 1 || others[0].Name != project+"_"+stateKey {
		t.Fatalf("mounted: %+v %+v %v", data, others, err)
	}
	if err := c.CheckData(ctx, Public, nil, data, none); err != nil {
		t.Errorf("the data: %v", err)
	}
	docker("volume", "create", "--label", labelProject+"="+project, project+"_unrelated")
	text, _ := os.ReadFile(filepath.Join(dir, OverrideFile))
	if err := os.WriteFile(filepath.Join(dir, OverrideFile), []byte(strings.Replace(string(text), plan.Volumes[0], project+"_unrelated", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckData(ctx, Public, nil, data, none); err == nil || !strings.Contains(err.Error(), project+"_unrelated") {
		t.Errorf("a name changed since: %v", err)
	}
	if _, _, err := c.MountedVolumes(ctx, nil); err == nil || !strings.Contains(err.Error(), project+"_unrelated") {
		t.Errorf("a name changed before: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, OverrideFile), text, 0o600); err != nil {
		t.Fatal(err)
	}
	// An undo removes only volumes of this migration.
	foreign := plan
	foreign.Owner = "mig_another"
	for _, p := range []RebuildRecord{foreign, {Override: OverrideFile, Volumes: plan.Volumes}} {
		_ = c.compose(ctx, "stop", "stop", "postgres", "convex-backend")
		for _, name := range p.Volumes {
			v, err := c.volume(ctx, name)
			if err != nil || v == nil || p.ours(0, *v) && p.ours(1, *v) {
				t.Errorf("taken for %q's: %+v %v", p.Owner, v, err)
			}
		}
	}
	if err := c.RemoveOld(ctx, Public, data, others, none); err != nil {
		t.Errorf("removing: %v", err)
	}
	for i, v := range []string{plan.Volumes[0], plan.Volumes[1], project + "_" + stateKey, project + "_unrelated"} {
		if there, err := c.volume(ctx, v); err != nil || (there != nil) != (i == 3) {
			t.Errorf("%s after: %v %v", v, there, err)
		}
	}
}

// An undo puts Postgres and Convex back on the volumes the Compose files
// name with any Docker Compose, the one at hand: an earlier one leaves their
// containers as they are when only a volume's name changed.
func TestTheUndoOnDocker(t *testing.T) {
	image := os.Getenv("VARLATCH_MIGRATE_TEST_IMAGE")
	if os.Getenv("VARLATCH_MIGRATE_TEST_DOCKER") != "1" || image == "" {
		t.Skip("VARLATCH_MIGRATE_TEST_DOCKER is not 1")
	}
	const project = "vl-migrate-test-undo"
	svc := func(name, vol, target string) string {
		return "  " + name + ":\n    image: " + image + "\n    command: [\"sleep\", \"600\"]\n    stop_grace_period: 1s\n    network_mode: none\n    volumes: [\"" + vol + ":" + target + "\"]\n"
	}
	dir := installationDir(t, map[string]string{
		"docker-compose.yml": "name: " + project + "\nservices:\n" + svc("varlatchd", "varlatch-state", "/var/lib/varlatch") + svc("postgres", "postgres-data", "/var/lib/postgresql/data") + svc("convex-backend", "convex-data", "/convex/data") +
			"volumes: {varlatch-state: {}, postgres-data: {}, convex-data: {}}\n",
	})
	var x ExecRunner
	ctx := t.Context()
	docker := func(args ...string) {
		t.Helper()
		if r, err := x.Run(ctx, dir, "docker", args, nil); err != nil || r.Code != 0 {
			t.Fatalf("docker %v: %v %s", args, err, r.Said)
		}
	}
	named := []string{"compose", "--project-name", project, "--project-directory", dir, "-f", filepath.Join(dir, "docker-compose.yml")}
	plan := RebuildRecord{Override: OverrideFile, Owner: "mig_undo", Volumes: []string{project + "_postgres-data-abcdefgh", project + "_convex-data-abcdefgh"}}
	t.Cleanup(func() {
		_, _ = x.Run(context.Background(), dir, "docker", append(slices.Clone(named), "down", "-v", "--remove-orphans", "--timeout", "1"), nil)
		for _, v := range plan.Volumes {
			_, _ = x.Run(context.Background(), dir, "docker", []string{"volume", "rm", "-f", v}, nil)
		}
	})
	docker(append(slices.Clone(named), "up", "-d", "--pull", "never")...)
	c := &Compose{Directory: dir, Run: x}
	p, err := c.project(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.KeepProject(&ComposeProject{Name: p.Name, Dir: p.Dir, Files: p.Files}, true)
	for i, v := range stockKeys[:2] {
		r, err := c.volume(ctx, project+"_"+v)
		if err != nil || r == nil {
			t.Fatalf("%s: %v %v", v, r, err)
		}
		plan.Retained = append(plan.Retained, *r)
		docker("volume", "create", "--label", labelProject+"="+project, "--label", labelVolume+"="+v, "--label", labelOwner+"="+plan.Owner, plan.Volumes[i])
	}
	// On the fresh volumes, made so whatever Compose does of itself.
	if err := os.WriteFile(filepath.Join(dir, OverrideFile), []byte("volumes:\n  postgres-data:\n    name: "+plan.Volumes[0]+"\n  convex-data:\n    name: "+plan.Volumes[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	docker(append(slices.Clone(named), "rm", "-sf", "postgres", "convex-backend")...)
	docker(append(slices.Clone(named), "-f", filepath.Join(dir, OverrideFile), "up", "-d", "--no-deps", "--pull", "never", "postgres", "convex-backend")...)
	on := func() []string {
		t.Helper()
		_, all, err := c.verified(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range dataMounts {
			for _, l := range serviceContainers(p, all, d.service) {
				out = append(out, l.volumeAt(d.target)+" "+l.status)
			}
		}
		return out
	}
	if got := on(); !slices.Equal(got, []string{plan.Volumes[0] + " running", plan.Volumes[1] + " running"}) {
		t.Fatalf("rebuilt: %v", got)
	}
	// The undo: the files as they were, the rest in its order.
	if err := os.Remove(filepath.Join(dir, OverrideFile)); err != nil {
		t.Fatal(err)
	}
	if err := c.stopContainers(ctx, service, "convex-backend", "postgres"); err != nil {
		t.Fatal(err)
	}
	if err := c.restoreVolumes(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if got := on(); !slices.Equal(got, []string{project + "_postgres-data running", project + "_convex-data running"}) {
		t.Errorf("put back: %v", got)
	}
	for _, v := range plan.Volumes {
		if users, err := c.volumeUsers(ctx, v); err != nil || len(users) > 0 {
			t.Errorf("%s is used by %v %v", v, users, err)
		}
	}
	if err := c.restoreVolumes(ctx, plan); err != nil {
		t.Errorf("again: %v", err)
	}
}

// The engine gives every command that goes on with a migration the
// journal's project, and one that changed is refused before anything of
// --resume, --abort or --rollback is done: the journal and both sides are
// as they were.
func TestTheEngineKeepsTheProject(t *testing.T) {
	project := &ComposeProject{Name: appID, Dir: "/data/coolify/applications/" + appID, Files: []string{"/data/coolify/applications/" + appID + "/docker-compose.coolify-tailscale.yml"}}
	changed := errors.New("the installation was started another way since")
	for _, c := range []struct {
		name  string
		phase Phase
		run   func(*Engine) (*Journal, error)
	}{
		{"resume, held", Copied, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"resume, transfer", Transfer, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"resume, switched", Switched, func(e *Engine) (*Journal, error) { return e.Resume(context.Background()) }},
		{"abort, held", Barrier, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"abort, transfer", Transfer, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"abort, reverse", Rollback, func(e *Engine) (*Journal, error) { return e.Abort(context.Background()) }},
		{"rollback", Open, func(e *Engine) (*Journal, error) { return e.Rollback(context.Background()) }},
	} {
		w := newWorld(t)
		info := w.src.info
		info.Project = project
		j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: c.phase, Source: info, Ingress: Coolify, Rollback: &RollbackRecord{},
			Transfer: &TransferRecord{}, History: []Step{{Phase: Switched, At: w.eng.now().Format(time.RFC3339Nano)}}}
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(w.src.dir, JournalFile))
		w.src.projectErr = changed
		_, err := c.run(w.eng)
		after, _ := os.ReadFile(filepath.Join(w.src.dir, JournalFile))
		if !errors.Is(err, changed) || w.src.checked != 1 || len(w.src.calls) != 0 || string(before) != string(after) {
			t.Errorf("%s: %v, checked %d, calls %v, journal changed %v", c.name, err, w.src.checked, w.src.calls, string(before) != string(after))
		}
		if w.src.kept == nil || w.src.kept.Name != project.Name || !slices.Equal(w.src.kept.Files, project.Files) {
			t.Errorf("%s: kept %v", c.name, w.src.kept)
		}
	}
}

// The rebuild never goes on with a Postgres on another volume than the
// journal's fresh one: before it starts, what the Compose files would give
// it (and Convex); before the import, what its container mounts. Each
// refusal names both volumes.
func TestTheRebuildRunsOnTheFreshVolume(t *testing.T) {
	const fresh, freshConvex, retained = appID + "_postgres-data-abcdefgh", appID + "_convex-data-abcdefgh", appID + "_postgres-data"
	plan := RebuildRecord{Override: OverrideFile, Volumes: []string{fresh, freshConvex}, Keys: []string{retained, appID + "_convex-data", appID + "_varlatch-state"}, Image: "x@sha256:y", Owner: "mig_x"}
	madeVolumes := map[string]VolumeRecord{}
	for _, n := range plan.Volumes {
		v := VolumeRecord{Name: n, CreatedAt: "2026-11-01T00:00:00Z", Mountpoint: "/v/" + n, Project: appID, Owner: "mig_x"}
		madeVolumes[n], plan.Made = v, append(plan.Made, v)
	}
	config := func(pg, convex string) Ran {
		return Ran{Answer: []byte(`{"name":"` + appID + `","services":{"postgres":{"volumes":[{"type":"volume","source":"` + retained + `","target":"/var/lib/postgresql/data"}]},` +
			`"convex-backend":{"volumes":[{"type":"volume","source":"` + appID + `_convex-data","target":"/convex/data"}]},"varlatchd":{"volumes":[{"type":"volume","source":"` + appID + `_varlatch-state","target":"/var/lib/varlatch"}]}},` +
			`"volumes":{"` + retained + `":{"name":"` + pg + `"},"` + appID + `_convex-data":{"name":"` + convex + `"}}}`)}
	}
	for _, c := range []struct {
		name, pg, convex string
		refused          []string
	}{
		{"fresh", fresh, freshConvex, nil},
		{"Postgres's retained", retained, freshConvex, []string{"give postgres the volume " + retained + ",", fresh}},
		{"Convex's retained", fresh, appID + "_convex-data", []string{"give convex-backend the volume " + appID + "_convex-data,", freshConvex}},
		{"unnamed: the project's", "", freshConvex, []string{"the volume " + appID + "_" + retained, fresh}},
	} {
		dir := coolifyDir(t)
		run := &scripted{t: t, host: &labelled{volumes: madeVolumes}, answers: map[string]Ran{"docker compose stop ": {}, "docker compose up -d postgres": {}, "docker compose config --no-interpolate --format json": config(c.pg, c.convex)}}
		cmp := &Compose{Directory: dir, Run: run, resolved: &ComposeProject{Name: appID, Dir: dir, Files: []string{filepath.Join(dir, "docker-compose.coolify-tailscale.yml")}}}
		err := cmp.Rebuild(t.Context(), plan)
		started := slices.Contains(run.ran, "docker compose up -d postgres")
		if started != (c.refused == nil) || (err == nil) != (c.refused == nil) {
			t.Errorf("%s: %v, started %v", c.name, err, started)
		}
		for _, w := range c.refused {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %v, want %q", c.name, err, w)
			}
		}
		// The configuration asked names migrate's file too.
		if last := run.argv[len(run.argv)-1]; !slices.Contains(last, filepath.Join(dir, OverrideFile)) {
			t.Errorf("%s: %q", c.name, last)
		}
	}
	const retainedConvex = appID + "_convex-data"
	pg := func(status, kind, name string) composeContainer {
		return composeContainer{project: appID, service: "postgres", status: status, mounts: []containerMount{{Type: "bind", Destination: "/docker-entrypoint-initdb.d"}, {Type: kind, Name: name, Destination: postgresTarget}}}
	}
	cv := func(name string) composeContainer {
		return composeContainer{project: appID, service: "convex-backend", status: "running", mounts: []containerMount{{Type: "volume", Name: name, Destination: convexTarget}}}
	}
	good := []composeContainer{pg("running", "volume", fresh), cv(freshConvex)}
	for _, c := range []struct {
		name       string
		containers []composeContainer
		config     Ran
		env        string // .env's COMPOSE_FILE ("" for none)
		lost       bool   // migrate's file is gone
		before     bool   // before Convex is reset
		refused    []string
	}{
		{name: "fresh", containers: good},
		{name: "fresh, Convex not yet", containers: []composeContainer{good[0], cv(retainedConvex)}, before: true},
		{name: "Convex's retained", containers: []composeContainer{good[0], cv(retainedConvex)}, refused: []string{"convex-backend runs on " + retainedConvex + ",", freshConvex}},
		{name: "no Convex", containers: good[:1], refused: []string{"0 convex-backend containers"}},
		{name: "deployed again: the override out of .env, the containers on the retained volumes", containers: []composeContainer{pg("running", "volume", retained), cv(retainedConvex)},
			config: config(retained, retainedConvex), env: "none",
			refused: []string{"give postgres the volume " + retained + ",", "set COMPOSE_FILE=docker-compose.coolify-tailscale.yml:" + OverrideFile + " in ", " up -d --no-deps postgres convex-backend varlatchd"}},
		{name: "the override out of .env, the containers still fresh", containers: good, config: config(retained, retainedConvex), env: "none", refused: []string{"give postgres the volume " + retained + ",", "COMPOSE_FILE="}},
		{name: "the override in .env, the containers on the retained volumes", containers: []composeContainer{pg("running", "volume", retained), cv(retainedConvex)},
			refused: []string{"postgres runs on " + retained + ",", fresh, "up -d --no-deps postgres"}},
		{name: "the override gone", containers: good, config: Ran{Code: 1}, lost: true, refused: []string{OverrideFile + " (the Compose file that names them) is gone"}},
		{name: "a longer name", containers: []composeContainer{pg("running", "volume", fresh+"x"), good[1]}, refused: []string{fresh + "x,"}},
		{name: "a bind mount", containers: []composeContainer{pg("running", "bind", ""), good[1]}, refused: []string{"runs on no named volume", fresh}},
		{name: "nothing mounted", containers: []composeContainer{{project: appID, service: "postgres", status: "running"}, good[1]}, refused: []string{"runs on no named volume", fresh}},
		{name: "restarting", containers: []composeContainer{pg("restarting", "volume", fresh), good[1]}, refused: []string{"does not run", "restarting", fresh}},
		{name: "no container", containers: good[1:], refused: []string{"0 postgres containers"}},
		{name: "two", containers: append(slices.Clone(good), good[0]), refused: []string{"2 postgres containers"}},
		{name: "another project's only", containers: []composeContainer{{project: "other", service: "postgres", status: "running", mounts: good[0].mounts}, good[1]}, refused: []string{"2 Compose projects"}},
	} {
		dir := coolifyDir(t)
		file := filepath.Join(dir, "docker-compose.coolify-tailscale.yml")
		host := &labelled{volumes: madeVolumes}
		for _, l := range c.containers {
			l.dir, l.files = dir, file+","+filepath.Join(dir, OverrideFile)
			host.containers = append(host.containers, l)
		}
		if !c.lost {
			if err := os.WriteFile(filepath.Join(dir, OverrideFile), []byte(override(plan)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if c.config.Answer == nil && c.config.Code == 0 {
			c.config = config(fresh, freshConvex)
		}
		run := &scripted{t: t, host: host, answers: map[string]Ran{"docker compose config --no-interpolate --format json": c.config}}
		cmp := &Compose{Directory: dir, Run: run}
		cmp.KeepProject(&ComposeProject{Name: appID, Dir: dir, Files: []string{file}}, true)
		if c.env == "" {
			v := "docker-compose.coolify-tailscale.yml:" + OverrideFile
			if err := cmp.setEnv("COMPOSE_FILE", &v, ""); err != nil {
				t.Fatal(err)
			}
		}
		err := cmp.CheckRebuilt(t.Context(), plan, !c.before)
		if (err == nil) != (c.refused == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
		for _, w := range c.refused {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %v, want %q", c.name, err, w)
			}
		}
		// Before the reverse records a start of the rebuilt release, the
		// same refusal keeps varlatchd stopped: the database services only.
		var nr *notRebuiltError
		if err != nil && strings.Contains(err.Error(), "to run it on them again") {
			if !errors.As(err, &nr) {
				t.Errorf("%s: %T is no notRebuiltError", c.name, err)
			} else if kept := nr.daemonKept().Error(); !strings.Contains(kept, " stop varlatchd; 3. docker ") || !strings.Contains(kept, " up -d --no-deps postgres convex-backend (") ||
				strings.Contains(kept, "convex-backend varlatchd") || !strings.Contains(kept, "Do not start varlatchd: varlatch migrate --resume starts it") {
				t.Errorf("%s, varlatchd kept stopped: %s", c.name, kept)
			}
		}
		if len(run.ran) > 0 && !slices.Equal(run.ran, []string{"docker compose config --no-interpolate --format json"}) {
			t.Errorf("%s: ran %v", c.name, run.ran)
		}
	}
}

// reverseFake are the reverse's halves of the fakes, as far as the import.
type reverseFake struct {
	*fakeSource
	checkErr, importErr error
	makeErr, imagesErr  error
	// gateErr answers the n-th check of the gate; gates are the ones asked
	// for; starts are the services ServeGated says it starts.
	gateErr func(n int) error
	gates   []GateRef
	starts  []string
	// remade is the gate an undo finds; undoErr, stopErr, holdErr, heldErr
	// (by its call) and frontErrs (in order) are the undo's failures.
	remade, position          string
	undoErr, stopErr, holdErr error
	heldErr                   func(n int) error
	remadeIn                  *VolumeRecord
	helds                     int
	frontErrs                 []error
	servingErr                error
	startServingErr           error
	startServing              func() error
	started                   bool
	planErr                   error
	// check, when set, answers instead of checkErr.
	check func() error
	did   []string
}

// apart is what was done, the undo's holding of the gate and its stops of the
// dashboard aside (TestTheUndosOrder's).
func apart(did []string) []string {
	return slices.DeleteFunc(slices.Clone(did), func(d string) bool {
		return strings.HasPrefix(d, "hold ") || strings.HasPrefix(d, "held ") || d == "stop front"
	})
}

func (r *reverseFake) do(what string) { r.did = append(r.did, what) }

func (r *reverseFake) RebuildPlan(context.Context, *Journal) (RebuildRecord, error) {
	if r.planErr != nil {
		return RebuildRecord{}, r.planErr
	}
	return RebuildRecord{Override: OverrideFile, Volumes: []string{"p_postgres-data-abcdefgh", "p_convex-data-abcdefgh"}}, nil
}
func (r *reverseFake) MakeVolumes(_ context.Context, p RebuildRecord) ([]VolumeRecord, error) {
	r.do("make")
	if r.makeErr != nil {
		return nil, r.makeErr
	}
	return []VolumeRecord{{Name: p.Volumes[0], Owner: p.Owner}, {Name: p.Volumes[1], Owner: p.Owner}}, nil
}
func (r *reverseFake) Rebuild(context.Context, RebuildRecord) error { r.do("rebuild"); return nil }
func (r *reverseFake) CheckRebuilt(_ context.Context, p RebuildRecord, convex bool) error {
	what := "check " + p.Volumes[0]
	if convex {
		what += " and Convex"
	}
	r.do(what)
	if r.check != nil {
		return r.check()
	}
	return r.checkErr
}
func (r *reverseFake) ImportReverse(context.Context, string) (TSImportRecord, error) {
	r.do("import")
	return TSImportRecord{}, r.importErr
}
func (r *reverseFake) ResetConvex(context.Context) error { r.do("convex"); return nil }
func (r *reverseFake) ExportForCheck(context.Context, []byte) (string, error) {
	return "", errors.New("not reached")
}
func (r *reverseFake) StartServing(context.Context, Ingress) error {
	r.do("serve")
	if r.startServing != nil {
		return r.startServing()
	}
	return r.startServingErr
}
func (r *reverseFake) StopServing(context.Context, Ingress) error {
	r.do("stop serving")
	return r.servingErr
}
func (r *reverseFake) UndoRebuild(_ context.Context, p RebuildRecord, g GateRef, start bool) error {
	r.do("undo " + p.Volumes[0])
	r.gates = append(r.gates, g)
	r.started = start
	return r.undoErr
}
func (r *reverseFake) HoldGate(_ context.Context, g GateRef, position string) (GateRef, error) {
	r.do("hold " + g.ID)
	r.position = position
	if r.holdErr != nil {
		return g, r.holdErr
	}
	if r.remade != "" {
		g.ID = r.remade
	}
	if r.remadeIn != nil {
		g.State = r.remadeIn
	}
	return g, nil
}
func (r *reverseFake) CheckHeld(_ context.Context, g GateRef) error {
	r.do("held " + g.ID)
	r.helds++
	if r.heldErr != nil {
		return r.heldErr(r.helds)
	}
	return nil
}
func (r *reverseFake) StopFront(_ context.Context, kind Ingress) error {
	r.do("stop front")
	r.ingressDown = true
	if len(r.frontErrs) > 0 {
		err := r.frontErrs[0]
		r.frontErrs = r.frontErrs[1:]
		return err
	}
	return nil
}
func (r *reverseFake) CheckGate(_ context.Context, g GateRef) error {
	r.gates = append(r.gates, g)
	if r.gateErr != nil {
		return r.gateErr(len(r.gates))
	}
	return nil
}
func (r *reverseFake) ServeGated(_ context.Context, s GatedStart) error {
	r.do(fmt.Sprintf("serve gated, the sidecar %v", s.Owned))
	r.gates = append(r.gates, s.Gate)
	for _, svc := range r.starts {
		if err := s.Starting(svc); err != nil {
			return err
		}
	}
	return nil
}
func (r *reverseFake) StopServers(context.Context) error {
	r.do("stop servers")
	return r.stopErr
}
func (r *reverseFake) StopStarted(_ context.Context, services []string) error {
	r.do("stop started " + strings.Join(services, " "))
	return nil
}
func (r *reverseFake) EnsureImages(context.Context, *Journal) error {
	if r.imagesErr != nil {
		r.do("images")
	}
	return r.imagesErr
}
func (r *reverseFake) ReverseReady(context.Context) error      { return nil }
func (r *reverseFake) StartNetworkOwner(context.Context) error { return nil }

type reverseTargetFake struct {
	*fakeTarget
	released    int
	onRelease   func()
	failRelease error
}

func (r *reverseTargetFake) Barrier(context.Context, string, time.Duration) (BarrierRecord, error) {
	return BarrierRecord{GateID: "g", AuditPosition: "1"}, nil
}

// WriteJournal: a reverse's is written beside the running varlatchd.
func (r *reverseTargetFake) WriteJournal(_ context.Context, j *Journal) error {
	r.journal = &JournalHead{ID: j.ID, Phase: j.Phase}
	return nil
}
func (r *reverseTargetFake) ReleaseBarrier(context.Context, string) error {
	if r.onRelease != nil {
		r.onRelease()
	}
	if r.failRelease != nil {
		return r.failRelease
	}
	r.released++
	r.barrier = ""
	return nil
}
func (r *reverseTargetFake) ExportReverse(context.Context, string, string) (CopyRecord, error) {
	return CopyRecord{InstallationID: "inst_x"}, nil
}
func (r *reverseTargetFake) CheckReverse(context.Context, string, string, []byte) (CheckSummary, error) {
	return CheckSummary{}, errors.New("not reached")
}
func (r *reverseTargetFake) Archives(context.Context) ([]ArchiveInfo, error) { return nil, nil }

// The check comes after the rebuild and before the import, on the
// journalled volume; its refusal imports nothing and undoes the reverse
// (Go open again, its barrier lifted), and --rollback may start again.
func TestARebuildOnAnotherVolumeIsUndoneBeforeTheImport(t *testing.T) {
	wrong := errors.New("postgres runs on p_postgres-data, not on the fresh volume p_postgres-data-abcdefgh the journal names; nothing was imported")
	for _, c := range []struct {
		name  string
		check error
		want  []string
	}{
		{"refused", wrong, []string{"make", "rebuild", "check p_postgres-data-abcdefgh", "undo p_postgres-data-abcdefgh"}},
		{"right", nil, []string{"make", "rebuild", "check p_postgres-data-abcdefgh", "import", "undo p_postgres-data-abcdefgh"}},
	} {
		w := newWorld(t)
		j := &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: Open, Source: w.src.info, Ingress: Public, Transfer: &TransferRecord{},
			History: []Step{{Phase: Switched, At: w.eng.now().Format(time.RFC3339Nano)}}}
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		w.tgt.journal, w.tgt.database, w.tgt.running = &JournalHead{ID: j.ID, Phase: Open}, true, true
		src, tgt := &reverseFake{fakeSource: w.src, checkErr: c.check, importErr: errors.New("the import, reached")}, &reverseTargetFake{fakeTarget: w.tgt}
		w.eng.Source, w.eng.Target = src, tgt
		_, err := w.eng.Rollback(context.Background())
		if !slices.Equal(apart(src.did), c.want) {
			t.Errorf("%s: %v, want %v (%v)", c.name, src.did, c.want, err)
		}
		if c.check != nil && (!errors.Is(err, wrong) || tgt.released != 1) {
			t.Errorf("%s: %v, barrier lifted %d times", c.name, err, tgt.released)
		}
		after, rerr := readJournal(w.src.dir)
		if rerr != nil || after.Phase != Open || after.Rollback == nil || after.Rollback.Undone == nil || !after.Rollback.Undone.Released ||
			after.Rollback.Rebuild == nil || after.Rollback.Rebuild.Volumes[0] != "p_postgres-data-abcdefgh" || after.Rollback.Import != nil {
			t.Errorf("%s: the journal after: %+v %v", c.name, after, rerr)
		}
		// It may start again.
		src.did = nil
		if _, err := w.eng.Rollback(context.Background()); len(src.did) == 0 {
			t.Errorf("%s: a second --rollback did nothing: %v", c.name, err)
		}
	}
}
