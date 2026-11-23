// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The reverse's TypeScript side, through Compose (go-step7 decision 16,
// slice 7.6a): the last TypeScript release started on a fresh database
// rebuilt from Go's reverse bundle.
//
//   - The fresh database is a new Postgres data volume, and a new Convex
//     one, never the retained pre-migration volumes, which stay as they are
//     until migrate --finish. A Compose file of migrate's
//     (OverrideFile) renames the installation's postgres-data and
//     convex-data volumes to fresh names, and .env's COMPOSE_FILE names it
//     after the installation's own files, so every later `docker compose`
//     of the installation uses them.
//   - The same file defines the import's one-off service: the release's
//     image (pinned by its digest), the migrate job's database role (which
//     owns the schema) and the Root KEK, both as the installation's
//     secrets and .env's variables, interpolated by Compose; no password or
//     key is ever in an argument here. It runs only when asked (a profile).
//   - `admin migration import` (7.2c) builds the schema and loads the
//     bundle, then lifts the migrated-out gate. Convex is reset: its fresh
//     volume and database, the release's functions deployed again; the
//     mirror publisher publishes every read model when varlatchd starts.
//   - The export the reverse checks read is the release's own `admin
//     migration export --dry-run --digests` of the rebuilt database, in a
//     one-off container of the varlatchd service (the daemon is not
//     started: nothing serves before the checks pass).
//
// An undo puts the installation back as the forward migration left it:
// COMPOSE_FILE as it was, migrate's file removed, the old volumes in use
// again, the fresh ones removed by their exact names, the migrated-out
// gate made again.

// OverrideFile is migrate's Compose file in the installation's directory.
const OverrideFile = "docker-compose.varlatch-rollback.yml"

// reverseProfile is the import service's profile.
const reverseProfile = "varlatch-rollback"

// ReverseSource is the TypeScript installation a reverse migration rebuilds.
type ReverseSource interface {
	// RebuildPlan names what the rebuild makes, before anything is made.
	RebuildPlan(ctx context.Context, j *Journal) (RebuildRecord, error)
	// Rebuild stops what holds the database, writes the plan's Compose
	// file and names it in COMPOSE_FILE, and starts Postgres on its fresh
	// volume.
	Rebuild(ctx context.Context, plan RebuildRecord) error
	// CheckRebuilt refuses an installation whose Compose files or running
	// Postgres (and, with convex, Convex) are not on the plan's fresh
	// volumes: before anything is imported into it, before the address
	// moves to it, before Go stops and before it is recorded rolled back,
	// each time a run or a --resume comes there.
	CheckRebuilt(ctx context.Context, plan RebuildRecord, convex bool) error
	// ImportReverse runs `admin migration import` of the bundle.
	ImportReverse(ctx context.Context, bundle string) (TSImportRecord, error)
	// ResetConvex starts Convex on its fresh volume and deploys its
	// functions.
	ResetConvex(ctx context.Context) error
	// ExportForCheck is the release's export of the rebuilt database, its
	// digests under runKey: the path of the bundle on this host.
	ExportForCheck(ctx context.Context, runKey []byte) (string, error)
	// StartServing starts varlatchd and what serves the address (the
	// shape's ingress); StopServing stops them.
	StartServing(ctx context.Context, kind Ingress) error
	StopServing(ctx context.Context, kind Ingress) error
	// UndoRebuild puts the installation back as the forward migration
	// left it.
	UndoRebuild(ctx context.Context, plan RebuildRecord) error
	// ReverseReady refuses, with the step to take, a reverse whose
	// one-off commands could not start (varlatchd in a stopped sidecar's
	// network), before anything of it is done.
	ReverseReady(ctx context.Context) error
	// StartNetworkOwner starts the service varlatchd shares its network
	// with (network_mode: service:<it>) when it is not running; nothing
	// otherwise. Only for a sidecar migrate itself stopped (sidecarOwned).
	StartNetworkOwner(ctx context.Context) error
}

// projectName is the installation's Compose project (compose_project.go),
// as `docker compose config` answers for it. Uninterpolated:
// the configuration interpolated would carry the installation's secrets
// from .env, and only its name is read. Every volume name the reverse and
// --finish derive starts with it.
func (c *Compose) projectName(ctx context.Context) (string, error) {
	cfg, err := c.config(ctx)
	return cfg.Name, err
}

// composeConfig is what migrate reads of `docker compose config`.
type composeConfig struct {
	Name     string `json:"name"`
	Services map[string]struct {
		NetworkMode string          `json:"network_mode"`
		Environment composeEnv      `json:"environment"`
		Volumes     []composeVolume `json:"volumes"`
		Networks    composeNetworks `json:"networks"`
	} `json:"services"`
	Volumes map[string]struct {
		Name string `json:"name"`
	} `json:"volumes"`
}

// Where the Postgres and Convex services mount their data.
const (
	postgresTarget = "/var/lib/postgresql/data"
	convexTarget   = "/convex/data"
)

// composeVolume is a service's volume: its long form, or the short one
// (source:target[:mode]).
type composeVolume struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Target string `json:"target"`
}

func (v *composeVolume) UnmarshalJSON(b []byte) error {
	var short string
	if json.Unmarshal(b, &short) == nil {
		f := strings.Split(short, ":")
		if len(f) < 2 {
			*v = composeVolume{Type: "volume", Target: short}
			return nil
		}
		*v = composeVolume{Type: "volume", Source: f[0], Target: f[1]}
		if strings.ContainsAny(f[0], "/.~$") {
			v.Type = "bind"
		}
		return nil
	}
	type long composeVolume
	return json.Unmarshal(b, (*long)(v))
}

// composeNetworks is a service's networks: a map's keys, or a list.
type composeNetworks []string

func (n *composeNetworks) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) == nil {
		*n = slices.Sorted(maps.Keys(m))
		return nil
	}
	return json.Unmarshal(b, (*[]string)(n))
}

// The stock Compose files' volumes, by their names there.
const (
	postgresKey = "postgres-data"
	convexKey   = "convex-data"
	stateKey    = "varlatch-state"
)

// volumeKeys are the names the installation's Compose files give its
// Postgres, Convex and state volumes, by where its services mount them: an
// orchestrator's rendered file can rename them (Coolify prefixes the
// application's id), and a file that names others would leave the retained
// ones in use.
func (m composeConfig) volumeKeys() ([]string, error) {
	var out []string
	for _, w := range []struct{ service, target string }{{"postgres", postgresTarget}, {"convex-backend", convexTarget}, {service, "/var/lib/varlatch"}} {
		key := ""
		for _, v := range m.Services[w.service].Volumes {
			if v.Type == "volume" && v.Target == w.target {
				key = v.Source
			}
		}
		if key == "" {
			return nil, fmt.Errorf("the installation's %s service mounts no named volume at %s: its data volume is not known", w.service, w.target)
		}
		out = append(out, key)
	}
	return out, nil
}

// composeEnv is a service's environment as `docker compose config --format
// json` prints it: a map ({"A": "1", "B": null}), or, when the Compose file
// writes it as a list (- A=1) or an overlay merges one in, a list
// (["A=1", "B"]), as Compose 5.6 does. A name without a value (null, or a
// list entry without =) is taken from the shell when Compose runs, so it
// is nil here: not set. A map's unquoted number or boolean (PORT: 8080,
// TS_USERSPACE: false) is a JSON number or boolean there: its text is the
// value, as the container gets it.
type composeEnv map[string]*string

func (e *composeEnv) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*e = nil
		return nil
	}
	if len(b) > 0 && b[0] == '[' {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			return err
		}
		m := composeEnv{}
		for _, kv := range list {
			name, v, ok := strings.Cut(kv, "=")
			if !ok {
				m[name] = nil
				continue
			}
			m[name] = &v
		}
		*e = m
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	m := composeEnv{}
	for name, v := range raw {
		v = bytes.TrimSpace(v)
		switch {
		case bytes.Equal(v, []byte("null")):
			m[name] = nil
		case len(v) > 0 && v[0] == '"':
			var str string
			if err := json.Unmarshal(v, &str); err != nil {
				return err
			}
			m[name] = &str
		case bytes.Equal(v, []byte("true")), bytes.Equal(v, []byte("false")), len(v) > 0 && (v[0] == '-' || v[0] >= '0' && v[0] <= '9'):
			str := string(v)
			m[name] = &str
		default:
			return fmt.Errorf("the environment's %s is neither a value nor null", name)
		}
	}
	*e = m
	return nil
}

func (c *Compose) config(ctx context.Context) (composeConfig, error) {
	r, err := c.docker(ctx, []string{"compose", "config", "--no-interpolate", "--format", "json"}, nil)
	if err != nil {
		return composeConfig{}, err
	}
	return parseConfig(r)
}

func parseConfig(r Ran) (composeConfig, error) {
	if r.Code != 0 {
		return composeConfig{}, errors.New("docker compose config failed: the installation's Compose project could not be read")
	}
	var m composeConfig
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &m); err != nil {
		return composeConfig{}, fmt.Errorf("docker compose config answered with a configuration migrate cannot read: %v", err)
	}
	if m.Name == "" || strings.ContainsAny(m.Name, "/ \t\n") {
		return composeConfig{}, errors.New("docker compose config did not name the installation's Compose project")
	}
	return m, nil
}

// RebuildPlan: the fresh volumes, named by the project and the migration
// (its id's last 8 letters), and COMPOSE_FILE as it is now.
func (c *Compose) RebuildPlan(ctx context.Context, j *Journal) (RebuildRecord, error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return RebuildRecord{}, err
	}
	project := cfg.Name
	keys, err := cfg.volumeKeys()
	if err != nil {
		return RebuildRecord{}, err
	}
	if j.Source.Digest == "" || j.Source.DigestRepository == "" {
		return RebuildRecord{}, errors.New("the journal records no image digest of the source: the rebuild runs the release's own image only")
	}
	short := j.ID[len(j.ID)-8:]
	plan := RebuildRecord{Override: OverrideFile, Image: j.Source.DigestRepository + "@" + j.Source.Digest,
		Volumes: []string{project + "_postgres-data-" + short, project + "_convex-data-" + short}}
	if !slices.Equal(keys, stockKeys) {
		plan.Keys = keys
	}
	// The import reaches Postgres as the installation's own migrate job
	// does.
	if nets := cfg.Services["varlatch-migrate"].Networks; len(nets) > 0 && !slices.Equal(nets, []string{"default"}) {
		plan.Networks = nets
	}
	cf, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		return plan, err
	}
	if ok {
		plan.ComposeFile = &cf
		if plan.ComposeFileLine, err = c.envRaw("COMPOSE_FILE"); err != nil {
			return plan, err
		}
	}
	if isFile(filepath.Join(c.Directory, plan.Override)) {
		// A second reverse's: the first's file is in use now.
		plan.OverrideWas = plan.Override + ".before-" + short
	}
	plan.Retained, err = c.retained(ctx, cfg, keys)
	return plan, err
}

// retained are the volumes the Postgres and Convex services are on now,
// one for each: what their containers mount (which the Compose files must
// give them too), else what the Compose files give them. One that is not
// there, or that does not carry the project's label, is no obstacle to the
// reverse: --finish then refuses to remove it.
func (c *Compose) retained(ctx context.Context, cfg composeConfig, keys []string) ([]VolumeRecord, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return nil, err
	}
	var out []VolumeRecord
	for i, d := range dataMounts {
		name := cfg.volumeName(keys[i])
		for _, l := range all {
			if l.project != p.Name || l.service != d.service || l.isOneOff() {
				continue
			}
			if on := l.volumeAt(d.target); on != name {
				return nil, fmt.Errorf("the installation's %s container is on %s, and its Compose files give it %s: which volume is the installation's is not known", d.service, orWord(on, "no named volume"), name)
			}
		}
		v, err := c.volume(ctx, name)
		if err != nil {
			return nil, err
		}
		if v == nil {
			v = &VolumeRecord{Name: name}
		}
		out = append(out, *v)
	}
	return out, nil
}

// volumeFormat is what migrate reads of a volume.
const volumeFormat = `{{json .Name}} {{json .CreatedAt}} {{json (index .Labels "` + labelProject + `")}}`

// volume is a volume's identity (nil when it is not there).
func (c *Compose) volume(ctx context.Context, name string) (*VolumeRecord, error) {
	r, err := c.docker(ctx, []string{"volume", "inspect", "--format", volumeFormat, name}, nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		if bytes.Contains(bytes.ToLower(r.Said), []byte("no such volume")) {
			return nil, nil
		}
		return nil, failure("docker volume inspect "+name, r)
	}
	var v VolumeRecord
	dec := json.NewDecoder(bytes.NewReader(r.Answer))
	for _, f := range []*string{&v.Name, &v.CreatedAt, &v.Project} {
		if err := dec.Decode(f); err != nil {
			return nil, fmt.Errorf("docker volume inspect %s did not give the volume's name, creation and labels", name)
		}
	}
	if v.Name != name {
		return nil, nil
	}
	return &v, nil
}

var stockKeys = []string{postgresKey, convexKey, stateKey}

// override is migrate's Compose file for plan.
func override(plan RebuildRecord) string {
	keys := plan.Keys
	if len(keys) != 3 {
		keys = stockKeys
	}
	networks := ""
	if len(plan.Networks) > 0 {
		networks = "    networks:\n"
		for _, n := range plan.Networks {
			networks += "      - " + n + "\n"
		}
	}
	return `# Written by varlatch migrate --rollback (go-step7 decision 16): this
# installation runs on a fresh database rebuilt from its Go installation.
# The volumes it ran on before the migration are kept, unchanged, until
# varlatch migrate --finish. Keep this file and COMPOSE_FILE as they are.
volumes:
  ` + keys[0] + `:
    name: ` + plan.Volumes[0] + `
  ` + keys[1] + `:
    name: ` + plan.Volumes[1] + `
services:
  varlatch-reverse-import:
    image: ` + plan.Image + `
    profiles: [` + reverseProfile + `]
    restart: "no"
` + networks + `    environment:
      VARLATCH_STATE_DIR: /var/lib/varlatch
      VARLATCH_DATABASE_URL: postgres://varlatchd_migrate:${VARLATCH_MIGRATE_PASSWORD:-}@postgres:5432/varlatch
      VARLATCH_DATABASE_PASSWORD_FILE: /run/secrets/varlatch-migrate-password
      VARLATCH_KEK_FILE: /run/secrets/varlatch-kek
      VARLATCH_PUBLIC_URL: ${VARLATCH_PUBLIC_URL:?set VARLATCH_PUBLIC_URL in .env}
    volumes:
      - ` + keys[2] + `:/var/lib/varlatch
      - ./backups:/backups
    secrets:
      - varlatch-kek
      - varlatch-migrate-password
    depends_on:
      postgres:
        condition: service_healthy
`
}

// composeFiles is COMPOSE_FILE's value naming migrate's file after the
// installation's own: its value now, else the project's files, by their
// names in Directory (docker-compose.yml, and docker-compose.override.yml
// when present, in the stock installation). It is joined with what
// splitFiles splits it with.
func (c *Compose) composeFiles(p *ComposeProject, plan RebuildRecord) (string, error) {
	sep, err := c.separator()
	if err != nil {
		return "", err
	}
	files := ""
	if plan.ComposeFile != nil && *plan.ComposeFile != "" {
		files = *plan.ComposeFile
	} else if files, err = c.fileList(p.Files); err != nil {
		return "", err
	}
	for _, f := range strings.Split(files, sep) {
		if filepath.Base(strings.TrimSpace(f)) == OverrideFile {
			return files, nil
		}
	}
	return files + sep + OverrideFile, nil
}

// writeFileDurably replaces path's content through a temporary name.
func writeFileDurably(path string, b []byte, mode fs.FileMode) error {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(suffix)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func (c *Compose) compose(ctx context.Context, what string, args ...string) error {
	r, err := c.docker(ctx, append([]string{"compose"}, args...), nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure(what, r)
	}
	return nil
}

// Rebuild: varlatchd, Convex and Postgres stopped (the old volumes left as
// they are), migrate's file written and named in COMPOSE_FILE, Postgres
// started on its fresh volume (its init scripts make the roles and
// databases). Each step is done again harmlessly.
func (c *Compose) Rebuild(ctx context.Context, plan RebuildRecord) error {
	p, err := c.project(ctx)
	if err != nil {
		return err
	}
	if err := c.compose(ctx, "docker compose stop", "stop", "varlatchd", "convex-backend", "postgres"); err != nil {
		return err
	}
	path := filepath.Join(c.Directory, plan.Override)
	if plan.OverrideWas != "" && !isFile(filepath.Join(c.Directory, plan.OverrideWas)) {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := writeFileDurably(filepath.Join(c.Directory, plan.OverrideWas), b, 0o600); err != nil {
			return err
		}
	}
	if err := writeFileDurably(path, []byte(override(plan)), 0o600); err != nil {
		return err
	}
	files, err := c.composeFiles(p, plan)
	if err != nil {
		return err
	}
	if err := c.setEnv("COMPOSE_FILE", &files, ""); err != nil {
		return err
	}
	// Before Postgres starts: what Compose would give it and Convex are the
	// fresh volumes.
	if err := c.checkVolumes(ctx, plan); err != nil {
		return fmt.Errorf("%w: it was not started", err)
	}
	return c.compose(ctx, "docker compose up -d postgres", "up", "-d", "postgres")
}

// checkVolumes refuses Compose files that do not give Postgres and Convex
// the plan's fresh volumes.
func (c *Compose) checkVolumes(ctx context.Context, plan RebuildRecord) error {
	cfg, err := c.config(ctx)
	if err != nil {
		return err
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return err
	}
	for i, d := range dataMounts {
		if name := cfg.volumeName(keys[i]); name != plan.Volumes[i] {
			return fmt.Errorf("the Compose files give %s the volume %s, not the fresh %s the journal names", d.service, name, plan.Volumes[i])
		}
	}
	return nil
}

// volumeName is the volume cfg gives key.
func (m composeConfig) volumeName(key string) string {
	if n := m.Volumes[key].Name; n != "" {
		return n
	}
	return m.Name + "_" + key
}

// dataMounts are the services that hold the installation's data, in
// RebuildRecord's order, and where each mounts it.
var dataMounts = []struct{ service, target string }{{"postgres", postgresTarget}, {"convex-backend", convexTarget}}

// CheckRebuilt reads what Compose would do (checkVolumes) and what it did:
// the running Postgres container's mount (and, with convex, Convex's) is
// the fresh volume the journal names, never the retained one. An
// orchestrator that deploys the installation again makes its containers
// from its own file, without migrate's: they then run on the retained
// volumes, and answer as the same installation and release.
func (c *Compose) CheckRebuilt(ctx context.Context, plan RebuildRecord, convex bool) error {
	p, all, err := c.verified(ctx)
	if err != nil {
		return err
	}
	if err := c.checkVolumes(ctx, plan); err != nil {
		return fmt.Errorf("%w; %s", err, c.rebuiltHelp(p, plan))
	}
	for i, d := range dataMounts {
		if i > 0 && !convex {
			break
		}
		var own []composeContainer
		for _, l := range all {
			if l.project == p.Name && l.service == d.service && !l.isOneOff() {
				own = append(own, l)
			}
		}
		why := ""
		switch {
		case len(own) != 1:
			why = fmt.Sprintf("the installation has %d %s containers, not one: the volume it runs on is not known", len(own), d.service)
		case own[0].status != "running":
			why = fmt.Sprintf("%s does not run on the fresh volume %s (its container is %s)", d.service, plan.Volumes[i], own[0].status)
		case own[0].volumeAt(d.target) != plan.Volumes[i]:
			why = fmt.Sprintf("%s runs on %s, not on the fresh volume %s the journal names", d.service, orWord(own[0].volumeAt(d.target), "no named volume"), plan.Volumes[i])
		}
		if why != "" {
			return errors.New(why + "; " + c.rebuiltHelp(p, plan))
		}
	}
	return nil
}

// rebuiltHelp is how the installation runs on the fresh volumes again.
func (c *Compose) rebuiltHelp(p *ComposeProject, plan RebuildRecord) string {
	path := filepath.Join(c.Directory, plan.Override)
	if !isFile(path) {
		return path + " (the Compose file that names them) is gone: put it back from a copy of that directory"
	}
	value, err := c.composeFiles(p, plan)
	if err != nil {
		return err.Error()
	}
	files := append(slices.Clone(p.Files), path)
	return fmt.Sprintf("to run it on them again: 1. set COMPOSE_FILE=%s in %s; 2. in %s: docker %s up -d --no-deps postgres convex-backend %s (it makes those that are on another volume again; no volume is removed)",
		value, c.envPath(), c.Directory, strings.Join(c.globalArgs(p, files), " "), service)
}

// importAnswerLimit bounds what the import's standard output keeps: its
// one JSON line.
const importAnswerLimit = 1 << 20

// ImportReverse runs the import's one-off service with the reverse bundle
// on its standard input (--in -): no copy of it in the installation's
// backups directory, which the container's user cannot read. The import's
// refusals (varlatchd running, a gate) come before it reads its input: its
// exit status and standard error say why.
func (c *Compose) ImportReverse(ctx context.Context, bundle string) (TSImportRecord, error) {
	in, err := os.Open(bundle)
	if err != nil {
		return TSImportRecord{}, err
	}
	defer in.Close()
	answer := &tail{n: importAnswerLimit}
	// The service's image runs its entrypoint (node dist/cli.js): run's
	// command is the CLI's arguments only.
	r, err := c.stream(ctx, []string{"compose", "--profile", reverseProfile, "run", "--rm", "-T", "varlatch-reverse-import",
		"admin", "migration", "import", "--in", "-"}, in, answer)
	if err != nil {
		return TSImportRecord{}, err
	}
	if r.Code != 0 {
		return TSImportRecord{}, failure("the TypeScript release's admin migration import", r)
	}
	var rec TSImportRecord
	if err := json.Unmarshal(lastLine(answer.bytes()), &rec); err != nil || rec.InstallationID == "" || rec.AuditPosition == "" {
		return TSImportRecord{}, errors.New("the TypeScript release's admin migration import did not answer with the installation and its audit position")
	}
	return rec, nil
}

// ResetConvex: Convex on its fresh volume and database, its functions
// deployed (the installation's convex-deploy service).
func (c *Compose) ResetConvex(ctx context.Context) error {
	if err := c.compose(ctx, "docker compose up -d convex-backend", "up", "-d", "convex-backend"); err != nil {
		return err
	}
	return c.compose(ctx, "docker compose run convex-deploy", "--profile", "deploy", "run", "--rm", "-T", "convex-deploy")
}

// oneOff is the TypeScript CLI in a one-off container of the varlatchd
// service, its daemon not started. Unlike exec, run keeps the image's
// entrypoint (node dist/cli.js), so its command is the CLI's arguments
// only (rehearsal r16d: "Unknown command: node").
func oneOff(args ...string) []string {
	return append([]string{"compose", "run", "--rm", "-T", "--no-deps", service, "admin"}, args...)
}

// ExportForCheck is `admin migration export --dry-run --digests` of the
// rebuilt database, in a one-off container.
func (c *Compose) ExportForCheck(ctx context.Context, runKey []byte) (string, error) {
	return c.export(ctx, runKey, true, oneOff)
}

// StartServing: varlatchd up, then the shape's ingress (Caddy, or the
// dashboard an own proxy targets); Coolify's proxy routes by itself.
func (c *Compose) StartServing(ctx context.Context, kind Ingress) error {
	if err := c.compose(ctx, "docker compose up -d varlatchd", "up", "-d", service); err != nil {
		return err
	}
	if kind == Coolify {
		return nil
	}
	return c.StartIngress(ctx, kind, false)
}

// StopServing: the shape's ingress, then varlatchd.
func (c *Compose) StopServing(ctx context.Context, kind Ingress) error {
	if kind != Coolify {
		if err := c.StopIngress(ctx, kind); err != nil {
			return err
		}
	}
	return c.compose(ctx, "docker compose stop varlatchd", "stop", service)
}

// UndoRebuild: what holds the database stopped; COMPOSE_FILE as it was and
// migrate's file removed, so Compose names the old volumes again; Postgres
// and Convex back on them (their containers made again, which frees the
// fresh volumes), the fresh volumes removed by their names; the
// migrated-out gate made again if the import lifted it; varlatchd started
// behind it, as the forward migration left it.
func (c *Compose) UndoRebuild(ctx context.Context, plan RebuildRecord) error {
	if err := c.compose(ctx, "docker compose stop", "stop", service, "convex-backend", "postgres"); err != nil {
		return err
	}
	if err := c.setEnv("COMPOSE_FILE", plan.ComposeFile, plan.ComposeFileLine); err != nil {
		return err
	}
	if path := filepath.Join(c.Directory, plan.Override); plan.OverrideWas != "" {
		// Not kept yet: the rebuild did not write over it.
		if was := filepath.Join(c.Directory, plan.OverrideWas); isFile(was) {
			if err := os.Rename(was, path); err != nil {
				return err
			}
		}
	} else if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := c.compose(ctx, "docker compose up -d postgres convex-backend", "up", "-d", "postgres", "convex-backend"); err != nil {
		return err
	}
	for _, v := range plan.Volumes {
		// Asked directly before its removal: no container, running or
		// stopped, still uses the fresh volume (the services are back on
		// their own ones).
		users, err := c.volumeUsers(ctx, v)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return fmt.Errorf("the reverse's fresh volume %s is still used by %s: left as it is", v, strings.Join(users, ", "))
		}
		r, err := c.docker(ctx, []string{"volume", "rm", "-f", v}, nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("docker volume rm "+v, r)
		}
	}
	// The one-off commands below and varlatchd itself run in varlatchd's
	// network, without their dependencies.
	if err := c.networkOwnerRunning(ctx, "varlatch migrate --resume"); err != nil {
		return err
	}
	g, err := c.gateOffline(ctx)
	if err != nil {
		return err
	}
	if g == nil || g.Kind != "migrated-out" {
		if g != nil && g.Kind != "migration" {
			return fmt.Errorf("the TypeScript installation is behind a %s gate (%s), not the migration's: left as it is", g.Kind, g.ID)
		}
		if g == nil {
			r, err := c.docker(ctx, oneOff("migration", "barrier", "--drain-seconds", "1"), nil)
			if err != nil {
				return err
			}
			if r.Code != 0 {
				return failure("the TypeScript release's migration barrier", r)
			}
			var b struct {
				Gate Gate `json:"gate"`
			}
			if err := json.Unmarshal(lastLine(r.Answer), &b); err != nil || b.Gate.ID == "" {
				return errors.New("the TypeScript release's migration barrier did not answer with its gate")
			}
			g = &b.Gate
		}
		r, err := c.docker(ctx, oneOff("migration", "mark-migrated-out", "--id", g.ID), nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("the TypeScript release's migration mark-migrated-out", r)
		}
	}
	// --no-deps: varlatchd's one-off dependency (varlatch-migrate,
	// service_completed_successfully) would run again with it and refuse
	// behind the migrated-out marker, so varlatchd would not start. Its
	// own volume's schema is current already, Postgres was started above,
	// and varlatchd restarts (unless-stopped) until Postgres answers.
	return c.compose(ctx, "docker compose up -d --no-deps varlatchd", "up", "-d", "--no-deps", service)
}

// networkOwnerRunning refuses, with the step to take, when varlatchd runs
// in another service's network (network_mode: service:tailscale) and that
// service is not running: without their dependencies, neither varlatchd
// nor a one-off container of its starts there. That service is not started
// here: it is the old Tailscale node, which must not come back beside Go's
// unasked (as ServeForArchive refuses to).
func (c *Compose) networkOwnerRunning(ctx context.Context, then string) error {
	cfg, err := c.config(ctx)
	if err != nil {
		return err
	}
	owner, ok := strings.CutPrefix(cfg.Services[service].NetworkMode, "service:")
	if !ok {
		return nil
	}
	running, err := c.running(ctx)
	if err != nil {
		return err
	}
	if slices.Contains(running, owner) {
		return nil
	}
	return fmt.Errorf("the TypeScript installation's varlatchd runs in %s's network (network_mode: service:%s), which is not running, so neither it nor its one-off commands can start: "+
		"start it by hand (%s, in %s; it brings the old Tailscale node back), then %s", owner, owner, c.byHand("up -d --no-deps "+owner), c.Directory, then)
}

// ReverseReady: the reverse's one-off commands (the rebuilt database's
// export for the checks among them) run in varlatchd's network, so a
// stopped sidecar it shares refuses the reverse before Go's barrier, not
// after the rebuild.
func (c *Compose) ReverseReady(ctx context.Context) error {
	return c.networkOwnerRunning(ctx, "varlatch migrate --rollback again")
}

// StartNetworkOwner: `docker compose start <owner>` when varlatchd runs in
// another service's network and that service is not running. The reverse
// of a migration whose tailnet handoff stopped the sidecar at the switch
// starts it so (the old node, under its temporary name: the name stays
// with Go's node until the reverse's own handoff), as StartTailnet does,
// without restarting varlatchd.
func (c *Compose) StartNetworkOwner(ctx context.Context) error {
	cfg, err := c.config(ctx)
	if err != nil {
		return err
	}
	owner, ok := strings.CutPrefix(cfg.Services[service].NetworkMode, "service:")
	if !ok {
		return nil
	}
	running, err := c.running(ctx)
	if err != nil {
		return err
	}
	if slices.Contains(running, owner) {
		return nil
	}
	return c.compose(ctx, "docker compose start "+owner, "start", owner)
}

// gateOffline is the installation's gate, read in a one-off container.
func (c *Compose) gateOffline(ctx context.Context) (*Gate, error) {
	r, err := c.docker(ctx, oneOff("migration", "status"), nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("the TypeScript release's admin migration status", r)
	}
	var s struct {
		Gate *Gate `json:"gate"`
	}
	if err := json.Unmarshal(lastLine(r.Answer), &s); err != nil {
		return nil, errors.New("the TypeScript release's admin migration status did not answer in JSON")
	}
	return s.Gate, nil
}
