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
	"net/url"
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
	// MakeVolumes makes the plan's fresh volumes (journalled, once made, as
	// plan's Made).
	MakeVolumes(ctx context.Context, plan RebuildRecord) ([]VolumeRecord, error)
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
	// HoldGate has the source behind g before anything of it is started: an
	// undo's first step. CheckHeld holds that whoever starts its server, it
	// is behind g. StopFront stops what serves its address.
	HoldGate(ctx context.Context, g GateRef, position string) (GateRef, error)
	CheckHeld(ctx context.Context, g GateRef) error
	StopFront(ctx context.Context, kind Ingress) error
	// UndoRebuild puts the installation back as the forward migration left
	// it, its server started (start) behind gate.
	UndoRebuild(ctx context.Context, plan RebuildRecord, gate GateRef, start bool) error
	// ReverseReady refuses, with the step to take, a reverse whose
	// one-off commands could not start (varlatchd in a stopped sidecar's
	// network), before anything of it is done.
	ReverseReady(ctx context.Context) error
	// CheckGate refuses a source that is not behind exactly the gate g, as
	// its state volume carries it: nothing of it is started to read that.
	CheckGate(ctx context.Context, g GateRef) error
	// ServeGated starts what answers for the source behind its migrated-out
	// gate (CheckGate, before anything and again before varlatchd): the
	// service varlatchd shares its network with when owned, Postgres and
	// varlatchd, without their dependencies.
	ServeGated(ctx context.Context, s GatedStart) error
	// StopStarted stops the services named.
	StopStarted(ctx context.Context, services []string) error
	// StopServers has the source's server, and what else could write as it,
	// stopped.
	StopServers(ctx context.Context) error
	// EnsureImages has the images the reverse starts on this host, pulling
	// those that are not: before Go's barrier, never in the downtime.
	EnsureImages(ctx context.Context, j *Journal) error
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
		// ContainerName is uninterpolated ("" for Compose's own name).
		ContainerName string          `json:"container_name"`
		NetworkMode   string          `json:"network_mode"`
		Environment   composeEnv      `json:"environment"`
		Volumes       []composeVolume `json:"volumes"`
		Networks      composeNetworks `json:"networks"`
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
	for _, w := range []struct{ service, target string }{{"postgres", postgresTarget}, {"convex-backend", convexTarget}, {service, stateTarget}} {
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
	if err := c.checkVersion(ctx); err != nil {
		return RebuildRecord{}, err
	}
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
	// An undo holds its gate there: the volume is the recorded one.
	if j.Source.State != nil {
		v, _, err := c.stateVolume(ctx)
		if err != nil {
			return RebuildRecord{}, err
		}
		if why := v.differs(*j.Source.State); why != "" {
			return RebuildRecord{}, fmt.Errorf("the volume %s is not the one that carried the gate when the migration began (%s)", v.Name, why)
		}
	} else if _, _, err := c.stateName(ctx, cfg); err != nil {
		return RebuildRecord{}, err
	}
	// Names no volume has: one there already is another's, whatever it is.
	var names []string
	short := j.ID[len(j.ID)-8:]
	for try := 0; ; try++ {
		names = []string{project + "_postgres-data-" + short, project + "_convex-data-" + short}
		taken := ""
		for _, n := range names {
			v, err := c.volume(ctx, n)
			if err != nil {
				return RebuildRecord{}, err
			}
			if v != nil {
				taken = n
			}
		}
		if taken == "" {
			break
		}
		if try == 4 {
			return RebuildRecord{}, fmt.Errorf("the volume %s is there already: the reverse makes its fresh volumes, and takes none", taken)
		}
		id, err := newID()
		if err != nil {
			return RebuildRecord{}, err
		}
		short = id[len(id)-8:]
	}
	plan := RebuildRecord{Override: OverrideFile, Image: j.Source.DigestRepository + "@" + j.Source.Digest, Volumes: names, Owner: j.ID}
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
	plan.Retained, err = c.retained(ctx, cfg, keys, j.Source.Volumes)
	return plan, err
}

// retained are the volumes the Postgres and Convex services are on now,
// one for each, as installed gives them: their containers', as the Compose
// files name them, and the ones the migration read (recorded). Without
// containers, the recorded ones. One that is not there, or that does not
// carry the project's label, is no obstacle to the reverse: --finish then
// refuses to remove it.
func (c *Compose) retained(ctx context.Context, cfg composeConfig, keys []string, recorded []VolumeRecord) ([]VolumeRecord, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return nil, err
	}
	var out []VolumeRecord
	for i, d := range dataMounts {
		v, err := c.installed(ctx, p, all, d.service, d.target, cfg.volumeName(keys[i]), i, recorded)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// installed is the volume a data service is on: the one the Compose files
// name, which its container, when it has one, mounts, and which is the very
// volume the migration's journal recorded, when it did. Neither a container
// nor a record: which one it is is not known. One the files name that is
// not there is given by its name only.
func (c *Compose) installed(ctx context.Context, p *ComposeProject, all []composeContainer, svc, target, name string, i int, recorded []VolumeRecord) (VolumeRecord, error) {
	live, err := mountedAs(p, all, svc, target, name)
	if err != nil {
		return VolumeRecord{}, err
	}
	v, err := c.volume(ctx, name)
	if err != nil {
		return VolumeRecord{}, err
	}
	if len(recorded) == len(dataMounts) {
		switch {
		case recorded[i].Name != name:
			return VolumeRecord{}, fmt.Errorf("the Compose files give %s the volume %s, and the migration read the installation on %s: which volume is the installation's is not known", svc, name, recorded[i].Name)
		case v != nil && v.differs(recorded[i]) != "":
			return VolumeRecord{}, fmt.Errorf("the volume %s is not the one the migration read (%s): which volume is the installation's is not known", name, v.differs(recorded[i]))
		}
	} else if !live {
		return VolumeRecord{}, fmt.Errorf("the installation has no %s container, and the journal does not record which volume it ran on (the Compose files name %s): "+
			"make it again (%s), check the installation's data is on it, and run this again", svc, name, c.byHand("up --no-start --no-deps "+svc))
	}
	if v == nil {
		return VolumeRecord{Name: name}, nil
	}
	return *v, nil
}

// mountedAs refuses a service whose containers are not on the volume its
// Compose files give it (name): which one is the installation's is not
// known then. live is whether it has a container at all.
func mountedAs(p *ComposeProject, all []composeContainer, svc, target, name string) (live bool, err error) {
	for _, l := range all {
		if l.project != p.Name || l.service != svc || l.isOneOff() {
			continue
		}
		live = true
		if on := l.volumeAt(target); on != name {
			return live, fmt.Errorf("the installation's %s container is on %s, and its Compose files give it %s: which volume is the installation's is not known", svc, orWord(on, "no named volume"), name)
		}
	}
	return live, nil
}

// The labels on a volume: Compose's, and migrate's on the ones it makes.
const (
	labelVolume = "com.docker.compose.volume"
	labelOwner  = "varlatch.migrate.id"
)

// volumeFormat is what migrate reads of a volume.
const volumeFormat = `{{json .Name}} {{json .CreatedAt}} {{json .Mountpoint}} {{json (index .Labels "` + labelProject + `")}} {{json (index .Labels "` + labelVolume + `")}} {{json (index .Labels "` + labelOwner + `")}}`

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
	for _, f := range []*string{&v.Name, &v.CreatedAt, &v.Mountpoint, &v.Project, &v.Key, &v.Owner} {
		if err := dec.Decode(f); err != nil {
			return nil, fmt.Errorf("docker volume inspect %s did not give the volume's name, creation, place and labels", name)
		}
	}
	if v.Name != name {
		return nil, nil
	}
	return &v, nil
}

// differs says how v is not the recorded volume ("" when it is): by when
// it was made, where it is, and its labels, not by its name alone.
func (v VolumeRecord) differs(want VolumeRecord) string {
	switch {
	case v.Name != want.Name:
		return fmt.Sprintf("it is %s, not %s", v.Name, want.Name)
	case !sameTime(v.CreatedAt, want.CreatedAt):
		return fmt.Sprintf("it was made %s, and the journal's %s", v.CreatedAt, orWord(want.CreatedAt, "was not there"))
	case v.Mountpoint != want.Mountpoint:
		return fmt.Sprintf("it is at %s, and the journal's at %s", v.Mountpoint, want.Mountpoint)
	case v.Project != want.Project || v.Key != want.Key || v.Owner != want.Owner:
		return fmt.Sprintf("its labels (project %s, volume %s, migration %s) are not the journal's (%s, %s, %s)", orWord(v.Project, "none"), orWord(v.Key, "none"), orWord(v.Owner, "none"),
			orWord(want.Project, "none"), orWord(want.Key, "none"), orWord(want.Owner, "none"))
	}
	return ""
}

// ours is whether v is the plan's i-th fresh volume: labelled with the
// migration's id, and, once that is journalled, the very one made.
func (plan RebuildRecord) ours(i int, v VolumeRecord) bool {
	return plan.Owner != "" && v.Owner == plan.Owner && (i >= len(plan.Made) || v.differs(plan.Made[i]) == "")
}

// MakeVolumes makes the plan's fresh volumes, labelled with the migration's
// id, and gives what they are. Docker answers a name that is there with
// the volume there: one without the label is another's, refused.
func (c *Compose) MakeVolumes(ctx context.Context, plan RebuildRecord) ([]VolumeRecord, error) {
	p, _, err := c.verified(ctx)
	if err != nil {
		return nil, err
	}
	if plan.Owner == "" {
		return nil, errors.New("the journal's rebuild names no migration its volumes are of")
	}
	keys := stockKeys
	if len(plan.Keys) == 3 {
		keys = plan.Keys
	}
	var out []VolumeRecord
	for i, name := range plan.Volumes {
		r, err := c.docker(ctx, []string{"volume", "create", "--label", labelProject + "=" + p.Name, "--label", labelVolume + "=" + keys[i], "--label", labelOwner + "=" + plan.Owner, name}, nil)
		if err != nil {
			return nil, err
		}
		if r.Code != 0 {
			return nil, failure("docker volume create "+name, r)
		}
		v, err := c.volume(ctx, name)
		if err != nil {
			return nil, err
		}
		if v == nil || v.Owner != plan.Owner || v.Project != p.Name {
			return nil, fmt.Errorf("the volume %s is there, and is not this migration's (its label %s is not %s): the reverse does not use it", name, labelOwner, plan.Owner)
		}
		users, err := c.volumeUsers(ctx, name)
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			return nil, fmt.Errorf("the fresh volume %s is used by %s already", name, strings.Join(users, ", "))
		}
		out = append(out, *v)
	}
	return out, nil
}

// checkMade refuses fresh volumes that are not the ones MakeVolumes made.
func (c *Compose) checkMade(ctx context.Context, plan RebuildRecord) error {
	if len(plan.Made) != len(plan.Volumes) || plan.Owner == "" {
		return errors.New("the journal does not record the fresh volumes the reverse made")
	}
	for i, name := range plan.Volumes {
		v, err := c.volume(ctx, name)
		if err != nil {
			return err
		}
		if v == nil {
			return fmt.Errorf("the fresh volume %s is not there", name)
		}
		if why := v.differs(plan.Made[i]); why != "" || v.Owner != plan.Owner {
			return fmt.Errorf("the volume %s is not the fresh one the reverse made: %s", name, orWord(why, "another migration's"))
		}
	}
	return nil
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

// routePath is where the proxy's file goes, as Coolify's proxy reads them.
const routePath = "/data/coolify/proxy/dynamic/varlatch-rollback.yaml"

// RouteFile: a Traefik router for the origin's host, above those the
// containers' labels give, to the dashboard's container by its name (which
// it keeps while it is not deployed again), with the certificate the
// proxy's resolver has for the host, and routeHeader on each answer
// (Traefik 3.6 puts it on its own 502 too, the container stopped or gone).
func (c *Compose) RouteFile(ctx context.Context, origin, id string) (string, string, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return "", "", err
	}
	var names []string
	for _, l := range all {
		if l.project == p.Name && l.service == dashboardService && !l.isOneOff() {
			names = append(names, l.name)
		}
	}
	if len(names) == 0 {
		// Its container is gone: the name `up` makes it under.
		cfg, err := c.config(ctx)
		if err != nil {
			return "", "", err
		}
		if svc, ok := cfg.Services[dashboardService]; ok && svc.ContainerName != "" {
			names = []string{svc.ContainerName}
		} else if ok {
			names = []string{p.Name + "-" + dashboardService + "-1"}
		}
	}
	if len(names) != 1 || names[0] == "" {
		return "", "", fmt.Errorf("the installation has %d %s containers, not one: what the address goes back to is not known", len(names), dashboardService)
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return "", "", fmt.Errorf("the journal's address %q has no host", origin)
	}
	entry, tls := "http", ""
	if u.Scheme == "https" {
		entry, tls = "https", "      tls:\n        certResolver: letsencrypt\n"
	}
	return routePath, "http:\n  routers:\n    varlatch-rollback:\n      rule: \"Host(`" + u.Hostname() + "`)\"\n      entryPoints: [" + entry + "]\n      priority: 100000\n      service: varlatch-rollback\n      middlewares: [varlatch-rollback]\n" + tls +
		"  middlewares:\n    varlatch-rollback:\n      headers:\n        customResponseHeaders:\n          " + routeHeader + ": \"" + id + "\"\n" +
		"  services:\n    varlatch-rollback:\n      loadBalancer:\n        servers:\n          - url: \"http://" + names[0] + ":80\"\n", nil
}

// dashboardService is the source's dashboard in its Compose file.
const dashboardService = "varlatch-web"

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
	c.reversed = true
	p, _, err := c.verified(ctx)
	if err != nil {
		return err
	}
	if err := c.checkMade(ctx, plan); err != nil {
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
	c.reversed = true
	p, all, err := c.verified(ctx)
	if err != nil {
		return err
	}
	if err := c.checkMade(ctx, plan); err != nil {
		return err
	}
	if err := c.checkVolumes(ctx, plan); err != nil {
		return c.notRebuilt(err, p, plan)
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
			return c.notRebuilt(errors.New(why), p, plan)
		}
	}
	return nil
}

// notRebuiltError is CheckRebuilt's refusal: why, and how the
// installation runs on the fresh volumes again (help). Its text starts
// varlatchd with the database services; daemonKept is the same refusal
// with varlatchd stopped instead, for a reverse whose journal does not yet
// say it may serve (the engine's checkRebuilt).
type notRebuiltError struct {
	why  error
	help func(daemon bool) string
}

func (e *notRebuiltError) Error() string { return e.why.Error() + "; " + e.help(true) }
func (e *notRebuiltError) Unwrap() error { return e.why }

// daemonKept is the refusal whose help keeps varlatchd stopped.
func (e *notRebuiltError) daemonKept() error {
	return fmt.Errorf("%w; %s", e.why, e.help(false))
}

func (c *Compose) notRebuilt(why error, p *ComposeProject, plan RebuildRecord) error {
	return &notRebuiltError{why: why, help: func(daemon bool) string { return c.rebuiltHelp(p, plan, daemon) }}
}

// rebuiltHelp is how the installation runs on the fresh volumes again:
// with daemon, varlatchd made again with the database services; without,
// varlatchd stopped and left so, for varlatch migrate --resume to start
// once the journal records that it may serve.
func (c *Compose) rebuiltHelp(p *ComposeProject, plan RebuildRecord, daemon bool) string {
	path := filepath.Join(c.Directory, plan.Override)
	if !isFile(path) {
		return path + " (the Compose file that names them) is gone: put it back from a copy of that directory"
	}
	value, err := c.composeFiles(p, plan)
	if err != nil {
		return err.Error()
	}
	files := append(slices.Clone(p.Files), path)
	args := shellArgs(c.globalArgs(p, files))
	if !daemon {
		return fmt.Sprintf("to run it on them again: 1. set COMPOSE_FILE=%s in %s; 2. docker %s stop %s; 3. docker %s up -d --no-deps postgres convex-backend (it makes those that are on another volume again; no volume is removed). Do not start %s: varlatch migrate --resume starts it once the journal records that it may serve",
			value, c.envPath(), args, service, args, service)
	}
	return fmt.Sprintf("to run it on them again: 1. set COMPOSE_FILE=%s in %s; 2. docker %s up -d --no-deps postgres convex-backend %s (it makes those that are on another volume again; no volume is removed)",
		value, c.envPath(), args, service)
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

// StartServing: varlatchd up, the dashboard made again, then Caddy where it
// serves the address. The dashboard's nginx resolves varlatchd once, at its
// start, and the rebuild gave varlatchd's container (or its sidecar's) a
// new address, or may have: always made again, whatever it resolved.
func (c *Compose) StartServing(ctx context.Context, kind Ingress) error {
	if err := c.compose(ctx, "docker compose up -d varlatchd", "up", "-d", service); err != nil {
		return err
	}
	if err := c.compose(ctx, "docker compose up -d --no-deps --force-recreate "+dashboardService, "up", "-d", "--no-deps", "--force-recreate", dashboardService); err != nil {
		return err
	}
	if kind != Public {
		return nil
	}
	return c.StartIngress(ctx, kind, false)
}

// refreshDashboard restarts a running dashboard, so that it resolves
// varlatchd again (StartServing).
func (c *Compose) refreshDashboard(ctx context.Context) error {
	running, err := c.running(ctx)
	if err != nil || !slices.Contains(running, dashboardService) {
		return err
	}
	return c.compose(ctx, "docker compose restart "+dashboardService, "restart", dashboardService)
}

// StopServing: the shape's ingress, then varlatchd.
func (c *Compose) StopServing(ctx context.Context, kind Ingress) error {
	if err := c.StopFront(ctx, kind); err != nil {
		return err
	}
	return c.StopServers(ctx)
}

// StopFront stops the service of the shape's ingress, by its containers: an
// undo's, which may have no Compose files to go by.
func (c *Compose) StopFront(ctx context.Context, kind Ingress) error {
	svc, err := ingressService(kind)
	if err != nil {
		return err
	}
	return c.stopContainers(ctx, svc)
}

// UndoRebuild: what holds the database stopped; COMPOSE_FILE as it was and
// migrate's file removed, so Compose names the old volumes again; Postgres
// and Convex back on them, the fresh volumes removed by their names; with
// start, varlatchd started behind the gate, which is there already
// (HoldGate), as the forward migration left it.
func (c *Compose) UndoRebuild(ctx context.Context, plan RebuildRecord, gate GateRef, start bool) error {
	c.reversed = true
	if err := c.stopContainers(ctx, service, importService, "convex-deploy", "convex-backend", "postgres"); err != nil {
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
	if err := c.restoreVolumes(ctx, plan); err != nil {
		return err
	}
	for i, name := range plan.Volumes {
		// Only a volume this migration made (its label, and, once it is
		// journalled, the very one): whatever else has the name is left.
		v, err := c.volume(ctx, name)
		if err != nil {
			return err
		}
		if v == nil || !plan.ours(i, *v) {
			continue
		}
		// Asked directly before its removal: no container, running or
		// stopped, still uses the fresh volume (the services are back on
		// their own ones).
		users, err := c.volumeUsers(ctx, name)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return fmt.Errorf("the reverse's fresh volume %s is still used by %s: left as it is", name, strings.Join(users, ", "))
		}
		r, err := c.docker(ctx, []string{"volume", "rm", "-f", name}, nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("docker volume rm "+name, r)
		}
	}
	if !start {
		return nil
	}
	// Without its dependencies: varlatchd's one-off dependency
	// (varlatch-migrate, service_completed_successfully) would run again and
	// refuse behind the migrated-out marker, so varlatchd would not start.
	// Its own volume's schema is current already, Postgres was started above,
	// and varlatchd restarts (unless-stopped) until Postgres answers.
	if err := c.networkOwnerRunning(ctx, "varlatch migrate --resume"); err != nil {
		return err
	}
	if err := c.startGated(ctx, gate, true); err != nil {
		return err
	}
	return c.refreshDashboard(ctx)
}

// importService is the import's one-off service (override).
const importService = "varlatch-reverse-import"

// stopContainers stops the containers of the services named, one-offs among
// them (a killed run's go on), each by its id, and holds them to be stopped:
// Compose's own stop refuses a project whose files it cannot take.
func (c *Compose) stopContainers(ctx context.Context, services ...string) error {
	for try := 0; ; try++ {
		p, all, err := c.verified(ctx)
		if err != nil {
			return err
		}
		var ids, names []string
		for _, l := range all {
			if l.project == p.Name && slices.Contains(services, l.service) && l.status != "exited" && l.status != "created" && l.status != "dead" {
				ids, names = append(ids, l.id), append(names, l.name)
			}
		}
		if len(ids) == 0 {
			return nil
		}
		if try == 3 {
			return fmt.Errorf("%s did not stop", strings.Join(names, ", "))
		}
		r, err := c.docker(ctx, append([]string{"stop"}, ids...), nil)
		if err != nil {
			return err
		}
		// One removed since it was listed is not there to stop.
		if r.Code != 0 && !bytes.Contains(bytes.ToLower(r.Said), []byte("no such container")) {
			return failure("docker stop of "+strings.Join(names, ", "), r)
		}
	}
}

// StopServers stops the installation's varlatchd, and what else could write
// as it, however the installation's Compose files are.
func (c *Compose) StopServers(ctx context.Context) error {
	return c.stopContainers(ctx, service, importService)
}

// restoreVolumes has Postgres and Convex on the volumes the Compose files
// give them again, the retained ones: a container on a fresh volume is
// removed, that one, stopped already, and made again. An earlier Docker
// Compose leaves it as it is when only its volume's name changed, so it is
// not left to Compose to see; what they are on then is held.
func (c *Compose) restoreVolumes(ctx context.Context, plan RebuildRecord) error {
	p, all, err := c.verified(ctx)
	if err != nil {
		return err
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return err
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return err
	}
	for i, d := range dataMounts {
		want := cfg.volumeName(keys[i])
		if slices.Contains(plan.Volumes, want) {
			return fmt.Errorf("the Compose files still give %s the reverse's volume %s", d.service, want)
		}
		if len(plan.Retained) == len(dataMounts) && plan.Retained[i].CreatedAt != "" {
			// Compose would make one that is not there, empty.
			v, err := c.volume(ctx, want)
			switch {
			case err != nil:
				return err
			case v == nil:
				return fmt.Errorf("the volume %s, which %s was on before the reverse, is not there", want, d.service)
			case v.differs(plan.Retained[i]) != "":
				return fmt.Errorf("the volume %s is not the one %s was on before the reverse (%s)", want, d.service, v.differs(plan.Retained[i]))
			}
		}
		for _, l := range serviceContainers(p, all, d.service) {
			on := l.volumeAt(d.target)
			if on == want {
				continue
			}
			if !slices.Contains(plan.Volumes, on) {
				return fmt.Errorf("the installation's %s container is on %s, neither the volume from before the reverse (%s) nor the reverse's: left as it is", d.service, orWord(on, "no named volume"), want)
			}
			r, err := c.docker(ctx, []string{"rm", l.id}, nil)
			if err != nil {
				return err
			}
			if r.Code != 0 {
				return failure("docker rm of "+l.name, r)
			}
		}
	}
	if err := c.compose(ctx, "docker compose up -d postgres convex-backend", "up", "-d", "postgres", "convex-backend"); err != nil {
		return err
	}
	if p, all, err = c.verified(ctx); err != nil {
		return err
	}
	for i, d := range dataMounts {
		own := serviceContainers(p, all, d.service)
		if want := cfg.volumeName(keys[i]); len(own) != 1 || own[0].volumeAt(d.target) != want {
			return fmt.Errorf("the installation's %s did not go back to the volume from before the reverse, %s", d.service, want)
		}
	}
	return nil
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

// StartNetworkOwner starts the service varlatchd shares its network with,
// when it is not running (startOwner). The reverse of a migration whose
// tailnet handoff stopped the sidecar at the switch starts it so (the old
// node, under its temporary name: the name stays with Go's node until the
// reverse's own handoff), as StartTailnet does, without restarting
// varlatchd.
func (c *Compose) StartNetworkOwner(ctx context.Context) error {
	_, _, err := c.startNetworkOwner(ctx)
	return err
}

func (c *Compose) startNetworkOwner(ctx context.Context) (started, made bool, err error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return false, false, err
	}
	owner, ok := strings.CutPrefix(cfg.Services[service].NetworkMode, "service:")
	if !ok {
		return false, false, nil
	}
	running, err := c.running(ctx)
	if err != nil {
		return false, false, err
	}
	if slices.Contains(running, owner) {
		return false, false, nil
	}
	made, err = c.startOwner(ctx, owner)
	return true, made, err
}

// ServeGated: Postgres as it is (or made again), the network's owner, then
// varlatchd in its network. Each service that does not run is said to
// s.Starting before it is started: an undo stops those, and no other.
func (c *Compose) ServeGated(ctx context.Context, s GatedStart) error {
	// Before anything starts: without its gate the TypeScript release takes
	// requests, on the database it left.
	if err := c.CheckGate(ctx, s.Gate); err != nil {
		return err
	}
	running, err := c.running(ctx)
	if err != nil {
		return err
	}
	starting := func(svc string) error {
		if slices.Contains(running, svc) || s.Starting == nil {
			return nil
		}
		return s.Starting(svc)
	}
	if !slices.Contains(running, "postgres") {
		if err := starting("postgres"); err != nil {
			return err
		}
		if err := c.compose(ctx, "docker compose up -d --no-deps postgres", "up", "-d", "--no-deps", "--no-recreate", "postgres"); err != nil {
			return err
		}
	}
	started, made := false, false
	if s.Owned {
		if started, made, err = c.startNetworkOwner(ctx); err != nil {
			return err
		}
	}
	// Otherwise its own network, or the operator's sidecar (ReverseReady).
	if !started && slices.Contains(running, service) {
		return nil
	}
	if err := c.CheckGate(ctx, s.Gate); err != nil {
		return err
	}
	if err := starting(service); err != nil {
		return err
	}
	return c.startGated(ctx, s.Gate, !s.Owned || made)
}

// EnsureImages: the images the Compose files give their services, and the
// release's own for the import.
func (c *Compose) EnsureImages(ctx context.Context, j *Journal) error {
	// Every service's, convex-deploy's (a profile's in the stock files) too.
	args := []string{"compose", "--profile", "deploy", "config", "--images"}
	r, err := c.docker(ctx, args, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		// Its output is not said: the files are interpolated with .env.
		return fmt.Errorf("docker compose config --images failed (exit %d): the images the reverse needs are not known", r.Code)
	}
	images := append(strings.Fields(string(r.Answer)), j.Source.DigestRepository+"@"+j.Source.Digest)
	slices.Sort(images)
	for _, img := range slices.Compact(images) {
		if err := c.ensureImage(ctx, img); err != nil {
			return err
		}
	}
	return nil
}

// ensureImage has img on this host, pulling it when it is not.
func (c *Compose) ensureImage(ctx context.Context, img string) error {
	r, err := c.docker(ctx, []string{"image", "inspect", "--format", "{{.Id}}", img}, nil)
	if err != nil || r.Code == 0 {
		return err
	}
	if r, err = c.docker(ctx, []string{"pull", "-q", img}, nil); err != nil {
		return err
	}
	if r.Code != 0 {
		// Said in parts, as pinned does (the fail-safe reads what comes
		// before an "@" as possible credentials).
		repo, digest, _ := strings.Cut(img, "@")
		return fmt.Errorf("the image %s %s is not on this host and could not be pulled (exit %d): pull it, then run this again", repo, digest, r.Code)
	}
	return nil
}
