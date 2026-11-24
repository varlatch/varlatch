// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The source's migrated-out gate, read where the TypeScript release keeps
// it without starting anything of the installation: a release that finds no
// maintenance.json in its state directory takes requests.

// stateTarget is the release's state directory (VARLATCH_STATE_DIR), and
// where the installation mounts its state volume.
const (
	stateTarget = "/var/lib/varlatch"
	gateFile    = "maintenance.json"
	stateEnv    = "VARLATCH_STATE_DIR"
)

// GateRef is the gate a migration's source is behind: its id, and the
// volume that carries it, as the journal records them (State nil in an
// earlier build's journal), and the image it is read with when varlatchd has
// no container.
type GateRef struct {
	ID    string
	State *VolumeRecord
	Image string
	// Barrier also takes the gate before it is migrated out: the barrier.
	Barrier bool
	// Was is the id it had before, when the journal records another too.
	Was string
}

// gateChecker is a source whose gate is read, and whose state is held to be
// where it can be, without starting it.
type gateChecker interface {
	// CheckState is the volume that carries the gate: refused where the gate
	// could not be read and held.
	CheckState(ctx context.Context) (*VolumeRecord, error)
	CheckGate(ctx context.Context, g GateRef) error
	// StartTailnetGated is StartTailnet, varlatchd's container started only
	// behind g.
	StartTailnetGated(ctx context.Context, g GateRef) error
}

// GatedStart is what ServeGated starts behind.
type GatedStart struct {
	Gate GateRef
	// Owned is a sidecar migrate itself stopped, to be started.
	Owned bool
	// Starting journals, before it is started, a service that did not run.
	Starting func(service string) error
}

// sourceGate is the migrated-out gate j's source is behind.
func sourceGate(j *Journal) GateRef {
	g := GateRef{ID: j.SourceGate, State: j.Source.State, Image: j.Source.DigestRepository + "@" + j.Source.Digest}
	if j.Barrier != nil {
		if g.ID == "" {
			g.ID = j.Barrier.GateID
		} else if g.ID != j.Barrier.GateID {
			g.Was = j.Barrier.GateID
		}
	}
	return g
}

// barrierGate is the gate j's source is behind before it is marked: the
// barrier, or, marked already, the gate it became.
func barrierGate(j *Journal) GateRef {
	g := sourceGate(j)
	g.Barrier = true
	return g
}

// stateName is the name of the volume the Compose files give varlatchd's
// state directory, which its containers, when it has some, mount there
// (daemon is its one container, nil for none).
func (c *Compose) stateName(ctx context.Context, cfg composeConfig) (name string, daemon *composeContainer, err error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return "", nil, err
	}
	if v := cfg.Services[service].Environment[stateEnv]; v != nil && *v != stateTarget {
		return "", nil, fmt.Errorf("the installation's %s keeps its state in another directory than %s (%s): where its gate is is not known", service, stateTarget, stateEnv)
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return "", nil, err
	}
	name = cfg.volumeName(keys[2])
	if _, err := mountedAs(p, all, service, stateTarget, name); err != nil {
		return "", nil, err
	}
	own := serviceContainers(p, all, service)
	if len(own) > 1 {
		return "", nil, fmt.Errorf("the installation has %d %s containers, not one", len(own), service)
	}
	if len(own) == 1 {
		daemon = &own[0]
	}
	return name, daemon, nil
}

// serviceContainers are a service's containers, its one-offs aside.
func serviceContainers(p *ComposeProject, all []composeContainer, svc string) []composeContainer {
	var out []composeContainer
	for _, l := range all {
		if l.project == p.Name && l.service == svc && !l.isOneOff() {
			out = append(out, l)
		}
	}
	return out
}

// stateVolume is that volume, which must be there, and varlatchd's container.
func (c *Compose) stateVolume(ctx context.Context) (*VolumeRecord, *composeContainer, error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, nil, err
	}
	name, daemon, err := c.stateName(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	v, err := c.volume(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	if v == nil {
		return nil, nil, fmt.Errorf("the volume %s, which carries the installation's gate, is not there", name)
	}
	return v, daemon, nil
}

// CheckState holds the installation's state directory to be one whose gate
// is read and held: a named volume mounted whole at stateTarget, in the
// Compose files and in varlatchd's container as it is.
func (c *Compose) CheckState(ctx context.Context) (*VolumeRecord, error) {
	v, daemon, err := c.stateVolume(ctx)
	if err != nil {
		return nil, err
	}
	if daemon != nil {
		if err := c.checkMounts(ctx, daemon.id, v.Name); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// CheckGate refuses an installation that is not behind g, exactly: the
// volume that carries it is the one the migration recorded, and its file
// says migrated out, paused, with g's id (gone, the volume or the file, it
// is refused). Nothing of the installation is started for it: the file is
// read through varlatchd's own container, as it would find it; without one,
// in a container of migrate's, the volume read only.
func (c *Compose) CheckGate(ctx context.Context, g GateRef) error {
	if g.ID == "" {
		return errors.New("the journal records no gate of the TypeScript installation's")
	}
	v, daemon, err := c.stateVolume(ctx)
	if err != nil {
		return err
	}
	if err := g.in(v); err != nil {
		return err
	}
	if daemon != nil {
		return c.containerGate(ctx, daemon.id, v.Name, g)
	}
	text, there, err := c.volumeGate(ctx, g.Image, v.Name)
	if err != nil {
		return err
	}
	if !there {
		return noGate(v.Name)
	}
	return g.matches(v.Name, text)
}

// volumeGate is the gate's file in volume, read in a container of migrate's
// own, the volume read only: a plain file of its own, links not followed.
func (c *Compose) volumeGate(ctx context.Context, image, volume string) (text []byte, there bool, err error) {
	if err := c.ensureImage(ctx, image); err != nil {
		return nil, false, err
	}
	r, err := c.docker(ctx, append(ownRun("type=volume,source="+volume+",target=/state,readonly,volume-nocopy"), image, "-c", readGateScript), nil)
	if err != nil {
		return nil, false, err
	}
	switch r.Code {
	case 0:
		return r.Answer, true, nil
	case gateNone:
		return nil, false, nil
	case gateNotPlain:
		return nil, false, fmt.Errorf("the gate in the volume %s (%s) is not a plain file of its own", volume, gateFile)
	}
	return nil, false, failure("reading the TypeScript installation's gate", r)
}

// ownRun is docker's arguments for a shell in a container of migrate's own
// with mount, and nothing else: no network, nothing pulled.
func ownRun(mount string) []string {
	return []string{"run", "--rm", "-i", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--mount", mount, "--entrypoint", "sh"}
}

// The scripts of migrate's own containers. The gate's file is made as the
// release makes it (durableJson): a temporary name, synced, then linked
// (never over another) or renamed, and its directory synced.
const (
	gateNone, gateNotPlain = 3, 4

	readGateScript = `f=/state/` + gateFile + `; [ -e "$f" ] || [ -L "$f" ] || exit 3; [ -f "$f" ] && [ ! -L "$f" ] || exit 4; cat "$f"`

	writeGateScript = `set -eu; umask 022; cd ` + stateTarget + `; t=.` + gateFile + `.migrate; rm -f "$t"; cat > "$t"; sync "$t"; ` +
		`if [ "$1" = replace ]; then grep -qF "\"id\":\"$2\"" ` + gateFile + `; mv "$t" ` + gateFile + `; else ln "$t" ` + gateFile + `; rm "$t"; fi; sync .`
)

// HoldGate has the installation behind g, in the volume that carries it,
// before anything of it is started: the gate's file is made there when it is
// gone (the reverse's import lifts it), as it was. The Compose files are not
// needed (they may not be whole). A volume that is gone is made as Compose
// makes it. A gate there that the journal does not record is another's, and
// left. The gate it is behind then, and its volume, are given.
func (c *Compose) HoldGate(ctx context.Context, g GateRef, position string) (GateRef, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return g, err
	}
	if g.ID == "" {
		return g, errors.New("the journal records no gate of the TypeScript installation's")
	}
	name, key := "", stateKey
	if g.State != nil {
		name, key = g.State.Name, orWord(g.State.Key, stateKey)
	} else {
		// An earlier build's journal.
		cfg, err := c.config(ctx)
		if err != nil {
			return g, err
		}
		if name, _, err = c.stateName(ctx, cfg); err != nil {
			return g, err
		}
	}
	for _, l := range serviceContainers(p, all, service) {
		if err := c.checkMounts(ctx, l.id, name); err != nil {
			return g, err
		}
	}
	if err := c.ensureImage(ctx, g.Image); err != nil {
		return g, err
	}
	v, err := c.volume(ctx, name)
	if err != nil {
		return g, err
	}
	if v == nil && g.State != nil && g.State.Project != p.Name {
		// Not one Compose makes.
		return g, fmt.Errorf("the volume %s, which carries the installation's gate, is not there", name)
	}
	if v == nil {
		r, err := c.docker(ctx, []string{"volume", "create", "--label", labelProject + "=" + p.Name, "--label", labelVolume + "=" + key, name}, nil)
		if err != nil {
			return g, err
		}
		if r.Code != 0 {
			return g, failure("docker volume create "+name, r)
		}
		if v, err = c.volume(ctx, name); err != nil {
			return g, err
		}
	}
	// The recorded one as it was, whatever its labels (an external volume has
	// none); another only of the project.
	if v == nil || v.Project != p.Name && (g.State == nil || v.differs(*g.State) != "") {
		return g, fmt.Errorf("the volume %s, which carries the installation's gate, is not of its project %s", name, p.Name)
	}
	text, there, err := c.volumeGate(ctx, g.Image, name)
	if err != nil {
		return g, err
	}
	how := []string{"new"}
	if there {
		f, err := parseGate(text)
		switch {
		case err != nil:
			return g, fmt.Errorf("the gate in the volume %s (%s) cannot be read: %v", name, gateFile, err)
		case f.ID != g.ID && (f.ID != g.Was || g.Was == "") || f.Kind != "migrated-out" && f.Kind != "migration" || !f.Permanent:
			return g, fmt.Errorf("the installation is behind a %s gate (%s), not the migration's: left as it is", f.Kind, f.ID)
		case f.Kind == "migrated-out" && f.Phase == "paused":
			g.ID, g.State = f.ID, v
			return g, nil
		}
		how = []string{"replace", f.ID}
	}
	r, err := c.docker(ctx, append(append(ownRun("type=volume,source="+name+",target="+stateTarget), g.Image, "-c", writeGateScript, "sh"), how...), g.text(position))
	if err != nil {
		return g, err
	}
	if r.Code != 0 {
		return g, failure("making the TypeScript installation's gate again", r)
	}
	g.State = v
	if text, there, err = c.volumeGate(ctx, g.Image, name); err != nil {
		return g, err
	}
	if !there {
		return g, noGate(name)
	}
	return g, g.matches(name, text)
}

// text is the gate's file for g, as the release writes it: frozen at the
// barrier's position.
func (g GateRef) text(position string) []byte {
	var at *string
	if frozenPosition.MatchString(position) {
		at = &position
	}
	b, _ := json.Marshal(struct {
		ID             string  `json:"id"`
		Kind           string  `json:"kind"`
		Phase          string  `json:"phase"`
		ExpiresAt      *int64  `json:"expiresAt"`
		ArchiveID      *string `json:"archiveId"`
		FrozenPosition *string `json:"frozenPosition"`
		FrozenSnapshot *string `json:"frozenSnapshot"`
	}{ID: g.ID, Kind: "migrated-out", Phase: "paused", FrozenPosition: at})
	return b
}

// CheckHeld refuses an installation whose server, whoever starts it (Docker
// itself, an orchestrator's deploy), would not be behind g: g is in the
// volume the journal records, the Compose files as they are now give that
// volume to varlatchd, its containers have it, whole, for their state, no
// container of the project has another there, and nothing that could lift it
// runs.
func (c *Compose) CheckHeld(ctx context.Context, g GateRef) error {
	if g.ID == "" || g.State == nil {
		return errors.New("the journal does not record the TypeScript installation's gate and the volume that carries it")
	}
	p, all, err := c.verified(ctx)
	if err != nil {
		return err
	}
	v, err := c.volume(ctx, g.State.Name)
	if err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("the volume %s, which carries the installation's gate, is not there", g.State.Name)
	}
	if why := v.differs(*g.State); why != "" {
		return fmt.Errorf("the volume %s is not the one that carries the gate (%s)", v.Name, why)
	}
	text, there, err := c.volumeGate(ctx, g.Image, v.Name)
	if err != nil {
		return err
	}
	if !there {
		return noGate(v.Name)
	}
	if err := g.matches(v.Name, text); err != nil {
		return err
	}
	// What the next container is made with: nothing else tells it, when
	// varlatchd has none now.
	cfg, err := c.config(ctx)
	if err != nil {
		return fmt.Errorf("%w; which volume its Compose files give varlatchd's state is not known: put them back as the migration left them", err)
	}
	if name, _, err := c.stateName(ctx, cfg); err != nil {
		return err
	} else if name != v.Name {
		return fmt.Errorf("the Compose files give varlatchd's state the volume %s, and the gate is in %s: put them back as the migration left them", name, v.Name)
	}
	for _, l := range all {
		if l.project != p.Name {
			continue
		}
		for _, m := range l.mounts {
			if m.Destination == stateTarget && (m.Type != "volume" || m.Name != v.Name) {
				return fmt.Errorf("the project's %s container has %s at %s, not the volume %s that carries the gate", l.called(), orWord(m.Name, "a "+orWord(m.Type, "mount")), stateTarget, v.Name)
			}
		}
		switch {
		case l.service == service && !l.isOneOff():
			if err := c.checkMounts(ctx, l.id, v.Name); err != nil {
				return err
			}
		case l.service == importService && l.status != "exited" && l.status != "created" && l.status != "dead":
			return fmt.Errorf("the reverse's import (%s) still runs", l.name)
		}
	}
	return nil
}

// in refuses a volume that is not the recorded one, when one is.
func (g GateRef) in(v *VolumeRecord) error {
	if g.State != nil {
		if why := v.differs(*g.State); why != "" {
			return fmt.Errorf("the volume %s is not the one that carried the gate when the migration began (%s)", v.Name, why)
		}
	}
	return nil
}

func noGate(volume string) error {
	return fmt.Errorf("the volume %s holds no gate (%s): the TypeScript installation would take requests", volume, gateFile)
}

// containerGate is CheckGate of one container, which need not run: its
// state directory is volume, mounted whole, and the file there the gate.
// Docker's copy reads it through the container's own mounts, links not
// followed.
func (c *Compose) containerGate(ctx context.Context, id, volume string, g GateRef) error {
	if err := c.checkMounts(ctx, id, volume); err != nil {
		return err
	}
	r, err := c.docker(ctx, []string{"cp", id + ":" + stateTarget + "/" + gateFile, "-"}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		if bytes.Contains(r.Said, []byte("Could not find the file")) {
			return noGate(volume)
		}
		return failure("reading the TypeScript installation's gate", r)
	}
	t := tar.NewReader(bytes.NewReader(r.Answer))
	h, err := t.Next()
	if err != nil {
		return fmt.Errorf("the gate in the volume %s (%s) cannot be read", volume, gateFile)
	}
	if h.Typeflag != tar.TypeReg || h.Name != gateFile || h.Size > maxGate {
		return fmt.Errorf("the gate in the volume %s (%s) is not a plain file of its own", volume, gateFile)
	}
	b, err := io.ReadAll(t)
	if err != nil {
		return fmt.Errorf("the gate in the volume %s (%s) cannot be read", volume, gateFile)
	}
	if _, err := t.Next(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("the gate in the volume %s (%s) is not one file", volume, gateFile)
	}
	return g.matches(volume, b)
}

// maxGate bounds the gate's file.
const maxGate = 64 << 10

// mountsFormat is what a container's state directory is told by.
const mountsFormat = `{{json .Config.Env}} {{json .Mounts}} {{json .HostConfig.Mounts}} {{json .HostConfig.Tmpfs}}`

// checkMounts refuses a container whose state directory is not volume,
// whole: another volume or a part of it (a subpath), a bind, another
// directory, or something else mounted in it.
func (c *Compose) checkMounts(ctx context.Context, id, volume string) error {
	r, err := c.docker(ctx, []string{"inspect", "--type", "container", "--format", mountsFormat, id}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("docker inspect", r)
	}
	var env []string
	var mounts []struct {
		containerMount
		Driver string
		RW     bool
	}
	var asked []struct {
		Type, Source, Target string
		VolumeOptions        *struct{ Subpath string }
	}
	var tmpfs map[string]string
	dec := json.NewDecoder(bytes.NewReader(r.Answer))
	for _, v := range []any{&env, &mounts, &asked, &tmpfs} {
		if err := dec.Decode(v); err != nil {
			return errors.New("docker inspect did not give the container's mounts")
		}
	}
	// Only its state directory is read of the environment.
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, stateEnv+"="); ok && v != stateTarget {
			return fmt.Errorf("the installation's %s container keeps its state in another directory than %s (%s): where its gate is is not known", service, stateTarget, stateEnv)
		}
	}
	// The directory's own mount, and none over it or in it.
	at := func(target string) bool {
		target = path.Clean(target)
		return target == stateTarget || strings.HasPrefix(target, stateTarget+"/")
	}
	const not = "the installation's " + service + " container's state directory, " + stateTarget + ", is not the whole of the volume %s (%s): its gate cannot be held to be what the server would find"
	own := 0
	for _, m := range mounts {
		switch {
		case !at(m.Destination):
		case m.Destination != stateTarget:
			return fmt.Errorf(not, volume, "something is mounted in it, at "+m.Destination)
		case m.Type != "volume" || m.Name != volume:
			return fmt.Errorf(not, volume, "it is "+orWord(m.Name, "a "+orWord(m.Type, "mount")))
		case m.Driver != "" && m.Driver != "local":
			return fmt.Errorf(not, volume, "the volume's driver is "+m.Driver)
		case !m.RW:
			return fmt.Errorf(not, volume, "it is read only")
		default:
			own++
		}
	}
	if own != 1 {
		return fmt.Errorf(not, volume, fmt.Sprintf("it is mounted there %d times", own))
	}
	for _, m := range asked {
		if !at(m.Target) {
			continue
		}
		if path.Clean(m.Target) != stateTarget || m.Type != "volume" || m.VolumeOptions != nil && m.VolumeOptions.Subpath != "" {
			return fmt.Errorf(not, volume, "a part of it, or something else, is mounted there")
		}
	}
	for target := range tmpfs {
		if at(target) {
			return fmt.Errorf(not, volume, "a temporary file system is mounted at "+target)
		}
	}
	return nil
}

// startGated starts varlatchd's container, the very one whose gate was read:
// made first when it is not there, or with again (its network's owner was
// made again, or the Compose files may give it another), without starting
// it. Started by its id, so one that is made again meanwhile is not started
// here, and held to be the installation's own one after.
func (c *Compose) startGated(ctx context.Context, g GateRef, again bool, flags ...string) error {
	if g.ID == "" {
		return errors.New("the journal records no gate of the TypeScript installation's")
	}
	has, err := c.hasContainer(ctx, service)
	if err != nil {
		return err
	}
	if !has || again {
		// Compose makes a volume that is not there, and the container on the
		// one its files give now.
		v, _, err := c.stateVolume(ctx)
		if err != nil {
			return err
		}
		if err := g.in(v); err != nil {
			return err
		}
		args := append([]string{"up", "--no-start", "--no-deps"}, flags...)
		if err := c.compose(ctx, "docker compose up --no-start varlatchd", append(args, service)...); err != nil {
			return err
		}
	}
	v, daemon, err := c.stateVolume(ctx)
	if err != nil {
		return err
	}
	if daemon == nil || daemon.id == "" {
		return fmt.Errorf("the installation has no %s container", service)
	}
	if err := g.in(v); err != nil {
		return err
	}
	if err := c.containerGate(ctx, daemon.id, v.Name, g); err != nil {
		return err
	}
	verb := "start"
	if daemon.status != "created" && daemon.status != "exited" {
		// Its network's owner may be another than the one it joined.
		verb = "restart"
	}
	r, err := c.docker(ctx, []string{verb, daemon.id}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("docker "+verb+" of "+service+"'s container", r)
	}
	_, now, err := c.stateVolume(ctx)
	if err != nil {
		return err
	}
	if now == nil || now.id != daemon.id {
		return fmt.Errorf("the installation's %s container was made again while it was started: what runs now was not checked", service)
	}
	return nil
}

// gateKeys are the TypeScript release's gate, as it writes it (Gate,
// packages/backup/src/maintenance.ts): no key other than these, each once.
var gateKeys = []string{"id", "kind", "phase", "expiresAt", "archiveId", "frozenPosition", "frozenSnapshot"}

var (
	frozenPosition = regexp.MustCompile(`^[0-9]+$`)
	frozenSnapshot = regexp.MustCompile(`^[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+$`)
)

// matches refuses a gate's file that is not g. It is read as JavaScript
// reads it: exact keys (encoding/json takes a key in any case, and the last
// of two), one value, nothing after it.
func (g GateRef) matches(volume string, b []byte) error {
	f, err := parseGate(b)
	if err != nil {
		return fmt.Errorf("the gate in the volume %s (%s) cannot be read: %v", volume, gateFile, err)
	}
	if f.Kind != "migrated-out" && !(g.Barrier && f.Kind == "migration") || f.Phase != "paused" || f.ID != g.ID || !f.Permanent {
		return fmt.Errorf("the gate in the volume %s is %s %s (%s), not the migration's own, %s", volume, orWord(f.Kind, "no kind"), orWord(f.ID, "without an id"), orWord(f.Phase, "no phase"), g.ID)
	}
	return nil
}

// gateDoc is a gate's file; Permanent is one that never expires and is no
// archive's.
type gateDoc struct {
	ID, Kind, Phase string
	Permanent       bool
}

func parseGate(b []byte) (gateDoc, error) {
	var f gateDoc
	if len(b) > maxGate || !utf8.Valid(b) {
		return f, errors.New("not UTF-8 text of a gate's size")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return f, errors.New("not one JSON object")
	}
	seen := map[string]bool{}
	f.Permanent = true
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return f, errors.New("not one JSON object")
		}
		if !slices.Contains(gateKeys, key) {
			return f, errors.New("a key a gate has not")
		}
		if seen[key] {
			return f, fmt.Errorf("%s twice", key)
		}
		seen[key] = true
		v, err := dec.Token()
		if err != nil {
			return f, errors.New("not one JSON object")
		}
		s, isText := v.(string)
		switch key {
		case "id", "kind", "phase":
			if !isText || s == "" {
				return f, fmt.Errorf("%s is not a text", key)
			}
			*map[string]*string{"id": &f.ID, "kind": &f.Kind, "phase": &f.Phase}[key] = s
		case "expiresAt", "archiveId":
			if v != nil {
				f.Permanent = false
				if _, nested := v.(json.Delim); nested {
					return f, fmt.Errorf("%s is not a value", key)
				}
			}
		case "frozenPosition":
			if v != nil && (!isText || !frozenPosition.MatchString(s)) {
				return f, fmt.Errorf("%s is not a position", key)
			}
		case "frozenSnapshot":
			if v != nil && (!isText || !frozenSnapshot.MatchString(s)) {
				return f, fmt.Errorf("%s is not a snapshot", key)
			}
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return f, errors.New("not one JSON object")
	}
	if int(dec.InputOffset()) != len(b) {
		return f, errors.New("something follows it")
	}
	for _, key := range []string{"id", "kind", "phase", "expiresAt", "archiveId"} {
		if !seen[key] {
			return f, fmt.Errorf("it has no %s", key)
		}
	}
	return f, nil
}

// minCompose is the Compose a migration needs: the first that makes a
// service again when only its volume's name changed, which the way back's
// fresh volumes are (measured: 2.31.0 does not, 2.32.0 does).
var minCompose = [3]int{2, 32, 0}

var composeVersion = regexp.MustCompile(`^v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(?:[-+].*)?$`)

// checkVersion refuses a Docker Compose too old for a migration and its
// way back.
func (c *Compose) checkVersion(ctx context.Context) error {
	need := fmt.Sprintf("%d.%d.%d", minCompose[0], minCompose[1], minCompose[2])
	r, err := c.Run.Run(ctx, c.Directory, c.dockerName(), []string{"compose", "version", "--short"}, nil)
	if err != nil {
		return err
	}
	said := strings.TrimSpace(string(r.Answer))
	m := composeVersion.FindStringSubmatch(said)
	if r.Code != 0 || m == nil {
		return fmt.Errorf("docker compose version did not say which Docker Compose this is: varlatch migrate needs %s or later", need)
	}
	for i, min := range minCompose {
		n, err := strconv.Atoi(m[i+1])
		if err != nil || n > min {
			return err
		}
		if n < min {
			return fmt.Errorf("Docker Compose %s is too old: varlatch migrate needs %s or later (an earlier one leaves Postgres on the old volume when a rollback gives it a fresh one); update the Docker Compose plugin", said, need)
		}
	}
	return nil
}
