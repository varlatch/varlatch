// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The source's migrated-out gate, read where the TypeScript release keeps
// it without starting anything of the installation: a release that finds no
// maintenance.json in its state directory takes requests.

// stateTarget is the release's state directory (VARLATCH_STATE_DIR), and
// where the installation mounts its state volume.
const (
	stateTarget = "/var/lib/varlatch"
	gateFile    = "maintenance.json"
)

// GateRef is the gate a migration's source is behind: its id, and the
// volume that carries it, as the journal records them (State nil in an
// earlier build's journal), and the image it is read with.
type GateRef struct {
	ID    string
	State *VolumeRecord
	Image string
	// Barrier also takes the gate before it is migrated out: the barrier.
	Barrier bool
}

// gateChecker is a source whose gate is read without starting it.
type gateChecker interface {
	CheckGate(ctx context.Context, g GateRef) error
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
	if g.ID == "" && j.Barrier != nil {
		g.ID = j.Barrier.GateID
	}
	return g
}

// stateName is the name of the volume the Compose files give varlatchd's
// state directory, which its container, when it has one, mounts there.
func (c *Compose) stateName(ctx context.Context, cfg composeConfig) (string, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return "", err
	}
	if v := cfg.Services[service].Environment["VARLATCH_STATE_DIR"]; v != nil && *v != stateTarget {
		return "", fmt.Errorf("the installation's %s keeps its state in another directory than %s (VARLATCH_STATE_DIR): where its gate is is not known", service, stateTarget)
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return "", err
	}
	name := cfg.volumeName(keys[2])
	_, err = mountedAs(p, all, service, stateTarget, name)
	return name, err
}

// stateVolume is that volume, which must be there.
func (c *Compose) stateVolume(ctx context.Context) (*VolumeRecord, error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	name, err := c.stateName(ctx, cfg)
	if err != nil {
		return nil, err
	}
	v, err := c.volume(ctx, name)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("the volume %s, which carries the installation's gate, is not there", name)
	}
	return v, nil
}

// CheckGate refuses an installation that is not behind g, exactly: the
// volume that carries it is the one the migration recorded, and its file
// says migrated out, paused, with g's id (gone, the volume or the file, it
// is refused). Nothing of the installation is
// started for it; the file is read in a container of its own, the volume
// read only.
func (c *Compose) CheckGate(ctx context.Context, g GateRef) error {
	if g.ID == "" {
		return errors.New("the journal records no gate of the TypeScript installation's")
	}
	v, err := c.stateVolume(ctx)
	if err != nil {
		return err
	}
	if g.State != nil {
		if why := v.differs(*g.State); why != "" {
			return fmt.Errorf("the volume %s is not the one that carried the gate when the migration began (%s)", v.Name, why)
		}
	}
	if err := c.ensureImage(ctx, g.Image); err != nil {
		return err
	}
	r, err := c.docker(ctx, []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--mount", "type=volume,source=" + v.Name + ",target=/state,readonly,volume-nocopy", "--entrypoint", "cat", g.Image, "/state/" + gateFile}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		if bytes.Contains(r.Said, []byte("No such file")) {
			return fmt.Errorf("the volume %s holds no gate (%s): the TypeScript installation would take requests", v.Name, gateFile)
		}
		return failure("reading the TypeScript installation's gate", r)
	}
	var f struct {
		Gate
		Phase     string          `json:"phase"`
		ExpiresAt json.RawMessage `json:"expiresAt"`
	}
	if json.Unmarshal(bytes.TrimSpace(r.Answer), &f) != nil {
		return fmt.Errorf("the gate in the volume %s (%s) cannot be read", v.Name, gateFile)
	}
	if f.Kind != "migrated-out" && !(g.Barrier && f.Kind == "migration") || f.Phase != "paused" || f.ID != g.ID || len(f.ExpiresAt) > 0 && string(f.ExpiresAt) != "null" {
		return fmt.Errorf("the gate in the volume %s is %s %s (%s), not the migration's own, %s", v.Name, orWord(f.Kind, "no kind"), orWord(f.ID, "without an id"), orWord(f.Phase, "no phase"), g.ID)
	}
	return nil
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
