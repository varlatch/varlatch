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
}

// projectName is the installation's Compose project, as Compose itself
// resolves it (its -p, COMPOSE_PROJECT_NAME, the files' top-level name:,
// the directory's name, in that order): `docker compose config` in the
// installation's directory, whose .env names its files. Uninterpolated:
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
		NetworkMode string             `json:"network_mode"`
		Environment map[string]*string `json:"environment"`
	} `json:"services"`
}

func (c *Compose) config(ctx context.Context) (composeConfig, error) {
	r, err := c.docker(ctx, []string{"compose", "config", "--no-interpolate", "--format", "json"}, nil)
	if err != nil {
		return composeConfig{}, err
	}
	if r.Code != 0 {
		return composeConfig{}, errors.New("docker compose config failed: the installation's Compose project could not be read")
	}
	var m composeConfig
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &m); err != nil || m.Name == "" || strings.ContainsAny(m.Name, "/ \t\n") {
		return composeConfig{}, errors.New("docker compose config did not name the installation's Compose project")
	}
	return m, nil
}

// RebuildPlan: the fresh volumes, named by the project and the migration
// (its id's last 8 letters), and COMPOSE_FILE as it is now.
func (c *Compose) RebuildPlan(ctx context.Context, j *Journal) (RebuildRecord, error) {
	project, err := c.projectName(ctx)
	if err != nil {
		return RebuildRecord{}, err
	}
	if j.Source.Digest == "" || j.Source.DigestRepository == "" {
		return RebuildRecord{}, errors.New("the journal records no image digest of the source: the rebuild runs the release's own image only")
	}
	short := j.ID[len(j.ID)-8:]
	plan := RebuildRecord{Override: OverrideFile, Image: j.Source.DigestRepository + "@" + j.Source.Digest,
		Volumes: []string{project + "_postgres-data-" + short, project + "_convex-data-" + short}}
	cf, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		return plan, err
	}
	if ok {
		plan.ComposeFile = &cf
	}
	return plan, nil
}

// override is migrate's Compose file for plan.
func override(plan RebuildRecord) string {
	return `# Written by varlatch migrate --rollback (go-step7 decision 16): this
# installation runs on a fresh database rebuilt from its Go installation.
# The volumes it ran on before the migration are kept, unchanged, until
# varlatch migrate --finish. Keep this file and COMPOSE_FILE as they are.
volumes:
  postgres-data:
    name: ` + plan.Volumes[0] + `
  convex-data:
    name: ` + plan.Volumes[1] + `
services:
  varlatch-reverse-import:
    image: ` + plan.Image + `
    profiles: [` + reverseProfile + `]
    restart: "no"
    environment:
      VARLATCH_STATE_DIR: /var/lib/varlatch
      VARLATCH_DATABASE_URL: postgres://varlatchd_migrate:${VARLATCH_MIGRATE_PASSWORD:-}@postgres:5432/varlatch
      VARLATCH_DATABASE_PASSWORD_FILE: /run/secrets/varlatch-migrate-password
      VARLATCH_KEK_FILE: /run/secrets/varlatch-kek
      VARLATCH_PUBLIC_URL: ${VARLATCH_PUBLIC_URL:?set VARLATCH_PUBLIC_URL in .env}
    volumes:
      - varlatch-state:/var/lib/varlatch
      - ./backups:/backups
    secrets:
      - varlatch-kek
      - varlatch-migrate-password
    depends_on:
      postgres:
        condition: service_healthy
`
}

// envValue is one of .env's values, and whether it is set.
func (c *Compose) envValue(name string) (string, bool, error) {
	env, err := c.envFile()
	if err != nil {
		return "", false, err
	}
	v, ok := env[name]
	return v, ok, nil
}

// composeFiles is COMPOSE_FILE's value naming migrate's file after the
// installation's own: its value now, else the files Compose reads without
// it (docker-compose.yml, and docker-compose.override.yml when present).
func (c *Compose) composeFiles(plan RebuildRecord) string {
	sep := string(os.PathListSeparator)
	var files []string
	if plan.ComposeFile != nil {
		files = strings.Split(*plan.ComposeFile, sep)
	} else {
		files = []string{"docker-compose.yml"}
		if _, err := os.Stat(filepath.Join(c.Directory, "docker-compose.override.yml")); err == nil {
			files = append(files, "docker-compose.override.yml")
		}
	}
	for _, f := range files {
		if filepath.Base(strings.TrimSpace(f)) == OverrideFile {
			return strings.Join(files, sep)
		}
	}
	return strings.Join(append(files, OverrideFile), sep)
}

// setEnv writes .env with name set to value (nil: the line removed), every
// other byte as it was: the file is split on newlines, never scanned, so a
// line of any length is kept whole (a scanner stopped by its token limit
// would write a truncated .env over the operator's). A .env that is a
// symbolic link is written at its target, which is replaced through a
// temporary name beside it; the link stays. A link whose target is not
// there is refused, never replaced by a file. Its mode is kept.
func (c *Compose) setEnv(name string, value *string) error {
	path := filepath.Join(c.Directory, ".env")
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if st, lerr := os.Lstat(path); lerr == nil && st.Mode()&fs.ModeSymlink != 0 {
		link, _ := os.Readlink(path)
		return fmt.Errorf("%s is a symbolic link to %s, which is not there: the installation's .env is not replaced by a file; restore its target, then run varlatch migrate again", path, link)
	}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	mode := fs.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	var out bytes.Buffer
	done := false
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		text := strings.TrimSpace(string(line))
		key, _, ok := strings.Cut(text, "=")
		if ok && strings.TrimSpace(key) == name && !strings.HasPrefix(text, "#") {
			if value != nil && !done {
				out.WriteString(name + "=" + *value + "\n")
			}
			done = true
			continue
		}
		out.Write(line)
	}
	if value != nil && !done {
		if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
			out.WriteByte('\n')
		}
		out.WriteString(name + "=" + *value + "\n")
	}
	return writeFileDurably(path, out.Bytes(), mode)
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
	if err := c.compose(ctx, "docker compose stop", "stop", "varlatchd", "convex-backend", "postgres"); err != nil {
		return err
	}
	if err := writeFileDurably(filepath.Join(c.Directory, plan.Override), []byte(override(plan)), 0o600); err != nil {
		return err
	}
	files := c.composeFiles(plan)
	if err := c.setEnv("COMPOSE_FILE", &files); err != nil {
		return err
	}
	return c.compose(ctx, "docker compose up -d postgres", "up", "-d", "postgres")
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
	r, err := c.stream(ctx, []string{"compose", "--profile", reverseProfile, "run", "--rm", "-T", "varlatch-reverse-import",
		"node", "dist/cli.js", "admin", "migration", "import", "--in", "-"}, in, answer)
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
// service, its daemon not started.
func oneOff(args ...string) []string {
	return append([]string{"compose", "run", "--rm", "-T", "--no-deps", service, "node", "dist/cli.js", "admin"}, args...)
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
	return c.StartIngress(ctx, kind)
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
	if err := c.setEnv("COMPOSE_FILE", plan.ComposeFile); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(c.Directory, plan.Override)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := c.compose(ctx, "docker compose up -d postgres convex-backend", "up", "-d", "postgres", "convex-backend"); err != nil {
		return err
	}
	for _, v := range plan.Volumes {
		// Asked directly before its removal: no container, running or
		// stopped, still uses the fresh volume (the services are back on
		// their own ones).
		r, err := c.docker(ctx, []string{"ps", "-a", "--filter", "volume=" + v, "--format", "{{.Names}}"}, nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("docker ps --filter volume="+v, r)
		}
		if users := strings.Fields(string(r.Answer)); len(users) > 0 {
			return fmt.Errorf("the reverse's fresh volume %s is still used by %s: left as it is", v, strings.Join(users, ", "))
		}
		r, err = c.docker(ctx, []string{"volume", "rm", "-f", v}, nil)
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
		"start it by hand (docker compose up -d --no-deps %s, in %s; it brings the old Tailscale node back), then %s", owner, owner, owner, c.Directory, then)
}

// ReverseReady: the reverse's one-off commands (the rebuilt database's
// export for the checks among them) run in varlatchd's network, so a
// stopped sidecar it shares refuses the reverse before Go's barrier, not
// after the rebuild.
func (c *Compose) ReverseReady(ctx context.Context) error {
	return c.networkOwnerRunning(ctx, "varlatch migrate --rollback again")
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
