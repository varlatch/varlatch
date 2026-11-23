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
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Compose is a Compose installation of the last TypeScript release, the
// migration's source (go-step7 decision 20): found by its containers'
// labels, else its Compose files in Directory (compose_project.go); driven with `docker compose exec` into its
// varlatchd service (the image's `node dist/cli.js admin migration ...`,
// slices 7.2a and 7.2b) and with the TypeScript host CLI for its backup.
type Compose struct {
	// Directory is the installation's Compose directory.
	Directory string
	// Run runs docker and the TypeScript CLI.
	Run Runner
	// Env is the environment docker runs in (Run's): a COMPOSE_FILE or
	// COMPOSE_PROJECT_NAME there must agree with the containers.
	Env []string
	// Docker is the docker program ("docker").
	Docker string
	// TSCLI is the TypeScript host CLI ("varlatch-ts").
	TSCLI string
	// KEKFile is the source's Root KEK file ("" for the installation's:
	// VARLATCH_KEK_HOST_PATH in .env, else secrets/varlatch-kek).
	KEKFile string
	// BEKFile, Destination, DestinationsFile and ReadCredentialsFile are
	// the backup's: the Backup Encryption Key file, the destination it
	// is uploaded to (backup-destinations.json's name, or the file given)
	// and the credentials it is downloaded again with.
	BEKFile             string
	Destination         string
	DestinationsFile    string
	ReadCredentialsFile string

	// kept is the project the migration's journal records (KeepProject);
	// resolved the one in use, once resolved.
	kept, resolved *ComposeProject
}

// service is the source's varlatchd service in its Compose file.
const service = "varlatchd"

func (c *Compose) Dir() string { return c.Directory }

func (c *Compose) docker(ctx context.Context, args []string, stdin []byte) (Ran, error) {
	full, err := c.argv(ctx, args)
	if err != nil {
		return Ran{}, err
	}
	return c.Run.Run(ctx, c.Directory, c.dockerName(), full, stdin)
}

func (c *Compose) dockerName() string {
	if c.Docker == "" {
		return "docker"
	}
	return c.Docker
}

// stream runs docker on streams (Streamer): a bundle in or out, never
// held in memory, and never in a directory the container's user must
// share with the operator.
func (c *Compose) stream(ctx context.Context, args []string, in io.Reader, out io.Writer) (Ran, error) {
	s, ok := c.Run.(Streamer)
	if !ok {
		return Ran{}, errors.New("this runner cannot stream a bundle")
	}
	full, err := c.argv(ctx, args)
	if err != nil {
		return Ran{}, err
	}
	return s.Stream(ctx, c.Directory, c.dockerName(), full, in, out)
}

// admin runs the source's `admin migration` (or another admin command)
// inside its varlatchd container.
func (c *Compose) admin(ctx context.Context, args []string, stdin []byte) (Ran, error) {
	full := append([]string{"compose", "exec", "-T", service, "node", "dist/cli.js", "admin"}, args...)
	return c.docker(ctx, full, stdin)
}

// Discover finds the installation: its Compose project (compose_project.go,
// resolved now whatever an earlier journal recorded), and its varlatchd
// service's image, by its release (the image's version label, else its
// tag) and its digest (the registry's, which a published release has).
func (c *Compose) Discover(ctx context.Context) (SourceInfo, error) {
	info := SourceInfo{Kind: "compose", Dir: c.Directory}
	c.KeepProject(nil)
	p, err := c.project(ctx)
	if err != nil {
		return info, err
	}
	info.Project = p
	r, err := c.docker(ctx, []string{"compose", "images", "--format", "json", service}, nil)
	if err != nil {
		return info, err
	}
	if r.Code != 0 {
		return info, failure("docker compose images", r)
	}
	var images []struct {
		Repository string `json:"Repository"`
		Tag        string `json:"Tag"`
		ID         string `json:"ID"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &images); err != nil || len(images) != 1 || images[0].ID == "" {
		return info, fmt.Errorf("docker compose images did not name the %s service's one image: is the installation running?", service)
	}
	img := images[0]
	r, err = c.docker(ctx, []string{"image", "inspect", "--format", "{{json .}}", img.ID}, nil)
	if err != nil {
		return info, err
	}
	if r.Code != 0 {
		return info, failure("docker image inspect", r)
	}
	var inspect struct {
		RepoDigests []string `json:"RepoDigests"`
		Config      struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &inspect); err != nil {
		return info, errors.New("docker image inspect did not answer in JSON")
	}
	info.Image = img.Repository + ":" + img.Tag
	info.Release = strings.TrimPrefix(inspect.Config.Labels["org.opencontainers.image.version"], "v")
	if info.Release == "" {
		info.Release = strings.TrimPrefix(img.Tag, "v")
	}
	info.Digest, info.DigestRepository = repoDigest(inspect.RepoDigests, img.Repository, releasePin())
	return info, nil
}

// repoDigest is the registry digest an image is checked by, of the
// repository and digest pairs Docker lists for it (RepoDigests, in no
// order that means anything): the pinned image's when the image is it
// (pulled by tag and by digest, an index and a platform's manifest, under
// several names), else the first of the pinned repository, else the
// first of the name it runs under. A digest of another repository is
// never taken for the pinned one's: the pin compares both.
func repoDigest(repoDigests []string, running string, pin imagePin) (digest, repository string) {
	var ofPin, ofRunning [2]string
	for _, d := range repoDigests {
		repo, dig, ok := strings.Cut(d, "@")
		if !ok || !strings.HasPrefix(dig, "sha256:") {
			continue
		}
		switch {
		case repo == pin.Repository && dig == pin.Digest:
			return dig, repo
		case repo == pin.Repository && ofPin[0] == "":
			ofPin = [2]string{dig, repo}
		case repo == running && ofRunning[0] == "":
			ofRunning = [2]string{dig, repo}
		}
	}
	if ofPin[0] != "" {
		return ofPin[0], ofPin[1]
	}
	return ofRunning[0], ofRunning[1]
}

// Gate is the source's gate (`admin migration status`).
func (c *Compose) Gate(ctx context.Context) (*Gate, error) {
	r, err := c.admin(ctx, []string{"migration", "status"}, nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("the source's admin migration status", r)
	}
	var s struct {
		Gate *Gate `json:"gate"`
	}
	if err := json.Unmarshal(lastLine(r.Answer), &s); err != nil {
		return nil, errors.New("the source's admin migration status did not answer in JSON")
	}
	return s.Gate, nil
}

// lastLine is a program's last line of output (the TypeScript CLI prints
// its one JSON answer last).
func lastLine(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// envFile is the installation's .env as Compose reads it: NAME=value
// lines, the last of a name wins, quotes around a value taken off.
func (c *Compose) envFile() (map[string]string, error) {
	env, err := os.ReadFile(filepath.Join(c.Directory, ".env"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	out := map[string]string{}
	// Split on newlines, not scanned: a line of any length is read whole
	// (a scanner's token limit would stop at a long one and read on as if
	// the file ended there).
	for _, raw := range bytes.Split(env, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(name)] = v
	}
	return out, nil
}

// outboundEnv is the source's outbound allow list's variable.
const outboundEnv = "VARLATCH_OUTBOUND_ALLOW"

// outboundAllow is the source's outbound allow list, the value Compose
// gave varlatchd (from .env, the shell or an overlay, its own way with
// quotes and comments): the running container's environment (docker
// inspect), else, the service not running, `docker compose config` with
// interpolation (fromConfig). Only this variable is read of either: no
// other value is kept, and no error carries their output.
func (c *Compose) outboundAllow(ctx context.Context) (value string, fromConfig bool, err error) {
	r, err := c.docker(ctx, []string{"compose", "ps", "-q", service}, nil)
	if err != nil {
		return "", false, err
	}
	ids := strings.Fields(string(r.Answer))
	switch {
	case r.Code != 0:
		// Not "not running": Docker did not say.
		return "", false, fmt.Errorf("docker compose ps -q %s failed (exit %d), so migrate cannot tell whether the source's %s runs: its %s cannot be read", service, r.Code, service, outboundEnv)
	case len(ids) > 1:
		return "", false, fmt.Errorf("docker compose ps -q %s names %d running containers (%s): a migration takes an installation with one %s; its %s cannot be read", service, len(ids), strings.Join(ids, ", "), service, outboundEnv)
	}
	if len(ids) == 1 {
		r, err := c.docker(ctx, []string{"inspect", "--format", "{{json .Config.Env}}", ids[0]}, nil)
		if err != nil {
			return "", false, err
		}
		var env []string
		if r.Code != 0 || json.Unmarshal(bytes.TrimSpace(r.Answer), &env) != nil {
			return "", false, fmt.Errorf("docker inspect did not give the %s container's environment: its %s cannot be read", service, outboundEnv)
		}
		for _, kv := range env {
			if name, v, ok := strings.Cut(kv, "="); ok && name == outboundEnv {
				value = v // the last of a name holds, as in the process
			}
		}
		return strings.TrimSpace(value), false, nil
	}
	r, err = c.docker(ctx, []string{"compose", "config", "--format", "json"}, nil)
	if err != nil {
		return "", true, err
	}
	if r.Code != 0 {
		// Its output is not said: with the variables resolved, it can
		// hold any value of the installation's.
		hint := "run " + c.byHand("config") + " in " + c.Directory + " to see why"
		if said := strings.ToLower(string(r.Said)); strings.Contains(said, "variable") &&
			(strings.Contains(said, "not set") || strings.Contains(said, "missing a value") || strings.Contains(said, "required")) {
			hint = "a variable the Compose files need is unset (" + c.byHand("config") + " in " + c.Directory + " names it)"
		}
		return "", true, fmt.Errorf("docker compose config failed (exit %d; %s), with the source's %s not running: its %s cannot be read", r.Code, hint, service, outboundEnv)
	}
	var m composeConfig
	if json.Unmarshal(bytes.TrimSpace(r.Answer), &m) != nil {
		return "", true, fmt.Errorf("docker compose config did not give the %s service's environment: its %s cannot be read", service, outboundEnv)
	}
	if v := m.Services[service].Environment[outboundEnv]; v != nil {
		value = *v
	}
	return strings.TrimSpace(value), true, nil
}

// kekPath is the source's Root KEK file on this host: KEKFile, else .env's
// VARLATCH_KEK_HOST_PATH (relative to Directory), else secrets/varlatch-kek, as
// the Compose file has it.
func (c *Compose) kekPath() (string, error) {
	if c.KEKFile != "" {
		return c.KEKFile, nil
	}
	p := filepath.Join(c.Directory, "secrets", "varlatch-kek")
	env, err := c.envFile()
	if err != nil {
		return "", err
	}
	if v := env["VARLATCH_KEK_HOST_PATH"]; v != "" {
		p = v
		if !filepath.IsAbs(p) {
			p = filepath.Join(c.Directory, p)
		}
	}
	return p, nil
}

// Ingress reads the installation's .env as its Compose files do: the
// public URL (VARLATCH_PUBLIC_URL), the Caddy overlay among the project's
// files (public ingress), the dashboard's published address
// (BIND_ADDRESS:VARLATCH_WEB_PORT, 127.0.0.1:8787 by default); and the
// outbound allow list as varlatchd has it (outboundAllow).
func (c *Compose) Ingress(ctx context.Context) (IngressInfo, error) {
	env, err := c.envFile()
	if err != nil {
		return IngressInfo{}, err
	}
	info := IngressInfo{PublicURL: env["VARLATCH_PUBLIC_URL"]}
	if info.OutboundAllow, info.OutboundAllowFromConfig, err = c.outboundAllow(ctx); err != nil {
		return IngressInfo{}, err
	}
	p, err := c.project(ctx)
	if err != nil {
		return IngressInfo{}, err
	}
	for _, f := range p.Files {
		if filepath.Base(f) == "docker-compose.caddy.yml" {
			info.Caddy = true
		}
	}
	bind, port := env["BIND_ADDRESS"], env["VARLATCH_WEB_PORT"]
	if bind == "" {
		bind = "127.0.0.1"
	}
	if port == "" {
		port = "8787"
	}
	info.WebAddress = net.JoinHostPort(bind, port)
	return info, nil
}

// ingressService is the Compose service that serves the address, by
// shape: Caddy for public ingress, the dashboard for an own proxy.
func ingressService(kind Ingress) (string, error) {
	switch kind {
	case Public:
		return "caddy", nil
	case Proxy:
		return "varlatch-web", nil
	}
	return "", fmt.Errorf("the %s shape has no service of this host's to stop or start", kind)
}

// StopIngress is `docker compose stop` of the service that serves the
// address (idempotent).
func (c *Compose) StopIngress(ctx context.Context, kind Ingress) error {
	return c.ingress(ctx, []string{"stop"}, kind)
}

// StartIngress is `docker compose up -d --no-deps` of it, recreating it
// (--force-recreate) unless its container serves (containerServes), and
// always with recreate. A start that failed (its port held, 7.8b
// rehearsal run r13) leaves the container with no network, which `docker
// compose start` reuses: the dashboard then cannot resolve varlatchd and
// never answers. Such a container can still be running (Caddy resolves
// its upstream per request, so it runs and answers 502), or be caught
// running between restarts. Both services are stateless (the dashboard is
// nginx in front of varlatchd; Caddy keeps its certificates in its
// volumes), and the new container comes from the same Compose project, so
// recreating changes nothing of the installation. One that serves is left
// as it is (a retry would otherwise kill a dashboard still starting, or
// drop Caddy's connections). --no-deps: the services they depend on run
// already, and varlatch-migrate's one-off is not run again.
func (c *Compose) StartIngress(ctx context.Context, kind Ingress, recreate bool) error {
	svc, err := ingressService(kind)
	if err != nil {
		return err
	}
	if !recreate {
		serves, err := c.containerServes(ctx, svc)
		if err != nil {
			return err
		}
		if serves {
			return c.ingress(ctx, []string{"up", "-d", "--no-deps"}, kind)
		}
	}
	return c.ingress(ctx, []string{"up", "-d", "--no-deps", "--force-recreate"}, kind)
}

// containerFormat is what containerServes reads of a container.
const containerFormat = "{{.State.Status}} {{.State.Restarting}} {{.RestartCount}} {{len .NetworkSettings.Networks}}"

// containerServes reports whether the service's one container is running,
// not restarting, never restarted by its restart policy (a crash loop can
// be caught running), and attached to a network. Anything else, or what
// Docker cannot say, is a container to recreate.
func (c *Compose) containerServes(ctx context.Context, svc string) (bool, error) {
	r, err := c.docker(ctx, []string{"compose", "ps", "-a", "-q", svc}, nil)
	if err != nil {
		return false, err
	}
	ids := strings.Fields(string(r.Answer))
	if r.Code != 0 || len(ids) != 1 {
		return false, nil
	}
	r, err = c.docker(ctx, []string{"inspect", "--format", containerFormat, ids[0]}, nil)
	if err != nil {
		return false, err
	}
	f := strings.Fields(string(r.Answer))
	return r.Code == 0 && len(f) == 4 && f[0] == "running" && f[1] == "false" && f[2] == "0" && f[3] != "0", nil
}

func (c *Compose) ingress(ctx context.Context, verb []string, kind Ingress) error {
	svc, err := ingressService(kind)
	if err != nil {
		return err
	}
	args := append(append([]string{"compose"}, verb...), svc)
	r, err := c.docker(ctx, args, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("docker "+strings.Join(args, " "), r)
	}
	return nil
}

// RootKEK reads the source's Root KEK file.
func (c *Compose) RootKEK() ([]byte, error) {
	p, err := c.kekPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("the source's Root KEK file: %w", err)
	}
	return b, nil
}

// archiveCreated is the TypeScript CLI's line for a new archive.
var archiveCreated = regexp.MustCompile(`(?m)^Archive created: .* \(([0-9a-f-]{36})\)$`)

func (c *Compose) backupArgs(verb string) ([]string, error) {
	kek, err := c.kekPath()
	if err != nil {
		return nil, err
	}
	if c.BEKFile == "" || c.Destination == "" {
		return nil, errors.New("the preflight's backup needs --bek-file and --backup-destination")
	}
	args := []string{"admin", "backup", verb, "--dir", c.Directory, "--bek-file", c.BEKFile, "--kek-file", kek, "--destination", c.Destination}
	if c.DestinationsFile != "" {
		args = append(args, "--destinations-file", c.DestinationsFile)
	}
	return args, nil
}

func (c *Compose) tsCLI() string {
	if c.TSCLI == "" {
		return "varlatch-ts"
	}
	return c.TSCLI
}

// Backup makes a fresh backup and uploads it (the TypeScript CLI's
// `admin backup create --destination`).
func (c *Compose) Backup(ctx context.Context) (string, error) {
	args, err := c.backupArgs("create")
	if err != nil {
		return "", err
	}
	r, err := c.runTS(ctx, args)
	if err != nil {
		return "", err
	}
	if r.Code != 0 {
		return "", failure(c.tsCLI()+" admin backup create", r)
	}
	m := archiveCreated.FindSubmatch(r.Answer)
	if m == nil || !bytes.Contains(r.Answer, []byte("Upload completed to ")) {
		return "", errors.New("the backup was not both created and uploaded")
	}
	return string(m[1]), nil
}

// VerifyBackup downloads the archive and verifies it (`admin backup
// verify --destination --archive --record`).
func (c *Compose) VerifyBackup(ctx context.Context, archive string) error {
	if c.ReadCredentialsFile == "" {
		return errors.New("verifying the backup downloads it: give --read-credentials-file")
	}
	args, err := c.backupArgs("verify")
	if err != nil {
		return err
	}
	args = append(args, "--archive", archive, "--read-credentials-file", c.ReadCredentialsFile, "--record")
	r, err := c.runTS(ctx, args)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure(c.tsCLI()+" admin backup verify", r)
	}
	var v struct {
		ArchiveID     string `json:"archiveId"`
		Integrity     bool   `json:"integrity"`
		Compatibility bool   `json:"compatibility"`
		KeyMatch      bool   `json:"keyMatch"`
	}
	if err := json.Unmarshal(lastLine(r.Answer), &v); err != nil || v.ArchiveID != archive || !v.Integrity || !v.Compatibility || !v.KeyMatch {
		return errors.New("the downloaded archive's checks did not all pass")
	}
	return nil
}

// Barrier opens (or continues) the barrier and drains it.
func (c *Compose) Barrier(ctx context.Context, drain time.Duration) (BarrierRecord, error) {
	seconds := int(drain / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	r, err := c.admin(ctx, []string{"migration", "barrier", "--drain-seconds", fmt.Sprint(seconds)}, nil)
	if err != nil {
		return BarrierRecord{}, err
	}
	if r.Code != 0 {
		return BarrierRecord{}, failure("the source's migration barrier", r)
	}
	var b struct {
		Gate    Gate `json:"gate"`
		Drained struct {
			Ms int64 `json:"ms"`
		} `json:"drained"`
		Frozen struct {
			AuditPosition string  `json:"auditPosition"`
			At            string  `json:"at"`
			Snapshot      *string `json:"snapshot"`
		} `json:"frozen"`
	}
	if err := json.Unmarshal(lastLine(r.Answer), &b); err != nil || b.Gate.ID == "" || b.Frozen.AuditPosition == "" {
		return BarrierRecord{}, errors.New("the source's migration barrier did not answer with its gate and frozen point")
	}
	rec := BarrierRecord{GateID: b.Gate.ID, AuditPosition: b.Frozen.AuditPosition, FrozenAt: b.Frozen.At, DrainedMs: b.Drained.Ms}
	if b.Frozen.Snapshot != nil {
		rec.Snapshot = *b.Frozen.Snapshot
	}
	return rec, nil
}

// Export is the source bundle, written on this host into the
// installation's backups directory under a new name, mode 0600 and owned
// as that directory is: the export writes it to its standard output
// (--out -), the run key on its standard input, so the container's user
// never writes the operator's directory. Its path on this host.
func (c *Compose) Export(ctx context.Context, runKey []byte, dryRun bool) (string, error) {
	return c.export(ctx, runKey, dryRun, func(args ...string) []string {
		return append([]string{"compose", "exec", "-T", service, "node", "dist/cli.js", "admin"}, args...)
	})
}

// ExportSummaryPrefix starts the last line of the export's standard error
// when it writes the bundle to its standard output: its summary, as JSON.
const ExportSummaryPrefix = "varlatch-export-summary: "

// export runs the export with the command prefix gives (exec into the
// running daemon's container, or a one-off one), into a new name in the
// installation's backups directory (receiveBundle).
func (c *Compose) export(ctx context.Context, runKey []byte, dryRun bool, prefix func(...string) []string) (string, error) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	backups := filepath.Join(c.Directory, "backups")
	host := filepath.Join(backups, "migration-"+hex.EncodeToString(suffix)+".jsonl")
	args := []string{"migration", "export", "--out", "-", "--digests"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	err := receiveBundle(ctx, "the source's migration export", host, runKey, func(ctx context.Context, in io.Reader, out io.Writer) (Ran, error) {
		return c.stream(ctx, prefix(args...), in, out)
	})
	if err != nil {
		return "", err
	}
	return host, nil
}

// receiveBundle runs an export that writes its bundle on its standard
// output (the last TypeScript release's `admin migration export --out -`),
// the run key line on its input, into path on this host: mode 0600, owned
// as path's directory is when this process is root. The bundle streams
// into a .partial beside path, never held in memory, and is renamed to
// path only once the export ended with status 0 and its summary (the last
// line of its standard error, ExportSummaryPrefix and a JSON object); the
// rename is then made durable. Anything else removes the .partial: a
// killed run leaves only it (CleanLeftovers, the converter's scratch), and
// never a bundle. what names the export in its failure.
func receiveBundle(ctx context.Context, what, path string, runKey []byte, run func(ctx context.Context, in io.Reader, out io.Writer) (Ran, error)) error {
	dir := filepath.Dir(path)
	partial := path + ".partial"
	out, err := createOwned(partial, dir)
	if err != nil {
		return fmt.Errorf("the bundle in %s: %w", dir, err)
	}
	key := RunKeyText(runKey)
	defer clear(key)
	r, err := run(ctx, bytes.NewReader(key), out)
	if serr := out.Sync(); err == nil && serr != nil {
		err = serr
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err == nil && r.Code != 0 {
		err = failure(what, r)
	}
	if err == nil && !exportSummary(r.Said) {
		err = fmt.Errorf("%s ended without its summary: the bundle it wrote is not taken", what)
	}
	if err == nil {
		err = os.Rename(partial, path)
	}
	if err != nil {
		_ = os.Remove(partial)
		return err
	}
	// The rename made durable, as writeJournal's is: the bundle the
	// journal will name is there after a crash.
	if err := syncDir(dir); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// syncDir makes a directory's entries durable (a rename into it).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// exportSummary is whether said (the export's standard error) ends with
// its summary line: the prefix, then a JSON object.
func exportSummary(said []byte) bool {
	line, ok := bytes.CutPrefix(lastLine(said), []byte(ExportSummaryPrefix))
	return ok && len(line) > 0 && line[0] == '{' && json.Valid(line)
}

// createOwned creates path (it must not exist), mode 0600, owned as dir is
// when this process is root (dir is the operator's: setup makes it 0700).
func createOwned(path, dir string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if os.Getuid() == 0 {
		// As root the file must be the directory's owner's: a directory
		// whose owner cannot be read is refused, never a root-owned file.
		st, err := os.Stat(dir)
		var uid, gid uint32
		ok := false
		if err == nil {
			uid, gid, ok = ownerOf(st)
			if !ok {
				err = fmt.Errorf("the owner of %s cannot be read", dir)
			}
		}
		if err == nil {
			err = f.Chown(int(uid), int(gid))
		}
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, err
		}
	}
	return f, nil
}

// leftoverBundle is a bundle Export names (and the export's .partial).
var leftoverBundle = regexp.MustCompile(`^migration-[0-9a-f]{12}\.jsonl(\.partial)?$`)

// CleanLeftovers removes the bundles a killed run left in the
// installation's backups directory (an export's .partial, a bundle not
// yet removed): Export's names only, regular files only.
func (c *Compose) CleanLeftovers() error {
	return removeMatching(filepath.Join(c.Directory, "backups"), leftoverBundle, false)
}

// Release lifts the barrier.
func (c *Compose) Release(ctx context.Context, gateID string) error {
	r, err := c.admin(ctx, []string{"migration", "release", "--id", gateID}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("the source's migration release", r)
	}
	return nil
}

// MarkMigratedOut makes the barrier the permanent migrated-out gate.
func (c *Compose) MarkMigratedOut(ctx context.Context, gateID string) error {
	r, err := c.admin(ctx, []string{"migration", "mark-migrated-out", "--id", gateID}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("the source's migration mark-migrated-out", r)
	}
	return nil
}
