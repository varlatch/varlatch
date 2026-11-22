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
// migration's source (go-step7 decision 20): found by its
// docker-compose.yml in Directory; driven with `docker compose exec` into its
// varlatchd service (the image's `node dist/cli.js admin migration ...`,
// slices 7.2a and 7.2b) and with the TypeScript host CLI for its backup.
type Compose struct {
	// Directory is the installation's Compose directory.
	Directory string
	// Run runs docker and the TypeScript CLI.
	Run Runner
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
}

// service is the source's varlatchd service in its Compose file.
const service = "varlatchd"

func (c *Compose) Dir() string { return c.Directory }

func (c *Compose) docker(ctx context.Context, args []string, stdin []byte) (Ran, error) {
	return c.Run.Run(ctx, c.Directory, c.dockerName(), args, stdin)
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
	return s.Stream(ctx, c.Directory, c.dockerName(), args, in, out)
}

// admin runs the source's `admin migration` (or another admin command)
// inside its varlatchd container.
func (c *Compose) admin(ctx context.Context, args []string, stdin []byte) (Ran, error) {
	full := append([]string{"compose", "exec", "-T", service, "node", "dist/cli.js", "admin"}, args...)
	return c.docker(ctx, full, stdin)
}

// Discover finds the installation: its docker-compose.yml, and its
// varlatchd service's image, by its release (the image's version label,
// else its tag) and its digest (the registry's, which a published release
// has).
func (c *Compose) Discover(ctx context.Context) (SourceInfo, error) {
	info := SourceInfo{Kind: "compose", Dir: c.Directory}
	if st, err := os.Stat(filepath.Join(c.Directory, "docker-compose.yml")); err != nil || !st.Mode().IsRegular() {
		return info, fmt.Errorf("%s holds no docker-compose.yml: --from names a Compose installation's directory", c.Directory)
	}
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
// public URL (VARLATCH_PUBLIC_URL), the Caddy overlay in COMPOSE_FILE
// (public ingress), and the dashboard's published address
// (BIND_ADDRESS:VARLATCH_WEB_PORT, 127.0.0.1:8787 by default).
func (c *Compose) Ingress(context.Context) (IngressInfo, error) {
	env, err := c.envFile()
	if err != nil {
		return IngressInfo{}, err
	}
	info := IngressInfo{PublicURL: env["VARLATCH_PUBLIC_URL"]}
	for _, f := range strings.Split(env["COMPOSE_FILE"], string(os.PathListSeparator)) {
		if filepath.Base(strings.TrimSpace(f)) == "docker-compose.caddy.yml" {
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
	return c.ingress(ctx, "stop", kind)
}

// StartIngress is `docker compose start` of it.
func (c *Compose) StartIngress(ctx context.Context, kind Ingress) error {
	return c.ingress(ctx, "start", kind)
}

func (c *Compose) ingress(ctx context.Context, verb string, kind Ingress) error {
	svc, err := ingressService(kind)
	if err != nil {
		return err
	}
	r, err := c.docker(ctx, []string{"compose", verb, svc}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return failure("docker compose "+verb+" "+svc, r)
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
	r, err := c.Run.Run(ctx, c.Directory, c.tsCLI(), args, nil)
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
	r, err := c.Run.Run(ctx, c.Directory, c.tsCLI(), args, nil)
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
// running daemon's container, or a one-off one). The bundle streams into
// a .partial beside its name, renamed to it only once the export ended
// with status 0 and its summary: a killed run leaves the .partial, which
// CleanLeftovers removes, and never a bundle.
func (c *Compose) export(ctx context.Context, runKey []byte, dryRun bool, prefix func(...string) []string) (string, error) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	backups := filepath.Join(c.Directory, "backups")
	host := filepath.Join(backups, "migration-"+hex.EncodeToString(suffix)+".jsonl")
	partial := host + ".partial"
	out, err := createOwned(partial, backups)
	if err != nil {
		return "", fmt.Errorf("the bundle in the installation's backups directory: %w", err)
	}
	args := []string{"migration", "export", "--out", "-", "--digests"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	key := RunKeyText(runKey)
	defer clear(key)
	r, err := c.stream(ctx, prefix(args...), bytes.NewReader(key), out)
	if serr := out.Sync(); err == nil && serr != nil {
		err = serr
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err == nil && r.Code != 0 {
		err = failure("the source's migration export", r)
	}
	if err == nil && !exportSummary(r.Said) {
		err = errors.New("the source's migration export ended without its summary: the bundle it wrote is not taken")
	}
	if err == nil {
		err = os.Rename(partial, host)
	}
	if err != nil {
		_ = os.Remove(partial)
		return "", err
	}
	// The rename made durable, as writeJournal's is: the bundle the
	// journal will name is there after a crash.
	if err := syncDir(backups); err != nil {
		_ = os.Remove(host)
		return "", err
	}
	return host, nil
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
