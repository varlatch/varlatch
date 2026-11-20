// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bufio"
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
	name := c.Docker
	if name == "" {
		name = "docker"
	}
	return c.Run.Run(ctx, c.Directory, name, args, stdin)
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
	for _, d := range inspect.RepoDigests {
		if at := strings.LastIndex(d, "@"); at >= 0 && strings.HasPrefix(d[at+1:], "sha256:") {
			info.Digest = d[at+1:]
			break
		}
	}
	return info, nil
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

// kekPath is the source's Root KEK file on this host: KEKFile, else .env's
// VARLATCH_KEK_HOST_PATH (relative to Directory), else secrets/varlatch-kek, as
// the Compose file has it.
func (c *Compose) kekPath() (string, error) {
	if c.KEKFile != "" {
		return c.KEKFile, nil
	}
	p := filepath.Join(c.Directory, "secrets", "varlatch-kek")
	env, err := os.ReadFile(filepath.Join(c.Directory, ".env"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(env))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "VARLATCH_KEK_HOST_PATH="); ok {
			v = strings.Trim(v, `"'`)
			if v != "" {
				p = v
				if !filepath.IsAbs(p) {
					p = filepath.Join(c.Directory, p)
				}
			}
		}
	}
	return p, nil
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

// Export writes the source bundle into the installation's backups
// directory (the Compose file's ./backups, /backups in the container),
// under a new name, the run key on the export's stdin; its path on this
// host.
func (c *Compose) Export(ctx context.Context, runKey []byte, dryRun bool) (string, error) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	name := "migration-" + hex.EncodeToString(suffix) + ".jsonl"
	args := []string{"migration", "export", "--out", "/backups/" + name, "--digests"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	key := RunKeyText(runKey)
	defer clear(key)
	r, err := c.admin(ctx, args, key)
	host := filepath.Join(c.Directory, "backups", name)
	if err != nil {
		_ = os.Remove(host)
		return "", err
	}
	if r.Code != 0 {
		_ = os.Remove(host)
		return "", failure("the source's migration export", r)
	}
	if st, err := os.Stat(host); err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("the export wrote no bundle at %s", host)
	}
	return host, nil
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
