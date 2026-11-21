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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// The backup converter (go-step7 decision 18, slice 7.7b): `varlatch
// migrate --from-archive` turns a TypeScript archive (format 1 or 2) into a
// format 3 archive of the same installation, by the migration's own path:
//
//  1. The archive is opened with the Backup Encryption Key (authenticated
//     whole before any of it is read) and the Root KEK must open its
//     canaries. A wrong key, a Go archive or a damaged one is refused here,
//     before any container exists or anything is written but the scratch
//     copy, which is removed.
//  2. An isolated restore: a throwaway PostgreSQL (pinned by digest) with no
//     network (--network none), the archive's Secret Plane restored into it
//     as the TypeScript restore does, then the last TypeScript release's
//     image (pinned by digest) in that PostgreSQL's network namespace, so
//     the loopback is all it has: its `migrate` (an older archive's schema
//     brought to the release's), its `admin migration backfill` (the
//     exposure index an archive from before 0.20.0 lacks, built once, as
//     the daemon's backfill would) and its `admin migration export
//     --dry-run --digests`, the run key on its stdin. Never its daemon: no
//     worker loop starts and nothing is sent. Both containers are removed.
//  3. varlatchd, as a process, on a scratch data directory: `admin migrate
//     import`, `admin migrate check` (every check must pass), `admin backup
//     run`, whose archive becomes the output. The installation's identifier
//     and its key requirement are the archive's.

// PostgresImage is the throwaway PostgreSQL: the major the TypeScript
// release supports (release.json supportedPostgresMajor, 17), its Compose
// file's 17.6, by its index digest.
const PostgresImage = "postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929"

// pinnedImage is an image by its registry digest (name@sha256:...).
var pinnedImage = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// localImage is a local image's ID (sha256:...): an image built on this
// host, as the tests' and the nightly run's are. Taken only with
// AllowLocalImage (VARLATCH_ALLOW_LOCAL_TS_IMAGE=1), and said.
var localImage = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// leftover names what an interrupted conversion leaves in its scratch
// root: its working directory.
var leftover = regexp.MustCompile(`^varlatch-convert-[0-9]+$`)

// partialOut names the copy place writes beside --out before it links it.
var partialOut = regexp.MustCompile(`^\.varlatch-convert-[0-9]+\.partial$`)

// sweepFiles removes what a killed conversion left in dir: directories
// (dirs) or regular files named by names, never a symbolic link. One it
// may not remove (another user's) is left, with a warning.
func sweepFiles(dir string, names *regexp.Regexp, dirs bool, say func(string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !names.MatchString(e.Name()) || (dirs && !e.Type().IsDir()) || (!dirs && !e.Type().IsRegular()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		var err error
		if dirs {
			err = os.RemoveAll(p)
		} else {
			err = os.Remove(p)
		}
		if err != nil {
			say(fmt.Sprintf("Warning: %s, an interrupted conversion's leftover, could not be removed: %v", p, err))
		}
	}
}

// DefaultTSImage is the last TypeScript release's image, once its digest
// is published (sides.go); "" until then, when --ts-image is required.
func DefaultTSImage() string {
	if LastTypeScriptDigest == "" {
		return ""
	}
	return LastTypeScriptRepository + "@" + LastTypeScriptDigest
}

// ArchiveOptions is one conversion.
type ArchiveOptions struct {
	// Archive is the TypeScript archive; Out the format 3 archive to write
	// (it must not exist).
	Archive, Out string
	// KEKFile is the Root KEK file; BEKFile the Backup Encryption Key file
	// (a key or a passphrase); OutBEKFile, when set, the key file the output
	// is sealed with (required when BEKFile holds a passphrase: varlatchd
	// seals with a key file only).
	KEKFile, BEKFile, OutBEKFile string
	// TSImage is the last TypeScript release's image, by digest;
	// PostgresImage the throwaway PostgreSQL ("" for the pinned one).
	TSImage, PostgresImage string
	// Varlatchd is the varlatchd program.
	Varlatchd string
	// Scratch is where the working directory is made ("" for the system's).
	Scratch string
	// Docker is the docker program ("" for "docker"); Run runs it and
	// Varlatchd's commands (VarlatchdRun, when set, runs varlatchd).
	Docker            string
	Run, VarlatchdRun Runner
	// User is the user the export runs as in its container ("uid:gid", so
	// it can write the scratch directory); "" for this process's.
	User string
	// AllowLocalImage lets TSImage be a local image's ID (sha256:...), not
	// only a registry digest: the tests' and the nightly run's own builds.
	AllowLocalImage bool
	// LockDir is where the conversion's host-wide lock is ("" for
	// /run/lock when this user may write it, else /tmp, whatever TMPDIR
	// says): one conversion at a time on a host, so the sweep of an
	// interrupted one's leftovers never touches a running one's.
	LockDir string
	Say     func(string)
}

// ArchiveResult is what a conversion did.
type ArchiveResult struct {
	Source struct {
		ArchiveID           string `json:"archiveId"`
		Format              int    `json:"format"`
		Release             string `json:"release"`
		InstallationID      string `json:"installationId"`
		RequiredKeyVersions []int  `json:"requiredKeyVersions"`
	} `json:"source"`
	Copy   CopyRecord   `json:"copy"`
	Checks CheckSummary `json:"checks"`
	Output struct {
		ArchiveID string `json:"archiveId"`
		Path      string `json:"path"`
		Bytes     int64  `json:"bytes"`
	} `json:"output"`
	// CleanupIncomplete is set, with or without an error, when a container
	// or the scratch directory could not be removed: the next conversion
	// sweeps what is left.
	CleanupIncomplete bool `json:"cleanupIncomplete,omitempty"`
}

// ErrArchive is a refusal before anything was written.
type ErrArchive struct{ msg string }

func (e *ErrArchive) Error() string { return e.msg }

func refuse(format string, args ...any) error { return &ErrArchive{fmt.Sprintf(format, args...)} }

// archiveKeys are the conversion's keys, read from their files.
type archiveKeys struct {
	rootKEK []byte
	bek     backup.BEK
	// outBEKFile is the key file the output is sealed with.
	outBEKFile string
}

func (k *archiveKeys) clear() {
	clear(k.rootKEK)
	k.bek.Clear()
}

// readKeys reads the three key files, refusing what cannot convert: a Root
// KEK that is not one, a BEK that is neither a key nor a passphrase, an
// output key that is not a key file, a BEK or output key that is the Root
// KEK.
func readKeys(o ArchiveOptions) (*archiveKeys, error) {
	raw, err := os.ReadFile(o.KEKFile)
	if err != nil {
		return nil, refuse("the Root KEK file: %v", err)
	}
	k := &archiveKeys{}
	k.rootKEK, err = envelope.ParseRootKEK(string(raw))
	clear(raw)
	if err != nil {
		return nil, refuse("the Root KEK file %s holds no Root KEK", o.KEKFile)
	}
	raw, err = os.ReadFile(o.BEKFile)
	if err != nil {
		k.clear()
		return nil, refuse("the Backup Encryption Key file: %v", err)
	}
	key, keyErr := backup.ParseKey(string(raw))
	if keyErr == nil {
		k.bek, err = backup.KeyBEK(key)
		clear(key)
	} else {
		// A passphrase: the file's text, as the TypeScript CLI reads it (a
		// final newline removed).
		k.bek, err = backup.PassphraseBEK(bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r")))
	}
	clear(raw)
	if err != nil {
		k.clear()
		return nil, refuse("the Backup Encryption Key file %s holds neither a 32-byte key nor a passphrase of at least 12 characters", o.BEKFile)
	}
	if err := backup.DistinctKeys(k.bek, k.rootKEK); err != nil {
		k.clear()
		return nil, refuse("%v", err)
	}
	switch {
	case o.OutBEKFile != "":
		k.outBEKFile = o.OutBEKFile
	case keyErr == nil:
		k.outBEKFile = o.BEKFile
	default:
		k.clear()
		return nil, refuse("the Backup Encryption Key %s is a passphrase: it opens the archive, but varlatchd seals with a key file; give --out-bek-file (32 bytes, hex or base64)", o.BEKFile)
	}
	// A key file given for the output is checked even when it is the BEK's
	// own file: a passphrase there is no key.
	if o.OutBEKFile != "" {
		raw, err := os.ReadFile(k.outBEKFile)
		if err != nil {
			k.clear()
			return nil, refuse("the output's Backup Encryption Key file: %v", err)
		}
		out, err := backup.ParseKey(string(raw))
		clear(raw)
		if err != nil {
			k.clear()
			return nil, refuse("the output's Backup Encryption Key file %s holds no 32-byte key", k.outBEKFile)
		}
		outBEK, _ := backup.KeyBEK(out)
		clear(out)
		err = backup.DistinctKeys(outBEK, k.rootKEK)
		outBEK.Clear()
		if err != nil {
			k.clear()
			return nil, refuse("%v", err)
		}
	}
	return k, nil
}

// releaseVersion is a TypeScript manifest's release record's version.
func releaseVersion(raw json.RawMessage) string {
	var r struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.Version
}

// ConvertArchive converts o.Archive (see the comment at the top).
func ConvertArchive(ctx context.Context, o ArchiveOptions) (res ArchiveResult, _ error) {
	say := o.Say
	if say == nil {
		say = func(string) {}
	}
	tsImage := o.TSImage
	if tsImage == "" {
		tsImage = DefaultTSImage()
	}
	pgImage := o.PostgresImage
	if pgImage == "" {
		pgImage = PostgresImage
	}
	switch {
	case tsImage == "":
		return res, refuse("give --ts-image: the last TypeScript release's image (%s %s), by its digest (name@sha256:...), until this varlatch carries it", LastTypeScriptRepository, LastTypeScriptRelease)
	case localImage.MatchString(tsImage) && !o.AllowLocalImage, !localImage.MatchString(tsImage) && !pinnedImage.MatchString(tsImage):
		return res, refuse("--ts-image %q is not pinned by its registry digest (name@sha256:<64 hex>): the converter runs one exact image", tsImage)
	case !pinnedImage.MatchString(pgImage):
		return res, refuse("the PostgreSQL image %q is not pinned by digest", pgImage)
	case o.Out == "":
		return res, refuse("give --out, the format 3 archive to write")
	}
	if _, err := os.Lstat(o.Out); err == nil {
		return res, refuse("%s exists: the converter writes a new archive", o.Out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return res, refuse("%s: %v", o.Out, err)
	}
	if localImage.MatchString(tsImage) {
		say("Warning: --ts-image is a local image ID, not the published release's registry digest (VARLATCH_ALLOW_LOCAL_TS_IMAGE is set): for tests only.")
	}
	keys, err := readKeys(o)
	if err != nil {
		return res, err
	}
	defer keys.clear()

	// One conversion at a time on this host; then what an interrupted one
	// left in the scratch root goes (its containers, once the archive has
	// opened: no program runs before that).
	lockDir := o.LockDir
	if lockDir == "" {
		lockDir = defaultLockDir()
	}
	unlock, err := lockConversion(lockDir)
	if err != nil {
		return res, refuse("%v", err)
	}
	defer unlock()
	scratchRoot := o.Scratch
	if scratchRoot == "" {
		scratchRoot = os.TempDir()
	}
	sweepFiles(scratchRoot, leftover, true, say)
	// A copy being placed beside --out when a conversion was killed.
	sweepFiles(filepath.Dir(o.Out), partialOut, false, say)

	work, err := os.MkdirTemp(o.Scratch, "varlatch-convert-")
	if err != nil {
		return res, err
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			res.CleanupIncomplete = true
		}
	}()

	// 1. The archive, opened and its keys checked, before any container.
	opened, err := backup.Open(o.Archive, keys.bek, work)
	if err != nil {
		var be *backup.Error
		if errors.As(err, &be) {
			return res, refuse("%s: %v", o.Archive, err)
		}
		return res, refuse("%s cannot be opened: %v", o.Archive, err)
	}
	defer opened.Close()
	m := opened.Manifest
	if m.FormatVersion != backup.FormatTSBothPlanes && m.FormatVersion != backup.FormatTSSecretPlane {
		return res, refuse("%s is a varlatchd archive (format %d): restore it with varlatchd admin backup restore; the converter takes the TypeScript server's (format 1 or 2)", o.Archive, m.FormatVersion)
	}
	candidates := map[int][]byte{}
	for _, v := range m.RequiredKeyVersions {
		candidates[v] = keys.rootKEK
	}
	if !backup.CheckKeys(m, candidates) {
		return res, refuse("the Root KEK in %s does not open the archive's canaries: it is not this installation's key (archive %s, installation %s)", o.KEKFile, m.ArchiveID, m.InstallationID)
	}
	res.Source.ArchiveID, res.Source.Format, res.Source.InstallationID = m.ArchiveID, int(m.FormatVersion), m.InstallationID
	res.Source.Release, res.Source.RequiredKeyVersions = releaseVersion(m.Release), m.RequiredKeyVersions
	say(fmt.Sprintf("Opened archive %s (format %d, release %s, installation %s); its Root KEK canaries open.", m.ArchiveID, m.FormatVersion, res.Source.Release, m.InstallationID))

	// 2. The isolated restore and the export.
	runKey := make([]byte, 32)
	if _, err := rand.Read(runKey); err != nil {
		return res, err
	}
	defer clear(runKey)
	iso := &isolation{docker: o.Docker, run: o.Run, pgImage: pgImage, tsImage: tsImage, user: o.User, say: say}
	defer func() {
		if iso.cleanupFailed {
			res.CleanupIncomplete = true
		}
	}()
	if iso.docker == "" {
		iso.docker = "docker"
	}
	if err := iso.sweep(ctx); err != nil {
		return res, err
	}
	if iso.user == "" {
		iso.user = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	bundleDir := filepath.Join(work, "bundle")
	if err := os.Mkdir(bundleDir, 0o700); err != nil {
		return res, err
	}
	kekFile, err := filepath.Abs(o.KEKFile)
	if err != nil {
		return res, err
	}
	bundle, err := iso.export(ctx, opened.Path("secret-plane.dump"), kekFile, bundleDir, runKey)
	if err != nil {
		return res, err
	}

	// 3. varlatchd: import, check, back up.
	dataDir := filepath.Join(work, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		return res, err
	}
	outBEK, err := filepath.Abs(keys.outBEKFile)
	if err != nil {
		return res, err
	}
	conf := filepath.Join(work, "varlatchd.conf")
	text := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n", dataDir, kekFile, outBEK)
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		return res, err
	}
	runV := o.VarlatchdRun
	if runV == nil {
		runV = o.Run
	}
	h := &Host{Varlatchd: o.Varlatchd, Config: conf, Run: runV}
	say("Importing into a scratch varlatchd data directory.")
	if res.Copy, err = h.Import(ctx, bundle, ""); err != nil {
		return res, err
	}
	if res.Copy.InstallationID != m.InstallationID {
		return res, fmt.Errorf("the import made installation %s from archive %s of installation %s", res.Copy.InstallationID, m.ArchiveID, m.InstallationID)
	}
	say("Checking the import against the bundle.")
	if res.Checks, err = h.Check(ctx, bundle, "", runKey); err != nil {
		return res, err
	}
	if !res.Checks.Passed {
		return res, fmt.Errorf("the migration's checks failed: %s", strings.Join(res.Checks.Faults, "; "))
	}
	say("Sealing the format 3 archive.")
	r, err := runV.Run(ctx, "", o.Varlatchd, []string{"admin", "backup", "run", "--json", "--config", conf}, nil)
	if err != nil {
		return res, err
	}
	if r.Code != 0 {
		return res, failure("varlatchd admin backup run", r)
	}
	var run struct {
		ArchiveID string `json:"archiveId"`
		Path      string `json:"path"`
		Bytes     int64  `json:"bytes"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(r.Answer), &run); err != nil || run.ArchiveID == "" || run.Path == "" {
		return res, errors.New("varlatchd admin backup run did not answer in JSON")
	}
	var record backup.StatusRecord
	if raw, err := os.ReadFile(filepath.Join(dataDir, "backups", run.ArchiveID+".json")); err != nil || json.Unmarshal(raw, &record) != nil {
		return res, fmt.Errorf("the new archive %s has no status record", run.ArchiveID)
	}
	if record.InstallationID != m.InstallationID || !equalInts(record.RequiredKeyVersions, m.RequiredKeyVersions) {
		return res, fmt.Errorf("the new archive %s is of installation %s needing key versions %v, not the archive's %s and %v",
			run.ArchiveID, record.InstallationID, record.RequiredKeyVersions, m.InstallationID, m.RequiredKeyVersions)
	}
	if err := place(run.Path, o.Out); err != nil {
		return res, err
	}
	res.Output.ArchiveID, res.Output.Path, res.Output.Bytes = run.ArchiveID, o.Out, run.Bytes
	return res, nil
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// place moves the archive to out, which must not exist: a link where the
// two share a file system (it fails if out appeared meanwhile), a copy
// written beside out and linked into place otherwise. Made durable.
func place(from, out string) error {
	if err := os.Link(from, out); err == nil {
		return backup.SyncDir(filepath.Dir(out))
	}
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(out), ".varlatch-convert-*.partial")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), out); err != nil {
		return fmt.Errorf("the archive could not be placed at %s: %w", out, err)
	}
	return backup.SyncDir(filepath.Dir(out))
}

// isolation is the converter's two containers.
type isolation struct {
	docker, pgImage, tsImage, user string
	run                            Runner
	say                            func(string)
	// cleanupFailed: a container it started could not be removed.
	cleanupFailed bool
}

func (i *isolation) do(ctx context.Context, what string, args []string, stdin []byte) (Ran, error) {
	r, err := i.run.Run(ctx, "", i.docker, args, stdin)
	if err != nil {
		return r, err
	}
	if r.Code != 0 {
		return r, failure(what, r)
	}
	return r, nil
}

// quiet is do for PostgreSQL's own tools (psql, pg_restore), whose errors
// can quote a row's values: a failure names the step and its exit only.
func (i *isolation) quiet(ctx context.Context, what string, args []string, stdin []byte) error {
	r, err := i.run.Run(ctx, "", i.docker, args, stdin)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		return fmt.Errorf("%s failed (exit %d; PostgreSQL's own message is not shown: it can hold the archive's data)", what, r.Code)
	}
	return nil
}

// sweep removes the containers an interrupted conversion left (killed
// before its own cleanup ran): every container with the converter's
// label, by its exact ID. The host-wide lock makes them no running
// conversion's.
func (i *isolation) sweep(ctx context.Context) error {
	r, err := i.do(ctx, "listing an interrupted conversion's containers", []string{"ps", "-aq", "--filter", "label=varlatch.convert"}, nil)
	if err != nil {
		return err
	}
	ids := strings.Fields(string(r.Answer))
	if len(ids) == 0 {
		return nil
	}
	i.say(fmt.Sprintf("Removing %d container(s) an interrupted conversion left.", len(ids)))
	_, err = i.do(ctx, "removing an interrupted conversion's containers", append([]string{"rm", "-fv"}, ids...), nil)
	return err
}

// name is a container's: the converter's prefix and a random suffix, so
// nothing else's container is ever touched.
func name(role string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "varlatch-convert-" + hex.EncodeToString(b) + "-" + role, nil
}

// databaseURL is the TypeScript release's database as it sees it: the
// owning role, over the namespace's loopback (trust: no network exists).
const databaseURL = "postgres://varlatchd_migrate@127.0.0.1:5432/varlatch"

// startPostgres starts the throwaway PostgreSQL, with no network, and
// waits until it answers on its loopback; its name, already in started so
// the caller's cleanup removes it.
func (i *isolation) startPostgres(ctx context.Context, started *[]string) (string, error) {
	pg, err := name("postgres")
	if err != nil {
		return "", err
	}
	*started = append(*started, pg)
	i.say("Starting an isolated PostgreSQL (no network).")
	if _, err := i.do(ctx, "starting the isolated PostgreSQL", []string{"run", "-d", "--name", pg, "--network", "none",
		"--label", "varlatch.convert=postgres", "-e", "POSTGRES_HOST_AUTH_METHOD=trust", i.pgImage}, nil); err != nil {
		return "", err
	}
	// The image's init runs a server on its socket only; the TCP loopback
	// answers once the real one runs.
	for n := 0; n < 240; n++ {
		r, err := i.run.Run(ctx, "", i.docker, []string{"exec", pg, "psql", "-h", "127.0.0.1", "-U", "postgres", "-Atc", "SELECT 1"}, nil)
		if err != nil {
			return "", err
		}
		if r.Code == 0 && strings.TrimSpace(string(r.Answer)) == "1" {
			return pg, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return "", errors.New("the isolated PostgreSQL did not start within two minutes")
}

// inNamespace runs image (the last TypeScript release's) with cmd in pg's
// network namespace, so the loopback is all it has: read-only but for its
// /tmp and the mounts given, as i.user, no capability, removed when it
// ends. Its name goes in started first.
func (i *isolation) inNamespace(ctx context.Context, pg, image, role string, started *[]string, mounts, cmd []string, stdin []byte) (Ran, error) {
	args, err := i.namespaceArgs(pg, image, role, started, mounts, cmd, stdin != nil)
	if err != nil {
		return Ran{}, err
	}
	return i.run.Run(ctx, "", i.docker, args, stdin)
}

// inNamespaceStream is inNamespace on streams (Streamer): in on the
// container's standard input, its standard output to out as it writes it.
func (i *isolation) inNamespaceStream(ctx context.Context, pg, image, role string, started *[]string, mounts, cmd []string, in io.Reader, out io.Writer) (Ran, error) {
	s, ok := i.run.(Streamer)
	if !ok {
		return Ran{}, errors.New("this runner cannot stream a bundle")
	}
	args, err := i.namespaceArgs(pg, image, role, started, mounts, cmd, in != nil)
	if err != nil {
		return Ran{}, err
	}
	return s.Stream(ctx, "", i.docker, args, in, out)
}

// namespaceArgs is docker run's arguments for inNamespace (-i when the
// container is given an input).
func (i *isolation) namespaceArgs(pg, image, role string, started *[]string, mounts, cmd []string, input bool) ([]string, error) {
	n, err := name(role)
	if err != nil {
		return nil, err
	}
	*started = append(*started, n)
	args := []string{"run", "--rm", "--name", n, "--network", "container:" + pg, "--label", "varlatch.convert=" + role,
		"--read-only", "--tmpfs", "/tmp", "--user", i.user, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"-e", "VARLATCH_DATABASE_URL=" + databaseURL, "-e", "VARLATCH_STATE_DIR=/tmp/state", "-e", "HOME=/tmp"}
	args = append(args, mounts...)
	if input {
		args = append(args, "-i")
	}
	return append(append(args, image), cmd...), nil
}

// removeAll removes the containers named, with a fresh context, so a
// cancelled one still cleans up.
func (i *isolation) removeAll(started []string) {
	if len(started) == 0 {
		return
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := i.run.Run(cleanup, "", i.docker, append([]string{"rm", "-fv"}, started...), nil)
	if err != nil || r.Code != 0 {
		i.cleanupFailed = true
	}
}

// export restores dump into a throwaway PostgreSQL and runs the last
// TypeScript release's migrate, backfill and export against it, all with
// no network; the bundle's path. Every container it started is removed.
func (i *isolation) export(ctx context.Context, dump, kekFile, bundleDir string, runKey []byte) (string, error) {
	var started []string
	defer func() { i.removeAll(started) }()
	pg, err := i.startPostgres(ctx, &started)
	if err != nil {
		return "", err
	}
	// The TypeScript installation's roles (infra/compose/postgres-init),
	// then its restore: pg_restore as the superuser, objects owned by the
	// owning role (apps/cli backup.ts restoreInstallation).
	roles := "CREATE ROLE varlatchd_migrate LOGIN; CREATE ROLE varlatchd_runtime LOGIN;\n" +
		"CREATE DATABASE varlatch OWNER varlatchd_migrate;\nGRANT CONNECT ON DATABASE varlatch TO varlatchd_runtime;\n"
	if err := i.quiet(ctx, "creating the TypeScript installation's roles", []string{"exec", "-i", pg, "psql", "-h", "127.0.0.1", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"}, []byte(roles)); err != nil {
		return "", err
	}
	if _, err := i.do(ctx, "copying the Secret Plane's dump in", []string{"cp", dump, pg + ":/tmp/secret-plane.dump"}, nil); err != nil {
		return "", err
	}
	i.say("Restoring the Secret Plane.")
	if err := i.quiet(ctx, "restoring the Secret Plane (pg_restore)", []string{"exec", pg, "pg_restore", "-h", "127.0.0.1", "-U", "postgres",
		"--exit-on-error", "--no-owner", "--role", "varlatchd_migrate", "-d", "varlatch", "/tmp/secret-plane.dump"}, nil); err != nil {
		return "", err
	}
	if _, err := i.do(ctx, "removing the dump's copy", []string{"exec", pg, "rm", "-f", "/tmp/secret-plane.dump"}, nil); err != nil {
		return "", err
	}
	ts := func(role string, mounts, cmd []string, stdin []byte) error {
		r, err := i.inNamespace(ctx, pg, i.tsImage, role, &started, mounts, cmd, stdin)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("the TypeScript release's "+role, r)
		}
		return nil
	}
	i.say("Bringing the schema to the last TypeScript release's.")
	if err := ts("migrate", nil, []string{"migrate"}, nil); err != nil {
		return "", err
	}
	i.say("Building the exposure index, if the archive predates it.")
	if err := ts("backfill", nil, []string{"admin", "migration", "backfill"}, nil); err != nil {
		return "", err
	}
	// The bundle on the export's standard output (--out -), into the
	// conversion's own scratch on this host: no directory is shared with
	// the container's user, which writes nothing but its /tmp.
	i.say("Exporting the bundle.")
	mounts := []string{"-v", kekFile + ":/run/varlatch/root-kek:ro", "-e", "VARLATCH_KEK_FILE=/run/varlatch/root-kek"}
	cmd := []string{"admin", "migration", "export", "--out", "-", "--digests", "--dry-run"}
	bundle := filepath.Join(bundleDir, "bundle.jsonl")
	err = receiveBundle(ctx, "the TypeScript release's export", bundle, runKey, func(ctx context.Context, in io.Reader, out io.Writer) (Ran, error) {
		return i.inNamespaceStream(ctx, pg, i.tsImage, "export", &started, mounts, cmd, in, out)
	})
	if err != nil {
		return "", err
	}
	return bundle, nil
}
