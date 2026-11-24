// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sync"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/preread"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// A host command run as root works in the data directory as its owner, the
// user varlatchd runs as: the directory is that user's, so what root wrote
// there by name could be led elsewhere by a link, and would be root's
// afterwards, where varlatchd could not open it. So `varlatchd admin`, once
// it has its configuration, opens what only root may read (keepForOwner),
// becomes the owner for good (becomeOwner), and then runs.

// staysRoot are the commands that keep root's identity: those that do not
// work in the data directory or write nothing there (kek, with the
// operator's key files; config check; doctor, which reads root's files;
// outbound check; tailnet reaches, a probe in a temporary directory), and,
// where only root may change what their paths lead to, the two that write
// at a path they are given: schema upgrade of another database, and migrate
// keys, which writes root's key files and nothing in the data directory
// (runMigrate).
func staysRoot(cfg *config.Config, sub string, rest []string) bool {
	switch sub {
	case "kek", "config", "doctor", "outbound", "conformance-probe", "conformance-fixture":
		return true
	case "migrate":
		return len(rest) > 0 && rest[0] == "keys" && keysAreRoots(cfg)
	case "tailnet":
		return len(rest) > 0 && rest[0] == "reaches"
	case "schema":
		cmd, _, database, _ := schemaArguments(rest)
		return cmd == "upgrade" && database != "" && databaseIsRoots(cfg, database)
	}
	return false
}

// keysAreRoots is whether every key file's directory is root's alone.
func keysAreRoots(cfg *config.Config) bool {
	paths := []string{cfg.RootKEKFile, cfg.BackupKeyFile}
	if cfg.Tailnet != nil {
		paths = append(paths, cfg.Tailnet.AuthKeyFile)
	}
	for _, p := range paths {
		if p != "" && !rootsAlone(filepath.Dir(p)) {
			return false
		}
	}
	return true
}

// databaseIsRoots is whether database is root's own database: a file of root's,
// with no other name, in a directory that is root's alone, and not the
// configured one, whatever the path it is given by.
func databaseIsRoots(cfg *config.Config, database string) bool {
	info, err := os.Lstat(database)
	if err != nil || !info.Mode().IsRegular() || !rootsOnlyName(info) || !rootsAlone(filepath.Dir(database)) {
		return false
	}
	live, err := os.Stat(cfg.DatabasePath())
	return err != nil || !os.SameFile(info, live)
}

// outputEnv tells a command started by withRootsOutput that descriptors 3
// and 4 are its output file and that file's directory.
const outputEnv = "VARLATCHD_ADMIN_OUTPUT"

// handedOutput are the output file and its directory that withRootsOutput
// handed this command, descriptors 3 and 4: nil for any other, and when they
// are not a regular file and a directory, whatever the environment says.
var handedOutput = sync.OnceValues(func() (f, dir *os.File) {
	if os.Getenv(outputEnv) == "" || !fileAndDirectory(3, 4) {
		return nil, nil
	}
	return os.NewFile(3, "output"), os.NewFile(4, "output's directory")
})

// withRootsOutput runs `admin migrate export --out <file>` as root over a
// directory of another user's, into a directory that is root's alone, where
// that user may make nothing: this process makes the file, and, when the
// command fails, removes it; the command, this program again, becomes the
// owner with the file open. started is false for anything else.
func withRootsOutput(cfg *config.Config, sub string, rest []string, stdout, stderr io.Writer) (status int, started bool) {
	if sub != "migrate" || rest[0] != "export" || !rootOverOwner(cfg.DataDir) {
		return 0, false
	}
	if f, _ := handedOutput(); f != nil {
		return 0, false // this is the command it runs
	}
	a, _ := parseMigrate(rest)
	abs, err := filepath.Abs(a.out)
	if err != nil || a.out == "" || !rootsAlone(filepath.Dir(abs)) {
		return 0, false
	}
	fail := func(err error) (int, bool) {
		fmt.Fprintf(stderr, "varlatchd admin migrate export: %v (the reverse bundle is a new file); nothing was written\n", err)
		return ExitFailure, true
	}
	exe, err := os.Executable()
	if err != nil {
		return fail(err)
	}
	f, err := createAlone(abs)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	dir, err := os.Open(filepath.Dir(abs))
	if err != nil {
		_ = os.Remove(abs)
		return fail(err)
	}
	defer dir.Close()
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Args[0] = os.Args[0]
	cmd.Env = append(os.Environ(), outputEnv+"=3")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	cmd.ExtraFiles = []*os.File{f, dir}
	err = cmd.Run()
	if err == nil {
		return ExitOK, true
	}
	_ = os.Remove(abs)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() > 0 {
		return exit.ExitCode(), true // it said why
	}
	return fail(err)
}

// output is a command's output file out: the one withRootsOutput opened, or
// made now. done ends it: durable, with its name, or, when the
// command failed, gone.
func output(out string) (f *os.File, done func(error) error, err error) {
	f, dir := handedOutput()
	kept := f != nil
	if !kept {
		if f, err = createAlone(out); err != nil {
			return nil, nil, err
		}
		if dir, err = os.Open(filepath.Dir(out)); err != nil {
			f.Close()
			_ = os.Remove(out)
			return nil, nil, err
		}
	}
	return f, func(err error) error {
		defer dir.Close()
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			// Its name in its directory, durable too.
			err = dir.Sync()
		}
		if err != nil && !kept {
			_ = os.Remove(out)
		}
		return err
	}, nil
}

// leftovers are the names root-run commands of an earlier release (0.50.0
// before rc.4) made in the data directory, as path.Match patterns below it,
// that varlatchd opens or writes again: nothing else of root's there is
// given to its owner. The directories are varlatchd's own.
var leftovers = []string{
	config.DatabaseFile, config.DatabaseFile + "-wal", config.DatabaseFile + "-shm", config.DatabaseFile + ".restore",
	LockFile, JournalFile, backup.GateFile, release.ReleaseCheckFile, FrozenCopyName("mig_*"),
	tailnet.PinFile, tailnet.ListenersFile, tailnet.HoldFile, TakeoverFile, IssuanceFile,
	tailnet.StateDir, tailnet.StateDir + "/*", tailnet.StateDir + "/*/*", tailnet.StateDir + "/*/*/*",
	backups.Dir, backups.Dir + "/*.vltbak", backups.Dir + "/*.json",
	backups.Dir + "/.work-*", backups.Dir + "/.work-*/*", backups.Dir + "/.work-*/*/*",
	backups.Dir + "/.remote-*", backups.Dir + "/.remote-*/*", backups.Dir + "/.remote-*/*/*",
	backups.Dir + "/.bucket-test-*", backups.Dir + "/.bucket-test-*/*", backups.Dir + "/.bucket-test-*/*/*",
	".restore-work", ".restore-work/*", ".restore-work/*/*",
	"upgrades", "upgrades/*", "upgrades/*/snapshot.vltbak",
	"upgrades/*/db", "upgrades/*/db/" + config.DatabaseFile + "*", "upgrades/*/original", "upgrades/*/original/" + config.DatabaseFile + "*",
}

// isLeftover is whether a path below the data directory, slash-separated,
// is one of leftovers.
func isLeftover(rel string) bool {
	return slices.ContainsFunc(leftovers, func(p string) bool {
		ok, _ := path.Match(p, rel)
		return ok
	})
}

// keepForOwner keeps what a command reads outside the data directory open:
// the upgrade journal, the two keys, a backup's destination, a restore's archive and key, a
// migration's bundle, the tailnet's key and a name takeover's authority. One
// that cannot be opened is refused where it is used, as it would have been.
func keepForOwner(cfg *config.Config, configDir, sub string, rest []string) {
	preread.Keep(filepath.Join(configDir, upgradejournal.File), nil)
	preread.Keep(cfg.RootKEKFile, nil)
	preread.Keep(cfg.BackupKeyFile, nil)
	if cfg.Tailnet != nil && slices.Contains([]string{"tailnet", "migrate"}, sub) {
		preread.Keep(cfg.Tailnet.AuthKeyFile, nil)
	}
	switch sub {
	case "backup":
		if rest[0] == "restore" {
			args, _ := restoreArgs(rest[1:])
			preread.Keep(args["--in"], nil)
			preread.Keep(args["--backup-key-file"], nil)
			return
		}
		if cfg.BackupDestinationsFile == "" {
			return
		}
		preread.Keep(cfg.BackupDestinationsFile, nil)
		if d, err := backup.ReadDestination(cfg.BackupDestinationsFile, cfg.BackupDestination); err == nil {
			credentials := d.WriteCredentialsFile
			if !filepath.IsAbs(credentials) {
				credentials = filepath.Join(filepath.Dir(cfg.BackupDestinationsFile), credentials)
			}
			preread.Keep(credentials, nil)
		}
	case "migrate":
		a, _ := parseMigrate(rest)
		preread.Keep(a.in, nil)
	case "tailnet":
		c, _ := nodeArgs(rest)
		preread.Keep(c.oauthFile, checkedSecretFile)
		preread.Keep(c.headscaleKeyFile, checkedSecretFile)
	}
}

// rootOverOwner is whether root runs this over a data directory that is
// another user's.
func rootOverOwner(dataDir string) bool {
	if !adminAsRoot() {
		return false
	}
	st, err := os.Stat(dataDir)
	return err == nil && statOwner(st) > 0
}

// actsAsOwner is varlatchd's answer, in `admin config check`, that its host
// commands run as root work as the data directory's owner: setup refuses to
// restore with one that does not say so.
const actsAsOwner = true
