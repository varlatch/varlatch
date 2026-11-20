// SPDX-License-Identifier: Apache-2.0

// Package setup is `varlatch setup` for a Go installation on a systemd
// host (ADR-0059 Decision 8; internal docs/design/go-step6.md, decision 7,
// slice 6.4a): the questions and their flags, the answers file,
// /etc/varlatch/varlatchd.conf, the two keys, the varlatch user, the data
// directory and its fsync probe, the unit started, and a journal in
// /etc/varlatch so that a rerun continues where it stopped and changes
// nothing once done.
//
// The keys: the Root KEK and the Backup Encryption Key, 32 random bytes
// each, made here and written straight into /etc/varlatch (root, 0600),
// where the unit loads them as credentials. They never go into an
// argument, the environment, the journal, a log or a temporary file
// outside /etc/varlatch. Interactively they are shown once on the
// terminal; a run without a terminal writes them to the files the
// operator named (0600, never over another file). A rerun never replaces
// a key it made.
package setup

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
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
)

// The installation's paths on the host.
const (
	EtcDir     = "/etc/varlatch"
	ConfigFile = "/etc/varlatch/varlatchd.conf"
	RootKEK    = "/etc/varlatch/root-kek"
	BackupKey  = "/etc/varlatch/backup-key"
	Journal    = "/etc/varlatch/setup.json"
	DataDir    = "/var/lib/varlatch"
	UnitFile   = "/etc/systemd/system/varlatchd.service"
	Unit       = "varlatchd.service"
	User       = "varlatch"
)

// Steps, in order. The journal records each once it is done.
var Steps = []string{"answers", "user", "data-dir", "probe", "keys", "config", "unit", "ready", "admin", "key-copies", "custody", "backup", "doctor"}

// Host is what setup changes on the host; tests replace it.
type Host interface {
	// Path is where the host path p is (tests: under a root).
	Path(p string) string
	// LookupUser is the user's ids; found false when there is none.
	LookupUser(name string) (uid, gid int, found bool, err error)
	// CreateUser makes the system user (no home, no login).
	CreateUser(name string) error
	// LoginShell is the user's login shell ("" when none is set).
	LoginShell(name string) (string, error)
	// SupplementaryGroups are the groups the user is in beyond its own
	// (primary) group, as the name service sees them: systemd gives
	// varlatchd every one of them.
	SupplementaryGroups(name string) ([]string, error)
	// SysUIDMax is the top of the system accounts' uids (login.defs'
	// SYS_UID_MAX, 999 when it says none).
	SysUIDMax() int
	Chown(path string, uid, gid int) error
	// Systemctl runs systemctl with args.
	Systemctl(args ...string) (string, error)
	// Probe measures dir's disk (diskprobe, with files without a name).
	Probe(ctx context.Context, dir string) (diskprobe.Result, error)
	// CheckConfig is `varlatchd admin config-check --config path`: "" when
	// the configuration is valid, what varlatchd said otherwise.
	CheckConfig(path string) (string, error)
	// Ready waits until the plain listener's /readyz answers 200.
	Ready(ctx context.Context, listen string) error
	// Admin runs `varlatchd admin <args> --config /etc/varlatch/varlatchd.conf`
	// as a child process, as root, with CREDENTIALS_DIRECTORY set to
	// /etc/varlatch so the configuration finds the keys as the unit would;
	// that varlatchd goes through the running unit's control socket, or
	// runs offline when none answers (the restore). It returns what the
	// child printed, which may hold a one-time link and is never logged;
	// its error carries what the child said on failure.
	Admin(ctx context.Context, args ...string) ([]byte, error)
}

// Asker asks the operator (nil without a terminal).
type Asker interface {
	Choose(question string, options []string, preselected int) (int, error)
	Confirm(question string, defaultYes bool) (bool, error)
	Text(question, defaultValue string) (string, error)
	// Secret reads a line without echo (the paste-back of a key).
	Secret(question string) ([]byte, error)
}

// Options are a run's.
type Options struct {
	Host Host
	// Given are the answers from the flags and the answers file.
	Given Answers
	// Ask is nil without a terminal: every answer must be given.
	Ask Asker
	// Say writes a line of progress (never a key).
	Say func(string) error
	// ShowKeys shows the two keys on the terminal (interactive runs only).
	ShowKeys func(rootKEK, backupKey []byte) error
	// ShowLink shows the first administrator's one-time enrollment link on
	// the terminal (interactive runs only).
	ShowLink func(link, expires string) error
	// AdminLinkOut is where a run without a terminal writes that link
	// (0600): never its output.
	AdminLinkOut string
	// AdminWait is how long setup waits for the passkey; zero issues the
	// link and stops (ErrPending), for a rerun to continue.
	AdminWait time.Duration
	// PollEvery is how often the wait asks varlatchd (2 s by default).
	PollEvery time.Duration
	// Attest is the operator's statement, without a terminal, that both
	// keys' copies are stored off this host (--attest).
	Attest bool
	// Doctor runs `varlatch doctor` and shows its report: ok is false when
	// a mandatory check failed. Nil skips the step.
	Doctor func(ctx context.Context) (ok bool, err error)
	// RootKEKOut and BackupKeyOut are where a run without a terminal
	// writes the keys' copies.
	RootKEKOut, BackupKeyOut string
	// AcceptSlowDisk continues on a disk the probe found slow.
	AcceptSlowDisk bool
	// AcceptExistingUser uses a varlatch user that exists already and is
	// not a system account.
	AcceptExistingUser bool
	// StopAfter ends the run once that step is done (tests of resuming).
	StopAfter string
	Now       func() time.Time
}

// JournalDoc is /etc/varlatch/setup.json: the answers, the steps done and
// the probe's measure. Never a key.
type JournalDoc struct {
	FormatVersion int               `json:"formatVersion"`
	Answers       Answers           `json:"answers"`
	Done          map[string]string `json:"done"`
	Probe         *ProbeRecord      `json:"probe,omitempty"`
	// FirstBackup is the first backup's archive id, once verified.
	FirstBackup string `json:"firstBackup,omitempty"`
}

// ProbeRecord is what the fsync probe measured, and whether a slow disk
// was accepted.
type ProbeRecord struct {
	AppendP99Ms  float64 `json:"appendP99Ms"`
	RewriteP99Ms float64 `json:"rewriteP99Ms"`
	Pass         bool    `json:"pass"`
	Accepted     bool    `json:"accepted"`
}

// Errors a run ends with.
var (
	// ErrStopped: StopAfter ended the run.
	ErrStopped = errors.New("setup: stopped after a step, as asked")
	// ErrNotAnswered: a run without a terminal lacks an answer.
	ErrNotAnswered = errors.New("setup: an answer is missing")
	// ErrPending: setup waits for the operator (the passkey, the keys'
	// custody); a rerun continues.
	ErrPending = errors.New("setup: waiting for you")
	// ErrDoctor: setup is done, and doctor found something to fix.
	ErrDoctor = errors.New("setup: doctor found something to fix")
)

// UsageError is an answer's problem: the operator fixes the command line.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

type run struct {
	o Options
	h Host
	j JournalDoc
}

// Run runs setup, continuing where an earlier run stopped.
func Run(ctx context.Context, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PollEvery <= 0 {
		o.PollEvery = 2 * time.Second
	}
	if o.Say == nil {
		o.Say = func(string) error { return nil }
	}
	r := &run{o: o, h: o.Host}
	if err := r.loadJournal(); err != nil {
		return err
	}
	// Without a terminal, the keys' copies need their files: refused
	// before anything is changed, as a missing answer is.
	if o.Ask == nil && r.j.Done["key-copies"] == "" && (o.RootKEKOut == "" || o.BackupKeyOut == "") {
		return fmt.Errorf("%w: without a terminal the keys are written to files you name: give --root-kek-out <file> and --backup-key-out <file>", ErrNotAnswered)
	}
	if o.Ask == nil && r.j.Done["admin"] == "" && o.AdminLinkOut == "" {
		return fmt.Errorf("%w: without a terminal the first administrator's enrollment link is written to a file you name: give --admin-link-out <file>", ErrNotAnswered)
	}
	for _, step := range Steps {
		var err error
		switch step {
		case "answers":
			err = r.answers()
		case "user":
			err = r.user()
		case "data-dir":
			err = r.dataDir()
		case "probe":
			err = r.probe(ctx)
		case "keys":
			err = r.keys()
		case "key-copies":
			err = r.keyCopies()
		case "config":
			err = r.config()
		case "unit":
			err = r.unit()
		case "ready":
			err = r.ready(ctx)
		case "admin":
			err = r.admin(ctx)
		case "custody":
			err = r.custody(ctx)
		case "backup":
			err = r.backup(ctx)
		case "doctor":
			err = r.doctor(ctx)
		}
		if err != nil {
			return err
		}
		if err := r.done(step); err != nil {
			return err
		}
		if step == o.StopAfter {
			return ErrStopped
		}
	}
	return nil
}

func (r *run) path(p string) string { return r.h.Path(p) }

func (r *run) loadJournal() error {
	b, err := os.ReadFile(r.path(Journal))
	if errors.Is(err, fs.ErrNotExist) {
		r.j = JournalDoc{FormatVersion: 1, Done: map[string]string{}}
		return nil
	}
	if err != nil {
		return fmt.Errorf("setup: cannot read its journal %s: %w", Journal, err)
	}
	if err := json.Unmarshal(b, &r.j); err != nil || r.j.FormatVersion != 1 {
		return fmt.Errorf("setup: its journal %s is not one this setup reads; it changes nothing", Journal)
	}
	if r.j.Done == nil {
		r.j.Done = map[string]string{}
	}
	return nil
}

// done records step in the journal, the first time only (a rerun leaves
// the journal as it is).
func (r *run) done(step string) error {
	if r.j.Done[step] != "" {
		return nil
	}
	r.j.Done[step] = r.o.Now().UTC().Format(time.RFC3339)
	return r.saveJournal()
}

func (r *run) saveJournal() error {
	if err := os.MkdirAll(r.path(EtcDir), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r.j, "", "  ")
	if err != nil {
		return err
	}
	return replacePrivate(r.path(Journal), append(b, '\n'))
}

// answers: the journal's answers are final; given ones must agree; the
// missing ones are asked, or, without a terminal, refused.
func (r *run) answers() error {
	a := r.j.Answers
	if differ := a.Merge(r.o.Given); len(differ) > 0 {
		return &UsageError{fmt.Sprintf("setup already answered --%s differently for this host (%s); setup does not change an installation: moving it is `varlatch move`", strings.Join(differ, ", --"), Journal)}
	}
	for {
		missing := a.Missing()
		if missing == "" {
			break
		}
		if r.o.Ask == nil {
			return fmt.Errorf("%w: give --%s (or the answers file's %q), or run setup on a terminal", ErrNotAnswered, missing, jsonName(missing))
		}
		if err := r.ask(&a, missing); err != nil {
			return err
		}
	}
	a.Defaults()
	if err := a.Check(); err != nil {
		return &UsageError{err.Error()}
	}
	r.j.Answers = a
	return nil
}

func jsonName(flag string) string {
	parts := strings.Split(flag, "-")
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

// ask asks one question.
func (r *run) ask(a *Answers, question string) error {
	switch question {
	case "ingress":
		modes := []string{Public, Proxy, Localhost, Tailnet}
		i, err := r.o.Ask.Choose("How do people reach Varlatch?", []string{
			"A public domain: varlatchd serves HTTPS itself, with a Let's Encrypt certificate",
			"My own reverse proxy, in front of varlatchd's plain listener on this host",
			"This machine only: http://localhost",
			"A tailnet: varlatchd joins it as its own node",
		}, 0)
		if err != nil {
			return err
		}
		a.Ingress = modes[i]
		if a.Ingress == Public {
			email, err := r.o.Ask.Text("Email address for the certificate authority's notices (empty for none)", "")
			if err != nil {
				return err
			}
			a.ACMEEmail = email
		}
	case "public-url":
		v, err := r.o.Ask.Text("The address people open, such as https://varlatch.example.com", "")
		if err != nil {
			return err
		}
		a.PublicURL = strings.TrimRight(v, "/")
	case "tailnet-auth-key-file":
		v, err := r.o.Ask.Text("The file holding a tailnet auth key for the node (it is read by varlatchd, never shown)", "")
		if err != nil {
			return err
		}
		a.TailnetAuthKeyFile = v
	case "backups":
		if err := r.o.Say("Varlatch's hosted backups are not available yet."); err != nil {
			return err
		}
		i, err := r.o.Ask.Choose("Where do backups go?", []string{
			"On this host only: copy the archives off it yourself",
			"To a bucket, through a destinations file you wrote (S3, B2)",
		}, 0)
		if err != nil {
			return err
		}
		a.Backups = []string{"host", "bucket"}[i]
	case "backup-destinations-file":
		v, err := r.o.Ask.Text("The destinations file", "")
		if err != nil {
			return err
		}
		a.BackupDestinationsFile = v
	}
	return nil
}

// user: the varlatch system user. One that exists already must be a system
// account (no login shell, a uid in the system range, in no group but its
// own: systemd gives varlatchd every supplementary group, docker's or
// wheel's included) unless the operator says to use it anyway
// (--accept-existing-user): varlatchd runs as it and owns the
// installation's data. Once the step is done, a rerun asks no more.
func (r *run) user() error {
	uid, _, found, err := r.h.LookupUser(User)
	if err != nil {
		return err
	}
	if !found {
		if err := r.o.Say("Creating the system user " + User + "."); err != nil {
			return err
		}
		return r.h.CreateUser(User)
	}
	if r.j.Done["user"] != "" {
		return nil
	}
	shell, err := r.h.LoginShell(User)
	if err != nil {
		return err
	}
	if uid == 0 {
		return fmt.Errorf("setup: the user %s exists with uid 0, root's: varlatchd never runs as root; remove or rename that user", User)
	}
	var notes []string
	switch base := path.Base(shell); {
	case shell == "":
		notes = append(notes, "it has no login shell set, so it logs in with /bin/sh")
	case base != "nologin" && base != "false":
		notes = append(notes, "its login shell is "+shell)
	}
	if most := r.h.SysUIDMax(); uid > most {
		notes = append(notes, fmt.Sprintf("its uid %d is above the system accounts' range (SYS_UID_MAX %d)", uid, most))
	}
	groups, err := r.h.SupplementaryGroups(User)
	if err != nil {
		return err
	}
	if len(groups) > 0 {
		notes = append(notes, "it is in the groups "+strings.Join(groups, ", ")+", which varlatchd would run with")
	}
	if len(notes) == 0 {
		return nil
	}
	what := "the user " + User + " exists and is not a system account: " + strings.Join(notes, "; ")
	if !r.o.AcceptExistingUser {
		return fmt.Errorf("setup: %s. varlatchd runs as it and owns the installation's data: if that account is meant for it, run setup again with --accept-existing-user; otherwise remove or rename it", what)
	}
	return r.o.Say("Using the existing user " + User + " as --accept-existing-user says, although " + what + ".")
}

// dataDir: /var/lib/varlatch, the user's, 0700, made before the probe
// measures its disk. A directory that holds a database setup did not make
// is refused: that is a restore (setup --restore, slice 6.4c).
func (r *run) dataDir() error {
	uid, gid, _, err := r.h.LookupUser(User)
	if err != nil {
		return err
	}
	dir := r.path(DataDir)
	if r.j.Done["data-dir"] == "" {
		if _, err := os.Stat(filepath.Join(dir, "varlatch.db")); err == nil {
			return fmt.Errorf("setup: %s already holds a database setup did not make: a restore is `varlatch setup --restore <archive>`; nothing was changed", DataDir)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return r.h.Chown(dir, uid, gid)
}

// probe: the data directory's fsync p99 against Decision 2's 10 ms, before
// the database is placed there; a slow disk is said with its measure, and
// setup continues only when the operator accepts.
func (r *run) probe(ctx context.Context) error {
	if p := r.j.Probe; p != nil && (p.Pass || p.Accepted) {
		return nil
	}
	if err := r.o.Say("Measuring the data directory's disk (5 seconds)."); err != nil {
		return err
	}
	res, err := r.h.Probe(ctx, r.path(DataDir))
	slow := errors.Is(err, diskprobe.ErrTooFewSamples)
	if err != nil && !slow {
		if errors.Is(err, diskprobe.ErrUnnamed) {
			return r.o.Say("The disk could not be measured on this filesystem; setup continues.")
		}
		return fmt.Errorf("setup: the fsync probe: %w", err)
	}
	rec := &ProbeRecord{AppendP99Ms: ms(res.Append.P99), RewriteP99Ms: ms(res.Rewrite.P99), Pass: res.Pass && !slow}
	r.j.Probe = rec
	if rec.Pass {
		return r.o.Say("The disk: " + res.String() + ".")
	}
	measure := res.String()
	if slow {
		measure = err.Error()
	}
	if err := r.o.Say("The data directory's disk is slow: " + measure + ". Every write waits for its fsync; network block storage is not supported until G9a passes on it."); err != nil {
		return err
	}
	accepted := r.o.AcceptSlowDisk
	if !accepted && r.o.Ask != nil {
		if accepted, err = r.o.Ask.Confirm("Continue on this disk anyway?", false); err != nil {
			return err
		}
	}
	if !accepted {
		_ = r.saveJournal()
		return fmt.Errorf("setup: the data directory's disk is slower than 10 ms at p99 (%s); put it on a faster disk, or run setup again with --accept-slow-disk", measure)
	}
	rec.Accepted = true
	return nil
}

// removeLeftovers removes from /etc/varlatch the temporary files a run
// that ended mid-write left (stagedName's: "." + one of the files setup
// writes there + "." + 12 hex digits + ".tmp", regular files only), and
// says how many. Nothing else there is touched.
func (r *run) removeLeftovers() error {
	dir := r.path(EtcDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, e := range entries {
		// The configuration's staged copy (config's ".setup") too: a run
		// killed between its write and its rename leaves it, and the next
		// writes it anew, but a run never repeated would keep it.
		if !e.Type().IsRegular() || !isStagedName(e.Name()) && e.Name() != filepath.Base(ConfigFile)+".setup" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		removed++
	}
	if removed == 0 {
		return nil
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	noun := "files"
	if removed == 1 {
		noun = "file"
	}
	return r.o.Say(fmt.Sprintf("Removed %d temporary %s an interrupted run left in %s.", removed, noun, EtcDir))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// keys: the Root KEK and the backup key, made once: a key file setup made
// is never replaced; one the journal says it made but that is gone stops
// setup (the copies are the operator's to restore).
func (r *run) keys() error {
	if err := r.removeLeftovers(); err != nil {
		return err
	}
	for _, k := range []struct{ name, path string }{{"the Root KEK", RootKEK}, {"the backup key", BackupKey}} {
		p := r.path(k.path)
		_, err := os.Stat(p)
		switch {
		case err == nil && r.j.Done["keys"] == "":
			// Not made by a run this journal knows of: said, so that an
			// operator who did not expect it can stop.
			if err := r.o.Say("Kept the existing " + strings.TrimPrefix(k.name, "the ") + " at " + k.path + "."); err != nil {
				return err
			}
			continue
		case err == nil:
			continue
		case !errors.Is(err, fs.ErrNotExist):
			return err
		case r.j.Done["keys"] != "":
			return fmt.Errorf("setup: %s (%s) it made is gone; put it back from your copy before running setup again, or the installation's data cannot be read", k.name, k.path)
		}
		if err := os.MkdirAll(r.path(EtcDir), 0o750); err != nil {
			return err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		text := make([]byte, hex.EncodedLen(len(key))+1)
		hex.Encode(text, key)
		text[len(text)-1] = '\n'
		clear(key)
		err = createPrivate(p, text)
		clear(text)
		if err != nil {
			return fmt.Errorf("setup: writing %s: %w", k.path, err)
		}
		if err := r.o.Say("Made " + k.name + " in " + k.path + " (root, 0600)."); err != nil {
			return err
		}
	}
	return nil
}

// keyCopies: interactively, the two keys on the terminal, once; without a
// terminal, written to the files the operator named, 0600, never over
// another file.
func (r *run) keyCopies() error {
	if r.j.Done["key-copies"] != "" {
		return nil
	}
	kek, err := os.ReadFile(r.path(RootKEK))
	if err != nil {
		return err
	}
	defer clear(kek)
	bek, err := os.ReadFile(r.path(BackupKey))
	if err != nil {
		return err
	}
	defer clear(bek)
	if r.o.Ask != nil && r.o.ShowKeys != nil {
		if err := r.o.ShowKeys(bytes.TrimSpace(kek), bytes.TrimSpace(bek)); err != nil {
			return err
		}
		return r.pasteBack(kek, bek)
	}
	if r.o.RootKEKOut == "" || r.o.BackupKeyOut == "" {
		return fmt.Errorf("%w: without a terminal the keys are written to files you name: give --root-kek-out <file> and --backup-key-out <file>", ErrNotAnswered)
	}
	for _, c := range []struct {
		out string
		key []byte
	}{{r.o.RootKEKOut, kek}, {r.o.BackupKeyOut, bek}} {
		if err := copyPrivate(c.out, c.key); err != nil {
			return err
		}
	}
	return r.o.Say("Wrote copies of the Root KEK to " + r.o.RootKEKOut + " and of the backup key to " + r.o.BackupKeyOut + " (0600): store them off this host, then delete them.")
}

// RenderConfig is varlatchd.conf for the answers: the same answers make the
// same file, byte for byte. No key and no key file: the unit hands the
// keys over as credentials (root_kek_file and backup_key_file default to
// them).
func RenderConfig(a Answers) []byte {
	var b strings.Builder
	b.WriteString("# varlatchd.conf, written by `varlatch setup` (its answers: " + Journal + ").\n")
	b.WriteString("# The keys are the unit's credentials (" + RootKEK + ", " + BackupKey + "); none is named here.\n")
	set := func(name, value string) {
		if value != "" {
			b.WriteString(name + " = " + value + "\n")
		}
	}
	set("listen", a.Listen)
	set("public_url", a.PublicURL)
	set("trusted_proxies", a.TrustedProxies)
	if a.Ingress == Public {
		set("listen_https", a.ListenHTTPS)
		set("listen_http_redirect", a.ListenHTTPRedirect)
		set("acme_email", a.ACMEEmail)
		set("acme_ca", a.ACMECA)
		set("acme_ca_root", a.ACMECARoot)
	}
	if a.Ingress == Tailnet {
		set("tailnet", "on")
		set("tailnet_hostname", a.TailnetHostname)
		set("tailnet_tags", a.TailnetTags)
		set("tailnet_port", a.TailnetPort)
		set("tailnet_auth_key_file", a.TailnetAuthKeyFile)
	}
	if a.Backups == "bucket" {
		set("backup_destinations_file", a.BackupDestinationsFile)
		set("backup_destination", a.BackupDestination)
	}
	return []byte(b.String())
}

// config: varlatchd.conf (0640, root:varlatch), checked by varlatchd before
// it is put in place. A file already there is kept as it is (an operator's
// edit is theirs).
func (r *run) config() error {
	// /etc/varlatch: root's, readable by the service's group only (the
	// unit's user reads the configuration; the keys stay root's alone).
	_, gid, _, err := r.h.LookupUser(User)
	if err != nil {
		return err
	}
	etc := r.path(EtcDir)
	if err := os.Chmod(etc, 0o750); err != nil {
		return err
	}
	if err := r.h.Chown(etc, 0, gid); err != nil {
		return err
	}
	want := RenderConfig(r.j.Answers)
	p := r.path(ConfigFile)
	got, err := os.ReadFile(p)
	switch {
	case err == nil && bytes.Equal(got, want):
		return nil
	case err == nil:
		return r.o.Say("Kept " + ConfigFile + " as it is: it differs from what setup would write.")
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	staged := p + ".setup"
	if err := writeStaged(staged, want, 0o640); err != nil {
		return err
	}
	if err := r.h.Chown(staged, 0, gid); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if msg, err := r.h.CheckConfig(staged); err != nil || msg != "" {
		_ = os.Remove(staged)
		if err != nil {
			return err
		}
		return &UsageError{"setup: varlatchd refuses the configuration these answers make: " + msg}
	}
	if err := os.Rename(staged, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

// unit: the varlatchd unit enabled and started; an active unit is left
// running (a rerun restarts nothing).
func (r *run) unit() error {
	if _, err := os.Stat(r.path(UnitFile)); err != nil {
		return fmt.Errorf("setup: %s is not installed: install.sh --server installs it", UnitFile)
	}
	if out, err := r.h.Systemctl("is-active", Unit); err == nil && strings.TrimSpace(out) == "active" {
		return nil
	}
	if err := r.o.Say("Starting " + Unit + "."); err != nil {
		return err
	}
	if out, err := r.h.Systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("setup: systemctl daemon-reload: %v %s", err, oneLine(out))
	}
	if out, err := r.h.Systemctl("enable", "--now", Unit); err != nil {
		return fmt.Errorf("setup: systemctl enable --now %s: %v %s (journalctl -u varlatchd says why)", Unit, err, oneLine(out))
	}
	return nil
}

// ready: the installation answers /readyz on its plain listener.
func (r *run) ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := r.h.Ready(ctx, r.j.Answers.Listen); err != nil {
		return fmt.Errorf("setup: varlatchd did not become ready on %s: %w (journalctl -u varlatchd says why)", r.j.Answers.Listen, err)
	}
	return r.o.Say("varlatchd is ready on " + r.j.Answers.Listen + " (" + r.j.Answers.PublicURL + ").")
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
