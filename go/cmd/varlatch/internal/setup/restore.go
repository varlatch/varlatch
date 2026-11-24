// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailcontrol"
)

// A restore onto a fresh host (slice 6.4c; ADR-0059's G13, through setup):
// `varlatch setup --restore <archive> --root-kek-file <file>
// --backup-key-file <file>`. The operator's keys are installed where setup
// would have made new ones (root, 0600), the archive is restored with
// `varlatchd admin backup restore` before the unit first starts, and the
// rest is setup's own steps: the restored administrators keep their
// passkeys, so no link is issued, no key is shown or copied, and the first
// backup proves the restored installation backs up and verifies again.

// restoreIntent records a restore in the journal, the first time, and
// refuses a restore onto a host whose setup is not one, or another archive
// than the one being restored.
func (r *run) restoreIntent() error {
	given := r.o.Restore
	switch {
	case r.j.Restore == nil && given == "":
		return nil
	case r.j.Restore == nil:
		if len(r.j.Done) > 0 {
			return &UsageError{"setup: this host's setup is not a restore (" + Journal + " has steps done): a restore goes onto a fresh host"}
		}
		if !filepath.IsAbs(given) || !filepath.IsAbs(r.o.RootKEKIn) || !filepath.IsAbs(r.o.BackupKeyIn) {
			return &UsageError{"setup: --restore, --root-kek-file and --backup-key-file each name a file with an absolute path"}
		}
		r.j.Restore = &RestoreRecord{Archive: given}
	case given != "" && given != r.j.Restore.Archive:
		return &UsageError{"setup: this host is restoring " + r.j.Restore.Archive + " (" + Journal + "): setup does not switch archives"}
	}
	return nil
}

// keyText is a key file's text: 64 hex digits, or 32 bytes in base64, as
// varlatchd reads them.
var keyText = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)

func isKey(b []byte) bool {
	if keyText.Match(b) {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(string(b))
	defer clear(raw)
	return err == nil && len(raw) == 32
}

// restoreKeys installs the operator's two keys in /etc/varlatch (root,
// 0600, linked into place, never over another key): the same file again is
// left as it is; a different one is refused.
func (r *run) restoreKeys() error {
	if err := os.MkdirAll(r.path(EtcDir), 0o750); err != nil {
		return err
	}
	var installed [][]byte
	defer func() {
		for _, k := range installed {
			clear(k)
		}
	}()
	for _, k := range []struct{ name, flag, in, path string }{
		{"Root KEK", "--root-kek-file", r.o.RootKEKIn, RootKEK},
		{"backup key", "--backup-key-file", r.o.BackupKeyIn, BackupKey},
	} {
		var given []byte
		if k.in != "" {
			raw, err := os.ReadFile(k.in)
			if err != nil {
				return fmt.Errorf("setup: cannot read the %s's file %s: %w", k.name, k.in, err)
			}
			given = bytes.TrimSpace(raw)
			if len(given) != len(raw) {
				given = append([]byte(nil), given...)
				clear(raw)
			}
			if !isKey(given) {
				clear(given)
				return &UsageError{fmt.Sprintf("setup: %s %s does not hold a key (64 hex digits, or 32 bytes in base64)", k.flag, k.in)}
			}
			installed = append(installed, given)
		}
		have, err := os.ReadFile(r.path(k.path))
		switch {
		case err == nil:
			same := given == nil || bytes.Equal(bytes.TrimSpace(have), given)
			clear(have)
			if !same {
				return fmt.Errorf("setup: %s already holds another %s: a restore installs your keys on a fresh host and never replaces one", k.path, k.name)
			}
			continue
		case !errors.Is(err, fs.ErrNotExist):
			return err
		case given == nil:
			return &UsageError{fmt.Sprintf("setup: give %s again: the %s is not installed yet", k.flag, k.name)}
		}
		data := append(append([]byte(nil), given...), '\n')
		err = createPrivate(r.path(k.path), data)
		clear(data)
		if err != nil {
			return fmt.Errorf("setup: writing %s: %w", k.path, err)
		}
		if err := r.o.Say("Installed your " + k.name + " in " + k.path + " (root, 0600)."); err != nil {
			return err
		}
	}
	if len(installed) == 2 && bytes.Equal(installed[0], installed[1]) {
		return &UsageError{"setup: --root-kek-file and --backup-key-file hold the same key: they are two different keys"}
	}
	return nil
}

var (
	restored     = regexp.MustCompile(`Restore completed for (\S+) from archive (\S+) \(created ([^)]*)\)`)
	restoredSets = regexp.MustCompile(`(?m)^  ([a-z_]+) = (.*)$`)
)

// restore: the archive restored into the data directory with the
// operator's keys, before the unit first starts (varlatchd checks the
// archive, its release and the Root KEK against the archive's canary; a
// restore that stopped resumes). The archive's installation must be reached
// at the address the answers give: its passkeys belong to it.
func (r *run) restore(ctx context.Context) error {
	if r.j.Restore == nil || r.j.Done["restore"] != "" {
		return nil
	}
	if err := r.o.Say("Restoring " + r.j.Restore.Archive + " with your keys."); err != nil {
		return err
	}
	out, err := r.h.Admin(ctx, "backup", "restore", "--in", r.j.Restore.Archive, "--backup-key-file", BackupKey)
	if err != nil {
		return err
	}
	m := restored.FindSubmatch(out)
	if m == nil {
		return errors.New("setup: varlatchd admin backup restore did not say what it restored")
	}
	r.j.Restore.InstallationID, r.j.Restore.ArchiveID = string(m[1]), string(m[2])
	created := string(m[3])
	settings := map[string]string{}
	for _, s := range restoredSets.FindAllSubmatch(out, -1) {
		settings[string(s[1])] = string(s[2])
	}
	if was := strings.TrimSuffix(settings["public_url"], "/"); was != "" && was != strings.TrimSuffix(r.j.Answers.PublicURL, "/") {
		_ = r.saveJournal()
		return &UsageError{fmt.Sprintf("setup: the archive's installation is reached at %s, not %s: its passkeys belong to that address. Remove %s and %s (this run's answers; the keys and the restored data stay), then run setup --restore again with --public-url %s; to change the address, restore first and move it with varlatch move",
			was, r.j.Answers.PublicURL, Journal, ConfigFile, was)}
	}
	uid, gid, _, err := r.h.LookupUser(User)
	if err != nil {
		return err
	}
	// The restore ran as root: what it wrote becomes the unit's.
	if err := filepath.WalkDir(r.path(DataDir), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return r.h.Chown(p, uid, gid)
	}); err != nil {
		return err
	}
	return r.o.Say("Restored the installation " + r.j.Restore.InstallationID + " from the archive " + r.j.Restore.ArchiveID + " (made " + created + ").")
}

// takeName is a restore's tailnet handoff (go-step7 decision 11), with the
// operator's authority over the tailnet (Tailscale's OAuth client, or a
// self-hosted control server's API key): the restored node enrols held under its
// temporary name (<name>-vl-<op>-n), then varlatchd takes the dead node's
// name over by rename (`varlatchd admin tailnet take-name`, the old node
// renamed <name>-vl-<op>-o), before the unit first starts. The operation is
// journalled first; a rerun finishes what an interrupted one began.
func (r *run) takeName(ctx context.Context) error {
	a := r.j.Answers
	// The configuration must name the control server the answers do
	// (varlatchd's tailnet_control_url): a hand-edited one is refused
	// before anything is recorded or the node enrols against it.
	if got := r.configValue("tailnet_control_url"); got != a.TailnetControlURL {
		return fmt.Errorf("setup: %s's tailnet_control_url (%s) is not the answered control server (%s): nothing was changed; put it back as answered",
			ConfigFile, orTailscale(got), orTailscale(a.TailnetControlURL))
	}
	resumed := r.j.Restore.TailnetOperation != ""
	if !resumed {
		op, err := tailcontrol.NewOperationID()
		if err != nil {
			return err
		}
		r.j.Restore.TailnetOperation = op
		if err := r.saveJournal(); err != nil {
			return err
		}
	}
	op := r.j.Restore.TailnetOperation
	temp, err := tailcontrol.TempName(a.TailnetHostname, op, tailcontrol.RoleNew)
	if err != nil {
		return err
	}
	take := func() error {
		// The authority the answers name: Tailscale's OAuth client, or the
		// self-hosted control server's API (its URL tailnet_control_url,
		// which varlatchd requires the URL to equal).
		authority := []string{"--oauth-client-file", a.TailscaleOAuthClientFile}
		if a.HeadscaleAPIKeyFile != "" {
			authority = []string{"--headscale-url", a.TailnetControlURL, "--headscale-api-key-file", a.HeadscaleAPIKeyFile}
		}
		out, err := r.h.Admin(ctx, append(append([]string{"tailnet", "take-name"}, authority...), "--json")...)
		if err != nil {
			return err
		}
		var res struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(bytes.TrimSpace(out), &res) != nil || res.Phase != "done" {
			return errors.New("setup: varlatchd admin tailnet take-name did not say the name was taken over")
		}
		return r.o.Say("This node holds the tailnet name " + a.TailnetHostname + "; the old node is renamed aside. Tailnet access opens when varlatchd starts.")
	}
	enroll := func() error {
		if err := r.o.Say("Taking the tailnet name " + a.TailnetHostname + " over: this node joins as " + temp + " first (held, serving nothing), then the old node is renamed aside and this one takes the name."); err != nil {
			return err
		}
		if _, err := r.h.Admin(ctx, "tailnet", "enroll", "--hostname", temp, "--json"); err != nil {
			return err
		}
		r.j.Restore.TailnetEnrolled = true
		return r.saveJournal()
	}
	if !resumed {
		if err := enroll(); err != nil {
			return err
		}
		return take()
	}
	// A rerun: where this operation's takeover got to is read from the
	// node's state and the takeover's own records, never by trying
	// take-name (on Headscale every take-name expires its API key, a
	// refusal included); a record of another operation, name or control
	// server is not this takeover's.
	st, err := r.takeoverState()
	if err != nil {
		return err
	}
	ours := st.journal != nil && st.journal.Plan.Operation == op && strings.EqualFold(st.journal.Plan.Name, a.TailnetHostname) &&
		st.journal.ControlURL == a.TailnetControlURL
	// Enrolled: its enrol succeeded (recorded), or its takeover began.
	enrolled := r.j.Restore.TailnetEnrolled || ours
	switch {
	case st.held && st.holdName != temp:
		return fmt.Errorf("setup: the node is held as %s, not as this takeover's temporary name %s: nothing was done. %s",
			st.holdName, temp, r.notOursNext())
	case st.held && !enrolled:
		// Held, but its enrolment did not say it succeeded (a refusal after
		// it wrote the node, its tags say): enrolled again, then taken.
		if err := enroll(); err != nil {
			return err
		}
		return take()
	case st.held:
		return take()
	case ours && st.journal.Phase == "done":
		return r.o.Say("This node holds the tailnet name " + a.TailnetHostname + " (an earlier run took it over).")
	case ours && st.journal.Phase == "switching" && st.journal.IncomingOpened:
		// Stopped after the takeover opened the node (its hold removed),
		// before its journal said done: take-name finishes it.
		return take()
	case !st.enrolled && !enrolled:
		// Never enrolled (an enrolment that failed before writing the node).
		if err := enroll(); err != nil {
			return err
		}
		return take()
	case !enrolled:
		// No node held for this takeover, no record of it, and a node's
		// state there (a reused data directory, or an enrolment that did
		// not finish): nothing is tried against it.
		return fmt.Errorf("setup: this data directory holds a tailnet node that is neither held for this takeover (%s) nor recorded as taking the name over: nothing was done. %s",
			temp, r.notOursNext())
	}
	// Enrolled for this takeover, no longer held, and its journal does not
	// say it finished. take-name is not the way to find out: on a node not
	// held it only refuses (and on Headscale expires its key).
	read := "tailnet-takeover.json is absent"
	if st.journal != nil && ours {
		read = fmt.Sprintf("tailnet-takeover.json records phase %q (incoming opened: %t)", st.journal.Phase, st.journal.IncomingOpened)
	} else if st.journal != nil {
		read = "tailnet-takeover.json records another takeover"
	}
	return fmt.Errorf("setup: the takeover %s was enrolled, but its node is no longer held and %s: nothing was done. Inspect %s. If the node should be held for the takeover again, `varlatchd admin tailnet enroll --hostname %s` holds it (it checks the live name and uses no Headscale key); then run setup again",
		op, read, r.takeoverPaths(), temp)
}

// takeoverPaths are the node's files a takeover leaves, as this host has
// them.
func (r *run) takeoverPaths() string {
	dir := r.path(DataDir)
	return filepath.Join(dir, takeoverFile) + ", " + filepath.Join(dir, tailnetHoldFile) + " and " + filepath.Join(dir, tailnetStateFile)
}

// notOursNext is the next step when the data directory holds a node or
// hold that is not this takeover's: look, never remove first.
func (r *run) notOursNext() string {
	return "Inspect " + r.takeoverPaths() + ", and confirm whether another installation owns this data directory. Only on a fresh host, remove those leftovers (or start with a fresh " +
		DataDir + "), then run setup again"
}

// The node's files in the data directory that a takeover leaves, as
// varlatchd writes them (server/tailnet's StateDir and HoldFile, and
// daemon's TakeoverFile).
const (
	tailnetStateFile = "tailnet/tailscaled.state"
	tailnetHoldFile  = "tailnet-handoff.json"
	takeoverFile     = "tailnet-takeover.json"
)

// takeoverRecord is what setup reads of varlatchd's takeover journal.
type takeoverRecord struct {
	Plan struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
	} `json:"plan"`
	Phase          string `json:"phase"`
	IncomingOpened bool   `json:"incomingOpened"`
	ControlURL     string `json:"controlUrl"`
}

// takeover is where a restore's takeover got to, from the node's files:
// enrolled (its tailnet state there), held (and under which name), and
// varlatchd's takeover journal (nil without one). None is followed
// through a symbolic link.
type takeover struct {
	enrolled, held bool
	holdName       string
	journal        *takeoverRecord
}

func (r *run) takeoverState() (takeover, error) {
	dir := r.path(DataDir)
	var t takeover
	if st, err := os.Lstat(filepath.Join(dir, tailnetStateFile)); err == nil && st.Mode().IsRegular() {
		t.enrolled = true
	}
	read := func(name string, v any) (bool, error) {
		b, err := readNoFollow(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("setup: %s: %w", name, err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			return false, fmt.Errorf("setup: %s is not readable: %w", name, err)
		}
		return true, nil
	}
	var hold struct {
		Hostname string `json:"hostname"`
	}
	held, err := read(tailnetHoldFile, &hold)
	if err != nil {
		return t, err
	}
	t.held, t.holdName = held, hold.Hostname
	var j takeoverRecord
	ok, err := read(takeoverFile, &j)
	if err != nil {
		return t, err
	}
	if ok {
		t.journal = &j
	}
	return t, nil
}

// configValue is varlatchd.conf's value for key ("" when it has none),
// read as varlatchd reads it (a leading UTF-8 byte order mark ignored).
func (r *run) configValue(key string) string {
	b, err := os.ReadFile(r.path(ConfigFile))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimPrefix(string(b), "\ufeff"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func orTailscale(controlURL string) string {
	if controlURL == "" {
		return "none: Tailscale's control server"
	}
	return controlURL
}

// issuances is `varlatchd admin certificate issuances --json`.
type issuances struct {
	Name     string     `json:"name"`
	Limit    int        `json:"limit"`
	Attempts int        `json:"attempts"`
	Until    *time.Time `json:"until"`
	Full     bool       `json:"full"`
}

// issuanceCheck: a restore with public HTTPS reads the restored
// installation's certificate issuance count (decision 16; every request
// for the name it started, restores and renewals included) before
// varlatchd first asks the CA. At Let's Encrypt's five per exact name per
// week, the restore is refused before it asks, and says when the oldest
// request leaves the week; the restored data stays, and setup run again
// then goes on from here.
func (r *run) issuanceCheck(ctx context.Context) error {
	if r.j.Restore == nil || r.j.Answers.Ingress != Public {
		return nil
	}
	out, err := r.h.Admin(ctx, "certificate", "issuances", "--json")
	if err != nil {
		return err
	}
	var c issuances
	if err := json.Unmarshal(out, &c); err != nil {
		return errors.New("setup: varlatchd admin certificate issuances gave no count")
	}
	if c.Full {
		until := "the oldest request leaves the week"
		if c.Until != nil {
			until = c.Until.UTC().Format(time.RFC3339)
		}
		return fmt.Errorf("setup: the restored installation's records show %d certificate requests for %s in the last 7 days and an hour, Let's Encrypt's limit of %d per name per week: varlatchd's first request would be refused. Nothing has asked; the restored data stays. Run setup again after %s",
			c.Attempts, c.Name, c.Limit, until)
	}
	if c.Limit == 0 {
		return nil
	}
	return r.o.Say(fmt.Sprintf("Certificate requests for %s in the last 7 days and an hour, by the restored records: %d of Let's Encrypt's %d.", c.Name, c.Attempts, c.Limit))
}

// probeResult is `varlatchd admin tailnet probe-name --json`.
type probeResult struct {
	Seen       []string `json:"seen"`
	Reusable   bool     `json:"reusable"`
	SecondJoin string   `json:"secondJoin"`
}

// nameCheck: a restore with tailnet ingress checks, before the restored
// installation's node first enrols, that its name is free (decision 16): a
// probe joins with the auth key, twice, and leaves. A peer under the name
// refuses the restore; so does a key that joins once only, since the
// probe spent it. Nothing seen is not "free" (the tailnet's access rules
// may hide nodes): varlatchd reads its name back after enrolment and keeps
// tailnet access closed when the control plane suffixed it.
func (r *run) nameCheck(ctx context.Context) error {
	a := r.j.Answers
	if r.j.Restore == nil || a.Ingress != Tailnet || r.j.Done["name"] != "" {
		return nil
	}
	if a.TailscaleOAuthClientFile != "" || a.HeadscaleAPIKeyFile != "" {
		return r.takeName(ctx)
	}
	if err := r.o.Say("Checking that the tailnet name " + a.TailnetHostname + " is free: a probe joins with your auth key, twice, and leaves."); err != nil {
		return err
	}
	out, err := r.h.Admin(ctx, "tailnet", "probe-name", "--json")
	if err != nil {
		return err
	}
	var res probeResult
	if err := json.Unmarshal(out, &res); err != nil {
		return errors.New("setup: varlatchd admin tailnet probe-name gave no result")
	}
	if len(res.Seen) > 0 {
		return fmt.Errorf("setup: the tailnet name %s is still held by %s (the old installation's node, if it is not deleted): delete that node in the tailnet's admin console, then run setup again; nothing has enrolled",
			a.TailnetHostname, strings.Join(res.Seen, ", "))
	}
	if !res.Reusable {
		return fmt.Errorf("setup: the auth key in %s joined once only, so it is single-use and the probe has spent it (a restore checks the name with the key before enrolling with it). Create a reusable auth key tagged %s (Tailscale's admin console: Settings, Keys, Generate auth key, Reusable, with those tags), put it in %s, and run setup again; revoke it once the restore is done",
			a.TailnetAuthKeyFile, a.TailnetTags, a.TailnetAuthKeyFile)
	}
	return r.o.Say("No node named " + a.TailnetHostname + " is visible to the probe. The tailnet's access rules may hide some: varlatchd reads its name back after enrolling, and keeps tailnet access closed if the control plane added a suffix.")
}
