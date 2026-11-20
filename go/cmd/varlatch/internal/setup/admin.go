// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"crypto/subtle"
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

// The steps after the unit is ready (slice 6.4b): the first administrator's
// passkey, the keys shown and pasted back, the Custody Attestation, the
// first backup verified, doctor. Each asks varlatchd through Host.Admin;
// nothing here reads the database.

// bootstrapStatus is `varlatchd admin bootstrap-status`.
type bootstrapStatus struct {
	Initialized  bool `json:"initialized"`
	Bootstrapped bool `json:"bootstrapped"`
	Admins       []struct {
		ID         string `json:"id"`
		Enabled    bool   `json:"enabled"`
		HasPasskey bool   `json:"hasPasskey"`
	} `json:"admins"`
}

// ready is the first enabled Installation Admin with a passkey ("" when
// none has one yet).
func (s bootstrapStatus) ready() string {
	for _, a := range s.Admins {
		if a.Enabled && a.HasPasskey {
			return a.ID
		}
	}
	return ""
}

// issue is the admin command that gives a passkey link: bootstrap, or,
// when an administrator was made but never enrolled one (an interrupted
// enrollment, a headless bootstrap), a recovery link for that one.
func (s bootstrapStatus) issue() []string {
	if !s.Bootstrapped {
		return []string{"bootstrap"}
	}
	for _, a := range s.Admins {
		if a.Enabled {
			return []string{"recover", "--identity", a.ID}
		}
	}
	return []string{"recover", "--new-admin"}
}

func (r *run) bootstrapStatus(ctx context.Context) (bootstrapStatus, error) {
	var st bootstrapStatus
	out, err := r.h.Admin(ctx, "bootstrap-status")
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(out, &st); err != nil || !st.Initialized {
		return st, errors.New("setup: varlatchd admin bootstrap-status gave no installation")
	}
	return st, nil
}

var (
	enrollLink = regexp.MustCompile(`https?://\S+/enroll#\S+`)
	expiresAt  = regexp.MustCompile(`Expires: (\S+?)\.?(\s|$)`)
	// linkFile is what an earlier run wrote to --admin-link-out: one link.
	linkFile = regexp.MustCompile(`^https?://\S+/enroll#\S+\n?$`)
)

// admin: the first administrator's passkey. Setup issues a one-time
// enrollment link (shown on the terminal, or written to --admin-link-out
// without one) and waits until an enabled Installation Admin has a
// passkey; a rerun after the link lapsed issues another.
func (r *run) admin(ctx context.Context) error {
	st, err := r.bootstrapStatus(ctx)
	if err != nil {
		return err
	}
	if id := st.ready(); id != "" {
		return r.o.Say("The first administrator (" + id + ") has a passkey.")
	}
	issue := st.issue()
	out, err := r.h.Admin(ctx, issue...)
	if err != nil {
		return err
	}
	// Copied out of varlatchd's output, which is cleared below.
	link := append([]byte(nil), enrollLink.Find(out)...)
	expires := ""
	if m := expiresAt.FindSubmatch(out); m != nil {
		expires = string(m[1])
	}
	clear(out)
	if len(link) == 0 {
		return errors.New("setup: varlatchd gave no enrollment link")
	}
	defer clear(link)
	if issue[0] != "bootstrap" {
		if err := r.o.Say("An administrator exists but never finished enrolling a passkey: a new link for them."); err != nil {
			return err
		}
	}
	if r.o.Ask != nil && r.o.ShowLink != nil {
		if err := r.o.ShowLink(string(link), expires); err != nil {
			return err
		}
	} else {
		if err := writeLink(r.o.AdminLinkOut, link); err != nil {
			return err
		}
		if err := r.o.Say("Wrote the first administrator's one-time enrollment link to " + r.o.AdminLinkOut + " (0600; it expires " + expires + "): open it in the browser where you will sign in, and create a passkey."); err != nil {
			return err
		}
	}
	if r.o.AdminWait <= 0 {
		return fmt.Errorf("%w: enroll the first administrator's passkey from the link, then run setup again", ErrPending)
	}
	if err := r.o.Say("Waiting for the passkey (up to " + r.o.AdminWait.String() + ")."); err != nil {
		return err
	}
	// The wait is real time (the journal's clock may be a test's).
	deadline := time.Now().Add(r.o.AdminWait)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.o.PollEvery):
		}
		st, err := r.bootstrapStatus(ctx)
		if err != nil {
			return err
		}
		if id := st.ready(); id != "" {
			return r.o.Say("The first administrator (" + id + ") has a passkey.")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: no passkey was enrolled in %s; run setup again for a new link", ErrPending, r.o.AdminWait)
		}
	}
}

// writeLink puts the link in the operator's file, 0600: a new file, or one
// that holds an earlier run's link (replaced); never another file, and
// never through a link.
func writeLink(path string, link []byte) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("setup: %s: name the link's file with an absolute path", path)
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return fmt.Errorf("setup: %s is not a regular file: name a new file; nothing was written there", path)
	default:
		got, err := os.ReadFile(path)
		earlier := err == nil && linkFile.Match(got)
		clear(got)
		if !earlier {
			return fmt.Errorf("setup: %s already exists and holds no earlier enrollment link: name a new file; nothing was written there", path)
		}
	}
	data := append(append([]byte{}, link...), '\n')
	defer clear(data)
	return replacePrivate(path, data)
}

// pasteBack asks for each key again, without echo, as the operator stored
// it: the copy is checked before setup records its custody. A wrong copy
// is refused (three tries a key); what was typed is never shown.
func (r *run) pasteBack(kek, bek []byte) error {
	for _, k := range []struct {
		name string
		key  []byte
	}{{"Root KEK", kek}, {"backup key", bek}} {
		want := bytes.ToLower(bytes.TrimSpace(k.key))
		ok := false
		for try := 0; try < 3 && !ok; try++ {
			got, err := r.o.Ask.Secret("Paste the " + k.name + " back from where you stored it (input hidden): ")
			if err != nil {
				return err
			}
			typed := bytes.ToLower(bytes.TrimSpace(got))
			ok = len(typed) == len(want) && subtle.ConstantTimeCompare(typed, want) == 1
			clear(got)
			clear(typed)
			if !ok {
				if err := r.o.Say("That is not the " + k.name + ": check the copy you stored, and paste it again."); err != nil {
					return err
				}
			}
		}
		if !ok {
			return fmt.Errorf("setup: the %s pasted back did not match three times: nothing was recorded; run setup again to see the keys again", k.name)
		}
		if err := r.o.Say("The " + k.name + " you stored matches."); err != nil {
			return err
		}
	}
	return nil
}

// custodyStatus is `varlatchd admin custody status`.
type custodyStatus struct {
	Attestations map[string]*struct {
		Method string `json:"method"`
		At     string `json:"at"`
	} `json:"attestations"`
}

// custody: the Custody Attestation (ADR-0035 D9), the operator's dated
// statement that both keys' copies are stored off this host: asked on a
// terminal, --attest without one. Recorded with `varlatchd admin custody
// attest`, method copy, for each key.
func (r *run) custody(ctx context.Context) error {
	out, err := r.h.Admin(ctx, "custody", "status")
	if err != nil {
		return err
	}
	var st custodyStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return errors.New("setup: varlatchd admin custody status is not one setup reads")
	}
	if st.Attestations["root-kek"] != nil && st.Attestations["backup-key"] != nil {
		return r.o.Say("The keys' custody is attested (" + st.Attestations["root-kek"].At + ").")
	}
	stored := r.o.Attest
	if !stored && r.o.Ask != nil {
		if stored, err = r.o.Ask.Confirm("Are both keys stored off this host, where you will find them without it?", false); err != nil {
			return err
		}
	}
	if !stored {
		if r.o.Ask == nil {
			return fmt.Errorf("%w: store the two copies (%s, %s) off this host and delete them here, then run setup again with --attest", ErrPending, r.o.RootKEKOut, r.o.BackupKeyOut)
		}
		return fmt.Errorf("%w: store both keys off this host, then run setup again", ErrPending)
	}
	for _, key := range []string{"root-kek", "backup-key"} {
		if st.Attestations[key] != nil {
			continue
		}
		if _, err := r.h.Admin(ctx, "custody", "attest", "--key", key, "--method", "copy"); err != nil {
			return err
		}
	}
	return r.o.Say("Recorded your Custody Attestation for both keys (dated; the installation cannot check copies held elsewhere).")
}

// backupResult is `varlatchd admin backup run --json`.
type backupResult struct {
	ArchiveID    string `json:"archiveId"`
	Verification *struct {
		Integrity     bool `json:"integrity"`
		Compatibility bool `json:"compatibility"`
		KeyMatch      bool `json:"keyMatch"`
	} `json:"verification"`
	Delivery *struct {
		Destination string `json:"destination"`
	} `json:"delivery"`
	UploadError string `json:"uploadError"`
}

// backup: the first backup, made and verified (its integrity, its
// compatibility, the Root KEK it needs), and with a bucket delivered.
func (r *run) backup(ctx context.Context) error {
	if r.j.Done["backup"] != "" {
		return nil
	}
	if err := r.o.Say("Making the first backup."); err != nil {
		return err
	}
	out, err := r.h.Admin(ctx, "backup", "run", "--json")
	if err != nil {
		return err
	}
	var res backupResult
	if err := json.Unmarshal(out, &res); err != nil || res.ArchiveID == "" {
		return errors.New("setup: varlatchd admin backup run gave no archive")
	}
	v := res.Verification
	if v == nil || !v.Integrity || !v.Compatibility || !v.KeyMatch {
		return fmt.Errorf("setup: the first backup %s did not verify (integrity, compatibility, the Root KEK): run setup again; varlatchd admin backup status says more", res.ArchiveID)
	}
	delivered := ""
	if r.j.Answers.Backups == "bucket" {
		if res.Delivery == nil {
			return fmt.Errorf("setup: the first backup %s was verified here but not delivered to the bucket (%s): fix the destination, then run setup again", res.ArchiveID, strings.TrimSpace(res.UploadError))
		}
		delivered = ", and delivered to " + res.Delivery.Destination
	}
	r.j.FirstBackup = res.ArchiveID
	return r.o.Say("The first backup " + res.ArchiveID + " is made and verified: its integrity, its compatibility and the Root KEK" + delivered + ".")
}

// doctor: `varlatch doctor`, its report shown. Setup is done either way;
// a mandatory check that fails ends the run with ErrDoctor, and a rerun
// runs doctor again.
func (r *run) doctor(ctx context.Context) error {
	if r.o.Doctor == nil {
		return nil
	}
	ok, err := r.o.Doctor(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: see its report above; run setup again once it is fixed", ErrDoctor)
	}
	return nil
}
