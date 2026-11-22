// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ReleaseCheckFile is the host's last look for a newer release (ADR-0049),
// in the data directory: `varlatch upgrade --check` records it through
// `varlatchd admin release-check record`, and varlatchd only reads it, for
// GET /v1/installation/release. Display state, not authority: it starts
// nothing, and nothing in it is a URL. The format is the TypeScript line's
// (packages/backup/src/releaseCheck.ts).
const ReleaseCheckFile = "release-check.json"

// The release check's failures, as the TypeScript line names them.
var ReleaseCheckFailures = []string{"unreachable", "rate-limited", "not-found", "invalid-answer"}

var (
	// recordVersion is the TypeScript line's RELEASE_VERSION.
	recordVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	// checkRepo is the TypeScript line's RELEASE_REPO: owner/name.
	checkRepo = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
)

// Latest is the newest release a check found.
type Latest struct {
	Version     string  `json:"version"`
	PublishedAt *string `json:"publishedAt"`
}

// ReleaseCheck is the record.
type ReleaseCheck struct {
	LastAttempt struct {
		CheckedAt string  `json:"checkedAt"`
		Repo      string  `json:"repo"`
		Failed    *string `json:"failed"`
	} `json:"lastAttempt"`
	LastSuccess *struct {
		CheckedAt  string `json:"checkedAt"`
		Repo       string `json:"repo"`
		Latest     Latest `json:"latest"`
		ReleaseSet bool   `json:"releaseSet"`
	} `json:"lastSuccess"`
}

// CheckOutcome is one attempt, as the CLI reports it: found (Latest set) or
// failed (Failed set).
type CheckOutcome struct {
	Repo       string
	Latest     *Latest
	ReleaseSet bool
	Failed     string
}

func (o CheckOutcome) check() error {
	if !validRepo(o.Repo) {
		return fmt.Errorf("release check: %q is not a repository (owner/name)", o.Repo)
	}
	switch {
	case o.Latest != nil && o.Failed == "":
		return o.Latest.check()
	case o.Latest == nil && slices.Contains(ReleaseCheckFailures, o.Failed):
		return nil
	case o.Latest == nil && o.Failed != "":
		return fmt.Errorf("release check: %q is not a failure the record knows", o.Failed)
	}
	return errors.New("release check: an outcome is a release found or a failure, one of them")
}

// validRepo is the TypeScript line's RELEASE_REPO, its name neither "."
// nor "..".
func validRepo(r string) bool {
	if len(r) > 140 || !checkRepo.MatchString(r) {
		return false
	}
	_, name, _ := strings.Cut(r, "/")
	return name != "." && name != ".."
}

func (l Latest) check() error {
	if len(l.Version) > 100 || !recordVersion.MatchString(l.Version) {
		return fmt.Errorf("release check: %q is not a release version", l.Version)
	}
	if l.PublishedAt != nil {
		if _, err := time.Parse(time.RFC3339, *l.PublishedAt); err != nil {
			return fmt.Errorf("release check: %q is not a date and time", *l.PublishedAt)
		}
	}
	return nil
}

// ReadReleaseCheck reads the record: nil when none was ever recorded, an
// error when it is unreadable (not the record's shape included).
func ReadReleaseCheck(dir string) (*ReleaseCheck, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ReleaseCheckFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rc ReleaseCheck
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("release check: %s is not a release check: %w", ReleaseCheckFile, err)
	}
	if err := rc.check(); err != nil {
		return nil, err
	}
	return &rc, nil
}

func (rc ReleaseCheck) check() error {
	if _, err := time.Parse(time.RFC3339, rc.LastAttempt.CheckedAt); err != nil {
		return errors.New("release check: lastAttempt.checkedAt is not a date and time")
	}
	if !validRepo(rc.LastAttempt.Repo) {
		return errors.New("release check: lastAttempt.repo is not a repository")
	}
	if f := rc.LastAttempt.Failed; f != nil && !slices.Contains(ReleaseCheckFailures, *f) {
		return errors.New("release check: lastAttempt.failed is not a failure the record knows")
	}
	if s := rc.LastSuccess; s != nil {
		if _, err := time.Parse(time.RFC3339, s.CheckedAt); err != nil || !validRepo(s.Repo) {
			return errors.New("release check: lastSuccess is not a release found")
		}
		if err := s.Latest.check(); err != nil {
			return err
		}
	}
	return nil
}

// RecordReleaseCheck records one attempt at now, durably (a temporary file,
// synced, renamed over the record, the directory synced). A failure keeps
// the last success: an unreachable GitHub says nothing about which release
// is the latest. An unreadable record is replaced.
func RecordReleaseCheck(dir string, o CheckOutcome, now time.Time) (*ReleaseCheck, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	previous, _ := ReadReleaseCheck(dir)
	var rc ReleaseCheck
	at := now.UTC().Format("2006-01-02T15:04:05.000Z")
	rc.LastAttempt.CheckedAt, rc.LastAttempt.Repo = at, o.Repo
	if o.Latest != nil {
		rc.LastSuccess = &struct {
			CheckedAt  string `json:"checkedAt"`
			Repo       string `json:"repo"`
			Latest     Latest `json:"latest"`
			ReleaseSet bool   `json:"releaseSet"`
		}{at, o.Repo, *o.Latest, o.ReleaseSet}
	} else {
		failed := o.Failed
		rc.LastAttempt.Failed = &failed
		if previous != nil {
			rc.LastSuccess = previous.LastSuccess
		}
	}
	b, err := json.Marshal(rc)
	if err != nil {
		return nil, err
	}
	if err := WriteDurably(filepath.Join(dir, ReleaseCheckFile), append(b, '\n'), 0o644); err != nil {
		return nil, err
	}
	return &rc, nil
}

// ReleaseURL is a release's page, built from validated fields only.
func ReleaseURL(repo, version string) (string, error) {
	if !validRepo(repo) || !recordVersion.MatchString(version) {
		return "", errors.New("release check: not a release reference")
	}
	return "https://github.com/" + repo + "/releases/tag/v" + version, nil
}

// WriteDurably replaces path with data: a temporary file beside it, synced,
// renamed over it, then the directory synced, so a crash leaves the old
// file or the new one, never a part.
func WriteDurably(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
