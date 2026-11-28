// SPDX-License-Identifier: Apache-2.0

// Package upgraderequest holds the files through which the web app asks the
// host to upgrade (ADR-0065 Decisions 1 and 7), in the upgrade-request
// directory of varlatchd's data directory:
//
//	request.json   the one pending request: a version, its id, who asked,
//	               when it expires. varlatchd writes it whole (a temporary
//	               file renamed into place) and removes it to cancel; the
//	               host helper takes it by renaming it into its own
//	               root-only directory, and exactly one of the two wins.
//	status.json    what the host helper did with the last request it took
//	               (taken, refused and why, the journal it ran), written
//	               through `varlatchd admin upgrade-request record` as the
//	               data directory's owner.
//	helper.json    that the helper is installed, its version, whether it
//	               accepts requests, and a heartbeat from each release
//	               check, written the same way.
//
// None of them is authority. The request is untrusted input to the helper,
// which verifies and judges everything again itself; the status and the
// heartbeat are for display, and a forged one can make the dashboard show
// something, never make an upgrade happen.
package upgraderequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/varlatch/varlatch/go/lib/release"
)

// The directory and its files.
const (
	Dir         = "upgrade-request"
	RequestFile = "request.json"
	StatusFile  = "status.json"
	HelperFile  = "helper.json"
)

// Format is the one format of the three files.
const Format = 1

// MaxBytes is the most a request file may hold: the helper reads no more.
const MaxBytes = 4096

// Lifetime is how long a request may wait for the host (Decision 2).
const Lifetime = 10 * time.Minute

// TimeLayout is how the files write a time.
const TimeLayout = "2006-01-02T15:04:05.000Z"

var (
	requestIDPattern  = regexp.MustCompile(`^upr_[a-z2-7]{26}$`)
	identityIDPattern = regexp.MustCompile(`^idn_[a-z2-7]{26}$`)
	journalIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// ValidRequestID is whether id can be a request's id.
func ValidRequestID(id string) bool { return requestIDPattern.MatchString(id) }

// Request is one upgrade request: only a version, with its id, who asked
// and when it expires. No repository, URL, digest or flag: nothing in it
// can choose what is downloaded or from where.
type Request struct {
	Format      int    `json:"format"`
	ID          string `json:"id"`
	Version     string `json:"version"`
	RequestedBy string `json:"requestedBy"`
	RequestedAt string `json:"requestedAt"`
	ExpiresAt   string `json:"expiresAt"`
}

// NewRequest is a request for version by the identity, now, expiring after
// Lifetime.
func NewRequest(id, version, identityID string, now time.Time) Request {
	return Request{Format: Format, ID: id, Version: version, RequestedBy: identityID,
		RequestedAt: now.UTC().Format(TimeLayout), ExpiresAt: now.Add(Lifetime).UTC().Format(TimeLayout)}
}

// MaxSkew is how far ahead of the host's clock a request may say it was
// made: varlatchd runs on the host, so only a little.
const MaxSkew = 2 * time.Minute

// Expires is when the request expires.
func (r Request) Expires() time.Time {
	t, _ := time.Parse(TimeLayout, r.ExpiresAt)
	return t
}

// Current is whether the request may be acted on at now: not expired, and
// not made later than now and MaxSkew. With Check's bound on its expiry,
// a request is never acted on more than Lifetime and MaxSkew after the
// time it names, whatever that time is.
func (r Request) Current(now time.Time) bool {
	at, err := time.Parse(TimeLayout, r.RequestedAt)
	return err == nil && now.Before(r.Expires()) && !at.After(now.Add(MaxSkew))
}

// Check is the request's strict schema: every member present and valid, a
// release version, an expiry no more than Lifetime after the request.
func (r Request) Check() error {
	if r.Format != Format {
		return fmt.Errorf("upgrade request: format %d, not %d", r.Format, Format)
	}
	if !ValidRequestID(r.ID) || !identityIDPattern.MatchString(r.RequestedBy) || !release.ValidVersion(r.Version) {
		return errors.New("upgrade request: an id, an identity or a version that is not one")
	}
	at, err1 := time.Parse(TimeLayout, r.RequestedAt)
	until, err2 := time.Parse(TimeLayout, r.ExpiresAt)
	if err1 != nil || err2 != nil || !until.After(at) || until.Sub(at) > Lifetime {
		return errors.New("upgrade request: its times are not a request's")
	}
	return nil
}

// ParseRequest reads a request file's bytes, strictly: at most MaxBytes,
// one JSON object with exactly the members of Request, valid.
func ParseRequest(b []byte) (Request, error) {
	var r Request
	if len(b) > MaxBytes {
		return r, fmt.Errorf("upgrade request: more than %d bytes", MaxBytes)
	}
	if err := strict(b, &r); err != nil {
		return Request{}, fmt.Errorf("upgrade request: %w", err)
	}
	return r, r.Check()
}

// Encode is the request's file.
func (r Request) Encode() ([]byte, error) {
	if err := r.Check(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	return append(b, '\n'), err
}

// strict decodes one JSON object into v: no unknown member, no missing
// one, nothing after it.
func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more than one JSON value")
	}
	// Every member present: the same object, encoded again, has as many
	// members as the one read.
	var given, again map[string]json.RawMessage
	if err := json.Unmarshal(b, &given); err != nil {
		return err
	}
	re, _ := json.Marshal(v)
	if err := json.Unmarshal(re, &again); err != nil {
		return err
	}
	for k := range again {
		if _, ok := given[k]; !ok {
			return fmt.Errorf("no member %q", k)
		}
	}
	return nil
}

// Phase is how far the helper got with a request.
type Phase string

// The phases, in order; the last five end a request.
const (
	Taken     Phase = "taken"
	Verifying Phase = "verifying"
	BackingUp Phase = "backing-up"
	Restart   Phase = "restarting"
	Checking  Phase = "checking"
	Done      Phase = "done"
	Refused   Phase = "refused"
	Failed    Phase = "failed"
	Undone    Phase = "undone"
)

var phases = []Phase{Taken, Verifying, BackingUp, Restart, Checking, Done, Refused, Failed, Undone}

// Final is whether the phase ends the request.
func (p Phase) Final() bool { return p == Done || p == Refused || p == Failed || p == Undone }

// Reasons are the classes a refusal or a failure is recorded with: never
// free text (Decision 7).
var Reasons = map[Phase][]string{
	Refused: {
		"disabled",             // the host does not accept requests (web-upgrade.conf)
		"expired",              // it expired before the host took it, or names a time ahead of the host's clock
		"not-newer",            // the version is not newer than the installed one
		"prerelease",           // the version is a prerelease
		"superseded",           // a newer release was published since
		"not-latest",           // the version is not the latest release
		"not-rollback-safe",    // not declared rollback-safe for the installed release
		"ends-rollback-window", // it would end a migration's rollback window
		"undone",               // the host already undid an upgrade to it, or rolled back from it
		"held",                 // the installation is held after a restore
		"pending",              // another upgrade or rollback is not over
		"maintenance",          // a maintenance gate is set
		"schema",               // the release's schema is below the database's
		"no-backup-destination",
		"unreachable", // GitHub did not say which release is the newest, or could not be reached
	},
	Failed: {
		"verification", // the release did not verify (a security event)
		"backup",       // the snapshot, its upload or the delivered copy's check failed
		"error",        // anything else before the stop
		"undo",         // a health check failed and the undo did not complete
	},
	Undone: {"health"},
}

// Status is the helper's record of one request.
type Status struct {
	Format    int    `json:"format"`
	RequestID string `json:"requestId"`
	Version   string `json:"version"`
	Phase     Phase  `json:"phase"`
	Reason    string `json:"reason"`
	JournalID string `json:"journalId"`
	UpdatedAt string `json:"updatedAt"`
}

// Check is the status record's schema.
func (s Status) Check() error {
	if s.Format != Format || !ValidRequestID(s.RequestID) || s.Version != "" && !release.ValidVersion(s.Version) || !slices.Contains(phases, s.Phase) {
		return errors.New("upgrade request status: not a status record")
	}
	if want := Reasons[s.Phase]; len(want) > 0 != (s.Reason != "") || s.Reason != "" && !slices.Contains(want, s.Reason) {
		return fmt.Errorf("upgrade request status: reason %q for %s", s.Reason, s.Phase)
	}
	if s.JournalID != "" && !journalIDPattern.MatchString(s.JournalID) {
		return errors.New("upgrade request status: a journal id that is not one")
	}
	if _, err := time.Parse(TimeLayout, s.UpdatedAt); err != nil {
		return errors.New("upgrade request status: no time")
	}
	return nil
}

// Helper is the host helper's record of itself.
type Helper struct {
	Format  int    `json:"format"`
	Version string `json:"version"`
	// Enabled is whether the host accepts requests (web-upgrade.conf).
	Enabled     bool   `json:"enabled"`
	HeartbeatAt string `json:"heartbeatAt"`
	// Problem is why the helper's last run could not take a request, one
	// of HelperProblems, "" for none: the next heartbeat without one (the
	// release check's, or --enable-web's) clears it.
	Problem string `json:"problem,omitempty"`
}

// HelperProblems are the classes a helper's problem is recorded with,
// never free text. The request stays in request.json, and the helper tries
// again about once a minute until varlatchd removes it at its expiry.
var HelperProblems = []string{
	"data-directory", // varlatchd's configuration named no data directory the helper could use
	"take",           // the request could not be taken: a directory on the way is not what it must be
}

// Check is the helper record's schema.
func (h Helper) Check() error {
	if h.Format != Format || !release.ValidVersion(h.Version) {
		return errors.New("upgrade helper record: not a helper record")
	}
	if h.Problem != "" && !slices.Contains(HelperProblems, h.Problem) {
		return fmt.Errorf("upgrade helper record: problem %q", h.Problem)
	}
	if _, err := time.Parse(TimeLayout, h.HeartbeatAt); err != nil {
		return errors.New("upgrade helper record: no time")
	}
	return nil
}

// Heartbeat is when the helper last said it is there.
func (h Helper) Heartbeat() time.Time {
	t, _ := time.Parse(TimeLayout, h.HeartbeatAt)
	return t
}

// WriteStatus records s in dataDir, whole and durably, readable by the
// varlatchd that serves it.
func WriteStatus(dataDir string, s Status) error { return writeRecord(dataDir, StatusFile, s, s.Check) }

// WriteHelper records h in dataDir the same way.
func WriteHelper(dataDir string, h Helper) error { return writeRecord(dataDir, HelperFile, h, h.Check) }

func writeRecord(dataDir, name string, v any, check func() error) error {
	if err := check(); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := MakeDir(dataDir); err != nil {
		return err
	}
	err = release.WriteDurably(filepath.Join(dataDir, Dir, name), append(b, '\n'), 0o644)
	if errors.Is(err, release.ErrNotDurable) {
		return nil
	}
	return err
}

// MakeDir makes the upgrade-request directory in dataDir, its owner's
// alone (the host helper is root).
func MakeDir(dataDir string) error {
	dir := filepath.Join(dataDir, Dir)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// ReadStatus reads dataDir's status record: nil when there is none.
func ReadStatus(dataDir string) (*Status, error) {
	var s Status
	ok, err := readRecord(dataDir, StatusFile, &s)
	if !ok || err != nil {
		return nil, err
	}
	return &s, s.Check()
}

// ReadHelper reads dataDir's helper record: nil when there is none.
func ReadHelper(dataDir string) (*Helper, error) {
	var h Helper
	ok, err := readRecord(dataDir, HelperFile, &h)
	if !ok || err != nil {
		return nil, err
	}
	return &h, h.Check()
}

// ReadRequest reads dataDir's pending request, as varlatchd reads its own
// file: nil when there is none.
func ReadRequest(dataDir string) (*Request, error) {
	var r Request
	b, err := readSmall(filepath.Join(dataDir, Dir, RequestFile))
	if b == nil || err != nil {
		return nil, err
	}
	if r, err = ParseRequest(b); err != nil {
		return nil, err
	}
	return &r, nil
}

func readRecord(dataDir, name string, v any) (bool, error) {
	b, err := readSmall(filepath.Join(dataDir, Dir, name))
	if b == nil || err != nil {
		return false, err
	}
	if err := strict(b, v); err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return true, nil
}

// readSmall reads a file of at most MaxBytes: nil, nil when there is none.
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("%s holds more than %d bytes", path, MaxBytes)
	}
	return b, nil
}

// ErrPending refuses a request while another one is in request.json.
var ErrPending = errors.New("upgrade request: one is already waiting for the host")

// ErrTaken is a cancel that found no request: the host took it first.
var ErrTaken = errors.New("upgrade request: the host has taken it")

// WriteRequest puts r in dataDir's request.json, whole: written to a
// temporary name in the same directory, synced, then renamed to
// request.json, so the host's path unit never sees a part. It refuses
// while a request is there. Only one process writes there (varlatchd, under
// its own lock), so the check and the rename do not race another writer.
func WriteRequest(dataDir string, r Request) error {
	b, err := r.Encode()
	if err != nil {
		return err
	}
	if err := MakeDir(dataDir); err != nil {
		return err
	}
	path := filepath.Join(dataDir, Dir, RequestFile)
	if _, err := os.Lstat(path); err == nil {
		return ErrPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = release.WriteDurably(path, b, 0o600)
	if errors.Is(err, release.ErrNotDurable) {
		return nil
	}
	return err
}

// CancelRequest removes dataDir's request.json when it is the request id:
// ErrTaken when there is none (the host renamed it away first), so exactly
// one of the cancel and the take succeeds.
func CancelRequest(dataDir, id string) error {
	r, err := ReadRequest(dataDir)
	if err != nil {
		return err
	}
	if r == nil || r.ID != id {
		return ErrTaken
	}
	if err := os.Remove(filepath.Join(dataDir, Dir, RequestFile)); errors.Is(err, os.ErrNotExist) {
		return ErrTaken
	} else if err != nil {
		return err
	}
	return nil
}
