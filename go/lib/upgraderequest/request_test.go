// SPDX-License-Identifier: Apache-2.0

package upgraderequest

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	testID       = "upr_" + strings.Repeat("a", 26)
	testIdentity = "idn_" + strings.Repeat("b", 26)
	testNow      = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
)

func TestParseRequestIsStrict(t *testing.T) {
	r := NewRequest(testID, "0.52.0", testIdentity, testNow)
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRequest(b)
	if err != nil || got != r || !got.Expires().Equal(testNow.Add(Lifetime)) {
		t.Fatalf("%+v, %v", got, err)
	}
	good := string(b)
	for name, bad := range map[string]string{
		"an unknown member":     strings.Replace(good, `"format":1`, `"format":1,"repo":"elsewhere/varlatch"`, 1),
		"a missing member":      strings.Replace(good, `,"requestedBy":"`+testIdentity+`"`, "", 1),
		"a member in caps":      strings.Replace(good, `"version"`, `"Version"`, 1),
		"two values":            good + good,
		"another format":        strings.Replace(good, `"format":1`, `"format":2`, 1),
		"not a version":         strings.Replace(good, `"0.52.0"`, `"0.52.0; rm -rf /"`, 1),
		"not an id":             strings.Replace(good, testID, "upr_short", 1),
		"too long a lifetime":   strings.Replace(good, r.ExpiresAt, testNow.Add(Lifetime+time.Second).Format(TimeLayout), 1),
		"expiring before asked": strings.Replace(good, r.ExpiresAt, testNow.Add(-time.Second).Format(TimeLayout), 1),
		"too big":               good[:len(good)-2] + `,"pad":"` + strings.Repeat("x", MaxBytes) + `"}`,
	} {
		if _, err := ParseRequest([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// One request at a time; a cancel removes it, once; a cancel after the take
// finds nothing (ErrTaken).
func TestWriteAndCancel(t *testing.T) {
	dir := t.TempDir()
	r := NewRequest(testID, "0.52.0", testIdentity, testNow)
	if err := WriteRequest(dir, r); err != nil {
		t.Fatal(err)
	}
	// The modes are a Unix host's; Windows keeps none of them.
	info, err := os.Stat(filepath.Join(dir, Dir, RequestFile))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	if d, _ := os.Stat(filepath.Join(dir, Dir)); runtime.GOOS != "windows" && d.Mode().Perm() != 0o700 {
		t.Fatalf("the directory's mode: %v", d.Mode())
	}
	other := NewRequest("upr_"+strings.Repeat("c", 26), "0.52.0", testIdentity, testNow)
	if err := WriteRequest(dir, other); !errors.Is(err, ErrPending) {
		t.Fatalf("a second request: %v", err)
	}
	if err := CancelRequest(dir, other.ID); !errors.Is(err, ErrTaken) {
		t.Fatalf("cancel of another id: %v", err)
	}
	if err := CancelRequest(dir, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := CancelRequest(dir, r.ID); !errors.Is(err, ErrTaken) {
		t.Fatalf("a second cancel: %v", err)
	}
	if got, err := ReadRequest(dir); got != nil || err != nil {
		t.Fatalf("%+v %v", got, err)
	}
}

// A symlinked upgrade-request directory (or a file in its place, or a
// symlinked request.json) is refused: nothing outside the directory is
// read, written or removed.
func TestCancelRefusesSymlink(t *testing.T) {
	r := NewRequest(testID, "0.52.0", testIdentity, testNow)
	raw, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// A plain file where upgrade-request belongs is refused.
	fileData := t.TempDir()
	if err := os.WriteFile(filepath.Join(fileData, Dir), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CancelRequest(fileData, r.ID); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("regular file as upgrade-request: %v", err)
	}

	// A symlinked upgrade-request directory: refused, target untouched.
	elsewhere := t.TempDir()
	targetReq := filepath.Join(elsewhere, RequestFile)
	if err := os.WriteFile(targetReq, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	at := testNow.Format(TimeLayout)
	linkData := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(linkData, Dir)); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on this Windows host: %v", err)
		}
		t.Fatal(err)
	}
	if err := CancelRequest(linkData, r.ID); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory cancel: %v", err)
	}
	if got, err := os.ReadFile(targetReq); err != nil || string(got) != string(raw) {
		t.Fatalf("target request touched: %q %v", got, err)
	}
	if _, err := ReadRequest(linkData); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory ReadRequest: %v", err)
	}
	if _, err := ReadStatus(linkData); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory ReadStatus: %v", err)
	}
	if _, err := ReadHelper(linkData); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory ReadHelper: %v", err)
	}
	if err := WriteRequest(linkData, r); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory WriteRequest: %v", err)
	}
	if err := WriteStatus(linkData, Status{Format: Format, RequestID: r.ID, Phase: Taken, UpdatedAt: at}); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory WriteStatus: %v", err)
	}
	if err := WriteHelper(linkData, Helper{Format: Format, Version: "0.52.0", Enabled: true, HeartbeatAt: at}); !errors.Is(err, ErrNotDirectory) {
		t.Fatalf("symlinked directory WriteHelper: %v", err)
	}

	// A symlinked request.json inside a real upgrade-request directory:
	// refused, link and target both untouched.
	realData := t.TempDir()
	if err := MakeDir(realData); err != nil {
		t.Fatal(err)
	}
	reqLink := filepath.Join(realData, Dir, RequestFile)
	if err := os.Symlink(targetReq, reqLink); err != nil {
		t.Fatal(err)
	}
	if err := CancelRequest(realData, r.ID); err == nil {
		t.Fatal("symlinked request.json was cancelled")
	}
	if _, err := os.Lstat(reqLink); err != nil {
		t.Fatalf("symlinked request.json was removed: %v", err)
	}
	if got, err := os.ReadFile(targetReq); err != nil || string(got) != string(raw) {
		t.Fatalf("target request touched through file link: %q %v", got, err)
	}
}

func TestStatusAndHelperRecords(t *testing.T) {
	dir := t.TempDir()
	at := testNow.Format(TimeLayout)
	good := Status{Format: Format, RequestID: testID, Version: "0.52.0", Phase: Refused, Reason: "undone", UpdatedAt: at}
	if err := WriteStatus(dir, good); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadStatus(dir); err != nil || *s != good {
		t.Fatalf("%+v %v", s, err)
	}
	for name, bad := range map[string]Status{
		"free text":         {Format: Format, RequestID: testID, Phase: Refused, Reason: "it said no", UpdatedAt: at},
		"no reason":         {Format: Format, RequestID: testID, Phase: Failed, UpdatedAt: at},
		"a reason for none": {Format: Format, RequestID: testID, Phase: Done, Reason: "health", UpdatedAt: at},
		"a phase":           {Format: Format, RequestID: testID, Phase: "elsewhere", UpdatedAt: at},
		"a journal":         {Format: Format, RequestID: testID, Phase: Taken, JournalID: "../x", UpdatedAt: at},
	} {
		if err := WriteStatus(dir, bad); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	h := Helper{Format: Format, Version: "0.52.0", Enabled: true, HeartbeatAt: at}
	if err := WriteHelper(dir, h); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHelper(dir); err != nil || *got != h || !got.Heartbeat().Equal(testNow) {
		t.Fatalf("%+v %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, Dir, HelperFile), []byte(`{"format":1,"version":"0.52.0","enabled":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHelper(dir); err == nil {
		t.Fatal("a helper record without its heartbeat was read")
	}
	// A problem, by class: written, read, and anything else refused.
	h.Problem = "take"
	if err := WriteHelper(dir, h); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHelper(dir); err != nil || got.Problem != "take" {
		t.Fatalf("%+v %v", got, err)
	}
	h.Problem = "the disk is on fire"
	if err := WriteHelper(dir, h); err == nil {
		t.Fatal("a problem that is not a class was written")
	}
}

// A request is current from the time it names (and a little before, the
// skew) until it expires: never more than Lifetime and MaxSkew after that
// time, wherever it puts it.
func TestCurrent(t *testing.T) {
	r := NewRequest(testID, "0.52.0", "idn_"+strings.Repeat("b", 26), testNow)
	for d, want := range map[time.Duration]bool{
		0: true, Lifetime - time.Millisecond: true, Lifetime: false,
		-MaxSkew: true, -MaxSkew - time.Millisecond: false, -time.Hour: false,
	} {
		if got := r.Current(testNow.Add(d)); got != want {
			t.Errorf("%s from the request: current %v", d, got)
		}
	}
}

func TestConf(t *testing.T) {
	for _, accept := range []bool{true, false} {
		if got, err := ParseConf(EncodeConf(accept)); err != nil || got != accept {
			t.Fatalf("%v: %v %v", accept, got, err)
		}
	}
	for _, bad := range []string{"", "accept_requests = maybe\n", "accept_requests = yes\naccept_requests = yes\n", "repo = elsewhere\n"} {
		if _, err := ParseConf([]byte(bad)); err == nil {
			t.Errorf("%q: read", bad)
		}
	}
	dir := t.TempDir()
	if on, err := Accepting(dir); on || err != nil {
		t.Fatalf("no file: %v %v", on, err)
	}
}
