// SPDX-License-Identifier: Apache-2.0

package upgraderequest

import (
	"errors"
	"os"
	"path/filepath"
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
	info, err := os.Stat(filepath.Join(dir, Dir, RequestFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	if d, _ := os.Stat(filepath.Join(dir, Dir)); d.Mode().Perm() != 0o700 {
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
