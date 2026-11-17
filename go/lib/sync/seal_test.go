// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// WriteValues sends GitHub each value sealed to the destination's public
// key: every ciphertext submitted opens, with the recipient's secret key,
// to exactly the requested value's UTF-8 bytes (a lone surrogate as
// U+FFFD, as JavaScript encodes it), under the key id GitHub gave.
func TestGitHubSealsEachRequestedValue(t *testing.T) {
	public, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	items := []SyncItem{
		{"DATABASE_URL", "postgres://user:pw@host/db"},
		{"EMPTY", ""},
		{"UNICODE", "é€\U0001F600"},
		{"LONE", "lone \xed\xa0\x80 surrogate"},
		{"LONG", strings.Repeat("x", 4096)},
		{"BINARYISH", "line\nbreak\x00nul"},
	}
	want := map[string][]byte{}
	for _, it := range items {
		want[it.Name] = []byte(it.Value)
	}
	want["LONE"] = []byte("lone � surrogate")

	got := map[string][]byte{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		answer := func(status int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}
		path := r.URL.RequestURI()
		if strings.HasSuffix(path, "/public-key") {
			return answer(200, `{"key_id":"kid-1","key":"`+base64.StdEncoding.EncodeToString(public[:])+`"}`)
		}
		b, _ := io.ReadAll(r.Body)
		v, err := parseJSON(b)
		if err != nil {
			t.Fatalf("%s: %v", r.URL, err)
		}
		o := v.(Object)
		if o.Value("key_id") != "kid-1" {
			t.Errorf("%s: key_id %v", r.URL, o.Value("key_id"))
		}
		sealed, err := base64.StdEncoding.DecodeString(o.Value("encrypted_value").(string))
		if err != nil {
			t.Fatal(err)
		}
		opened, ok := SealedBoxOpen(sealed, public[:], secret[:])
		if !ok {
			t.Fatalf("%s: the sealed value does not open", r.URL)
		}
		got[path[strings.LastIndexByte(path, '/')+1:]] = opened
		return answer(201, "")
	})}
	req := &Request{BaseIdentity: "acme", Destination: Fields{{"repo", "api"}}, Credential: "t", Client: client}
	outcomes, err := GitHubActionsAdapter.WriteValues(context.Background(), req, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != len(items) || len(got) != len(items) {
		t.Fatalf("%d outcomes, %d values sent", len(outcomes), len(got))
	}
	for name, w := range want {
		if !bytes.Equal(got[name], w) {
			t.Errorf("%s: sealed %q, want %q", name, got[name], w)
		}
	}
}
