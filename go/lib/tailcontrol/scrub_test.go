// SPDX-License-Identifier: Apache-2.0

package tailcontrol

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	// Characters that escaping changes, so each form differs.
	return "s/" + hex.EncodeToString(b) + "+=?&"
}

// answering serves one error answer whose message is msg.
func answering(t *testing.T, status int, msg string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, secret string) error {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	return do(srv.Client(), req, nil, secret)
}

// TestScrubBeforeTruncate: a credential that straddles the 200-byte cut is
// scrubbed whole before the message is cut, so no fragment of it remains.
func TestScrubBeforeTruncate(t *testing.T) {
	secret := randomSecret(t)
	for offset := 180; offset <= 200; offset++ {
		msg := strings.Repeat("x", offset) + secret + " and more"
		err := get(t, answering(t, http.StatusBadRequest, msg), secret)
		if err == nil {
			t.Fatal("no error")
		}
		// No 6-byte window of the secret, wherever in it, remains.
		for i := 0; i+6 <= len(secret); i++ {
			if strings.Contains(err.Error(), secret[i:i+6]) {
				t.Fatalf("offset %d: the error holds the secret's bytes %d to %d: %v", offset, i, i+6, err)
			}
		}
	}
}

// TestScrubEveryForm: the secret is scrubbed as sent, query- and
// path-escaped, and in every base64 form.
func TestScrubEveryForm(t *testing.T) {
	secret := randomSecret(t)
	b := []byte(secret)
	forms := map[string]string{
		"as sent":       secret,
		"query":         url.QueryEscape(secret),
		"path":          url.PathEscape(secret),
		"base64":        base64.StdEncoding.EncodeToString(b),
		"base64url":     base64.URLEncoding.EncodeToString(b),
		"base64 raw":    base64.RawStdEncoding.EncodeToString(b),
		"base64url raw": base64.RawURLEncoding.EncodeToString(b),
	}
	for name, form := range forms {
		err := get(t, answering(t, http.StatusUnauthorized, "you sent "+form), secret)
		if err == nil || strings.Contains(err.Error(), form) || !strings.Contains(err.Error(), "[redacted]") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := scrub("ab", "a"); got != "ab" {
		t.Errorf("a secret under 4 bytes is not scrubbed (it would scrub everything): %q", got)
	}
}

// TestTransportErrorsKeepTheirCause: a passed deadline stays
// context.DeadlineExceeded through the scrubbed error, and its text holds
// no credential although the request's URL carried one.
func TestTransportErrorsKeepTheirCause(t *testing.T) {
	secret := randomSecret(t)
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, slow.URL+"/?k="+url.QueryEscape(secret), nil)
	err := do(slow.Client(), req, nil, secret)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("not DeadlineExceeded: %v", err)
	}
	if err == nil || strings.Contains(err.Error(), url.QueryEscape(secret)) || strings.Contains(err.Error(), secret) {
		t.Errorf("the error quotes the secret: %v", err)
	}
	var wrapped *OpError
	err = &OpError{Plane: "tailscale", Op: "list devices", Err: err}
	if !errors.As(err, &wrapped) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("through an OpError: %v", err)
	}
}

// TestNameTakenByStatusFirst: 409 is a taken name whatever it says; a 400 or
// 422 only when its message says so; any other failure stays plain.
func TestNameTakenByStatusFirst(t *testing.T) {
	for _, c := range []struct {
		code  int
		msg   string
		taken bool
	}{
		{http.StatusConflict, "conflict", true},
		{http.StatusBadRequest, "name already in use", true},
		{http.StatusUnprocessableEntity, "that name is taken", true},
		{http.StatusBadRequest, "invalid name", false},
		{http.StatusForbidden, "name already in use", false},
		{http.StatusInternalServerError, "already broken", false},
	} {
		err := nameTaken(&StatusError{Code: c.code, Message: c.msg}, "vault")
		if errors.Is(err, ErrNameTaken) != c.taken {
			t.Errorf("%d %q: %v", c.code, c.msg, err)
		}
	}
}
