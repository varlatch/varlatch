// SPDX-License-Identifier: AGPL-3.0-or-later

// Command enrollpasskey is a test tool, never shipped: it enrolls a passkey
// from a one-time enrollment link as the enrollment page would, with
// authtest's software authenticator, for go/install/test-setup.sh, where no
// browser runs.
//
//	enrollpasskey -link-file <file> [-connect http://127.0.0.1:8686] [-insecure]
//
// The link names the installation's origin (its public URL); -connect is
// where to send the requests when that origin is not reachable from here
// (a proxy's address in front of the plain listener). The link is read from
// a file and never printed. -insecure skips the TLS certificate's check
// (a test CA's certificate, reached at an address it does not name).
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// tb is authtest's testing.TB outside a test: Fatal ends the tool.
type tb struct{ testing.TB }

func (tb) Helper() {}
func (tb) Fatal(args ...any) {
	fmt.Fprintln(os.Stderr, append([]any{"enrollpasskey:"}, args...)...)
	os.Exit(1)
}

func main() {
	linkFile := flag.String("link-file", "", "the file holding the enrollment link")
	connect := flag.String("connect", "", "where to send the requests (default: the link's origin)")
	insecure := flag.Bool("insecure", false, "skip the TLS certificate's check (tests only)")
	flag.Parse()
	if err := enroll(*linkFile, *connect, *insecure); err != nil {
		fmt.Fprintln(os.Stderr, "enrollpasskey:", err)
		os.Exit(1)
	}
	fmt.Println("enrolled a passkey")
}

func enroll(linkFile, connect string, insecure bool) error {
	raw, err := os.ReadFile(linkFile)
	if err != nil {
		return err
	}
	link, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || link.Fragment == "" || !strings.HasSuffix(link.Path, "/enroll") {
		return errors.New("the file holds no enrollment link")
	}
	origin := link.Scheme + "://" + link.Host
	base := origin
	if connect != "" {
		base = strings.TrimSuffix(connect, "/")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{ServerName: link.Hostname(), InsecureSkipVerify: true}} // a test tool, against a test CA
	}
	b := &browser{base: base, origin: origin, host: link.Host, cookies: map[string]string{}, client: client}
	var session struct{ CsrfToken string }
	if err := b.do("GET", "/auth/session", nil, &session); err != nil || session.CsrfToken == "" {
		return fmt.Errorf("the session: %v", err)
	}
	b.csrf = session.CsrfToken
	var opts struct{ PublicKey auth.CreationOptions }
	if err := b.do("POST", "/auth/passkey/registration/options", map[string]any{"token": link.Fragment}, &opts); err != nil {
		return fmt.Errorf("the registration options: %v", err)
	}
	key := authtest.New(tb{})
	var reg struct{ SignedIn bool }
	if err := b.do("POST", "/auth/passkey/registration", map[string]any{"response": key.Register(tb{}, opts.PublicKey, origin), "name": "setup end to end"}, &reg); err != nil {
		return fmt.Errorf("the registration: %v", err)
	}
	if !reg.SignedIn {
		return errors.New("the registration did not sign in")
	}
	return nil
}

// browser sends what the enrollment page sends: the origin, the CSRF
// header and cookies (kept by hand: they may be Secure while -connect is
// plain http).
type browser struct {
	base, origin, host, csrf string
	cookies                  map[string]string
	client                   *http.Client
}

func (b *browser) do(method, path string, body, into any) error {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.base+path, r)
	if err != nil {
		return err
	}
	req.Host = b.host
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == "POST" {
		req.Header.Set("Origin", b.origin)
		req.Header.Set("Varlatch-CSRF", b.csrf)
	}
	if strings.HasPrefix(b.origin, "https://") && strings.HasPrefix(b.base, "http://") {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	res, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, res.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, into)
}
