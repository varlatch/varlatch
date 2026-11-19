// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// The browser and OIDC sign-ins, ported from main.ts's browserLogin,
// browser.ts and oidcLogin.ts at v0.22.0.

// noBrowserEnv is browser.ts's NO_BROWSER_ENV: for a desktop app that
// drives `varlatch login`, reads the printed address and opens it itself.
const noBrowserEnv = "VARLATCH_NO_BROWSER"

// browserTimeout is how long the browser sign-in waits for its callback.
const browserTimeout = 5 * time.Minute

// browserCommand is browser.ts's browserCommand: the command that opens url
// in the default browser on goos, or nil when nothing should be opened.
// On Windows the URL protocol handler is started directly, never through a
// shell, which would read a query string's "&" as a command separator.
func browserCommand(goos, url string, env Env) []string {
	if v, ok := env.LookupEnv(noBrowserEnv); ok && v != "" && v != "0" {
		return nil
	}
	switch goos {
	case "windows":
		return []string{"rundll32.exe", "url.dll,FileProtocolHandler", url}
	case "darwin":
		return []string{"open", url}
	}
	return []string{"xdg-open", url}
}

// callbackNonce is the random path of the loopback callback: only a POST to
// exactly that path is the sign-in's, so delivering a bearer takes the
// path, not just the port (go/README.md, the accepted difference
// "loopback-nonce"). The path is in the sign-in address, which the
// browser's command line holds while it runs: it keeps out what cannot
// read that, such as a web page, not another process of the same machine
// that can.
func callbackNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// browserLogin is main.ts's browserLogin (ADR-0017): a loopback listener
// on 127.0.0.1 only, the sign-in page's address printed (and opened, unless
// VARLATCH_NO_BROWSER), and the short-lived bearer the page posts back. The
// listener takes one callback, at its random path, and closes; it gives up
// after five minutes.
func (r *Run) browserLogin(server string) (string, error) {
	nonce, err := callbackNonce()
	if err != nil {
		return "", err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	origin := ""
	if u, ok := whatwg.ParseURL(server); ok && (u.Protocol == "http:" || u.Protocol == "https:") {
		origin = u.Protocol + "//" + u.Host
	}
	type delivered struct {
		token string
		err   error
	}
	result := make(chan delivered, 1)
	var taken atomic.Bool
	path := "/" + nonce
	port := listener.Addr().(*net.TCPAddr).Port
	portText := strconv.Itoa(port)
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// Chrome Local Network Access: page -> loopback requires this on the
		// preflight or the fetch fails with a bare "Failed to fetch".
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		// Only this listener's own address (a name another host resolves to
		// 127.0.0.1 is not it: DNS rebinding) and only its random path, the
		// path compared in constant time.
		if req.Host != "127.0.0.1:"+portText && req.Host != "localhost:"+portText ||
			subtle.ConstantTimeCompare([]byte(req.URL.Path), []byte(path)) != 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if taken.Swap(true) {
			w.WriteHeader(http.StatusGone) // a callback delivered already: single use
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		// Single use: the listener takes no other connection from here on,
		// before this one is answered.
		_ = listener.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
		if err != nil {
			result <- delivered{err: err}
			return
		}
		parsed, parseErr := jsjson.Parse(body)
		if parseErr != nil {
			result <- delivered{err: errors.New(jsonParseMessage(body))}
			return
		}
		token, ok := jsval.Get(parsed, "token")
		if parsed == nil {
			result <- delivered{err: &typeError{"Cannot destructure property 'token' of 'JSON.parse(...)' as it is null."}}
			return
		}
		if !ok || !jsjson.Truthy(token) {
			result <- delivered{err: errors.New("no token in callback")}
			return
		}
		result <- delivered{token: jsjson.String(token)}
	})
	server2 := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server2.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = server2.Shutdown(ctx)
		cancel()
	}()
	callback := "http://127.0.0.1:" + portText + path
	trimmed := strings.TrimRight(server, "/")
	address := trimmed + "/enroll?callback=" + apiclient.EncodeURIComponent(callback)
	if err := r.println("Complete passkey sign-in in your browser:"); err != nil {
		return "", err
	}
	if err := r.println("  " + shownServer(trimmed) + "/enroll?callback=" + apiclient.EncodeURIComponent(callback)); err != nil {
		return "", err
	}
	if opener := browserCommand(runtime.GOOS, address, r.Env); opener != nil {
		cmd := exec.Command(opener[0], opener[1:]...)
		cmd.Env = environ(r)
		detach(cmd)
		if cmd.Start() == nil {
			go func() { _ = cmd.Wait() }() // headless: the person opens it by hand
		}
	}
	select {
	case d := <-result:
		return d.token, d.err
	case <-time.After(browserTimeout):
		return "", errors.New("Browser login timed out after 5 minutes")
	}
}

// typeError is a TypeError JavaScript throws (its name shown with it).
type typeError struct{ message string }

func (e *typeError) Error() string { return e.message }

// jsonParseMessage is JSON.parse's SyntaxError for the callback's body, as
// V8 words the commonest: an empty body.
func jsonParseMessage(body []byte) string {
	if len(strings.TrimSpace(string(body))) == 0 {
		return "Unexpected end of JSON input"
	}
	return "Unexpected token in JSON"
}

// environ is the run's environment as a process gets it.
func environ(r *Run) []string {
	var out []string
	for k, v := range r.Environ() {
		out = append(out, k+"="+v)
	}
	return out
}

// oidcIDToken is oidcLogin.ts's obtainOidcIdToken: the platform's OIDC ID
// token, from --oidc-token, else VARLATCH_OIDC_TOKEN, else the GitHub
// Actions runtime endpoint (ACTIONS_ID_TOKEN_REQUEST_URL with
// ACTIONS_ID_TOKEN_REQUEST_TOKEN; the workflow grants `id-token: write`).
func (r *Run) oidcIDToken(explicit, audience string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if token := r.Getenv("VARLATCH_OIDC_TOKEN"); token != "" {
		return token, nil
	}
	requestURL, requestToken := r.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), r.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", errors.New("No OIDC token available: pass --oidc-token, set VARLATCH_OIDC_TOKEN, " +
			"or run inside GitHub Actions with `permissions: id-token: write`.")
	}
	r.holdSecret(requestToken)
	// fetch's own refusals, made here so that neither the request token nor
	// the URL's user name and password is ever quoted.
	u, ok := whatwg.ParseURL(requestURL)
	if !ok {
		return "", &apiclient.FetchError{Message: "Failed to parse URL from " + shownServer(requestURL)}
	}
	if u.Username != "" || u.Password != "" {
		return "", &apiclient.FetchError{Message: shownServer(requestURL) + ": a URL with a user name or password can't be used; remove them and try again"}
	}
	if apiclient.HeaderRefused("Authorization", "Bearer "+requestToken) {
		return "", &typeError{"ACTIONS_ID_TOKEN_REQUEST_TOKEN contains a character that is not allowed in an HTTP header"}
	}
	target := requestURL
	if audience != "" {
		path, query := u.RequestTarget()
		target = u.Protocol + "//" + u.Host + path + "?" + setSearchParam(query, "audience", audience)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := apiclient.NewTransport(r.Env).Do(ctx, apiclient.Request{
		Method: "GET",
		URL:    target,
		// fetch's own User-Agent, as undici sends it: this request is not the
		// CLI's API client's.
		Headers: [][2]string{{"Authorization", "Bearer " + requestToken}, {"Accept", "application/json"}, {"User-Agent", "node"}},
	})
	if err != nil {
		return "", err
	}
	if res.Status < 200 || res.Status > 299 {
		return "", fmt.Errorf("GitHub Actions ID token request failed (%d). Does the workflow grant `permissions: id-token: write`?", res.Status)
	}
	if res.BodyErr != nil {
		return "", res.BodyErr
	}
	parsed, err := jsjson.Parse([]byte(strings.TrimPrefix(string(res.Body), "\xef\xbb\xbf")))
	if err != nil {
		return "", errors.New(jsonParseMessage(res.Body))
	}
	value, ok, err := read(parsed, true, "value")
	if err != nil {
		return "", err
	}
	if !ok || !jsjson.Truthy(value) {
		return "", errors.New("GitHub Actions ID token response had no value")
	}
	return jsjson.String(value), nil
}

// setSearchParam is URLSearchParams' set(name, value) on a query, then its
// serialization (application/x-www-form-urlencoded): the first pair of
// that name takes the value, later ones go, and a missing one is appended.
func setSearchParam(query, name, value string) string {
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, pair{formDecode(k), formDecode(v)})
	}
	var out []pair
	set := false
	for _, p := range pairs {
		if p.k != name {
			out = append(out, p)
		} else if !set {
			out = append(out, pair{name, value})
			set = true
		}
	}
	if !set {
		out = append(out, pair{name, value})
	}
	parts := make([]string, len(out))
	for i, p := range out {
		parts[i] = formEncode(p.k) + "=" + formEncode(p.v)
	}
	return strings.Join(parts, "&")
}

func formDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			n, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b = append(b, byte(n))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return jsval.DecodeUTF8(b)
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func formEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("*-._", c) >= 0:
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// holdSecret is a credential, device code, hand-off bearer or OIDC token
// this run handles: a secret in flight (holdValue), so no output or
// diagnostic shows it, and a secret a server's free text has masked
// (Secrets, issue #119).
func (r *Run) holdSecret(value string) {
	r.holdValue(value)
	r.Secrets.Remember(value)
}
