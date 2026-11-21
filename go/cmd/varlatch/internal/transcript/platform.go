// SPDX-License-Identifier: Apache-2.0

package transcript

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
)

// The fake platforms (slice 5.8b), as goKit.ts's platformServer: the host
// names the Platform Adapters address, served by one HTTPS server with a
// certificate for them, which the CLI trusts through NODE_EXTRA_CA_CERTS.
// The replay gives the CLI under test the server's address in
// PlatformEnv; the test binary, running as the CLI, routes those names to
// it (apiclient.PlatformDial). Neither side reaches a real platform.

// PlatformHosts are goKit.ts's PLATFORM_HOSTS.
var PlatformHosts = []string{"api.github.com", "coolify.conformance.test", "convex.conformance.test"}

// PlatformEnv names the variable that holds the fake platforms' address.
const PlatformEnv = "VARLATCH_TEST_PLATFORM"

// platformHeaders are goKit.ts's PLATFORM_HEADERS.
var platformHeaders = []string{"authorization", "content-type", "accept", "x-github-api-version"}

// PlatformSecretKey is the fake GitHub repository's X25519 secret key, the
// bytes 1 to 32, and PlatformPublicKey its public key (goKit.ts's).
var PlatformSecretKey = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}()

const PlatformPublicKey = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="

// PlatformPublicKeyWord is what a case's platform answer says in place of
// the public key (goKit.ts's PLATFORM_PUBLIC_KEY_WORD): the fake serves
// PlatformPublicKey there, so a recording never holds the key itself.
const PlatformPublicKeyWord = "{{platform-public-key}}"

// PlatformRequest is goKit.ts's PlatformRequest.
type PlatformRequest struct {
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

// openSealed is goKit.ts's openSealed: a sealed GitHub value as
// `{{sealed <value>}}`, never the box.
func openSealed(body any) any {
	o, ok := body.(jsjson.Object)
	if !ok {
		return body
	}
	sealed, ok := o.Value("encrypted_value").(string)
	if !ok {
		return body
	}
	box, _ := base64.StdEncoding.DecodeString(sealed)
	public, _ := base64.StdEncoding.DecodeString(PlatformPublicKey)
	out := slices.Clone(o)
	if opened, ok := vsync.SealedBoxOpen(box, public, PlatformSecretKey); ok {
		return out.Set("encrypted_value", "{{sealed "+string(opened)+"}}")
	}
	return out.Set("encrypted_value", "{{sealed, not opened}}")
}

// platformServer is the fake platforms for one case.
type platformServer struct {
	addr   string
	cert   string // the certificate's PEM file, outside the case directory
	srv    *http.Server
	mu     sync.Mutex
	script []Exchange
	got    []PlatformRequest
}

func newPlatformServer(script []Exchange) (*platformServer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "varlatch-transcript-platforms"},
		DNSNames:     PlatformHosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "varlatch-platform-")
	if err != nil {
		return nil, err
	}
	certFile := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &platformServer{addr: ln.Addr().String(), cert: certFile, script: slices.Clone(script)}
	p.srv = &http.Server{Handler: http.HandlerFunc(p.serve), TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"http/1.1"},
	}}
	go func() { _ = p.srv.ServeTLS(ln, "", "") }()
	return p, nil
}

func (p *platformServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	headers := map[string]string{}
	for _, name := range platformHeaders {
		if v := r.Header.Values(name); len(v) > 0 {
			headers[name] = latin1(strings.Join(v, ", "))
		}
	}
	recorded := json.RawMessage("null")
	if len(body) > 0 {
		if v, err := jsjson.Parse(body); err == nil {
			recorded = jsjson.Stringify(openSealed(v))
		} else {
			quoted, _ := json.Marshal(string(body))
			recorded = quoted
		}
	}
	p.mu.Lock()
	p.got = append(p.got, PlatformRequest{Method: r.Method, Host: r.Host, Path: r.URL.RequestURI(), Headers: headers, Body: recorded})
	var next *Exchange
	if len(p.script) > 0 {
		next = &p.script[0]
		p.script = p.script[1:]
	}
	p.mu.Unlock()
	if next == nil || next.Method != r.Method || next.Path != r.URL.RequestURI() {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(599)
		_, _ = io.WriteString(w, "unexpected request")
		return
	}
	if next.Headers == nil {
		w.Header().Set("content-type", "application/json")
	}
	for k, v := range next.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(next.Status)
	if len(next.Answer) == 0 {
		return
	}
	var text string
	if next.Answer[0] == '"' && json.Unmarshal(next.Answer, &text) == nil {
		_, _ = io.WriteString(w, text)
		return
	}
	answer := bytes.ReplaceAll(next.Answer, []byte(`"`+PlatformPublicKeyWord+`"`), []byte(`"`+PlatformPublicKey+`"`))
	v, err := jsjson.Parse(answer)
	if err != nil {
		return
	}
	_, _ = w.Write(jsjson.Stringify(v))
}

func (p *platformServer) received() []PlatformRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.got)
}

func (p *platformServer) close() {
	_ = p.srv.Close()
	_ = os.RemoveAll(filepath.Dir(p.cert))
}

// comparePlatform lists how got's platform requests differ from want's.
func comparePlatform(want, got []PlatformRequest) []string {
	var problems []string
	for i := 0; i < max(len(want), len(got)); i++ {
		switch {
		case i >= len(got):
			problems = append(problems, fmt.Sprintf("expected platform request %d (%s %s%s) was never sent", i+1, want[i].Method, want[i].Host, want[i].Path))
		case i >= len(want):
			problems = append(problems, fmt.Sprintf("unexpected platform request %d: %s %s%s", i+1, got[i].Method, got[i].Host, got[i].Path))
		default:
			w, g := want[i], got[i]
			if w.Host != g.Host {
				problems = append(problems, fmt.Sprintf("platform request %d: host %s, want %s", i+1, g.Host, w.Host))
				continue
			}
			if p := compareRequest(Request{w.Method, w.Path, w.Headers, w.Body}, Request{g.Method, g.Path, g.Headers, g.Body}); p != "" {
				problems = append(problems, fmt.Sprintf("platform request %d: %s", i+1, p))
			}
		}
	}
	return problems
}
