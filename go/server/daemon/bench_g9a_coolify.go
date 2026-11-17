// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// benchCoolify is the G9a run's provider (feature-parity decision 8): a
// Coolify instance, Coolify-shaped, that the converge engine reaches
// through the outbound policy at a loopback address the run's
// outbound_allow opens, over TLS with a certificate made for the run. It
// keeps each application's variables, as Coolify's API answers them (the
// requests the Coolify adapter sends for an application destination), and
// waits delay before every answer: the plan's provider delay during the
// load (200 ms, feature-parity decision 8), none while the run seeds its
// Targets.
type benchCoolify struct {
	srv   *http.Server
	ln    net.Listener
	roots *x509.CertPool
	delay atomic.Int64 // nanoseconds

	mu    sync.Mutex
	apps  map[string][]map[string]any
	next  int
	calls atomic.Int64
	// writes counts the variables written (POST or PATCH): a converge
	// run's values.
	writes atomic.Int64
}

var benchCoolifyPath = regexp.MustCompile(`^/api/v1/applications/([^/]+)(/envs(?:/([^/]+))?|/start|/restart)?$`)

// startBenchCoolify listens on a loopback port with apps applications
// (app-0 to app-{apps-1}), none holding a variable yet.
func startBenchCoolify(apps int) (*benchCoolify, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "g9a coolify"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c := &benchCoolify{ln: ln, roots: roots, apps: map[string][]map[string]any{}, next: 1}
	for i := range apps {
		c.apps[benchApp(i)] = nil
	}
	c.srv = &http.Server{Handler: http.HandlerFunc(c.serve), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}}
	go func() { _ = c.srv.ServeTLS(ln, "", "") }()
	return c, nil
}

// benchApp is application i's UUID.
func benchApp(i int) string { return fmt.Sprintf("app-g9a-%02d", i) }

// URL is the instance's origin, a Connection's base identity.
func (c *benchCoolify) URL() string { return "https://" + c.ln.Addr().String() }

// Port is its loopback port, for outbound_allow.
func (c *benchCoolify) Port() int { return c.ln.Addr().(*net.TCPAddr).Port }

func (c *benchCoolify) setDelay(d time.Duration) { c.delay.Store(int64(d)) }

func (c *benchCoolify) close() { _ = c.srv.Close() }

func (c *benchCoolify) serve(w http.ResponseWriter, r *http.Request) {
	c.calls.Add(1)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if d := time.Duration(c.delay.Load()); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	answer := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		answer(401, map[string]any{"message": "Unauthenticated."})
		return
	}
	m := benchCoolifyPath.FindStringSubmatch(r.URL.Path)
	if m == nil {
		answer(404, map[string]any{"message": "Not found."})
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rows, ok := c.apps[m[1]]
	if !ok {
		answer(404, map[string]any{"message": "Not found."})
		return
	}
	switch {
	case m[2] == "/start" || m[2] == "/restart":
		answer(200, map[string]any{"message": "Queued."})
	case m[2] == "" && r.Method == "GET":
		answer(200, map[string]any{"uuid": m[1], "name": m[1], "build_pack": "dockerfile"})
	case m[2] == "/envs" && r.Method == "GET":
		if rows == nil {
			rows = []map[string]any{}
		}
		answer(200, rows)
	case m[2] == "/envs" && r.Method == "POST":
		row := map[string]any{}
		_ = json.Unmarshal(body, &row)
		row["uuid"] = "env-" + strconv.Itoa(c.next)
		row["is_preview"] = false
		c.next++
		c.apps[m[1]] = append(rows, row)
		c.writes.Add(1)
		answer(201, map[string]any{"uuid": row["uuid"]})
	case m[2] == "/envs" && r.Method == "PATCH":
		sent := map[string]any{}
		_ = json.Unmarshal(body, &sent)
		for _, row := range rows {
			if row["key"] == sent["key"] {
				for k, v := range sent {
					row[k] = v
				}
				c.writes.Add(1)
				answer(201, map[string]any{"uuid": row["uuid"]})
				return
			}
		}
		answer(404, map[string]any{"message": "Not found."})
	case m[3] != "" && r.Method == "DELETE":
		for i, row := range rows {
			if row["uuid"] == m[3] {
				c.apps[m[1]] = append(rows[:i:i], rows[i+1:]...)
				answer(200, map[string]any{"message": "Deleted."})
				return
			}
		}
		answer(404, map[string]any{"message": "Not found."})
	default:
		answer(404, map[string]any{"message": "Not found."})
	}
}
