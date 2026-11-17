// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tailnettest stands in for the node's certificate source in
// tests: a CA of its own issues the pair Let's Encrypt would, so no test
// needs a real tailnet or ACME.
package tailnettest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"
)

// CA issues certificate pairs, as tailnet.CertSource gives them.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// Pool trusts the CA (a client's RootCAs).
	Pool *x509.CertPool

	mu sync.Mutex
	// Lifetime of each certificate issued (default 90 days, as Let's
	// Encrypt's), backdated an hour.
	Lifetime time.Duration
	// Now is the clock certificates are issued at (default time.Now).
	Now func() time.Time
	// Fail, when set, is returned instead of a pair.
	Fail error
	// Names, when set, replaces the names a certificate is issued for.
	Names []string
	// Requests records each request's domain and minimum validity; read it
	// with Requested while a refresh may run.
	Requests []Request
}

// Request is one CertPair call.
type Request struct {
	Domain      string
	MinValidity time.Duration
}

// Requested is a copy of Requests, read under the CA's lock: a refresh
// may append to it meanwhile.
func (c *CA) Requested() []Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Request(nil), c.Requests...)
}

// NewCA makes a CA.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "varlatch test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{cert: cert, key: key, Pool: pool}, nil
}

// CertPair issues a pair for domain, as the node's local API answers it:
// the leaf then the CA certificate, and the leaf's key.
func (c *CA) CertPair(_ context.Context, domain string, minValidity time.Duration) ([]byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Requests = append(c.Requests, Request{Domain: domain, MinValidity: minValidity})
	if c.Fail != nil {
		return nil, nil, c.Fail
	}
	names := []string{domain}
	if c.Names != nil {
		names = c.Names
	}
	now, lifetime := time.Now(), 90*24*time.Hour
	if c.Now != nil {
		now = c.Now()
	}
	if c.Lifetime != 0 {
		lifetime = c.Lifetime
	}
	return c.Issue(names, now.Add(-time.Hour), now.Add(lifetime-time.Hour))
}

// Issue makes a pair for names, valid from notBefore to notAfter.
func (c *CA) Issue(names []string, notBefore, notAfter time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: first(names)}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func first(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// ErrUnavailable is a failure a test sets as Fail.
var ErrUnavailable = errors.New("500 Internal Server Error: the certificate is not available")
