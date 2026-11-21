// SPDX-License-Identifier: Apache-2.0

// Package releasetest signs release checksums the way the release
// workflow's keyless signature does, with a Sigstore of its own: a Fulcio
// root and intermediate, a certificate transparency log and a Rekor log,
// every key generated in this process when New runs. Its trusted root
// verifies exactly what it signed, for any identity a test names, through
// the same lib/release verifier the installers and self-update use. Only
// tests and varlatchd's conformance build (its conformance-sign-release)
// import it: nothing it makes is trusted outside them.
package releasetest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"
)

// oidIssuerV2 is Fulcio's extension naming the OIDC issuer of the identity.
var oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// Sigstore is a test Sigstore: its keys exist only in this process.
type Sigstore struct {
	rootCert, interCert *x509.Certificate
	interKey            *ecdsa.PrivateKey
	ctKey, rekorKey     *ecdsa.PrivateKey
	logIndex            int64
	trusted             *root.TrustedRoot
}

func key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// logID is a log's identifier: the SHA-256 of its public key's DER.
func logID(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return sum[:]
}

func certificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// New makes a test Sigstore, valid from an hour ago for a day.
func New() *Sigstore {
	s := &Sigstore{interKey: key(), ctKey: key(), rekorKey: key()}
	rootKey := key()
	start, end := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "releasetest root"},
		NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	s.rootCert = certificate(ca, ca, rootKey.Public(), rootKey)
	inter := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "releasetest intermediate"},
		NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	s.interCert = certificate(inter, s.rootCert, s.interKey.Public(), rootKey)

	ctID, rekorID := logID(s.ctKey), logID(s.rekorKey)
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{
			Root: s.rootCert, Intermediates: []*x509.Certificate{s.interCert},
			ValidityPeriodStart: start, ValidityPeriodEnd: end, URI: "https://fulcio.releasetest.invalid",
		}},
		map[string]*root.TransparencyLog{hex.EncodeToString(ctID): {
			BaseURL: "https://ctlog.releasetest.invalid", ID: ctID, HashFunc: crypto.SHA256,
			PublicKey: s.ctKey.Public(), SignatureHashFunc: crypto.SHA256,
			ValidityPeriodStart: start, ValidityPeriodEnd: end,
		}},
		nil,
		map[string]*root.TransparencyLog{hex.EncodeToString(rekorID): {
			BaseURL: "https://rekor.releasetest.invalid", ID: rekorID, HashFunc: crypto.SHA256,
			PublicKey: s.rekorKey.Public(), SignatureHashFunc: crypto.SHA256,
			ValidityPeriodStart: start, ValidityPeriodEnd: end,
		}},
	)
	if err != nil {
		panic(err)
	}
	s.trusted = tr
	return s
}

// TrustedRoot is what verifies this Sigstore's signatures.
func (s *Sigstore) TrustedRoot() *root.TrustedRoot { return s.trusted }

// TrustedRootJSON is TrustedRoot as a trusted_root.json file holds it.
func (s *Sigstore) TrustedRootJSON() []byte {
	b, err := s.trusted.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return b
}

// leaf issues a short-lived signing certificate for identity (a URI, as
// the release workflow's) through issuer, with an embedded SCT from the
// test log, as Fulcio does.
func (s *Sigstore) leaf(identity, issuer string, pub crypto.PublicKey) *x509.Certificate {
	uri, err := url.Parse(identity)
	if err != nil {
		panic(err)
	}
	issuerValue, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		panic(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuerV2, Value: issuerValue}},
	}
	// The SCT signs the certificate without its SCT list: the same template
	// issued without the extension, which is the last one added.
	pre := certificate(template, s.interCert, pub, s.interKey)
	stamp := uint64(now.UnixMilli())
	merkle := &ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			EntryType: ct.PrecertLogEntryType,
			Timestamp: stamp,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(s.interCert.RawSubjectPublicKeyInfo),
				TBSCertificate: pre.RawTBSCertificate,
			},
		},
	}
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: [32]byte(logID(s.ctKey))}, Timestamp: stamp}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: *merkle})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, s.ctKey, digest[:])
	if err != nil {
		panic(err)
	}
	sct.Signature = ct.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: sig}
	one, err := cttls.Marshal(sct)
	if err != nil {
		panic(err)
	}
	list, err := cttls.Marshal(ctx509.SignedCertificateTimestampList{SCTList: []ctx509.SerializedSCT{{Val: one}}})
	if err != nil {
		panic(err)
	}
	value, err := asn1.Marshal(list)
	if err != nil {
		panic(err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: value})
	return certificate(template, s.interCert, pub, s.interKey)
}

// Sign signs blob as identity through issuer and returns the Sigstore
// bundle (v0.1: the certificate, the signature, and the Rekor entry with
// its signed entry timestamp), as SHA256SUMS.sigstore.json holds it.
func (s *Sigstore) Sign(blob []byte, identity, issuer string) []byte {
	signer := key()
	cert := s.leaf(identity, issuer, signer.Public())
	digest := sha256.Sum256(blob)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1", "kind": "hashedrekord",
		"spec": map[string]any{
			"data":      map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(digest[:])}},
			"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(certPEM)}},
		},
	})
	if err != nil {
		panic(err)
	}
	if body, err = jsoncanonicalizer.Transform(body); err != nil {
		panic(err)
	}
	s.logIndex++
	integrated := time.Now().Unix()
	rekorID := logID(s.rekorKey)
	payload, err := json.Marshal(map[string]any{
		"body": base64.StdEncoding.EncodeToString(body), "integratedTime": integrated,
		"logIndex": s.logIndex, "logID": hex.EncodeToString(rekorID),
	})
	if err != nil {
		panic(err)
	}
	if payload, err = jsoncanonicalizer.Transform(payload); err != nil {
		panic(err)
	}
	payloadDigest := sha256.Sum256(payload)
	set, err := ecdsa.SignASN1(rand.Reader, s.rekorKey, payloadDigest[:])
	if err != nil {
		panic(err)
	}

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{Certificates: []*protocommon.X509Certificate{{RawBytes: cert.Raw}}},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex:          s.logIndex,
				LogId:             &protocommon.LogId{KeyId: rekorID},
				KindVersion:       &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.1"},
				IntegratedTime:    integrated,
				InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
				CanonicalizedBody: body,
			}},
		},
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest[:]},
			Signature:     sig,
		}},
	}
	if _, err := bundle.NewBundle(pb); err != nil {
		panic(fmt.Errorf("releasetest: the bundle is not valid: %w", err))
	}
	out, err := protojson.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return bytes.Clone(out)
}

// Sums is SHA256SUMS for files, as sha256sum writes it.
func Sums(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return []byte(b.String())
}
