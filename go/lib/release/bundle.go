// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// readBundle reads a signature bundle in either format a release may use:
// a Sigstore bundle (has "mediaType"; cosign sign-blob --new-bundle-format,
// cosign 3), or cosign's earlier bundle ("base64Signature", "cert",
// "rekorBundle"; what `cosign sign-blob --bundle` writes in cosign 2, and so
// every Varlatch release so far). The earlier format carries the same
// evidence (certificate, signature, Rekor entry and its signed entry
// timestamp) and is converted to a v0.1 Sigstore bundle, which sigstore-go
// verifies with the inclusion promise as its proof of logging.
func readBundle(data []byte) (*bundle.Bundle, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, errors.New("not a JSON object")
	}
	if _, ok := keys["mediaType"]; ok {
		var b bundle.Bundle
		if err := b.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		return &b, nil
	}
	if _, ok := keys["base64Signature"]; ok {
		return fromCosignBundle(data)
	}
	return nil, errors.New("neither a Sigstore bundle nor a cosign bundle")
}

type cosignBundle struct {
	Base64Signature string `json:"base64Signature"`
	Cert            string `json:"cert"` // base64 of a PEM certificate
	RekorBundle     *struct {
		SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
		Payload              struct {
			Body           string `json:"body"` // base64 of the canonical entry
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"` // hex
		} `json:"Payload"`
	} `json:"rekorBundle"`
}

// hashedRekord is the part of a Rekor hashedrekord entry the conversion
// reads: its kind and version, and the digest it logged.
type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
	} `json:"spec"`
}

func fromCosignBundle(data []byte) (*bundle.Bundle, error) {
	var cb cosignBundle
	if err := json.Unmarshal(data, &cb); err != nil {
		return nil, fmt.Errorf("cosign bundle: %w", err)
	}
	if cb.RekorBundle == nil || cb.Base64Signature == "" || cb.Cert == "" {
		return nil, errors.New("cosign bundle: a signature, a certificate and a Rekor entry are all required")
	}
	sig, err := base64.StdEncoding.DecodeString(cb.Base64Signature)
	if err != nil {
		return nil, errors.New("cosign bundle: the signature is not base64")
	}
	certPEM, err := base64.StdEncoding.DecodeString(cb.Cert)
	if err != nil {
		return nil, errors.New("cosign bundle: the certificate is not base64")
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 && len(trimSpace(rest)) != 0 {
		return nil, errors.New("cosign bundle: the certificate is not one PEM certificate")
	}
	p := cb.RekorBundle.Payload
	set, err := base64.StdEncoding.DecodeString(cb.RekorBundle.SignedEntryTimestamp)
	if err != nil || len(set) == 0 {
		return nil, errors.New("cosign bundle: the signed entry timestamp is missing or not base64")
	}
	body, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return nil, errors.New("cosign bundle: the Rekor entry is not base64")
	}
	logID, err := hex.DecodeString(p.LogID)
	if err != nil || len(logID) == 0 {
		return nil, errors.New("cosign bundle: the Rekor log id is missing or not hex")
	}
	var entry hashedRekord
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil, errors.New("cosign bundle: the Rekor entry is not JSON")
	}
	if entry.Kind != "hashedrekord" || entry.Spec.Data.Hash.Algorithm != "sha256" {
		return nil, fmt.Errorf("cosign bundle: a %q entry over %q; want a hashedrekord over sha256", entry.Kind, entry.Spec.Data.Hash.Algorithm)
	}
	digest, err := hex.DecodeString(entry.Spec.Data.Hash.Value)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("cosign bundle: the Rekor entry's digest is not a SHA-256")
	}

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{{RawBytes: block.Bytes}},
				},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex:          p.LogIndex,
				LogId:             &protocommon.LogId{KeyId: logID},
				KindVersion:       &protorekor.KindVersion{Kind: entry.Kind, Version: entry.APIVersion},
				IntegratedTime:    p.IntegratedTime,
				InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
				CanonicalizedBody: body,
			}},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest},
				Signature:     sig,
			},
		},
	}
	b, err := bundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("cosign bundle: %w", err)
	}
	return b, nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
