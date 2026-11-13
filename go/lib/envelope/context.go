// SPDX-License-Identifier: Apache-2.0

package envelope

// Context is an envelope's associated data before encoding: a purpose and
// the identifiers the envelope belongs to. It is encoded with CanonicalJSON,
// so key order never matters. Values are strings or integers.
type Context map[string]any

func (c Context) aad() ([]byte, error) {
	if c["purpose"] == nil {
		return nil, errNoPurpose
	}
	s, err := CanonicalJSON(map[string]any(c))
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// The purposes in use, one per kind of envelope (TypeScript:
// services/varlatchd/src/crypto/hierarchy.ts and canary.ts, auth/jwt.ts).
const (
	PurposeOrgKEK             = "org-kek"
	PurposeDEK                = "dek"
	PurposeValue              = "value"
	PurposeWebhookSecret      = "webhook-secret"
	PurposePlatformCredential = "platform-credential"
	PurposeGitHubAppKey       = "github-app-key"
	PurposeKEKCanary          = "kek-canary"
	PurposeJWTSigningKey      = "jwt-signing-key"
	// ADR-0056, since TypeScript 0.22.0.
	PurposeAuditExportCredential = "audit-export-credential"
	PurposeAuditExportDrain      = "audit-export-drain"
)

// OrgKEKContext binds an organization's KEK, wrapped by the Root KEK.
func OrgKEKContext(organizationID string) Context {
	return Context{"purpose": PurposeOrgKEK, "organizationId": organizationID}
}

// DEKContext binds a value version's data key, wrapped by the org KEK.
// secretID is the env value's row id (val_…), versionID the version's
// (ver_…).
func DEKContext(organizationID, secretID, versionID string) Context {
	return Context{"purpose": PurposeDEK, "organizationId": organizationID, "secretId": secretID, "versionId": versionID}
}

// ValueContext binds a value version's payload, encrypted by its DEK.
func ValueContext(organizationID, secretID, versionID string) Context {
	return Context{"purpose": PurposeValue, "organizationId": organizationID, "secretId": secretID, "versionId": versionID}
}

// WebhookSecretContext binds a webhook's signing secret (org KEK).
func WebhookSecretContext(organizationID, webhookID string) Context {
	return Context{"purpose": PurposeWebhookSecret, "organizationId": organizationID, "webhookId": webhookID}
}

// PlatformCredentialContext binds a platform connection's credential (org
// KEK).
func PlatformCredentialContext(organizationID, connectionID string) Context {
	return Context{"purpose": PurposePlatformCredential, "organizationId": organizationID, "connectionId": connectionID}
}

// GitHubAppKeyContext binds a GitHub App's private key (org KEK).
// githubAppID is Varlatch's row id (gha_…, or ghr_… while a registration is
// pending), not GitHub's numeric app id.
func GitHubAppKeyContext(organizationID, githubAppID string) Context {
	return Context{"purpose": PurposeGitHubAppKey, "organizationId": organizationID, "githubAppId": githubAppID}
}

// AuditExportCredentialContext binds an audit export's S3 credential (org
// KEK) while the export is active. exportID is the export's row id (aex_…).
func AuditExportCredentialContext(organizationID, exportID string) Context {
	return Context{"purpose": PurposeAuditExportCredential, "organizationId": organizationID, "exportId": exportID}
}

// AuditExportDrainContext binds the same credential re-encrypted under the
// Root KEK when its organization is deleted, so the export can drain after
// the org KEK is destroyed.
func AuditExportDrainContext(organizationID, exportID string) Context {
	return Context{"purpose": PurposeAuditExportDrain, "organizationId": organizationID, "exportId": exportID}
}

// KEKCanaryContext binds the installation's KEK canary (Root KEK).
func KEKCanaryContext(installationID string) Context {
	return Context{"purpose": PurposeKEKCanary, "installationId": installationID}
}

// JWTSigningKeyContext binds a JWT signing key (Root KEK).
func JWTSigningKeyContext(keyID string) Context {
	return Context{"purpose": PurposeJWTSigningKey, "keyId": keyID}
}

// WrapOrgKEK creates an organization KEK and wraps it with the Root KEK.
func WrapOrgKEK(rootKEK []byte, organizationID string) (orgKEK []byte, wrapped Envelope, err error) {
	orgKEK = GenerateKey()
	wrapped, err = Seal(rootKEK, orgKEK, OrgKEKContext(organizationID))
	return orgKEK, wrapped, err
}

// UnwrapOrgKEK opens an organization's wrapped KEK.
func UnwrapOrgKEK(rootKEK []byte, wrapped Envelope, organizationID string) ([]byte, error) {
	k, err := Open(rootKEK, wrapped, OrgKEKContext(organizationID))
	if err == nil && len(k) != KeySize {
		return nil, ErrKeySize
	}
	return k, err
}

// EncryptedValue is a value version as stored: the payload under a fresh
// DEK, and the DEK wrapped by the org KEK.
type EncryptedValue struct {
	Payload    Envelope `json:"payload"`
	WrappedDEK Envelope `json:"wrappedDek"`
}

// EncryptValue encrypts one value version under a new DEK.
func EncryptValue(orgKEK []byte, organizationID, secretID, versionID string, plaintext []byte) (EncryptedValue, error) {
	dek := GenerateKey()
	payload, err := Seal(dek, plaintext, ValueContext(organizationID, secretID, versionID))
	if err != nil {
		return EncryptedValue{}, err
	}
	wrapped, err := Seal(orgKEK, dek, DEKContext(organizationID, secretID, versionID))
	if err != nil {
		return EncryptedValue{}, err
	}
	return EncryptedValue{Payload: payload, WrappedDEK: wrapped}, nil
}

// DecryptValue opens one value version.
func DecryptValue(orgKEK []byte, organizationID, secretID, versionID string, v EncryptedValue) ([]byte, error) {
	dek, err := Open(orgKEK, v.WrappedDEK, DEKContext(organizationID, secretID, versionID))
	if err != nil {
		return nil, err
	}
	return Open(dek, v.Payload, ValueContext(organizationID, secretID, versionID))
}

// NewCanary creates the installation's KEK canary: a random value sealed
// under the Root KEK, which proves later that a KEK is the right one without
// touching any secret.
func NewCanary(rootKEK []byte, installationID string) (Envelope, error) {
	return Seal(rootKEK, GenerateKey(), KEKCanaryContext(installationID))
}

// VerifyCanary reports whether rootKEK opens the canary.
func VerifyCanary(rootKEK []byte, canary Envelope, installationID string) bool {
	_, err := Open(rootKEK, canary, KEKCanaryContext(installationID))
	return err == nil
}
