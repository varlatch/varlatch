// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// WebAuthn with go-webauthn's protocol package (ADR-0059 Decision 6):
// varlatchd writes the options itself, in the JSON shape the browser
// libraries take (@simplewebauthn/browser's), keeps every challenge
// server-side, bound to what it was issued for and used once, and verifies
// responses with protocol's parsers and verifiers: the challenge, the
// origin (the public URL's, exactly; no cross-origin use), the RP ID hash,
// user presence, user verification where required, and the signature.

// RelyingParty is the WebAuthn relying party: the public URL's host name
// (RP ID) and origin.
type RelyingParty struct {
	ID     string
	Origin string
}

// RelyingPartyOf is relyingPartyOf(publicUrl).
func RelyingPartyOf(u *url.URL) RelyingParty {
	host := u.Hostname()
	return RelyingParty{ID: host, Origin: u.Scheme + "://" + u.Host}
}

// RPName is the relying party's display name.
const RPName = "Varlatch"

// ceremonyTimeout is how long a sign-in, registration or approval prompt
// may take, and how long its challenge stays usable.
const ceremonyTimeout = 5 * time.Minute

// The algorithms a new passkey may use: EdDSA, ES256 and RS256, as
// @simplewebauthn/server offers them.
var credentialParameters = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// newChallenge is 32 random bytes in base64url, as clientDataJSON carries
// a challenge.
func newChallenge() string { return randomBase64URL(32) }

// CredentialDescriptor is PublicKeyCredentialDescriptorJSON.
type CredentialDescriptor struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

// RequestOptions is PublicKeyCredentialRequestOptionsJSON.
type RequestOptions struct {
	Challenge        string                 `json:"challenge"`
	Timeout          int64                  `json:"timeout"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
}

// CreationOptions is PublicKeyCredentialCreationOptionsJSON.
type CreationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Alg  int64  `json:"alg"`
		Type string `json:"type"`
	} `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	Attestation            string                 `json:"attestation"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Extensions struct {
		CredProps bool `json:"credProps"`
	} `json:"extensions"`
}

func transportList(stored string) []string {
	if stored == "" {
		return nil
	}
	return strings.Split(stored, ",")
}

func (rp RelyingParty) requestOptions(challenge, userVerification string, allow []CredentialDescriptor) RequestOptions {
	if allow == nil {
		allow = []CredentialDescriptor{}
	}
	return RequestOptions{
		Challenge: challenge, Timeout: ceremonyTimeout.Milliseconds(), RPID: rp.ID,
		AllowCredentials: allow, UserVerification: userVerification,
	}
}

func (rp RelyingParty) creationOptions(challenge string, userHandle []byte, name, displayName string, exclude []CredentialDescriptor) CreationOptions {
	var o CreationOptions
	o.Challenge = challenge
	o.RP.Name, o.RP.ID = RPName, rp.ID
	o.User.ID = base64.RawURLEncoding.EncodeToString(userHandle)
	o.User.Name, o.User.DisplayName = name, displayName
	for _, p := range credentialParameters {
		o.PubKeyCredParams = append(o.PubKeyCredParams, struct {
			Alg  int64  `json:"alg"`
			Type string `json:"type"`
		}{int64(p.Algorithm), string(p.Type)})
	}
	o.Timeout = ceremonyTimeout.Milliseconds()
	o.Attestation = "none"
	if exclude == nil {
		exclude = []CredentialDescriptor{}
	}
	o.ExcludeCredentials = exclude
	o.AuthenticatorSelection.ResidentKey = "preferred"
	o.AuthenticatorSelection.UserVerification = "preferred"
	o.Extensions.CredProps = true
	return o
}

// Registered is a verified registration: what is stored for the new
// passkey (Better Auth's columns: the COSE public key in standard base64,
// the credential id in base64url, the counter, singleDevice or
// multiDevice from the backup-eligible flag, the backup state, the
// transports and the AAGUID).
type Registered struct {
	CredentialID string
	PublicKey    string
	Counter      uint32
	DeviceType   string
	BackedUp     bool
	Transports   string
	AAGUID       string
	UserVerified bool
}

// verifyRegistration checks a registration response against its challenge.
func (rp RelyingParty) verifyRegistration(response json.RawMessage, challenge string) (Registered, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Registered{}, err
	}
	origins := []string{rp.Origin}
	if _, err := parsed.Verify(challenge, rp.ID, origins, nil, origins, protocol.TopOriginExplicitVerificationMode,
		false, false, true, nil, credentialParameters, protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		return Registered{}, err
	}
	auth := parsed.Response.AttestationObject.AuthData
	att := auth.AttData
	r := Registered{
		CredentialID: base64.RawURLEncoding.EncodeToString(att.CredentialID),
		PublicKey:    base64.StdEncoding.EncodeToString(att.CredentialPublicKey),
		Counter:      auth.Counter,
		DeviceType:   "singleDevice",
		BackedUp:     auth.Flags.HasBackupState(),
		UserVerified: auth.Flags.HasUserVerified(),
	}
	if auth.Flags.HasBackupEligible() {
		r.DeviceType = "multiDevice"
	}
	var transports []string
	for _, t := range parsed.Response.Transports {
		transports = append(transports, string(t))
	}
	r.Transports = strings.Join(transports, ",")
	if len(att.AAGUID) == 16 {
		h := hex.EncodeToString(att.AAGUID)
		r.AAGUID = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	return r, nil
}

// assertion is a parsed assertion response.
type assertion struct {
	parsed *protocol.ParsedCredentialAssertionData
}

// CredentialID is the assertion's credential id, base64url.
func (a assertion) CredentialID() string { return base64.RawURLEncoding.EncodeToString(a.parsed.RawID) }

func parseAssertion(response json.RawMessage) (assertion, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return assertion{}, err
	}
	return assertion{parsed: parsed}, nil
}

// errCounter is an assertion whose signature counter does not move
// forward: a cloned authenticator, or a replay.
var errCounter = errors.New("the passkey's signature counter did not increase")

// verify checks an assertion made with a stored passkey (its COSE public key
// in base64, and its counter as committed now) against its challenge, and
// returns the new counter and whether the user was verified. The counter
// rule is the trigger's (passkey_counter_forward): with the stored or the
// new counter above zero, the new one must be greater.
func (rp RelyingParty) verify(a assertion, challenge string, publicKey string, stored int64, requireUserVerification bool) (uint32, bool, error) {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return 0, false, err
	}
	origins := []string{rp.Origin}
	if err := a.parsed.Verify(challenge, rp.ID, "", origins, nil, origins, protocol.TopOriginExplicitVerificationMode,
		false, requireUserVerification, true, key, protocol.SignaturePolicy{}); err != nil {
		return 0, false, err
	}
	data := a.parsed.Response.AuthenticatorData
	if (data.Counter > 0 || stored > 0) && int64(data.Counter) <= stored {
		return 0, false, errCounter
	}
	return data.Counter, data.Flags.HasUserVerified(), nil
}

// AssertionChallenge is the challenge an assertion's client data carries,
// or "" when it is not a WebAuthn assertion (assertionChallenge).
func AssertionChallenge(response json.RawMessage) string {
	var body struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if json.Unmarshal(response, &body) != nil || body.Response.ClientDataJSON == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body.Response.ClientDataJSON, "="))
	if err != nil {
		return ""
	}
	var cd struct {
		Challenge any `json:"challenge"`
	}
	if json.Unmarshal(raw, &cd) != nil {
		return ""
	}
	c, _ := cd.Challenge.(string)
	return c
}

// The ceremonies a browser runs before or within a session: sign-in,
// enrollment with a setup grant, and adding a passkey. Their challenges are
// kept in memory, bound to the browser that asked for them (its CSRF
// cookie, before a session exists; its session, after) and used once; a
// restart forgets them, and the person starts the prompt again. Approval
// assertions (device sign-in, passkey confirmation) keep theirs in the
// database, bound to the person, the session and the operation.

const (
	ceremonySignIn   = "sign-in"
	ceremonyRegister = "register"
)

// maxCeremonies bounds the challenges held at once.
const maxCeremonies = 10_000

type ceremony struct {
	kind string
	// binding is what the browser must present again: "csrf:<hash>" or
	// "session:<id>".
	binding string
	expires time.Time
	// Registration: the setup grant's token (enrollment), or the signed-in
	// identity (adding a passkey), and the user handle offered.
	grantToken string
	grantID    string
	identityID string
	sessionID  string
	userHandle []byte
}

type ceremonyStore struct {
	mu sync.Mutex
	m  map[string]ceremony
}

func newCeremonyStore() *ceremonyStore { return &ceremonyStore{m: map[string]ceremony{}} }

// errTooManyCeremonies refuses a ceremony while the store is full.
var errTooManyCeremonies = errors.New("too many passkey ceremonies are in progress")

func (c *ceremonyStore) put(now time.Time, challenge string, e ceremony) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCeremonies {
		for k, v := range c.m {
			if !v.expires.After(now) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxCeremonies {
			return errTooManyCeremonies
		}
	}
	e.expires = now.Add(ceremonyTimeout)
	c.m[challenge] = e
	return nil
}

// take removes and returns the ceremony of a challenge, when it is of this
// kind, bound to one of the bindings this browser presents and unexpired.
// A challenge is removed on any attempt: whatever the outcome, it is never
// used twice.
func (c *ceremonyStore) take(now time.Time, challenge, kind string, bindings ...string) (ceremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[challenge]
	if !ok {
		return ceremony{}, false
	}
	delete(c.m, challenge)
	if e.kind != kind || !slices.Contains(bindings, e.binding) || !e.expires.After(now) {
		return ceremony{}, false
	}
	return e, true
}

// CSRFBinding is the ceremony binding of a browser without a session: the
// hash of its CSRF cookie.
func CSRFBinding(csrfToken string) string {
	sum := sha256.Sum256([]byte("varlatch-ceremony\x00" + csrfToken))
	return "csrf:" + hex.EncodeToString(sum[:])
}

// SessionBinding is the ceremony binding of a browser session.
func SessionBinding(sessionID string) string { return "session:" + sessionID }
