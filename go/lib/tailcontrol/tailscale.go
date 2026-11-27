// SPDX-License-Identifier: Apache-2.0

package tailcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// TailscaleAPI is Tailscale's public API.
const TailscaleAPI = "https://api.tailscale.com"

// TailscaleScope is the one scope the OAuth client must have (O4):
// devices:core lists, renames and deletes devices, and nothing else. The
// only other scope it may have is PolicyScope (policy_file:read), which
// reads the tailnet policy file and changes nothing.
const TailscaleScope = "devices:core"

// TailscaleConfig is what NewTailscale takes. It holds the OAuth client's
// secret as given: build the Tailscale from it and drop it; its String and
// GoString redact the secret should it be printed.
type TailscaleConfig struct {
	// BaseURL is the API's origin, https only; TailscaleAPI when empty.
	BaseURL string
	// Tailnet is the tailnet's name, or "-" (the default) for the OAuth
	// client's own.
	Tailnet string
	// ClientID and ClientSecret are the OAuth client's.
	ClientID     string
	ClientSecret string `json:"-"`
	// HTTP is the client every request goes through, required: tailcontrol
	// never makes one of its own. The CLI (varlatch migrate) passes its own
	// client; varlatchd (the restore handoff, slice 7.5b) must pass the
	// outbound policy's client (go/server/outbound, ADR-0057 Decision 9).
	HTTP *http.Client `json:"-"`
	// Now is the clock that judges a device's key expiry; time.Now when nil.
	Now func() time.Time `json:"-"`
}

func (c TailscaleConfig) String() string {
	return fmt.Sprintf("tailcontrol.TailscaleConfig{BaseURL:%q Tailnet:%q ClientID:%q ClientSecret:[redacted]}", c.BaseURL, c.Tailnet, c.ClientID)
}

func (c TailscaleConfig) GoString() string { return c.String() }

// Tailscale is a tailnet on Tailscale's control plane, reached through its
// API with an OAuth client. Each operation exchanges the client's
// credentials for a token, uses it, and drops it: no token outlives the
// operation it was made for. The secret is held in a closure, so printing
// a Tailscale, even inside another struct, shows no credential.
type Tailscale struct {
	base, tailnet, clientID string
	secret                  func() string
	http                    *http.Client
	now                     func() time.Time
}

// NewTailscale checks a configuration and builds the control plane from it.
// The API's origin must be https.
func NewTailscale(c TailscaleConfig) (*Tailscale, error) {
	base, err := httpsOrigin(c.BaseURL, TailscaleAPI)
	if err != nil {
		return nil, &OpError{Plane: "tailscale", Op: "configure", Err: err}
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, &OpError{Plane: "tailscale", Op: "configure", Err: errors.New("no OAuth client id or secret")}
	}
	if c.HTTP == nil {
		return nil, &OpError{Plane: "tailscale", Op: "configure", Err: errNoClient}
	}
	tailnet := c.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	secret := c.ClientSecret
	now := c.Now
	if now == nil {
		now = time.Now
	}
	return &Tailscale{base: base, tailnet: tailnet, clientID: c.ClientID, secret: func() string { return secret }, http: c.HTTP, now: now}, nil
}

// httpsOrigin is the configured origin, or the default when empty, refused
// unless it is https: a control plane's credentials never travel in clear.
func httpsOrigin(configured, fallback string) (string, error) {
	origin := configured
	if origin == "" {
		origin = fallback
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("the control plane's URL must be https (got %q)", origin)
	}
	return strings.TrimRight(origin, "/"), nil
}

// Kind is "tailscale".
func (t *Tailscale) Kind() string { return "tailscale" }

// Close keeps nothing to end: no token outlives its operation.
func (t *Tailscale) Close(context.Context) error { return nil }

func (t *Tailscale) err(op, device string, err error) error {
	return &OpError{Plane: "tailscale", Op: op, Device: device, Err: err}
}

// token exchanges the OAuth client's credentials for a token, and checks
// that the client has devices:core and no other scope but, optionally,
// policy_file:read (O4).
func (t *Tailscale) token(ctx context.Context, op, device string) (string, error) {
	tok, _, err := t.tokenScopes(ctx, op, device)
	return tok, err
}

// tokenScopes is token, also reporting whether the token may read the
// tailnet policy file (PolicyScope).
func (t *Tailscale) tokenScopes(ctx context.Context, op, device string) (tok string, policy bool, err error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {t.clientID}, "client_secret": {t.secret()}}
	var got struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", false, t.err(op, device, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := do(t.http, req, &got, t.secret()); err != nil {
		return "", false, t.err(op, device, fmt.Errorf("exchanging the OAuth client for a token: %w", err))
	}
	if got.AccessToken == "" {
		return "", false, t.err(op, device, errors.New("the token exchange answered no token"))
	}
	core, ok := false, true
	seen := map[string]bool{}
	for _, s := range strings.Fields(got.Scope) {
		if seen[s] {
			ok = false
		}
		seen[s] = true
		switch s {
		case TailscaleScope:
			core = true
		case PolicyScope:
			policy = true
		default:
			ok = false
		}
	}
	if !core || !ok {
		return "", false, t.err(op, device, fmt.Errorf("the OAuth client must have the %s scope and no other but, optionally, %s (it has %q): create one with only those", TailscaleScope, PolicyScope, truncate(scrub(got.Scope, t.secret(), got.AccessToken), 200)))
	}
	return got.AccessToken, policy, nil
}

var _ PolicyReader = (*Tailscale)(nil)

// PolicyHosts reads the tailnet policy file and answers the names of its
// hosts aliases. It needs the OAuth client's optional PolicyScope: without
// it, or when the API refuses the read (401, 403), it answers an error
// wrapping ErrPolicyUnreadable, and sends no request for the file when the
// token's scopes already say so. The file is HuJSON (comments, trailing
// commas), read as such.
func (t *Tailscale) PolicyHosts(ctx context.Context) ([]string, error) {
	const op = "read policy file"
	tok, policy, err := t.tokenScopes(ctx, op, "")
	if err != nil {
		return nil, err
	}
	if !policy {
		return nil, t.err(op, "", ErrPolicyNoScope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+"/api/v2/tailnet/"+url.PathEscape(t.tailnet)+"/acl", nil)
	if err != nil {
		return nil, t.err(op, "", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	var body []byte
	if err := do(t.http, req, &body, t.secret(), tok); err != nil {
		var status *StatusError
		if errors.As(err, &status) && (status.Code == http.StatusUnauthorized || status.Code == http.StatusForbidden) {
			err = fmt.Errorf("%w: the API refused the read although the OAuth client has the %s scope (check the client's tailnet and scopes): %v", ErrPolicyUnreadable, PolicyScope, err)
		}
		return nil, t.err(op, "", err)
	}
	std, err := hujson.Standardize(body)
	if err != nil {
		return nil, t.err(op, "", fmt.Errorf("the policy file is not HuJSON: %s", scrub(err.Error(), t.secret(), tok)))
	}
	var got struct {
		Hosts map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(std, &got); err != nil {
		return nil, t.err(op, "", fmt.Errorf("the policy file is not the JSON expected: %s", scrub(err.Error(), t.secret(), tok)))
	}
	hosts := make([]string, 0, len(got.Hosts))
	for h := range got.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts, nil
}

// tailscaleDevice is a device as the API lists it (fields=all).
type tailscaleDevice struct {
	ID                 string    `json:"id"`
	NodeID             string    `json:"nodeId"`
	Name               string    `json:"name"` // the MagicDNS name, machine.tailnet.ts.net
	ConnectedToControl bool      `json:"connectedToControl"`
	KeyExpiryDisabled  bool      `json:"keyExpiryDisabled"`
	Expires            time.Time `json:"expires"`
	LastSeen           time.Time `json:"lastSeen"`
}

var _ ClockedLister = (*Tailscale)(nil)

// Devices lists every device of the tailnet.
func (t *Tailscale) Devices(ctx context.Context) ([]Device, error) {
	d, _, err := t.DevicesAt(ctx)
	return d, err
}

// DevicesAt is Devices, with the listing's time by Tailscale's clock (its
// answer's Date header; zero without a usable one).
func (t *Tailscale) DevicesAt(ctx context.Context) ([]Device, time.Time, error) {
	const op = "list devices"
	tok, err := t.token(ctx, op, "")
	if err != nil {
		return nil, time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base+"/api/v2/tailnet/"+url.PathEscape(t.tailnet)+"/devices?fields=all", nil)
	if err != nil {
		return nil, time.Time{}, t.err(op, "", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var got struct {
		Devices []tailscaleDevice `json:"devices"`
	}
	at, err := doDated(t.http, req, &got, t.secret(), tok)
	if err != nil {
		return nil, time.Time{}, t.err(op, "", err)
	}
	now := t.now()
	out := make([]Device, 0, len(got.Devices))
	for _, d := range got.Devices {
		if d.ID == "" || d.Name == "" {
			return nil, time.Time{}, t.err(op, "", fmt.Errorf("a device without an id or a name (%q, %q)", d.ID, d.Name))
		}
		machine, _, _ := strings.Cut(d.Name, ".")
		out = append(out, Device{
			ID:       d.ID,
			NodeID:   d.NodeID,
			Name:     machine,
			Online:   d.ConnectedToControl,
			Expired:  !d.KeyExpiryDisabled && !d.Expires.IsZero() && d.Expires.Before(now),
			LastSeen: d.LastSeen,
		})
	}
	return out, at, nil
}

// Rename asks Tailscale to give the device the machine name, which must be
// canonical. A name another device holds is refused (ErrNameTaken); any
// other name is accepted, and may be rewritten, so the caller reads it back
// (RenameAndReadBack).
func (t *Tailscale) Rename(ctx context.Context, deviceID, name string) error {
	const op = "rename"
	if err := checkName("tailscale", deviceID, name); err != nil {
		return err
	}
	tok, err := t.token(ctx, op, deviceID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return t.err(op, deviceID, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/api/v2/device/"+url.PathEscape(deviceID)+"/name", bytes.NewReader(body))
	if err != nil {
		return t.err(op, deviceID, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if err := do(t.http, req, nil, t.secret(), tok); err != nil {
		return t.err(op, deviceID, nameTaken(err, name))
	}
	return nil
}

// nameTaken marks a refused rename as ErrNameTaken when the answer says the
// name is another device's: by its status first (409 Conflict), then, for a
// 400 or 422, by its message. Either way the rename failed; the mark only
// says why, and an answer it cannot place stays a plain failure.
func nameTaken(err error, name string) error {
	var status *StatusError
	if !errors.As(err, &status) {
		return err
	}
	taken := status.Code == http.StatusConflict
	if !taken && (status.Code == http.StatusBadRequest || status.Code == http.StatusUnprocessableEntity) {
		m := strings.ToLower(status.Message)
		taken = strings.Contains(m, "already") || strings.Contains(m, "in use") || strings.Contains(m, "taken")
	}
	if taken {
		return fmt.Errorf("%w (%q): %v", ErrNameTaken, name, err)
	}
	return err
}

// StatusError is a control plane's answer that was not a success: its
// status and its message, with any credential scrubbed.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("status %d", e.Code)
	}
	return fmt.Sprintf("status %d: %s", e.Code, e.Message)
}

// errNoClient is a configuration without its http.Client: tailcontrol never
// makes one, so that inside varlatchd every request goes through the
// outbound policy's client, and the guard in go/server/outbound
// (TestNoRequestInLibOutsideItsExceptions) needs no exception for it.
var errNoClient = errors.New("no http.Client: the caller passes one (varlatchd passes the outbound policy's)")

// do sends req and decodes a 2xx answer's JSON into out (unless out is nil).
// Any other answer is a StatusError carrying the answer's message (its
// "message" or "error" member, else its body), scrubbed of the given
// secrets and only then cut to 200 bytes, so no credential straddles the
// cut. A transport error keeps answering errors.Is as it did (a passed
// deadline stays context.DeadlineExceeded), with its text scrubbed.
func do(c *http.Client, req *http.Request, out any, secrets ...string) error {
	_, err := doDated(c, req, out, secrets...)
	return err
}

// doDated is do, answering too the response's Date (zero when it has none
// that parses).
func doDated(c *http.Client, req *http.Request, out any, secrets ...string) (time.Time, error) {
	res, err := c.Do(req)
	if err != nil {
		return time.Time{}, scrubbed(err, secrets...)
	}
	var at time.Time
	if v := res.Header.Get("Date"); v != "" {
		if t, err := http.ParseTime(v); err == nil {
			at = t.UTC()
		}
	}
	err = answer(res, out, secrets...)
	return at, err
}

func answer(res *http.Response, out any, secrets ...string) error {
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return scrubbed(err, secrets...)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var m struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		msg := ""
		if json.Unmarshal(body, &m) == nil {
			msg = m.Message
			if msg == "" {
				msg = m.Error
			}
		}
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		return &StatusError{Code: res.StatusCode, Message: truncate(scrub(msg, secrets...), 200)}
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		// The body as it came: a HuJSON policy file, say.
		*raw = body
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the answer is not the JSON expected: %s", scrub(err.Error(), secrets...))
	}
	return nil
}
