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
	"strings"
	"time"
)

// TailscaleAPI is Tailscale's public API.
const TailscaleAPI = "https://api.tailscale.com"

// TailscaleScope is the one scope the OAuth client may have (O4): devices:core
// lists, renames and deletes devices, and nothing else.
const TailscaleScope = "devices:core"

// Tailscale is a tailnet on Tailscale's control plane, reached through its
// API with an OAuth client. Each operation exchanges the client's
// credentials for a token, uses it, and drops it: no token outlives the
// operation it was made for.
type Tailscale struct {
	// BaseURL is the API's origin, TailscaleAPI unless a test serves it.
	BaseURL string
	// Tailnet is the tailnet's name, or "-" for the OAuth client's own.
	Tailnet string
	// ClientID and ClientSecret are the OAuth client's.
	ClientID     string
	ClientSecret string
	// HTTP is the client requests go through; http.DefaultClient when nil.
	HTTP *http.Client
	// Now is the clock that judges a device's key expiry; time.Now when nil.
	Now func() time.Time
}

// Kind is "tailscale".
func (t *Tailscale) Kind() string { return "tailscale" }

// Close keeps nothing to end: no token outlives its operation.
func (t *Tailscale) Close(context.Context) error { return nil }

func (t *Tailscale) base() string {
	if t.BaseURL == "" {
		return TailscaleAPI
	}
	return strings.TrimRight(t.BaseURL, "/")
}

func (t *Tailscale) tailnet() string {
	if t.Tailnet == "" {
		return "-"
	}
	return t.Tailnet
}

func (t *Tailscale) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tailscale) err(op, device string, err error) error {
	return &OpError{Plane: "tailscale", Op: op, Device: device, Err: err}
}

// token exchanges the OAuth client's credentials for a token, and checks
// that the client has devices:core and no other scope (O4).
func (t *Tailscale) token(ctx context.Context, op, device string) (string, error) {
	if t.ClientID == "" || t.ClientSecret == "" {
		return "", t.err(op, device, errors.New("no OAuth client id or secret"))
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {t.ClientID}, "client_secret": {t.ClientSecret}}
	var got struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base()+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", t.err(op, device, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := do(httpClient(t.HTTP), req, &got, t.ClientSecret); err != nil {
		return "", t.err(op, device, fmt.Errorf("exchanging the OAuth client for a token: %w", err))
	}
	if got.AccessToken == "" {
		return "", t.err(op, device, errors.New("the token exchange answered no token"))
	}
	scopes := strings.Fields(got.Scope)
	if len(scopes) != 1 || scopes[0] != TailscaleScope {
		return "", t.err(op, device, fmt.Errorf("the OAuth client must have the %s scope and no other (it has %q): create one with only that scope", TailscaleScope, got.Scope))
	}
	return got.AccessToken, nil
}

// tailscaleDevice is a device as the API lists it (fields=all).
type tailscaleDevice struct {
	ID                 string    `json:"id"`
	NodeID             string    `json:"nodeId"`
	Name               string    `json:"name"`     // the MagicDNS name, machine.tailnet.ts.net
	Hostname           string    `json:"hostname"` // the OS's host name, not the machine name
	ConnectedToControl bool      `json:"connectedToControl"`
	KeyExpiryDisabled  bool      `json:"keyExpiryDisabled"`
	Expires            time.Time `json:"expires"`
	LastSeen           time.Time `json:"lastSeen"`
}

// Devices lists every device of the tailnet.
func (t *Tailscale) Devices(ctx context.Context) ([]Device, error) {
	const op = "list devices"
	tok, err := t.token(ctx, op, "")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.base()+"/api/v2/tailnet/"+url.PathEscape(t.tailnet())+"/devices?fields=all", nil)
	if err != nil {
		return nil, t.err(op, "", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var got struct {
		Devices []tailscaleDevice `json:"devices"`
	}
	if err := do(httpClient(t.HTTP), req, &got, t.ClientSecret, tok); err != nil {
		return nil, t.err(op, "", err)
	}
	now := t.now()
	out := make([]Device, 0, len(got.Devices))
	for _, d := range got.Devices {
		if d.ID == "" || d.Name == "" {
			return nil, t.err(op, "", fmt.Errorf("a device without an id or a name (%q, %q)", d.ID, d.Name))
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
	return out, nil
}

// Rename asks Tailscale to give the device the machine name. A name another
// device holds is refused (ErrNameTaken); any other name is accepted, and
// may be rewritten, so the caller reads it back (RenameAndReadBack).
func (t *Tailscale) Rename(ctx context.Context, deviceID, name string) error {
	const op = "rename"
	tok, err := t.token(ctx, op, deviceID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return t.err(op, deviceID, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base()+"/api/v2/device/"+url.PathEscape(deviceID)+"/name", bytes.NewReader(body))
	if err != nil {
		return t.err(op, deviceID, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	err = do(httpClient(t.HTTP), req, nil, t.ClientSecret, tok)
	var status *StatusError
	if errors.As(err, &status) && (status.Code == http.StatusConflict || strings.Contains(strings.ToLower(status.Message), "already")) {
		err = fmt.Errorf("%w (%q): %v", ErrNameTaken, name, err)
	}
	if err != nil {
		return t.err(op, deviceID, err)
	}
	return nil
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

func httpClient(c *http.Client) *http.Client {
	if c == nil {
		return http.DefaultClient
	}
	return c
}

// do sends req and decodes a 2xx answer's JSON into out (unless out is nil).
// Any other answer is a StatusError carrying the answer's message (its
// "message" or "error" member, else its first bytes), and every error is
// scrubbed of the given secrets: the request's credentials never reach an
// error's text, even when the control plane echoes them.
func do(c *http.Client, req *http.Request, out any, secrets ...string) error {
	res, err := c.Do(req)
	if err != nil {
		// The URL holds no credential; the error may still quote one.
		return errors.New(scrub(err.Error(), secrets...))
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return errors.New(scrub(err.Error(), secrets...))
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
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return &StatusError{Code: res.StatusCode, Message: scrub(msg, secrets...)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("the answer is not the JSON expected: %s", scrub(err.Error(), secrets...))
	}
	return nil
}
