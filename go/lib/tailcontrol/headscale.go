// SPDX-License-Identifier: Apache-2.0

package tailcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// HeadscaleKeyLifetime is the longest an API key given for a handoff may
// still have to live (ADR-0059 Decision 9: every Headscale API key is a
// full administrator, so only one that expires within the hour is taken).
// A minute of slack covers the time between its creation and its check.
const HeadscaleKeyLifetime = time.Hour + time.Minute

// headscaleNode is a node as Headscale lists it: its API answers in
// lowerCamelCase, and its CLI's JSON output in the protobuf's snake_case,
// so both spellings are read.
type headscaleNode struct {
	ID           json.RawMessage `json:"id"` // a uint64, as a JSON string or number
	Name         string          `json:"name"`
	GivenName    string          `json:"givenName"`
	GivenNameCLI string          `json:"given_name"`
	Online       bool            `json:"online"`
	Expiry       *time.Time      `json:"expiry"`
	LastSeen     *time.Time      `json:"lastSeen"`
	LastSeenCLI  *time.Time      `json:"last_seen"`
}

func (n headscaleNode) device(now time.Time) (Device, error) {
	id := strings.Trim(string(n.ID), `"`)
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return Device{}, fmt.Errorf("a node whose id is not a number (%s)", string(n.ID))
	}
	// The given name is the node's MagicDNS name, the one a rename sets;
	// a node that never got one is known by its own.
	name := n.GivenName
	if name == "" {
		name = n.GivenNameCLI
	}
	if name == "" {
		name = n.Name
	}
	if name == "" {
		return Device{}, fmt.Errorf("node %s has no name", id)
	}
	d := Device{ID: id, Name: name, Online: n.Online}
	// Headscale writes an unset expiry as the zero time.
	if n.Expiry != nil && !n.Expiry.IsZero() && n.Expiry.Year() > 1 && n.Expiry.Before(now) {
		d.Expired = true
	}
	switch {
	case n.LastSeen != nil:
		d.LastSeen = *n.LastSeen
	case n.LastSeenCLI != nil:
		d.LastSeen = *n.LastSeenCLI
	}
	return d, nil
}

func headscaleDevices(nodes []headscaleNode, now time.Time) ([]Device, error) {
	out := make([]Device, 0, len(nodes))
	for _, n := range nodes {
		d, err := n.device(now)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// HeadscaleAPI is a tailnet on Headscale, reached through its API with a
// key that must expire within the hour (Open checks it); Close expires it.
type HeadscaleAPI struct {
	// BaseURL is Headscale's server URL.
	BaseURL string
	// APIKey is the key, as `headscale apikeys create --expiration 1h`
	// printed it.
	APIKey string
	// HTTP is the client requests go through; http.DefaultClient when nil.
	HTTP *http.Client
	// Now is the clock that judges expiries; time.Now when nil.
	Now func() time.Time

	prefix string // the key's prefix, as Headscale lists it; set by Open
}

// Kind is "headscale".
func (h *HeadscaleAPI) Kind() string { return "headscale" }

func (h *HeadscaleAPI) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *HeadscaleAPI) err(op, device string, err error) error {
	return &OpError{Plane: "headscale", Op: op, Device: device, Err: err}
}

func (h *HeadscaleAPI) request(ctx context.Context, method, path string, body any, out any) error {
	var r *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.BaseURL, "/")+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return do(httpClient(h.HTTP), req, out, h.APIKey)
}

// Open checks the key: Headscale lists it, it has not expired, and it
// expires within the hour. Every other operation needs it to have passed.
func (h *HeadscaleAPI) Open(ctx context.Context) error {
	const op = "check key"
	if h.APIKey == "" || h.BaseURL == "" {
		return h.err(op, "", errors.New("no server URL or API key"))
	}
	var got struct {
		APIKeys []struct {
			Prefix     string     `json:"prefix"`
			Expiration *time.Time `json:"expiration"`
		} `json:"apiKeys"`
	}
	if err := h.request(ctx, http.MethodGet, "/api/v1/apikey", nil, &got); err != nil {
		return h.err(op, "", err)
	}
	// The key's own entry: the longest listed prefix the key starts with.
	best := -1
	for i, k := range got.APIKeys {
		if len(k.Prefix) >= 4 && strings.HasPrefix(h.APIKey, k.Prefix) && (best < 0 || len(k.Prefix) > len(got.APIKeys[best].Prefix)) {
			best = i
		}
	}
	if best < 0 {
		return h.err(op, "", errors.New("the server does not list the API key given"))
	}
	k := got.APIKeys[best]
	now := h.now()
	switch {
	case k.Expiration == nil || k.Expiration.IsZero():
		return h.err(op, "", errors.New("the API key never expires: create one with --expiration 1h"))
	case !k.Expiration.After(now):
		return h.err(op, "", errors.New("the API key has expired"))
	case k.Expiration.After(now.Add(HeadscaleKeyLifetime)):
		return h.err(op, "", fmt.Errorf("the API key expires at %s, more than an hour from now: every Headscale key is a full administrator, so create one with --expiration 1h", k.Expiration.UTC().Format(time.RFC3339)))
	}
	h.prefix = k.Prefix
	return nil
}

func (h *HeadscaleAPI) opened(op, device string) error {
	if h.prefix == "" {
		return h.err(op, device, errors.New("the API key was not checked (Open)"))
	}
	return nil
}

// Devices lists every node.
func (h *HeadscaleAPI) Devices(ctx context.Context) ([]Device, error) {
	const op = "list devices"
	if err := h.opened(op, ""); err != nil {
		return nil, err
	}
	var got struct {
		Nodes []headscaleNode `json:"nodes"`
	}
	if err := h.request(ctx, http.MethodGet, "/api/v1/node", nil, &got); err != nil {
		return nil, h.err(op, "", err)
	}
	devices, err := headscaleDevices(got.Nodes, h.now())
	if err != nil {
		return nil, h.err(op, "", err)
	}
	return devices, nil
}

// Rename gives the node the name.
func (h *HeadscaleAPI) Rename(ctx context.Context, deviceID, name string) error {
	const op = "rename"
	if err := h.opened(op, deviceID); err != nil {
		return err
	}
	if _, err := strconv.ParseUint(deviceID, 10, 64); err != nil {
		return h.err(op, deviceID, errors.New("a Headscale node id is a number"))
	}
	err := h.request(ctx, http.MethodPost, "/api/v1/node/"+deviceID+"/rename/"+url.PathEscape(name), nil, nil)
	if err != nil {
		var status *StatusError
		if errors.As(err, &status) && strings.Contains(strings.ToLower(status.Message), "already") {
			err = fmt.Errorf("%w (%q): %v", ErrNameTaken, name, err)
		}
		return h.err(op, deviceID, err)
	}
	return nil
}

// Close expires the key, so the authority given for the work ends with it.
// Closing twice, or after a failed Open, does nothing.
func (h *HeadscaleAPI) Close(ctx context.Context) error {
	if h.prefix == "" {
		return nil
	}
	if err := h.request(ctx, http.MethodPost, "/api/v1/apikey/expire", map[string]string{"prefix": h.prefix}, nil); err != nil {
		return h.err("close", "", fmt.Errorf("expiring the API key: %w", err))
	}
	h.prefix = ""
	return nil
}

// HeadscaleCLI is a tailnet on Headscale, reached through the headscale
// command on the control server itself: no key leaves that host.
type HeadscaleCLI struct {
	// Run runs the headscale command with the arguments and answers its
	// output; nil runs `headscale` from PATH.
	Run func(ctx context.Context, args ...string) ([]byte, error)
	// Now is the clock that judges expiries; time.Now when nil.
	Now func() time.Time
}

// Kind is "headscale".
func (h *HeadscaleCLI) Kind() string { return "headscale" }

// Close has nothing to end: the CLI needs no key.
func (h *HeadscaleCLI) Close(context.Context) error { return nil }

func (h *HeadscaleCLI) run(ctx context.Context, args ...string) ([]byte, error) {
	if h.Run != nil {
		return h.Run(ctx, args...)
	}
	cmd := exec.CommandContext(ctx, "headscale", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return nil, fmt.Errorf("headscale %s: %v: %s", strings.Join(args[:min(2, len(args))], " "), err, msg)
	}
	return out, nil
}

func (h *HeadscaleCLI) err(op, device string, err error) error {
	return &OpError{Plane: "headscale", Op: op, Device: device, Err: err}
}

// Devices lists every node (`headscale nodes list --output json`).
func (h *HeadscaleCLI) Devices(ctx context.Context) ([]Device, error) {
	const op = "list devices"
	out, err := h.run(ctx, "nodes", "list", "--output", "json")
	if err != nil {
		return nil, h.err(op, "", err)
	}
	// An array of nodes; some versions wrap it as {"nodes": [...]}.
	var nodes []headscaleNode
	if err := json.Unmarshal(out, &nodes); err != nil {
		var wrapped struct {
			Nodes []headscaleNode `json:"nodes"`
		}
		if err2 := json.Unmarshal(out, &wrapped); err2 != nil {
			return nil, h.err(op, "", fmt.Errorf("the output is not the JSON expected: %v", err))
		}
		nodes = wrapped.Nodes
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	devices, err := headscaleDevices(nodes, now)
	if err != nil {
		return nil, h.err(op, "", err)
	}
	return devices, nil
}

// Rename gives the node the name (`headscale nodes rename --identifier <id> <name>`).
func (h *HeadscaleCLI) Rename(ctx context.Context, deviceID, name string) error {
	const op = "rename"
	if _, err := strconv.ParseUint(deviceID, 10, 64); err != nil {
		return h.err(op, deviceID, errors.New("a Headscale node id is a number"))
	}
	if _, err := h.run(ctx, "nodes", "rename", "--identifier", deviceID, name); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already") {
			err = fmt.Errorf("%w (%q): %v", ErrNameTaken, name, err)
		}
		return h.err(op, deviceID, err)
	}
	return nil
}
