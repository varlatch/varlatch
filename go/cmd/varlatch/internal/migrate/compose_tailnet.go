// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/tailhandoff"
)

// The source's tailnet side: its Tailscale sidecar (infra/compose's
// docker-compose.tailscale.yml), which the TypeScript varlatchd shares its
// network with, so stopping the sidecar closes every tailnet connection.

// tailscaleService is the sidecar's Compose service, its state directory
// and the certificates tailscaled caches there.
const (
	tailscaleService  = "tailscale"
	tailscaleCertsDir = "/var/lib/tailscale/certs/"
)

// certDomain is a domain a sidecar command takes: lower-case letters,
// digits, - and dots, nothing a shell or a path could read otherwise.
var certDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Tailnet reads the sidecar from the Compose project and .env.
func (c *Compose) Tailnet(ctx context.Context) (TailnetInfo, error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return TailnetInfo{}, err
	}
	svc, ok := cfg.Services[tailscaleService]
	if !ok {
		return TailnetInfo{}, nil
	}
	env, err := c.envFile()
	if err != nil {
		return TailnetInfo{}, err
	}
	info := TailnetInfo{Enabled: true, Machine: strings.ToLower(env["VARLATCH_TAILNET_MACHINE"]), Suffix: strings.ToLower(env["VARLATCH_TAILNET_NAME"])}
	if info.Machine == "" {
		info.Machine = "varlatch"
	}
	if v := svc.Environment["TS_SERVE_CONFIG"]; v != nil && *v != "" {
		info.HTTPS = true
	}
	if v := svc.Environment["TS_EXTRA_ARGS"]; v != nil {
		if info.ControlURL, err = loginServer(*v); err != nil {
			return TailnetInfo{}, fmt.Errorf("the sidecar's TS_EXTRA_ARGS: %w", err)
		}
	}
	return info, nil
}

// SharesTailnetNetwork is whether varlatchd runs in the sidecar's network
// (network_mode service:tailscale), as the stock topology's does: stopping
// the sidecar then takes its network away.
func (c *Compose) SharesTailnetNetwork(ctx context.Context) (bool, error) {
	cfg, err := c.config(ctx)
	if err != nil {
		return false, err
	}
	return cfg.Services[service].NetworkMode == "service:"+tailscaleService, nil
}

// StopTailnet is `docker compose stop tailscale`: tailscaled stops without
// logging out, its state volume kept.
func (c *Compose) StopTailnet(ctx context.Context) error {
	return c.compose(ctx, "docker compose stop tailscale", "stop", tailscaleService)
}

// StartTailnet starts the sidecar, then restarts varlatchd, which shares
// its network (a restart keeps the migration's barrier, which a start
// never clears), and a running dashboard, which resolved them before.
func (c *Compose) StartTailnet(ctx context.Context) error {
	made, err := c.startOwner(ctx, tailscaleService)
	if err != nil {
		return err
	}
	if err := c.restartDaemon(ctx, made); err != nil {
		return err
	}
	return c.refreshDashboard(ctx)
}

// StartTailnetGated is StartTailnet, varlatchd's container started, by its
// id, only behind g.
func (c *Compose) StartTailnetGated(ctx context.Context, g GateRef) error {
	made, err := c.startOwner(ctx, tailscaleService)
	if err != nil {
		return err
	}
	if err := c.startGated(ctx, g, made); err != nil {
		return err
	}
	return c.refreshDashboard(ctx)
}

// startOwner starts the service varlatchd shares its network with, without
// its dependencies: its container, or a new one when it is gone (`docker
// compose start` then does nothing, and exits 0). made is the latter.
func (c *Compose) startOwner(ctx context.Context, owner string) (made bool, err error) {
	has, err := c.hasContainer(ctx, owner)
	if err != nil {
		return false, err
	}
	if has {
		return false, c.compose(ctx, "docker compose start "+owner, "start", owner)
	}
	return true, c.compose(ctx, "docker compose up -d --no-deps "+owner, "up", "-d", "--no-deps", owner)
}

// restartDaemon puts varlatchd in its network owner's network again, once
// that started: a restart, or, when its container is gone or of an owner
// that is (which a restart cannot join), `up --no-deps`, which makes it
// again. Without its dependencies: the one-off varlatch-migrate refuses
// behind a gate.
func (c *Compose) restartDaemon(ctx context.Context, made bool) error {
	has, err := c.hasContainer(ctx, service)
	if err != nil {
		return err
	}
	if has && !made {
		return c.compose(ctx, "docker compose restart varlatchd", "restart", service)
	}
	return c.compose(ctx, "docker compose up -d --no-deps varlatchd", "up", "-d", "--no-deps", service)
}

// hasContainer is whether the service has a container, running or not.
func (c *Compose) hasContainer(ctx context.Context, svc string) (bool, error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(all, func(l composeContainer) bool {
		return l.project == p.Name && l.service == svc && !l.isOneOff()
	}), nil
}

// TailnetCertExpiry reads the sidecar's cached certificate for domain from
// its state volume, by a one-off container of the service (so it works
// whether the sidecar runs or not), never asking for one.
func (c *Compose) TailnetCertExpiry(ctx context.Context, domain string) (time.Time, bool, error) {
	domain = strings.ToLower(domain)
	if !certDomain.MatchString(domain) {
		return time.Time{}, false, fmt.Errorf("%q is not a tailnet domain", domain)
	}
	r, err := c.docker(ctx, []string{"compose", "run", "--rm", "--no-deps", "-T", "--entrypoint", "cat", tailscaleService, tailscaleCertsDir + domain + ".crt"}, nil)
	if err != nil {
		return time.Time{}, false, err
	}
	if r.Code != 0 {
		if bytes.Contains(r.Said, []byte("No such file")) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, failure("reading the sidecar's certificate", r)
	}
	return leafNotAfter(r.Answer)
}

// RenewTailnetCert asks the running sidecar for a certificate for domain
// valid at least minValidity (tailscale cert --min-validity), written in
// the container's temporary directory and removed there: the key never
// leaves the container.
func (c *Compose) RenewTailnetCert(ctx context.Context, domain string, minValidity time.Duration) error {
	domain = strings.ToLower(domain)
	if !certDomain.MatchString(domain) {
		return fmt.Errorf("%q is not a tailnet domain", domain)
	}
	script := fmt.Sprintf("set -e; d=$(mktemp -d); trap 'rm -rf \"$d\"' EXIT; tailscale cert --min-validity %s --cert-file \"$d/c\" --key-file \"$d/k\" %s",
		minValidity.Truncate(time.Second).String(), domain)
	r, err := c.docker(ctx, []string{"compose", "exec", "-T", tailscaleService, "sh", "-c", script}, nil)
	if err != nil {
		return err
	}
	if r.Code != 0 {
		said := strings.ToLower(string(r.Said))
		if strings.Contains(said, "ratelimited") || strings.Contains(said, "rate limit") || strings.Contains(said, "too many certificates") {
			return fmt.Errorf("%w: %v", tailhandoff.ErrRateLimited, failure("tailscale cert", r))
		}
		return failure("tailscale cert", r)
	}
	return nil
}

// leafNotAfter is the first certificate's end in a PEM chain.
func leafNotAfter(certPEM []byte) (time.Time, bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, false, errors.New("the sidecar's cached certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false, err
	}
	return cert.NotAfter, true, nil
}
