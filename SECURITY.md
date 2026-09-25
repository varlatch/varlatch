# Security policy

Varlatch stores and delivers secrets, so a vulnerability report is the most
important thing anyone can send us.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security
problem.** Report it privately through either channel:

- **GitHub Private Vulnerability Reporting.** On this repository, open the
  **Security** tab and choose **Report a vulnerability**.
- **Email:** [security@varlatch.com](mailto:security@varlatch.com).

Include as much as you can:

- the affected version, from `varlatch --version` or `varlatch doctor`;
- the component, such as varlatchd, the dashboard, the CLI, the SDK, or the
  Compose deployment;
- steps to reproduce, or a proof of concept;
- the impact you expect: what an attacker gains, and from what position.

Use synthetic values. Never send us real secrets from an installation.

## What happens next

We handle security reports as soon as we can, ahead of other work. We
confirm we received your report, keep you informed until it is resolved,
and agree with you when the problem is disclosed. We publish each confirmed
vulnerability as a GitHub Security Advisory on this repository (the
**Security** tab, under **Advisories**) and request a CVE through it where
one applies. We credit you unless you prefer not to be named.

## Supported versions

Fixes, security fixes included, are made on the latest release only. An
older installation gets a fix by upgrading with `varlatch upgrade`.

## Scope

In scope: the code in this repository and the release artifacts it
publishes. That covers varlatchd, the dashboard, the CLI, the SDK and other
packages, the release images, and the Compose deployment as the
documentation configures it.

[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) states what Varlatch
guarantees and what it explicitly does not. A report that a stated
guarantee does not hold is especially valuable.

Out of scope:

- vulnerabilities in third-party components themselves. Report those
  upstream to Convex, PostgreSQL, Tailscale, Caddy, or the package
  concerned. Do tell us if the way Varlatch uses a component makes a flaw
  exploitable.
- attacks that need what the threat model lists as outside Varlatch's
  protection, such as control of the host, of the running varlatchd process,
  or of the Root KEK;
- denial of service through request volume alone;
- scanner output that does not show an impact.

## Testing

Test only against an installation you run yourself. Do not test against
installations that belong to other people or organizations.
