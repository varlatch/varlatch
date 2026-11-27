# Run an installation

> This guide moved to **[Install Varlatch](self-hosting.md)**, which has the
> full setup walkthrough, ingress choices, and local trial instructions. For
> containers, see **[Docker and Coolify](self-hosting/docker-and-coolify.md)**.

## Install

On a Linux host (amd64 or arm64, with systemd and `sudo`):

```sh
V=0.51.0  # latest release
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sudo sh install.sh --server
```

## What you need

- A Linux host (amd64 or arm64) with systemd and `sudo` ([Host requirements](self-hosting/requirements.md)).
- A domain name or reverse proxy, or pick **localhost** to try it on your own
  machine first.

See [Install Varlatch](self-hosting.md) for every step.

## Try it on your own machine

Run the install commands above on your Linux workstation and choose
**localhost** (`http://localhost:8686`). See
[Try it on your own machine](self-hosting.md#try-it-on-your-own-machine) for
details.

<details>
<summary>Moved sections (links from older pages)</summary>

- <a id="choose-the-address"></a>Choose the address: [Install Varlatch](self-hosting.md#what-you-need)
- <a id="what-setup-does"></a>What setup does: [Install Varlatch](self-hosting.md#what-varlatch-setup-does)
- <a id="without-a-terminal"></a>Without a terminal: [Install Varlatch](self-hosting.md#what-varlatch-setup-does)
- <a id="the-container-image"></a>The container image: [Docker and Coolify](self-hosting/docker-and-coolify.md)

</details>
