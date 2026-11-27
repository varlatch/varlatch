# Install the CLI

The `varlatch` CLI is a single standalone binary for Linux, macOS, and Windows
(amd64 and arm64) with no external dependencies. Match the release version your
Varlatch server runs (shown in the dashboard under **Settings → Server**).

## On Linux and macOS

```sh
V=0.51.0  # match the release your server runs
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sh install.sh
```

The script downloads `varlatch` from GitHub, verifies it against `SHA256SUMS`
and the release workflow's Sigstore signature, and installs it to
`~/.local/bin` (no `sudo` needed). Pass `--dir <path>` to choose another
directory.

## On Windows

In PowerShell (no administrator rights needed):

```powershell
$V = "0.50.2"  # match the release your server runs
irm "https://github.com/varlatch/varlatch/releases/download/v$V/install.ps1" -OutFile install.ps1
if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }
```

This verifies the signature, installs `varlatch.exe` in
`%LOCALAPPDATA%\Programs\Varlatch`, and adds it to your user `PATH` (open a new
terminal to use it). [Varlatch for Windows](https://github.com/varlatch/windows-tray)
can also install the CLI for you.

## From your installation

*(Optional — only if your server administrator enabled
[`serve_cli = on`](../self-hosting/configuration.md#serving-the-cli), which is
off by default.)* Your server can host the exact CLI version it runs:

**Linux and macOS:**

```sh
curl -fsSLo install.sh https://vault.example.com/install.sh && sh install.sh
```

**Windows (PowerShell):**

```powershell
irm https://vault.example.com/install.ps1 -OutFile install.ps1
if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }
```

If that returns `404`, `serve_cli` is off—use the GitHub release commands above
instead. Note that installing from your server trusts that server (and its host
operator) to serve the install script; the downloaded CLI still checks the
official release signature.

## Update the CLI

```sh
varlatch self-update
```

Shows old and new versions, verifies the signature, and asks before replacing
the binary (pass `--yes` in scripts). If you installed via Homebrew or winget,
update through them instead.

## Verify manually without running an install script

To check the Sigstore signature with `cosign` before executing any downloaded
file, download the binary, `SHA256SUMS`, and `SHA256SUMS.sigstore.json`
directly. Example for Linux amd64:

```sh
V=0.51.0
B=https://github.com/varlatch/varlatch/releases/download/v$V
curl -fLO "$B/varlatch-$V-linux-amd64"
curl -fLO "$B/SHA256SUMS"
curl -fLO "$B/SHA256SUMS.sigstore.json"
sha256sum --ignore-missing -c SHA256SUMS
```

Verify `SHA256SUMS` with `cosign` ([Verifying a release](../operations/verify-release.md#release-assets)),
then install:

```sh
mkdir -p ~/.local/bin
install -m 755 "varlatch-$V-linux-amd64" ~/.local/bin/varlatch
varlatch --version
```

Other builds: `linux-arm64`, `darwin-amd64`, `darwin-arm64`,
`windows-amd64.exe`, and `windows-arm64.exe`. On macOS, verify the hash with
`grep " varlatch-$V-darwin-arm64\$" SHA256SUMS | shasum -a 256 -c -`.

<details>
<summary>Browser download warnings on macOS (Gatekeeper) and Windows (SmartScreen)</summary>

Release binaries are signed with Sigstore rather than an Apple or Microsoft
code-signing certificate. `curl` and `install.ps1` do not trigger OS quarantine
warnings, but downloading via a web browser will:

- **macOS:** After verifying the checksum and signature, clear quarantine:
  `xattr -d com.apple.quarantine ./varlatch-$V-darwin-arm64`
- **Windows:** After verifying, run
  `Unblock-File .\varlatch-$V-windows-amd64.exe` (or click **More info → Run anyway**).

</details>

## On a Varlatch server host

`install.sh --server` installs both `varlatch` and `varlatchd` into
`/usr/local/bin` ([Install Varlatch](../self-hosting.md#install)), and
`varlatch upgrade` updates both together.

## Removing the CLI

See [Removing Varlatch](uninstall.md#what-varlatch-puts-on-your-machine).

<details>
<summary>Upgrading from the 0.23.0 Node.js CLI</summary>

<a id="nodejs-version"></a>

From 0.50, the CLI is a native binary and no longer needs Node.js. `self-update`
from 0.23.0 or earlier cannot jump to 0.50 directly—run `install.sh`,
`install.ps1`, or `brew upgrade varlatch` above to replace it. Your sign-ins
and settings carry over automatically. (On a legacy Compose host, the old CLI
is kept alongside as `varlatch-ts` for migration.) For 0.23.0 Node.js
requirements, see the
[0.23.0 docs](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/reference/install-the-cli.md#nodejs-version).

</details>

<a id="from-the-release"></a>
