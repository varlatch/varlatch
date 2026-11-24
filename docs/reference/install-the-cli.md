# Install the CLI

> **Prerelease.** This page is for Varlatch 0.50, which is not released yet.
> The current release is 0.23.0, whose CLI needs Node.js:
> [its version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/reference/install-the-cli.md).

The CLI is one program, `varlatch`, for Linux, macOS and Windows, on amd64
and arm64. It needs nothing else. Use the version your installation runs:
the dashboard shows it under Settings, then Server.

## From your installation

When whoever runs your installation
[turned it on](../self-hosting/configuration.md#serving-the-cli), the
installation serves its own CLI, always the version it runs. On Linux and
macOS:

```sh
curl -fsSLo install.sh https://vault.example.com/install.sh && sh install.sh
```

On Windows, in PowerShell:

```powershell
irm https://vault.example.com/install.ps1 -OutFile install.ps1
if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }
```

It installs for you alone, in `~/.local/bin` (or
`%LOCALAPPDATA%\Programs\Varlatch` on Windows), without `sudo`. It leaves a
copy Homebrew or winget installed to them. Where it is not turned on, the
installation answers 404: install it from the release instead.

Installing this way trusts your installation, and whoever controls its
host or its address, to run code on your machine. The script downloads the
CLI from it, and the downloaded CLI checks that Varlatch's release workflow
signed it.

## On Linux and macOS

```sh
V=0.50.0  # the release your installation runs
curl -fsSL -o install.sh https://github.com/varlatch/varlatch/releases/download/v$V/install.sh
sh install.sh
```

The script downloads the CLI from GitHub and checks it against the
release's `SHA256SUMS`. The downloaded CLI then checks that the release
workflow signed `SHA256SUMS` for this version. When a check fails, nothing
is installed. It ends with the `varlatch login` line to run, and tells you
when `~/.local/bin` is not on your `PATH`.

`--dir <directory>` chooses another directory. Read the script first if
you like: it is a short shell script.

The first check runs code you just downloaded. To check the signature with
cosign before you run anything, install by hand:
[Without running the script](#without-running-the-script).

## On Windows

```powershell
$V = "0.50.0"  # the release your installation runs
irm "https://github.com/varlatch/varlatch/releases/download/v$V/install.ps1" -OutFile install.ps1
if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }
```

It makes the same checks, installs `varlatch.exe` in
`%LOCALAPPDATA%\Programs\Varlatch`, and adds that directory to your user
`PATH`, keeping the variables in it. Open a new terminal to use it. It
needs no administrator rights.

[Varlatch for Windows](https://github.com/varlatch/windows-tray), the tray
app, can install the CLI too.

## Without running the script

Download the file for your system, `SHA256SUMS` and its signature. On Linux,
amd64:

```sh
V=0.50.0
B=https://github.com/varlatch/varlatch/releases/download/v$V
curl -fLO "$B/varlatch-$V-linux-amd64"
curl -fLO "$B/SHA256SUMS"
curl -fLO "$B/SHA256SUMS.sigstore.json"
sha256sum --ignore-missing -c SHA256SUMS
```

Check the signature on `SHA256SUMS` with cosign, as
[Verifying a release](../operations/verify-release.md#release-assets)
describes, then install the file:

```sh
mkdir -p ~/.local/bin
install -m 755 "varlatch-$V-linux-amd64" ~/.local/bin/varlatch
varlatch --version
```

The other files are `linux-arm64`, `darwin-amd64`, `darwin-arm64`,
`windows-amd64.exe` and `windows-arm64.exe`. On macOS, check the file with
`grep " varlatch-$V-darwin-arm64\$" SHA256SUMS | shasum -a 256 -c -`.

### Warnings on macOS and Windows

The binaries are signed with Sigstore, not with an Apple or Microsoft
certificate. A file you download in a browser is marked as coming from the
internet, and the system warns about it:

- **macOS** (Gatekeeper) refuses to open it. The scripts above use `curl`,
  which does not mark files. For a file you checked as above and downloaded
  in a browser, remove the mark:
  `xattr -d com.apple.quarantine ./varlatch-$V-darwin-arm64`.
- **Windows** (SmartScreen) says it protected your PC. `install.ps1` does
  not cause this. For a file you checked and downloaded in a browser, use
  `Unblock-File .\varlatch-$V-windows-amd64.exe`, or choose **More info**,
  then **Run anyway**.

Remove a mark only after the checksum and the signature are right.

## On the installation's host

`install.sh --server` installs the CLI in `/usr/local/bin`, with
`varlatchd`: [Run an installation](../run-an-installation.md#install).
`varlatch upgrade` replaces both.

## Update it

```sh
varlatch self-update
```

It shows both versions, checks the file and the release's signature, and
asks before it replaces the CLI. Without a terminal, add `--yes`. It never
installs an older release without `--allow-downgrade`, nor a prerelease
without `--prerelease` unless you run one. A copy that Homebrew or winget
installed is updated with them.

`self-update` of 0.23.0 and earlier does not reach 0.50: it installs nothing
and says that `releases before 0.9.0 predate the single-file CLI`. Run the
script for your system, above, or `brew upgrade varlatch`.

## Node.js version

From 0.50, the CLI does not need Node.js. The CLI of 0.23.0 and earlier
runs on Node.js 22, 24 or 26:
[their version of this page](https://github.com/varlatch/varlatch/tree/v0.23.0/docs/reference/install-the-cli.md#nodejs-version).

`install.sh` and `install.ps1` replace that CLI when they find it where they
install, once the new one runs. Your sign-ins and settings carry over. On
the host of a Compose installation it is kept beside the new one as
`varlatch-ts`: that installation's host commands need it.

## Removing it

[What Varlatch puts on your machine](uninstall.md#what-varlatch-puts-on-your-machine)
lists the CLI's files and how to remove them.

<a id="from-the-release"></a>
