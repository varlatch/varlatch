# Install the CLI

## From your installation

When whoever runs your installation turned it on, the installation serves
its own CLI, always the version it runs. One line installs it for you, in
`~/.local/bin` (or `%LOCALAPPDATA%\Programs\Varlatch` on Windows), without
`sudo` and without installing Node.js:

```sh
curl -fsSL https://vault.example.com/install.sh | sh          # Linux and macOS
```

```powershell
irm https://vault.example.com/install.ps1 | iex               # Windows PowerShell
```

Leave out `| sh` (or `| iex`) to read the script first. It checks the file
against the SHA-256 it carries, asks before replacing a copy you already
have, leaves a Homebrew copy to Homebrew, and ends with the `varlatch login`
line to run. Without it, the installation answers 404: use the verified
route below.

Installing this way trusts your installation, and whoever controls its
host or its address, to run code on your machine. To check the release's
signature instead, install it from GitHub as below.

## From the release

The CLI is one file, `varlatch-cli-<version>.cjs`, attached to every
release. It needs only Node.js: [Node.js version](#nodejs-version). Use
the version your installation runs: the CLI and the installation are
released together. The dashboard shows it under Settings, then Server.

## On Linux and macOS

```sh
V=0.21.0  # the release your installation runs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-cli-$V.cjs
curl -fLO https://github.com/varlatch/varlatch/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Releases after 0.15.0 also sign `SHA256SUMS`: check that signature
first, as [Verifying a release](../operations/verify-release.md) describes.
On macOS, check the file with
`grep " varlatch-cli-$V.cjs\$" SHA256SUMS | shasum -a 256 -c -`.

Then put it on your `PATH` as `varlatch`:

- **On your own machine,** a directory you own, so that
  `varlatch self-update` can replace it without `sudo`:

  ```sh
  mkdir -p ~/.local/bin
  install -m 755 varlatch-cli-$V.cjs ~/.local/bin/varlatch
  varlatch --version
  ```

- **On the installation's host,** root-owned, as the backup runbook's
  [Install the operator CLI](../operations/backup.md#install-the-operator-cli)
  describes. Replace it after every upgrade.
- **On Windows,** a directory you own, with a small `varlatch.cmd` that
  starts it: [On Windows](#on-windows) below.

`varlatch self-update` installs a newer release the same way: it checks the
file against `SHA256SUMS`, and the signature when the release is signed and
cosign is installed.

## Node.js version

The CLI runs on Node.js 22, 24 or 26, from a release with that line's
security fixes: at least 22.23.4 on 22, 24.22.1 on 24, or 26.12.1 on 26.
These are the Node.js security releases of 21 October 2026, which fixed,
among others, a flaw in decompressing Brotli data received over the network
(CVE-2026-111497).

On an older release, on a line that no longer receives security fixes
(such as 20, 23 or 25), or on a prerelease (a nightly or release candidate,
whose fixes its version cannot show), every command first prints one
warning on stderr, and otherwise works as before: its output and exit
status do not change. Only `varlatch agents hook`, which a coding agent's
guardrail calls on every tool call, stays quiet. Update Node.js to clear
the warning. If your Node.js carries those fixes
under an older version number, as a distribution's backport can, set
`VARLATCH_NODE_CHECK=off` to hide the warning.

## On Windows

Install a current Node.js LTS release ([Node.js version](#nodejs-version)),
for example with winget:

```powershell
winget install OpenJS.NodeJS.LTS
```

In a new PowerShell window, so that it finds `node`, download the CLI and
`SHA256SUMS`, and check the file against its line in `SHA256SUMS`:

```powershell
$V = "0.21.0"  # the release your installation runs
curl.exe -fLO "https://github.com/varlatch/varlatch/releases/download/v$V/varlatch-cli-$V.cjs"
curl.exe -fLO "https://github.com/varlatch/varlatch/releases/download/v$V/SHA256SUMS"
$Line = Get-Content SHA256SUMS | Where-Object { $_ -like "* varlatch-cli-$V.cjs" }
$Hash = (Get-FileHash -Algorithm SHA256 "varlatch-cli-$V.cjs").Hash
if ($Line -and $Hash -eq ($Line -split " ")[0]) { "OK" } else { "MISMATCH: do not install this file" }
```

It must print `OK`. Releases after 0.15.0 also sign `SHA256SUMS`: check
that signature first, as [Verifying a release](../operations/verify-release.md)
describes.

Then install it as `%LOCALAPPDATA%\Programs\Varlatch\varlatch.cjs`, with a
`varlatch.cmd` next to it that runs it with Node.js, and add that directory
to your user `PATH`:

```powershell
$Dir = "$env:LOCALAPPDATA\Programs\Varlatch"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Copy-Item "varlatch-cli-$V.cjs" "$Dir\varlatch.cjs"
Set-Content -Path "$Dir\varlatch.cmd" -Value '@node "%~dp0varlatch.cjs" %*' -Encoding Ascii
$Key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
$UserPath = $Key.GetValue("Path", "", "DoNotExpandEnvironmentNames")
if (($UserPath -split ";") -notcontains $Dir) {
  $Kind = if ($Key.GetValueNames() -contains "Path") { $Key.GetValueKind("Path") } else { "ExpandString" }
  $Key.SetValue("Path", ((@($UserPath -split ";" | Where-Object { $_ }) + $Dir) -join ";"), $Kind)
  $R = "VARLATCH_PATH_REFRESH_" + [Guid]::NewGuid().ToString("N")
  [Environment]::SetEnvironmentVariable($R, "1", "User")
  [Environment]::SetEnvironmentVariable($R, [NullString]::Value, "User")
}
$Key.Dispose()
$env:Path = "$env:Path;$Dir"
varlatch --version
```

The `PATH` is edited in the registry as it is stored, so entries such as
`%JAVA_HOME%\bin` keep their variables (`[Environment]::SetEnvironmentVariable`
would write them back expanded). Setting and removing a variable of its own
tells new terminals that the `PATH` changed; they find `varlatch` on their
own, and the second-to-last line makes this one find it too. `varlatch self-update` replaces `varlatch.cjs` in
place, without administrator rights, because the directory is yours.
[Varlatch for Windows](https://github.com/varlatch/windows-tray), the tray
app, installs the CLI the same way.

## Removing it

[What Varlatch puts on your machine](uninstall.md#what-varlatch-puts-on-your-machine)
lists the CLI's files and how to remove them.
