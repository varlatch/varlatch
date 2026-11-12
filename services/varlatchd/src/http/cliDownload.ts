// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * The installation serves its own CLI (ADR-0058 Decision 3), off unless the
 * host operator turns it on (VARLATCH_SERVE_CLI=on): GET /cli/varlatch.cjs,
 * the CLI built with this image, and GET /install.sh and /install.ps1,
 * scripts that download it from this address, check its SHA-256 and
 * install it for the current user.
 *
 * Installing this way trusts the installation, and whoever controls its
 * host or its address, to run code on the installer's machine; the SHA-256
 * only catches a damaged download. Hence off by default, and only over
 * https: or loopback http:, where nothing leaves the machine.
 */

export const CLI_IMAGE_PATH = "/opt/varlatch/varlatch.cjs";

export interface CliDownload {
  /** The CLI file, as built with this image. */
  file: Buffer;
  sha256: string;
  version: string;
  /** The installation's address (VARLATCH_PUBLIC_URL's origin): never taken from a request. */
  origin: string;
  /** Loopback http: (local trials): curl may not follow redirects at all. */
  loopbackHttp: boolean;
}

export type CliDownloadSetting =
  | { serving: true; download: CliDownload }
  | { serving: false; reason: string };

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Whether to serve, and what. Never throws: a problem turns serving off and
 * says why once, at start, so a misconfiguration cannot stop varlatchd.
 */
export function cliDownloadSetting(input: {
  serve: "on" | "off" | undefined;
  publicUrl: string | undefined;
  version: string;
  path?: string;
  read?: (path: string) => Buffer;
}): CliDownloadSetting {
  if (input.serve !== "on") return { serving: false, reason: "VARLATCH_SERVE_CLI is not on" };
  if (!input.publicUrl) return { serving: false, reason: "VARLATCH_PUBLIC_URL is not set" };
  let url: URL;
  try {
    url = new URL(input.publicUrl);
  } catch {
    return { serving: false, reason: "VARLATCH_PUBLIC_URL is not a URL" };
  }
  const loopbackHttp = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !loopbackHttp) {
    return { serving: false, reason: `${url.origin} is neither https: nor http: on this machine (localhost), and a script fetched over plain http: can be replaced on the way` };
  }
  let file: Buffer;
  try {
    file = (input.read ?? readFileSync)(input.path ?? CLI_IMAGE_PATH);
  } catch (err) {
    return { serving: false, reason: `the CLI file cannot be read (${err instanceof Error ? err.message : String(err)})` };
  }
  return {
    serving: true,
    download: { file, sha256: createHash("sha256").update(file).digest("hex"), version: input.version, origin: url.origin, loopbackHttp },
  };
}

/** A value safe inside single quotes in sh and in PowerShell: the inputs above never contain one, and this proves it. */
function quoted(value: string): string {
  if (!/^[A-Za-z0-9.:/\[\]_-]+$/.test(value)) throw new Error(`refusing to put ${JSON.stringify(value)} in an install script`);
  return `'${value}'`;
}

export function installSh(d: CliDownload): string {
  // Only this scheme. curl follows no redirect without -L, and the script
  // accepts nothing but a 200, so a redirect fails the download.
  // -q first: no ~/.curlrc, which could turn on redirects (location) or
  // switch off certificate checks (insecure).
  const curl = d.loopbackHttp ? "curl -q -sS --proto '=http'" : "curl -q -sS --proto '=https' --tlsv1.2";
  return `#!/bin/sh
# Installs the Varlatch CLI ${d.version} from ${d.origin} for the current user.
# Read it first: curl -fsSL ${d.origin}/install.sh
# Installing from an installation trusts it, and whoever controls its host
# or its address, to run code on this machine. The SHA-256 below only
# catches a damaged download. To check the release signature instead, see
# https://docs.varlatch.com/reference/install-the-cli/
set -eu

ORIGIN=${quoted(d.origin)}
VERSION=${quoted(d.version)}
SHA256=${quoted(d.sha256)}
DIR="\${VARLATCH_INSTALL_DIR:-\$HOME/.local/bin}"
TARGET="\$DIR/varlatch"

say() { printf '%s\\n' "\$*"; }
stop() { printf 'varlatch install: %s\\n' "\$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || stop "needs curl"
command -v node >/dev/null 2>&1 || stop "needs Node.js 22, 24 or 26 with its current security fixes (https://nodejs.org); this script never installs it"
major=\$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null) || stop "node does not run"
case "\$major" in
  ''|*[!0-9]*) stop "cannot tell which Node.js this is" ;;
esac
[ "\$major" -ge 22 ] || stop "needs Node.js 22 or newer; this is \$(node --version)"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "\$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "\$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r "\$1" | cut -d' ' -f1
  else stop "needs sha256sum, shasum or openssl to check the download"
  fi
}

# A Homebrew copy is Homebrew's to update: every varlatch on PATH, and the
# target, checked. PATH is split on ':' only, never on spaces, and no
# pattern in it is expanded.
homebrew() {
  [ -e "\$1" ] || return 0
  if grep -q 'installed with Homebrew' "\$1" 2>/dev/null; then
    stop "varlatch is installed with Homebrew at \$1; update it with: brew upgrade varlatch"
  fi
  case "\$(readlink "\$1" 2>/dev/null || true)" in
    */Cellar/*) stop "varlatch is installed with Homebrew at \$1; update it with: brew upgrade varlatch" ;;
  esac
}
homebrew "\$TARGET"
saved_ifs=\$IFS
IFS=:
set -f
for entry in \$PATH; do
  [ -n "\$entry" ] && homebrew "\$entry/varlatch"
done
set +f
IFS=\$saved_ifs

if [ -f "\$TARGET" ] && [ "\$(sha256 "\$TARGET")" = "\$SHA256" ]; then
  say "varlatch \$VERSION is already installed at \$TARGET."
else
  tmp=\$(mktemp -d)
  trap 'rm -rf "\$tmp"' EXIT INT TERM
  status=\$(${curl} -w '%{http_code}' -o "\$tmp/varlatch.cjs" "\$ORIGIN/cli/varlatch.cjs") || stop "could not download \$ORIGIN/cli/varlatch.cjs"
  [ "\$status" = 200 ] || stop "could not download \$ORIGIN/cli/varlatch.cjs (HTTP \$status; a redirect is never followed)"
  [ "\$(sha256 "\$tmp/varlatch.cjs")" = "\$SHA256" ] || stop "the download does not match its SHA-256; nothing was installed"
  reported=\$(node "\$tmp/varlatch.cjs" --version) || stop "the downloaded CLI does not run; nothing was installed"
  case "\$reported" in
    "varlatch \$VERSION "*|"varlatch \$VERSION") ;;
    *) stop "the downloaded CLI reports '\$reported', not \$VERSION; nothing was installed" ;;
  esac
  if [ -e "\$TARGET" ]; then
    say "\$TARGET exists: \$(node "\$TARGET" --version 2>/dev/null || echo 'a file that does not run as the CLI')."
    # Probed in a subshell: a failed redirection on exec would end this shell.
    if ! ( : </dev/tty ) 2>/dev/null; then
      stop "replacing it needs your answer in a terminal; nothing was installed"
    fi
    printf 'Replace it with varlatch %s? [y/N] ' "\$VERSION" >/dev/tty
    read -r answer </dev/tty || answer=
    case "\$answer" in
      y|Y|yes|YES) ;;
      *) stop "nothing was installed" ;;
    esac
  fi
  mkdir -p "\$DIR"
  cp "\$tmp/varlatch.cjs" "\$DIR/.varlatch.\$\$.tmp"
  chmod 755 "\$DIR/.varlatch.\$\$.tmp"
  mv -f "\$DIR/.varlatch.\$\$.tmp" "\$TARGET"
  say "Installed varlatch \$VERSION at \$TARGET."
fi

case ":\$PATH:" in
  *":\$DIR:"*)
    first=\$(command -v varlatch 2>/dev/null || true)
    if [ -n "\$first" ] && [ "\$first" != "\$TARGET" ]; then
      say "Another varlatch comes first on your PATH: \$first. Remove it, or put \$DIR before it."
    fi ;;
  *) say "\$DIR is not on your PATH. Add it, for example: echo 'export PATH=\\"\$DIR:\\$PATH\\"' >> ~/.profile" ;;
esac

say "Next: varlatch login --server \$ORIGIN"
`;
}

export function installPs1(d: CliDownload): string {
  return `# Installs the Varlatch CLI ${d.version} from ${d.origin} for the current user.
# Read it first: irm ${d.origin}/install.ps1
# Installing from an installation trusts it, and whoever controls its host
# or its address, to run code on this machine. The SHA-256 below only
# catches a damaged download. To check the release signature instead, see
# https://docs.varlatch.com/reference/install-the-cli/
& {
  Set-StrictMode -Version 3
  $ErrorActionPreference = 'Stop'
  $Origin = ${quoted(d.origin)}
  $Version = ${quoted(d.version)}
  $Sha256 = ${quoted(d.sha256)}
  $Dir = Join-Path $env:LOCALAPPDATA 'Programs\\Varlatch'
  $Target = Join-Path $Dir 'varlatch.cjs'
  function Stop-Install([string]$Message) { throw "varlatch install: $Message" }

  if (-not ($Origin.StartsWith('https://') -or $Origin -match '^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(:\\d+)?$')) {
    Stop-Install "$Origin is neither https: nor this machine"
  }
  if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Stop-Install 'needs Node.js 22, 24 or 26 with its current security fixes (winget install OpenJS.NodeJS.LTS); this script never installs it'
  }
  $Major = [int](& node -p "process.versions.node.split('.')[0]")
  if ($Major -lt 22) { Stop-Install "needs Node.js 22 or newer; this is $(& node --version)" }

  $Shim = Join-Path $Dir 'varlatch.cmd'
  $ShimText = '@node "%~dp0varlatch.cjs" %*'
  $Installed = (Test-Path $Target) -and ((Get-FileHash -Algorithm SHA256 $Target).Hash -ieq $Sha256)
  $ShimOk = (Test-Path $Shim) -and ((Get-Content -Raw $Shim).Trim() -eq $ShimText)
  # Replace a file atomically when it exists ([IO.File]::Replace, with a real
  # null for "no backup": PowerShell would pass $null as ""), move it in
  # when it does not; the staged file sits in the same directory.
  function Install-File([string]$Staged, [string]$Destination) {
    if (Test-Path $Destination) { [IO.File]::Replace($Staged, $Destination, [NullString]::Value) } else { [IO.File]::Move($Staged, $Destination) }
  }

  if ($Installed -and $ShimOk) {
    Write-Host "varlatch $Version is already installed at $Target."
  } else {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ('varlatch-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Temp | Out-Null
    $NextCli = Join-Path $Dir 'varlatch.cjs.new'
    $NextShim = Join-Path $Dir 'varlatch.cmd.new'
    try {
      $Staged = Join-Path $Temp 'varlatch.cjs'
      if (-not $Installed) {
        # No redirect is followed: a redirect fails the download.
        Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri "$Origin/cli/varlatch.cjs" -OutFile $Staged
        if ((Get-FileHash -Algorithm SHA256 $Staged).Hash -ine $Sha256) { Stop-Install 'the download does not match its SHA-256; nothing was installed' }
        $Reported = (& node $Staged --version) -join ' '
        if (-not ($Reported -eq "varlatch $Version" -or $Reported.StartsWith("varlatch $Version "))) {
          Stop-Install "the downloaded CLI reports '$Reported', not $Version; nothing was installed"
        }
      }
      # Everything that would be replaced, asked about once, before any write.
      $Replacing = @()
      if ((Test-Path $Target) -and -not $Installed) {
        Write-Host "$Target exists: $((& node $Target --version 2>$null) -join ' ')."
        $Replacing += $Target
      }
      if ((Test-Path $Shim) -and -not $ShimOk) {
        Write-Host "$Shim exists and starts something else: $((Get-Content -Raw $Shim).Trim())"
        $Replacing += $Shim
      }
      if ($Replacing.Count -gt 0) {
        try { $Answer = Read-Host "Replace $($Replacing -join ' and ')? [y/N]" } catch { Stop-Install 'replacing it needs your answer in an interactive window; nothing was installed' }
        if ($Answer -notmatch '^(y|yes)$') { Stop-Install 'nothing was installed' }
      }
      New-Item -ItemType Directory -Force -Path $Dir | Out-Null
      if (-not $Installed) {
        Copy-Item $Staged $NextCli -Force
        Install-File $NextCli $Target
        Write-Host "Installed varlatch $Version at $Target."
      }
      if (-not $ShimOk) {
        Set-Content -Path $NextShim -Value $ShimText -Encoding Ascii
        Install-File $NextShim $Shim
      }
    } finally {
      Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
      Remove-Item -Force $NextCli, $NextShim -ErrorAction SilentlyContinue
    }
  }

  # The user PATH as stored, never the combined process PATH; added once.
  $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $Entries = @(if ($UserPath) { $UserPath -split ';' | Where-Object { $_ -ne '' } })
  if (-not ($Entries | Where-Object { $_.TrimEnd('\\') -ieq $Dir.TrimEnd('\\') })) {
    [Environment]::SetEnvironmentVariable('Path', (@($Entries) + $Dir) -join ';', 'User')
    $env:Path = "$env:Path;$Dir"
    Write-Host "Added $Dir to your user PATH. New terminals find varlatch; this one does too."
  }
  $First = Get-Command varlatch -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($First -and ($First.Source -ine $Shim)) {
    Write-Host "Another varlatch comes first on your PATH: $($First.Source). Remove it, or put $Dir before it."
  }
  Write-Host "Next: varlatch login --server $Origin"
}
`;
}
