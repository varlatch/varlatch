# SPDX-License-Identifier: Apache-2.0
#
# Installs the Varlatch CLI on Windows (ADR-0059 Decision 8), for the
# current user, in %LOCALAPPDATA%\Programs\Varlatch, and adds that folder to
# the user PATH. A server needs Linux: see install.sh.
#
#   irm https://varlatch.com/install.ps1 -OutFile install.ps1; if ($?) { powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 }
#
# Options: --version <version> (default: the release this script came
# with), --help.
#
# What this trusts: HTTPS to github.com for the release files, which are
# checked against the release's SHA256SUMS; then, before anything is put in
# place, the downloaded varlatch checks that SHA256SUMS is signed by the
# release workflow of varlatch/varlatch for this version (Sigstore). If any
# check fails, nothing is installed. The release files always come from
# github.com: the downloaded varlatch checks its own signature, which only
# means something when the download itself is trusted. For the strongest
# route, download the files and check them with cosign first:
# https://docs.varlatch.com/operations/verify-release/
#
# An installation that serves this script (varlatchd's serve_cli; ADR-0058
# Decision 3) stamps its own address in $Origin below: the CLI then comes
# from it, and is checked the same way. Installing from an installation
# trusts it, and whoever controls its host or its address, to run code on
# this machine.
#
# Every line that runs is inside the & { ... } below, which ends the file.
# PowerShell parses a whole script before it runs any of it, and a copy cut
# off before the closing brace does not parse, so it runs nothing at all.

& {
  Set-StrictMode -Version 3
  $ErrorActionPreference = 'Stop'
  # The script's own arguments, read from the script's scope: passing them
  # as "} @args" would let a copy cut off inside "@args" run with a
  # different argument.
  [object[]]$Arguments = Get-Variable -Name args -Scope 1 -ValueOnly

  # The release stamps its version here; a copy that was not stamped needs
  # --version.
  $VarlatchRelease = '@VARLATCH_VERSION@'
  $Base = 'https://github.com/varlatch/varlatch/releases/download/v'
  # The serving installation's address, stamped when it serves this script;
  # empty in a release, which installs from github.com.
  $Origin = ''
  # https, or http when the installation is on this machine.
  $Scheme = 'https'

  function Stop-Install([string]$Message) { throw "varlatch install: $Message" }

  function Show-Usage { Write-Host 'usage: .\install.ps1 [--version <version>]' }

  # SHA-256 through .NET: Get-FileHash is a script function in Windows
  # PowerShell 5.1 and is missing where that module does not load.
  function Get-Sha256([string]$Path) {
    $Algorithm = [Security.Cryptography.SHA256]::Create()
    $Stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($Algorithm.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $Stream.Dispose(); $Algorithm.Dispose() }
  }

  # Downloads over HTTPS only. Redirects are followed by hand (GitHub
  # serves release files from another host), each one checked to be HTTPS
  # too, at most five.
  function Get-File([string]$Uri, [string]$Path) {
    $Next = [Uri]$Uri
    for ($Hop = 0; $Hop -le 5; $Hop++) {
      if ($Next.Scheme -ne $Scheme) { Stop-Install "refusing to download $($Next.AbsoluteUri): not $($Scheme.ToUpperInvariant())" }
      $Request = [Net.HttpWebRequest]::Create($Next)
      $Request.AllowAutoRedirect = $false
      $Request.UserAgent = 'varlatch-install'
      try {
        $Response = $Request.GetResponse()
      } catch [Net.WebException] {
        if ($null -eq $_.Exception.Response) { Stop-Install "could not download $Uri ($($_.Exception.Message))" }
        $Response = $_.Exception.Response
      }
      try {
        $Code = [int]$Response.StatusCode
        if ($Code -ge 300 -and $Code -lt 400) {
          if ($Origin) { Stop-Install "could not download $Uri (HTTP ${Code}: a redirect is never followed from an installation)" }
          $Location = $Response.Headers['Location']
          if (-not $Location) { Stop-Install "could not download $Uri (HTTP $Code without a location)" }
          $Next = [Uri]::new($Next, $Location)
          continue
        }
        if ($Code -ne 200) { Stop-Install "could not download $Uri (HTTP $Code)" }
        $Out = [IO.File]::Create($Path)
        try { $Response.GetResponseStream().CopyTo($Out) } finally { $Out.Dispose() }
        return
      } finally {
        $Response.Dispose()
      }
    }
    Stop-Install "could not download $Uri (too many redirects)"
  }

  # Runs a program and returns its exit code and output. In Windows
  # PowerShell 5.1 a native program's stderr becomes error records, which
  # 'Stop' would turn into a failure before the exit code is read, so the
  # preference is relaxed around the call alone.
  function Invoke-Program([string]$Program, [string[]]$ProgramArguments) {
    $Saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      # No exit code read back counts as a failure, never as success.
      $global:LASTEXITCODE = $null
      $Output = @(& $Program @ProgramArguments 2>&1 | ForEach-Object { "$_" })
      $Code = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { -1 }
      return [pscustomobject]@{ Code = $Code; Output = $Output }
    } finally {
      $ErrorActionPreference = $Saved
    }
  }

  # The one SHA-256 SHA256SUMS lists for exactly that file name.
  function Get-Expected([string]$Sums, [string]$Name) {
    $Found = @(Get-Content -LiteralPath $Sums | ForEach-Object {
        if ($_ -cmatch '^([0-9a-f]{64}) [ *](.+)$' -and $Matches[2] -ceq $Name) { $Matches[1] }
      })
    if ($Found.Count -ne 1) { Stop-Install "SHA256SUMS does not list $Name exactly once; nothing was installed" }
    return $Found[0]
  }

  # Whether a file is the TypeScript CLI's single-file build
  # (varlatch-cli-<version>.cjs): its banner is in its first bytes.
  function Test-TypeScriptCli([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $Stream = [IO.File]::OpenRead($Path)
    try {
      $Head = New-Object byte[] 512
      $Read = $Stream.Read($Head, 0, $Head.Length)
      return [Text.Encoding]::ASCII.GetString($Head, 0, $Read).Contains('Varlatch CLI. Copyright')
    } finally { $Stream.Dispose() }
  }

  # Replaces a file atomically when it exists ([IO.File]::Replace, with a
  # real null for "no backup": PowerShell would pass $null as ""), moves it
  # in when it does not; the staged file sits in the same directory.
  function Install-File([string]$Staged, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) { [IO.File]::Replace($Staged, $Destination, [NullString]::Value) }
    else { [IO.File]::Move($Staged, $Destination) }
  }

  function Install-Varlatch {
    $Version = $VarlatchRelease
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
      switch -CaseSensitive ($Arguments[$i]) {
        '--version' {
          if ($i + 1 -ge $Arguments.Count) { Stop-Install '--version needs a value' }
          $i++
          $Version = [string]$Arguments[$i]
        }
        { $_ -in '--help', '-h' } { Show-Usage; return }
        default { Show-Usage; Stop-Install "unknown option: $($Arguments[$i])" }
      }
    }
    if ($Version.StartsWith('@')) { Stop-Install 'this copy of install.ps1 is not from a release; pass --version <version>' }
    # A plain release version: nothing in it can change where files come from.
    if ($Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?\z') {
      Stop-Install "not a release version: $Version"
    }

    if ($env:OS -ne 'Windows_NT') { Stop-Install 'this installs varlatch on Windows; elsewhere use install.sh' }
    # A 32-bit PowerShell on a 64-bit Windows reports the machine in
    # PROCESSOR_ARCHITEW6432.
    $Machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $Arch = switch ($Machine) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { $null } }
    if (-not $Arch) { Stop-Install "no varlatch for $Machine processors" }
    if (-not $env:LOCALAPPDATA) { Stop-Install 'LOCALAPPDATA is not set' }

    # Windows PowerShell 5.1 may still offer TLS 1.0: TLS 1.2, and 1.3
    # where .NET has it, only.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
      $Protocols = [Net.SecurityProtocolType]::Tls12
      if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') { $Protocols = $Protocols -bor [Net.SecurityProtocolType]::Tls13 }
      [Net.ServicePointManager]::SecurityProtocol = $Protocols
    }

    $From = "$Base$Version"
    if ($Origin) {
      if ($Origin -cmatch '^https://[A-Za-z0-9.:\[\]-]+$') { $Scheme = 'https' }
      elseif ($Origin -cmatch '^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$') { $Scheme = 'http' }
      else { Stop-Install "$Origin is neither https: nor http: on this machine" }
      $From = "$Origin/cli/v$Version"
    }
    $Name = "varlatch-$Version-windows-$Arch.exe"
    $Dir = Join-Path $env:LOCALAPPDATA 'Programs\Varlatch'
    $Target = Join-Path $Dir 'varlatch.exe'
    $Temp = Join-Path ([IO.Path]::GetTempPath()) ('varlatch-' + [Guid]::NewGuid().ToString('N'))
    $Next = Join-Path $Dir 'varlatch.exe.new'
    New-Item -ItemType Directory -Path $Temp | Out-Null
    try {
      $Sums = Join-Path $Temp 'SHA256SUMS'
      $Bundle = Join-Path $Temp 'SHA256SUMS.sigstore.json'
      $Staged = Join-Path $Temp $Name
      Get-File "$From/SHA256SUMS" $Sums
      Get-File "$From/SHA256SUMS.sigstore.json" $Bundle
      $Want = Get-Expected $Sums $Name
      Get-File "$From/$Name" $Staged
      if ((Get-Sha256 $Staged) -cne $Want) { Stop-Install "$Name does not match SHA256SUMS; nothing was installed" }

      # The downloaded CLI must run here, be this version, and verify the
      # release signature before anything is put in place.
      try { $Run = Invoke-Program $Staged @('--version') } catch { $Run = $null }
      if ($null -eq $Run -or $Run.Code -ne 0 -or $Run.Output.Count -eq 0) {
        Stop-Install 'the downloaded varlatch does not run on this machine; nothing was installed'
      }
      $Reported = $Run.Output[0]
      if (-not ($Reported -ceq "varlatch $Version" -or $Reported.StartsWith("varlatch $Version "))) {
        Stop-Install "the downloaded varlatch reports '$Reported', not $Version; nothing was installed"
      }
      $Run = Invoke-Program $Staged @('verify-release', '--version', $Version, '--sums', $Sums, '--bundle', $Bundle, '--file', "$Staged=$Name")
      $Run.Output | ForEach-Object { Write-Host $_ }
      if ($Run.Code -ne 0) { Stop-Install 'the release signature does not verify; nothing was installed' }

      if ((Test-Path -LiteralPath $Target) -and ((Get-Sha256 $Target) -ceq $Want)) {
        Write-Host "varlatch $Version is already installed at $Target."
      } else {
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        Copy-Item -LiteralPath $Staged -Destination $Next -Force
        # What goes in place is what was checked.
        if ((Get-Sha256 $Next) -cne $Want) { Stop-Install "$Name changed after it was checked; nothing was installed" }
        try { Install-File $Next $Target }
        catch { Stop-Install "could not replace $Target (is varlatch running?): $($_.Exception.Message)" }
        Write-Host "Installed varlatch $Version at $Target."
      }
    } finally {
      Remove-Item -Recurse -Force -LiteralPath $Temp -ErrorAction SilentlyContinue
      Remove-Item -Force -LiteralPath $Next -ErrorAction SilentlyContinue
    }

    # The TypeScript CLI this replaces (decision 11): the varlatch.cmd that
    # starts varlatch.cjs with Node.js, in this folder, as the documentation
    # and the tray app install it. Both go once the new varlatch runs from
    # its place; until then both CLIs share one store of sign-ins and
    # settings. If it does not run, it goes, and the TypeScript CLI stays.
    $Shim = Join-Path $Dir 'varlatch.cmd'
    $Script = Join-Path $Dir 'varlatch.cjs'
    $OldShim = (Test-Path -LiteralPath $Shim -PathType Leaf) -and ([IO.File]::ReadAllText($Shim).Trim() -ceq '@node "%~dp0varlatch.cjs" %*')
    $OldScript = Test-TypeScriptCli $Script
    if ($OldShim -or $OldScript) {
      try { $Run = Invoke-Program $Target @('--version') } catch { $Run = $null }
      if ($null -eq $Run -or $Run.Code -ne 0) {
        Remove-Item -Force -LiteralPath $Target -ErrorAction SilentlyContinue
        Stop-Install "the new varlatch does not run at $Target; the TypeScript CLI (varlatch.cmd, varlatch.cjs) was left in place"
      }
      # varlatch.exe is in place and runs: a file that cannot be removed
      # now (in use) is named, never reported as nothing installed.
      $Left = @()
      if ($OldShim) {
        try { Remove-Item -Force -LiteralPath $Shim -ErrorAction Stop } catch { $Left += 'varlatch.cmd' }
      }
      if ($OldScript) {
        try { Remove-Item -Force -LiteralPath $Script -ErrorAction Stop } catch { $Left += 'varlatch.cjs' }
      }
      if ($Left.Count -eq 0) {
        Write-Host "Removed the TypeScript CLI (varlatch.cmd, varlatch.cjs) from ${Dir}: varlatch.exe replaces it. Your sign-ins and settings carry over: both CLIs use the same store."
      } else {
        Write-Host "varlatch.exe is installed and comes first in ${Dir}, but the TypeScript CLI's $($Left -join ' and ') could not be removed (in use?); remove it once nothing runs it. Your sign-ins and settings carry over: both CLIs use the same store."
      }
    }

    # The user PATH as stored in the registry: its %VARIABLES% unexpanded
    # and its kind kept ([Environment]::SetEnvironmentVariable would write it
    # back expanded, as REG_SZ). Entries are compared expanded; added once.
    $Added = $false
    $Key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
      $Stored = [string]$Key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $Kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
      if ($Key.GetValueNames() -contains 'Path' -and $Key.GetValueKind('Path') -eq [Microsoft.Win32.RegistryValueKind]::String) {
        $Kind = [Microsoft.Win32.RegistryValueKind]::String
      }
      $Entries = @($Stored -split ';' | Where-Object { $_ -ne '' })
      if (-not ($Entries | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $Dir.TrimEnd('\') })) {
        $Key.SetValue('Path', ((@($Entries) + $Dir) -join ';'), $Kind)
        $Added = $true
      }
    } finally {
      $Key.Dispose()
    }
    if ($Added) {
      # Setting a user variable broadcasts the change, so new terminals and
      # Explorer see the new PATH; this one, named so that it cannot be one
      # the user has, is set and removed again (removed with a real null:
      # PowerShell would pass $null as "", which leaves it set and empty).
      $Refresh = 'VARLATCH_INSTALL_REFRESH_' + [Guid]::NewGuid().ToString('N')
      [Environment]::SetEnvironmentVariable($Refresh, '1', 'User')
      [Environment]::SetEnvironmentVariable($Refresh, [NullString]::Value, 'User')
      $env:Path = "$env:Path;$Dir"
      Write-Host "Added $Dir to your user PATH. Open a new terminal to use varlatch."
    }
    $First = Get-Command varlatch -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($First -and ($First.Source -ine $Target)) {
      Write-Host "Another varlatch comes first on your PATH: $($First.Source). Remove it, or put $Dir before it."
    }
    if ($Origin) { Write-Host "Next: varlatch login --server $Origin" }
    else { Write-Host 'Next: varlatch login --server <your Varlatch address>' }
  }

  # A failed check prints its one line and exits 1; nothing was installed.
  try { Install-Varlatch }
  catch {
    $Message = $_.Exception.Message
    if (-not $Message.StartsWith('varlatch install:')) { $Message = "varlatch install: $Message; nothing was installed" }
    [Console]::Error.WriteLine($Message)
    exit 1
  }
}
