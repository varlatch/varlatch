# SPDX-License-Identifier: Apache-2.0
#
# G8 for install.ps1: runs every prefix of a script that ends before its
# closing brace, in this one PowerShell process, three ways: with an alias,
# a function, or a command on PATH standing in for every word and every
# prefix of every word the script contains. Prints "BAD <length> <how>
# <text>" for any prefix that ran something, then "CHECKED <count>".
# install_ps1_test.go runs it with each PowerShell found (5.1 and 7).
param([string]$Script, [int]$Closing, [string]$Work)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Source = [IO.File]::ReadAllText($Script)

# The whole script's shape, as PowerShell's parser sees it: one statement
# (the & { } group), no param block, no using statements, no #requires
# (which PowerShell enforces while parsing).
$Tokens = $null
$ParseErrors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile($Script, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count -gt 0) { Write-Output "BADSHAPE the script does not parse: $($ParseErrors[0].Message)" }
if ($null -ne $Ast.ParamBlock) { Write-Output 'BADSHAPE the script has a param block' }
if ($Ast.UsingStatements.Count -gt 0) { Write-Output 'BADSHAPE the script has using statements' }
if ($null -ne $Ast.ScriptRequirements) { Write-Output 'BADSHAPE the script has #requires' }
if ($null -ne $Ast.BeginBlock -or $null -ne $Ast.ProcessBlock -or $Ast.EndBlock.Statements.Count -ne 1) {
  Write-Output 'BADSHAPE the script is not exactly one statement'
}
$Names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($Match in [regex]::Matches($Source, '[A-Za-z0-9_.-]+')) {
  for ($i = 1; $i -le $Match.Value.Length; $i++) { [void]$Names.Add($Match.Value.Substring(0, $i)) }
}
$OnWindows = $env:OS -eq 'Windows_NT'
# Names Windows cannot give a file.
$Reserved = '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])$'

# Commands: an executable on PATH per name, logging its own name.
$Bin = Join-Path $Work 'bin'
$CommandLog = Join-Path $Work 'commands.log'
New-Item -ItemType Directory -Path $Bin | Out-Null
foreach ($Name in $Names) {
  if ($Name -in '.', '..' -or $Name.EndsWith('.') -or $Name -match $Reserved) { continue }
  if ($OnWindows) {
    # The redirect first: "echo COMMAND 5>>log" would redirect handle 5.
    [IO.File]::WriteAllText((Join-Path $Bin "$Name.cmd"), "@>>`"$CommandLog`" echo COMMAND $Name`r`n")
  } else {
    $File = Join-Path $Bin $Name
    [IO.File]::WriteAllText($File, "#!/bin/sh`necho COMMAND $Name >> '$CommandLog'`n")
    [IO.File]::SetUnixFileMode($File, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
  }
}
$env:PATH = $Bin

# Functions and aliases, each in a session of its own (an alias would hide
# a function of the same name).
$Hits = [Collections.ArrayList]::Synchronized([Collections.ArrayList]::new())
function New-SentinelRunspace([string]$Kind) {
  $State = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
  if ($OnWindows) { $State.ExecutionPolicy = 'Bypass' }
  $State.Variables.Add([Management.Automation.Runspaces.SessionStateVariableEntry]::new('SentinelHits', $Hits, ''))
  $State.Commands.Add([Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Invoke-VarlatchSentinel', '[void]$SentinelHits.Add("ALIAS " + $MyInvocation.InvocationName)'))
  foreach ($Name in $Names) {
    # Names PowerShell would not read as a command name at all.
    if ($Name -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$' -or $Name -eq 'Invoke-VarlatchSentinel') { continue }
    if ($Kind -eq 'function') {
      $State.Commands.Add([Management.Automation.Runspaces.SessionStateFunctionEntry]::new($Name, "[void]`$SentinelHits.Add('FUNCTION $Name')"))
    } else {
      $State.Commands.Add([Management.Automation.Runspaces.SessionStateAliasEntry]::new($Name, 'Invoke-VarlatchSentinel'))
    }
  }
  $Runspace = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($State)
  $Runspace.Open()
  return $Runspace
}
$Runspaces = @{ alias = New-SentinelRunspace 'alias'; function = New-SentinelRunspace 'function' }

# The script's own messages start a line.
$Messages = '(?m)^(varlatch install:|usage:|Installed|Next:|Added )'
$Checked = 0
$Bytes = [IO.File]::ReadAllBytes($Script)
for ($Length = 0; $Length -le $Closing; $Length++) {
  $File = Join-Path $Work "p$Length.ps1"
  $Prefix = [byte[]]::new($Length)
  [Array]::Copy($Bytes, $Prefix, $Length)
  [IO.File]::WriteAllBytes($File, $Prefix)
  # Before the closing brace, a prefix either does not parse or holds no
  # statement at all (comments only).
  $PrefixErrors = $null
  $PrefixAst = [Management.Automation.Language.Parser]::ParseFile($File, [ref]$Tokens, [ref]$PrefixErrors)
  if ($PrefixErrors.Count -eq 0 -and $PrefixAst.EndBlock.Statements.Count -gt 0) {
    Write-Output "BAD $Length parse the prefix parses and has statements"
  }
  foreach ($Kind in 'alias', 'function') {
    $Hits.Clear()
    if (Test-Path -LiteralPath $CommandLog) { Remove-Item -LiteralPath $CommandLog }
    $Shell = [PowerShell]::Create()
    $Shell.Runspace = $Runspaces[$Kind]
    [void]$Shell.AddCommand($File)
    $Text = ''
    try { $Text = (@($Shell.Invoke()) | ForEach-Object { "$_" }) -join "`n" } catch { $Text = '' }
    $Text += "`n" + ((@($Shell.Streams.Information) + @($Shell.Streams.Error)) | ForEach-Object { "$_" }) -join "`n"
    $Shell.Dispose()
    $Ran = @()
    if ($Hits.Count -gt 0) { $Ran += "$Kind sentinel: $($Hits -join ', ')" }
    if (Test-Path -LiteralPath $CommandLog) { $Ran += "command sentinel: $((Get-Content -LiteralPath $CommandLog) -join ', ')" }
    if ($Text -match $Messages) { $Ran += "message: $($Matches[0])" }
    if ($Ran.Count -gt 0) { Write-Output "BAD $Length $Kind $($Ran -join '; ')" }
    $Checked++
  }
  Remove-Item -LiteralPath $File
}
Write-Output "CHECKED $Checked"
