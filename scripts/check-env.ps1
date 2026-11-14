<#
.SYNOPSIS
    Reports which required keys in .env are still unset. Never prints a value.

.DESCRIPTION
    Reads a dotenv file, skips blank lines and comments, and checks that every
    required key exists and is neither empty nor the __replace_me__ placeholder.
    Only key NAMES are ever written to the console.
    Exit code 0 = all required keys are set; 1 = something is missing or no file.
    Later this becomes one check inside `hexbrief doctor`.

.PARAMETER Path
    Path to the env file. Defaults to the .env in the repo root.

.PARAMETER Required
    Keys that must be set. Phase 0 requires only the two free feed keys.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check-env.ps1
    $LASTEXITCODE
#>
[CmdletBinding()]
param(
    [string]$Path = '',
    [string[]]$Required = @('OTX_API_KEY', 'ABUSECH_AUTH_KEY')
)

Set-StrictMode -Version Latest
$Placeholder = '__replace_me__'

# Resolve the default here, not in param(): Windows PowerShell 5.1 leaves
# $PSScriptRoot empty inside parameter default values.
if (-not $Path) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Path = Join-Path $scriptDir '..\.env'
}

function Test-Unset([string]$Value) {
    return [string]::IsNullOrWhiteSpace($Value) -or $Value -eq $Placeholder
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Host "No env file at $Path. Copy .env.example to .env first."
    exit 1
}

# Parse KEY=VALUE lines into a hashtable. Values stay in memory only.
$values = @{}
foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
    $line = $raw.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { continue }
    if ($line.StartsWith('export ')) { $line = $line.Substring(7).Trim() }

    # Split on the FIRST '=' only, so values that contain '=' stay whole.
    $parts = $line -split '=', 2
    if ($parts.Count -lt 2) { continue }
    $key = $parts[0].Trim()
    $value = $parts[1].Trim()
    if ($value -match '^"([^"]*)"' -or $value -match "^'([^']*)'") {
        # Quoted: keep what is inside the quotes and ignore anything after them.
        $value = $Matches[1]
    }
    else {
        # Unquoted: a '#' at the start or after whitespace begins a comment,
        # so `KEY=__replace_me__ # TODO` still counts as unset.
        $value = ($value -replace '(^|\s)#.*$', '').Trim()
    }
    if ($key -ne '') { $values[$key] = $value }
}

# Required keys: missing from the file, empty, or still the placeholder.
$missing = @()
foreach ($name in $Required) {
    if (-not $values.ContainsKey($name) -or (Test-Unset $values[$name])) {
        $missing += $name
        Write-Host "MISSING  $name"
    }
    else {
        Write-Host "OK       $name"
    }
}

# Other keys that are still unset: names only, as a to-do list.
$optionalUnset = @($values.Keys |
    Where-Object { $_ -notin $Required -and (Test-Unset $values[$_]) } |
    Sort-Object)
if ($optionalUnset.Count -gt 0) {
    Write-Host ('Not set yet (not required in this phase): ' + ($optionalUnset -join ', '))
}

if ($missing.Count -gt 0) {
    Write-Host "$($missing.Count) required key(s) missing. Edit .env yourself; never paste keys into chat."
    exit 1
}

Write-Host 'All required keys are set.'
exit 0
