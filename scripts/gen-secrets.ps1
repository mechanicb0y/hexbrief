<#
.SYNOPSIS
    Fills generated secrets in .env (only where the value is empty or __replace_me__).
    Never prints a secret value and never overwrites a value that is already set.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gen-secrets.ps1
#>
[CmdletBinding()]
param([string]$Path = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Path) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $Path = Join-Path $scriptDir '..\.env'
}
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Host "No env file at $Path. Copy .env.example to .env first."
    exit 1
}

function New-Secret([int]$Bytes = 32) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    # base64url without padding: safe in .env, URLs and JSON
    return [Convert]::ToBase64String($buf).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Keys this script may generate, and how.
$generators = [ordered]@{
    'TAXII_USER'     = { 'hexbrief' }
    'TAXII_PASSWORD' = { New-Secret 32 }
}

$fullPath = (Resolve-Path -LiteralPath $Path).Path
$lines = [System.IO.File]::ReadAllLines($fullPath)
$changed = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
    $parts = $lines[$i] -split '=', 2
    if ($parts.Count -lt 2) { continue }
    $key = $parts[0].Trim()
    if (-not $generators.Contains($key)) { continue }
    $value = ($parts[1] -replace '(^|\s)#.*$', '').Trim().Trim('"')
    if ($value -eq '' -or $value -eq '__replace_me__') {
        $lines[$i] = "$key=" + (& $generators[$key])
        $changed += $key
    }
}

if ($changed.Count -eq 0) {
    Write-Host 'Nothing to generate; all generated keys already have values.'
    exit 0
}
# UTF-8 without BOM, so Docker Compose and python-dotenv read it cleanly.
[System.IO.File]::WriteAllLines($fullPath, $lines, (New-Object System.Text.UTF8Encoding $false))
Write-Host ('Generated: ' + ($changed -join ', ') + ' (values written to .env, not shown)')
