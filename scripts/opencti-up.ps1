<#
.SYNOPSIS
    Starts the lab OpenCTI on http://127.0.0.1:8088 (on demand; stop with opencti-down.ps1).

.DESCRIPTION
    - Creates docker/opencti/.env.opencti from the template once, with generated secrets.
    - Raises vm.max_map_count for Elasticsearch (Docker Desktop resets it; TROUBLESHOOTING).
    - Stops the lab MISP first unless -WithMisp (ADR-001/004: never both heavy at once).
    - -WithMisp also starts the MISP connector; -WithTaxii starts the TAXII2 connector
      (pulls from the lab medallion).
#>
[CmdletBinding()]
param([switch]$WithMisp, [switch]$WithTaxii, [switch]$NoWait)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$dir     = Join-Path $repo 'docker\opencti'
$envFile = Join-Path $dir '.env.opencti'

if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $dir 'env.opencti.template') $envFile
}
if (Select-String -Path $envFile -Pattern '__replace_me__' -Quiet) {
    & (Join-Path $PSScriptRoot 'gen-secrets.ps1') -Path $envFile
}

if ($WithMisp) {
    if (-not (docker ps -q --filter 'name=hexbrief-misp-misp-core-1')) {
        throw 'MISP is not running. Start it first with scripts\misp-up.ps1.'
    }
} elseif (docker ps -q --filter 'name=hexbrief-misp-') {
    Write-Host 'Stopping the lab MISP to free RAM (use -WithMisp to keep it)...'
    & (Join-Path $PSScriptRoot 'misp-down.ps1')
}

Write-Host 'Setting vm.max_map_count=1048575 for Elasticsearch (resets on Docker restart)...'
docker run --rm --privileged alpine:3.22 sysctl -w vm.max_map_count=1048575 | Out-Null

$composeArgs = @('compose', '-p', 'hexbrief-opencti',
          '--env-file', (Join-Path $repo '.env'), '--env-file', $envFile,
          '-f', (Join-Path $dir 'compose.yml'))
if ($WithMisp)  { $composeArgs += @('--profile', 'misp') }
if ($WithTaxii) { $composeArgs += @('--profile', 'taxii') }

# Healthchecks can outlast compose's patience on first boot (index creation);
# `up -d` is idempotent, so retry for up to 25 minutes.
$deadline = (Get-Date).AddMinutes(25)
$try = 0
while ($true) {
    $try++
    docker @composeArgs up -d   # no 2>&1: PS 5.1 + ErrorAction Stop turns compose warnings into errors
    if ($LASTEXITCODE -eq 0) { break }
    if ((Get-Date) -gt $deadline) { Write-Host 'OpenCTI did not come up within 25 min.'; exit 1 }
    Write-Host "attempt ${try}: still starting; retrying in 30 s..."
    Start-Sleep -Seconds 30
}

if (-not $NoWait) {
    $deadline = (Get-Date).AddMinutes(20)
    do {
        Start-Sleep -Seconds 15
        $state = docker inspect -f '{{.State.Health.Status}}' hexbrief-opencti-opencti-1 2>$null
    } until ($state -eq 'healthy' -or (Get-Date) -gt $deadline)
    if ($state -ne 'healthy') { Write-Host "OpenCTI not healthy yet ($state). Check: docker logs hexbrief-opencti-opencti-1"; exit 1 }
}
Write-Host 'OpenCTI is up: http://127.0.0.1:8088  (admin: OPENCTI_ADMIN_EMAIL / OPENCTI_ADMIN_PASSWORD in docker\opencti\.env.opencti)'
