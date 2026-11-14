<#
.SYNOPSIS
    Builds and starts the lab TAXII 2.1 server (medallion) on http://127.0.0.1:5000.
    Data lives in memory only: a restart empties the daily-briefs collection.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
docker compose --env-file (Join-Path $repo '.env') -f (Join-Path $repo 'docker\taxii\compose.yml') up -d --build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'TAXII discovery: http://127.0.0.1:5000/taxii2/  (API root /hexbrief/, collection daily-briefs)'
