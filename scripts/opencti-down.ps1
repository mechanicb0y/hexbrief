<#
.SYNOPSIS
    Stops the lab OpenCTI and frees its RAM. Data volumes are kept (never `down -v`).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$dir  = Join-Path $repo 'docker\opencti'
docker compose -p hexbrief-opencti --env-file (Join-Path $repo '.env') --env-file (Join-Path $dir '.env.opencti') `
    -f (Join-Path $dir 'compose.yml') --profile misp --profile taxii down
exit $LASTEXITCODE
