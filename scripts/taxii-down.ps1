<#
.SYNOPSIS
    Stops the lab TAXII server. Its data is in memory only, so nothing is kept.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
docker compose --env-file (Join-Path $repo '.env') -f (Join-Path $repo 'docker\taxii\compose.yml') down
exit $LASTEXITCODE
