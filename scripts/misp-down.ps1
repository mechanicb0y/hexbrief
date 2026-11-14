<#
.SYNOPSIS
    Stops the lab MISP and frees its RAM. Data (database, files) is kept.
    It never deletes volumes; removing data is a separate, deliberate step.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$mispDir = Join-Path $repo 'docker\misp'
docker compose -p hexbrief-misp --env-file (Join-Path $mispDir '.env.misp') `
    -f (Join-Path $mispDir 'upstream\docker-compose.yml') -f (Join-Path $mispDir 'compose.override.yml') `
    down
exit $LASTEXITCODE
