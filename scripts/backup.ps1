<#
.SYNOPSIS
    Backs up the HexBrief Docker volumes (OpenCTI + MISP) to backups\<date>\ as tar.gz.
    Run while the stacks are DOWN (the daily job does this on Sundays) so the
    Elasticsearch and MariaDB files are consistent. Keeps the newest -Keep sets.

    Only volumes named hexbrief-* are touched; volumes are mounted read-only.
#>
[CmdletBinding()]
param([int]$Keep = 4)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$root = Join-Path $repo 'backups'          # git-ignored
$dest = Join-Path $root (Get-Date -Format 'yyyy-MM-dd')
New-Item -ItemType Directory -Force $dest | Out-Null

$running = docker ps --filter 'name=hexbrief-' --format '{{.Names}}' |
    Where-Object { $_ -match 'elasticsearch|db-1' }
if ($running) { throw "stop the stacks first (running: $($running -join ', '))" }

$volumes = docker volume ls --format '{{.Name}}' | Where-Object { $_ -like 'hexbrief-*' }
foreach ($v in $volumes) {
    Write-Host "backing up $v"
    docker run --rm -v "${v}:/data:ro" -v "${dest}:/backup" alpine:3.22 `
        tar czf "/backup/$v.tar.gz" -C /data .
    if ($LASTEXITCODE -ne 0) { throw "backup of $v failed" }
}
# Retention: delete only dated folders created by this script, oldest first.
Get-ChildItem $root -Directory | Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}$' } |
    Sort-Object Name -Descending | Select-Object -Skip $Keep |
    ForEach-Object { Write-Host "removing old backup $($_.Name)"; Remove-Item -Recurse -Force $_.FullName }
Write-Host "backup done: $dest"
