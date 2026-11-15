<#
.SYNOPSIS
    The 07:00 MYT daily job (ADR-006). Idempotent: re-running the same day overwrites
    that day's outputs, updates the same STIX Report and re-commits the same page.

.DESCRIPTION
    1. Docker Desktop up; doctor (fail fast on missing keys/engine).
    2. MISP session (optional, -SkipMisp to skip): misp-up -> feed fetch -> snapshot of
       fresh findings -> misp-down. (MISP and OpenCTI don't fit in RAM together.)
    3. OpenCTI session: opencti-up -> abuse.ch import -> hexbrief run --push --pages.
    4. Commit + push the public page (site/ only, TLP:CLEAR) if it changed.
    5. opencti-down; weekly backup on Sundays.
    Each step retries up to 2 times; the transcript goes to runs/daily-<day>.log.
    No step prints secrets.
#>
[CmdletBinding()]
param([switch]$SkipMisp, [switch]$NoPublish, [switch]$KeepRunning)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$day  = (Get-Date).ToString('yyyy-MM-dd')
New-Item -ItemType Directory -Force (Join-Path $repo 'runs') | Out-Null
$log  = Join-Path $repo "runs\daily-$day.log"
Start-Transcript -Path $log -Append | Out-Null
$py   = Join-Path $repo '.venv\Scripts\python.exe'
$hb   = Join-Path $repo '.venv\Scripts\hexbrief.exe'
$status = 'ok'

function Step([string]$Name, [scriptblock]$Body, [int]$Tries = 3, [switch]$Optional) {
    for ($i = 1; $i -le $Tries; $i++) {
        try {
            Write-Host "== [$((Get-Date).ToString('HH:mm:ss'))] $Name (try $i)"
            & $Body
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
            return $true
        } catch {
            Write-Host "   $Name failed: $($_.Exception.Message)"
            if ($i -lt $Tries) { Start-Sleep -Seconds (30 * $i) }
        }
    }
    if ($Optional) { Write-Host "   $Name skipped after $Tries tries (optional)"; $script:status = 'degraded'; return $false }
    throw "$Name failed after $Tries tries"
}

try {
    Step 'docker' {
        docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { docker desktop start --timeout 300 }
    }
    Step 'doctor (keys/engine)' { & $hb doctor --no-services } -Tries 1

    if (-not $SkipMisp) {
        $mispOk = Step 'misp-up' { & (Join-Path $PSScriptRoot 'misp-up.ps1') } -Optional
        if ($mispOk) {
            Step 'misp feeds fetch' { & $py (Join-Path $PSScriptRoot 'misp_feeds.py') fetch } -Optional | Out-Null
            Start-Sleep -Seconds 600   # let MISP's workers pull the new feed events
            Step 'misp snapshot' { & $hb misp snapshot --hours 24 } -Optional | Out-Null
        }
        Step 'misp-down' { & (Join-Path $PSScriptRoot 'misp-down.ps1') } -Optional | Out-Null
    }

    Step 'opencti-up' { & (Join-Path $PSScriptRoot 'opencti-up.ps1') }
    Step 'taxii-up' { & (Join-Path $PSScriptRoot 'taxii-up.ps1') } -Optional | Out-Null
    Step 'abuse.ch import' { & $py (Join-Path $PSScriptRoot 'abusech_import.py') } -Optional | Out-Null
    Start-Sleep -Seconds 120   # give the OpenCTI workers time to ingest
    if ($NoPublish) {
        Step 'brief' { & $hb run } -Tries 2
    } else {
        Step 'brief + publish' { & $hb run --push --pages } -Tries 2
        Step 'commit public page' {
            # Only ever push from a clean main: never ship half-done branch work.
            $branch = (git rev-parse --abbrev-ref HEAD).Trim()
            $dirty = git status --porcelain -- . ':(exclude)site'
            if ($branch -ne 'main' -or $dirty) {
                Write-Host "   not on a clean main (branch=$branch); page kept locally, not pushed"
                $script:status = 'degraded'
                $global:LASTEXITCODE = 0
                return
            }
            git pull --ff-only origin main
            git add -- site
            git diff --cached --quiet -- site
            if ($LASTEXITCODE -ne 0) {
                git commit -m "data: daily brief $day (TLP:CLEAR)" -- site
                git push origin HEAD:main
            } else { $global:LASTEXITCODE = 0 }
        } -Optional | Out-Null
    }
} catch {
    $status = 'failed'
    Write-Host "DAILY RUN FAILED: $($_.Exception.Message)"
} finally {
    if (-not $KeepRunning) {
        try { & (Join-Path $PSScriptRoot 'opencti-down.ps1') | Out-Null } catch { Write-Host 'opencti-down failed' }
        try { & (Join-Path $PSScriptRoot 'taxii-down.ps1') | Out-Null } catch { Write-Host 'taxii-down failed' }
    }
    if ((Get-Date).DayOfWeek -eq 'Sunday') {
        try { & (Join-Path $PSScriptRoot 'backup.ps1') } catch { Write-Host "backup failed: $($_.Exception.Message)" }
    }
    Write-Host "== daily run $day finished: $status"
    Stop-Transcript | Out-Null
}
if ($status -eq 'failed') { exit 1 }
exit 0
