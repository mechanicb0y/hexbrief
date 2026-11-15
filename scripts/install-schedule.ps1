<#
.SYNOPSIS
    Registers the daily HexBrief job in Windows Task Scheduler (current user, 07:00
    local time = MYT). Run it yourself once; it changes a Windows setting.

    -Remove deletes only the task named "HexBrief daily".
#>
[CmdletBinding()]
param([string]$At = '07:00', [switch]$Remove)

$ErrorActionPreference = 'Stop'
$name = 'HexBrief daily'
if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false
    Write-Host "removed task '$name'"
    exit 0
}
$repo   = Split-Path -Parent $PSScriptRoot
$script = Join-Path $PSScriptRoot 'daily.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" -WorkingDirectory $repo
$trigger  = New-ScheduledTaskTrigger -Daily -At $At
# Run only when logged on (needs Docker Desktop + your git credentials); wake to run;
# catch up if the PC was off at 07:00; never run twice at once; stop after 3 h.
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 3) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
    -Description 'HexBrief: daily threat-intel brief (scripts\daily.ps1)' -Force | Out-Null
Write-Host "registered '$name' daily at $At (logs: runs\daily-<date>.log)"
