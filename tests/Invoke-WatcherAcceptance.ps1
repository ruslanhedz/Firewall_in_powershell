<#
.SYNOPSIS
    MANUAL acceptance test of the audit watcher on a real machine (needs an elevated Windows PowerShell 5.1).

.DESCRIPTION
    Test-FirewallAudit.ps1 cannot verify what needs real administrator rights: the Scheduled Task running as
    SYSTEM, the ACL on C:\ProgramData\FirewallAudit and the "who" taken from the Windows Firewall event log.
    This script does exactly that, end to end, with throw-away rules named FWAUDIT-ACCEPT-<id>:

      1. checks / creates the protected audit directory (ACL),
      2. installs the watcher (through Invoke-AuditedChange, so the install itself is audited),
      3. checks the task definition (event + startup + 15-minute triggers, SYSTEM),
      4. creates and deletes a rule OUTSIDE the tool (New-NetFirewallRule / Remove-NetFirewallRule) and waits
         for the watcher to log both; reports whether the "who" was recovered,
      5. starts the task by hand and checks state.json,
      6. fail-open with a locked log: the change happens, a marker is written, the next sync reconciles it,
      7. verifies the hash chain, then removes the test rules (and the watcher unless -KeepWatcher).

    It WRITES to the real audit log and the real firewall policy (only its own test rules). Run it on a
    test machine / VM. Exit code 0 = every check passed; 'INFO' lines are things for a human to read.

    powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-WatcherAcceptance.ps1 [-KeepWatcher] [-Force]
#>
#Requires -RunAsAdministrator
param(
    [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'firewall.ps1'),
    [switch]$KeepWatcher,
    [switch]$Force,
    [int]$WaitSeconds = 120
)
$ErrorActionPreference = 'Stop'
$script:Fail = 0
function Step  { param([string]$t) Write-Host "`n== $t" -ForegroundColor Cyan }
function Check { param([bool]$ok, [string]$t) if ($ok) { Write-Host "  [PASS] $t" -ForegroundColor Green } else { $script:Fail++; Write-Host "  [FAIL] $t" -ForegroundColor Red } }
function Info  { param([string]$t) Write-Host "  [INFO] $t" -ForegroundColor Yellow }

if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Windows PowerShell 5.1 (Desktop) is required.' }
if (-not $Force) {
    Write-Host 'This installs the real audit watcher and writes to the real audit log (C:\ProgramData\FirewallAudit).' -ForegroundColor Yellow
    if ((Read-Host 'Continue? (y/N)').Trim().ToLowerInvariant() -ne 'y') { return }
}

$text = [IO.File]::ReadAllText($ScriptPath)
$m = [regex]::Match($text, '(?s)#region AUDIT\r?\n.*?#endregion AUDIT')
if (-not $m.Success) { throw 'AUDIT region not found' }
. ([scriptblock]::Create($m.Value))
$script:AuditSelfPath = $ScriptPath

$id = [guid]::NewGuid().ToString('N').Substring(0, 8)
$nameExt  = "FWAUDIT-ACCEPT-$id-external"
$nameOpen = "FWAUDIT-ACCEPT-$id-failopen"

function Wait-AuditChange {
    param([string]$RuleId, [string]$Op, [int]$Seconds)
    $until = (Get-Date).AddSeconds($Seconds)
    do {
        $r = @(Read-AuditRecords -Type 'change' | Where-Object { $_.ruleId -eq $RuleId -and $_.op -eq $Op })
        if ($r.Count -gt 0) { return $r[-1] }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $until)
    return $null
}

try {
    Step '1. Audit directory'
    Initialize-AuditStore
    $acl = Get-Acl -LiteralPath $script:AuditDir
    $sec = Test-AuditDirSecurity -Acl $acl
    Check $sec.Ok "ACL of $($script:AuditDir) is protected ($($sec.Issues -join '; '))"
    $users = @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in 'S-1-5-32-545', 'S-1-1-0', 'S-1-5-11' -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band 'CreateFiles,WriteData,Modify,Delete,FullControl') })
    Check ($users.Count -eq 0) 'no write access for Users / Everyone / Authenticated Users'

    Step '2. Install the watcher (audited)'
    [void](Invoke-AuditedChange -Operation 'WatcherInstall' -Scope Names -Names @() -Reason 'acceptance test' -Action { Install-AuditWatcher })
    $task = Get-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName -ErrorAction SilentlyContinue
    Check ($null -ne $task) 'scheduled task \FirewallAudit\Watcher exists'
    Check ($task.Principal.UserId -match 'SYSTEM') 'task runs as SYSTEM'
    Check (@($task.Triggers).Count -eq 3) 'task has 3 triggers (event, startup, periodic)'
    $rep = @($task.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval })
    Check ($rep.Count -eq 1 -and $rep[0].Repetition.Interval -eq "PT$($script:AuditWatcherIntervalMin)M") "periodic trigger every $($script:AuditWatcherIntervalMin) minutes (indefinite: Duration='$($rep[0].Repetition.Duration)')"
    $w = Get-AuditWatcherStatus
    Check ($w.UpToDate -eq $true) 'the installed copy in bin\ equals firewall.ps1'
    $binAcl = Get-Acl -LiteralPath (Get-AuditFile 'Bin')
    Check ($binAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in 'S-1-5-18', 'S-1-5-32-544') 'bin\ is owned by SYSTEM/Administrators'

    Step '3. Change made OUTSIDE the tool is picked up by the event trigger'
    [void](Invoke-AuditSync -Trigger manual -Quiet)     # known-good baseline first
    New-NetFirewallRule -DisplayName $nameExt -Direction Inbound -Action Block -Protocol TCP -LocalPort 59999 | Out-Null
    $rid = (Get-NetFirewallRule -DisplayName $nameExt).Name
    Info "waiting up to $WaitSeconds s for the watcher (rule id $rid)..."
    $add = Wait-AuditChange -RuleId $rid -Op 'Added' -Seconds $WaitSeconds
    Check ($null -ne $add) 'the external Add was logged without anybody pressing a button'
    if ($add) {
        Check ($add.source -eq 'external') "source = external (was: $($add.source))"
        Check ($add.detection -in 'watcher', 'reconcile') "detection = $($add.detection)"
        $who = $add.actor
        if ($who -and $who.evidence -in 'eventlog', 'process') { Check $true "the WHO was recovered: $($who.user) via $($who.application) (evidence: $($who.evidence))" }
        else { Info "no actor evidence ('who' unknown). Is the firewall event log enabled? auditpol /get /subcategory:""MPSSVC Rule-Level Policy Change""" }
    }
    Remove-NetFirewallRule -Name $rid
    $del = Wait-AuditChange -RuleId $rid -Op 'Removed' -Seconds $WaitSeconds
    Check ($null -ne $del) 'the external Remove was logged and keeps the old rule contents'

    Step '4. Periodic / manual task run writes state.json'
    $before = Read-AuditState
    Start-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName
    $until = (Get-Date).AddSeconds(90); $st = $null
    do {
        Start-Sleep -Seconds 3
        $st = Read-AuditState
    } while ((Get-Date) -lt $until -and (-not $st -or ($before -and [string]$st.finished -eq [string]$before.finished)))
    Check ($st -and $st.status -eq 'ok') 'a task run finished and state.json says ok'
    Check ((Get-AuditWatcherHealth -State $st).Health -eq 'Healthy') 'watcher health = Healthy'

    Step '5. Fail-open with an unwritable log'
    $fs = New-Object IO.FileStream((Get-AuditFile 'Log'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $refused = $false
    try {
        try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Reason 'acceptance closed' -Action { New-NetFirewallRule -DisplayName "$nameOpen-closed" -Direction Inbound -Action Block | Out-Null } | Out-Null }
        catch { $refused = $_.Exception.Message -match 'NOT performed' }
        $res = Invoke-AuditedChange -Operation 'Add' -Scope NewRules -FailPolicy Open -Reason 'acceptance open' -WarningAction SilentlyContinue -Action {
            New-NetFirewallRule -DisplayName $nameOpen -Direction Inbound -Action Block | Out-Null }
    } finally { $fs.Dispose() }
    Check $refused 'Closed: the change was refused while the log was locked'
    Check ($res.FailOpen -and (Get-NetFirewallRule -DisplayName $nameOpen -ErrorAction SilentlyContinue)) 'Open: the change was performed'
    $sum = Invoke-AuditSync -Trigger manual -Quiet
    Check ($sum.Pending -ge 1) 'the next sync consumed the pending marker'
    $oid = (Get-NetFirewallRule -DisplayName $nameOpen).Name
    $logged = Wait-AuditChange -RuleId $oid -Op 'Added' -Seconds 30
    Check ($null -ne $logged) 'the fail-open change was reconciled into the log'

    Step '6. Hash chain'
    $ver = Test-AuditLogIntegrity -Quiet
    Check $ver.Ok 'the audit chain verifies after all of the above'
    $head = Get-AuditHeadHash
    Info "head hash (store it off this machine): $($head.Text)"
}
finally {
    Step 'Cleanup'
    foreach ($n in $nameExt, $nameOpen, "$nameOpen-closed") {
        Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    try { [void](Invoke-AuditSync -Trigger manual -Quiet) } catch { Info "final sync failed: $($_.Exception.Message)" }
    if (-not $KeepWatcher) {
        try { [void](Invoke-AuditedChange -Operation 'WatcherUninstall' -Scope Names -Names @() -Reason 'acceptance test cleanup' -Action { Uninstall-AuditWatcher }) }
        catch { Info "watcher uninstall failed: $($_.Exception.Message)" }
    }
    Write-Host ''
    if ($script:Fail -eq 0) { Write-Host 'ACCEPTANCE: all checks passed.' -ForegroundColor Green } else { Write-Host "ACCEPTANCE: $($script:Fail) check(s) FAILED." -ForegroundColor Red }
}
if ($script:Fail -gt 0) { exit 1 }
