<#
.SYNOPSIS
    Self-contained tests of the audit module embedded in firewall.ps1.

.DESCRIPTION
    Does NOT touch the real firewall policy and does not need administrator rights:
    the audit region is extracted from firewall.ps1 and pointed at
      * a temporary directory instead of C:\ProgramData\FirewallAudit,
      * a fake FirewallPolicy registry tree under HKCU instead of the real one,
      * a private mutex name.
    Run:  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-FirewallAudit.ps1
#>
param([string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'firewall.ps1'))

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0
function Assert {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passed++; Write-Host "  [ok]   $Message" -ForegroundColor DarkGreen }
    else { $script:Failed++; Write-Host "  [FAIL] $Message" -ForegroundColor Red }
}
function Section { param([string]$Name) Write-Host "`n== $Name" -ForegroundColor Cyan }

# ---- load the audit region from the script under test -----------------------------------
$text = [IO.File]::ReadAllText($ScriptPath)
$m = [regex]::Match($text, '(?s)#region AUDIT\r?\n.*?#endregion AUDIT')
if (-not $m.Success) { throw 'AUDIT region not found' }
. ([scriptblock]::Create($m.Value))

# ---- sandbox ---------------------------------------------------------------------------
$suffix = [guid]::NewGuid().ToString('N')
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) "FwAuditTest-$suffix"
$regRoot = "Software\FwAuditTest-$suffix"
$regPolicy = "$regRoot\FirewallPolicy"
$script:AuditDir = $tmpDir
$script:AuditMutexName = "Local\FwAuditTest-$suffix"
$script:AuditPolicyHive = [Microsoft.Win32.Registry]::CurrentUser
$script:AuditPolicyPath = $regPolicy
$script:AuditSelfPath = $ScriptPath

function New-FakeRegistry {
    $hive = [Microsoft.Win32.Registry]::CurrentUser
    $hive.CreateSubKey("$regPolicy\FirewallRules").Close()
    foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile') {
        $k = $hive.CreateSubKey("$regPolicy\$p")
        $k.SetValue('EnableFirewall', 1, 'DWord'); $k.SetValue('DisableNotifications', 0, 'DWord'); $k.Close()
        $l = $hive.CreateSubKey("$regPolicy\$p\Logging")
        $l.SetValue('LogFileSize', 4096, 'DWord'); $l.SetValue('LogDroppedPackets', 0, 'DWord'); $l.Close()
    }
}
function Set-FakeRule {
    param([string]$Id, [string]$Raw)
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$regPolicy\FirewallRules", $true)
    $k.SetValue($Id, $Raw, 'String'); $k.Close()
}
function Remove-FakeRule {
    param([string]$Id)
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$regPolicy\FirewallRules", $true)
    $k.DeleteValue($Id); $k.Close()
}
function Set-FakeProfileValue {
    param([string]$Profile, [string]$Name, $Value)
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$regPolicy\$Profile", $true)
    $k.SetValue($Name, $Value, 'DWord'); $k.Close()
}
function Get-LogRecords { @(Read-AuditRecords) }
function Reset-Sandbox {
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    $script:AuditTailCache = $null
    $script:AuditLockDepth = 0
    $hive = [Microsoft.Win32.Registry]::CurrentUser
    try { $hive.DeleteSubKeyTree($regRoot) } catch { }
    New-FakeRegistry
}

$ruleA = 'v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=80|RA4=1.2.3.4|Name=01-OSO-Allow-Inbound-120000|Desc=test|'
$ruleB = 'v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort=53|RA4=8.8.8.8|RA6=2001:db8::1|Name=02-OSO-Block-Outbound-120001|'

try {
    # ---------------------------------------------------------------------------------
    Section 'Rule string parser and normalisation'
    $e = ConvertFrom-AuditRuleString 'v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|Profile=Domain|RPort=2869|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=fdphost|Name=@FirewallAPI.dll,-32765|Desc=a|b|EmbedCtxt=@FirewallAPI.dll,-32752|Edge=TRUE|'
    Assert ($e.enabled -eq $false) 'Active=FALSE -> enabled=false'
    Assert ($e.direction -eq 'Outbound') 'Dir=Out -> Outbound'
    Assert ($e.protocol -eq 'TCP') 'Protocol=6 -> TCP'
    Assert ((@($e.profile) -join ',') -eq 'Domain,Public') 'repeated Profile keys -> sorted list'
    Assert ((@($e.localPort) -join ',') -eq 'Any') 'missing LPort -> Any'
    Assert ($e.program -eq '%SystemRoot%\system32\svchost.exe') 'environment variables are not expanded'
    Assert ($e.description -eq 'a|b') "'|' inside a value is glued back"
    Assert ($e.edge -eq 'TRUE') 'unknown keys are kept (generic)'

    Section 'Compare-PolicySnapshot'
    $a = [ordered]@{ 'rule:1' = (ConvertFrom-AuditRuleString $ruleA) }
    $b = [ordered]@{ 'rule:1' = (ConvertFrom-AuditRuleString ($ruleA -replace 'Profile=Public\|Profile=Private', 'Profile=private|Profile=PUBLIC')) }
    Assert (@(Compare-PolicySnapshot $a $b).Count -eq 0) 'order and case of list items do not create a diff'
    $c = [ordered]@{ 'rule:1' = (ConvertFrom-AuditRuleString ($ruleA -replace 'LPort=80', 'LPort=8080')) }
    $d = @(Compare-PolicySnapshot $a $c)
    Assert ($d.Count -eq 1 -and $d[0].Op -eq 'Modified' -and $d[0].Changes[0].field -eq 'localPort') 'port change -> Modified/localPort'
    $d = @(Compare-PolicySnapshot $a ([ordered]@{}))
    Assert ($d.Count -eq 1 -and $d[0].Op -eq 'Removed') 'missing in after -> Removed'
    $d = @(Compare-PolicySnapshot ([ordered]@{}) $a)
    Assert ($d.Count -eq 1 -and $d[0].Op -eq 'Added') 'missing in before -> Added'

    # ---------------------------------------------------------------------------------
    Section 'Hash chain, tamper detection, torn writes'
    Reset-Sandbox
    for ($i = 1; $i -le 5; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = $i; text = "line`nbreak `"quote`" <tag> & 'x'" })) }
    $r = Test-AuditLogIntegrity -Quiet
    Assert ($r.Ok -and $r.Records -eq 5 -and $r.LastSeq -eq 5) 'fresh chain of 5 records verifies'
    Assert ((Get-LogRecords).Count -eq 5 -and (Get-Content (Get-AuditFile Log)).Count -eq 5) 'newline/quotes inside values stay on ONE line'
    $bytes = [IO.File]::ReadAllBytes((Get-AuditFile Log))
    Assert ($bytes[0] -ne 0xEF) 'log is UTF-8 without BOM'

    $log = Get-AuditFile Log
    $orig = [IO.File]::ReadAllLines($log)
    [IO.File]::WriteAllLines($log, @($orig[0], $orig[1], ($orig[2] -replace '"n":3', '"n":9'), $orig[3], $orig[4]))
    $r = Test-AuditLogIntegrity -Quiet
    Assert (-not $r.Ok -and ($r.Errors -join ';') -match 'hash mismatch') 'edited record is detected'
    [IO.File]::WriteAllLines($log, @($orig[0], $orig[1], $orig[3], $orig[4]))
    $r = Test-AuditLogIntegrity -Quiet
    Assert (-not $r.Ok -and ($r.Errors -join ';') -match 'chain broken') 'removed record is detected'
    [IO.File]::WriteAllLines($log, @($orig[0], $orig[2], $orig[1], $orig[3], $orig[4]))
    $r = Test-AuditLogIntegrity -Quiet
    Assert (-not $r.Ok) 'reordered records are detected'
    [IO.File]::WriteAllLines($log, $orig)

    # torn write: half a line without newline at the end
    [IO.File]::AppendAllText($log, '{"v":1,"seq":6,"ts":"2026-01-01T00:00:00.0000000Z","type":"info","tr', $script:AuditUtf8)
    $script:AuditTailCache = $null
    $r = Test-AuditLogIntegrity -Quiet
    Assert (-not $r.Ok) 'torn line is reported by verification'
    [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = 6 }))
    $recs = Get-LogRecords
    Assert ($recs[-2].type -eq 'integrity' -and $recs[-2].issue -eq 'torn-write') 'writer records a torn-write integrity record and continues the chain'
    Assert ((Get-Content $log)[-1] -match '"n":6') 'new record starts on its own line after the torn one'

    # ---------------------------------------------------------------------------------
    Section 'Rotation keeps the chain continuous'
    Reset-Sandbox
    $script:AuditMaxBytes = 3000
    for ($i = 1; $i -le 30; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = $i; pad = ('x' * 120) })) }
    $files = @(Get-AuditFiles)
    Assert ($files.Count -ge 3) "log rotated into $($files.Count) files"
    $r = Test-AuditLogIntegrity -Quiet
    Assert ($r.Ok -and $r.Records -ge 30) 'chain verifies across rotated files'
    $first = ConvertFrom-AuditLine ((Get-Content $files[-1])[0])
    Assert ($first.Obj.type -eq 'rotation') 'first record of the live file is a rotation record'
    Remove-Item $files[1]
    $r = Test-AuditLogIntegrity -Quiet
    Assert (-not $r.Ok -and ($r.Errors -join ';') -match 'file boundary') 'a missing rotated file is detected'
    $script:AuditMaxBytes = 10MB

    # ---------------------------------------------------------------------------------
    Section 'Invoke-AuditedChange: Add (NewRules), Remove (Names), failure, write-ahead'
    Reset-Sandbox
    Set-FakeRule 'existing-1' $ruleB
    $res = Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Reason 'test add' -Action { Set-FakeRule 'new-1' $ruleA }
    Assert ($res.Added -eq 1 -and $res.Removed -eq 0) 'Add detected as exactly one Added'
    $recs = Get-LogRecords
    $types = ($recs | ForEach-Object { $_.type }) -join ','
    Assert ($types -eq 'baseline,intent,change,result') "record order: $types"
    $ch = $recs | Where-Object type -eq 'change'
    Assert ($ch.op -eq 'Added' -and $ch.ruleId -eq 'new-1' -and $ch.source -eq 'oso' -and $ch.detection -eq 'script') 'change record: op/ruleId/source/detection'
    Assert ($ch.after.displayName -eq '01-OSO-Allow-Inbound-120000' -and $null -eq $ch.before) 'change record carries the full after-snapshot'
    Assert ($ch.actor.user -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name) 'actor = current Windows identity'
    $intent = $recs | Where-Object type -eq 'intent'; $result = $recs | Where-Object type -eq 'result'
    Assert ($intent.txid -eq $ch.txid -and $ch.txid -eq $result.txid) 'intent/change/result share one txid'
    Assert ($result.status -eq 'success' -and $result.counts.added -eq 1) 'result: success, counts.added=1'

    $sync = Invoke-AuditSync -Trigger startup -Quiet
    Assert (($sync.Added + $sync.Removed + $sync.Modified) -eq 0) 'sync right after an audited change finds nothing (no duplicate)'

    $res = Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @('new-1') -Details @{ expectedDisplayName = 'something else' } -Action { Remove-FakeRule 'new-1' }
    $recs = Get-LogRecords
    $ch = @($recs | Where-Object { $_.type -eq 'change' })[-1]
    Assert ($ch.op -eq 'Removed' -and $ch.before.displayName -eq '01-OSO-Allow-Inbound-120000' -and $null -eq $ch.after) 'Remove keeps the full before-snapshot'
    $in = @($recs | Where-Object type -eq 'intent')[-1]
    Assert (@($in.warnings).Count -eq 1 -and $in.warnings[0] -match 'changed since it was listed') 'TOCTOU: listed name differs -> warning in intent'

    $threw = $false
    try { Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @('does-not-exist') -Action { throw 'boom' } | Out-Null } catch { $threw = ($_.Exception.Message -eq 'boom') }
    Assert $threw 'Action error is re-thrown to the caller'
    $result = @(Get-LogRecords | Where-Object type -eq 'result')[-1]
    Assert ($result.status -eq 'failed' -and $result.error -eq 'boom') 'failed action -> result.status=failed with the error'

    # partial success: action creates one rule and then fails -> the REAL change is still logged
    try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { Set-FakeRule 'half-1' $ruleA; throw 'late failure' } | Out-Null } catch { }
    $recs = Get-LogRecords
    Assert ((@($recs | Where-Object { $_.type -eq 'change' -and $_.ruleId -eq 'half-1' }).Count -eq 1) -and (@($recs | Where-Object type -eq 'result')[-1].status -eq 'failed')) 'partial success: real change logged, result=failed'

    # write-ahead: log unavailable -> change must NOT happen
    $script:AuditTailCache = $null
    $lock = New-Object IO.FileStream((Get-AuditFile Log), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $ran = $false; $msg = ''
    try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { $script:ran = $true; Set-FakeRule 'blocked-1' $ruleA } | Out-Null } catch { $msg = $_.Exception.Message }
    $lock.Dispose()
    $script:AuditTailCache = $null
    Assert ((-not $ran) -and $msg -match 'NOT performed') 'unwritable log -> Action not executed (fail-closed)'
    Assert ((Get-PolicySnapshot -Scope Names -Names @('blocked-1')).Count -eq 0) 'policy unchanged after the refused change'

    # ---------------------------------------------------------------------------------
    Section 'Invoke-AuditSync: changes made behind the tool'
    Reset-Sandbox
    Set-FakeRule 'keep-1' $ruleA; Set-FakeRule 'del-1' $ruleB; Set-FakeRule 'mod-1' $ruleB
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert ($s.Created) 'first sync creates the baseline'
    Set-FakeRule 'ext-1' $ruleA                                          # added
    Remove-FakeRule 'del-1'                                              # removed
    Set-FakeRule 'mod-1' ($ruleB -replace 'Action=Block', 'Action=Allow') # modified
    Set-FakeProfileValue 'PublicProfile' 'EnableFirewall' 0              # profile setting
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert ($s.Added -eq 1 -and $s.Removed -eq 1 -and $s.Modified -eq 2) "sync: +$($s.Added) -$($s.Removed) ~$($s.Modified) (expected +1 -1 ~2)"
    $ch = @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.detection -eq 'reconcile' })
    Assert ($ch.Count -eq 4 -and (@($ch | Where-Object source -eq 'external').Count -eq 4)) 'four change records, source=external, detection=reconcile'
    $pm = $ch | Where-Object { $_.kind -eq 'profile' }
    Assert ($pm.profile -eq 'Public' -and $pm.changes[0].field -eq 'enableFirewall' -and "$($pm.changes[0].from)" -eq '1' -and "$($pm.changes[0].to)" -eq '0') 'profile setting change: Public/enableFirewall 1 -> 0'
    $mm = $ch | Where-Object { $_.ruleId -eq 'mod-1' }
    Assert ($mm.changes.Count -eq 1 -and $mm.changes[0].field -eq 'action') 'rule modification lists exactly the changed field'
    Assert ($ch[0].actor.user -eq 'unknown' -and $ch[0].actor.evidence -ne 'eventlog') 'no event-log evidence -> actor unknown (with time window)'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert (($s.Added + $s.Removed + $s.Modified) -eq 0) 'second sync finds nothing'
    $s = Invoke-AuditSync -Trigger task -Quiet
    $syncRecs = @(Get-LogRecords | Where-Object type -eq 'sync')
    Assert ($syncRecs.Count -eq 2) 'task/startup syncs with no changes stay silent; manual ones leave a sync record'

    Section 'Drift is logged BEFORE our own change (detection=pre-change)'
    Set-FakeRule 'mod-1' ($ruleB -replace 'RPort=53', 'RPort=5353')      # external edit, not yet synced
    [void](Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @('mod-1') -Action { Remove-FakeRule 'mod-1' })
    $recs = Get-LogRecords
    $pre = @($recs | Where-Object { $_.detection -eq 'pre-change' })
    $own = @($recs | Where-Object { $_.detection -eq 'script' })[-1]
    Assert ($pre.Count -eq 1 -and $pre[0].op -eq 'Modified' -and $pre[0].source -eq 'external') 'external edit found before the audited Remove'
    Assert ($own.op -eq 'Removed' -and $own.before.remotePort -contains '5353') 'audited Remove sees (and logs) the edited state'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert (($s.Added + $s.Removed + $s.Modified) -eq 0) 'nothing left for the next sync'

    Section 'Interrupted operation (intent without result) is recovered'
    [void](Write-AuditRecord -Type 'intent' -TxId 'dead-tx' -Fields ([ordered]@{ operation = 'Add'; scope = 'NewRules'; names = @() }))
    Set-FakeRule 'orphan-1' $ruleA
    $s = Invoke-AuditSync -Trigger startup -Quiet
    $recs = Get-LogRecords
    $rec = @($recs | Where-Object { $_.type -eq 'result' -and $_.txid -eq 'dead-tx' })
    $ch = @($recs | Where-Object { $_.ruleId -eq 'orphan-1' })
    Assert ($s.Recovered -eq 1 -and $rec.Count -eq 1 -and $rec[0].status -eq 'recovered') 'dangling intent closed with status=recovered'
    Assert ($ch.Count -eq 1 -and $ch[0].relatedTxids -contains 'dead-tx') 'the real change is recorded and linked to the interrupted transaction'
    $s = Invoke-AuditSync -Trigger startup -Quiet
    Assert ($s.Recovered -eq 0) 'a recovered intent is not recovered twice'

    Section 'Baseline tampering'
    $bp = Get-AuditFile Baseline
    $json = [IO.File]::ReadAllText($bp)
    [IO.File]::WriteAllText($bp, $json.Replace('orphan-1', 'orphan-X'))
    $s = Invoke-AuditSync -Trigger manual -Quiet
    $integ = @(Get-LogRecords | Where-Object type -eq 'integrity')
    Assert (@($integ | Where-Object issue -eq 'baseline-log-mismatch').Count -ge 1 -and @($integ | Where-Object issue -eq 'baseline-file-modified').Count -ge 1) 'edited baseline.json -> integrity records (file hash + log hash)'
    [IO.File]::WriteAllText($bp, '{not json')
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert ($s.Created) 'corrupt baseline is rebuilt'
    Assert ((Test-AuditLogIntegrity -Quiet).Ok) 'log chain still intact after all of the above'

    # ---------------------------------------------------------------------------------
    Section 'Attribution from the Windows event log (mocked index) and source tagging'
    Reset-Sandbox
    Set-FakeRule 'ev-add' $ruleA; Set-FakeRule 'ev-del' $ruleB
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Set-FakeRule 'ev-new' $ruleA; Remove-FakeRule 'ev-del'
    $origEventIndex = ${function:Get-AuditEventIndex}
    function Get-AuditEventIndex {
        param([DateTime]$Since)
        $idx = [pscustomobject]@{ Available = $true; Rules = @{}; AllDeleted = @(); Settings = @() }
        $idx.Rules['ev-new'] = @([pscustomobject]@{ Id = 2097; Kind = 'Added'; Time = [DateTime]::UtcNow; RuleId = 'ev-new'; Sid = 'S-1-5-18'; App = "$env:SystemRoot\System32\svchost.exe" })
        $idx.Rules['ev-del'] = @([pscustomobject]@{ Id = 2052; Kind = 'Deleted'; Time = [DateTime]::UtcNow; RuleId = 'ev-del'; Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; App = "$env:SystemRoot\System32\mmc.exe" })
        return $idx
    }
    [void](Invoke-AuditSync -Trigger task -Quiet)
    $ch = @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.detection -eq 'watcher' })
    $n = $ch | Where-Object ruleId -eq 'ev-new'; $dl = $ch | Where-Object ruleId -eq 'ev-del'
    Assert ($n.actor.evidence -eq 'eventlog' -and $n.actor.sid -eq 'S-1-5-18' -and $n.source -eq 'system') 'SYSTEM + Windows binary -> source=system, actor from event'
    Assert ($dl.actor.evidence -eq 'eventlog' -and $dl.source -eq 'external') 'ordinary user + mmc.exe -> source=external, actor from event'
    Assert ($dl.actor.user -ne 'unknown') 'SID resolved to an account name'
    Set-Item function:\Get-AuditEventIndex $origEventIndex
    $real = Get-AuditEventIndex -Since ([DateTime]::UtcNow.AddHours(-1))
    Assert ($null -ne $real) 'real Get-AuditEventIndex runs against the live event log without error'

    # ---------------------------------------------------------------------------------
    Section 'Two processes writing at once (mutex)'
    Reset-Sandbox
    $jobs = 1..2 | ForEach-Object {
        Start-Job -ArgumentList $m.Value, $tmpDir, $script:AuditMutexName, $_ -ScriptBlock {
            param($region, $dir, $mutex, $who)
            . ([scriptblock]::Create($region))
            $script:AuditDir = $dir; $script:AuditMutexName = $mutex
            for ($i = 1; $i -le 25; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ who = $who; n = $i })) }
        }
    }
    $jobs | Wait-Job -Timeout 120 | Out-Null
    $jobs | ForEach-Object { if ($_.State -ne 'Completed') { Write-Host ($_ | Receive-Job 2>&1 | Out-String) } }
    $jobs | Remove-Job -Force
    $script:AuditTailCache = $null
    $r = Test-AuditLogIntegrity -Quiet
    Assert ($r.Ok -and $r.Records -eq 50 -and $r.LastSeq -eq 50) "50 records from 2 processes: contiguous seq, intact chain ($($r.Errors -join '; '))"

    # ---------------------------------------------------------------------------------
    Section 'Live (read-only) snapshot of the real policy store'
    $script:AuditPolicyHive = [Microsoft.Win32.Registry]::LocalMachine
    $script:AuditPolicyPath = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    $raws = @{}
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $snap = Get-PolicySnapshot -Scope All -RawSink $raws
    $msFull = $sw.ElapsedMilliseconds
    Assert ($snap.Count -gt 10) "real snapshot (parse everything): $($snap.Count) objects in $msFull ms"
    $rawOrdered = [ordered]@{}
    foreach ($k in ($raws.Keys | Sort-Object)) { $rawOrdered[$k] = $raws[$k] }
    $h1 = Get-AuditBaselineHash -Entries $snap -Raws $rawOrdered
    Assert ($h1 -match '^[0-9a-f]{64}$') 'baseline hash computed'
    Reset-Sandbox
    $script:AuditPolicyHive = [Microsoft.Win32.Registry]::LocalMachine
    $script:AuditPolicyPath = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    Initialize-AuditStore
    Save-AuditBaseline -Entries $snap -Raws $rawOrdered -Hash $h1 -Ts ([DateTime]::UtcNow)
    $back = Read-AuditBaseline
    Assert ((Get-AuditBaselineHash -Entries $back.Entries -Raws $back.Raws) -eq $h1) 'baseline JSON round trip keeps the hash (serialisation is stable)'
    $sw.Restart()
    $raws2 = @{}
    $snap2 = Get-PolicySnapshot -Scope All -RawSink $raws2 -Reuse $back
    $msReuse = $sw.ElapsedMilliseconds
    $sw.Restart()
    $diff = @(Compare-PolicySnapshot $back.Entries $snap2)
    $msCmp = $sw.ElapsedMilliseconds
    Assert ($diff.Count -eq 0) "unchanged policy: zero diff (snapshot with reuse $msReuse ms, compare $msCmp ms)"
    Assert ($msReuse -lt ($msFull / 2) -or $msFull -lt 500) 'reuse of unchanged rules makes the snapshot much cheaper than a full parse'
}
finally {
    try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($regRoot) } catch { }
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host "`nPassed: $script:Passed   Failed: $script:Failed" -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 }
