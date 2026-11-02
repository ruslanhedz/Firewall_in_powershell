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
$regGpo = "$regRoot\GpoFirewall"
$script:AuditGpoPath = $regGpo
$script:AuditSelfPath = $ScriptPath
# the tests run as an ordinary user: that user plays the role of "Administrators" for the directory ACL
$mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:AuditTrustedExtra = @($mySid)
$isElevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

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
function Set-FakeRegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Kind = 'String')
    $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($Path)
    $k.SetValue($Name, $Value, $Kind); $k.Close()
}
function Remove-FakeRegValue {
    param([string]$Path, [string]$Name)
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path, $true)
    if ($k) { $k.DeleteValue($Name, $false); $k.Close() }
}
# Finds firewall-policy-changing commands that are NOT inside Invoke-AuditedChange (outside the AUDIT region).
function Find-UnauditedPolicyCalls {
    param([string]$Source)
    $tokens = $null; $errs = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$errs)
    $reg = [regex]::Match($Source, '(?s)#region AUDIT.*?#endregion AUDIT')
    $found = @()
    $cmds = $ast.FindAll({ param($a) $a -is [Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        $name = $c.GetCommandName()
        if (-not $name) { continue }
        $isPolicy = ($name -match '^(New|Set|Remove|Enable|Disable|Rename|Copy)-NetFirewall') -or
                    ($name -ieq 'netsh' -and $c.Extent.Text -match 'advfirewall')
        if (-not $isPolicy) { continue }
        if ($reg.Success -and $c.Extent.StartOffset -ge $reg.Index -and $c.Extent.StartOffset -lt ($reg.Index + $reg.Length)) { continue }
        $p = $c.Parent; $audited = $false
        while ($p) {
            if ($p -is [Management.Automation.Language.CommandAst] -and $p.GetCommandName() -eq 'Invoke-AuditedChange') { $audited = $true; break }
            $p = $p.Parent
        }
        if (-not $audited) { $found += "line $($c.Extent.StartLineNumber): $($c.Extent.Text)" }
    }
    return $found
}
function Get-LogRecords { @(Read-AuditRecords) }
function Reset-Sandbox {
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    $script:AuditTailCache = $null
    $script:AuditLockDepth = 0
    $script:AuditNotices = @()
    $script:AuditInInit = $false
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
    Section 'Coverage: connection security, Group Policy, generic settings, schema upgrade'
    Reset-Sandbox
    Set-FakeRegValue "$regPolicy\ConSecRules" 'cs-1' 'v2.33|Action=SecureOptional|Name=consec one|'
    Set-FakeRegValue $regPolicy 'PolicyVersion' 538 'DWord'
    Set-FakeRegValue "$regPolicy\Mdm\DomainProfile" 'EnableFirewall' 1 'DWord'
    Set-FakeRegValue "$regGpo\FirewallRules" 'g-1' $ruleA
    Set-FakeRegValue "$regGpo\DomainProfile" 'EnableFirewall' 1 'DWord'
    Set-FakeRegValue $regGpo 'PolicyVersion' 5 'DWord'
    $snap = Get-PolicySnapshot -Scope All
    foreach ($want in 'consec:cs-1', 'gporule:g-1', 'gpoprofile:Domain', 'setting:.', 'setting:Mdm\DomainProfile', 'gposetting:.', 'profile:Public') {
        Assert (Test-AuditKey $snap $want) "snapshot contains $want"
    }
    Assert (-not (Test-AuditKey $snap 'setting:FirewallRules') -and -not (Test-AuditKey $snap 'setting:DomainProfile')) 'families with their own handler are not walked twice'
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Set-FakeRegValue "$regGpo\DomainProfile" 'EnableFirewall' 0 'DWord'          # GPO switches the firewall off
    Set-FakeRegValue "$regPolicy\ConSecRules" 'cs-2' 'v2.33|Action=Secure|Name=consec two|'
    Set-FakeRegValue "$regPolicy\Mdm\DomainProfile" 'EnableFirewall' 0 'DWord'
    Set-FakeRegValue "$regPolicy\HyperVRules" 'h1' 'x'                          # a brand new subtree
    Set-FakeRegValue $regPolicy 'PolicyVersion' 539 'DWord'
    Set-FakeRegValue "$regGpo\FirewallRules" 'g-2' $ruleB
    Remove-FakeRegValue "$regGpo\FirewallRules" 'g-1'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    $ch = @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.detection -eq 'reconcile' })
    $byKind = @{}; foreach ($c in $ch) { $byKind["$($c.kind)/$($c.op)"] = $c }
    Assert ($s.Added -eq 3 -and $s.Removed -eq 1 -and $s.Modified -eq 3) "sync after changes in every family: +$($s.Added) -$($s.Removed) ~$($s.Modified) (expected +3 -1 ~3)"
    $gp = $byKind['gpo-profile/Modified']
    Assert ($gp -and $gp.profile -eq 'Domain' -and $gp.changes[0].field -eq 'enableFirewall' -and "$($gp.changes[0].to)" -eq '0') 'GPO profile EnableFirewall 1 -> 0 is logged (kind=gpo-profile)'
    Assert ($gp.source -eq 'gpo' -and $byKind['gpo-rule/Added'].source -eq 'gpo' -and $byKind['gpo-rule/Removed'].source -eq 'gpo') 'source=gpo comes from the key location'
    Assert ($byKind['consec/Added'].ruleId -eq 'cs-2' -and $byKind['consec/Added'].displayName -eq 'consec two') 'connection security rule added: kind=consec with name'
    Assert ($byKind['setting/Added'].path -eq 'HyperVRules' -and $byKind['setting/Modified'].path -in @('.', 'Mdm\DomainProfile')) 'generic subtrees: new key and changed value are logged with their path'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert (($s.Added + $s.Removed + $s.Modified) -eq 0) 'second sync finds nothing'

    # baseline of an older schema (rules + profiles only) is rebuilt without false 'Added' records
    $bp = Get-AuditFile Baseline
    $j = [IO.File]::ReadAllText($bp)
    Assert ($j.StartsWith('{"v":2')) 'baseline file carries schema version 2'
    [IO.File]::WriteAllText($bp, ('{"v":1' + $j.Substring(6)))
    $before = @(Get-LogRecords).Count
    $s = Invoke-AuditSync -Trigger startup -Quiet
    $new = @(Get-LogRecords | Select-Object -Skip $before)
    Assert ($s.Created -and (@($new | Where-Object type -eq 'change').Count -eq 0) -and (@($new | Where-Object type -eq 'integrity').Count -eq 0)) 'schema-v1 baseline: rebuilt, no change and no integrity records'
    Assert (@($new | Where-Object { $_.type -eq 'baseline' -and $_.reason -eq 'schema-upgrade' }).Count -eq 1) 'baseline record says reason=schema-upgrade'

    # ---------------------------------------------------------------------------------
    Section 'Scope escapes: the wrapper looks at the WHOLE policy'
    Reset-Sandbox
    Set-FakeRule 'a' $ruleA; Set-FakeRule 'b' $ruleB
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    $res = Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @('a') -Action {
        Remove-FakeRule 'a'
        Set-FakeRule 'b' ($ruleB -replace 'Action=Block', 'Action=Allow')     # touches a rule it did not declare
    }
    $recs = Get-LogRecords
    $ca = @($recs | Where-Object { $_.type -eq 'change' -and $_.ruleId -eq 'a' })[-1]
    $cb = @($recs | Where-Object { $_.type -eq 'change' -and $_.ruleId -eq 'b' })[-1]
    Assert ($ca.detection -eq 'script' -and $ca.source -eq 'oso' -and -not $ca.attribution) 'declared change: detection=script'
    Assert ($cb.detection -eq 'scope-escape' -and $cb.source -eq 'oso' -and $cb.attribution -eq 'inferred-window' -and $cb.actor.evidence -eq 'process') 'undeclared change: scope-escape, attributed to the script by time window'
    $rs = @($recs | Where-Object type -eq 'result')[-1]
    Assert ($rs.counts.scopeEscapes -eq 1 -and @($rs.warnings).Count -eq 1 -and @($res.Warnings).Count -ge 1) 'result and return value carry the scope warning'
    [void](Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { Set-FakeRule 'c' $ruleA })
    [void](Invoke-AuditedChange -Operation 'Set' -Scope Profiles -Action { Set-FakeProfileValue 'PublicProfile' 'EnableFirewall' 0 })
    $recs = Get-LogRecords
    Assert (@($recs | Where-Object detection -eq 'scope-escape').Count -eq 1) 'correctly declared NewRules / Profiles produce no scope-escape'
    [void](Invoke-AuditedChange -Operation 'Set' -Scope Profiles -Action { Set-FakeProfileValue 'DomainProfile' 'EnableFirewall' 0; Set-FakeRule 'd' $ruleA })
    $esc = @(Get-LogRecords | Where-Object detection -eq 'scope-escape')
    Assert ($esc.Count -eq 2 -and $esc[-1].ruleId -eq 'd') 'a rule added inside a Profiles action is an escape'
    Set-FakeRule 'b' ($ruleB -replace 'RPort=53', 'RPort=5454')                 # external edit, outside the scope
    [void](Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @('c') -Action { Remove-FakeRule 'c' })
    $recs = Get-LogRecords
    $pre = @($recs | Where-Object { $_.detection -eq 'pre-change' -and $_.ruleId -eq 'b' })
    Assert ($pre.Count -eq 1 -and $pre[0].source -eq 'external' -and @($recs | Where-Object detection -eq 'scope-escape').Count -eq 2) 'drift outside the declared scope is pre-change/external, not a scope-escape'

    Section 'Contract: every policy change in firewall.ps1 goes through Invoke-AuditedChange'
    $bad = @(Find-UnauditedPolicyCalls $text)
    Assert ($bad.Count -eq 0) "no unaudited policy-changing command outside the AUDIT region ($($bad -join '; '))"
    Assert (@(Find-UnauditedPolicyCalls 'New-NetFirewallRule -DisplayName x').Count -eq 1) 'detector flags a direct New-NetFirewallRule'
    Assert (@(Find-UnauditedPolicyCalls 'netsh advfirewall set allprofiles state off').Count -eq 1) 'detector flags netsh advfirewall'
    Assert (@(Find-UnauditedPolicyCalls 'Invoke-AuditedChange -Operation Add -Scope NewRules -Action { New-NetFirewallRule -DisplayName x }').Count -eq 0) 'detector accepts a call inside the wrapper action'
    Assert (@(Find-UnauditedPolicyCalls 'Get-NetFirewallRule | Out-Null').Count -eq 0) 'read-only cmdlets are not flagged'

    # ---------------------------------------------------------------------------------
    Section 'Source labels: no spoofing by name, allow-listed system apps, low-confidence bulk delete'
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $item = [pscustomobject]@{ Key = 'rule:x'; Before = $null; After = [ordered]@{ displayName = '@FirewallAPI.dll,-1' } }
    $cases = @(
        @{ sid = 'S-1-5-18'; app = "$sys32\svchost.exe"; exp = 'system'; why = 'SYSTEM + svchost.exe -> system' }
        @{ sid = 'S-1-5-18'; app = "$sys32\WindowsPowerShell\v1.0\powershell.exe"; exp = 'external'; why = 'SYSTEM + powershell.exe -> external' }
        @{ sid = 'S-1-5-18'; app = "$sys32\netsh.exe"; exp = 'external'; why = 'SYSTEM + netsh.exe -> external' }
        @{ sid = 'S-1-5-18'; app = 'C:\Temp\svchost.exe'; exp = 'external'; why = 'SYSTEM + svchost.exe from a user folder -> external' }
        @{ sid = 'S-1-5-21-1-2-3-1001'; app = "$sys32\mmc.exe"; exp = 'external'; why = 'ordinary user + mmc.exe -> external' }
        @{ sid = 'S-1-5-21-1-2-3-1001'; app = "$sys32\svchost.exe"; exp = 'external'; why = 'ordinary user via WMI service host -> external' }
    )
    foreach ($c in $cases) {
        $a = [ordered]@{ evidence = 'eventlog'; sid = $c.sid; application = $c.app }
        Assert ((Get-AuditChangeSource $item $a) -eq $c.exp) $c.why
    }
    $noEv = [ordered]@{ evidence = 'none'; user = 'unknown' }
    Assert ((Get-AuditChangeSource $item $noEv) -eq 'external') "name like '@FirewallAPI.dll,-1' without evidence is NOT system"
    Assert ((Get-AuditChangeSource ([pscustomobject]@{ Key = 'gporule:x'; After = [ordered]@{} }) $noEv) -eq 'gpo') 'Group Policy key -> gpo'
    Reset-Sandbox
    Set-FakeRule 'sp-1' ($ruleA -replace 'Name=[^|]*', 'Name=@evil-rule')
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Set-FakeRule 'sp-2' ($ruleA -replace 'Name=[^|]*', 'Name=@FirewallAPI.dll,-80200')
    Set-FakeRule 'sp-3' ($ruleA -replace 'Name=[^|]*', 'Name=another')
    Remove-FakeRule 'sp-1'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    $ch = @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.detection -eq 'reconcile' })
    Assert ($ch.Count -eq 3 -and @($ch | Where-Object { $_.source -ne 'external' }).Count -eq 0) "rules named like resource strings are 'external' without evidence"
    Reset-Sandbox
    Set-FakeRule 'bd-1' $ruleA; Set-FakeRule 'bd-2' $ruleB
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Remove-FakeRule 'bd-1'; Remove-FakeRule 'bd-2'
    $origEventIndex = ${function:Get-AuditEventIndex}
    function Get-AuditEventIndex {
        param([DateTime]$Since)
        $idx = [pscustomobject]@{ Available = $true; Rules = @{}; AllDeleted = @(); Settings = @() }
        $idx.AllDeleted = @([pscustomobject]@{ Id = 2059; Kind = 'AllDeleted'; Time = [DateTime]::UtcNow; RuleId = $null; Sid = 'S-1-5-18'; App = "$env:SystemRoot\System32\svchost.exe" })
        return $idx
    }
    [void](Invoke-AuditSync -Trigger task -Quiet)
    Set-Item function:\Get-AuditEventIndex $origEventIndex
    $ch = @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.detection -eq 'watcher' })
    Assert ($ch.Count -eq 2 -and @($ch | Where-Object { $_.actor.evidence -eq 'bulk-delete-correlation' -and $_.actor.confidence -eq 'low' -and $_.source -eq 'external' }).Count -eq 2) 'bulk "delete all" event: evidence=bulk-delete-correlation, confidence=low, never source=system'

    # ---------------------------------------------------------------------------------
    Section 'Audit directory: protected ACL, pre-created directory, planted files'
    Reset-Sandbox
    Initialize-AuditStore
    $di = New-Object IO.DirectoryInfo($tmpDir)
    $acl = $di.GetAccessControl()
    Assert ((Test-AuditDirSecurity -Acl $acl).Ok) 'a directory created by the module passes its own check'
    Assert ($acl.AreAccessRulesProtected) 'the new directory does not inherit the permissive ProgramData ACL'
    $aceSids = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value })
    Assert (($aceSids -contains 'S-1-5-18') -and ($aceSids -contains 'S-1-5-32-544') -and -not ($aceSids -contains 'S-1-5-32-545')) 'explicit ACEs: SYSTEM + Administrators, no Users'

    $sidSystem = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $sidUsers = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $sidEveryone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    function New-TestAcl {
        param($Owner, $Sid, $Rights, $Type = 'Allow')
        $a = New-Object Security.AccessControl.DirectorySecurity
        $a.SetOwner($Owner)
        if ($Sid) {
            $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Sid, $Rights, 'ContainerInherit, ObjectInherit', 'None', $Type)))
        }
        return $a
    }
    $r1 = Test-AuditDirSecurity -Acl (New-TestAcl $sidSystem $sidUsers 'Modify')
    Assert ((-not $r1.Ok) -and $r1.OwnerTrusted -and ($r1.Issues -join ';') -match 'S-1-5-32-545') 'Users:Modify is flagged'
    Assert ((Test-AuditDirSecurity -Acl (New-TestAcl $sidSystem $sidUsers 'ReadAndExecute')).Ok) 'Users:ReadAndExecute is acceptable'
    Assert (-not (Test-AuditDirSecurity -Acl (New-TestAcl $sidSystem $sidUsers 'CreateFiles')).Ok) 'Users:CreateFiles (the ProgramData default) is flagged'
    Assert (-not (Test-AuditDirSecurity -Acl (New-TestAcl $sidSystem $sidEveryone 'Delete')).Ok) 'Everyone:Delete is flagged'
    Assert ((Test-AuditDirSecurity -Acl (New-TestAcl $sidSystem $sidUsers 'FullControl' 'Deny')).Ok) 'deny entries are not treated as grants'
    $r2 = Test-AuditDirSecurity -Acl (New-TestAcl $sidUsers $null $null)
    Assert ((-not $r2.Ok) -and (-not $r2.OwnerTrusted) -and $r2.Owner -eq 'S-1-5-32-545') 'a directory owned by Users is not trusted'

    # a directory that already exists with a bad ACL is repaired and the repair is logged
    Reset-Sandbox
    [void](New-Item -ItemType Directory -Path $tmpDir)
    $di = New-Object IO.DirectoryInfo($tmpDir)
    $acl = $di.GetAccessControl()
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sidUsers, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    $di.SetAccessControl($acl)
    Assert (-not (Test-AuditDirSecurity -Acl $di.GetAccessControl()).Ok) 'precondition: pre-created directory grants Users write access'
    [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = 1 }))
    Assert ((Test-AuditDirSecurity -Acl (New-Object IO.DirectoryInfo($tmpDir)).GetAccessControl()).Ok) 'the ACL was repaired on first use'
    $recs = Get-LogRecords
    Assert (@($recs | Where-Object { $_.type -eq 'integrity' -and $_.issue -eq 'audit-dir-acl-repaired' }).Count -eq 1 -and (Test-AuditLogIntegrity -Quiet).Ok) 'the repair is recorded as an integrity record and the chain verifies'

    # directory owned by somebody who is not trusted: refuse (only meaningful for a non-elevated run)
    if (-not $isElevated) {
        Reset-Sandbox
        [void](New-Item -ItemType Directory -Path $tmpDir)
        $script:AuditTrustedExtra = @()
        $msg = ''
        try { Initialize-AuditStore } catch { $msg = $_.Exception.Message }
        $script:AuditTrustedExtra = @($mySid)
        Assert ($msg -match 'not SYSTEM/Administrators') 'pre-created directory owned by an untrusted account is refused'
        $ran = $false
        $script:AuditTrustedExtra = @()
        try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { $script:ran = $true } | Out-Null } catch { $msg = $_.Exception.Message }
        $script:AuditTrustedExtra = @($mySid)
        Assert ((-not $ran) -and $msg -match 'NOT performed') 'an untrusted audit directory stops the change (fail-closed)'
    } else {
        Assert $true 'untrusted-owner refusal is checked in non-elevated runs only (this run is elevated)'
        Assert $true 'untrusted-owner fail-closed is checked in non-elevated runs only (this run is elevated)'
    }

    # planted files are not part of the chain and are reported
    Reset-Sandbox
    for ($i = 1; $i -le 3; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = $i })) }
    [IO.File]::WriteAllText((Join-Path $tmpDir 'audit-99999999.jsonl'), '{"v":1}' + "`n")
    [IO.File]::WriteAllText((Join-Path $tmpDir 'baseline.json.tmp'), '{}')
    $r = Test-AuditLogIntegrity -Quiet
    Assert ((-not $r.Ok) -and ($r.Errors -join ';') -match 'audit-99999999\.jsonl') 'a planted audit-* file is reported as an integrity error'
    Assert (($r.Warnings -join ';') -match 'baseline\.json\.tmp') 'a stale temporary file is reported as a warning'
    Assert (@(Get-AuditFiles).Count -eq 1 -and $r.Records -eq 3) 'planted files are not read as part of the chain'

    # ---------------------------------------------------------------------------------
    Section 'Fail policy: Closed by default, Open as a toggle, reconciled afterwards'
    $script:AuditEventLogFallback = $false          # never write to the real Application log from tests
    function Lock-AuditLogFile {
        $script:AuditTailCache = $null
        New-Object IO.FileStream((Get-AuditFile Log), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    Reset-Sandbox
    Set-FakeRule 'fp-0' $ruleA
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Assert ((Get-AuditFailPolicy).Policy -eq 'Closed') 'default policy is Closed'

    $lock = Lock-AuditLogFile
    $ran = $false; $msg = ''
    try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { $script:ran = $true; Set-FakeRule 'fp-1' $ruleA } | Out-Null } catch { $msg = $_.Exception.Message }
    Assert ((-not $ran) -and $msg -match 'NOT performed') 'Closed: unwritable log refuses the change'
    $ran = $false
    $res = Invoke-AuditedChange -Operation 'Add' -Scope NewRules -FailPolicy Open -Reason 'open test' -WarningAction SilentlyContinue -Action { $script:ran = $true; Set-FakeRule 'fp-2' $ruleA }
    $lock.Dispose(); $script:AuditTailCache = $null
    Assert ($ran -and $res.FailOpen -and (Get-PolicySnapshot -Scope Names -Names @('fp-2')).Count -eq 1) 'per-call Open: the change is performed although the log is unwritable'
    $pend = @(Read-AuditPending)
    Assert ($pend.Count -eq 1 -and $pend[0].operation -eq 'Add' -and $pend[0].reason -eq 'open test' -and $pend[0].txid -eq $res.TxId) 'a pending marker describes the unlogged change'
    Assert (@($res.Warnings).Count -ge 1 -and "$($res.Warnings)" -match 'fail policy Open') 'the return value warns about the missing audit trail'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    $recs = Get-LogRecords
    $ul = @($recs | Where-Object { $_.type -eq 'integrity' -and $_.issue -eq 'unlogged-change' })
    $chg = @($recs | Where-Object { $_.type -eq 'change' -and $_.ruleId -eq 'fp-2' })
    Assert ($s.Pending -eq 1 -and $s.Added -eq 1 -and $ul.Count -eq 1 -and $ul[0].txid -eq $res.TxId) 'next sync: integrity record for the marker + the real change'
    Assert ($chg.Count -eq 1 -and $chg[0].relatedTxids -contains $res.TxId) 'the reconciled change is linked to the unlogged transaction'
    Assert ((-not (Test-Path (Get-AuditPendingPath))) -and (Test-AuditLogIntegrity -Quiet).Ok) 'markers are cleared and the chain is intact'
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert (($s.Added + $s.Removed + $s.Modified + $s.Pending) -eq 0) 'nothing is reported twice'

    # the persisted toggle
    Set-AuditFailPolicy -Policy Open -Reason 'unit test'
    $fp = Get-AuditFailPolicy
    $setRec = @(Get-LogRecords | Where-Object type -eq 'setting')
    Assert ($fp.Policy -eq 'Open' -and (Test-Path (Get-AuditSettingsPath))) 'toggle to Open is persisted'
    Assert ($setRec.Count -eq 1 -and $setRec[0].oldValue -eq 'Closed' -and $setRec[0].newValue -eq 'Open' -and $setRec[0].recorder.user) 'the toggle is an audit record (old, new, who)'
    $lock = Lock-AuditLogFile
    $ran = $false
    $res = Invoke-AuditedChange -Operation 'Add' -Scope NewRules -WarningAction SilentlyContinue -Action { $script:ran = $true; Set-FakeRule 'fp-3' $ruleA }
    Assert ($ran -and $res.FailOpen) 'persisted Open applies when no per-call policy is given'
    $ran = $false; $msg = ''
    try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -FailPolicy Closed -Action { $script:ran = $true; Set-FakeRule 'fp-4' $ruleA } | Out-Null } catch { $msg = $_.Exception.Message }
    $lock.Dispose(); $script:AuditTailCache = $null
    Assert ((-not $ran) -and $msg -match 'NOT performed') 'per-call Closed beats the persisted Open'
    [void](Invoke-AuditSync -Trigger manual -Quiet)
    Set-AuditFailPolicy -Policy Closed -Reason 'unit test'
    Assert ((Get-AuditFailPolicy).Policy -eq 'Closed' -and @(Get-LogRecords | Where-Object type -eq 'setting').Count -eq 2) 'toggle back to Closed is logged too'

    # settings.json cannot be used to switch fail-open on behind the log's back
    $sp = Get-AuditSettingsPath
    $forgedTs = '2026-01-01T00:00:00.0000000Z'
    [IO.File]::WriteAllText($sp, (ConvertTo-AuditJson ([ordered]@{ v = 1; failPolicy = 'Open'; ts = $forgedTs; by = 'x'; hash = ('0' * 64) })), $script:AuditUtf8)
    $fp = Get-AuditFailPolicy
    Assert ($fp.Policy -eq 'Closed' -and $fp.Tampered) 'hand-edited settings.json (wrong hash) -> Closed, flagged'
    $goodHash = Get-AuditSettingsHash -Policy 'Open' -Ts $forgedTs -By 'x'
    [IO.File]::WriteAllText($sp, (ConvertTo-AuditJson ([ordered]@{ v = 1; failPolicy = 'Open'; ts = $forgedTs; by = 'x'; hash = $goodHash })), $script:AuditUtf8)
    $fp = Get-AuditFailPolicy
    Assert ($fp.Policy -eq 'Closed' -and $fp.Tampered) 'self-consistent settings.json without a matching log record -> Closed, flagged'
    [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = 1 }))
    Assert (@(Get-LogRecords | Where-Object { $_.type -eq 'integrity' -and $_.issue -eq 'settings-file-modified' }).Count -ge 1) 'the tampering is written to the log'
    Remove-Item $sp
    Assert ((Get-AuditFailPolicy).Policy -eq 'Closed') 'a missing settings.json means Closed'

    # lock timeout: another process holds the audit mutex
    $script:AuditLockTimeoutMs = 1500
    $holder = Start-Job -ArgumentList $script:AuditMutexName -ScriptBlock {
        param($n)
        $mx = New-Object System.Threading.Mutex($false, $n)
        [void]$mx.WaitOne()
        'held'
        Start-Sleep -Seconds 40
    }
    $up = $false
    for ($i = 0; $i -lt 60 -and -not $up; $i++) { Start-Sleep -Milliseconds 500; $up = (@(Receive-Job $holder -Keep) -contains 'held') }
    Assert $up 'precondition: a second process holds the audit lock'
    $ran = $false; $msg = ''
    try { Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Action { $script:ran = $true; Set-FakeRule 'lk-1' $ruleA } | Out-Null } catch { $msg = $_.Exception.Message }
    Assert ((-not $ran) -and $msg -match 'NOT performed' -and $msg -match 'Timed out') 'Closed: lock timeout refuses the change'
    $res = Invoke-AuditedChange -Operation 'Add' -Scope NewRules -FailPolicy Open -WarningAction SilentlyContinue -Action { Set-FakeRule 'lk-2' $ruleA }
    $pend = @(Read-AuditPending)
    Assert ($res.FailOpen -and $pend.Count -eq 1 -and $pend[0].why -match 'Timed out') 'Open: lock timeout does not block the change; the marker names the reason'
    Stop-Job $holder; Remove-Job $holder -Force           # the mutex is abandoned, the next owner takes it over
    $script:AuditLockTimeoutMs = 60000
    $s = Invoke-AuditSync -Trigger manual -Quiet
    Assert ($s.Pending -eq 1 -and $s.Added -ge 1 -and (Test-AuditLogIntegrity -Quiet).Ok) 'after the lock is free the change is reconciled (abandoned mutex is taken over)'
    $script:AuditEventLogFallback = $true

    # ---------------------------------------------------------------------------------
    Section 'Watcher: definition, state.json and health (nothing is registered)'
    $def = New-AuditWatcherDefinition -ScriptPath 'C:\ProgramData\FirewallAudit\bin\firewall.ps1'
    Assert (@($def.Triggers).Count -eq 3) 'three triggers: firewall events, startup, periodic'
    $rep = @($def.Triggers | Where-Object { $_.Repetition -and $_.Repetition.Interval })
    Assert ($rep.Count -eq 1 -and $rep[0].Repetition.Interval -eq 'PT15M') 'periodic trigger repeats every 15 minutes'
    $sub = [string]@($def.Triggers | Where-Object { $_.Subscription })[0].Subscription
    Assert ($sub -match 'EventID=2004' -and $sub -match 'EventID=2006' -and $sub -match 'EventID=2002') 'event subscription covers add, delete and setting events'
    Assert ($def.Action.Arguments -match '-SyncAudit' -and $def.Action.Arguments -match 'bin\\firewall\.ps1') 'action runs the protected copy with -SyncAudit'
    Assert ($def.Principal.UserId -eq 'SYSTEM' -and [string]$def.Principal.RunLevel -eq 'Highest') 'task runs as SYSTEM, highest privileges'

    $now = [DateTime]::UtcNow
    $iso = { param($d) $d.ToString('o') }
    Assert ((Get-AuditWatcherHealth -State $null -NowUtc $now).Health -eq 'NeverRan') 'no state.json -> NeverRan'
    $okFresh = [pscustomobject]@{ status = 'ok'; lastOk = (& $iso $now.AddMinutes(-5)); message = $null }
    $okOld   = [pscustomobject]@{ status = 'ok'; lastOk = (& $iso $now.AddMinutes(-50)); message = $null }
    $stFailed = [pscustomobject]@{ status = 'failed'; lastOk = (& $iso $now.AddMinutes(-5)); message = 'boom' }
    Assert ((Get-AuditWatcherHealth -State $okFresh -NowUtc $now).Health -eq 'Healthy') 'recent success -> Healthy'
    Assert ((Get-AuditWatcherHealth -State $okOld -NowUtc $now).Health -eq 'Stale') 'no success for > 3 intervals -> Stale'
    $h = Get-AuditWatcherHealth -State $stFailed -NowUtc $now
    Assert ($h.Health -eq 'Failed' -and $h.Message -eq 'boom') 'last run failed -> Failed with the message'

    Reset-Sandbox
    Set-FakeRule 'w-0' $ruleA
    Invoke-AuditWatcherRun -SettleSeconds 0
    $st = Read-AuditState
    Assert ($st -and $st.status -eq 'ok' -and $st.lastOk -and $st.user) 'a watcher run writes state.json (status ok, lastOk)'
    Assert ((Get-AuditWatcherHealth -State $st).Health -eq 'Healthy') 'and is Healthy right after'
    $firstOk = [string]$st.lastOk
    $origSync = ${function:Invoke-AuditSync}
    function Invoke-AuditSync { throw 'simulated sync failure' }
    $threw = $false
    try { Invoke-AuditWatcherRun -SettleSeconds 0 } catch { $threw = $true }
    ${function:Invoke-AuditSync} = $origSync
    $st = Read-AuditState
    Assert ($threw -and $st.status -eq 'failed' -and $st.message -match 'simulated') 'a failing run is re-thrown and recorded as failed'
    Assert ([string]$st.lastOk -eq $firstOk) 'lastOk survives a later failure'
    Assert ((Get-AuditWatcherHealth -State $st).Health -eq 'Failed') 'health shows Failed'
    Set-FakeRule 'w-1' $ruleA
    Invoke-AuditWatcherRun -SettleSeconds 0
    $st = Read-AuditState
    Assert ($st.status -eq 'ok' -and $st.summary.added -eq 1 -and @(Get-LogRecords | Where-Object { $_.type -eq 'change' -and $_.ruleId -eq 'w-1' }).Count -eq 1) 'the next run recovers and the change is logged'
    [IO.File]::WriteAllText((Get-AuditFile State), '{ not json', $script:AuditUtf8)
    Assert ($null -eq (Read-AuditState) -and (Get-AuditWatcherHealth -State (Read-AuditState)).Health -eq 'NeverRan') 'a corrupt state.json is treated as "never ran"'

    # ---------------------------------------------------------------------------------
    Section 'Head hash anchoring: truncation and full rewrites'
    Reset-Sandbox
    Assert ($null -eq (Get-AuditHeadHash)) 'no log -> no head'
    for ($i = 1; $i -le 10; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = $i })) }
    $head = Get-AuditHeadHash
    Assert ($head.Seq -eq 10 -and $head.Text -match '^10:[0-9a-f]{64}$') "head is seq:hash ($($head.Text.Substring(0, 12))...)"
    Assert ((Test-AuditLogIntegrity -Quiet -ExpectedHead $head.Text).Ok) 'untouched log matches the saved head'
    for ($i = 11; $i -le 13; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = $i })) }
    Assert ((Test-AuditLogIntegrity -Quiet -ExpectedHead $head.Text).Ok) 'a log that has only grown still matches an older saved head'
    $log = Get-AuditFile Log
    $lines = [IO.File]::ReadAllLines($log)
    [IO.File]::WriteAllLines($log, $lines[0..7])                                     # cut off the newest records
    $script:AuditTailCache = $null
    Assert ((Test-AuditLogIntegrity -Quiet).Ok) 'precondition: a truncated log is still a valid chain'
    $r = Test-AuditLogIntegrity -Quiet -ExpectedHead $head.Text
    Assert ((-not $r.Ok) -and ($r.Errors -join ';') -match 'not found') 'truncation is detected against the saved head'
    Reset-Sandbox                                                                     # an attacker rewrites everything consistently
    for ($i = 1; $i -le 10; $i++) { [void](Write-AuditRecord -Type 'info' -Fields ([ordered]@{ n = "forged $i" })) }
    Assert ((Test-AuditLogIntegrity -Quiet).Ok) 'precondition: a fully rewritten log is a valid chain'
    $r = Test-AuditLogIntegrity -Quiet -ExpectedHead $head.Text
    Assert ((-not $r.Ok) -and ($r.Errors -join ';') -match 'saved head mismatch') 'a complete rewrite is detected against the saved head'
    $r = Test-AuditLogIntegrity -Quiet -ExpectedHead 'garbage'
    Assert ((-not $r.Ok) -and ($r.Errors -join ';') -match 'seq>:<64 hex|must look like') 'a malformed saved head is rejected'

    # ---------------------------------------------------------------------------------
    Section 'Two processes writing at once (mutex)'
    Reset-Sandbox
    $jobs = 1..2 | ForEach-Object {
        Start-Job -ArgumentList $m.Value, $tmpDir, $script:AuditMutexName, $_, $mySid -ScriptBlock {
            param($region, $dir, $mutex, $who, $sid)
            . ([scriptblock]::Create($region))
            $script:AuditDir = $dir; $script:AuditMutexName = $mutex; $script:AuditTrustedExtra = @($sid)
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
    Assert ($msReuse -lt ($msFull * 0.8) -or $msFull -lt 500) 'reuse of unchanged rules makes the snapshot cheaper than a full parse'
    Assert (@($snap.Keys | Where-Object { $_.StartsWith('setting:') }).Count -ge 1) 'live store: generic settings (Mdm, RestrictedServices, ...) are part of the snapshot'
}
finally {
    try { [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($regRoot) } catch { }
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host "`nPassed: $script:Passed   Failed: $script:Failed" -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 }
