#Requires -Version 5.1
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Interactive Windows Firewall rule manager with a tamper-evident audit trail.

.PARAMETER SyncAudit
    Non-interactive mode used by the audit watcher (Scheduled Task, SYSTEM).
    Reconciles the live firewall policy with the audit baseline and records every
    difference (changes made outside this script) in the audit log, then exits.

.PARAMETER Agent
    Non-interactive modes of the BACKUP module (owner: Ruslan). Used only by the backup
    server over SSH (forced command in administrators_authorized_keys) and by the rollback
    task: Export (print the policy), Import (restore a policy through the audit wrapper),
    Rollback (return to the pre-restore policy unless the user confirmed).
#>
[CmdletBinding()]
param(
    [switch]$SyncAudit,
    [ValidateSet('Export', 'Import', 'Rollback')][string]$Agent
)

#region AUDIT
# =============================================================================
# AUDIT MODULE  (owner: Aleh Shehda)  -  logging of every firewall policy change
# =============================================================================
# Team contract (do not edit this region without talking to the owner):
#
#   Every operation that CHANGES the firewall policy must run through
#
#       Invoke-AuditedChange -Operation <Name> -Scope <Names|NewRules|Profiles|All>
#                            [-Names <rule IDs>] -Action { ...cmdlets... }
#                            [-Initiator interactive|automation|...] [-Reason <text>]
#                            [-Details @{ ... }]
#
#   Scope tells the audit engine which part of the policy the Action may touch:
#       Names     the rules whose ID (the 'Name' property, NOT DisplayName) is in -Names
#       NewRules  the Action creates new rules (they are discovered automatically)
#       Profiles  the Domain/Private/Public profile settings (Set-NetFirewallProfile)
#       All       whole policy (e.g. restore from backup: netsh advfirewall import)
#
#   Examples of the intended usage by the other modules:
#       Adam      Add   -> -Operation Add          -Scope NewRules
#                 Delete-> -Operation Remove       -Scope Names -Names @($ruleId)
#       Aliaksei  profile switch (Enable/Disable-NetFirewallRule)
#                         -Operation ProfileSwitch -Scope Names -Names $ids
#                         -Initiator automation -Reason 'Public -> Private'
#       Ruslan    restore -Operation Restore       -Scope All
#                 (the diff of the whole policy is turned into per-rule records)
#
#   The Action scriptblock sees the caller's variables (dynamic scoping). All local
#   variables inside the audit functions are prefixed 'audit' to avoid shadowing.
#   Errors thrown by the Action are logged and then re-thrown to the caller.
#   If the audit log cannot be written BEFORE the change, the change is NOT performed.
#
# How the log is built: see the 'Audit' chapters in SOS-FW-project. In short:
#   * source of truth = the persistent policy store (registry FirewallPolicy);
#     what is logged is the real difference between snapshots, not the intent;
#   * write-ahead: 'intent' record -> action -> 'change' records -> 'result' record;
#   * JSON Lines, every record carries SHA-256 of the previous one (hash chain);
#   * a Scheduled Task (SYSTEM) runs this script with -SyncAudit on firewall events
#     and records changes made outside this tool (GUI, netsh, other admins, Windows).
# =============================================================================

$script:AuditSchemaVersion = 1
$script:AuditDir           = Join-Path $env:ProgramData 'FirewallAudit'
$script:AuditMutexName     = 'Global\FirewallAuditLog'
$script:AuditMaxBytes      = 10MB
$script:AuditTaskPath      = '\FirewallAudit\'
$script:AuditTaskName      = 'Watcher'
$script:AuditWatcherIntervalMin = 15      # periodic sync: the event trigger can miss events (log full/disabled/cleared)
$script:AuditEventLog      = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
# Event IDs differ between Windows builds (2004/2005/2006/2033 on older ones, 2097/2099/2052/2059
# observed on Windows 11 24H2). All known IDs are listed on purpose.
$script:AuditEventIds      = @{
    Added      = @(2004, 2097)
    Modified   = @(2005, 2098, 2099)
    Deleted    = @(2006, 2052)
    AllDeleted = @(2033, 2059)
    Setting    = @(2002, 2003)
}
$script:AuditPolicyHive    = [Microsoft.Win32.Registry]::LocalMachine
$script:AuditPolicyPath    = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
# Group Policy store (same hive); absent on machines without a firewall GPO.
$script:AuditGpoPath       = 'SOFTWARE\Policies\Microsoft\WindowsFirewall'
$script:AuditProfileKeys   = [ordered]@{ Domain = 'DomainProfile'; Private = 'StandardProfile'; Public = 'PublicProfile' }
# Top-level subkeys of the policy roots that have their own handlers (everything else is walked generically).
$script:AuditHandledTopKeys = @('FirewallRules', 'ConSecRules', 'DomainProfile', 'StandardProfile', 'PublicProfile')
# Registry keys (relative, wildcard) excluded from the generic walk because they change on their own.
# Empty on purpose: "visibility over everything". Every entry needs a written rationale and is logged in
# the 'baseline' record (ignoredKeys).
$script:AuditIgnoreKeys    = @()
# Who may own / write the audit directory. Tests add the current user via AuditTrustedExtra.
$script:AuditTrustedSids   = @('S-1-5-18', 'S-1-5-32-544')
$script:AuditTrustedExtra  = @()
$script:AuditInInit        = $false
$script:AuditNotices       = @()
$script:AuditLockTimeoutMs = 60000
# Last resort for fail-open markers when pending.jsonl cannot be written: the Application event log.
$script:AuditEventLogFallback = $true
$script:AuditSettingsTamperNoted = $false
$script:AuditRotatedNameRegex = '^audit-\d{8}-\d{9}(-\d+)?\.jsonl$'
# Baseline file schema: 2 = rules + ConSec + GPO + generic settings. Older baselines are rebuilt silently.
$script:AuditBaselineSchema = 2
$script:AuditZeroHash      = '0' * 64
$script:AuditSelfPath      = $PSCommandPath
$script:AuditInitiatorDefault = $null
$script:AuditUtf8          = New-Object System.Text.UTF8Encoding($false)
$script:AuditLockDepth     = 0
$script:AuditMutex         = $null
$script:AuditTailCache     = $null
$script:AuditSelfHash      = $null
$script:AuditRecorderCache = @{}
$script:AuditSidCache      = @{}
$script:AuditResourceCache = @{}
$script:AuditSerializer    = $null
$script:AuditKeyRegex      = [regex]::new('^[A-Za-z][A-Za-z0-9_]*$')
$script:AuditConsumedKeys  = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('Name', 'Desc', 'EmbedCtxt', 'Active', 'Dir', 'Action', 'Protocol', 'Profile',
                'LPort', 'RPort', 'LA4', 'LA6', 'RA4', 'RA6', 'App', 'Svc'))

# ---------------------------------------------------------------- small helpers

function Get-AuditFile {
    param([ValidateSet('Log', 'Baseline', 'Bin', 'State')][string]$Kind = 'Log')
    switch ($Kind) {
        'State'    { Join-Path $script:AuditDir 'state.json' }
        'Log'      { Join-Path $script:AuditDir 'audit.jsonl' }
        'Baseline' { Join-Path $script:AuditDir 'baseline.json' }
        'Bin'      { Join-Path $script:AuditDir 'bin' }
    }
}

# ----------------------------------------------- the audit directory must not be writable by users
# C:\ProgramData lets every user create files and folders. The audit directory therefore gets its own
# protected ACL, and an existing directory is checked (and repaired) on EVERY use: a user could have
# pre-created it, and then could delete or replace the log and the baseline.

function Get-AuditTrustedSids {
    $sids = [System.Collections.Generic.List[string]]::new()
    foreach ($s in @($script:AuditTrustedSids) + @($script:AuditTrustedExtra)) { if ($s) { $sids.Add([string]$s) } }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    # an elevated administrator (not necessarily as the Administrators group) may own what it creates
    if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $sids.Add($id.User.Value)
    }
    return $sids.ToArray()
}

# Pure check of a DirectorySecurity: trusted owner, and nobody untrusted may write/create/delete/change ACLs.
function Test-AuditDirSecurity {
    param([Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$Acl)
    $trusted = Get-AuditTrustedSids
    $issues = [System.Collections.Generic.List[string]]::new()
    $owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier])
    $ownerSid = if ($owner) { $owner.Value } else { '' }
    $ownerOk = $trusted -contains $ownerSid
    $mask = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    foreach ($r in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($trusted -contains $r.IdentityReference.Value) { continue }
        $bad = $r.FileSystemRights -band $mask
        if ([int]$bad -ne 0) { $issues.Add("$($r.IdentityReference.Value) is allowed: $bad") }
    }
    return [pscustomobject]@{ Ok = ($ownerOk -and $issues.Count -eq 0); OwnerTrusted = $ownerOk; Owner = $ownerSid; Issues = $issues.ToArray() }
}

function New-AuditSecureAcl {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)       # no inheritance from ProgramData
    $flags = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $sids = @($script:AuditTrustedSids) + @($script:AuditTrustedExtra) | Where-Object { $_ } | Select-Object -Unique
    foreach ($s in $sids) {
        $sid = New-Object Security.Principal.SecurityIdentifier($s)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl, $flags, $none, $allow)))
    }
    return $acl
}

function Initialize-AuditStore {
    if ($script:AuditInInit) { return }
    $script:AuditInInit = $true
    try {
        if (-not (Test-Path -LiteralPath $script:AuditDir)) {
            [void][IO.Directory]::CreateDirectory($script:AuditDir, (New-AuditSecureAcl))
            return
        }
        $info = New-Object IO.DirectoryInfo($script:AuditDir)
        $check = Test-AuditDirSecurity -Acl $info.GetAccessControl()
        if ($check.Ok) { return }
        if (-not $check.OwnerTrusted) {
            throw "Audit directory $($script:AuditDir) is owned by $($check.Owner), who is not SYSTEM/Administrators (a user may have pre-created it). Remove it as an administrator and run again."
        }
        $info.SetAccessControl((New-AuditSecureAcl))
        $script:AuditNotices += ,([ordered]@{ issue = 'audit-dir-acl-repaired'; detail = "Untrusted access removed from $($script:AuditDir): $($check.Issues -join '; ')" })
    } finally { $script:AuditInInit = $false }
}

# All log files, oldest first (rotated files first, the live file last). Only strictly named files count;
# anything else called audit-* is reported by Test-AuditLogIntegrity.
function Get-AuditFiles {
    if (-not (Test-Path -LiteralPath $script:AuditDir)) { return @() }
    $files = @()
    $files += @(Get-ChildItem -LiteralPath $script:AuditDir -Filter 'audit-*.jsonl' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:AuditRotatedNameRegex } | Sort-Object Name | ForEach-Object { $_.FullName })
    $live = Get-AuditFile 'Log'
    if (Test-Path -LiteralPath $live) { $files += $live }
    return $files
}

function Get-AuditTimestamp {
    [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-AuditDate {
    param($Value)
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $parsed = [DateTime]::MinValue
    if ([DateTime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function Get-AuditSha256Hex {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash($script:AuditUtf8.GetBytes($Text))
        return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-AuditSelfHash {
    if ($null -eq $script:AuditSelfHash) {
        $script:AuditSelfHash = ''
        if ($script:AuditSelfPath -and (Test-Path -LiteralPath $script:AuditSelfPath)) {
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $bytes = $sha.ComputeHash([IO.File]::ReadAllBytes($script:AuditSelfPath))
                $script:AuditSelfHash = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
            } finally { $sha.Dispose() }
        }
    }
    return $script:AuditSelfHash
}

function ConvertTo-AuditJson {
    param($InputObject)
    ConvertTo-Json -InputObject $InputObject -Compress -Depth 12
}

function New-AuditSerializer {
    if ($null -eq $script:AuditSerializer) {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 64
        $script:AuditSerializer = $ser
    }
    return $script:AuditSerializer
}

# Sorted, de-duplicated, case-insensitive list of strings (comma/space separated when asked).
function ConvertTo-AuditStringList {
    param($Value, [switch]$DefaultAny, [switch]$SplitCommas)
    $set   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        $parts = if ($SplitCommas) { "$v" -split '[,\s]+' } else { @("$v") }
        foreach ($p in $parts) {
            $s = $p.Trim()
            if ($s.Length -eq 0) { continue }
            if ($s -eq '*') { $s = 'Any' }
            if ($set.Add($s)) { $items.Add($s) }
        }
    }
    if ($items.Count -eq 0 -and $DefaultAny) { $items.Add('Any') }
    $arr = $items.ToArray()
    [Array]::Sort($arr, [StringComparer]::OrdinalIgnoreCase)
    return , $arr
}

# Canonical string used ONLY for comparison and hashing (case-insensitive, order-insensitive).
function ConvertTo-AuditCanon {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [string]) { return $Value.Trim().ToLowerInvariant() }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = ConvertTo-AuditStringList $Value
        return (($list | ForEach-Object { $_.ToLowerInvariant() }) -join '|')
    }
    return "$Value".Trim().ToLowerInvariant()
}

# SHLoadIndirectString: turns '@FirewallAPI.dll,-32765' into readable text.
function Resolve-AuditResourceString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or -not $Text.StartsWith('@')) { return $Text }
    if ($script:AuditResourceCache.ContainsKey($Text)) { return $script:AuditResourceCache[$Text] }
    $resolved = $Text
    try {
        if (-not ('FwAuditNative' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class FwAuditNative {
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    public static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved);
}
'@
        }
        $sb = New-Object System.Text.StringBuilder 512
        if ([FwAuditNative]::SHLoadIndirectString($Text, $sb, $sb.Capacity, [IntPtr]::Zero) -eq 0 -and $sb.Length -gt 0) {
            $resolved = $sb.ToString()
        }
    } catch { }
    $script:AuditResourceCache[$Text] = $resolved
    return $resolved
}

function Resolve-AuditSid {
    param([string]$Sid)
    if ([string]::IsNullOrEmpty($Sid)) { return $null }
    if ($script:AuditSidCache.ContainsKey($Sid)) { return $script:AuditSidCache[$Sid] }
    $name = $Sid
    try {
        $name = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value
    } catch { }
    $script:AuditSidCache[$Sid] = $name
    return $name
}

# ------------------------------------------------------------ locking (mutex)

# One named mutex serialises everything that writes the audit log or the baseline
# (menu instances, the SYSTEM watcher task, other modules). Re-entrant per thread.
function Enter-AuditLock {
    param([int]$TimeoutMs = $script:AuditLockTimeoutMs)
    if ($script:AuditLockDepth -gt 0) { $script:AuditLockDepth++; return }
    if ($null -eq $script:AuditMutex) {
        $script:AuditMutex = New-Object System.Threading.Mutex($false, $script:AuditMutexName)
    }
    $acquired = $false
    try {
        $acquired = $script:AuditMutex.WaitOne($TimeoutMs)
    } catch [System.Threading.AbandonedMutexException] {
        # The previous owner died while holding the lock: we own it now.
        $acquired = $true
    }
    if (-not $acquired) {
        throw "Timed out waiting for the audit lock ($($script:AuditMutexName)); another instance is busy."
    }
    $script:AuditLockDepth = 1
    $script:AuditTailCache = $null
}

function Exit-AuditLock {
    if ($script:AuditLockDepth -le 0) { return }
    $script:AuditLockDepth--
    if ($script:AuditLockDepth -eq 0) {
        $script:AuditTailCache = $null
        try { $script:AuditMutex.ReleaseMutex() } catch { }
    }
}

# --------------------------------------------------------------- who is acting

function Get-AuditRecorder {
    param([string]$Initiator)
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $Initiator) {
        $Initiator = if ($script:AuditInitiatorDefault) { $script:AuditInitiatorDefault }
                     elseif ($id.IsSystem) { 'scheduled-task' }
                     else { 'interactive' }
    }
    $cacheKey = "$($id.User.Value)|$Initiator"
    if ($script:AuditRecorderCache.ContainsKey($cacheKey)) { return $script:AuditRecorderCache[$cacheKey] }

    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $recorder = [ordered]@{
        user         = $id.Name
        sid          = $id.User.Value
        elevated     = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        initiator    = $Initiator
        pid          = $PID
        session      = [Diagnostics.Process]::GetCurrentProcess().SessionId
        psVersion    = $PSVersionTable.PSVersion.ToString()
        script       = $script:AuditSelfPath
        scriptSha256 = Get-AuditSelfHash
    }
    $script:AuditRecorderCache[$cacheKey] = $recorder
    return $recorder
}

# Actor of a change made through this tool (the identity running the script).
function Get-AuditScriptActor {
    param([string]$Initiator)
    $r = Get-AuditRecorder -Initiator $Initiator
    $app = if ($script:AuditSelfPath) { Split-Path -Leaf $script:AuditSelfPath } else { 'firewall.ps1' }
    return [ordered]@{
        user = $r.user; sid = $r.sid; application = $app
        initiator = $r.initiator; evidence = 'process'
    }
}

# ------------------------------------------------- policy snapshot (registry)
# The persistent policy store lives in
#   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
# Rules: value name = rule ID (the 'Name' property), data = 'v2.xx|Key=Value|...'.
# Reading it takes milliseconds, whereas Get-NetFirewallRule needs tens of seconds for
# ~500 rules and loses nothing relevant for an audit.

function Open-AuditPolicyKey {
    param([string]$SubKey)
    $path = $script:AuditPolicyPath
    if ($SubKey) { $path = "$path\$SubKey" }
    return $script:AuditPolicyHive.OpenSubKey($path)
}

function ConvertFrom-AuditRuleString {
    param([Parameter(Mandatory)][string]$Raw)

    $kv = @{}                                                    # key -> List[string] (keys repeat: Profile=..|Profile=..)
    $order = [System.Collections.Generic.List[string]]::new()
    $lastKey = $null
    $tokens = $Raw.Split('|')
    for ($i = 0; $i -lt $tokens.Length; $i++) {
        $tok = $tokens[$i]
        if ($tok.Length -eq 0) { continue }
        $eq = $tok.IndexOf('=')
        if ($i -eq 0 -and $eq -lt 0 -and $tok[0] -eq 'v') { continue }      # version token, e.g. v2.33
        $isPair = $false
        if ($eq -gt 0) {
            $k = $tok.Substring(0, $eq)
            $isPair = $script:AuditKeyRegex.IsMatch($k)
        }
        if ($isPair) {
            $list = $kv[$k]
            if ($null -eq $list) { $list = [System.Collections.Generic.List[string]]::new(); $kv[$k] = $list; $order.Add($k) }
            $list.Add($tok.Substring($eq + 1))
            $lastKey = $k
        } elseif ($null -ne $lastKey) {
            # a '|' inside a value (e.g. description): glue the fragment back
            $l = $kv[$lastKey]
            $l[$l.Count - 1] = $l[$l.Count - 1] + '|' + $tok
        }
    }

    $e = [ordered]@{}
    $x = $kv['Name'];      $e['displayName']  = if ($x) { $x[0] } else { '' }
    $x = $kv['Desc'];      $e['description']  = if ($x) { $x[0] } else { '' }
    $x = $kv['EmbedCtxt']; $e['displayGroup'] = if ($x) { $x[0] } else { '' }
    $x = $kv['Active'];    $e['enabled']      = [bool]($x -and $x[0] -eq 'TRUE')
    $x = $kv['Dir'];       $dir = if ($x) { $x[0] } else { '' }
    $e['direction'] = if ($dir -eq 'In') { 'Inbound' } elseif ($dir -eq 'Out') { 'Outbound' } else { $dir }
    $x = $kv['Action'];    $e['action'] = if ($x) { $x[0] } else { '' }
    $x = $kv['Protocol'];  $proto = if ($x) { $x[0] } else { '' }
    $e['protocol'] = switch ($proto) {
        ''      { 'Any' }
        '256'   { 'Any' }
        '6'     { 'TCP' }
        '17'    { 'UDP' }
        '1'     { 'ICMPv4' }
        '58'    { 'ICMPv6' }
        default { $proto }
    }
    $e['profile']       = ConvertTo-AuditStringList $kv['Profile'] -DefaultAny
    $e['localPort']     = ConvertTo-AuditStringList $kv['LPort'] -DefaultAny
    $e['remotePort']    = ConvertTo-AuditStringList $kv['RPort'] -DefaultAny
    $e['localAddress']  = ConvertTo-AuditStringList (@($kv['LA4']) + @($kv['LA6'])) -DefaultAny
    $e['remoteAddress'] = ConvertTo-AuditStringList (@($kv['RA4']) + @($kv['RA6'])) -DefaultAny
    $x = $kv['App'];       $e['program'] = if ($x) { $x[0] } else { '' }
    $x = $kv['Svc'];       $e['service'] = if ($x) { $x[0] } else { '' }

    foreach ($k in $order) {
        if ($script:AuditConsumedKeys.Contains($k)) { continue }
        $name = $k.Substring(0, 1).ToLowerInvariant() + $k.Substring(1)
        $vals = $kv[$k]
        $e[$name] = if ($vals.Count -eq 1) { $vals[0] } else { ConvertTo-AuditStringList $vals }
    }
    return $e
}

function ConvertTo-AuditRegistryText {
    param($Value)
    if ($Value -is [byte[]]) { return [BitConverter]::ToString($Value) }
    if ($Value -is [array]) { return (($Value | ForEach-Object { "$_" }) -join ',') }
    return "$Value"
}

function Get-AuditProfileEntry {
    param($Key)
    $e = [ordered]@{}
    foreach ($v in ($Key.GetValueNames() | Sort-Object)) {
        if ($v -eq '') { continue }
        $name = $v.Substring(0, 1).ToLowerInvariant() + $v.Substring(1)
        $e[$name] = ConvertTo-AuditRegistryText ($Key.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
    }
    $log = $Key.OpenSubKey('Logging')
    if ($log) {
        try {
            foreach ($v in ($log.GetValueNames() | Sort-Object)) {
                if ($v -eq '') { continue }
                $name = 'logging.' + $v.Substring(0, 1).ToLowerInvariant() + $v.Substring(1)
                $e[$name] = ConvertTo-AuditRegistryText ($log.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
            }
        } finally { $log.Close() }
    }
    return $e
}

function Get-PolicyRuleNames {
    $k = Open-AuditPolicyKey 'FirewallRules'
    if (-not $k) { return , ([string[]]@()) }
    try { return , ([string[]]$k.GetValueNames()) } finally { $k.Close() }
}

# Scope: All | Rules | Profiles | Names (with -Names).
# Returns an ordered map:  'rule:<ID>' / 'profile:<Domain|Private|Public>'  ->  entry.
#   -RawSink  hashtable that receives key -> raw registry string of every rule read
#   -Reuse    baseline state (Entries + Raws): rules whose raw string is unchanged are NOT
#             parsed again, the baseline entry is reused (shared reference). This makes a full
#             snapshot cost milliseconds instead of seconds when little has changed.
function Get-PolicySnapshot {
    param(
        [ValidateSet('All', 'Rules', 'Profiles', 'Names')][string]$Scope = 'All',
        [string[]]$Names = @(),
        [hashtable]$RawSink,
        $Reuse
    )
    $snap = [ordered]@{}
    $pol = $script:AuditPolicyPath
    $gpo = $script:AuditGpoPath

    if ($Scope -eq 'Names') {
        Add-AuditRuleStrings -Snap $snap -Prefix 'rule' -Path "$pol\FirewallRules" -Names $Names -RawSink $RawSink -Reuse $Reuse
        return $snap
    }
    if ($Scope -in 'All', 'Rules') {
        Add-AuditRuleStrings -Snap $snap -Prefix 'rule'      -Path "$pol\FirewallRules" -RawSink $RawSink -Reuse $Reuse
        Add-AuditRuleStrings -Snap $snap -Prefix 'consec'    -Path "$pol\ConSecRules"   -RawSink $RawSink -Reuse $Reuse
        Add-AuditRuleStrings -Snap $snap -Prefix 'gporule'   -Path "$gpo\FirewallRules" -RawSink $RawSink -Reuse $Reuse
        Add-AuditRuleStrings -Snap $snap -Prefix 'gpoconsec' -Path "$gpo\ConSecRules"   -RawSink $RawSink -Reuse $Reuse
    }
    if ($Scope -in 'All', 'Profiles') {
        foreach ($p in $script:AuditProfileKeys.Keys) {
            $pk = $script:AuditPolicyHive.OpenSubKey("$pol\$($script:AuditProfileKeys[$p])")
            if ($pk) {
                try { $snap["profile:$p"] = Get-AuditProfileEntry $pk } finally { $pk.Close() }
            }
            $gk = $script:AuditPolicyHive.OpenSubKey("$gpo\$($script:AuditProfileKeys[$p])")
            if ($gk) {
                try { $snap["gpoprofile:$p"] = Get-AuditProfileEntry $gk } finally { $gk.Close() }
            }
        }
    }
    if ($Scope -eq 'All') {
        Add-AuditGenericKeys -Snap $snap -Prefix 'setting'    -RootPath $pol -RawSink $RawSink -Reuse $Reuse
        Add-AuditGenericKeys -Snap $snap -Prefix 'gposetting' -RootPath $gpo -RawSink $RawSink -Reuse $Reuse
    }
    return $snap
}

# Values 'name = data' of one registry value-string family (rules or connection security rules).
function Add-AuditRuleStrings {
    param($Snap, [string]$Prefix, [string]$Path, [string[]]$Names, [hashtable]$RawSink, $Reuse)
    $k = $script:AuditPolicyHive.OpenSubKey($Path)
    if (-not $k) { return }
    try {
        $list = if ($PSBoundParameters.ContainsKey('Names')) { $Names } else { $k.GetValueNames() }
        foreach ($n in $list) {
            if ([string]::IsNullOrEmpty($n)) { continue }
            $raw = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $raw) { continue }
            $raw = [string]$raw
            $key = "${Prefix}:$n"
            if ($null -ne $RawSink) { $RawSink[$key] = $raw }
            if ($Reuse -and (Test-AuditKey $Reuse.Raws $key) -and (Test-AuditKey $Reuse.Entries $key) -and
                ([string]$Reuse.Raws[$key] -ceq $raw)) {
                $Snap[$key] = $Reuse.Entries[$key]
            } else {
                $Snap[$key] = ConvertFrom-AuditRuleString $raw
            }
        }
    } finally { $k.Close() }
}

function Test-AuditIgnoredKey {
    param([string]$Key)
    foreach ($pattern in $script:AuditIgnoreKeys) { if ($Key -like $pattern) { return $true } }
    return $false
}

# Every registry key below RootPath (except the families that have their own handlers) becomes ONE entry
# 'Prefix:relative\path' holding all its values. Catches global settings, Mdm, Hyper-V, RestrictedServices,
# DynamicKeywords, ... without knowing their format.
function Add-AuditGenericKeys {
    param($Snap, [string]$Prefix, [string]$RootPath, [hashtable]$RawSink, $Reuse)
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push('')
    while ($stack.Count -gt 0) {
        $rel = $stack.Pop()
        $path = if ($rel) { "$RootPath\$rel" } else { $RootPath }
        $k = $null
        try { $k = $script:AuditPolicyHive.OpenSubKey($path) } catch { continue }
        if (-not $k) { continue }
        try {
            $key = "${Prefix}:" + $(if ($rel) { $rel } else { '.' })
            if (-not (Test-AuditIgnoredKey $key)) {
                $sb = [System.Text.StringBuilder]::new()
                $vals = [ordered]@{}
                foreach ($v in ($k.GetValueNames() | Sort-Object)) {
                    $name = if ($v -eq '') { '(default)' } else { $v }
                    $text = ConvertTo-AuditRegistryText ($k.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
                    $vals[$name] = $text
                    [void]$sb.Append($name).Append('=').Append($text).Append("`n")
                }
                $raw = $sb.ToString()
                if ($null -ne $RawSink) { $RawSink[$key] = $raw }
                if ($Reuse -and (Test-AuditKey $Reuse.Raws $key) -and (Test-AuditKey $Reuse.Entries $key) -and
                    ([string]$Reuse.Raws[$key] -ceq $raw)) {
                    $Snap[$key] = $Reuse.Entries[$key]
                } else {
                    $Snap[$key] = $vals
                }
            }
            foreach ($s in $k.GetSubKeyNames()) {
                if (-not $rel -and ($script:AuditHandledTopKeys -contains $s)) { continue }
                $stack.Push($(if ($rel) { "$rel\$s" } else { $s }))
            }
        } finally { $k.Close() }
    }
}

# Integrity hash of the baseline FILE content (entries + raw strings), exactly as it is serialised.
# It is stored in the log (baselineHash), so editing baseline.json afterwards is detectable.
function Get-AuditBaselineHash {
    param($Entries, $Raws)
    $json = (New-AuditSerializer).Serialize([ordered]@{ entries = $Entries; raws = $Raws })
    return Get-AuditSha256Hex $json
}

# Key test that works for Hashtable, OrderedDictionary and Dictionary<string,object>
# (the latter is what the JSON deserializer returns and has no public Contains()).
function Test-AuditKey {
    param($Dictionary, [string]$Key)
    if ($Dictionary -is [System.Collections.Hashtable] -or $Dictionary -is [System.Collections.Specialized.OrderedDictionary]) {
        return $Dictionary.Contains($Key)
    }
    return $Dictionary.ContainsKey($Key)
}

# Diff of two snapshots (maps key -> entry). Returns Added / Removed / Modified items.
function Compare-PolicySnapshot {
    param($Before, $After)
    if ($null -eq $Before) { $Before = [ordered]@{} }
    if ($null -eq $After)  { $After  = [ordered]@{} }
    $bd = $Before
    $ad = $After

    $keys = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($k in $bd.Keys) { [void]$keys.Add([string]$k) }
    foreach ($k in $ad.Keys) { [void]$keys.Add([string]$k) }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) {
        $hasB = Test-AuditKey $bd $k
        $hasA = Test-AuditKey $ad $k
        if ($hasA -and $hasB -and [object]::ReferenceEquals($bd[$k], $ad[$k])) { continue }   # reused, unchanged entry
        if ($hasB -and -not $hasA) {
            $out.Add([pscustomobject]@{ Key = $k; Op = 'Removed'; Before = $bd[$k]; After = $null; Changes = @() })
            continue
        }
        if ($hasA -and -not $hasB) {
            $out.Add([pscustomobject]@{ Key = $k; Op = 'Added'; Before = $null; After = $ad[$k]; Changes = @() })
            continue
        }
        $be = $bd[$k]
        $ae = $ad[$k]
        $fields = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $be.Keys) { if (-not $fields.Contains([string]$f)) { $fields.Add([string]$f) } }
        foreach ($f in $ae.Keys) { if (-not $fields.Contains([string]$f)) { $fields.Add([string]$f) } }
        $changes = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $fields) {
            $from = if (Test-AuditKey $be $f) { $be[$f] } else { $null }
            $to   = if (Test-AuditKey $ae $f) { $ae[$f] } else { $null }
            if ((ConvertTo-AuditCanon $from) -ne (ConvertTo-AuditCanon $to)) {
                $changes.Add([ordered]@{ field = $f; from = $from; to = $to })
            }
        }
        if ($changes.Count -gt 0) {
            $out.Add([pscustomobject]@{ Key = $k; Op = 'Modified'; Before = $be; After = $ae; Changes = $changes.ToArray() })
        }
    }
    return $out.ToArray()
}

# Applies diff items to the baseline maps (entries + raw strings). RawSource: key -> raw of the AFTER state.
function Update-AuditEntries {
    param($Entries, $Raws, $Items, [hashtable]$RawSource)
    foreach ($it in $Items) {
        if ($it.Op -eq 'Removed') {
            $Entries.Remove($it.Key)
            $Raws.Remove($it.Key)
        } else {
            $Entries[$it.Key] = $it.After
            if ($RawSource -and $RawSource.ContainsKey($it.Key)) { $Raws[$it.Key] = $RawSource[$it.Key] }
        }
    }
}

# ------------------------------------------------ log file: reading from the end

function Read-AuditFileTail {
    param([string]$Path, [long]$Window)
    $fs = New-Object System.IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $len = $fs.Length
        $start = [Math]::Max(0L, $len - $Window)
        $complete = ($start -eq 0)
        [void]$fs.Seek($start, [IO.SeekOrigin]::Begin)
        $buf = New-Object byte[] ($len - $start)
        $read = 0
        while ($read -lt $buf.Length) {
            $n = $fs.Read($buf, $read, $buf.Length - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        $text = $script:AuditUtf8.GetString($buf, 0, $read)
        $endsNl = ($read -gt 0 -and $buf[$read - 1] -eq 10)
    } finally { $fs.Dispose() }

    $lines = @($text -split "`n")
    if (-not $complete) {
        $lines = if ($lines.Count -le 1) { @() } else { @($lines[1..($lines.Count - 1)]) }   # first line is partial
    }
    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        $t = $l.TrimEnd("`r")
        if ($t.Trim() -ne '') { $clean.Add($t) }
    }
    return [pscustomobject]@{ Lines = $clean.ToArray(); Complete = $complete; EndsWithNewline = $endsNl }
}

# Parses one log line. Returns $null when it is not a record at all, otherwise an object with
# Valid (hash matches), Hash (claimed) and Obj (parsed JSON).
function ConvertFrom-AuditLine {
    param([string]$Line)
    $m = [regex]::Match($Line, ',"hash":"([0-9a-f]{64})"\}\s*$')
    if (-not $m.Success) { return $null }
    $claimed = $m.Groups[1].Value
    $body = $Line.Substring(0, $m.Index) + '}'
    $obj = $null
    try { $obj = ConvertFrom-Json -InputObject $body } catch { return $null }
    return [pscustomobject]@{
        Valid = ((Get-AuditSha256Hex $body) -eq $claimed)
        Hash  = $claimed
        Obj   = $obj
        Line  = $Line
    }
}

# Walks the newest log files backwards and returns the first VALID record accepted by the predicate.
function Find-AuditRecordFromEnd {
    param([scriptblock]$Predicate = { param($o) $true }, [int]$MaxFiles = 2)
    $files = @(Get-AuditFiles)
    [Array]::Reverse($files)
    $checked = 0
    foreach ($f in $files) {
        if ($checked -ge $MaxFiles) { break }
        if ((Get-Item -LiteralPath $f).Length -eq 0) { continue }
        $checked++
        foreach ($w in @(65536L, 4194304L, [long]::MaxValue)) {
            $t = Read-AuditFileTail -Path $f -Window $w
            $trailing = 0
            $seenValid = $false
            for ($i = $t.Lines.Count - 1; $i -ge 0; $i--) {
                $p = ConvertFrom-AuditLine $t.Lines[$i]
                if ($null -eq $p -or -not $p.Valid) {
                    if (-not $seenValid) { $trailing++ }
                    continue
                }
                $seenValid = $true
                if (& $Predicate $p.Obj) {
                    return [pscustomobject]@{
                        Obj = $p.Obj; Hash = $p.Hash; File = $f
                        TrailingInvalid = $trailing; EndsWithNewline = $t.EndsWithNewline
                    }
                }
            }
            if ($t.Complete) { break }
        }
    }
    return $null
}

# Last valid record of the newest log file = chain head. Genesis when there is no log yet.
# Fail-closed: a non-empty log without any valid record is reported as corrupt.
function Get-AuditTail {
    if ($null -ne $script:AuditTailCache) { return $script:AuditTailCache }
    $hasData = $false
    foreach ($f in @(Get-AuditFiles)) { if ((Get-Item -LiteralPath $f).Length -gt 0) { $hasData = $true } }
    if (-not $hasData) {
        return [pscustomobject]@{ Hash = $script:AuditZeroHash; Seq = 0L; TrailingInvalid = 0 }
    }
    $found = Find-AuditRecordFromEnd -MaxFiles 1
    if ($null -eq $found) {
        throw 'The audit log has no valid record at its end (corrupted or tampered). Run "Verify audit log integrity".'
    }
    $tail = [pscustomobject]@{ Hash = $found.Hash; Seq = [long]$found.Obj.seq; TrailingInvalid = $found.TrailingInvalid }
    $script:AuditTailCache = $tail
    return $tail
}

# ------------------------------------------------ log file: writing (hash chain)

# Appends one record. Caller must hold the lock.
function Add-AuditLine {
    param(
        [Parameter(Mandatory)][string]$Type,
        [System.Collections.IDictionary]$Fields,
        [string]$TxId = '',
        [string]$Initiator
    )
    $tail = Get-AuditTail
    $rec = [ordered]@{
        v        = $script:AuditSchemaVersion
        seq      = $tail.Seq + 1
        ts       = Get-AuditTimestamp
        host     = $env:COMPUTERNAME
        type     = $Type
        txid     = $TxId
        recorder = Get-AuditRecorder -Initiator $Initiator
    }
    if ($Fields) { foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] } }
    $rec['prev'] = $tail.Hash

    $body = ConvertTo-AuditJson $rec
    $hash = Get-AuditSha256Hex $body
    $line = $body.Substring(0, $body.Length - 1) + ',"hash":"' + $hash + '"}'

    $path = Get-AuditFile 'Log'
    $prefix = ''
    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 0) {
        $chk = New-Object System.IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { [void]$chk.Seek(-1, [IO.SeekOrigin]::End); if ($chk.ReadByte() -ne 10) { $prefix = "`n" } } finally { $chk.Dispose() }
    }
    $bytes = $script:AuditUtf8.GetBytes($prefix + $line + "`n")
    $fs = New-Object System.IO.FileStream($path, [IO.FileMode]::Append, [IO.FileAccess]::Write,
        [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try {
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush($true)
    } finally { $fs.Dispose() }

    $script:AuditTailCache = [pscustomobject]@{ Hash = $hash; Seq = [long]$rec['seq']; TrailingInvalid = 0 }
    return [pscustomobject]@{ Hash = $hash; Seq = [long]$rec['seq']; Ts = $rec['ts'] }
}

# Size-based rotation; the chain continues across files (first record of the new file carries
# the hash of the last record of the previous one).
function Invoke-AuditRotation {
    $tail = Get-AuditTail
    $lastBaseline = $null
    $f = Find-AuditRecordFromEnd -Predicate { param($o) [bool]$o.baselineHash } -MaxFiles 1
    if ($f) { $lastBaseline = [string]$f.Obj.baselineHash }

    $log = Get-AuditFile 'Log'
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfff', [Globalization.CultureInfo]::InvariantCulture)
    $dest = Join-Path $script:AuditDir "audit-$stamp.jsonl"
    $n = 0
    while (Test-Path -LiteralPath $dest) { $n++; $dest = Join-Path $script:AuditDir "audit-$stamp-$n.jsonl" }
    Move-Item -LiteralPath $log -Destination $dest -ErrorAction Stop
    [void](Add-AuditLine -Type 'rotation' -Fields ([ordered]@{
        rotatedTo = (Split-Path -Leaf $dest); previousSeq = $tail.Seq; baselineHash = $lastBaseline
    }))
}

# Public writer. Throws when the record cannot be persisted (callers decide what that means).
function Write-AuditRecord {
    param(
        [Parameter(Mandatory)][string]$Type,
        [System.Collections.IDictionary]$Fields,
        [string]$TxId = '',
        [string]$Initiator
    )
    Enter-AuditLock
    try {
        Initialize-AuditStore
        $log = Get-AuditFile 'Log'
        if ((Test-Path -LiteralPath $log) -and (Get-Item -LiteralPath $log).Length -ge $script:AuditMaxBytes) {
            Invoke-AuditRotation
        }
        while ($script:AuditNotices.Count -gt 0) {
            $notice = $script:AuditNotices[0]
            $script:AuditNotices = @($script:AuditNotices | Select-Object -Skip 1)
            [void](Add-AuditLine -Type 'integrity' -Initiator $Initiator -Fields $notice)
        }
        $tail = Get-AuditTail
        if ($tail.TrailingInvalid -gt 0) {
            [void](Add-AuditLine -Type 'integrity' -Initiator $Initiator -Fields ([ordered]@{
                issue = 'torn-write'
                detail = "$($tail.TrailingInvalid) unparsable line(s) found after the last valid record (interrupted write?)"
            }))
        }
        return (Add-AuditLine -Type $Type -Fields $Fields -TxId $TxId -Initiator $Initiator)
    } finally { Exit-AuditLock }
}

# ------------------------------------------------------------------- baseline

function Read-AuditBaseline {
    $path = Get-AuditFile 'Baseline'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $ser = New-AuditSerializer
        $obj = $ser.DeserializeObject([IO.File]::ReadAllText($path, $script:AuditUtf8))
        $entries = [ordered]@{}
        foreach ($k in $obj['entries'].Keys) { $entries[[string]$k] = $obj['entries'][$k] }
        $raws = [ordered]@{}
        if ($obj.ContainsKey('raws')) { foreach ($k in $obj['raws'].Keys) { $raws[[string]$k] = [string]$obj['raws'][$k] } }
        $schema = 1
        if ($obj.ContainsKey('v')) { $schema = [int]$obj['v'] }
        return [pscustomobject]@{
            Corrupt = $false; Entries = $entries; Raws = $raws; Schema = $schema
            StoredHash = [string]$obj['hash']; Ts = (ConvertTo-AuditDate $obj['ts'])
        }
    } catch {
        return [pscustomobject]@{ Corrupt = $true; Error = $_.Exception.Message }
    }
}

function Save-AuditBaseline {
    param($Entries, $Raws, [string]$Hash, [DateTime]$Ts)
    $path = Get-AuditFile 'Baseline'
    $obj = [ordered]@{
        v = $script:AuditBaselineSchema; ts = $Ts.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        hash = $Hash; count = $Entries.Count; entries = $Entries; raws = $Raws
    }
    $json = (New-AuditSerializer).Serialize($obj)
    $tmp = "$path.tmp"
    [IO.File]::WriteAllText($tmp, $json, $script:AuditUtf8)
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $path) }
}

# Loads the baseline (creating it from the live policy when missing/corrupt) and checks it against
# the hash stored in the log. Caller must hold the lock.
function Get-AuditBaselineState {
    $loaded = Read-AuditBaseline
    $upgrade = [bool]($loaded -and -not $loaded.Corrupt -and $loaded.Schema -lt $script:AuditBaselineSchema)
    if ($loaded -and -not $loaded.Corrupt -and -not $upgrade) {
        $computed = Get-AuditBaselineHash -Entries $loaded.Entries -Raws $loaded.Raws
        if ($loaded.StoredHash -ne $computed) {
            [void](Write-AuditRecord -Type 'integrity' -Fields ([ordered]@{
                issue = 'baseline-file-modified'
                detail = "baseline.json content hash $computed differs from the hash stored inside the file ($($loaded.StoredHash))"
            }))
        }
        $last = Find-AuditRecordFromEnd -Predicate { param($o) [bool]$o.baselineHash } -MaxFiles 2
        if ($last -and ([string]$last.Obj.baselineHash -ne $computed)) {
            [void](Write-AuditRecord -Type 'integrity' -Fields ([ordered]@{
                issue = 'baseline-log-mismatch'
                detail = "baseline.json hash $computed differs from the last baselineHash in the log ($($last.Obj.baselineHash)); baseline edited, or a previous run was interrupted"
            }))
        }
        return [pscustomobject]@{ Entries = $loaded.Entries; Raws = $loaded.Raws; Ts = $loaded.Ts; Created = $false }
    }

    $why = if ($upgrade) { 'schema-upgrade' } elseif ($null -eq $loaded) { 'missing' } else { "corrupt: $($loaded.Error)" }
    $ts = [DateTime]::UtcNow
    $raws = @{}
    $snap = Get-PolicySnapshot -Scope All -RawSink $raws
    $rawOrdered = [ordered]@{}
    foreach ($k in ($raws.Keys | Sort-Object)) { $rawOrdered[$k] = $raws[$k] }
    $hash = Get-AuditBaselineHash -Entries $snap -Raws $rawOrdered
    [void](Write-AuditRecord -Type 'baseline' -Fields ([ordered]@{
        reason = $why; schema = $script:AuditBaselineSchema; objectCount = $snap.Count
        ruleCount = @($snap.Keys | Where-Object { $_.StartsWith('rule:') }).Count
        ignoredKeys = [string[]]@($script:AuditIgnoreKeys)
        baselineHash = $hash
    }))
    Save-AuditBaseline -Entries $snap -Raws $rawOrdered -Hash $hash -Ts $ts
    return [pscustomobject]@{ Entries = $snap; Raws = $rawOrdered; Ts = $ts; Created = $true }
}

# -------------------------------------- attribution of external changes (event log)

function Get-AuditEventKind {
    param([int]$Id)
    foreach ($k in $script:AuditEventIds.Keys) { if ($script:AuditEventIds[$k] -contains $Id) { return $k } }
    return $null
}

function Get-AuditEventIndex {
    param([DateTime]$Since)
    $idx = [pscustomobject]@{ Available = $true; Rules = @{}; AllDeleted = @(); Settings = @() }
    $ids = @($script:AuditEventIds.Values | ForEach-Object { $_ }) | Sort-Object -Unique
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $script:AuditEventLog; Id = $ids; StartTime = $Since.ToLocalTime()
        } -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $idx.Available = $false }
        return $idx
    }
    foreach ($ev in ($events | Sort-Object TimeCreated)) {
        $data = @{}
        try {
            $xml = [xml]$ev.ToXml()
            foreach ($d in $xml.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
        } catch { continue }
        $kind = Get-AuditEventKind -Id $ev.Id
        $rec = [pscustomobject]@{
            Id = $ev.Id; Kind = $kind; Time = $ev.TimeCreated.ToUniversalTime()
            RuleId = $data['RuleId']; RuleName = $data['RuleName']
            Sid = $data['ModifyingUser']; App = $data['ModifyingApplication']
        }
        switch ($kind) {
            'AllDeleted' { $idx.AllDeleted += $rec }
            'Setting'    { $idx.Settings += $rec }
            default {
                if ($rec.RuleId) {
                    if (-not $idx.Rules.ContainsKey($rec.RuleId)) { $idx.Rules[$rec.RuleId] = @() }
                    $idx.Rules[$rec.RuleId] += $rec
                }
            }
        }
    }
    return $idx
}

function New-AuditEventActor {
    param($Event, [string]$Evidence = 'eventlog', [string]$Confidence = '')
    $a = [ordered]@{
        user = (Resolve-AuditSid $Event.Sid); sid = $Event.Sid; application = $Event.App
        evidence = $Evidence; eventId = $Event.Id
        eventTime = $Event.Time.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Confidence) { $a['confidence'] = $Confidence }
    return $a
}

# Returns key -> actor for the given diff items.
function Resolve-AuditActors {
    param($Items, [DateTime]$Since)
    $result = @{}
    $idx = Get-AuditEventIndex -Since $Since
    $now = [DateTime]::UtcNow
    foreach ($it in $Items) {
        $actor = $null
        if ($it.Key.StartsWith('rule:')) {
            $rid = $it.Key.Substring(5)
            $cands = @()
            if ($idx.Rules.ContainsKey($rid)) { $cands = @($idx.Rules[$rid]) }
            if ($cands.Count -gt 0) {
                $pref = switch ($it.Op) { 'Added' { 'Added' } 'Removed' { 'Deleted' } default { 'Modified' } }
                $match = @($cands | Where-Object { $_.Kind -eq $pref })
                $ev = if ($match.Count -gt 0) { $match[-1] } else { $cands[-1] }
                $actor = New-AuditEventActor $ev
            } elseif ($it.Op -eq 'Removed' -and $idx.AllDeleted.Count -gt 0) {
                # one 'delete all' event, many removed rules: a correlation guess, never proof
                $actor = New-AuditEventActor $idx.AllDeleted[-1] -Evidence 'bulk-delete-correlation' -Confidence 'low'
            }
        } elseif ((Get-AuditKeyFamily $it.Key).Gpo) {
            $actor = $null   # Group Policy changes are applied by the policy engine; the key location is the evidence
        } elseif ($idx.Settings.Count -gt 0 -and (Get-AuditKeyFamily $it.Key).Shape -ne 'rule') {
            $pairs = @($idx.Settings | ForEach-Object { "$($_.Sid)|$($_.App)" } | Sort-Object -Unique)
            if ($pairs.Count -eq 1) { $actor = New-AuditEventActor $idx.Settings[-1] }
        }
        if ($null -eq $actor) {
            $actor = [ordered]@{
                user = 'unknown'; sid = $null; application = $null
                evidence = $(if ($idx.Available) { 'none' } else { 'eventlog-unavailable' })
                window = [ordered]@{
                    from = $Since.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    to   = $now.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                }
            }
        }
        $result[$it.Key] = $actor
    }
    return $result
}

# Describes a snapshot key: Kind (as written in the log), Shape (rule|profile|setting), Gpo (Group Policy store).
function Get-AuditKeyFamily {
    param([string]$Key)
    $prefix = $Key.Substring(0, [Math]::Max(0, $Key.IndexOf(':')))
    switch ($prefix) {
        'rule'       { return [pscustomobject]@{ Kind = 'rule';        Shape = 'rule';    Gpo = $false } }
        'consec'     { return [pscustomobject]@{ Kind = 'consec';      Shape = 'rule';    Gpo = $false } }
        'gporule'    { return [pscustomobject]@{ Kind = 'gpo-rule';    Shape = 'rule';    Gpo = $true } }
        'gpoconsec'  { return [pscustomobject]@{ Kind = 'gpo-consec';  Shape = 'rule';    Gpo = $true } }
        'profile'    { return [pscustomobject]@{ Kind = 'profile';     Shape = 'profile'; Gpo = $false } }
        'gpoprofile' { return [pscustomobject]@{ Kind = 'gpo-profile'; Shape = 'profile'; Gpo = $true } }
        'gposetting' { return [pscustomobject]@{ Kind = 'gpo-setting'; Shape = 'setting'; Gpo = $true } }
        default      { return [pscustomobject]@{ Kind = 'setting';     Shape = 'setting'; Gpo = $false } }
    }
}

# Applications whose changes under a system account are treated as Windows itself (MpsSvc runs in svchost).
# SYSTEM running powershell.exe / netsh.exe / cmd.exe is NOT Windows: it is 'external'.
$script:AuditSystemApps = @('svchost.exe', 'services.exe', 'lsass.exe')

function Test-AuditSystemActor {
    param($Actor)
    $sid = [string]$Actor.sid
    $app = [string]$Actor.application
    $sysSid = ($sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) -or $sid.StartsWith('S-1-5-80-')
    if (-not $sysSid -or $app.Length -eq 0) { return $false }
    foreach ($name in $script:AuditSystemApps) {
        if ($app -ieq (Join-Path $env:SystemRoot "System32\$name")) { return $true }
    }
    return $false
}

# source = what made the change:
#   gpo      the key lives in the Group Policy store (decided by the registry location, not by a name)
#   system   event log proves a system account AND an allow-listed Windows service binary
#   external anything else (GUI, netsh, other admins, SYSTEM running a shell, unknown). 'oso' is set by the wrapper.
# A name that looks like a Windows resource string ('@FirewallAPI.dll,-1') is NOT evidence: anybody can use it.
function Get-AuditChangeSource {
    param($Item, $Actor)
    if ((Get-AuditKeyFamily $Item.Key).Gpo) { return 'gpo' }
    if ($Actor.evidence -eq 'eventlog' -and (Test-AuditSystemActor $Actor)) { return 'system' }
    return 'external'
}

function Write-AuditChange {
    param($Item, [string]$Detection, [string]$Source, $Actor, [string]$TxId, [string]$Initiator, [string[]]$Related = @(), [string]$Attribution = '')
    $family = Get-AuditKeyFamily $Item.Key
    $id = $Item.Key.Substring($Item.Key.IndexOf(':') + 1)
    $entry = if ($Item.After) { $Item.After } else { $Item.Before }
    $f = [ordered]@{
        op = $Item.Op
        kind = $family.Kind
    }
    switch ($family.Shape) {
        'rule' {
            $f['ruleId'] = $id
            $dn = [string]$entry['displayName']
            $f['displayName'] = $dn
            if ($dn.StartsWith('@')) {
                $f['displayNameResolved'] = Resolve-AuditResourceString $dn
                # a hint only: anyone can name a rule like a Windows resource string
                if ($f['displayNameResolved'] -ne $dn) { $f['hint'] = 'builtin-resource-name' }
            }
        }
        'profile' { $f['profile'] = $id }
        default   { $f['path'] = $id }
    }
    $f['source'] = $Source
    $f['detection'] = $Detection
    if ($Attribution) { $f['attribution'] = $Attribution }
    $f['actor'] = $Actor
    $f['before'] = $Item.Before
    $f['after'] = $Item.After
    $f['changes'] = @($Item.Changes)
    if ($Related.Count -gt 0) { $f['relatedTxids'] = [string[]]$Related }
    [void](Write-AuditRecord -Type 'change' -TxId $TxId -Initiator $Initiator -Fields $f)
}

# ------------------------------------------------------- the audited-change wrapper

# ------------------------------------------------ fail policy (settings.json) and pending markers

function Get-AuditSettingsPath { Join-Path $script:AuditDir 'settings.json' }
function Get-AuditPendingPath  { Join-Path $script:AuditDir 'pending.jsonl' }

function Get-AuditSettingsHash {
    param([string]$Policy, [string]$Ts, [string]$By)
    return Get-AuditSha256Hex "v=1|failPolicy=$Policy|ts=$Ts|by=$By"
}

# Effective fail policy. Only a settings file that is consistent with the audit log can turn it to Open;
# anything suspicious (edited file, missing log entry, unreadable file) means Closed.
function Get-AuditFailPolicy {
    $res = [pscustomobject]@{ Policy = 'Closed'; Source = 'default'; Tampered = $false; Unverified = $false }
    try {
        $path = Get-AuditSettingsPath
        if (-not (Test-Path -LiteralPath $path)) { return $res }
        $o = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path, $script:AuditUtf8))
        $res.Source = 'file'
        if ([string]$o.failPolicy -ne 'Open') { return $res }
        $ok = ([string]$o.hash -eq (Get-AuditSettingsHash -Policy 'Open' -Ts ([string]$o.ts) -By ([string]$o.by)))
        if ($ok) {
            $logReadable = $true
            try { $rec = Find-AuditRecordFromEnd -Predicate { param($x) $x.type -eq 'setting' } -MaxFiles 3 } catch { $logReadable = $false }
            if ($logReadable) {
                $ok = [bool]($rec -and [string]$rec.Obj.settingsHash -eq [string]$o.hash -and [string]$rec.Obj.newValue -eq 'Open')
            } else {
                # The log cannot be read right now - which is exactly when fail-open matters. A self-consistent
                # file is accepted but marked Unverified; the next sync cross-checks it against the log.
                $res.Unverified = $true
            }
        }
        if ($ok) { $res.Policy = 'Open'; return $res }
        $res.Tampered = $true; $res.Source = 'tampered'
    } catch {
        $res.Tampered = $true; $res.Source = 'unreadable'
    }
    if ($res.Tampered -and -not $script:AuditSettingsTamperNoted) {
        $script:AuditSettingsTamperNoted = $true
        $script:AuditNotices += ,([ordered]@{ issue = 'settings-file-modified'; detail = 'settings.json asks for fail-open but does not match the audit log (edited or unreadable); fail-closed is used.' })
    }
    return $res
}

# Changes the persisted fail policy. The change is written to the audit log FIRST (so it is attributable and
# the file can be cross-checked), then to settings.json.
function Set-AuditFailPolicy {
    param([Parameter(Mandatory)][ValidateSet('Closed', 'Open')][string]$Policy, [string]$Reason)
    Enter-AuditLock
    try {
        Initialize-AuditStore
        $old = (Get-AuditFailPolicy).Policy
        $ts = Get-AuditTimestamp
        $by = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $hash = Get-AuditSettingsHash -Policy $Policy -Ts $ts -By $by
        [void](Write-AuditRecord -Type 'setting' -Fields ([ordered]@{
            setting = 'failPolicy'; oldValue = $old; newValue = $Policy; settingsHash = $hash; reason = $Reason
        }))
        $path = Get-AuditSettingsPath
        $json = ConvertTo-AuditJson ([ordered]@{ v = 1; failPolicy = $Policy; ts = $ts; by = $by; hash = $hash })
        $tmp = "$path.tmp"
        [IO.File]::WriteAllText($tmp, $json, $script:AuditUtf8)
        if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value) } else { [IO.File]::Move($tmp, $path) }
        $script:AuditSettingsTamperNoted = $false
    } finally { Exit-AuditLock }
}

# Marker for a change that was performed while the audit trail was unavailable (fail-open).
function Add-AuditPending {
    param([string]$TxId, [string]$Operation, [string]$Scope, [string[]]$Names, [string]$Reason, [string]$Why)
    $rec = [ordered]@{
        ts = Get-AuditTimestamp; txid = $TxId; operation = $Operation; scope = $Scope
        names = [string[]]@($Names); reason = $Reason; why = $Why
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name; pid = $PID
    }
    $line = (ConvertTo-AuditJson $rec) + "`n"
    $done = $false
    try {
        [IO.File]::AppendAllText((Get-AuditPendingPath), $line, $script:AuditUtf8)
        $done = $true
    } catch { }
    if (-not $done -and $script:AuditEventLogFallback) {
        try {
            if (-not [Diagnostics.EventLog]::SourceExists('FirewallAudit')) { New-EventLog -LogName Application -Source 'FirewallAudit' }
            [Diagnostics.EventLog]::WriteEntry('FirewallAudit', "UNLOGGED firewall change (fail-open): $line", [Diagnostics.EventLogEntryType]::Warning, 4001)
        } catch { }
    }
}

function Read-AuditPending {
    $path = Get-AuditPendingPath
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $out = @()
    foreach ($l in [IO.File]::ReadAllLines($path, $script:AuditUtf8)) {
        if ($l.Trim() -eq '') { continue }
        try { $out += ,(ConvertFrom-Json -InputObject $l) } catch { $out += ,([pscustomobject]@{ txid = ''; operation = '?'; why = "unparsable marker: $l" }) }
    }
    return @($out)
}

function Write-AuditPendingRecords {
    param($Pending)
    foreach ($p in @($Pending)) {
        [void](Write-AuditRecord -Type 'integrity' -TxId ([string]$p.txid) -Fields ([ordered]@{
            issue = 'unlogged-change'
            detail = "A change ($($p.operation), scope $($p.scope)) was performed without an audit trail (fail-open): $($p.why). Real changes, if they could be detected, are recorded as reconcile/watcher changes."
            markerTs = $p.ts; markerUser = $p.user; operation = $p.operation; names = $p.names; reason = $p.reason
        }))
    }
}

# Removes the first $Count markers (the ones that were just processed); markers added meanwhile stay.
function Clear-AuditPending {
    param([int]$Count)
    $path = Get-AuditPendingPath
    if (-not (Test-Path -LiteralPath $path)) { return }
    $lines = @([IO.File]::ReadAllLines($path, $script:AuditUtf8) | Where-Object { $_.Trim() -ne '' })
    $rest = @($lines | Select-Object -Skip $Count)
    if ($rest.Count -eq 0) { Remove-Item -LiteralPath $path -Force } else { [IO.File]::WriteAllLines($path, $rest, $script:AuditUtf8) }
}

# Is this diff item what the caller DECLARED it would change? Anything else is a 'scope-escape'.
function Test-AuditInScope {
    param($Item, [string]$Scope, [string[]]$Names)
    switch ($Scope) {
        'All'      { return $true }
        'Profiles' { return $Item.Key.StartsWith('profile:') }
        'NewRules' { return ($Item.Op -eq 'Added' -and ($Item.Key.StartsWith('rule:') -or $Item.Key.StartsWith('consec:'))) }
        default    { foreach ($n in $Names) { if ($Item.Key -ceq "rule:$n") { return $true } }; return $false }
    }
}

function Invoke-AuditedChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [ValidateSet('Names', 'NewRules', 'Profiles', 'All')][string]$Scope = 'Names',
        [string[]]$Names = @(),
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Initiator,
        [string]$Reason,
        [System.Collections.IDictionary]$Details,
        # What to do when the audit trail cannot be written BEFORE the change:
        #   Closed  the change is NOT performed (default; the audit guarantee wins)
        #   Open    the change is performed, a marker is queued and the next sync reconciles it
        #   Default follow the persisted setting (menu 8 -> [F]); Closed when there is none
        [ValidateSet('Default', 'Closed', 'Open')][string]$FailPolicy = 'Default'
    )
    $auditErr = $null
    $auditOut = $null
    $auditTx = [guid]::NewGuid().ToString()
    $auditWarn = @()
    $auditDiff = @()
    $auditLogErr = $null
    $auditFailOpen = $false
    $auditPrepErr = $null
    $auditPolicy = if ($FailPolicy -eq 'Default') { (Get-AuditFailPolicy).Policy } else { $FailPolicy }

    try { Enter-AuditLock } catch {
        $auditPrepErr = $_.Exception.Message
        if ($auditPolicy -ne 'Open') { throw "Audit log unavailable - the change was NOT performed. $auditPrepErr" }
        $auditFailOpen = $true
    }
    try {
        # Everything up to and including the write-ahead 'intent' record is the PREPARE phase:
        # if any of it fails (log unwritable, corrupt, locked...) the change is NOT executed
        # (fail-closed) unless the fail policy is Open.
        if (-not $auditFailOpen) {
          try {
            Initialize-AuditStore
            $auditWatch = [Diagnostics.Stopwatch]::StartNew()
            $auditBl = Get-AuditBaselineState
            $auditEntries = $auditBl.Entries

            # ---- state before the change: the WHOLE policy (unchanged objects are reused from the
            # baseline, so this costs about a second). -Scope only says which changes are EXPECTED.
            $auditRawBefore = @{}
            $auditBefore = Get-PolicySnapshot -Scope All -RawSink $auditRawBefore -Reuse $auditBl

            # ---- write-ahead record
            if ($Details -and $Details.Contains('expectedDisplayName') -and $Scope -eq 'Names' -and $Names.Count -eq 1) {
                $auditKey = "rule:$($Names[0])"
                if (-not (Test-AuditKey $auditBefore $auditKey)) {
                    $auditWarn += 'rule no longer exists at execution time'
                } elseif ([string]$auditBefore[$auditKey]['displayName'] -ne [string]$Details['expectedDisplayName']) {
                    $auditWarn += "rule changed since it was listed (expected '$($Details['expectedDisplayName'])', found '$($auditBefore[$auditKey]['displayName'])')"
                }
            }
            [void](Write-AuditRecord -Type 'intent' -TxId $auditTx -Initiator $Initiator -Fields ([ordered]@{
                operation = $Operation; scope = $Scope; names = [string[]]@($Names)
                reason = $Reason; details = $Details; warnings = [string[]]@($auditWarn)
            }))

            # ---- drift: ANY change made behind our back since the last baseline (not only the objects we touch)
            $auditDrift = @(Compare-PolicySnapshot -Before $auditEntries -After $auditBefore)
            if ($auditDrift.Count -gt 0) {
                $auditSince = if ($auditBl.Ts) { $auditBl.Ts.AddSeconds(-120) } else { [DateTime]::UtcNow.AddDays(-7) }
                $auditActors = Resolve-AuditActors -Items $auditDrift -Since $auditSince
                foreach ($auditD in $auditDrift) {
                    $auditA = $auditActors[$auditD.Key]
                    Write-AuditChange -Item $auditD -Detection 'pre-change' -Source (Get-AuditChangeSource $auditD $auditA) `
                        -Actor $auditA -TxId $auditTx -Initiator $Initiator
                }
                Update-AuditEntries -Entries $auditEntries -Raws $auditBl.Raws -Items $auditDrift -RawSource $auditRawBefore
            }
          } catch {
            $auditPrepErr = $_.Exception.Message
            if ($auditPolicy -ne 'Open') { throw "Audit log unavailable - the change was NOT performed. $auditPrepErr" }
            $auditFailOpen = $true
          }
        }

        if ($auditFailOpen) {
            # Fail-open: queue a marker (the next sync turns it into an integrity record), warn loudly, go on.
            Add-AuditPending -TxId $auditTx -Operation $Operation -Scope $Scope -Names $Names -Reason $Reason -Why $auditPrepErr
            $auditWarn += "audit trail unavailable, change performed anyway (fail policy Open): $auditPrepErr"
            Write-Warning "AUDIT FAIL-OPEN: the audit trail is unavailable ($auditPrepErr). The change is performed and will be reconciled by the next audit sync."
        }

        # ---- the change itself
        try { $auditOut = & $Action } catch { $auditErr = $_ }

        # ---- state after the change; the log reflects what REALLY changed
        if (-not $auditFailOpen) {
        $auditSnapTime = [DateTime]::UtcNow
        $auditRawAfter = @{}
        $auditAfter = Get-PolicySnapshot -Scope All -RawSink $auditRawAfter -Reuse $auditBl
        $auditDiff = @(Compare-PolicySnapshot -Before $auditBefore -After $auditAfter)
        $auditEscapes = @($auditDiff | Where-Object { -not (Test-AuditInScope -Item $_ -Scope $Scope -Names $Names) })

        try {
            $auditActor = Get-AuditScriptActor -Initiator $Initiator
            foreach ($auditD in $auditDiff) {
                $auditEsc = $auditEscapes -contains $auditD
                $auditFam = Get-AuditKeyFamily $auditD.Key
                Write-AuditChange -Item $auditD -Detection $(if ($auditEsc) { 'scope-escape' } else { 'script' }) `
                    -Source $(if ($auditFam.Gpo) { 'gpo' } else { 'oso' }) -Actor $auditActor `
                    -Attribution $(if ($auditEsc) { 'inferred-window' } else { '' }) -TxId $auditTx -Initiator $Initiator
            }
            if ($auditEscapes.Count -gt 0) {
                $auditWarn += "$($auditEscapes.Count) change(s) outside the declared scope '$Scope' (logged as scope-escape)"
            }
            Update-AuditEntries -Entries $auditEntries -Raws $auditBl.Raws -Items $auditDiff -RawSource $auditRawAfter
            $auditBh = Get-AuditBaselineHash -Entries $auditEntries -Raws $auditBl.Raws
            [void](Write-AuditRecord -Type 'result' -TxId $auditTx -Initiator $Initiator -Fields ([ordered]@{
                operation = $Operation
                status = $(if ($auditErr) { 'failed' } else { 'success' })
                error = $(if ($auditErr) { $auditErr.Exception.Message } else { $null })
                counts = [ordered]@{
                    added = @($auditDiff | Where-Object Op -eq 'Added').Count
                    removed = @($auditDiff | Where-Object Op -eq 'Removed').Count
                    modified = @($auditDiff | Where-Object Op -eq 'Modified').Count
                    drift = $auditDrift.Count
                    scopeEscapes = $auditEscapes.Count
                }
                warnings = [string[]]@($auditWarn)
                durationMs = [int]$auditWatch.ElapsedMilliseconds
                baselineHash = $auditBh
            }))
            Save-AuditBaseline -Entries $auditEntries -Raws $auditBl.Raws -Hash $auditBh -Ts $auditSnapTime
        } catch {
            $auditLogErr = $_.Exception.Message
        }
        if ($auditLogErr) {
            Write-Warning ("AUDIT: the change was applied but its audit record could not be completed ($auditLogErr). " +
                'It will be recovered by the next audit sync.')
        }
        }   # end of: if (-not $auditFailOpen)
    } finally { Exit-AuditLock }

    if ($auditErr) { throw $auditErr }
    return [pscustomobject]@{
        Success = $true; TxId = $auditTx; Changes = $auditDiff
        Added = @($auditDiff | Where-Object Op -eq 'Added').Count
        Removed = @($auditDiff | Where-Object Op -eq 'Removed').Count
        Modified = @($auditDiff | Where-Object Op -eq 'Modified').Count
        AuditWarning = $auditLogErr; Warnings = $auditWarn; FailOpen = $auditFailOpen
    }
}

# ---------------------------------------------------------- sync / reconcile

# Intents that have no matching result (process killed, Ctrl+C, power loss).
function Get-AuditDanglingIntents {
    $files = @(Get-AuditFiles)
    [Array]::Reverse($files)
    foreach ($f in $files) {
        if ((Get-Item -LiteralPath $f).Length -eq 0) { continue }
        $t = Read-AuditFileTail -Path $f -Window 8388608L
        $intents = [ordered]@{}
        $done = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in $t.Lines) {
            $p = ConvertFrom-AuditLine $line
            if ($null -eq $p -or -not $p.Valid) { continue }
            $o = $p.Obj
            if ($o.type -eq 'intent' -and $o.txid) { $intents[[string]$o.txid] = $o }
            elseif ($o.type -eq 'result' -and $o.txid) { [void]$done.Add([string]$o.txid) }
        }
        return @($intents.Keys | Where-Object { -not $done.Contains($_) } | ForEach-Object { $intents[$_] })
    }
    return @()
}

# Compares the live policy with the baseline and records every difference.
# Trigger: manual (menu) | startup (menu start) | task (watcher).
function Invoke-AuditSync {
    [CmdletBinding()]
    param([ValidateSet('manual', 'startup', 'task')][string]$Trigger = 'manual', [switch]$Quiet)

    $summary = [pscustomobject]@{ Created = $false; Added = 0; Removed = 0; Modified = 0; Recovered = 0; Total = 0; Pending = 0 }
    Enter-AuditLock
    try {
        Initialize-AuditStore
        [void](Get-AuditFailPolicy)          # cross-checks settings.json against the log; a mismatch becomes a notice
        $auditBl = Get-AuditBaselineState
        if ($auditBl.Created) {
            # the baseline is taken from the CURRENT policy, so earlier unlogged changes can only be reported as markers
            $auditPendingNow = @(Read-AuditPending)
            if ($auditPendingNow.Count -gt 0) {
                Write-AuditPendingRecords $auditPendingNow
                Clear-AuditPending -Count $auditPendingNow.Count
                $summary.Pending = $auditPendingNow.Count
            }
            $summary.Created = $true
            $summary.Total = $auditBl.Entries.Count
            if (-not $Quiet) { Write-Host "Audit baseline created ($($auditBl.Entries.Count) policy objects)." -ForegroundColor Green }
            return $summary
        }

        $auditSnapTime = [DateTime]::UtcNow
        $auditRawNow = @{}
        $auditCurrent = Get-PolicySnapshot -Scope All -RawSink $auditRawNow -Reuse $auditBl
        $auditDiff = @(Compare-PolicySnapshot -Before $auditBl.Entries -After $auditCurrent)
        $auditDangling = @(Get-AuditDanglingIntents)
        $auditTx = [guid]::NewGuid().ToString()
        $auditSince = if ($auditBl.Ts) { $auditBl.Ts.AddSeconds(-120) } else { [DateTime]::UtcNow.AddDays(-7) }
        $auditActors = if ($auditDiff.Count -gt 0) { Resolve-AuditActors -Items $auditDiff -Since $auditSince } else { @{} }

        foreach ($auditI in $auditDangling) {
            [void](Write-AuditRecord -Type 'result' -TxId ([string]$auditI.txid) -Fields ([ordered]@{
                operation = $auditI.operation; status = 'recovered'
                note = 'No result was recorded (process interrupted?). Real changes, if any, are recorded below as reconcile/watcher detections.'
            }))
        }
        # changes performed while the audit trail was unavailable (fail-open): one integrity record each
        $auditPending = @(Read-AuditPending)
        Write-AuditPendingRecords $auditPending
        $auditRelated = [string[]]@(@($auditDangling | ForEach-Object { [string]$_.txid }) + @($auditPending | ForEach-Object { [string]$_.txid }) | Where-Object { $_ })
        $auditDet = if ($Trigger -eq 'task') { 'watcher' } else { 'reconcile' }
        foreach ($auditD in $auditDiff) {
            $auditA = $auditActors[$auditD.Key]
            Write-AuditChange -Item $auditD -Detection $auditDet -Source (Get-AuditChangeSource $auditD $auditA) `
                -Actor $auditA -TxId $auditTx -Related $auditRelated
        }

        $auditRawOrdered = [ordered]@{}
        foreach ($auditK in ($auditRawNow.Keys | Sort-Object)) { $auditRawOrdered[$auditK] = $auditRawNow[$auditK] }
        $auditBh = Get-AuditBaselineHash -Entries $auditCurrent -Raws $auditRawOrdered
        $summary.Added = @($auditDiff | Where-Object Op -eq 'Added').Count
        $summary.Removed = @($auditDiff | Where-Object Op -eq 'Removed').Count
        $summary.Modified = @($auditDiff | Where-Object Op -eq 'Modified').Count
        $summary.Recovered = $auditDangling.Count
        $summary.Total = $auditCurrent.Count

        if ($auditDiff.Count -gt 0 -or $auditDangling.Count -gt 0 -or $auditPending.Count -gt 0 -or $Trigger -eq 'manual') {
            $unattributed = @($auditDiff | Where-Object { $auditActors[$_.Key].evidence -ne 'eventlog' }).Count
            [void](Write-AuditRecord -Type 'sync' -TxId $auditTx -Fields ([ordered]@{
                trigger = $Trigger
                window = [ordered]@{
                    from = $auditSince.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    to = $auditSnapTime.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                }
                counts = [ordered]@{ added = $summary.Added; removed = $summary.Removed; modified = $summary.Modified }
                unattributed = $unattributed; recoveredIntents = $auditDangling.Count
                objects = $auditCurrent.Count; baselineHash = $auditBh
            }))
            Save-AuditBaseline -Entries $auditCurrent -Raws $auditRawOrdered -Hash $auditBh -Ts $auditSnapTime
        }
        if ($auditPending.Count -gt 0) { Clear-AuditPending -Count $auditPending.Count }
        $summary.Pending = $auditPending.Count
    } finally { Exit-AuditLock }

    if (-not $Quiet) {
        $color = if (($summary.Added + $summary.Removed + $summary.Modified) -gt 0) { 'Yellow' } else { 'Green' }
        Write-Host ("Audit sync: {0} added, {1} removed, {2} modified outside this tool; {3} interrupted operation(s) recovered; {4} objects checked." -f
            $summary.Added, $summary.Removed, $summary.Modified, $summary.Recovered, $summary.Total) -ForegroundColor $color
    }
    return $summary
}

# ----------------------------------------------------------- integrity / viewing

function Test-AuditLogIntegrity {
    [CmdletBinding()]
    param([switch]$Quiet, [string]$ExpectedHead)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $files = @(Get-AuditFiles)
    $prevHash = $null; $prevSeq = $null; $prevTs = $null
    $total = 0

    # A head noted earlier ('seq:hash', see Get-AuditHeadHash) is the only defence against truncation and
    # against a complete, self-consistent rewrite of the log.
    $expSeq = $null; $expHash = $null; $headFound = $false
    if ($ExpectedHead) {
        $hm = [regex]::Match($ExpectedHead.Trim(), '^(\d+):([0-9a-fA-F]{64})$')
        if ($hm.Success) { $expSeq = [long]$hm.Groups[1].Value; $expHash = $hm.Groups[2].Value.ToLowerInvariant() }
        else { $errors.Add("the saved head must look like <seq>:<64 hex characters>, got '$ExpectedHead'") }
    }

    if (Test-Path -LiteralPath $script:AuditDir) {
        foreach ($it in @(Get-ChildItem -LiteralPath $script:AuditDir -Force -ErrorAction SilentlyContinue)) {
            $n = $it.Name
            if ($n -like 'audit*' -and $n -ne 'audit.jsonl' -and $n -notmatch $script:AuditRotatedNameRegex) {
                $errors.Add("unexpected file in the audit directory: $n (it is not part of the chain)")
            } elseif ($n -like '*.tmp') {
                $warnings.Add("stale temporary file in the audit directory: $n")
            }
        }
        try {
            $sec = Test-AuditDirSecurity -Acl ((New-Object IO.DirectoryInfo($script:AuditDir)).GetAccessControl())
            if (-not $sec.Ok) {
                $why = @($sec.Issues)
                if (-not $sec.OwnerTrusted) { $why += "owner is $($sec.Owner)" }
                $errors.Add("audit directory is not protected: $($why -join '; ')")
            }
        } catch { $warnings.Add("cannot check the audit directory ACL: $($_.Exception.Message)") }
    }

    foreach ($f in $files) {
        $leaf = Split-Path -Leaf $f
        $fs = New-Object System.IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, $script:AuditUtf8)
        $lineNo = 0
        $firstInFile = $true
        try {
            while ($null -ne ($line = $sr.ReadLine())) {
                $lineNo++
                if ($line.Trim() -eq '') { continue }
                $p = ConvertFrom-AuditLine $line
                if ($null -eq $p) { $errors.Add("${leaf}:${lineNo} not a valid audit record (garbage or torn write)"); continue }
                $total++
                if (-not $p.Valid) { $errors.Add("${leaf}:${lineNo} record hash mismatch (record was modified)") }
                $o = $p.Obj
                $seq = [long]$o.seq
                if ($null -eq $prevHash) {
                    if ($seq -ne 1) { $warnings.Add("log starts at seq $seq (earlier files are missing or were removed)") }
                    elseif ([string]$o.prev -ne $script:AuditZeroHash) { $errors.Add("${leaf}:${lineNo} first record does not start from the genesis hash") }
                } else {
                    if ([string]$o.prev -ne $prevHash) {
                        $where = if ($firstInFile) { ' at a file boundary: a log file may be missing' } else { ' (record(s) removed, inserted or reordered)' }
                        $errors.Add("${leaf}:${lineNo} chain broken$where")
                    }
                    if ($seq -ne $prevSeq + 1) { $errors.Add("${leaf}:${lineNo} sequence gap (expected $($prevSeq + 1), found $seq)") }
                }
                if ($null -ne $expSeq -and $seq -eq $expSeq) {
                    $headFound = $true
                    if ($p.Hash -ne $expHash) { $errors.Add("saved head mismatch: record seq $seq has hash $($p.Hash), expected $expHash (log replaced or rewritten)") }
                }
                $ts = ConvertTo-AuditDate $o.ts
                if ($prevTs -and $ts -and $ts -lt $prevTs) { $warnings.Add("${leaf}:${lineNo} timestamp goes backwards (clock changed?)") }
                $prevHash = $p.Hash; $prevSeq = $seq; $prevTs = $ts
                $firstInFile = $false
            }
        } finally { $sr.Dispose() }
    }

    if ($null -ne $expSeq -and -not $headFound) {
        $errors.Add("saved head seq $expSeq not found: the log was truncated (last seq here: $prevSeq) or replaced")
    }

    $result = [pscustomobject]@{
        Ok = ($errors.Count -eq 0); Files = $files.Count; Records = $total
        LastSeq = $prevSeq; LastHash = $prevHash
        Errors = $errors.ToArray(); Warnings = $warnings.ToArray()
    }
    if (-not $Quiet) {
        if ($files.Count -eq 0) {
            Write-Host 'No audit log yet.' -ForegroundColor Yellow
        } elseif ($result.Ok) {
            Write-Host "Audit log OK: $total record(s) in $($files.Count) file(s), hash chain intact." -ForegroundColor Green
        } else {
            Write-Host "AUDIT LOG INTEGRITY FAILURE ($($errors.Count) problem(s)):" -ForegroundColor Red
            $errors | Select-Object -First 20 | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        }
        $warnings | Select-Object -First 10 | ForEach-Object { Write-Host "  ! $_" -ForegroundColor Yellow }
        if ($total -gt 0) {
            Write-Host "Chain head: seq=$prevSeq hash=$prevHash"
            Write-Host '(Note the head OFF this machine: cut-off records or a full rewrite are only detected by comparing it with a saved head. Submenu 8 -> [H].)' -ForegroundColor DarkGray
        }
    }
    return $result
}

# Newest valid record as 'seq:hash'. Store it OFF this machine (mail it to yourself, ticket, paper):
# the unkeyed hash chain cannot prove that records were not cut off or the whole log rewritten.
function Get-AuditHeadHash {
    $f = Find-AuditRecordFromEnd -MaxFiles 1
    if ($null -eq $f) { return $null }
    $seq = [long]$f.Obj.seq
    return [pscustomobject]@{ Seq = $seq; Hash = $f.Hash; Ts = [string]$f.Obj.ts; Text = "${seq}:$($f.Hash)" }
}

function Read-AuditRecords {
    param([DateTime]$SinceUtc, [string]$Type)
    foreach ($f in @(Get-AuditFiles)) {
        $fs = New-Object System.IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, $script:AuditUtf8)
        try {
            while ($null -ne ($line = $sr.ReadLine())) {
                if ($line.Trim() -eq '') { continue }
                if ($Type -and $line.IndexOf('"type":"' + $Type + '"') -lt 0) { continue }
                if ($SinceUtc) {
                    $m = [regex]::Match($line, '"ts":"([^"]+)"')
                    if ($m.Success) {
                        $d = ConvertTo-AuditDate $m.Groups[1].Value
                        if ($d -and $d -lt $SinceUtc) { continue }
                    }
                }
                $p = ConvertFrom-AuditLine $line
                if ($p) { $p.Obj }
            }
        } finally { $sr.Dispose() }
    }
}

function Show-AuditLog {
    $days = 7
    $d = Read-Host 'Show records from the last N days (Enter = 7)'
    if ($d -match '^\d+$' -and [int]$d -gt 0) { $days = [int]$d }
    $kind = Read-Host 'Records: [1] changes only (default)  [2] everything (intent/result/sync/...)'
    $type = if ($kind -eq '2') { $null } else { 'change' }
    $op = $null; $src = $null
    if ($type) {
        switch (Read-Host 'Operation filter: [1] Added  [2] Removed  [3] Modified  (Enter = any)') {
            '1' { $op = 'Added' } '2' { $op = 'Removed' } '3' { $op = 'Modified' }
        }
        switch (Read-Host 'Source filter: [1] oso (this tool)  [2] system  [3] external  [4] gpo  (Enter = any)') {
            '1' { $src = 'oso' } '2' { $src = 'system' } '3' { $src = 'external' } '4' { $src = 'gpo' }
        }
    }
    $since = [DateTime]::UtcNow.AddDays(-$days)
    $rows = @(Read-AuditRecords -SinceUtc $since -Type $type | Where-Object {
        (-not $op -or $_.op -eq $op) -and (-not $src -or $_.source -eq $src)
    })
    if ($rows.Count -eq 0) { Write-Host 'No matching records.' -ForegroundColor Yellow; return }

    $view = foreach ($r in ($rows | Select-Object -Last 50)) {
        $time = (ConvertTo-AuditDate $r.ts).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        switch ($r.type) {
            'change' {
                $name = if ($r.ruleId) { if ($r.displayNameResolved) { $r.displayNameResolved } else { $r.displayName } }
                        elseif ($r.profile) { "$($r.kind) $($r.profile)" }
                        else { "$($r.kind) $($r.path)" }
                $detail = if ($r.op -eq 'Modified') { (@($r.changes) | ForEach-Object { $_.field }) -join ',' } else { '' }
                [pscustomobject]@{ Seq = $r.seq; Time = $time; Type = 'change'; Op = $r.op; Source = $r.source; Target = $name; By = $r.actor.user; How = $r.detection; Detail = $detail }
            }
            default {
                $detail = switch ($r.type) {
                    'intent' { "$($r.operation) ($($r.scope))" }
                    'result' { "$($r.operation): $($r.status)" }
                    'sync'   { "+$($r.counts.added) -$($r.counts.removed) ~$($r.counts.modified) ($($r.trigger))" }
                    default  { "$($r.issue) $($r.reason)".Trim() }
                }
                [pscustomobject]@{ Seq = $r.seq; Time = $time; Type = $r.type; Op = ''; Source = ''; Target = ''; By = $r.recorder.user; How = ''; Detail = $detail }
            }
        }
    }
    $view | Format-Table -AutoSize -Wrap
    Write-Host "Showing the last $(@($view).Count) of $($rows.Count) matching record(s). Log: $(Get-AuditFile 'Log')" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- the watcher

function Get-AuditLatestEventRecordId {
    try { return [long](Get-WinEvent -LogName $script:AuditEventLog -MaxEvents 1 -ErrorAction Stop).RecordId } catch { return 0L }
}

# Entry point of the Scheduled Task (-SyncAudit): wait until the event burst settles, sync,
# and repeat if new events appeared during the sync.
function Invoke-AuditWatcherRun {
    param([int]$SettleSeconds = 30)
    $started = Get-AuditTimestamp
    try {
        $deadline = (Get-Date).AddSeconds($SettleSeconds)
        $stable = 0
        $last = Get-AuditLatestEventRecordId
        while ($stable -lt 3 -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 1
            $cur = Get-AuditLatestEventRecordId
            if ($cur -eq $last) { $stable++ } else { $stable = 0; $last = $cur }
        }
        $summary = $null
        for ($i = 0; $i -lt 3; $i++) {
            $mark = Get-AuditLatestEventRecordId
            $summary = Invoke-AuditSync -Trigger task -Quiet
            if ((Get-AuditLatestEventRecordId) -eq $mark) { break }
        }
        Write-AuditState -Status 'ok' -Started $started -Summary $summary
    } catch {
        Write-AuditState -Status 'failed' -Started $started -Message $_.Exception.Message
        throw
    }
}

# state.json: outcome of the last watcher run. It is how the menu notices a watcher that is "installed"
# but no longer doing anything (task disabled, script broken, errors on every run).
function Write-AuditState {
    param([ValidateSet('ok', 'failed')][string]$Status, [string]$Started, $Summary, [string]$Message)
    try {
        $o = [ordered]@{
            v = 1; status = $Status; started = $Started; finished = (Get-AuditTimestamp)
            user = [Security.Principal.WindowsIdentity]::GetCurrent().Name; message = $Message
        }
        if ($Summary) { $o.summary = [ordered]@{ added = $Summary.Added; removed = $Summary.Removed; modified = $Summary.Modified; pending = $Summary.Pending } }
        # keep the time of the last SUCCESS even when later runs fail
        $prev = Read-AuditState
        $o.lastOk = if ($Status -eq 'ok') { $o.finished } elseif ($prev) { [string]$prev.lastOk } else { $null }
        $path = Get-AuditFile 'State'
        $tmp = "$path.tmp"
        [IO.File]::WriteAllText($tmp, (ConvertTo-AuditJson $o), $script:AuditUtf8)
        if (Test-Path -LiteralPath $path) { [IO.File]::Replace($tmp, $path, [NullString]::Value) } else { [IO.File]::Move($tmp, $path) }
    } catch { }
}

function Read-AuditState {
    try {
        $path = Get-AuditFile 'State'
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        return (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path, $script:AuditUtf8)))
    } catch { return $null }
}

# 'Healthy' | 'NeverRan' | 'Failed' | 'Stale' - pure function of state.json and the clock (testable).
function Get-AuditWatcherHealth {
    param($State, [datetime]$NowUtc = [DateTime]::UtcNow)
    if (-not $State) { return [pscustomobject]@{ Health = 'NeverRan'; LastOk = $null; Message = 'the watcher has not completed a run yet' } }
    $lastOk = $null
    if ($State.lastOk) { $lastOk = ConvertTo-AuditDate ([string]$State.lastOk) }
    if ([string]$State.status -eq 'failed') {
        return [pscustomobject]@{ Health = 'Failed'; LastOk = $lastOk; Message = [string]$State.message }
    }
    $limit = [TimeSpan]::FromMinutes($script:AuditWatcherIntervalMin * 3)
    if (-not $lastOk -or ($NowUtc - $lastOk) -gt $limit) {
        return [pscustomobject]@{ Health = 'Stale'; LastOk = $lastOk; Message = "no successful run for more than $([int]$limit.TotalMinutes) minutes" }
    }
    return [pscustomobject]@{ Health = 'Healthy'; LastOk = $lastOk; Message = $null }
}

function Get-AuditWatcherStatus {
    $st = [ordered]@{ Installed = $false; State = $null; LastRun = $null; LastResult = $null; UpToDate = $null; EventLog = $null; Health = $null }
    try {
        $t = Get-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -InputObject $t
        $st.Installed = $true
        $st.State = [string]$t.State
        $st.LastRun = $info.LastRunTime
        $st.LastResult = $info.LastTaskResult
        $installed = Join-Path (Get-AuditFile 'Bin') 'firewall.ps1'
        if ((Test-Path -LiteralPath $installed) -and $script:AuditSelfPath) {
            $h = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant()
            $st.UpToDate = ($h -eq (Get-AuditSelfHash))
        } else { $st.UpToDate = $false }
        $st.Health = Get-AuditWatcherHealth -State (Read-AuditState)
    } catch { }
    try {
        $l = Get-WinEvent -ListLog $script:AuditEventLog -ErrorAction Stop
        $st.EventLog = [ordered]@{ enabled = $l.IsEnabled; maxBytes = $l.MaximumSizeInBytes; mode = [string]$l.LogMode }
    } catch { }
    return [pscustomobject]$st
}

function Get-AuditWatcherSummaryLine {
    $s = Get-AuditWatcherStatus
    if (-not $s.Installed) { return @{ Text = 'Audit watcher: NOT INSTALLED (changes made outside this tool are only detected at startup / "Sync now")'; Color = 'Yellow' } }
    $txt = "Audit watcher: $($s.State)"
    $color = 'Green'
    if ($s.State -ne 'Ready' -and $s.State -ne 'Running') { $txt += ' (task is not active!)'; $color = 'Red' }
    if ($s.UpToDate -eq $false) { $txt += ' - installed copy differs from this script, reinstall it'; $color = 'Yellow' }
    if ($s.Health) {
        switch ($s.Health.Health) {
            'Failed'   { $txt += " - LAST RUN FAILED: $($s.Health.Message)"; $color = 'Red' }
            'Stale'    { $txt += " - $($s.Health.Message)"; $color = 'Red' }
            'NeverRan' { $txt += ' - has not completed a run yet'; if ($color -eq 'Green') { $color = 'Yellow' } }
        }
    }
    if ($s.EventLog -and -not $s.EventLog.enabled) { $txt += ' - firewall event log disabled: no "who" for external changes'; $color = 'Yellow' }
    return @{ Text = $txt; Color = $color }
}

function Test-AuditDirTrusted {
    # The watcher runs as SYSTEM, so the directory it executes code from must not be owned by a normal user.
    $acl = Get-Acl -LiteralPath $script:AuditDir
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) {
        throw "$($script:AuditDir) is owned by $owner, not SYSTEM/Administrators. Remove it (or take ownership) before installing the watcher."
    }
}

function Install-AuditWatcher {
    if (-not $script:AuditSelfPath -or -not (Test-Path -LiteralPath $script:AuditSelfPath)) {
        throw 'Cannot determine the script path; run the script from a file to install the watcher.'
    }
    Initialize-AuditStore
    Test-AuditDirTrusted
    $bin = Get-AuditFile 'Bin'
    if (-not (Test-Path -LiteralPath $bin)) { New-Item -ItemType Directory -Path $bin -Force | Out-Null }
    # SYSTEM and Administrators: full control; Users: read only; nothing inherited.
    & icacls.exe $bin /setowner '*S-1-5-32-544' | Out-Null
    & icacls.exe $bin /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to secure $bin (exit code $LASTEXITCODE)." }

    $installed = Join-Path $bin 'firewall.ps1'
    Copy-Item -LiteralPath $script:AuditSelfPath -Destination $installed -Force
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant() -ne (Get-AuditSelfHash)) {
        throw 'The installed copy does not match the source script.'
    }

    $def = New-AuditWatcherDefinition -ScriptPath $installed
    Register-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName -Action $def.Action `
        -Trigger $def.Triggers -Principal $def.Principal -Settings $def.Settings -Force `
        -Description 'Records firewall policy changes made outside firewall.ps1 (audit watcher).' | Out-Null
}

# Everything the Scheduled Task consists of, without registering it (so it can be inspected and tested
# without administrator rights). Triggers: firewall change events, system start, and a periodic safety net.
function New-AuditWatcherDefinition {
    param([Parameter(Mandatory)][string]$ScriptPath)
    $ids = @($script:AuditEventIds.Values | ForEach-Object { $_ }) | Sort-Object -Unique
    $cond = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
    $sub = "<QueryList><Query Id=`"0`" Path=`"$($script:AuditEventLog)`"><Select Path=`"$($script:AuditEventLog)`">*[System[($cond)]]</Select></Query></QueryList>"
    $class = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
    $evTrigger = New-CimInstance -CimClass $class -ClientOnly
    $evTrigger.Subscription = $sub
    $evTrigger.Enabled = $true
    $startTrigger = New-ScheduledTaskTrigger -AtStartup
    $periodic = New-ScheduledTaskTrigger -Once -At ((Get-Date).Date) -RepetitionInterval (New-TimeSpan -Minutes $script:AuditWatcherIntervalMin)

    $psArg = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -SyncAudit"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    return [pscustomobject]@{
        Triggers = @($evTrigger, $startTrigger, $periodic); Action = $action; Principal = $principal; Settings = $settings
        Subscription = $sub; IntervalMinutes = $script:AuditWatcherIntervalMin
    }
}

function Uninstall-AuditWatcher {
    Unregister-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName -Confirm:$false -ErrorAction Stop
    $bin = Get-AuditFile 'Bin'
    if (Test-Path -LiteralPath $bin) { Remove-Item -LiteralPath $bin -Recurse -Force -ErrorAction SilentlyContinue }
}
#endregion AUDIT

# ---- non-interactive entry point used by the Scheduled Task ------------------
if ($SyncAudit) {
    $script:AuditInitiatorDefault = if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { 'scheduled-task' } else { 'manual-sync' }
    try {
        Invoke-AuditWatcherRun
        exit 0
    } catch {
        try {
            [void](Write-AuditRecord -Type 'error' -Fields ([ordered]@{ where = 'SyncAudit'; message = $_.Exception.Message }))
        } catch { }
        exit 1
    }
}

# =============================================================================
# BACKUP MODULE  (owner: Ruslan)  -  backup / restore with the central backup server
# =============================================================================
# * The backup server PULLS the policy from this computer over SSH (key restricted by
#   authorized_keys to:  powershell ... -File <this script> -Agent Export | Import).
# * Restores are PUSHED by the server to the agent (-Agent Import) after the user asked for
#   them in menu option 9. The import runs through Invoke-AuditedChange (Operation Restore,
#   Scope All), as the audit contract requires, so every changed rule lands in the audit log.
# * After a restore the policy is rolled back automatically (scheduled task, -Agent Rollback)
#   unless the user confirms within the countdown.
# Variables and functions of this module use the prefix Bk / Bk- to avoid clashes with AUDIT.
# =============================================================================
#region BACKUP
$script:BkServerIp = '10.0.2.30'
$script:BkWork     = Join-Path $env:ProgramData 'FirewallBackup\agent'
$script:BkAgentLog = Join-Path $script:BkWork 'agent.log'
$script:BkFlag     = Join-Path $script:BkWork 'confirm.flag'

function Write-BkLog {
    param([string]$Text, [string]$Tag = 'agent')
    Add-Content -Path $script:BkAgentLog -Value ("{0} [{1}] {2}" -f (Get-Date -Format 's'), $Tag, $Text)
}

function Initialize-BkWork {
    if (-not (Test-Path -LiteralPath $script:BkWork)) {
        New-Item -ItemType Directory -Path $script:BkWork -Force | Out-Null
        icacls.exe $script:BkWork /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    }
}

function Test-BkSshRule { return [bool](Get-NetFirewallRule -Name 'FWBackup-SSH-In' -ErrorAction SilentlyContinue) }

# Raw creation (no audit wrapper): used INSIDE audited actions.
function New-BkSshRule {
    New-NetFirewallRule -Name 'FWBackup-SSH-In' -DisplayName 'FWBackup SSH from backup server' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $script:BkServerIp -Profile Any -ErrorAction Stop | Out-Null
}

# Audited creation: used when the rule is missing outside of a restore.
function Ensure-BkSshRule {
    if (Test-BkSshRule) { return }
    [void](Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Initiator 'automation' `
        -Reason 'Backup agent: the SSH rule for the backup server was missing' -Action { New-BkSshRule })
    Write-BkLog 'SSH rule re-created'
}

function Fail-Bk {
    param([string]$Text)
    $Text = ($Text -replace '[\r\n]+', ' ').Trim()
    Write-BkLog "FAIL $Text" 'Import'
    Write-Output 'RESULT=FAIL'
    Write-Output "MESSAGE=$Text"
    exit 1
}

# Entry point of the three agent modes (called by the backup server through SSH or by the rollback task).
function Invoke-BackupAgent {
    param([Parameter(Mandatory)][ValidateSet('Export', 'Import', 'Rollback')][string]$Agent)
    $WarningPreference  = 'SilentlyContinue'      # stdout belongs to the protocol with the server
    $ProgressPreference = 'SilentlyContinue'
    $script:AuditInitiatorDefault = 'automation'
    Initialize-BkWork
    try {
        switch ($Agent) {

            'Export' {
                Ensure-BkSshRule
                $tmp = Join-Path $script:BkWork ("export_{0}.wfw" -f [guid]::NewGuid())
                & netsh.exe advfirewall export "$tmp" | Out-Null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp) -or (Get-Item -LiteralPath $tmp).Length -le 0) { throw 'netsh export failed' }
                $bytes = [IO.File]::ReadAllBytes($tmp)
                $hash  = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
                Remove-Item -LiteralPath $tmp -Force
                Write-Output 'FWAGENT-BEGIN'
                Write-Output "COMPUTER=$env:COMPUTERNAME"
                Write-Output "SHA256=$hash"
                Write-Output "SIZE=$($bytes.Length)"
                Write-Output 'DATA'
                Write-Output ([Convert]::ToBase64String($bytes, [Base64FormattingOptions]::InsertLineBreaks))
                Write-Output 'FWAGENT-END'
                Write-BkLog "exported $($bytes.Length) bytes, sha256=$hash" 'Export'
                exit 0
            }

            'Import' {
                Write-BkLog 'import started' 'Import'
                # raw bytes from stdin; stop at the FWAGENT-END marker (do not wait for end-of-stream)
                $stdin = [Console]::OpenStandardInput()
                $ms  = New-Object System.IO.MemoryStream
                $buf = New-Object byte[] 65536
                while ($true) {
                    $task = $stdin.ReadAsync($buf, 0, $buf.Length)
                    if (-not $task.Wait(30000)) {
                        Write-BkLog "stdin timeout after $($ms.Length) bytes" 'Import'
                        Fail-Bk 'timeout waiting for request data'
                    }
                    $n = $task.Result
                    if ($n -le 0) { break }
                    $ms.Write($buf, 0, $n)
                    if ($ms.Length -gt 3MB) { Fail-Bk 'request too large' }
                    $len  = [int]$ms.Length
                    $tail = [Text.Encoding]::ASCII.GetString($ms.GetBuffer(), [Math]::Max(0, $len - 16), [Math]::Min(16, $len)).TrimEnd("`r", "`n")
                    if ($tail.EndsWith('FWAGENT-END')) { break }
                }
                Write-BkLog "request complete: $($ms.Length) bytes" 'Import'
                $text  = [Text.Encoding]::ASCII.GetString($ms.ToArray())
                $lines = @($text -split "`r?`n")
                if ($lines.Count -lt 7 -or $lines[0] -ne 'FWAGENT-BEGIN') { Fail-Bk 'bad request framing' }

                $expected = (($lines | Where-Object { $_ -like 'SHA256=*' } | Select-Object -First 1) -replace '^SHA256=', '').Trim().ToLower()
                if ($expected -notmatch '^[0-9a-f]{64}$') { Fail-Bk 'bad hash in request' }

                $rbText = (($lines | Where-Object { $_ -like 'ROLLBACK_SEC=*' } | Select-Object -First 1) -replace '^ROLLBACK_SEC=', '').Trim()
                $rbSec = 90
                [void][int]::TryParse($rbText, [ref]$rbSec)
                $rbSec = [Math]::Min([Math]::Max($rbSec, 30), 300)

                $start = [Array]::IndexOf($lines, 'DATA')
                $end   = [Array]::IndexOf($lines, 'FWAGENT-END')
                if ($start -lt 0 -or $end -le ($start + 1)) { Fail-Bk 'bad data framing' }

                $b64   = (($lines[($start + 1)..($end - 1)]) -join '').Trim()
                $bytes = [Convert]::FromBase64String($b64)
                $incoming = Join-Path $script:BkWork 'incoming.wfw'
                [IO.File]::WriteAllBytes($incoming, $bytes)
                $calc = (Get-FileHash -LiteralPath $incoming -Algorithm SHA256).Hash.ToLower()
                if ($calc -ne $expected) { Remove-Item -LiteralPath $incoming -Force; Fail-Bk 'SHA-256 mismatch' }

                # snapshot for the automatic rollback (fresh temp file, then replace the old snapshot)
                $rollback = Join-Path $script:BkWork 'rollback.wfw'
                $snapTmp  = Join-Path $script:BkWork ("snap_{0}.wfw" -f [guid]::NewGuid())
                $snapOut  = & netsh.exe advfirewall export "$snapTmp" 2>&1
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $snapTmp) -or (Get-Item -LiteralPath $snapTmp).Length -le 0) {
                    Write-BkLog "snapshot export failed (exit $LASTEXITCODE): $($snapOut -join ' ')" 'Import'
                    Fail-Bk 'cannot create rollback snapshot'
                }
                Move-Item -LiteralPath $snapTmp -Destination $rollback -Force -ErrorAction Stop
                Remove-Item -LiteralPath $script:BkFlag -Force -ErrorAction SilentlyContinue

                # The restore itself goes through the audit wrapper (Operation Restore, Scope All).
                try {
                    [void](Invoke-AuditedChange -Operation 'Restore' -Scope All -Initiator 'automation' `
                        -Reason "Restore pushed by the backup server (sha256 $calc)" `
                        -Details @{ source = 'backup-server'; sha256 = $calc; bytes = $bytes.Length; rollbackSec = $rbSec } `
                        -Action {
                            $impOut = & netsh.exe advfirewall import "$incoming" 2>&1
                            if ($LASTEXITCODE -ne 0) { throw "netsh import failed (exit $LASTEXITCODE): $($impOut -join ' ')" }
                            if (-not (Test-BkSshRule)) { New-BkSshRule }
                        })
                } catch {
                    $impErr = $_.Exception.Message
                    Write-BkLog "import failed: $impErr" 'Import'
                    # safety first: put the previous policy back even if the audit trail is the problem
                    & netsh.exe advfirewall import "$rollback" 2>&1 | Out-Null
                    if (-not (Test-BkSshRule)) { try { New-BkSshRule } catch { } }
                    Fail-Bk "import failed, previous policy restored: $impErr"
                }

                # one-shot task: rolls back unless the user confirms (confirm.flag)
                $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
                       -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Agent Rollback"
                $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($rbSec)
                $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                [void](Register-ScheduledTask -TaskName 'FwRollback' -Action $act -Trigger $trg -Principal $pri -Force -ErrorAction Stop)

                Write-BkLog "imported sha256=$calc, rollback in $rbSec s" 'Import'
                Write-Output 'RESULT=OK'
                Write-Output "ROLLBACK_SEC=$rbSec"
                exit 0
            }

            'Rollback' {
                $rb = Join-Path $script:BkWork 'rollback.wfw'
                try {
                    if (Test-Path -LiteralPath $script:BkFlag) {
                        Remove-Item -LiteralPath $script:BkFlag -Force
                        Write-BkLog 'changes confirmed by user - no rollback' 'Rollback'
                    }
                    elseif (Test-Path -LiteralPath $rb) {
                        try {
                            [void](Invoke-AuditedChange -Operation 'RestoreRollback' -Scope All -Initiator 'automation' `
                                -Reason 'No confirmation after a restore: returning to the pre-restore policy' -Action {
                                    $rbOut = & netsh.exe advfirewall import "$rb" 2>&1
                                    if ($LASTEXITCODE -ne 0) { throw "netsh import failed (exit $LASTEXITCODE): $($rbOut -join ' ')" }
                                    if (-not (Test-BkSshRule)) { New-BkSshRule }
                                })
                            Write-BkLog 'no confirmation - policy rolled back' 'Rollback'
                        } catch {
                            # the rollback must happen even when the audit trail is unavailable
                            Write-BkLog "audited rollback failed ($($_.Exception.Message)); raw import" 'Rollback'
                            & netsh.exe advfirewall import "$rb" 2>&1 | Out-Null
                            if (-not (Test-BkSshRule)) { try { New-BkSshRule } catch { } }
                        }
                    }
                    else { Write-BkLog 'no rollback snapshot found' 'Rollback' }
                }
                finally {
                    Unregister-ScheduledTask -TaskName 'FwRollback' -Confirm:$false -ErrorAction SilentlyContinue
                }
                exit 0
            }
        }
    }
    catch {
        Write-BkLog "ERROR $($_.Exception.Message)" $Agent
        if ($Agent -eq 'Import') {
            Write-Output 'RESULT=FAIL'
            Write-Output "MESSAGE=$(($_.Exception.Message -replace '[\r\n]+', ' '))"
        } else {
            [Console]::Error.WriteLine($_.Exception.Message)
        }
        exit 1
    }
}

# ---- non-interactive entry point used by the backup server (SSH forced command) and the rollback task
if ($Agent) {
    Invoke-BackupAgent -Agent $Agent
    exit 0
}

# ---------------------------------------------------------------- client side (menu option 9)
$script:BkCfg = @{
    Host           = $script:BkServerIp
    SftpPort       = 2022                    # SFTPGo, read-only listing of backups
    SshPort        = 22                      # backup server: backup / restore requests
    SshUser        = 'fwbackup'
    UserOverride   = ''                      # SFTP account; empty = Windows user name (lowercase)
    KeyPath        = (Join-Path (Join-Path $env:USERPROFILE '.fwbackup') 'id_ed25519')
    KnownHosts     = (Join-Path (Join-Path $env:USERPROFILE '.fwbackup') 'known_hosts')
    WaitSec        = 120
    RestoreWaitSec = 180
    ConfirmFlag    = $script:BkFlag
}
$script:BkCfg.User = if ($script:BkCfg.UserOverride) { $script:BkCfg.UserOverride } else { $env:USERNAME.ToLower() }
if ($script:BkCfg.User -notmatch '^[a-z0-9][a-z0-9._-]{0,31}$') {
    Write-Host "Backup: account name '$($script:BkCfg.User)' is not allowed on the server (a-z, 0-9, . _ -). Set UserOverride in the BACKUP region." -ForegroundColor Yellow
}

function Test-ServerReachable {
    param([int]$Port)
    if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue) -or -not (Get-Command sftp.exe -ErrorAction SilentlyContinue)) {
        Write-Host "ssh.exe / sftp.exe not found (install OpenSSH Client)." -ForegroundColor Yellow
        return $false
    }
    if (-not (Test-Path -LiteralPath $script:BkCfg.KeyPath)) {
        Write-Host "SSH key not found: $($script:BkCfg.KeyPath)." -ForegroundColor Yellow
        return $false
    }
    $probe = Test-NetConnection -ComputerName $script:BkCfg.Host -Port $Port -WarningAction SilentlyContinue -InformationLevel Quiet
    if (-not $probe) {
        Write-Host "Server $($script:BkCfg.Host):$Port is unreachable." -ForegroundColor Yellow
        return $false
    }
    return $true
}

# Sends one command to the backup server over SSH (forced command) and returns its KEY=VALUE answer
function Invoke-ServerCommand {
    param([string]$Command, [int]$TimeoutSec)
    $key     = $script:BkCfg.KeyPath -replace '\\', '/'
    $known   = $script:BkCfg.KnownHosts -replace '\\', '/'
    $outFile = Join-Path $env:TEMP ("fwreq_{0}.out" -f [guid]::NewGuid())
    $argLine = "-T -i `"$key`" -p $($script:BkCfg.SshPort) -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o `"UserKnownHostsFile=$known`" -o ConnectTimeout=10 -o ServerAliveInterval=10 $($script:BkCfg.SshUser)@$($script:BkCfg.Host) `"$Command`""
    try {
        $p = Start-Process -FilePath 'ssh.exe' -ArgumentList $argLine -NoNewWindow -PassThru `
             -RedirectStandardOutput $outFile -RedirectStandardError "$outFile.err"
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            return [pscustomobject]@{ STATUS = 'FAIL'; MESSAGE = "no answer within $TimeoutSec s" }
        }
        $h = @{}
        if (Test-Path -LiteralPath $outFile) {
            Get-Content -LiteralPath $outFile | ForEach-Object { if ($_ -match '^([A-Z0-9_]+)=(.*)$') { $h[$Matches[1]] = $Matches[2] } }
        }
        if (-not $h.ContainsKey('STATUS')) {
            $err = if (Test-Path -LiteralPath "$outFile.err") { "$(Get-Content -LiteralPath "$outFile.err" -Tail 1)" } else { '' }
            $h['STATUS']  = 'FAIL'
            $h['MESSAGE'] = "no valid answer from the server. $err"
        }
        return [pscustomobject]$h
    } finally {
        Remove-Item -LiteralPath $outFile, "$outFile.err" -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Sftp {
    param([string[]]$Commands)
    $batch = Join-Path $env:TEMP ("sftp_{0}.txt" -f [guid]::NewGuid())
    Set-Content -Path $batch -Value $Commands -Encoding ASCII
    try {
        $out = & sftp.exe -b $batch `
            -i ($script:BkCfg.KeyPath -replace '\\','/') -P $script:BkCfg.SftpPort `
            -o BatchMode=yes -o StrictHostKeyChecking=yes `
            -o "UserKnownHostsFile=$($script:BkCfg.KnownHosts -replace '\\','/')" `
            -o ConnectTimeout=10 "$($script:BkCfg.User)@$($script:BkCfg.Host)" 2>&1
        [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = @($out) }
    } catch {
        [pscustomobject]@{ Ok = $false; Output = @($_.Exception.Message) }
    } finally {
        Remove-Item -LiteralPath $batch -Force -ErrorAction SilentlyContinue
    }
}

function Request-ServerBackup {
    param([string]$Reason = 'manual')
    if (-not (Test-ServerReachable -Port $script:BkCfg.SshPort)) { return $false }
    Write-Host "Asking the backup server to pull the configuration..." -ForegroundColor Cyan
    $res = Invoke-ServerCommand -Command "backup $Reason" -TimeoutSec $script:BkCfg.WaitSec
    if ($res.STATUS -eq 'OK') { Write-Host "Backup OK: $($res.FILE)" -ForegroundColor Green; return $true }
    Write-Host "Backup failed: $($res.MESSAGE)" -ForegroundColor Red
    return $false
}

# Called before a policy change (Add / Remove). A backup is NOT a policy change, so it is not audited.
function Invoke-PreChangeBackup {
    param([string]$Reason)
    if (Request-ServerBackup -Reason $Reason) { return $true }
    return ((Read-Host "Backup failed. Continue WITHOUT a backup? (yes/no) [no]").Trim().ToLower() -eq 'yes')
}

# Lists complete backups on the server (read-only SFTP account)
function Get-ServerBackups {
    if (-not (Test-ServerReachable -Port $script:BkCfg.SftpPort)) { return }
    $res = Invoke-Sftp -Commands @("ls -1 backups")
    if (-not $res.Ok) { Write-Host "Cannot read the backup list from the server." -ForegroundColor Red; return }
    $all   = @($res.Output | ForEach-Object { ("$_" -replace '^.*/', '').Trim() })
    $names = @($all | Where-Object { $_ -match '\.wfw$' -and ($all -contains "$_.sha256") } | Sort-Object -Descending)
    $i = 1
    foreach ($n in $names) {
        $m = [regex]::Match($n, '_(\d{8})_(\d{6})_([a-z\-]+)\.wfw$')
        $date = '?'; $reason = '?'
        if ($m.Success) {
            $date   = [datetime]::ParseExact("$($m.Groups[1].Value)$($m.Groups[2].Value)", 'yyyyMMddHHmmss', $null).ToString('yyyy-MM-dd HH:mm')
            $reason = $m.Groups[3].Value
        }
        [pscustomobject]@{ Index = $i; Date = $date; Reason = $reason; File = $n }
        $i++
    }
}

function Invoke-ServerRestore {
    $list = @(Get-ServerBackups)
    if ($list.Count -eq 0) { Write-Host "No backups found on the server." -ForegroundColor Yellow; return }
    $list | Format-Table Index, Date, Reason, File -AutoSize

    $sel = Read-Host "Backup number to restore (Enter = cancel)"
    $n = 0
    if (-not ([int]::TryParse($sel, [ref]$n) -and $n -ge 1 -and $n -le $list.Count)) {
        Write-Host "Cancelled." -ForegroundColor Yellow; return
    }
    $item = $list[$n - 1]

    Write-Host "`nSelected backup: $($item.File)" -ForegroundColor Cyan
    Write-Host "The server will push this backup to this computer and import it." -ForegroundColor Yellow
    Write-Host "The import will OVERWRITE the entire current firewall policy (it is recorded in the audit log)." -ForegroundColor Yellow

    $saveFirst = (Read-Host "Create a backup of the current firewall policy on the server before restoring? (yes/no) [yes]").Trim().ToLower()
    $preVal = if ($saveFirst -eq '' -or $saveFirst -eq 'yes') { 'yes' } else { 'no' }

    if ((Read-Host "Type RESTORE to confirm") -cne 'RESTORE') { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if (-not (Test-ServerReachable -Port $script:BkCfg.SshPort)) { return }

    Write-Host "Restore requested - the server is working..." -ForegroundColor Cyan
    $res = Invoke-ServerCommand -Command "restore $($item.File) $preVal" -TimeoutSec $script:BkCfg.RestoreWaitSec
    if ($res.STATUS -ne 'OK') { Write-Host "Restore failed: $($res.MESSAGE)" -ForegroundColor Red; return }

    Write-Host "Import completed by the server." -ForegroundColor Green
    $rb = 0
    [void][int]::TryParse("$($res.ROLLBACK_SEC)", [ref]$rb)
    if ($rb -le 0) { return }

    $window = [Math]::Max($rb - 25, 10)
    Write-Host "`nPress Y within $window s to KEEP the changes. Otherwise the agent rolls back automatically." -ForegroundColor Yellow
    $keep = $false
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $window) {
            if ([Console]::KeyAvailable) {
                if ([Console]::ReadKey($true).Key -eq 'Y') { $keep = $true; break }
            }
            Write-Host -NoNewline ("`rRemaining: {0,3} s " -f [int]($window - $sw.Elapsed.TotalSeconds))
            Start-Sleep -Milliseconds 250
        }
    } catch {
        $keep = ((Read-Host "`nNo console mode. Keep the changes? (yes/no)").Trim().ToLower() -eq 'yes')
    }
    Write-Host ""
    if ($keep) {
        New-Item -ItemType File -Path $script:BkCfg.ConfirmFlag -Force | Out-Null
        Write-Host "Changes kept (confirmation sent to the agent)." -ForegroundColor Green
    } else {
        Write-Host "Not confirmed - the agent will roll back to the previous policy shortly." -ForegroundColor Yellow
    }
}
#endregion BACKUP

function Show-Menu {
    Clear-Host
    Write-Host "=== FIREWALL RULES MANAGEMENT ===" -ForegroundColor Cyan
    Write-Host "1. Add Inbound Rule"
    Write-Host "2. Add Outbound Rule"
    Write-Host "3. List Firewall Rules"
    Write-Host "4. Delete Firewall Rule"
    Write-Host "5. View audit log"
    Write-Host "6. Verify audit log integrity"
    Write-Host "7. Sync audit now (detect changes made outside this tool)"
    Write-Host "8. Audit settings: watcher, fail policy, head hash"
    Write-Host "9. Backups: backup now / restore / list (backup server)"
    Write-Host "10. Exit"
    Write-Host "==============================================="
    if ($script:AuditStatus) { Write-Host $script:AuditStatus.Text -ForegroundColor $script:AuditStatus.Color }
    $pol = Get-AuditPolicyStatusLine
    if ($pol) { Write-Host $pol.Text -ForegroundColor $pol.Color }
}

# Shown on every menu redraw: fail-open must never be a silent state.
function Get-AuditPolicyStatusLine {
    try {
        $fp = Get-AuditFailPolicy
        $pend = 0
        try { $pend = @(Read-AuditPending).Count } catch { }
        if ($fp.Tampered) { return @{ Text = 'AUDIT: settings.json does not match the log - fail-closed is enforced (see integrity records)'; Color = 'Red' } }
        if ($fp.Policy -eq 'Open') {
            $t = 'AUDIT FAIL-OPEN: changes are performed even if the audit log is unavailable'
            if ($pend -gt 0) { $t += " ($pend unlogged change(s) waiting for reconciliation - run sync)" }
            return @{ Text = $t; Color = 'Red' }
        }
        if ($pend -gt 0) { return @{ Text = "AUDIT: $pend unlogged change(s) waiting for reconciliation - run option 7"; Color = 'Yellow' } }
    } catch { }
    return $null
}

# Asks which network profile(s) the rule should be active on.
# Returns an array like @('Private','Public') or @('Any').
function Read-ProfileChoice {
    $map = @{ '1' = 'Domain'; '2' = 'Private'; '3' = 'Public' }

    Write-Host "`nNetwork profile for this rule:"
    Write-Host "  1. Domain"
    Write-Host "  2. Private"
    Write-Host "  3. Public"
    Write-Host "  (press Enter = all profiles; several allowed, e.g. 2,3)"

    while ($true) {
        $profileInput = Read-Host "Select profile(s)"
        if ([string]::IsNullOrWhiteSpace($profileInput)) {
            return @('Any')
        }

        $parts = @($profileInput -split '[,\s]+' | Where-Object { $_ })
        $selected = @()
        $valid = $true
        foreach ($p in $parts) {
            if ($map.ContainsKey($p)) {
                $selected += $map[$p]
            } else {
                $valid = $false
            }
        }

        if ($valid -and $selected.Count -gt 0) {
            return @($selected | Select-Object -Unique)
        }
        Write-Host "Invalid choice. Use numbers 1-3, e.g. 1 or 2,3." -ForegroundColor Red
    }
}

# Asks which protocol the rule applies to. Returns 'TCP', 'UDP' or 'Any'.
# If a port was given, a protocol is mandatory (Windows Firewall requires
# TCP or UDP for port rules), so Enter defaults to TCP in that case.
function Read-ProtocolChoice {
    param([bool]$PortSet)

    Write-Host "`nProtocol:"
    Write-Host "  1. TCP"
    Write-Host "  2. UDP"
    if ($PortSet) {
        Write-Host "  (press Enter = TCP)"
    } else {
        Write-Host "  (press Enter = any protocol)"
    }

    while ($true) {
        $protoInput = (Read-Host "Select protocol").Trim()
        switch ($protoInput) {
            '1' { return 'TCP' }
            '2' { return 'UDP' }
            ''  { if ($PortSet) { return 'TCP' } else { return 'Any' } }
            default { Write-Host "Invalid choice. Enter 1 or 2." -ForegroundColor Red }
        }
    }
}

# Reconcile the live policy with the audit baseline before anything else happens:
# whatever changed while this tool was not looking is recorded now.
Write-Host "Checking the firewall policy against the audit baseline..." -ForegroundColor Cyan
try {
    [void](Invoke-AuditSync -Trigger startup)
} catch {
    Write-Host "Audit reconcile failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Read-Host "Press Enter to continue"
}
$script:AuditStatus = Get-AuditWatcherSummaryLine

while ($true) {
    Show-Menu
    $choice = Read-Host "Select an option (1-10)"

    if ($choice -eq '10') {
        Write-Host "Exiting script..." -ForegroundColor Yellow
        break
    }
    if ($choice -notin @('1', '2', '3', '4', '5', '6', '7', '8', '9')) {
        Write-Host "Invalid choice. Press Enter to try again." -ForegroundColor Red
        Read-Host
        continue
    }

    if ($choice -eq '5') {
        try { Show-AuditLog } catch { Write-Host "Cannot read the audit log: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    if ($choice -eq '6') {
        $savedHead = (Read-Host "Saved head hash from an earlier check (<seq>:<hash>), Enter = skip").Trim()
        try {
            if ($savedHead) { [void](Test-AuditLogIntegrity -ExpectedHead $savedHead) } else { [void](Test-AuditLogIntegrity) }
        } catch { Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    if ($choice -eq '7') {
        try { [void](Invoke-AuditSync -Trigger manual) } catch { Write-Host "Audit sync failed: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    if ($choice -eq '8') {
        $w = Get-AuditWatcherStatus
        Write-Host "`n--- Audit watcher ---" -ForegroundColor Cyan
        if ($w.Installed) {
            Write-Host "Installed: yes, state: $($w.State), last run: $($w.LastRun), last result: $($w.LastResult), installed copy up to date: $($w.UpToDate)"
        } else {
            Write-Host "Installed: no"
        }
        if ($w.EventLog) {
            Write-Host "Firewall event log: enabled=$($w.EventLog.enabled), max size=$($w.EventLog.maxBytes) bytes, mode=$($w.EventLog.mode)"
            if (-not $w.EventLog.enabled) {
                Write-Host "WARNING: the event log is disabled; external changes will be recorded without the 'who'." -ForegroundColor Yellow
            }
        } else {
            Write-Host "WARNING: the firewall event log is not readable; external changes will be recorded without the 'who'." -ForegroundColor Yellow
        }
        if ($w.Health) { Write-Host "Watcher health: $($w.Health.Health) $($w.Health.Message)" }
        $fpNow = Get-AuditFailPolicy
        Write-Host "Fail policy: $($fpNow.Policy) (Closed = no audit, no change; Open = change anyway, reconcile later)"
        $wChoice = (Read-Host "[I] Install / update watcher   [U] Uninstall watcher   [F] Toggle fail policy   [H] Show head hash   [Enter] Cancel").Trim().ToUpperInvariant()
        try {
            if ($wChoice -eq 'F') {
                $newPol = if ($fpNow.Policy -eq 'Open') { 'Closed' } else { 'Open' }
                if ($newPol -eq 'Open') {
                    Write-Host "FAIL-OPEN lets firewall changes happen WITHOUT an audit record when the log is broken or locked." -ForegroundColor Yellow
                    Write-Host "They are marked and reconciled by the next sync, but the 'who' may be lost." -ForegroundColor Yellow
                }
                $why = (Read-Host "Reason (recorded in the audit log)").Trim()
                if ((Read-Host "Switch fail policy to $newPol? (y/N)").Trim().ToLowerInvariant() -eq 'y') {
                    Set-AuditFailPolicy -Policy $newPol -Reason $why
                    Write-Host "Fail policy is now $newPol." -ForegroundColor Yellow
                }
            } elseif ($wChoice -eq 'H') {
                $head = Get-AuditHeadHash
                if ($head) {
                    Write-Host "Head: $($head.Text)   (record time $($head.Ts))" -ForegroundColor Cyan
                    Write-Host "Store it OFF this machine. Option 6 can later check it to detect truncation or a full rewrite."
                } else { Write-Host "The audit log is empty." }
            } elseif ($wChoice -eq 'I') {
                $wDetails = [ordered]@{ eventLog = $w.EventLog; taskPath = $script:AuditTaskPath + $script:AuditTaskName }
                [void](Invoke-AuditedChange -Operation 'WatcherInstall' -Scope Names -Names @() -Reason 'Install audit watcher' -Details $wDetails -Action { Install-AuditWatcher })
                Write-Host "Watcher installed." -ForegroundColor Green
                [void](Invoke-AuditSync -Trigger manual)
            } elseif ($wChoice -eq 'U') {
                [void](Invoke-AuditedChange -Operation 'WatcherUninstall' -Scope Names -Names @() -Reason 'Uninstall audit watcher' -Action { Uninstall-AuditWatcher })
                Write-Host "Watcher uninstalled (the audit log is kept)." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Watcher operation failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        $script:AuditStatus = Get-AuditWatcherSummaryLine
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    if ($choice -eq '9') {
        Write-Host "`n--- Backup server $($script:BkCfg.Host) ---" -ForegroundColor Cyan
        $bChoice = (Read-Host "[B] Backup now   [R] Restore from a backup   [L] List backups   [Enter] Cancel").Trim().ToUpperInvariant()
        try {
            if ($bChoice -eq 'B') {
                [void](Request-ServerBackup -Reason 'manual')
            } elseif ($bChoice -eq 'R') {
                Invoke-ServerRestore
            } elseif ($bChoice -eq 'L') {
                $bl = @(Get-ServerBackups)
                if ($bl.Count -eq 0) { Write-Host "No backups found on the server." -ForegroundColor Yellow }
                else { $bl | Format-Table Index, Date, Reason, File -AutoSize }
            }
        } catch {
            Write-Host "Backup operation failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    if ($choice -eq '3' -or $choice -eq '4') {
        # Show which profile(s) this machine is connected to right now
        Write-Host "`n--- Active Network Profile(s) ---" -ForegroundColor Cyan
        try {
            Get-NetConnectionProfile -ErrorAction Stop |
                Select-Object InterfaceAlias, Name, NetworkCategory |
                Format-Table -AutoSize
        } catch {
            Write-Host "Could not read network profile: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        Write-Host "--- Current Firewall Rules ---" -ForegroundColor Cyan

        $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "OSO-" } | Sort-Object @{Expression="Action"; Descending=$true}, @{Expression="DisplayName"; Ascending=$true}

        if ($rules) {
            $ruleDetails = @()
            $index = 1

            foreach ($rule in $rules) {
                $addressFilter = $rule | Get-NetFirewallAddressFilter
                $portFilter = $rule | Get-NetFirewallPortFilter

                $ruleDetails += [PSCustomObject]@{
                    Index         = $index
                    DisplayName   = $rule.DisplayName
                    Direction     = $rule.Direction
                    Action        = $rule.Action
                    Profile       = $rule.Profile
                    Protocol      = $portFilter.Protocol
                    LocalAddress  = $addressFilter.LocalAddress
                    RemoteAddress = $addressFilter.RemoteAddress
                    LocalPort     = $portFilter.LocalPort
                    RemotePort    = $portFilter.RemotePort
                    Name          = $rule.Name
                }
                $index++
            }

            $ruleDetails | Select-Object Index, DisplayName, Direction, Action, Profile, Protocol, LocalAddress, RemoteAddress, LocalPort, RemotePort | Format-Table -AutoSize

            if ($choice -eq '4') {
                $delIndex = Read-Host "`nEnter the Index of the rule to delete (or press Enter to cancel)"
                $idx = 0
                if ([int]::TryParse($delIndex, [ref]$idx) -and $idx -ge 1 -and $idx -le $ruleDetails.Count) {
                    $ruleToDelete = $ruleDetails[$idx - 1]
                    if (-not (Invoke-PreChangeBackup -Reason 'auto-delete')) {
                        Write-Host "No backup - deletion aborted." -ForegroundColor Red
                        Read-Host "`nPress Enter to return to the menu..."
                        continue
                    }
                    Write-Host "Deleting rule: $($ruleToDelete.DisplayName)..." -ForegroundColor Yellow
                    try {
                        # Audited: intent -> snapshot before/after -> change + result records.
                        [void](Invoke-AuditedChange -Operation 'Remove' -Scope Names -Names @($ruleToDelete.Name) `
                            -Reason 'Interactive delete (menu option 4)' `
                            -Details @{ expectedDisplayName = $ruleToDelete.DisplayName } `
                            -Action { Remove-NetFirewallRule -Name $ruleToDelete.Name -ErrorAction Stop })
                        Write-Host "Rule deleted successfully." -ForegroundColor Green
                    } catch {
                        Write-Host "Error while deleting rule: $($_.Exception.Message)" -ForegroundColor Red
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace($delIndex)) {
                    Write-Host "Invalid index. Operation cancelled." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No firewall rules found." -ForegroundColor Yellow
        }

        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    $direction = if ($choice -eq '1') { 'Inbound' } else { 'Outbound' }

    Write-Host "`n--- Rule Configuration ($direction) ---" -ForegroundColor Cyan

    $existingRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "OSO-" }
    $maxNumber = 0
    if ($existingRules) {
        foreach ($r in $existingRules) {
            if ($r.DisplayName -match '^(\d+)-OSO') {
                $num = [int]$matches[1]
                if ($num -gt $maxNumber) { $maxNumber = $num }
            }
        }
    }
    $nextNumber = $maxNumber + 1
    $prefix = "{0:D2}" -f $nextNumber

    $ip = $null
    while ($true) {
        $inputIp = Read-Host "Enter IP address (or press Enter to apply to all addresses)"
        if ([string]::IsNullOrWhiteSpace($inputIp)) {
            break
        }
        if ([ipaddress]::TryParse($inputIp, [ref]$null) -and ($inputIp -match '\.' -or $inputIp -match ':')) {
            $ip = $inputIp
            break
        } else {
            Write-Host "Invalid IP address format. Please enter a valid IPv4 or IPv6 address." -ForegroundColor Red
        }
    }

    $port = $null
    while ($true) {
        $inputPort = Read-Host "Enter port number (or press Enter to apply to all ports)"
        if ([string]::IsNullOrWhiteSpace($inputPort)) {
            break
        }
        $parsedPort = 0
        if ([int]::TryParse($inputPort, [ref]$parsedPort) -and $parsedPort -ge 1 -and $parsedPort -le 65535) {
            $port = $inputPort
            break
        } else {
            Write-Host "Invalid port. Please enter a number between 1 and 65535." -ForegroundColor Red
        }
    }

    $protocol = Read-ProtocolChoice -PortSet ([bool]$port)

    $action = $null
    while (-not $action) {
        $actionChoice = Read-Host "Select action - [1] Allow / [2] Block"
        switch ($actionChoice) {
            '1' { $action = 'Allow' }
            '2' { $action = 'Block' }
            default { Write-Host "Invalid choice. Enter 1 or 2." -ForegroundColor Red }
        }
    }

    $ruleProfile = Read-ProfileChoice

    $ruleName = "$prefix-OSO-$action-$direction-$(Get-Date -Format 'HHmmss')"

    $parameters = @{
        DisplayName = $ruleName
        Direction   = $direction
        Action      = $action
        Profile     = $ruleProfile
    }

    if ([string]::IsNullOrWhiteSpace($ip) -eq $false) {
        $parameters.Add('RemoteAddress', $ip)
    }

    if ($protocol -ne 'Any') {
        $parameters.Add('Protocol', $protocol)
    }

    if ([string]::IsNullOrWhiteSpace($port) -eq $false) {
        if ($direction -eq 'Inbound') {
            $parameters.Add('LocalPort', $port)
        } else {
            $parameters.Add('RemotePort', $port)
        }
    }

    if (-not (Invoke-PreChangeBackup -Reason 'auto-add')) {
        Write-Host "No backup - adding the rule aborted." -ForegroundColor Red
        Read-Host "`nPress Enter to return to the menu..."
        continue
    }

    Write-Host "`nCreating rule..." -ForegroundColor Yellow
    try {
        # Audited: intent -> snapshot before/after -> change + result records.
        [void](Invoke-AuditedChange -Operation 'Add' -Scope NewRules -Reason "Interactive add (menu option $choice)" `
            -Action { New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null })
        Write-Host "Success! Rule '$ruleName' has been added (protocol: $protocol, profile: $($ruleProfile -join ', '))." -ForegroundColor Green
    } catch {
        Write-Host "Error while adding rule: $($_.Exception.Message)" -ForegroundColor Red
    }

    Read-Host "`nPress Enter to return to the menu..."
}
