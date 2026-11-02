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
#>
[CmdletBinding()]
param(
    [switch]$SyncAudit
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
$script:AuditProfileKeys   = [ordered]@{ Domain = 'DomainProfile'; Private = 'StandardProfile'; Public = 'PublicProfile' }
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
    param([ValidateSet('Log', 'Baseline', 'Bin')][string]$Kind = 'Log')
    switch ($Kind) {
        'Log'      { Join-Path $script:AuditDir 'audit.jsonl' }
        'Baseline' { Join-Path $script:AuditDir 'baseline.json' }
        'Bin'      { Join-Path $script:AuditDir 'bin' }
    }
}

function Initialize-AuditStore {
    if (-not (Test-Path -LiteralPath $script:AuditDir)) {
        New-Item -ItemType Directory -Path $script:AuditDir -Force -ErrorAction Stop | Out-Null
    }
}

# All log files, oldest first (rotated files first, the live file last).
function Get-AuditFiles {
    if (-not (Test-Path -LiteralPath $script:AuditDir)) { return @() }
    $files = @()
    $files += @(Get-ChildItem -LiteralPath $script:AuditDir -Filter 'audit-*.jsonl' -File -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object { $_.FullName })
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
    param([int]$TimeoutMs = 60000)
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
    if ($Scope -in 'All', 'Rules', 'Names') {
        $k = Open-AuditPolicyKey 'FirewallRules'
        if ($k) {
            try {
                $list = if ($Scope -eq 'Names') { $Names } else { $k.GetValueNames() }
                foreach ($n in $list) {
                    if ([string]::IsNullOrEmpty($n)) { continue }
                    $raw = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ($null -eq $raw) { continue }
                    $raw = [string]$raw
                    $key = "rule:$n"
                    if ($null -ne $RawSink) { $RawSink[$key] = $raw }
                    if ($Reuse -and (Test-AuditKey $Reuse.Raws $key) -and (Test-AuditKey $Reuse.Entries $key) -and
                        ([string]$Reuse.Raws[$key] -ceq $raw)) {
                        $snap[$key] = $Reuse.Entries[$key]
                    } else {
                        $snap[$key] = ConvertFrom-AuditRuleString $raw
                    }
                }
            } finally { $k.Close() }
        }
    }
    if ($Scope -in 'All', 'Profiles') {
        foreach ($p in $script:AuditProfileKeys.Keys) {
            $pk = Open-AuditPolicyKey $script:AuditProfileKeys[$p]
            if ($pk) {
                try { $snap["profile:$p"] = Get-AuditProfileEntry $pk } finally { $pk.Close() }
            }
        }
    }
    return $snap
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
        return [pscustomobject]@{
            Corrupt = $false; Entries = $entries; Raws = $raws
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
        v = 1; ts = $Ts.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
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
    if ($loaded -and -not $loaded.Corrupt) {
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

    $why = if ($null -eq $loaded) { 'missing' } else { "corrupt: $($loaded.Error)" }
    $ts = [DateTime]::UtcNow
    $raws = @{}
    $snap = Get-PolicySnapshot -Scope All -RawSink $raws
    $rawOrdered = [ordered]@{}
    foreach ($k in ($raws.Keys | Sort-Object)) { $rawOrdered[$k] = $raws[$k] }
    $hash = Get-AuditBaselineHash -Entries $snap -Raws $rawOrdered
    [void](Write-AuditRecord -Type 'baseline' -Fields ([ordered]@{
        reason = $why; ruleCount = $rawOrdered.Count; profileCount = ($snap.Count - $rawOrdered.Count)
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
    param($Event)
    return [ordered]@{
        user = (Resolve-AuditSid $Event.Sid); sid = $Event.Sid; application = $Event.App
        evidence = 'eventlog'; eventId = $Event.Id
        eventTime = $Event.Time.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
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
                $actor = New-AuditEventActor $idx.AllDeleted[-1]
            }
        } elseif ($idx.Settings.Count -gt 0) {
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

# source = who/what made the change: 'oso' (this tool), 'system' (Windows itself), 'external'.
function Get-AuditChangeSource {
    param($Item, $Actor)
    if ($Actor.evidence -eq 'eventlog') {
        $sid = [string]$Actor.sid
        $app = [string]$Actor.application
        $sysSid = ($sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) -or $sid.StartsWith('S-1-5-80-')
        $inWin = ($app.Length -gt 0) -and $app.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
        if ($sysSid -and $inWin) { return 'system' }
        return 'external'
    }
    $entry = if ($Item.After) { $Item.After } else { $Item.Before }
    foreach ($f in 'displayName', 'displayGroup') {
        if ((Test-AuditKey $entry $f) -and ([string]$entry[$f]).StartsWith('@')) { return 'system' }
    }
    return 'external'
}

function Write-AuditChange {
    param($Item, [string]$Detection, [string]$Source, $Actor, [string]$TxId, [string]$Initiator, [string[]]$Related = @())
    $isRule = $Item.Key.StartsWith('rule:')
    $id = $Item.Key.Substring($Item.Key.IndexOf(':') + 1)
    $entry = if ($Item.After) { $Item.After } else { $Item.Before }
    $f = [ordered]@{
        op = $Item.Op
        kind = $(if ($isRule) { 'rule' } else { 'profile' })
    }
    if ($isRule) {
        $f['ruleId'] = $id
        $dn = [string]$entry['displayName']
        $f['displayName'] = $dn
        if ($dn.StartsWith('@')) { $f['displayNameResolved'] = Resolve-AuditResourceString $dn }
    } else {
        $f['profile'] = $id
    }
    $f['source'] = $Source
    $f['detection'] = $Detection
    $f['actor'] = $Actor
    $f['before'] = $Item.Before
    $f['after'] = $Item.After
    $f['changes'] = @($Item.Changes)
    if ($Related.Count -gt 0) { $f['relatedTxids'] = [string[]]$Related }
    [void](Write-AuditRecord -Type 'change' -TxId $TxId -Initiator $Initiator -Fields $f)
}

# ------------------------------------------------------- the audited-change wrapper

function Invoke-AuditedChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [ValidateSet('Names', 'NewRules', 'Profiles', 'All')][string]$Scope = 'Names',
        [string[]]$Names = @(),
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Initiator,
        [string]$Reason,
        [System.Collections.IDictionary]$Details
    )
    $auditErr = $null
    $auditOut = $null
    Enter-AuditLock
    try {
        # Everything up to and including the write-ahead 'intent' record is the PREPARE phase:
        # if any of it fails (log unwritable, corrupt, locked...) the change is NOT executed.
        try {
            Initialize-AuditStore
            $auditTx = [guid]::NewGuid().ToString()
            $auditWatch = [Diagnostics.Stopwatch]::StartNew()
            $auditBl = Get-AuditBaselineState
            $auditEntries = $auditBl.Entries

            # ---- state before the change
            $auditPreNames = $null
            $auditRawBefore = @{}
            switch ($Scope) {
                'Names'    { $auditBefore = Get-PolicySnapshot -Scope Names -Names $Names -RawSink $auditRawBefore }
                'NewRules' { $auditPreNames = Get-PolicyRuleNames; $auditBefore = [ordered]@{} }
                'Profiles' { $auditBefore = Get-PolicySnapshot -Scope Profiles }
                'All'      { $auditBefore = Get-PolicySnapshot -Scope All -RawSink $auditRawBefore -Reuse $auditBl }
            }

            # ---- write-ahead record
            $auditWarn = @()
            if ($Details -and $Details.Contains('expectedDisplayName') -and $Scope -eq 'Names' -and $Names.Count -eq 1) {
                $auditKey = "rule:$($Names[0])"
                if (-not $auditBefore.Contains($auditKey)) {
                    $auditWarn += 'rule no longer exists at execution time'
                } elseif ([string]$auditBefore[$auditKey]['displayName'] -ne [string]$Details['expectedDisplayName']) {
                    $auditWarn += "rule changed since it was listed (expected '$($Details['expectedDisplayName'])', found '$($auditBefore[$auditKey]['displayName'])')"
                }
            }
            [void](Write-AuditRecord -Type 'intent' -TxId $auditTx -Initiator $Initiator -Fields ([ordered]@{
                operation = $Operation; scope = $Scope; names = [string[]]@($Names)
                reason = $Reason; details = $Details; warnings = [string[]]@($auditWarn)
            }))

            # ---- drift: changes made behind our back to the objects we are about to touch
            $auditSub = [ordered]@{}
            switch ($Scope) {
                'Names' {
                    foreach ($auditN in $Names) { if ($auditEntries.Contains("rule:$auditN")) { $auditSub["rule:$auditN"] = $auditEntries["rule:$auditN"] } }
                }
                'Profiles' {
                    foreach ($auditK in @($auditEntries.Keys)) { if ($auditK.StartsWith('profile:')) { $auditSub[$auditK] = $auditEntries[$auditK] } }
                }
                'All' { $auditSub = $auditEntries }
            }
            $auditDrift = @(Compare-PolicySnapshot -Before $auditSub -After $auditBefore)
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
            throw "Audit log unavailable - the change was NOT performed. $($_.Exception.Message)"
        }

        # ---- the change itself
        try { $auditOut = & $Action } catch { $auditErr = $_ }

        # ---- state after the change; the log reflects what REALLY changed
        $auditSnapTime = [DateTime]::UtcNow
        $auditRawAfter = @{}
        switch ($Scope) {
            'Names'    { $auditAfter = Get-PolicySnapshot -Scope Names -Names $Names -RawSink $auditRawAfter }
            'NewRules' {
                $auditSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($auditN in $auditPreNames) { [void]$auditSeen.Add($auditN) }
                $auditNew = @((Get-PolicyRuleNames) | Where-Object { -not $auditSeen.Contains($_) })
                $auditAfter = Get-PolicySnapshot -Scope Names -Names $auditNew -RawSink $auditRawAfter
            }
            'Profiles' { $auditAfter = Get-PolicySnapshot -Scope Profiles }
            'All'      { $auditAfter = Get-PolicySnapshot -Scope All -RawSink $auditRawAfter -Reuse $auditBl }
        }
        $auditDiff = @(Compare-PolicySnapshot -Before $auditBefore -After $auditAfter)

        $auditLogErr = $null
        try {
            $auditActor = Get-AuditScriptActor -Initiator $Initiator
            foreach ($auditD in $auditDiff) {
                Write-AuditChange -Item $auditD -Detection 'script' -Source 'oso' -Actor $auditActor `
                    -TxId $auditTx -Initiator $Initiator
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
                }
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
    } finally { Exit-AuditLock }

    if ($auditErr) { throw $auditErr }
    return [pscustomobject]@{
        Success = $true; TxId = $auditTx; Changes = $auditDiff
        Added = @($auditDiff | Where-Object Op -eq 'Added').Count
        Removed = @($auditDiff | Where-Object Op -eq 'Removed').Count
        Modified = @($auditDiff | Where-Object Op -eq 'Modified').Count
        AuditWarning = $auditLogErr; Warnings = $auditWarn
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

    $summary = [pscustomobject]@{ Created = $false; Added = 0; Removed = 0; Modified = 0; Recovered = 0; Total = 0 }
    Enter-AuditLock
    try {
        Initialize-AuditStore
        $auditBl = Get-AuditBaselineState
        if ($auditBl.Created) {
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
        $auditRelated = [string[]]@($auditDangling | ForEach-Object { [string]$_.txid })
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

        if ($auditDiff.Count -gt 0 -or $auditDangling.Count -gt 0 -or $Trigger -eq 'manual') {
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
    param([switch]$Quiet)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $files = @(Get-AuditFiles)
    $prevHash = $null; $prevSeq = $null; $prevTs = $null
    $total = 0

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
                $ts = ConvertTo-AuditDate $o.ts
                if ($prevTs -and $ts -and $ts -lt $prevTs) { $warnings.Add("${leaf}:${lineNo} timestamp goes backwards (clock changed?)") }
                $prevHash = $p.Hash; $prevSeq = $seq; $prevTs = $ts
                $firstInFile = $false
            }
        } finally { $sr.Dispose() }
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
            Write-Host '(Note the head: removal of the newest records can only be detected by comparing it with an earlier note.)' -ForegroundColor DarkGray
        }
    }
    return $result
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
        switch (Read-Host 'Source filter: [1] oso (this tool)  [2] system  [3] external  (Enter = any)') {
            '1' { $src = 'oso' } '2' { $src = 'system' } '3' { $src = 'external' }
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
                $name = if ($r.kind -eq 'rule') { if ($r.displayNameResolved) { $r.displayNameResolved } else { $r.displayName } } else { "profile $($r.profile)" }
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
    $deadline = (Get-Date).AddSeconds(30)
    $stable = 0
    $last = Get-AuditLatestEventRecordId
    while ($stable -lt 3 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 1
        $cur = Get-AuditLatestEventRecordId
        if ($cur -eq $last) { $stable++ } else { $stable = 0; $last = $cur }
    }
    for ($i = 0; $i -lt 3; $i++) {
        $mark = Get-AuditLatestEventRecordId
        [void](Invoke-AuditSync -Trigger task -Quiet)
        if ((Get-AuditLatestEventRecordId) -eq $mark) { break }
    }
}

function Get-AuditWatcherStatus {
    $st = [ordered]@{ Installed = $false; State = $null; LastRun = $null; LastResult = $null; UpToDate = $null; EventLog = $null }
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

    $ids = @($script:AuditEventIds.Values | ForEach-Object { $_ }) | Sort-Object -Unique
    $cond = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
    $sub = "<QueryList><Query Id=`"0`" Path=`"$($script:AuditEventLog)`"><Select Path=`"$($script:AuditEventLog)`">*[System[($cond)]]</Select></Query></QueryList>"
    $class = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
    $evTrigger = New-CimInstance -CimClass $class -ClientOnly
    $evTrigger.Subscription = $sub
    $evTrigger.Enabled = $true
    $startTrigger = New-ScheduledTaskTrigger -AtStartup

    $psArg = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$installed`" -SyncAudit"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArg
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskPath $script:AuditTaskPath -TaskName $script:AuditTaskName -Action $action `
        -Trigger @($evTrigger, $startTrigger) -Principal $principal -Settings $settings -Force `
        -Description 'Records firewall policy changes made outside firewall.ps1 (audit watcher).' | Out-Null
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
    Write-Host "8. Install / Uninstall audit watcher"
    Write-Host "9. Exit"
    Write-Host "==============================================="
    if ($script:AuditStatus) { Write-Host $script:AuditStatus.Text -ForegroundColor $script:AuditStatus.Color }
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
    $choice = Read-Host "Select an option (1-9)"

    if ($choice -eq '9') {
        Write-Host "Exiting script..." -ForegroundColor Yellow
        break
    }
    if ($choice -notin @('1', '2', '3', '4', '5', '6', '7', '8')) {
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
        try { [void](Test-AuditLogIntegrity) } catch { Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red }
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
        $wChoice = (Read-Host "[I] Install / update   [U] Uninstall   [Enter] Cancel").Trim().ToUpperInvariant()
        try {
            if ($wChoice -eq 'I') {
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
