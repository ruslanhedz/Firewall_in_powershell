# =============================================================================
# Backup-Create.ps1  -  BACKUP module, part 1 of 2  (owner: Ruslan)
# =============================================================================
# Loaded (dot-sourced) by FirewallRules.ps1 from the 'backup' directory next to it.
# Contains: shared settings and helpers, the Export agent (the backup server pulls the policy
# over SSH), asking the server for a backup, and listing the backups on the server.
# Restoring lives in Backup-Restore.ps1, which needs this file.
# Variables and functions of this module use the prefix Bk / Bk- to avoid clashes with AUDIT.
# =============================================================================

$script:BkServerIp = '10.0.2.30'
$script:BkWork     = Join-Path $env:ProgramData 'FirewallBackup\agent'
$script:BkAgentLog = Join-Path $script:BkWork 'agent.log'

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

# Entry point of the agent (called by the backup server through SSH, forced command "-Agent Export").
# stdout belongs to the protocol with the server. Restoring does NOT use the agent any more:
# the client downloads the backup over SFTP (see Backup-Restore.ps1).
function Invoke-BackupAgent {
    param([Parameter(Mandatory)][ValidateSet('Export')][string]$Agent)
    $WarningPreference  = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $script:AuditInitiatorDefault = 'automation'
    Initialize-BkWork
    try {
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
    catch {
        Write-BkLog "ERROR $($_.Exception.Message)" $Agent
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}

# ---------------------------------------------------------------- client side (menu option 9)
# Called by FirewallRules.ps1 after the agent entry point (so it never runs in -Agent mode).
function Initialize-BkClient {
    $script:BkCfg = @{
        Host           = $script:BkServerIp
        SftpPort       = 2022                    # SFTPGo: list + download of backups
        SshPort        = 22                      # backup server: backup / restore requests
        SshUser        = 'fwbackup'
        UserOverride   = ''                      # SFTP account; empty = Windows user name (lowercase)
        KeyPath        = (Join-Path (Join-Path $env:USERPROFILE '.fwbackup') 'id_ed25519')
        KnownHosts     = (Join-Path (Join-Path $env:USERPROFILE '.fwbackup') 'known_hosts')
        WaitSec        = 120
        RestoreWaitSec = 180
    }
    $script:BkCfg.User = if ($script:BkCfg.UserOverride) { $script:BkCfg.UserOverride } else { $env:USERNAME.ToLower() }
    if ($script:BkCfg.User -notmatch '^[a-z0-9][a-z0-9._-]{0,31}$') {
        Write-Host "Backup: account name '$($script:BkCfg.User)' is not allowed on the server (a-z, 0-9, . _ -). Set UserOverride in Initialize-BkClient (Backup-Create.ps1)." -ForegroundColor Yellow
    }
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
    $argLine = "-T -i `"$key`" -p $($script:BkCfg.SshPort) -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o `"UserKnownHostsFile=$known`" -o ConnectTimeout=10 -o ServerAliveInterval=10 -o LogLevel=ERROR $($script:BkCfg.SshUser)@$($script:BkCfg.Host) `"$Command`""
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

# Lists complete backups on the server (SFTP account: list + download, no write access)
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
