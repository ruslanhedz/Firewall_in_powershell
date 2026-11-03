# =============================================================================
# Backup-Restore.ps1  -  BACKUP module, part 2 of 2  (owner: Ruslan)
# =============================================================================
# Loaded (dot-sourced) by FirewallRules.ps1 AFTER Backup-Create.ps1, whose helpers it uses
# (Invoke-Sftp, Invoke-ServerCommand, Get-ServerBackups, Test-ServerReachable, Write-BkLog, ...).
#
# Restore flow:
#   1. the user picks a backup in menu 9 -> R and confirms;
#   2. the server checks the backup (name, existence, SHA-256) and optionally saves a
#      'pre-restore' backup of the current policy;
#   3. THIS computer downloads the backup over SFTP (account permissions: list + download),
#      verifies SHA-256 and imports it through Invoke-AuditedChange (Operation Restore, Scope All),
#      as the audit contract requires. Nothing is pushed over SSH stdin.
# =============================================================================

# Downloads a backup, verifies it and imports it through the audit wrapper.
function Invoke-LocalRestore {
    param([Parameter(Mandatory)][string]$File)

    if ($File -notmatch '^[A-Za-z0-9._-]+\.wfw$') { throw 'invalid backup name' }
    Initialize-BkWork
    $dlDir = Join-Path $script:BkWork 'download'
    if (Test-Path -LiteralPath $dlDir) { Remove-Item -LiteralPath $dlDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $dlDir -Force | Out-Null

    try {
        $dlDirSftp = $dlDir -replace '\\', '/'
        $dl = Invoke-Sftp -Commands @("lcd `"$dlDirSftp`"", "get backups/$File", "get backups/$File.sha256")
        if (-not $dl.Ok) {
            $lastLine = @($dl.Output) | Select-Object -Last 1
            throw "download failed (does the SFTP account have the 'download' permission, and can SFTPGo read the file?): $lastLine"
        }

        $restoreWfw = Join-Path $dlDir $File
        $restoreSha = "$restoreWfw.sha256"
        if (-not (Test-Path -LiteralPath $restoreWfw) -or -not (Test-Path -LiteralPath $restoreSha)) {
            throw 'downloaded files are missing'
        }
        $restoreExpected = ((Get-Content -LiteralPath $restoreSha -TotalCount 1) -split '\s+')[0].ToLower()
        if ($restoreExpected -notmatch '^[0-9a-f]{64}$') { throw 'the .sha256 file is malformed' }
        $restoreCalc = (Get-FileHash -LiteralPath $restoreWfw -Algorithm SHA256).Hash.ToLower()
        if ($restoreCalc -ne $restoreExpected) { throw 'SHA-256 mismatch (download corrupted or backup changed)' }
        $restoreBytes = (Get-Item -LiteralPath $restoreWfw).Length
        Write-BkLog "downloaded $File ($restoreBytes bytes), sha256=$restoreCalc" 'Restore'

        # The restore goes through the audit wrapper (Operation Restore, Scope All).
        [void](Invoke-AuditedChange -Operation 'Restore' -Scope All -Initiator 'interactive' `
            -Reason "Restore of $File downloaded from the backup server (sha256 $restoreCalc)" `
            -Details @{ source = 'backup-server'; file = $File; sha256 = $restoreCalc; bytes = $restoreBytes } `
            -Action {
                $impOut = & netsh.exe advfirewall import "$restoreWfw" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "netsh import failed (exit $LASTEXITCODE): $($impOut -join ' ')" }
                if (-not (Test-BkSshRule)) { New-BkSshRule }
            })
        Write-BkLog "imported $File sha256=$restoreCalc" 'Restore'
    } finally {
        Remove-Item -LiteralPath $dlDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Menu 9 -> R
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
    Write-Host "This computer will download the backup from the server and import it." -ForegroundColor Yellow
    Write-Host "The import will OVERWRITE the entire current firewall policy (it is recorded in the audit log)." -ForegroundColor Yellow

    $saveFirst = (Read-Host "Create a backup of the current firewall policy on the server before restoring? (yes/no) [yes]").Trim().ToLower()
    $preVal = if ($saveFirst -eq '' -or $saveFirst -eq 'yes') { 'yes' } else { 'no' }

    if ((Read-Host "Type RESTORE to confirm") -cne 'RESTORE') { Write-Host "Cancelled." -ForegroundColor Yellow; return }
    if (-not (Test-ServerReachable -Port $script:BkCfg.SshPort)) { return }

    Write-Host "Restore requested - the server is checking the backup..." -ForegroundColor Cyan
    $res = Invoke-ServerCommand -Command "restore $($item.File) $preVal" -TimeoutSec $script:BkCfg.RestoreWaitSec
    if ($res.STATUS -ne 'OK') { Write-Host "Restore failed: $($res.MESSAGE)" -ForegroundColor Red; return }

    Write-Host "Server confirmed. Downloading and importing..." -ForegroundColor Cyan
    try {
        Invoke-LocalRestore -File $item.File
        Write-Host "Restore completed: the firewall policy was imported (recorded in the audit log)." -ForegroundColor Green
    } catch {
        Write-Host "Restore failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "The firewall policy was NOT changed unless the message above comes from netsh." -ForegroundColor Yellow
    }
}
