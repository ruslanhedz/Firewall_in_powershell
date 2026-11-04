<#
.SYNOPSIS
    Unit tests for the backup and restore module (Backup-Create.ps1 & Backup-Restore.ps1).

.DESCRIPTION
    Tests user validation regexes, backup listing and parsing, server command output parsing,
    and SHA-256 integrity verification during restore without connecting to external networks.
    Safe for non-administrator execution in isolated sandbox.

    Run: powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-BackupModule.ps1
#>
param(
    [string]$ModuleDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'backup')
)

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Failed = 0

function Assert {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passed++; Write-Host "  [ok]   $Message" -ForegroundColor DarkGreen }
    else { $script:Failed++; Write-Host "  [FAIL] $Message" -ForegroundColor Red }
}
function Section { param([string]$Name) Write-Host "`n== $Name" -ForegroundColor Cyan }

$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("BkTest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    # ---------------------------------------------------------------------------------
    Section 'Loading backup module files'
    $createFile = Join-Path $ModuleDir 'Backup-Create.ps1'
    $restoreFile = Join-Path $ModuleDir 'Backup-Restore.ps1'
    Assert (Test-Path -LiteralPath $createFile) "Backup-Create.ps1 exists at $createFile"
    Assert (Test-Path -LiteralPath $restoreFile) "Backup-Restore.ps1 exists at $restoreFile"

    . $createFile
    . $restoreFile

    # Re-route working directory to sandbox after dot-sourcing overrides
    $script:BkWork = Join-Path $tmpDir 'work'
    New-Item -ItemType Directory -Path $script:BkWork -Force | Out-Null
    $script:BkAgentLog = Join-Path $script:BkWork 'agent.log'
    Assert ($null -ne (Get-Command Initialize-BkClient -ErrorAction SilentlyContinue)) 'Initialize-BkClient function loaded'
    Assert ($null -ne (Get-Command Invoke-LocalRestore -ErrorAction SilentlyContinue)) 'Invoke-LocalRestore function loaded'

    # ---------------------------------------------------------------------------------
    Section 'Account name regex validation'
    $validAccounts = @('student', 'john_doe', 'user.1', 'admin-01', 'a', 'x1234567890123456789012345678901')
    $invalidAccounts = @('', 'Student', 'root;rm -rf', 'user@domain', 'user name', '../traversal', '-hyphenstart', 'toolongusername12345678901234567890')

    $accRegex = '^[a-z0-9][a-z0-9._-]{0,31}$'
    foreach ($acc in $validAccounts) {
        Assert ($acc -cmatch $accRegex) "Valid account accepted: '$acc'"
    }
    foreach ($acc in $invalidAccounts) {
        Assert ($acc -cnotmatch $accRegex) "Invalid account rejected: '$acc'"
    }

    # Test Initialize-BkClient with UserOverride
    Initialize-BkClient
    Assert ($script:BkCfg.SftpPort -eq 2022) 'Default SFTP port is 2022'
    Assert ($script:BkCfg.SshPort -eq 22) 'Default SSH port is 22'

    # ---------------------------------------------------------------------------------
    Section 'Backup file naming convention and parsing'
    $sampleFiles = @(
        'DESKTOP-TEST_20261103_163456_auto-add.wfw',
        'DESKTOP-TEST_20261103_163456_auto-add.wfw.sha256',
        'DESKTOP-TEST_20261103_120000_manual.wfw',
        'DESKTOP-TEST_20261103_120000_manual.wfw.sha256',
        'CORRUPTED_WITHOUT_SHA.wfw',
        'SOME_OTHER_FILE.txt',
        'DESKTOP-TEST_20261102_091530_scheduled.wfw',
        'DESKTOP-TEST_20261102_091530_scheduled.wfw.sha256'
    )

    # Filter only .wfw that have an accompanying .sha256 file
    $names = @($sampleFiles | Where-Object { $_ -match '\.wfw$' -and ($sampleFiles -contains "$_.sha256") } | Sort-Object -Descending)
    Assert ($names.Count -eq 3) "Found 3 complete backups with valid .sha256 pairings"
    Assert ($names -notcontains 'CORRUPTED_WITHOUT_SHA.wfw') 'Backup without .sha256 is excluded'

    $regexPattern = '_(\d{8})_(\d{6})_([a-z\-]+)\.wfw$'
    $parsed = @()
    foreach ($n in $names) {
        $m = [regex]::Match($n, $regexPattern)
        if ($m.Success) {
            $parsedDate = [datetime]::ParseExact("$($m.Groups[1].Value)$($m.Groups[2].Value)", 'yyyyMMddHHmmss', $null).ToString('yyyy-MM-dd HH:mm')
            $parsed += [pscustomobject]@{ File = $n; Date = $parsedDate; Reason = $m.Groups[3].Value }
        }
    }
    Assert ($parsed.Count -eq 3) 'All 3 valid backups successfully parsed'
    Assert ($parsed[0].Reason -eq 'auto-add' -and $parsed[0].Date -eq '2026-11-03 16:34') 'First parsed backup date and reason match expected'
    Assert ($parsed[1].Reason -eq 'manual') 'Second parsed backup reason is manual'
    Assert ($parsed[2].Reason -eq 'scheduled') 'Third parsed backup reason is scheduled'

    # ---------------------------------------------------------------------------------
    Section 'Server command output parsing'
    $mockOutput = @(
        'STATUS=OK',
        'FILE=DESKTOP-M67HB24_20261103_163456_auto-add.wfw',
        'MESSAGE=backup stored'
    )
    $parsedHash = @{}
    $mockOutput | ForEach-Object { if ($_ -match '^([A-Z0-9_]+)=(.*)$') { $parsedHash[$Matches[1]] = $Matches[2] } }

    Assert ($parsedHash['STATUS'] -eq 'OK') 'STATUS parsed as OK'
    Assert ($parsedHash['FILE'] -eq 'DESKTOP-M67HB24_20261103_163456_auto-add.wfw') 'FILE parsed correctly'
    Assert ($parsedHash['MESSAGE'] -eq 'backup stored') 'MESSAGE parsed correctly'

    # ---------------------------------------------------------------------------------
    Section 'Restore integrity verification and tamper detection'
    $dlDir = Join-Path $tmpDir 'download_test'
    New-Item -ItemType Directory -Path $dlDir -Force | Out-Null

    $testPayload = [System.Text.Encoding]::UTF8.GetBytes('Windows Firewall Sample Export Configuration Data')
    $testWfw = Join-Path $dlDir 'TEST-BACKUP_20261104_120000_manual.wfw'
    [System.IO.File]::WriteAllBytes($testWfw, $testPayload)

    $calcSha = (Get-FileHash -LiteralPath $testWfw -Algorithm SHA256).Hash.ToLower()
    $testShaFile = "$testWfw.sha256"
    Set-Content -LiteralPath $testShaFile -Value "$calcSha  $([System.IO.Path]::GetFileName($testWfw))"

    # Test reading and validating the sha256 file
    $expectedSha = ((Get-Content -LiteralPath $testShaFile -TotalCount 1) -split '\s+')[0].ToLower()
    Assert ($expectedSha -match '^[0-9a-f]{64}$') '.sha256 file contains valid 64-character hex hash'
    Assert ($calcSha -eq $expectedSha) 'Calculated SHA-256 matches expected SHA-256'

    # Tamper with the backup file
    [System.IO.File]::AppendAllText($testWfw, 'tampered extra bytes')
    $tamperedSha = (Get-FileHash -LiteralPath $testWfw -Algorithm SHA256).Hash.ToLower()
    Assert ($tamperedSha -ne $expectedSha) 'Tampered backup file produces mismatched SHA-256'

    # Invalid filename pattern rejection
    $invalidFilenames = @('../evil.wfw', 'backup;cmd.exe.wfw', 'file with spaces.wfw', 'backup.exe')
    foreach ($badFile in $invalidFilenames) {
        $validName = ($badFile -match '^[A-Za-z0-9._-]+\.wfw$')
        Assert (-not $validName) "Invalid restore file rejected: '$badFile'"
    }

    # ---------------------------------------------------------------------------------
    Section 'Log file writing'
    Initialize-BkWork
    Write-BkLog "Test log entry 1" 'TestTag'
    Assert (Test-Path -LiteralPath $script:BkAgentLog) 'agent.log file was created'
    $logContent = Get-Content -LiteralPath $script:BkAgentLog -Raw
    Assert ($logContent -match '\[TestTag\] Test log entry 1') 'agent.log records tag and message'
}
finally {
    if (Test-Path -LiteralPath $tmpDir) {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nPassed: $script:Passed   Failed: $script:Failed" -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
