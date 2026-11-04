<#
.SYNOPSIS
    Unit tests for CLI helper functions, input validation, and rule formatting.

.DESCRIPTION
    Extracts Read-ProfileChoice and Read-ProtocolChoice from firewall.ps1 using AST
    and tests them using a canned Read-Host mock. Also tests IP, port, and rule naming
    logic without modifying firewall.ps1 or requiring administrative privileges.

    Run: powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-CliHelpers.ps1
#>
param(
    [string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'firewall.ps1')
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

# ---- 1. AST extraction of helper functions from firewall.ps1 --------------------------
Section 'AST extraction of functions from firewall.ps1'
Assert (Test-Path -LiteralPath $ScriptPath) "firewall.ps1 found at $ScriptPath"

$astTokens = $null
$astErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$astTokens, [ref]$astErrors)
Assert ($astErrors.Count -eq 0) "firewall.ps1 parses with 0 AST errors"

$funcAsts = $ast.FindAll([Func[System.Management.Automation.Language.Ast,bool]]{
    param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true)

$loaded = @{}
foreach ($fn in $funcAsts) {
    if ($fn.Name -in @('Read-ProfileChoice', 'Read-ProtocolChoice', 'Get-AuditPolicyStatusLine')) {
        . ([scriptblock]::Create($fn.Extent.Text))
        $loaded[$fn.Name] = $true
    }
}
Assert ($loaded['Read-ProfileChoice'] -eq $true) 'Read-ProfileChoice successfully extracted and loaded'
Assert ($loaded['Read-ProtocolChoice'] -eq $true) 'Read-ProtocolChoice successfully extracted and loaded'

# ---- 2. Mocking Read-Host for deterministic CLI input testing -------------------------
$script:MockInputQueue = [System.Collections.Generic.Queue[string]]::new()
function script:Queue-Input {
    param([string[]]$Values)
    $script:MockInputQueue.Clear()
    foreach ($v in $Values) { $script:MockInputQueue.Enqueue($v) }
}
# Define mock Read-Host in script scope
function Read-Host {
    param([string]$Prompt)
    if ($script:MockInputQueue.Count -gt 0) {
        return $script:MockInputQueue.Dequeue()
    }
    return ''
}

# ---------------------------------------------------------------------------------------
Section 'Read-ProfileChoice input handling'

Queue-Input @('')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 1) -and ($p[0] -eq 'Any')) "Empty input (Enter) defaults to Any profile"

Queue-Input @('1')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 1) -and ($p[0] -eq 'Domain')) "Option 1 maps to Domain"

Queue-Input @('2')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 1) -and ($p[0] -eq 'Private')) "Option 2 maps to Private"

Queue-Input @('3')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 1) -and ($p[0] -eq 'Public')) "Option 3 maps to Public"

Queue-Input @('2,3')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 2) -and ($p -contains 'Private') -and ($p -contains 'Public')) "Option '2,3' maps to Private and Public"

Queue-Input @('1, 2, 3')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 3) -and ($p -contains 'Domain') -and ($p -contains 'Private') -and ($p -contains 'Public')) "Space/comma separated '1, 2, 3' maps all three"

Queue-Input @('invalid', '99', '2')
$p = @(Read-ProfileChoice)
Assert (($p.Count -eq 1) -and ($p[0] -eq 'Private')) "Recovers after invalid inputs and accepts next valid choice"

# ---------------------------------------------------------------------------------------
Section 'Read-ProtocolChoice input handling'

Queue-Input @('1')
$proto = Read-ProtocolChoice -PortSet $false
Assert ($proto -eq 'TCP') "Option 1 maps to TCP"

Queue-Input @('2')
$proto = Read-ProtocolChoice -PortSet $false
Assert ($proto -eq 'UDP') "Option 2 maps to UDP"

Queue-Input @('')
$proto = Read-ProtocolChoice -PortSet $false
Assert ($proto -eq 'Any') "Empty input when port is NOT set defaults to Any"

Queue-Input @('')
$proto = Read-ProtocolChoice -PortSet $true
Assert ($proto -eq 'TCP') "Empty input when port IS set defaults to TCP (Windows Firewall requirement)"

Queue-Input @('bad_input', '1')
$proto = Read-ProtocolChoice -PortSet $false
Assert ($proto -eq 'TCP') "Recovers after invalid input and returns TCP"

# ---------------------------------------------------------------------------------------
Section 'IP address validation logic'
function Test-ValidIp {
    param([string]$inputIp)
    return ([ipaddress]::TryParse($inputIp, [ref]$null) -and ($inputIp -match '\.' -or $inputIp -match ':'))
}

$validIps = @('192.168.1.1', '10.0.0.1', '127.0.0.1', '8.8.8.8', '2001:db8::1', '::1', 'fe80::1ff:fe23:4567:890a')
$invalidIps = @('', 'not_an_ip', '999.999.999.999', '192.168.1.500', '1.2.3.4.5', '12345', '::g', '192.168.1.1/24')

foreach ($ip in $validIps) {
    Assert (Test-ValidIp $ip) "Valid IP accepted: '$ip'"
}
foreach ($ip in $invalidIps) {
    Assert (-not (Test-ValidIp $ip)) "Invalid IP rejected: '$ip'"
}

# ---------------------------------------------------------------------------------------
Section 'Port validation logic'
function Test-ValidPort {
    param([string]$inputPort)
    $parsedPort = 0
    return ([int]::TryParse($inputPort, [ref]$parsedPort) -and $parsedPort -ge 1 -and $parsedPort -le 65535)
}

$validPorts = @('80', '443', '22', '1', '65535', '8080')
$invalidPorts = @('', '0', '-1', '65536', '70000', 'abc', '80.5', '22/tcp')

foreach ($p in $validPorts) {
    Assert (Test-ValidPort $p) "Valid port accepted: '$p'"
}
foreach ($p in $invalidPorts) {
    Assert (-not (Test-ValidPort $p)) "Invalid port rejected: '$p'"
}

# ---------------------------------------------------------------------------------------
Section 'Rule naming and prefix formatting'
function Get-NextRulePrefix {
    param([string[]]$ExistingNames)
    $maxNumber = 0
    foreach ($rName in $ExistingNames) {
        if ($rName -match '^(\d+)-OSO') {
            $num = [int]$matches[1]
            if ($num -gt $maxNumber) { $maxNumber = $num }
        }
    }
    return ("{0:D2}" -f ($maxNumber + 1))
}

$emptyList = @()
Assert ((Get-NextRulePrefix $emptyList) -eq '01') 'First rule prefix is 01'

$existingRules = @('01-OSO-Allow-Inbound-120000', '02-OSO-Block-Outbound-120100', '04-OSO-Allow-Inbound-130000', 'NonMatchingRule')
Assert ((Get-NextRulePrefix $existingRules) -eq '05') 'Next rule prefix increments max (04 -> 05)'

$ruleName = ("{0}-OSO-{1}-{2}-{3}" -f (Get-NextRulePrefix $existingRules), 'Allow', 'Inbound', '120000')
Assert ($ruleName -match '^05-OSO-Allow-Inbound-\d{6}$') "Rule name correctly formatted: $ruleName"

Write-Host "`nPassed: $script:Passed   Failed: $script:Failed" -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
