function Show-Menu {
    Clear-Host
    Write-Host "=== FIREWALL RULES MANAGEMENT (OSO PROJECT) ===" -ForegroundColor Cyan
    Write-Host "1. Add Inbound Rule"
    Write-Host "2. Add Outbound Rule"
    Write-Host "3. Exit"
    Write-Host "==============================================="
}

while ($true) {
    Show-Menu
    $directionChoice = Read-Host "Select an option (1-3)"

    if ($directionChoice -eq '3') {
        Write-Host "Exiting script..." -ForegroundColor Yellow
        break
    }
    if ($directionChoice -notin @('1', '2')) {
        Write-Host "Invalid choice. Press Enter to try again." -ForegroundColor Red
        Read-Host
        continue
    }

    $direction = if ($directionChoice -eq '1') { 'Inbound' } else { 'Outbound' }

    Write-Host "`n--- Rule Configuration ($direction) ---" -ForegroundColor Cyan

    $ip = Read-Host "Enter IP address (or press Enter to apply to all addresses)"
    $port = Read-Host "Enter port number (or press Enter to apply to all ports)"
    
    $actionChoice = Read-Host "Select action - [1] Allow / [2] Block"
    $action = if ($actionChoice -eq '1') { 'Allow' } else { 'Block' }

    $ruleName = "OSO-$action-$direction-$(Get-Date -Format 'HHmmss')"
    
    $parameters = @{
        DisplayName = $ruleName
        Direction   = $direction
        Action      = $action
    }

    if ([string]::IsNullOrWhiteSpace($ip) -eq $false) {
        $parameters.Add('RemoteAddress', $ip)
    }

    if ([string]::IsNullOrWhiteSpace($port) -eq $false) {
        $parameters.Add('Protocol', 'TCP') 
        if ($direction -eq 'Inbound') {
            $parameters.Add('LocalPort', $port)
        } else {
            $parameters.Add('RemotePort', $port)
        }
    }

    Write-Host "`nCreating rule..." -ForegroundColor Yellow
    try {
        New-NetFirewallRule @parameters | Out-Null
        Write-Host "Success! Rule '$ruleName' has been added." -ForegroundColor Green
    } catch {
        Write-Host "Error while adding rule: $($_.Exception.Message)" -ForegroundColor Red
    }

    Read-Host "`nPress Enter to return to the menu..."
}