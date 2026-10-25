function Show-Menu {
    Clear-Host
    Write-Host "=== FIREWALL RULES MANAGEMENT (OSO PROJECT) ===" -ForegroundColor Cyan
    Write-Host "1. Add Inbound Rule"
    Write-Host "2. Add Outbound Rule"
    Write-Host "3. List Firewall Rules"
    Write-Host "4. Delete Firewall Rule"
    Write-Host "5. Exit"
    Write-Host "==============================================="
}

while ($true) {
    Show-Menu
    $choice = Read-Host "Select an option (1-5)"

    if ($choice -eq '5') {
        Write-Host "Exiting script..." -ForegroundColor Yellow
        break
    }
    if ($choice -notin @('1', '2', '3', '4')) {
        Write-Host "Invalid choice. Press Enter to try again." -ForegroundColor Red
        Read-Host
        continue
    }

    if ($choice -eq '3' -or $choice -eq '4') {
        Write-Host "`n--- Current Firewall Rules ---" -ForegroundColor Cyan
        
        $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "OSO-" } | Sort-Object DisplayName
        
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
                    LocalAddress  = $addressFilter.LocalAddress
                    RemoteAddress = $addressFilter.RemoteAddress
                    LocalPort     = $portFilter.LocalPort
                    RemotePort    = $portFilter.RemotePort
                    Name          = $rule.Name
                }
                $index++
            }
            
            $ruleDetails | Select-Object Index, DisplayName, Direction, Action, LocalAddress, RemoteAddress, LocalPort, RemotePort | Format-Table -AutoSize
            
            if ($choice -eq '4') {
                $delIndex = Read-Host "`nEnter the Index of the rule to delete (or press Enter to cancel)"
                if ([int]::TryParse($delIndex, [ref]$null) -and $delIndex -ge 1 -and $delIndex -le $ruleDetails.Count) {
                    $ruleToDelete = $ruleDetails[$delIndex - 1]
                    Write-Host "Deleting rule: $($ruleToDelete.DisplayName)..." -ForegroundColor Yellow
                    Remove-NetFirewallRule -Name $ruleToDelete.Name
                    Write-Host "Rule deleted successfully." -ForegroundColor Green
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

    $priority = Read-Host "Enter rule position/priority number (e.g., 1, 2, 3)"
    $priNumber = 0
    if ([int]::TryParse($priority, [ref]$priNumber)) {
        $prefix = "{0:D2}" -f $priNumber
    } else {
    }

    $ip = Read-Host "Enter IP address (or press Enter to apply to all addresses)"
    $port = Read-Host "Enter port number (or press Enter to apply to all ports)"
    
    $actionChoice = Read-Host "Select action - [1] Allow / [2] Block"
    $action = if ($actionChoice -eq '1') { 'Allow' } else { 'Block' }

    $ruleName = "$prefix-OSO-$action-$direction-$(Get-Date -Format 'HHmmss')"
    
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