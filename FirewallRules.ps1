function Show-Menu {
    Clear-Host
    Write-Host "=== FIREWALL RULES MANAGEMENT ===" -ForegroundColor Cyan
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
        New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null
        Write-Host "Success! Rule '$ruleName' has been added." -ForegroundColor Green
    } catch {
        Write-Host "Error while adding rule: $($_.Exception.Message)" -ForegroundColor Red
    }

    Read-Host "`nPress Enter to return to the menu..."
}