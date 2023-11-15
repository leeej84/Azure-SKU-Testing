Function Get-ExternalIP {
    #Get the external IP from where the script is running
    return "error"#$(Invoke-WebRequest -uri "https://api.ipify.org/" -UseBasicParsing).Content
}

Function Get-Product {
    [CmdletBinding()]
    param(
        [string]$product
    )
    #Check for the existence of a product
    return  Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -match $product}
}

Function Wait-VM {
    [CmdletBinding()]
    param(
        [string]$ipAddress
    )
    Start-Sleep -Seconds 60
    do {
        $pingTest = $(Test-NetConnection -ComputerName $ipAddress -InformationLevel Quiet -WarningAction SilentlyContinue)
        Start-Sleep -Seconds 30
        Write-Host "Waiting for 30 seconds"
    } until ($pingTest -eq "True")
}

Function Restart-VM {
    [CmdletBinding()]
    param(
        $session
    )
    Write-Host "Rebooting VM"
    Invoke-Command -Session $session -ScriptBlock {
        Restart-Computer -Force
    }
}

Function Create-PSSession {
    [CmdletBinding()]
    param(
        $ipAddress,
        $username,
        $password
    )
    [securestring]$secStringPassword = ConvertTo-SecureString $password -AsPlainText -Force
    [pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($username, $secStringPassword)
    return New-PSSession -ComputerName $($tfOutputs.public_ip_address.value) -Credential $credObject -Authentication Basic
}

Function Create-CimSession {
    [CmdletBinding()]
    param(
        $ipAddress,
        $username,
        $password
    )
    [securestring]$secStringPassword = ConvertTo-SecureString $password -AsPlainText -Force
    [pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($username, $secStringPassword)
    return New-CimSession -ComputerName $($tfOutputs.public_ip_address.value) -Credential $credObject -Authentication Basic
}

Function Get-VMPowerState {
    param (
        $rg,
        $vmName
    )
    try {
        $powerState = az vm show --resource-group $rg --name $vmName --show-details | ConvertFrom-Json | Select-Object -ExpandProperty PowerState
        return $powerState
    } catch {
        Throw "Could not get the powerstate of the VM"
    }
}

Function Deallocate-VM {
    param (
        $rg,
        $vmName
    )
    try {
        az vm deallocate -g $rg -n $vmName | ConvertFrom-Json
    } catch {
        Throw "Unable to deallocate the VM"
    }
}

Function Start-VM {
    param (
        $rg,
        $vmName
    )
    try {
        az vm start -g $rg -n $vmName | ConvertFrom-Json
    } catch {
        Throw "Unable to start VM"
    }
}