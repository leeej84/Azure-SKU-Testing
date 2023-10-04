<#
.AUTHOR
Go-EUC - Leee Jeffries - 04.10.23

.SYNOPSIS
Runs a terraform process to deploy a single VM in Azure, the VM is then added as a trusted host for WinRM so that remote execution of code can be handled.

.DESCRIPTION
This script is designed to configure a VM in Azure and make it ready for testing.

.PARAMETER computers
List of computers to check

.EXAMPLE
& '.\Configure.ps1' -ExternalIP '10.60.93.10'

Deploys the Azure VM, Allows access to the Azure VM from the IP specified, Adds the VM's external IP to Trusted Hosts for WinRM
#>

[CmdletBinding()]

Param
(
    [Parameter(HelpMessage='External IP to allow access to the Azure VM')]
    [string]$ExternalIP
)

#Check to see if the Azure CLI is installed
    #If Azure CLI is not installed, prompt for install
    #If it is continue forwards with az login
#Run AZ Login to make sure the context is logged in before running terraform
#Run terraform and pass the external IP specified in the parameter

try {
    #If external IP is not specified, work it out and try and use that
    $autoExternalIP = $(Invoke-WebRequest -uri "https://api.ipify.org/").Content
    if (!($externalIP) -and !($autoExternalIP))  {
        Throw "No external IP address was specified and it could not be automatically detected."
    } elseif (!($externalIP)) {
        $ExternalIP = $autoExternalIP
    }

    #Check Azure CLI is installed
    $azCliCheck = Get-WmiObject -Class Win32_Product | Where {$_.Name -match 'Azure CLI'}
    if ($azCliCheck) {
        #Azure CLI found - continuing
    } else {
        Throw "Azure CLI is not installed and the script cannot continue, please install Azure CLI"
    }

    #Check if terraform is in the path environment variable
    $tfCheck = Invoke-Expression "terraform"
    if ($tfCheck) {
        #Terraform is installed and in the path
    } else {
        Throw "Terraform is not installed or is not in the path so that it can be run without specifying a location. Please ensure terraform is installed and added to the PATH variable"
    }

    #Check for az login
    $azCliLoginCheck = Invoke-Expression "az account show -o jsonc"
    if ($azCliLoginCheck) {
        #az cli returned a response so we are already logged in
        #json object should be received
    } else {
        #Not currently logged in with az cli, prompting for login
        Invoke-Expression "az login"
    }

    #Start the terraform deployment
    #Initiate terraform
    Start-Process terraform.exe -ArgumentList "init" -Wait
    #Run a terraform plan to asses the current environment
    Start-Process terraform.exe -ArgumentList "plan" -Wait
    #Implement the terraform application and wait for it to finish
    $process = Start-Process terraform.exe -ArgumentList "apply", "-auto-approve", "-var=`"ext_ip=$externalIP`"" -PassThru
    $process | Wait-Process
    #Output the results of the build process to a json file for later integrations
    Invoke-Expression "terraform.exe output -json > values.json"

    #Check for the TF outputs
    if (Test-Path "$PSScriptRoot\values.json") {
        #Values file found, we will now pull in the details
        $tfOutputs = Get-Content "$PSScriptRoot\values.json" | ConvertFrom-Json
    } else {
        Throw "Terraform did not output the values from deployment, the process of deployment cannot continue. Make sure you clean up your azure resources manually."
    }

    #Add the external IP of the VM created the the trusted hosts for WinRM
    if ($tfOutputs.public_ip_address.value) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $tfOutputs.public_ip_address.value -Confirm:$false -Force
    } else {
        Throw "Unable to add the provisioned VM to WinRM Trusted Hosts, please perform this steps manually."
    }

    #Test remote connection with the Azure VM
    $winrmCheck = Test-WSMan -ComputerName $tfOutputs.public_ip_address.value
} catch {
    Write-Error $_
}