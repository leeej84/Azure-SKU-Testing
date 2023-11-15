<#
.AUTHOR
Go-EUC - Leee Jeffries - 04.10.23

.SYNOPSIS
Runs a terraform process to deploy a single VM in Azure, the VM is then added as a trusted host for WinRM so that remote execution of code can be handled.

.DESCRIPTION
This script is designed to configure a VM in Azure and make it ready for testing.

.PARAMETER externalIP
External IP of the machine to be added to the Azure NSG to allow full access to the VM

.PARAMETER rootFolder
The root folder where all output files will be stored

.PARAMETER testTitle
The name of the folder to be created for the test plan to store all results

.PARAMETER testIterations
The number of iterations to perform for the test default is 1

.EXAMPLE
& '.\Configure.ps1' -ExternalIP '10.60.93.10'

Deploys the Azure VM, Allows access to the Azure VM from the IP specified, Adds the VM's external IP to Trusted Hosts for WinRM
#>

[CmdletBinding()]

Param
(
    [Parameter(HelpMessage='External IP to allow access to the Azure VM')]
    [string]$externalIP,
    [Parameter(HelpMessage='The root folder where all output files will be stored',Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$rootFolder,
    [Parameter(HelpMessage='The name of the folder to be created for the test plan to store all results',Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$testTitle,
    [Parameter(HelpMessage='The number of iterations to perform for the test, default is 1',Mandatory=$true)]
    [int32]$testIterations=1
)

#Dot source the functions written
. .\Functions.ps1

try {
    #If external IP is not specified, work it out and try and use that
    $autoExternalIP = Get-ExternalIP
    if (!($externalIP) -and !($autoExternalIP))  {
        Throw "No external IP address was specified and it could not be automatically detected."
    } elseif (!($externalIP)) {
        $ExternalIP = $autoExternalIP
    }

    #Check Azure CLI is installed
    if (Get-Product -product 'Azure CLI') {
        #Azure CLI found - continuing
    } else {
        Throw "Azure CLI is not installed and the script cannot continue, please install Azure CLI"
    }

    #Check if terraform is in the path environment variable
    if (Invoke-Expression "terraform") {
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
    if (Test-Path ".\values.json") {
        #Values file found, we will now pull in the details
        $tfOutputs = Get-Content ".\values.json" | ConvertFrom-Json
    } else {
        Write-Host $_
        Throw "Terraform did not output the values from deployment, the process of deployment cannot continue. Make sure you clean up your azure resources manually."
    }

    #Add the external IP of the VM created the the trusted hosts for WinRM
    if (-not [string]::IsNullOrEmpty($tfOutputs.public_ip_address.value)) {
        # Make sure the WinRM service is started on the client running this script or this command will fail and unencrypted traffic is allowed
        if ($(Get-Service WinRM).Status -ne "Running") { 
            Start-Service WinRM 
        }
        Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value true
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $tfOutputs.public_ip_address.value -Confirm:$false -Force
    } else {
        Throw "Unable to add the provisioned VM to WinRM Trusted Hosts, check the WinRM service is running on this machine and you have the relevant admin permissions."
    }

    #Test remote connection with the Azure VM
    try {
        Test-WSMan -ComputerName $tfOutputs.public_ip_address.value
    } catch {
        Throw "Unable to test the winRM remoting with the remote machine, connection failed"
    } 

    #Create a PS Remoteing Session
    $session = Create-PSSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)
    $cimsession = Create-CimSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)

    #Send a command to download PCMark
    Write-Host "Downloading PCMark"
    Invoke-Command -Session $session -ScriptBlock {
        #Hide progress bars for web downloads
        $ProgressPreference = 'SilentlyContinue'
        
        $PCMarkDownload = "https://www.guru3d.com/getdownload/2c1b2414f56a6594ffef91236a87c0e976d52e021eb6333846bab016c2f20c7c4d6ce7dfe1991cc241d59b5c8cb07e5018b083a5902ac6c67fbe3b852ca022b0f73541638028a2d270eb576309b5208d7642bced763e8806fd9c5a9bca00d71e03e3f895d9924372aebbd01f8d3b8f4f240343bb775a02b53a25b6bc5b6ecf760e598e0a09bb89138516334c15b8730a834acdb9dffc30ef1a9ea350c3d4107de0f69496b4be83b46c55febb0e533a1a32ec1e9bc4344ced2677201e0a"
        New-Item -Path 'C:\Temp' -ItemType Directory -Force | Out-Null
        if (!(Test-Path 'C:\Temp\PCMark10.zip')) {
            Invoke-WebRequest -Uri $PCMarkDownload -OutFile 'C:\Temp\PCMark10.zip'
            #Extract PCMark
            Expand-Archive 'C:\Temp\PCMark10.zip' -DestinationPath 'C:\Temp\PCMark10' -Force
            #Install PCMark
            $process = Start-Process 'C:\Temp\PCMark10\pcmark10-setup.exe' -ArgumentList '/quiet','force','install' -PassThru
            $process | Wait-Process
        }       

        #Install NuGet Package Provider
        Write-Host "Installing NuGet"
        Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.201 -Force | Out-Null

        #Install Evergreen Module#
        Write-Host "Installing EverGreen"
        Install-Module -Name Evergreen -Force | Out-Null
        Import-Module -Name Evergreen | Out-Null

        #Install Office
        Write-Host "Installing Office"
        If (!(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VersionToReport)) {
            #Get the latest office version
            $app = Get-EvergreenApp -Name 'Microsoft365Apps' | Where-Object {$_.Channel -eq 'MonthlyEnterprise'} | Sort-Object Version | Select-Object -First 1
            #Download the office XML file
            $officeXML = 'https://raw.githubusercontent.com/leeej84/Azure-SKU-Testing/main/Office.xml'
            Invoke-WebRequest -UseBasicParsing -Uri $officeXML -OutFile 'C:\Temp\Office.xml'
            Invoke-WebRequest -UseBasicParsing -Uri $app.URI -OutFile 'C:\Temp\Office_Setup.exe'
            #Run the office installer
            
            $process = Start-Process 'C:\Temp\Office_Setup.exe' '/configure C:\Temp\Office.xml' -Wait -Passthru
            $process | Wait-Process   
        }
    }

    $pcMarkLicense = Get-Content ".\pcmark_license.txt"
    Write-Host "Installing PCMark License"
    Invoke-Command -Session $session -ScriptBlock {
        param (
            $pcMarkLicense
        )
        
        #Register and PCMark
        $pcMarkExe = "C:\Program Files\UL\PCMark 10\pcmark10cmd.exe"
        $process = Start-Process -FilePath $pcMarkExe -ArgumentList "--register $pcMarkLicense" -PassThru
        $process | Wait-Process
    } -ArgumentList $pcMarkLicense

    #Active office with a test license and set registry values
    Write-Host "Activating Office"
    Invoke-Command -Session $session -ScriptBlock {
        #Activate office
        Set-Location "C:\Program files\Microsoft Office\Office16"
        $process = Start-Process -FilePath cscript -ArgumentList "OSPP.VBS"," /inpkey:DRNV7-VGMM2-B3G9T-4BF84-VMFTK" -PassThru
        $process | Wait-Process

        #Input reg values to stop office activation and prompts
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\privacy"
        New-Item -Path $regPath -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "controllerconnectedservicesenabled" -PropertyType DWORD -Value 2 -Force | Out-Null

        $regPath = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing"
        New-Item -Path $regPath -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "DisableActivationUI" -PropertyType DWORD -Value 1 -Force | Out-Null

        $regPath = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Registration"
        New-Item -Path $regPath -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "AcceptAllEulas" -PropertyType DWORD -Value 1 -Force | Out-Null
    }

    #Configure AutoLogon because we need to run an interactive session
    Write-Host "Configuring interactive logon"
    Invoke-Command -Session $session -Scriptblock {
        param (
            $username,
            $password
        )
        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String -Force
        Set-ItemProperty $RegistryPath 'DefaultUsername' -Value $username -type String -Force
        Set-ItemProperty $RegistryPath 'DefaultPassword' -Value $password -type String -Force
    } -ArgumentList $($tfOutputs.admin_username.value), $($tfOutputs.admin_password.value)
    
    #Reboot the machine to allow AutoLogon to trigger
    Restart-VM -session $session

    #Wait for reboot machine
    Wait-VM -ipAddress $($tfOutputs.public_ip_address.value)

    #Create a PS Remoteing Session
    $session = Create-PSSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)
    $cimsession = Create-CimSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)

    #Copy up the workloads for PCMark as we cannot download them
    Copy-Item -ToSession $session -Path ".\Temp_Workloads.zip" -Destination "C:\Temp"
    Invoke-Command -Session $session { Expand-Archive -Path "C:\Temp\Temp_Workloads.zip" -DestinationPath "C:\ProgramData\UL\PCMark 10\chops\dlc" -Force }
    Copy-Item -ToSession $session -Path .\pcm10_custom.pcmdef -Destination C:\Scripts -Force

    foreach ($ieration in 1..$testIterations) {
        #Set the testTitle
        $folderName = "$($testTitle)_run_$($iteration)"
        Write-Host "Folder name set to $($testTitle)_run_$($iteration)"

        #Create local folder structure for storing test results
        try {
            New-Item -Path "$rootFolder\$folderName" -ItemType Directory -Force | Out-Null
        } catch {
            Throw "Unable to create local folder structure for storing test results"
        }

        #Create remote folder structure for storing test results
        try {
            Invoke-Command -Session $session -ScriptBlock {
               param (
                $rootFolder,
                $folderName 
               )
               New-Item -Path "$rootFolder\$folderName" -ItemType Directory -Force | Out-Null 
            } -ArgumentList $rootFolder, $folderName
        } catch {
            Throw "Unable to remote folder structure for storing test results"
        }

        #Setup a scheduled task to run tests
        $taskName = "PCMark10_Test"
        $scriptLocation = "C:\Scripts\ScheduledTest.ps1"
        Invoke-Command -Session $session -Scriptblock {New-Item -Path "C:\Scripts" -ItemType Directory -Force | Out-Null}
        Copy-Item -ToSession $session -Path ".\ScheduledTest.ps1" -Destination $scriptLocation -Recurse -Force

        $Trigger = New-ScheduledTaskTrigger -Once
        $Action = New-ScheduledTaskAction -Execute "PowerShell" -Argument "-ExecutionPolicy Bypass -File $scriptLocation -rootFolder $rootFolder -testTitle $folderName" 
        $Principal = New-ScheduledTaskPrincipal -UserId "azureuser" -LogonType Interactive
        Register-ScheduledTask -CimSession $cimsession -TaskName $taskName -Trigger $Trigger -Action $Action -Principal $Principal
        Start-Sleep -Seconds 10
        Start-ScheduledTask -CimSession $cimsession -TaskName $taskName
        Start-Sleep -Seconds 10

        #Check if the scheduled task is completed or not
        do {
            $taskState = Get-ScheduledTask -CimSession $cimsession -TaskName $taskName | Select-Object -ExpandProperty State
            Write-Host "Waiting for the task to finish"
            Start-Sleep -Seconds 30
        } until ($taskState -eq "Ready")

        #Remove the scheduled task
        Unregister-ScheduledTask -CimSession $cimsession -TaskName $taskName -Confirm:$false

        #Gather all files
        Write-Host "Copying Test Results"
        Copy-Item -FromSession $session -Path $rootFolder\$folderName\* -Destination $rootFolder\$folderName -Recurse -Force

        #Reboot the VM and Wait for reboot
        #Create a PS Remoteing Session
        $session = Create-PSSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)
        $cimsession = Create-CimSession -username $($tfOutputs.admin_username.value) -password $($tfOutputs.admin_password.value) -ipaddress $($tfOutputs.public_ip_address.value)
        #Wait for reboot machine
        Wait-VM -ipAddress $($tfOutputs.public_ip_address.value) 

        #Deallocate and reallocate the VM
        Deallocate-VM -rg $tfOutputs.resource_group_name.value -vmName $tfOutputs.vm_name.value
        
        do {       
            Start-VM -rg $tfOutputs.resource_group_name.value -vmName $tfOutputs.vm_name.value     
            $powerState = Get-VMPowerState -rg $tfOutputs.resource_group_name.value -vmName $tfOutputs.vm_name.value
            Write-Host "Checking VM power state to make sure its running"
            Start-Sleep -Seconds 30
        } until ($powerState -eq "VM running")
    }
} catch {
    Write-Error $_
}

