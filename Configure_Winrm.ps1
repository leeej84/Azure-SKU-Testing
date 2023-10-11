#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the ipaddress or FQDN of machine                                                           #
#################################################################################################################################

param
(
    [string] $hostname,
    [string] $protocol
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

$ErrorActionPreference="Stop"
$winrmHttpPort=5985
$winrmHttpsPort=5986

$helpMsg = "Usage:
            To configure WinRM over Https:
                ./ConfigureWinRM.ps1 <fqdn\ipaddress> https

            To configure WinRM over Http:
                ./ConfigureWinRM.ps1 <fqdn\ipaddress> http"


function Is-InputValid
{  
    $isInputValid = $true

    if(-not $hostname -or ($protocol -ne "http" -and $protocol -ne "https"))
    {
        $isInputValid = $false
    }

    return $isInputValid
}

function Delete-WinRMListener
{
    $config = winrm enumerate winrm/config/listener
    foreach($conf in $config)
    {
        if($conf.Contains("HTTPS"))
        {
            Write-Verbose -Verbose "HTTPS is already configured. Deleting the exisiting configuration."

            winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
            break
        }
    }
}

function Configure-WinRMListener
{
    Write-Verbose -Verbose "Configuring the WinRM listener for $hostname over $protocol protocol. This operation takes little longer time, please wait..."

    if($protocol -ne "http")
    {
            Configure-WinRMHttpsListener -hostname $hostname -port $winrmHttpsPort
    }
    else
    {
            Configure-WinRMHttpListener
    }
    
    Write-Verbose -Verbose "Successfully Configured the WinRM listener for $hostname over $protocol protocol" 
}

function Configure-WinRMHttpListener
{
    winrm delete winrm/config/Listener?Address=*+Transport=HTTP
    winrm create winrm/config/Listener?Address=*+Transport=HTTP
}

function Configure-WinRMHttpsListener
{
    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    # Create a test certificate
    $thumbprint = (New-SelfSignedCertificate -DnsName $hostname -CertStoreLocation "cert:\LocalMachine\My").Thumbprint
    if(-not $thumbprint)
    {
        throw "Failed to create the test certificate."
    }

    # Configure WinRM
    $WinrmCreate= "winrm create --% winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=`"$hostName`";CertificateThumbprint=`"$thumbPrint`"}"
    invoke-expression $WinrmCreate
    winrm set winrm/config/service/auth '@{Basic="true"}'
}

function Add-FirewallException
{
    if( $protocol -ne "http")
    {
        $port = $winrmHttpsPort
    }
    else
    {
        $port = $winrmHttpPort
    }

    # Delete an exisitng rule
    Write-Verbose -Verbose "Deleting the existing firewall exception for port $port"
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port | Out-Null

    # Add a new firewall rule
    Write-Verbose -Verbose "Adding the firewall exception for port $port"
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port | Out-Null
}


#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

# Validate script arguments
if(-not (Is-InputValid))
{
    Write-Warning "Invalid Argument exception:"
    Write-Host $helpMsg

    return
}

#Disable local token filtering
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1#

# open port 5985 in the internal Windows firewall to allow WinRM communication
netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
netsh advfirewall firewall set rule group="remote administration" new enable=yes
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
winrm quickconfig -q

#Create self signed cert
$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName "packer"
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Cert.Thumbprint -Force

#Set WinRM Parameters
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="2048"}'
winrm set winrm/config/winrs '@{MaxConcurrentUsers="100"}'
winrm set winrm/config/winrs '@{MaxProcessesPerShell="0"}'
winrm set winrm/config/winrs '@{MaxShellsPerUser="0"}'
winrm set winrm/config '@{MaxTimeoutms="7200000"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{CredSSP="true"}'
winrm set winrm/config/client '@{TrustedHosts="*"}'
winrm set "winrm/config/client" '@{AllowUnencrypted="true"}'

winrm set "winrm/config/listener?Address=*+Transport=HTTPS" "@{Port=`"5986`";Hostname=`"packer`";CertificateThumbprint=`"$($Cert.Thumbprint)`"}"

# The default MaxEnvelopeSizekb on Windows Server is 500 Kb which is very less. It needs to be at 8192 Kb. The small envelop size if not changed
# results in WS-Management service responding with error that the request size exceeded the configured MaxEnvelopeSize quota.
winrm set winrm/config '@{MaxEnvelopeSizekb = "8192"}'

# Configure WinRM listener
Configure-WinRMListener

# Add firewall exception
Add-FirewallException

# Set service to start automatically
Get-Service Winrm | Stop-Service
Get-Service Winrm | Set-Service -StartupType Automatic
Get-Service Winrm | Start-Service

# List the listeners
Write-Verbose -Verbose "Listing the WinRM listeners:"

Write-Verbose -Verbose "Querying WinRM listeners by running command: winrm enumerate winrm/config/listener"
winrm enumerate winrm/config/listener

#################################################################################################################################
#################################################################################################################################