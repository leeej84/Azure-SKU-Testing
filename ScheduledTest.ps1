[CmdletBinding()]

Param
(
    [Parameter(HelpMessage='The root folder where all output files will be stored',Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$rootFolder,
    [Parameter(HelpMessage='The name of the folder to be created for the test plan to store all results',Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$testTitle
)

#Create testing Folder
Write-Host "Creating the test folder structure"
New-Item -Path "$rootFolder\$testTitle" -ItemType Directory -Force

#Performance capture start
Write-Host "Starting performance capture"
Start-Job -Name "Performance_Capture" -ScriptBlock {
    param (
        $rootFolder,
        $testTitle
    )
    Get-Counter -Continuous -SampleInterval 1 | Export-Counter -Path "$rootFolder\$testTitle\Performance.csv" -FileFormat CSV -Force
} -ArgumentList $rootFolder,$testTitle

#Run PCMark Test
Write-Host "Running PCMark Test"
$process = Start-Process "C:\Program Files\UL\PCMark 10\pcmark10cmd.exe" -ArgumentList "--export-xml `"$rootFolder\$testTitle\results.xml`" --systeminfo on --systeminfomonitor on --log `"$rootFolder\$testTitle\pcmark_log.txt`" --definition=c:\scripts\pcm10_custom.pcmdef" -PassThru
$process | Wait-Process

#Performance capture stop
Get-Job -Name Performance_Capture  | Stop-Job | Remove-Job