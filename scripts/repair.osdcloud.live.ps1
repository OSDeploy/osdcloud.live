<#PSScriptInfo
.VERSION 26.01.20
.GUID 0684aa00-9e31-461a-9821-6dd379aa9ae4
.AUTHOR David Segura @OSDeploy
.COMPANYNAME Recast Software
.COPYRIGHT (c) 2026 David Segura | Recast Software. All rights reserved.
.TAGS OSDeploy OSDCloud WinPE OOBE Windows AutoPilot
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/osdcloud.live
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
Script should be executed in a Command Prompt using the following command
powershell Invoke-Expression -Command (Invoke-RestMethod -Uri repair.osdcloud.live)
This is abbreviated as
powershell iex (irm repair.osdcloud.live)
#>
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerShell Script which supports the OSDCloud environment
.DESCRIPTION
    PowerShell Script which supports the OSDCloud environment
.NOTES
    Version 26.01.20
.LINK
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/scripts/repair.osdcloud.live.ps1
.EXAMPLE
    powershell iex (irm repair.osdcloud.live)
#>
[CmdletBinding()]
param()
$StartTime = Get-Date
$ScriptName = 'repair.osdcloud.live'
$ScriptVersion = '26.01.20'

#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore

if ($env:SystemDrive -eq 'X:') {
    $WindowsPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') {$WindowsPhase = 'OOBE'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') {$WindowsPhase = 'Specialize'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') {$WindowsPhase = 'AuditMode'}
    else {$WindowsPhase = 'Windows'}
}

$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Write-Host -ForegroundColor DarkGray "$ScriptName $ScriptVersion ($WindowsPhase)"
Write-Host -ForegroundColor DarkGray "OSDCloud Live Repair [$WindowsPhase]"
#endregion

#region Transport Layer Security (TLS) 1.2
# Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [TLS 1.2]"
# Write-Host -ForegroundColor DarkGray "[✓] [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/winpe/functions.psm1')
    # winpe-RepairTls
    winpe-RepairExecutionPolicy
    winpe-RepairUserShellFolder
    winpe-RepairRegistryEnvironment
    winpe-RepairSessionEnvironment
    winpe-RepairPowerShellProfilePath
    winpe-RepairPowerShellProfile
    winpe-RepairRealTimeClockUTC -Force
    winpe-RepairTimeService -Force
    winpe-RepairCurl -Force
    winpe-RepairPackageManagement -Force
    winpe-RepairNugetPackageProvider -Force
    winpe-RepairNugetExe -Force
    winpe-UpdatePackageManagement -Force
    winpe-UpdatePowerShellGet -Force
    winpe-TrustPSGallery -Force
    winpe-InstallAzCopy -Force
    # winpe-InstallPowerShellModule -Name OSD
    # winpe-InstallPowerShellModule -Name OSDCloud
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/specialize/functions.ps1)
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/auditmode/functions.ps1)
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region OOBE
if ($WindowsPhase -eq 'OOBE') {
    if ($isElevated) {
        Write-Host -ForegroundColor Green "[✓] Running as $whoiam (Admin Elevated)"
    }
    else {
        Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
    }
    Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/oobe/functions.psm1)
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    if ($isElevated) {
        Write-Host -ForegroundColor Green "[✓] Running as $whoiam (Admin Elevated)"
    }
    else {
        Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
        Break
    }
    Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/windows/functions.ps1)
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

$EndTime = Get-Date
$TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
# Write-Host
# Write-Host -ForegroundColor DarkGray "[✓] Total Time: $TotalSeconds seconds"
