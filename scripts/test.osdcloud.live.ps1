<#PSScriptInfo
.VERSION 26.01.20
.GUID 8d166026-3ff8-4a56-bb46-97e446a35ffe
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
powershell Invoke-Expression -Command (Invoke-RestMethod -Uri test.osdcloud.live)
This is abbreviated as
powershell iex (irm test.osdcloud.live)
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
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/scripts/test.osdcloud.live.ps1
.EXAMPLE
    powershell iex (irm test.osdcloud.live)
#>
[CmdletBinding()]
param()
$StartTime = Get-Date
$ScriptName = 'test.osdcloud.live'
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
Write-Host -ForegroundColor DarkGray "OSDCloud Live Test [$WindowsPhase]"
#endregion

#region Transport Layer Security (TLS) 1.2
# Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [TLS 1.2]"
# Write-Host -ForegroundColor DarkGray "[✓] [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/winpe/functions.psm1')
    $null = winpe-PowerShellModulesTest
    $null = Test-WinpeExecutionPolicyBypass -Interactive
    $null = winpe-UserShellFolderTest
    $null = winpe-RegistryEnvironmentTest
    $null = winpe-SessionEnvironmentTest
    $null = winpe-PowerShellProfilePathTest
    $null = winpe-PowerShellProfileTest
    $null = winpe-RealTimeClockUTCTest
    $null = winpe-TimeServiceTest
    $null = winpe-CurlExeTest
    $null = winpe-PackageManagementTest
    $null = winpe-NuGetPackageProviderTest
    $null = winpe-NugetExeTest
    $null = winpe-UpdatePackageManagementTest
    $null = winpe-UpdatePowerShellGetTest
    $null = winpe-PSGalleryTrustTest
    $null = winpe-AzcopyExeTest
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/specialize/functions.psm1')
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/audit/functions.psm1')
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
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
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/oobe/functions.psm1')
    $null = oobe-ExecutionPolicyTest
    $null = oobe-UserShellFolderTest
    $null = oobe-RegistryEnvironmentTest
    $null = oobe-SessionEnvironmentTest
    $null = oobe-PowerShellProfilePathTest
    $null = oobe-PowerShellProfileTest
    $null = oobe-RealTimeClockUTCTest
    $null = oobe-TimeServiceTest
    $null = oobe-CurlExeTest
    $null = oobe-PackageManagementTest
    $null = oobe-NuGetPackageProviderTest
    $null = oobe-NugetExeTest
    $null = oobe-UpdatePackageManagementTest
    $null = oobe-UpdatePowerShellGetTest
    $null = oobe-PSGalleryTrustTest
    $null = oobe-AzcopyExeTest
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
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
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/windows/functions.psm1')
    $EndTime = Get-Date
    $TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $TotalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

$EndTime = Get-Date
$TotalSeconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 2)
