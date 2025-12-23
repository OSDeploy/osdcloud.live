<#PSScriptInfo
.VERSION 24.2.22.1
.GUID 7a3671f6-485b-443e-8e86-b60fdcea1419
.AUTHOR David Segura @SeguraOSD
.COMPANYNAME osdcloud.com
.COPYRIGHT (c) 2024 David Segura osdcloud.com. All rights reserved.
.TAGS OSDeploy OSDCloud WinPE OOBE Windows AutoPilot
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/OSD
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
Script should be executed in a Command Prompt using the following command
powershell Invoke-Expression -Command (Invoke-RestMethod -Uri https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1)
This is abbreviated as
powershell iex (irm https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1)
#>
<#
.SYNOPSIS
    PSCloudScript at https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1
.DESCRIPTION
    PSCloudScript at https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1
.NOTES
    Version 24.2.22.1
.LINK
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1
.EXAMPLE
    powershell iex (irm https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1)
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1')
#>
[CmdletBinding()]
param()
$ScriptName = 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/functions.ps1'
$ScriptVersion = '24.2.22.1'

#region Initialize
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

Write-Host -ForegroundColor Green "[✓] $ScriptName $ScriptVersion ($WindowsPhase Phase)"
#endregion

#region Transport Layer Security (TLS) 1.2
#Write-Host -ForegroundColor Green "[✓] Transport Layer Security (TLS) 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region Gary Blok
function Test-HPIASupport {
    $CabPath = "$env:TEMP\platformList.cab"
    $XMLPath = "$env:TEMP\platformList.xml"
    $PlatformListCabURL = "https://hpia.hpcloud.hp.com/ref/platformList.cab"
    Invoke-WebRequest -Uri $PlatformListCabURL -OutFile $CabPath -UseBasicParsing
    $Expand = expand $CabPath $XMLPath
    [xml]$XML = Get-Content $XMLPath
    $Platforms = $XML.ImagePal.Platform.SystemID
    $MachinePlatform = (Get-CimInstance -Namespace root/cimv2 -ClassName Win32_BaseBoard).Product
    if ($MachinePlatform -in $Platforms){$HPIASupport = $true}
    else {$HPIASupport = $false}
    return $HPIASupport
    }

function Test-DCUSupport {
    $SystemSKUNumber = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemSKUNumber
    $CabPathIndex = "$env:temp\DellCabDownloads\CatalogIndexPC.cab"
    $DellCabExtractPath = "$env:temp\DellCabDownloads\DellCabExtract"
    # Pull down Dell XML CAB used in Dell Command Update ,extract and Load
    if (!(Test-Path $DellCabExtractPath)){$newfolder = New-Item -Path $DellCabExtractPath -ItemType Directory -Force}
    Invoke-WebRequest -Uri "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -OutFile $CabPathIndex -UseBasicParsing -ErrorAction SilentlyContinue
    New-Item -Path $DellCabExtractPath -ItemType Directory -Force | Out-Null
    $Expand = expand $CabPathIndex $DellCabExtractPath\CatalogIndexPC.xml
    [xml]$XMLIndex = Get-Content "$DellCabExtractPath\CatalogIndexPC.xml" -ErrorAction SilentlyContinue
    #Dig Through Dell XML to find Model of THIS Computer (Based on System SKU)
    $XMLModel = $XMLIndex.ManifestIndex.GroupManifest | Where-Object {$_.SupportedSystems.Brand.Model.systemID -match $SystemSKUNumber}
    if ($XMLModel){$DCUSupportedDevice = $true}
    else {$DCUSupportedDevice = $false}
    Return $DCUSupportedDevice
    }
    


$Manufacturer = (Get-CimInstance -Class:Win32_ComputerSystem).Manufacturer
$Model = (Get-CimInstance -Class:Win32_ComputerSystem).Model
if ($Manufacturer -match "HP" -or $Manufacturer -match "Hewlett-Packard"){
    $Manufacturer = "HP"
    $HPEnterprise = Test-HPIASupport
}
if ($Manufacturer -match "Dell"){
    $Manufacturer = "Dell"
    $DellEnterprise = Test-DCUSupport
}
#endregion

#region Load Modules
if ($WindowsPhase -eq 'WinPE') {
    if ($HPEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/deviceshp.psm1')
    }
    if ($DellEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/devicesdell.psm1')
    }
}
if ($WindowsPhase -eq 'OOBE') {
    if ($HPEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/deviceshp.psm1')
    }
    if ($DellEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/devicesdell.psm1')
    }
}
if ($WindowsPhase -eq 'Specialize') {
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/_anywhere.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/defender.psm1')
    if ($HPEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/deviceshp.psm1')
    }
    if ($DellEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/devicesdell.psm1')
    }
}
if ($WindowsPhase -eq 'Windows') {
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/_anywhere.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/ne-winpe.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/autopilot.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/azosdcloudbeta.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/azosdpad.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/defender.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/osdcloudazure.psm1')
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/secrets.psm1')
    if ($HPEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/deviceshp.psm1')
    }
    if ($DellEnterprise -eq $true) {
        Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/archive/devicesdell.psm1')
    }
}
#endregion

#region PowerShell Prompt
<#
Since these functions are temporarily loaded, the PowerShell Prompt is changed to make it visual if the functions are loaded or not
[OSDCloud]: PS C:\>

You can read more about how to make the change here
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_prompts?view=powershell-5.1
#>
function Prompt {
    $(if (Test-Path variable:/PSDebugContext) { '[DBG]: ' }
    else { "[OSDCloud]: " }
    ) + 'PS ' + $(Get-Location) +
    $(if ($NestedPromptLevel -ge 1) { '>>' }) + '> '
}
#endregion