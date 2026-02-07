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
    Version 26.02.06
.LINK
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/scripts/repair.osdcloud.live.ps1
.EXAMPLE
    powershell iex (irm repair.osdcloud.live)
#>
[CmdletBinding()]
param()
$startTime = Get-Date
$scriptName = 'repair.osdcloud.live'
$scriptVersion = '26.02.06'
$eventName = 'osdcloud_live_test'
#=================================================
Write-Host -ForegroundColor DarkCyan "OSDCloud Live collects diagnostic data to improve functionality"
Write-Host -ForegroundColor DarkCyan "By using OSDCloud Live, you consent to the collection of diagnostic data as outlined in the privacy policy"
Write-Host -ForegroundColor DarkGray "https://github.com/OSDeploy/osdcloud.live/privacy.md"
Write-Host ""
Write-Host -ForegroundColor DarkGray "Press Ctrl+C to cancel. Resuming in 5 seconds..."
Start-Sleep -Seconds 5
Write-Host ""
#=================================================
#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$scriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore
if ($env:SystemDrive -eq 'X:') {
    $deploymentPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') {$deploymentPhase = 'OOBE'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') {$deploymentPhase = 'Specialize'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') {$deploymentPhase = 'AuditMode'}
    else {$deploymentPhase = 'Windows'}
}
$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Write-Host -ForegroundColor DarkGray "OSDCloud Live Test [$deploymentPhase]"
#endregion
#=================================================
#region OSDCloud Live Analytics
function Send-OSDCloudLiveEvent {
    param(
        [Parameter(Mandatory)]
        [string]$EventName,
        [Parameter(Mandatory)]
        [string]$ApiKey,
        [Parameter(Mandatory)]
        [string]$DistinctId,
        [Parameter()]
        [hashtable]$Properties
    )

    try {
        $payload = [ordered]@{
            api_key     = $ApiKey
            event       = $EventName
            properties  = $Properties + @{
                distinct_id = $DistinctId
            }
            timestamp   = (Get-Date).ToString('o')
        }

        $body = $payload | ConvertTo-Json -Depth 4 -Compress
        Invoke-RestMethod -Method Post `
            -Uri 'https://us.i.posthog.com/capture/' `
            -Body $body `
            -ContentType 'application/json' `
            -TimeoutSec 2 `
            -ErrorAction Stop | Out-Null

        Write-Verbose "[$(Get-Date -format s)] [OSDCloud Live] Event sent: $EventName"
    } catch {
        Write-Verbose "[$(Get-Date -format s)] [OSDCloud Live] Failed to send event: $($_.Exception.Message)"
    }
}
# UUID
$deviceUUID = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Ignore).UUID
# Convert the UUID to a hash value to protect user privacyand ensure a consistent identifier across events
$deviceUUIDHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($deviceUUID))).Replace("-", "")
[string]$distinctId = $deviceUUIDHash
if ([string]::IsNullOrWhiteSpace($distinctId)) {
    $distinctId = [System.Guid]::NewGuid().ToString()
}
# Device
$deviceManufacturer = (Get-CimInstance -ClassName CIM_ComputerSystem -ErrorAction Stop).Manufacturer
$deviceManufacturer = $deviceManufacturer -as [string]
if ([string]::IsNullOrWhiteSpace($deviceManufacturer)) {
    $deviceManufacturer = 'OEM'
} else {
    $deviceManufacturer = $deviceManufacturer.Trim()
}
$deviceModel = ((Get-CimInstance -ClassName CIM_ComputerSystem).Model).Trim()
$deviceModel = $deviceModel -as [string]
if ([string]::IsNullOrWhiteSpace($deviceModel)) {
    $deviceModel = 'OEM'
} elseif ($deviceModel -match 'OEM|to be filled') {
    $deviceModel = 'OEM'
}
$deviceProduct = ((Get-CimInstance -ClassName Win32_BaseBoard).Product).Trim()
$deviceSystemSKU = ((Get-CimInstance -ClassName CIM_ComputerSystem).SystemSKUNumber).Trim()
$deviceVersion = ((Get-CimInstance -ClassName Win32_ComputerSystemProduct).Version).Trim()
if ($deviceManufacturer -match 'Dell') {
    $deviceManufacturer = 'Dell'
    $deviceModelId = $deviceSystemSKU
}
if ($deviceManufacturer -match 'Hewlett|Packard|\bHP\b') {
    $deviceManufacturer = 'HP'
    $deviceModelId = $deviceProduct
}
if ($deviceManufacturer -match 'Lenovo') {
    $deviceManufacturer = 'Lenovo'
    $deviceModel = $deviceVersion
    $deviceModelId = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4)
}
if ($deviceManufacturer -match 'Microsoft') {
    $deviceManufacturer = 'Microsoft'
    # Surface_Book or Surface_Pro_3
    $deviceModelId = $deviceSystemSKU
    # Surface Book or Surface Pro 3
    # $deviceProduct
}
if ($deviceManufacturer -match 'Panasonic') { $deviceManufacturer = 'Panasonic' }
if ($deviceManufacturer -match 'OEM|to be filled') { $deviceManufacturer = 'OEM' }
# Win32_ComputerSystem
$deviceSystemFamily = ((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore).SystemFamily).Trim()
# Win32_OperatingSystem
$osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Ignore).Caption
$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Ignore).Version

$computerInfo = Get-ComputerInfo -ErrorAction Ignore

if ($deploymentPhase -eq 'WinPE') {
    $osName = 'Microsoft WindowsPE'
}
else {
    $osName = [string]$computerInfo.OsName
}
$eventProperties = @{
    deploymentPhase             = [string]$deploymentPhase
    deviceManufacturer          = [string]$deviceManufacturer
    deviceModel                 = [string]$deviceModel
    deviceModelId               = [string]$deviceModelId
    deviceProduct               = [string]$deviceProduct
    deviceVersion               = [string]$deviceVersion
    deviceSystemFamily          = [string]$deviceSystemFamily
    deviceSystemSKU             = [string]$deviceSystemSKU
    deviceSystemType            = [string]$computerInfo.CsPCSystemType
    biosFirmwareType            = [string]$computerInfo.BiosFirmwareType
    biosReleaseDate             = [string]$computerInfo.BiosReleaseDate
    biosSMBIOSBIOSVersion       = [string]$computerInfo.BiosSMBIOSBIOSVersion
    keyboardName                = [string](Get-CimInstance -ClassName Win32_Keyboard | Select-Object -ExpandProperty Name)
    keyboardLayout              = [string](Get-CimInstance -ClassName Win32_Keyboard | Select-Object -ExpandProperty Layout)
    winArchitecture             = [string]$env:PROCESSOR_ARCHITECTURE
    winBuildLabEx               = [string]$computerInfo.WindowsBuildLabEx
    winBuildNumber              = [string]$computerInfo.OsBuildNumber
    winCountryCode              = [string]$computerInfo.OsCountryCode
    winEditionId                = [string]$computerInfo.WindowsEditionId
    winInstallationType         = [string]$computerInfo.WindowsInstallationType
    winLanguage                 = [string]$computerInfo.OsLanguage
    winName                     = [string]$osName
    winTimeZone                 = [string]$computerInfo.TimeZone
    winVersion                  = [string]$computerInfo.OsVersion
}
$postApi = 'phc_2h7nQJCo41Hc5C64B2SkcEBZOvJ6mHr5xAHZyjPl3ZK'
Send-OSDCloudLiveEvent -EventName $eventName -ApiKey $postApi -DistinctId $distinctId -Properties $eventProperties
#endregion
#=================================================
#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/winpe/functions.psm1')
    # winpe-RepairTls
    $null = Test-WinpePowerShellModuleDism -Interactive
    $null = Test-WinpePowerShellModuleStorage -Interactive
    Repair-WinpeExecutionPolicyBypass
    Repair-WinpeUserShellFolders
    Repair-WinpeRegistryEnvironment
    Repair-WinpeSessionEnvironment
    Repair-WinpePowerShellProfilePaths
    Repair-WinpePowerShellProfile
    Repair-WinpeRealTimeClockUTC
    Repair-WinpeTimeService
    Repair-WinpeFileCurlExe
    Repair-WinpePackageManagement
    Repair-WinpeNugetPackageProvider
    Repair-WinpeFileNugetExe
    Update-WinpePackageManagementVersion
    Update-WinpePowerShellGetVersion
    Repair-WinpePSGalleryTrust
    Repair-WinpeFileAzcopyExe
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
