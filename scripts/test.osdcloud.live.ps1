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
    Version 26.02.05
.LINK
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/scripts/test.osdcloud.live.ps1
.EXAMPLE
    powershell iex (irm test.osdcloud.live)
#>
[CmdletBinding()]
param()
$startTime = Get-Date
$scriptName = 'test.osdcloud.live'
$scriptVersion = '26.02.05'

Write-Host -ForegroundColor DarkCyan "OSDCloud Live collects diagnostic data to improve functionality"
Write-Host -ForegroundColor DarkCyan "By using OSDCloud Live, you consent to the collection of diagnostic data as outlined in the privacy policy"
Write-Host -ForegroundColor DarkGray "https://github.com/OSDeploy/osdcloud.live/privacy"
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

# Write-Host -ForegroundColor DarkGray "$scriptName $scriptVersion ($deploymentPhase)"
Write-Host -ForegroundColor DarkGray "OSDCloud Live Test [$deploymentPhase]"
#endregion

#region Transport Layer Security (TLS) 1.2
# Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [TLS 1.2]"
# Write-Host -ForegroundColor DarkGray "[✓] [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
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
# Win32_ComputerSystemProduct
$computerUUID = (Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Ignore).UUID
# Convert the UUID to a hash value to protect user privacy
$computerUUIDHash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($computerUUID))).Replace("-", "")
# Win32_ComputerSystemProduct
$computerManufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore).Manufacturer
$computerModel = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore).Model
$computerModelSubstring = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore | Select-Object -ExpandProperty Model).SubString(0, 4)
$computerSystemFamily = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore).SystemFamily
$computerSKUNumber = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Ignore).SystemSKUNumber
# Win32_BaseBoard
$computerProduct = (Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Ignore).Product
# Win32_OperatingSystem
$osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Ignore).Caption
$osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Ignore).Version

[string]$distinctId = $computerUUIDHash
if ([string]::IsNullOrWhiteSpace($distinctId)) {
    $distinctId = [System.Guid]::NewGuid().ToString()
}
$eventProperties = @{
    computerManufacturer    = [string]$computerManufacturer
    computerModel           = [string]$computerModel
    computerModelSubstring  = [string]$computerModelSubstring
    computerProduct         = [string]$computerProduct
    computerSystemFamily    = [string]$computerSystemFamily
    computerSKUNumber       = [string]$computerSKUNumber
    deploymentPhase         = [string]$deploymentPhase
    osArchitecture          = [string]$env:PROCESSOR_ARCHITECTURE
    osCaption               = [string]$osCaption
    osVersion               = [string]$osVersion
}
$postApi = 'phc_2h7nQJCo41Hc5C64B2SkcEBZOvJ6mHr5xAHZyjPl3ZK'
Send-OSDCloudLiveEvent -EventName 'osdcloud_live_test' -ApiKey $postApi -DistinctId $distinctId -Properties $eventProperties
#endregion
#=================================================
#region WinPE
if ($deploymentPhase -eq 'WinPE') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/winpe/functions.psm1')
    $null = Test-WinpePowerShellModuleDism -Interactive
    $null = Test-WinpePowerShellModuleStorage -Interactive
    $null = Test-WinpeExecutionPolicyBypass -Interactive
    $null = Test-WinpeUserShellFolders -Interactive
    $null = Test-WinpeRegistryEnvironment
    $null = Test-WinpeSessionEnvironment
    $null = Test-WinpePowerShellProfilePaths
    $null = Test-WinpePowerShellProfile
    $null = Test-WinpeRealTimeClockUTC
    $null = Test-WinpeTimeService
    $null = Test-WinpeFileCurlExe
    $null = Test-WinpePackageManagement
    $null = Test-WinpeNuGetPackageProvider
    $null = Test-WinpeFileNugetExe
    $null = Test-WinpePackageManagementVersion
    $null = Test-WinpePowerShellGetVersion
    $null = Test-WinpePSGalleryTrust
    $null = Test-WinpeFileAzcopyExe
    $endTime = Get-Date
    $totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $totalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($deploymentPhase -eq 'Specialize') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/specialize/functions.psm1')
    $endTime = Get-Date
    $totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $totalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($deploymentPhase -eq 'AuditMode') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/audit/functions.psm1')
    $endTime = Get-Date
    $totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $totalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region OOBE
if ($deploymentPhase -eq 'OOBE') {
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
    $endTime = Get-Date
    $totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $totalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($deploymentPhase -eq 'Windows') {
    if ($isElevated) {
        Write-Host -ForegroundColor Green "[✓] Running as $whoiam (Admin Elevated)"
    }
    else {
        Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
        Break
    }
    $endTime = Get-Date
    $totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    Write-Host -ForegroundColor DarkGray "[i] Finished in $totalSeconds seconds"
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

$endTime = Get-Date
$totalSeconds = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
