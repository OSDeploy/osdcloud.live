<#
.SYNOPSIS
WinPE environment setup and configuration functions.

.DESCRIPTION
Functions for configuring the Windows PE environment, including execution policy,
environment variables, package management, and tool installation.

Recommended execution order for initial setup:


Additional functions (can be run after the core setup above):
    - winpe-InstallPowerShellModule -Name <ModuleName>
    - winpe-InstallDotNetCore
    - winpe-InstallZip

.NOTES
Functions are designed to be idempotent and can be safely re-run.
Most functions will skip if the target is already configured/installed.
#>

#region Helpers
function Invoke-WinpeDownload {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Uri,

        [Parameter(Mandatory = $true)]
        [string]
        $Destination,

        [System.Management.Automation.SwitchParameter]
        $AllowCurlFallback
    )

    $curlPath = Join-Path $env:SystemRoot 'System32\\curl.exe'
    if (Test-Path $curlPath) {
        & $curlPath --fail --location --silent --show-error `
            $Uri `
            --output $Destination
        if ($LASTEXITCODE -eq 0 -and (Test-Path $Destination)) {
            return
        }
        Write-Host -ForegroundColor Yellow "[!] curl download failed with exit code $LASTEXITCODE, retrying"
    }

    $bitsDllPath = Join-Path $env:SystemRoot 'System32\QMgr.dll'
    $bitsCommand = $null
    if (Test-Path $bitsDllPath) {
        $bitsCommand = Get-Command -Name Start-BitsTransfer -Module BitsTransfer -ErrorAction SilentlyContinue
    }
    else {
        # Write-Host -ForegroundColor Yellow "[!] QMgr.dll not found; skipping Start-BitsTransfer"
    }
    if ($bitsCommand) {
        try {
            Start-BitsTransfer -Source $Uri -Destination $Destination -ErrorAction Stop
            return
        }
        catch {
            Write-Host -ForegroundColor Yellow "[!] Start-BitsTransfer failed, retrying with Invoke-WebRequest"
        }
    }

    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination -ErrorAction Stop
}
#endregion

#region ExecutionPolicy
function winpe-ExecutionPolicyTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )

    # Get the current execution policy
    try {
        $executionPolicy = Get-ExecutionPolicy -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    # Success
    if ($executionPolicy -eq 'Bypass') {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] PowerShell Execution Policy is set to Bypass"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] PowerShell Execution Policy is NOT set to Bypass [$executionPolicy]"
    return 1
}
function winpe-ExecutionPolicyRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-ExecutionPolicyTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        Remove-Variable -Name executionPolicy -ErrorAction SilentlyContinue
    }

    $results = winpe-ExecutionPolicyTest
}
#endregion

#region Modules
function winpe-PowerShellModulesTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )

    $requiredModules = @(
        "Dism",
        "Storage"
    )

    # Test if a repair is needed
    $remediate = $false
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $remediate = $true
            break
        }
    }

    # Success
    if (-not $remediate) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] Required PowerShell Modules exist"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] Required PowerShell Modules do NOT exist. This can NOT be repaired online."
    foreach ($module in $requiredModules) {
        # If Module is installed, continue
        if (Get-Module -ListAvailable -Name $module) {
            continue
        }
        if ($module -eq "Dism") {
            Write-Host -ForegroundColor DarkGray "$module PowerShell Module requires ADK Optional Component WinPE-DismCmdlets"
            continue
        }
        if ($module -eq "Storage") {
            Write-Host -ForegroundColor DarkGray "$module PowerShell Module requires ADK Optional Component WinPE-StorageWMI"
            continue
        }
        Write-Host -ForegroundColor DarkGray $module
    }
    return 1
}
#endregion

#region UserShellFolders
function winpe-UserShellFolderTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )

    $requiredFolders = @(
        "$env:ProgramFiles\WindowsPowerShell\Scripts",
        "$env:UserProfile\AppData\Local",
        "$env:UserProfile\AppData\Roaming",
        "$env:UserProfile\Desktop",
        "$env:UserProfile\Documents\WindowsPowerShell",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Scripts"
    )

    # Test if a repair is needed
    $remediate = $false
    foreach ($folder in $requiredFolders) {
        if (-not (Test-Path -Path $folder)) {
            $remediate = $true
            break
        }
    }

    # Success
    if (-not $remediate) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] User Shell Folders exist"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] User Shell Folders do NOT exist"
    foreach ($item in $requiredFolders) {
        if (Test-Path -Path $item) {
            continue
        }
        Write-Host -ForegroundColor DarkGray $item
    }
    return 1
}
function winpe-UserShellFolderRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-UserShellFolderTest -Quiet
    
    # Success
    if ($results -eq 0) {
        return
    }

    $requiredFolders = @(
        "$env:ProgramFiles\WindowsPowerShell\Modules",
        "$env:ProgramFiles\WindowsPowerShell\Scripts",
        "$env:UserProfile\AppData\Local",
        "$env:UserProfile\AppData\Roaming",
        "$env:UserProfile\Desktop",
        "$env:UserProfile\Documents\WindowsPowerShell",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Scripts"
    )

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    foreach ($item in $requiredFolders) {
        if (Test-Path -Path $item) {
            continue
        }

        try {
            $null = New-Item -Path $item -ItemType Directory -Force -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }
    $results = winpe-UserShellFolderTest
}
#endregion

#region RegistryEnvironment
function winpe-RegistryEnvironmentTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
        'USERPROFILE'   = "$env:UserProfile"
    }

    # Test
    $remediate = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            $remediate = $true
            break
        }
    }

    # Success
    if (-not $remediate) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] Environment Variables exist in the Registry"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] Environment Variables do NOT exist in the Registry"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            Write-Host -ForegroundColor DarkGray "$name = $value"
        }
    }
    return 1
}
function winpe-RegistryEnvironmentRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-RegistryEnvironmentTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }
    
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
        'USERPROFILE'   = "$env:UserProfile"
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            try {
                # Write-Host -ForegroundColor DarkGray "$name = $value"
                Set-ItemProperty -Path $registryPath -Name $name -Value $value -Force -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }
    }
    $results = winpe-RegistryEnvironmentTest
}
#endregion

#region SessionEnvironment
function winpe-SessionEnvironmentTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
    }

    # Test
    $remediate = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            $remediate = $true
            break
        }
    }

    # Success
    if (-not $remediate) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] Environment Variables exist in the current PowerShell Session"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] Environment Variables do NOT exist in the current PowerShell Session"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            Write-Host -ForegroundColor DarkGray "$name = $value"
        }
    }
    return 1
}
function winpe-SessionEnvironmentRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-SessionEnvironmentTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            try {
                # Write-Host -ForegroundColor DarkGray "$name = $value"
                Set-Item -Path "env:$name" -Value $value -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }
    }

    $results = winpe-SessionEnvironmentTest
}
#endregion

#region PowerShellProfilePath
function winpe-PowerShellProfilePathTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $profileDir = $PSHome
    $profilePath = Join-Path -Path $PSHome -ChildPath 'profile.ps1'
    $repairPSProfilePath = $false

    # Test
    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
        $repairPSProfilePath = $true
    }
    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
        $repairPSProfilePath = $true
    }

    # Success
    if ($repairPSProfilePath -eq $false) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] PowerShell Profile CurrentUser Paths are properly configured"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] PowerShell Profile CurrentUser Paths are NOT properly configured"
    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
        Write-Host -ForegroundColor DarkGray "CurrentUserAllHosts: [$($PROFILE.CurrentUserAllHosts)]"
    }
    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
        Write-Host -ForegroundColor DarkGray "CurrentUserCurrentHost: [$($PROFILE.CurrentUserCurrentHost)]"
    }
    return 1
}

function winpe-PowerShellProfilePathRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-PowerShellProfilePathTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
        $PROFILE.CurrentUserAllHosts = "$Home\Documents\WindowsPowerShell\profile.ps1"
        # Write-Host -ForegroundColor DarkGray "CurrentUserAllHosts: [$($PROFILE.CurrentUserAllHosts)]"
    }
    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
        $PROFILE.CurrentUserCurrentHost = "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        # Write-Host -ForegroundColor DarkGray "CurrentUserCurrentHost: [$($PROFILE.CurrentUserCurrentHost)]"
    }

    $results = winpe-PowerShellProfilePathTest
}
#endregion

#region PowerShellProfile
function winpe-PowerShellProfileTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $profileDir = $PSHome
    $profilePath = Join-Path -Path $PSHome -ChildPath 'profile.ps1'
    $repairPSProfileFile = $false

    # Test
    if (-not (Test-Path -Path $profilePath)) {
        $repairPSProfileFile = $true
    }
    else {
        $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop
        if (-not ($existingContent -match 'OSDCloud by Recast Software')) {
            $repairPSProfileFile = $true
        }
    }

    # Success
    if ($repairPSProfileFile -eq $false) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] PowerShell Profile AllUsersAllHosts is properly configured"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] PowerShell Profile AllUsersAllHosts is NOT configured"
    # Write-Host -ForegroundColor DarkGray "Causes issues with new PowerShell sessions not inheriting Registry Environment Variables"
    return 1
}

function winpe-PowerShellProfileRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
     # Test
    $results = winpe-PowerShellProfileTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    $winpePowerShellProfile = @'
# OSDCloud by Recast Software
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$registryPath | ForEach-Object {
    $k = Get-Item $_
    $k.GetValueNames() | ForEach-Object {
        $name = $_
        $value = $k.GetValue($_)
        Set-Item -Path Env:\$name -Value $value
    }
}
'@

    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    $profileDir = $PSHome
    $profilePath = Join-Path -Path $PSHome -ChildPath 'profile.ps1'

    if (Test-Path -Path $profilePath) {
        $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop
        if (-not ($existingContent -match 'OSDCloud by Recast Software')) {
            Add-Content -Path $profilePath -Value ("`r`n" + $winpePowerShellProfile) -Encoding Unicode -ErrorAction Stop
        }
    }
    else {
        if (-not (Test-Path $profileDir)) {
            $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
        $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
    }
    $results = winpe-PowerShellProfileTest
}
#endregion

#region RealTimeClockUTC
function winpe-RealTimeClockUTCTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    # Test if RealTimeIsUniversal is already set
    $realTimeIsUniversal = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -ErrorAction SilentlyContinue

    if ($realTimeIsUniversal -and ($realTimeIsUniversal.RealTimeIsUniversal -eq 1)) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] RealTime Clock is set to UTC"
        return 0
    }
    else {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] RealTime Clock is NOT set to UTC"
        return 1
    }
}

function winpe-RealTimeClockUTCRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-RealTimeClockUTCTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -Value 1 -Type DWord -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    $results = winpe-RealTimeClockUTCTest
}
#endregion

#region TimeService
function winpe-TimeServiceTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    # Can we connect to Time Service?
    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    # Test if the Time Service is correctly configured
    if (($w32timeService.StartType -eq 'Automatic') -and ($w32timeService.Status -eq 'Running')) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] Time Service [w32time] is set to Automatic and is Running"
        return 0
    }
    else {
        if ($Quiet) { return 1 }
        if ($w32timeService.StartType -ne 'Automatic') {
            Write-Host -ForegroundColor Red "[✗] Time Service [w32time] StartType is NOT set to Automatic"
        }
        if ($w32timeService.Status -ne 'Running') {
            Write-Host -ForegroundColor Red "[✗] Time Service [w32time] is NOT Running"
        }
        return 1
    }
}
function winpe-TimeServiceRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-TimeServiceTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    if ($w32timeService.StartType -ne 'Automatic') {
        try {
            Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop
            # Write-Host -ForegroundColor DarkGray "Time Service [w32time] StartType is set to Automatic"
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }

    if ($w32timeService.Status -eq 'Running') {
        # Write-Host -ForegroundColor DarkGray "Time Service [w32time] is being restarted"
        try {
            Restart-Service -Name w32time -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }
    else {
        # Write-Host -ForegroundColor DarkGray "Time Service [w32time] is being started"
        try {
            Start-Service -Name w32time -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }

    $results = winpe-TimeServiceTest
}
#endregion

#region CurlExe
function winpe-CurlExeTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $curlPath = "$env:SystemRoot\System32\curl.exe"
    if (Test-Path $curlPath) {
        if ($Quiet) { return 0 }
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor Green "[✓] Curl.exe [$($curl.VersionInfo.FileVersion)]"
        return 0
    }
    else {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] Curl is NOT installed at $curlPath"
        return 1
    }
}

function winpe-CurlExeRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-CurlExeTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    $curlPath = "$env:SystemRoot\System32\curl.exe"
    try {
        $tempZip = "$env:TEMP\curl.zip"
        $tempDir = "$env:TEMP\curl"
        
        # Download
        $url = 'https://curl.se/windows/latest.cgi?p=win64-mingw.zip'
        # Write-Host -ForegroundColor DarkGray "$url"
        Invoke-WinpeDownload -Uri $url -Destination $tempZip
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'curl.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_ -Destination $curlPath -Force -ErrorAction Stop }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $results = winpe-CurlExeTest
}
#endregion

#region PackageManagement
function winpe-PackageManagementTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    # Test if PackageManagement is already installed
    $installedModule = Get-Module -Name PackageManagement -ListAvailable

    # Success
    if ($installedModule) {
        if ($Quiet) { return 0 }
        $latestVersion = ($installedModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor Green "[✓] PackageManagement PowerShell Module [$latestVersion]"
        return 0
    }
    else {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] PackageManagement PowerShell Module is NOT installed"
        return 1
    }
}

function winpe-PackageManagementRepair {
    <#
    .SYNOPSIS
    Installs or updates the PackageManagement module in WinPE.

    .DESCRIPTION
    Checks for the presence of the PackageManagement module. If missing, warns and exits
    unless -Force is specified. With -Force, downloads version 1.4.8.1 from the PowerShell
    Gallery, installs it under Program Files, and imports it globally. If already installed,
    reports the latest installed version and does not reinstall.

    .PARAMETER Force
    When specified, performs installation/repair actions rather than only reporting status.

    .EXAMPLE
    winpe-PackageManagementRepair
    Displays the current status of the PackageManagement module without making changes.

    .EXAMPLE
    winpe-PackageManagementRepair -Force
    Downloads and installs PackageManagement 1.4.8.1, then imports the module.

    .OUTPUTS
    None. Writes status and progress messages to the host.

    .NOTES
    Designed for Windows PE. Prefers curl when available, then BitsTransfer, then Invoke-WebRequest.
    Safe to re-run; no changes are made if the desired state is already present.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-PackageManagementTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        # Write-Host -ForegroundColor DarkGray $url

        Invoke-WinpeDownload -Uri $url -Destination $tempZip -AllowCurlFallback

        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop

        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\1.4.8.1" -Force -ErrorAction Stop

        Import-Module PackageManagement -Force -Scope Global -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    
    $results = winpe-PackageManagementTest
}
#endregion

#region NuGetPackageProvider
function winpe-NuGetPackageProviderTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )

    # Test PackageManagement
    if (-not (Get-Module -Name PackageManagement -ListAvailable)) {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] NuGet Package Provider is NOT installed"
        # Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module is a required prerequisite"
        return 1
    }


    # Test Get-PackageProvider
    if (-not (Get-Command -Name Get-PackageProvider -ErrorAction SilentlyContinue)) {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] NuGet Package Provider is NOT installed"
        # Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module is a required prerequisite"
        return 1
    }

    # Test Execution Policy
    $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    if ($executionPolicy -ne 'Bypass' -and $executionPolicy -ne 'Unrestricted') {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] NuGet Package Provider is NOT installed"
        # Write-Host -ForegroundColor DarkGray "PowerShell Execution Policy is blocking installation of NuGetPackage Providers"
        return 1
    }

    # Test if NuGet Package Provider is already installed
    $provider = Get-PackageProvider -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'NuGet' }
    if ($provider) {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] NuGet Package Provider [$($provider.Version)]"
        return 0
    }

    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] NuGet Package Provider is NOT installed"
    return 1
}

function winpe-NugetPackageProviderRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-NuGetPackageProviderTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    try {
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    
    $results = winpe-NuGetPackageProviderTest
}
#endregion

#region NuGetExe
function winpe-NugetExeTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $nugetExeSourceURL = 'https://nuget.org/nuget.exe'
    $nugetFileName = 'NuGet.exe'

    # $env:LOCALAPPDATA may not be set in WinPE, so should not use env:LOCALAPPDATA
    # $nugetPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetPath = Join-Path -Path "$env:UserProfile\AppData\Local" -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetExeFilePath = Join-Path -Path $nugetPath -ChildPath $nugetFileName

    # Test if NuGet.exe is already installed
    if (Test-Path -Path $nugetExeFilePath) {
        if ($Quiet) { return 0 }
        $nugetExe = Get-Item -Path $nugetExeFilePath
        Write-Host -ForegroundColor Green "[✓] NuGet.exe [$($nugetExe.VersionInfo.FileVersion)]"
        return 0
    }

    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] NuGet.exe is NOT installed"
    return 1
}
function winpe-NugetExeRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-NugetExeTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    $nugetExeSourceURL = 'https://nuget.org/nuget.exe'
    $nugetFileName = 'NuGet.exe'
    # $env:LOCALAPPDATA may not be set in WinPE, so should not use env:LOCALAPPDATA
    # $nugetPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetPath = Join-Path -Path "$env:UserProfile\AppData\Local" -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetExeFilePath = Join-Path -Path $nugetPath -ChildPath $nugetFileName

    # Create directory if it does not exist
    if (-not (Test-Path -Path $nugetPath)) {
        $null = New-Item -Path $nugetPath -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    
    # Download using curl when available, then BitsTransfer, then Invoke-WebRequest
    Invoke-WinpeDownload -Uri $nugetExeSourceURL -Destination $nugetExeFilePath -AllowCurlFallback

    $results = winpe-NugetExeTest
}
#endregion

#region UpdatePackageManagement
function winpe-UpdatePackageManagementTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $installedModule = Get-Module -Name PackageManagement -ListAvailable | Where-Object { $_.Version -ge '1.4.8.1' }

    # Success
    if ($installedModule) {
        if ($Quiet) { return 0 }
        $latestVersion = ($installedModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor Green "[✓] PackageManagement PowerShell Module is updated [$latestVersion]"
        return 0
    }

    # Failure
    Write-Host -ForegroundColor Red "[✗] PackageManagement PowerShell Module is NOT updated to version 1.4.8.1 or later"
    if ($Quiet) { return 1 }
    return 1
}
function winpe-UpdatePackageManagementRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-UpdatePackageManagementTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        # Write-Host -ForegroundColor DarkGray $url

        Invoke-WinpeDownload -Uri $url -Destination $tempZip -AllowCurlFallback

        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop

        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\1.4.8.1" -Force -ErrorAction Stop

        Import-Module PackageManagement -Force -Scope Global -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Test again
    $results = winpe-UpdatePackageManagementTest
}
#endregion

#region PowerShellGet
function winpe-UpdatePowerShellGetTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $installedModule = Get-Module -Name PowerShellGet -ListAvailable | Where-Object { $_.Version -ge '2.2.5' }

    # Success
    if ($installedModule) {
        if ($Quiet) { return 0 }
        $latestVersion = ($installedModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor Green "[✓] PowerShellGet PowerShell Module is updated [$($latestVersion)]"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] PowerShellGet PowerShell Module is NOT updated to version 2.2.5 or later"
    return 1
}
function winpe-UpdatePowerShellGetRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-UpdatePowerShellGetTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
        $tempZip = "$env:TEMP\powershellget.2.2.5.zip"
        $tempDir = "$env:TEMP\2.2.5"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet"
        
        # Download using curl when available, then BitsTransfer, then Invoke-WebRequest
        $url = 'https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5'
        # Write-Host -ForegroundColor DarkGray $url
        Invoke-WinpeDownload -Uri $url -Destination $tempZip -AllowCurlFallback
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\2.2.5" -Force -ErrorAction Stop
        
        # Import
        Import-Module PowerShellGet -Force -Scope Global -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    # Test again
    $results = winpe-UpdatePowerShellGetTest
}
#endregion

#region PSGalleryTrust
function winpe-PSGalleryTrustTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    # Test
    $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    if ($executionPolicy -ne 'Bypass' -and $executionPolicy -ne 'Unrestricted') {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] PSGallery Repository Installation Policy is NOT Trusted [Execution Policy $executionPolicy]"
        # Write-Host -ForegroundColor DarkGray "Execution Policy is set to $executionPolicy"
        # Write-Host -ForegroundColor DarkGray "Execution Policy is blocking enumerating the PowerShell Gallery PSRepository"
        return 1
    }

    $PowerShellGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $PowerShellGallery) {
        if ($Quiet) { return 1 }
        Write-Host -ForegroundColor Red "[✗] PSGallery Repository was NOT found"
        return 1
    }

    if ($PowerShellGallery.InstallationPolicy -eq 'Trusted') {
        if ($Quiet) { return 0 }
        Write-Host -ForegroundColor Green "[✓] PSGallery Repository Installation Policy is Trusted"
        return 0
    }

    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] PSGallery Repository Installation Policy is NOT Trusted"
    return 1
}
function winpe-PSGalleryTrustRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-PSGalleryTrustTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    # Test
    $results = winpe-PSGalleryTrustTest
}
#endregion

#region AzCopyExe
function winpe-AzcopyExeTest {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Quiet
    )
    $azcopyPath = "$env:SystemRoot\System32\azcopy.exe"

    # Success
    if (Test-Path $azcopyPath) {
        if ($Quiet) { return 0 }
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor Green "[✓] Microsoft AzCopy"
        return 0
    }

    # Failure
    if ($Quiet) { return 1 }
    Write-Host -ForegroundColor Red "[✗] Microsoft AzCopy [NOT installed]"
    return 1
}

function winpe-AzcopyExeRepair {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test
    $results = winpe-AzcopyExeTest -Quiet

    # Success
    if ($results -eq 0) {
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    $azcopyPath = "$env:SystemRoot\System32\azcopy.exe"
    $tempZip = "$env:TEMP\azcopy.zip"
    $tempDir = "$env:TEMP\azcopy"

    try {
        # Determine download URL based on architecture
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows-arm64'
        }
        elseif ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows'
        }
        else {
            throw "Unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE"
        }
        # Write-Host -ForegroundColor DarkGray $downloadUrl

        Invoke-WinpeDownload -Uri $downloadUrl -Destination $tempZip -AllowCurlFallback
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'azcopy.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_.FullName -Destination $azcopyPath -Force -ErrorAction Stop }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $results = winpe-AzcopyExeTest
}
#endregion



#region Other
function winpe-RepairTls {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
        Write-Host "TLS 1.2 is already enabled"
    } else {
        Write-Host "TLS 1.2 is NOT enabled"
    }

    $currentProtocols = [Net.ServicePointManager]::SecurityProtocol
    $hasTls12 = $currentProtocols -band [Net.SecurityProtocolType]::Tls12
    Write-Host "Current protocols: $currentProtocols"
    Write-Host "TLS 1.2 enabled: $($hasTls12 -ne 0)"

    pause

    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol

    if ($SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
        Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [Tls12]"
        return
    }

    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] Transport Layer Security should be set to Tls12"
        return
    }

    # Repair
    Write-Host -ForegroundColor DarkGray "[→] $($MyInvocation.MyCommand.Name)"
    try {
        Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [Tls12] repaired"
        [Net.ServicePointManager]::SecurityProtocol = $SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }
}

function winpe-InstallDotNetCore {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $dotNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.1/dotnet-runtime-10.0.1-win-x64.zip'
    $dotNetCoreZip = Join-Path -Path $env:TEMP -ChildPath 'dotnet-runtime.zip'
    $dotNetCoreDir = Join-Path -Path $env:ProgramFiles -ChildPath 'dotnet'

    try {
        Write-Host -ForegroundColor DarkGray "[→] Downloading .NET Runtime"
        Invoke-WinpeDownload -Uri $dotNetCoreUrl -Destination $dotNetCoreZip -AllowCurlFallback
        Write-Host -ForegroundColor Green "[✓] .NET Runtime downloaded successfully"

        Write-Host -ForegroundColor DarkGray "[→] Extracting .NET Runtime"
        if (-not (Test-Path $dotNetCoreDir)) {
            $null = New-Item -Path $dotNetCoreDir -ItemType Directory -Force
        }
        Expand-Archive -Path $dotNetCoreZip -DestinationPath $dotNetCoreDir -Force -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] .NET Runtime installed successfully to $dotNetCoreDir"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install .NET Runtime: $_"
        throw
    }
    finally {
        if (Test-Path $dotNetCoreZip) { Remove-Item $dotNetCoreZip -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallPowerShellModule {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $InstalledModule = Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue | 
        Sort-Object Version -Descending | 
        Select-Object -First 1

    # If installed and not forcing, check for updates
    if ($InstalledModule -and -not $Force) {
        try {
            $GalleryModule = Find-Module -Name $Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($GalleryModule -and ([version]$GalleryModule.Version -gt [version]$InstalledModule.Version)) {
                Write-Host -ForegroundColor DarkGray "[→] Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber"
                Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host -ForegroundColor Green "[✓] $Name [$($GalleryModule.Version)]"
                return
            }
            
            # Already installed and current
            Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction SilentlyContinue
            Write-Host -ForegroundColor Green "[✓] $Name [$($InstalledModule.Version)]"
            return
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }

    # Module not installed or forced, install it
    try {
        Write-Host -ForegroundColor DarkGray "[→] Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber"
        $GalleryModule = Find-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        
        if (-not $GalleryModule) {
            throw "Module $Name not found in PowerShell Gallery"
        }

        Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] $Name [$($GalleryModule.Version)]"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
}

function winpe-InstallZip {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # requires both 7zr.exe and 7za.exe
    $zip7rPath = "$env:SystemRoot\System32\7zr.exe"
    $zip7aPath = "$env:SystemRoot\System32\7za.exe"
    
    if ((Test-Path $zip7rPath) -and (Test-Path $zip7aPath)) {
        $zip = Get-Item -Path $zip7rPath
        Write-Host -ForegroundColor DarkGray "[✓] 7-Zip [$($zip.VersionInfo.FileVersion)]"
        return
    }

    try {
        $downloadUrl = 'https://github.com/ip7z/7zip/releases/download/25.01/7z2501-extra.7z'
        $tempZip = "$env:TEMP\7z2501-extra.7z"
        $tempDir = "$env:TEMP\7za"

        Write-Host -ForegroundColor DarkCyan "[→] 7-Zip [25.01]"
        Write-Host -ForegroundColor DarkGray $downloadUrl
        
        Invoke-WinpeDownload -Uri $downloadUrl -Destination $tempZip -AllowCurlFallback
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            Copy-Item -Path "$tempDir\7za\x64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }
        elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            Copy-Item -Path "$tempDir\7za\arm64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }

        Write-Host -ForegroundColor Green "[✓] 7-Zip [25.01]"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] 7-Zip [25.01] failed: $_"
        throw
    }
    finally {
        # Cleanup
        # if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        # if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@

function Send-SettingChange {
  $HWND_BROADCAST = [IntPtr] 0xffff;
  $WM_SETTINGCHANGE = 0x1a;
  $result = [UIntPtr]::Zero

  [void] ([Win32.Nativemethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref] $result))
}

function Demo-ApplicationWorkspaceSetupComplete {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [String]$agentbootstrapperURL = "https://download.liquit.com/extra/Bootstrapper/AgentBootstrapper-Win-2.1.0.2.exe",
        [String]$DestinationPath = "C:\Windows\Temp"
    )

    $AWAgentJson = @'
{
  "zone": "https://david.liquit.com/",
  "promptZone": "Disabled",
  "registration": {
    "type": "Certificate"
  },
  "deployment": {
    "zoneTimeout": 60,
    "enabled": false,
    "start": false,
    "context": "Device",
    "cancel": false,
    "triggers": false,
    "autoStart": {
      "enabled": true,
      "deployment": "OSDCloud Live"
    }
  },
  "log": {
    "level": "Debug",
    "rotateCount": 5,
    "rotateSize": 1048576
  },
  "icon": {
    "enabled": false,
    "exit": false,
    "timeout": 1
  },
  "login": {
    "enabled": false,
    "identitySource": "LOCAL",
    "timeout": 15
  },
  "launcher": {
    "state": "Default",
    "close": true,
    "start": "Disabled",
    "contextMenu": true,
    "minimal": true,
    "enabled": true
  },
  "restrictZones": true,
  "trustedZones": [
    "david.liquit.com"
  ]
}
'@

    $AWAgentCer = @'
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIQexCxml36kblBc7bgKEEQSzANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQD
DChBcHBsaWNhdGlvbiBXb3Jrc3BhY2UgQWdlbnQgUmVnaXN0cmF0aW9uMB4XDTI2MDEwMjIxMzIz
MFoXDTM1MTIzMTIxMzIzMFowMzExMC8GA1UEAwwoQXBwbGljYXRpb24gV29ya3NwYWNlIEFnZW50
IFJlZ2lzdHJhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPdbbW0GusvkBdc3
pnGL3B3AXPzALAVQu6zY+2fyYVjQdn2lk/qwwtasn20pvwHvDFKOnprknqvNh1IrcQaMP+kJ6I1w
8jxd6t+25ZSb1By2369WXEQcsCU0nic6WNH1A6hzw1d57UxKgsx0ZuVa06M9JKJIF6fSb7D9o5Vs
LNC7/GdGl7fvzAeIeuCVZpV5xsFtzAQYuWGEU5TmvbQnJuKqpyJ5YifDYVHM95wvTphHEaC/Dptp
V0R0EaOXu24mqZuPBfhL/gV2YzabK8SjAqhOKjM4mBhdP8IXAVl1xKRyU6utIWQkD/YeotVmgeEZ
/dUMDFfR3aKIu20VgO0bGOMCAwEAAaN7MHkwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMCMDMGA1UdEQQsMCqCKEFwcGxpY2F0aW9uIFdvcmtzcGFjZSBBZ2VudCBSZWdpc3RyYXRp
b24wHQYDVR0OBBYEFO0P+6liUf1Jt/oQe0U6IIheWBoHMA0GCSqGSIb3DQEBCwUAA4IBAQAuGq/Z
2Po7O3F3eNL1aX3rE5tNsVIq7ThvFp+vU+wZd0XEjGMT+b7T+kNExQ8fVjlO+2AGvM+seMO5a7X8
+8iKERpKrKCJEGy8Uoe/cnyRKQXjET4Zl/b/Feel583vAGKKntAY0CO0JvbHvjpAgJXi2kDmWNli
30EKZYRpD7Y3ejVoB4FGa6Hg+pYhrMPgmr4OR5cOtbhgNjH7K7EnxX//PvTGd4yAcrcttFd0r/PC
QQ3+2uDROk8+8iuBcvRRCJ+XFlXj4M3VFZFtnESY16Krf3BqZDFYi2oMgpHhdfYE+8RL672ClrzH
8jN/Zx0EhesWn7xJMh2j4kFxjYqBm6mf
-----END CERTIFICATE-----
'@
    
    Write-Host -ForegroundColor Cyan "[→] Recast Software Application Workspace"

    # Agent Bootstrapper
    $InstallerPath = "$DestinationPath\AgentBootstrapper.exe"
    if (!(Test-Path $DestinationPath)) {  
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }
    Write-Host -ForegroundColor DarkGray "[↓] $agentbootstrapperURL"
    Write-Host -ForegroundColor DarkGray "[→] $InstallerPath"
    Invoke-WebRequest -Uri $agentbootstrapperURL -OutFile $InstallerPath -UseBasicParsing

    # Agent Registration Certificate
    Write-Host -ForegroundColor DarkGray "[→] $DestinationPath\AgentRegistration.cer"
    $AWAgentCer | Out-File -FilePath "$DestinationPath\AgentRegistration.cer" -Encoding ascii -Force

    # Agent Registration Json
    Write-Host -ForegroundColor DarkGray "[→] $DestinationPath\Agent.json"
    $AWAgentJson | Out-File -FilePath "$DestinationPath\Agent.json" -Encoding ascii -Force

    # SetupComplete.cmd
    $ScriptsPath = "C:\Windows\Setup\Scripts"
    if (-not (Test-Path $ScriptsPath)) {
        New-Item -Path $ScriptsPath -ItemType Directory -Force -ErrorAction Ignore | Out-Null
    }
    $SetupCompleteCmd = "$ScriptsPath\SetupComplete.cmd"

    $Content = @"
:: ========================================================
:: Recast Software - Application Workspace Demo
:: ========================================================
pushd C:\Windows\Temp
AgentBootstrapper.exe /certificate=AgentRegistration.cer /startDeployment /waitForDeployment
popd
:: ========================================================
"@
    $Content | Out-File -FilePath $SetupCompleteCmd -Append -Encoding ascii -Width 2000 -Force
    Write-Host -ForegroundColor DarkGray "[→] $SetupCompleteCmd"
    Set-Clipboard $SetupCompleteCmd
}
#endregion