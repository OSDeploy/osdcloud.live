<#
.SYNOPSIS
WinPE environment setup and configuration functions.

.DESCRIPTION
Functions for configuring the Windows PE environment, including execution policy,
environment variables, package management, and tool installation.

Recommended execution order for initial setup:
    1. winpe-RepairExecutionPolicy
    2. winpe-RepairUserShellFolder
    3. winpe-RepairEnvironmentRegistry
    4. winpe-RepairEnvironmentSession
    5. winpe-RepairPowerShellProfile
    6. winpe-RepairRealTimeClockUTC
    7. winpe-RepairTimeService
    8. winpe-InstallCurl
    9. winpe-InstallPackageProviderNuget
    10. winpe-InstallNuGet
    11. winpe-UpdatePackageManagement
    12. winpe-UpdatePowerShellGet
    13. winpe-TrustPSGallery
    14. winpe-InstallAzCopy

Additional functions (can be run after the core setup above):
    - winpe-InstallPowerShellModule -Name <ModuleName>
    - winpe-InstallDotNetCore
    - winpe-InstallZip

.NOTES
Functions are designed to be idempotent and can be safely re-run.
Most functions will skip if the target is already configured/installed.
#>

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
    try {
        Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [Tls12] repaired"
        [Net.ServicePointManager]::SecurityProtocol = $SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }
}

function winpe-RepairExecutionPolicy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor DarkGray "[>] $($MyInvocation.MyCommand.Name)"
    
    $currentPolicy = Get-ExecutionPolicy

    if ($currentPolicy -eq 'Bypass') {
        Write-Host -ForegroundColor DarkGray "[✓] Execution Policy is set to Bypass"
        return
    }

    # Informational only
    if (-not ($Force)) {
        Write-Host -ForegroundColor DarkGray "[!] Execution Policy is set to $currentPolicy"
        Write-Host -ForegroundColor DarkGray "[i] It is recommended that Execution Policy is set to Bypass in WinPE for proper scripting functionality"
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor DarkCyan "[→] Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }
}

function winpe-RepairUserShellFolder {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

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

    foreach ($item in $requiredFolders) {
        if (Test-Path -Path $item) {
            Write-Host -ForegroundColor DarkGray "[✓] User Shell Folder [$item]"
            continue
        }

        if (-not ($Force)) {
            Write-Host -ForegroundColor Yellow "[!] User Shell Folder [$item] is missing"
            continue
        }

        # Repair
        try {
            Write-Host -ForegroundColor DarkCyan "[→] User Shell Folder [$item] repaired"
            $null = New-Item -Path $item -ItemType Directory -Force -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
            throw
        }
    }
}

function winpe-RepairEnvironmentRegistry {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
        'USERPROFILE'   = "$env:UserProfile"
    }

    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -eq $value) {
            Write-Host -ForegroundColor DarkGray "[✓] Registry Environment [$name]"
            continue
        }

        if (-not ($Force)) {
            Write-Host -ForegroundColor Yellow "[!] Registry Environment [$name] is not set to [$value]"
            continue
        }

        # Set in registry for persistence
        try {
            Write-Host -ForegroundColor DarkCyan "[→] Registry Environment [$name] set to [$value]"
            Set-ItemProperty -Path $registryPath -Name $name -Value $value -Force -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Registry Environment [$name] repair failed: $_"
            throw
        }
    }
}

function winpe-RepairEnvironmentSession {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
    }

    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        # No change needed
        if ($currentValue -eq $value) {
            Write-Host -ForegroundColor DarkGray "[✓] Session Environment [$name] is set to [$value]"
            continue
        }

        # Informational only
        if (-not ($Force)) {
            if (-not $currentValue) {
                Write-Host -ForegroundColor Yellow "[!] Session Environment [$name] should be set to [$value] but does not exist"
            }
            else {
                Write-Host -ForegroundColor Yellow "[!] Session Environment [$name] is not set to [$value]"
            }
            continue
        }

        # Repair
        try {
            Write-Host -ForegroundColor DarkCyan "[→] Session Environment [$name] set to [$value]"
            Set-Item -Path "env:$name" -Value $value -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Session Environment [$name] repair failed: $_"
            throw
        }
    }
}

function winpe-RepairPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\profile.ps1") {
        if ($Force) {
            $PROFILE.CurrentUserAllHosts = "$Home\Documents\profile.ps1"
            Write-Host -ForegroundColor DarkCyan "[→] PowerShell Profile CurrentUserAllHosts Path updated to [$($PROFILE.CurrentUserAllHosts)]"
        }
        else {
            Write-Host -ForegroundColor Yellow "[!] PowerShell Profile CurrentUserAllHosts Path is incorrectly set to [$($PROFILE.CurrentUserAllHosts)]"
            return
        }
    }

    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\Microsoft.PowerShell_profile.ps1") {
        if ($Force) {
            $PROFILE.CurrentUserCurrentHost = "$Home\Documents\Microsoft.PowerShell_profile.ps1"
            Write-Host -ForegroundColor DarkCyan "[→] PowerShell Profile CurrentUserCurrentHost Path updated to [$($PROFILE.CurrentUserCurrentHost)]"
        }
        else {
            Write-Host -ForegroundColor Yellow "[!] PowerShell Profile CurrentUserCurrentHost Path is incorrectly set to [$($PROFILE.CurrentUserCurrentHost)]"
            return
        }
    }


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

    $profileDir = "$PSHome"
    $profilePath = "$PSHome\profile.ps1"

    try {
        if (Test-Path -Path $profilePath) {
            $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop

            # Search for string 'OSDCloud by Recast Software' to determine if content already exists
            if ($existingContent -match 'OSDCloud by Recast Software') {
                Write-Host -ForegroundColor DarkGray "[✓] PowerShell Profile contains OSDCloud update for new sessions"
                return
            }
            else {
                Write-Host -ForegroundColor DarkGray "[✓] PowerShell Profile does not contain OSDCloud update for new sessions"
            }

            if ($Force) {
                Write-Host -ForegroundColor DarkCyan "[→] Add to existing PowerShell Profile for AllUsersAllHosts"
                Write-Host -ForegroundColor DarkGray "[i] Resolves new environment variables added to Session Manager in the registry"
                Add-Content -Path $profilePath -Value ("`r`n" + $winpePowerShellProfile) -Encoding Unicode -ErrorAction Stop
            }
        }
        else {
            Write-Host -ForegroundColor DarkGray "[✓] PowerShell Profile does not exist with OSDCloud update for new sessions"
            if ($Force) {
                Write-Host -ForegroundColor DarkCyan "[→] Create new PowerShell Profile for AllUsersAllHosts"
                Write-Host -ForegroundColor DarkGray "[i] Resolves new environment variables added to Session Manager in the registry"
                if (-not (Test-Path $profileDir)) {
                    $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }
                $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
            }
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set PowerShell Profile failed: $_"
        throw
    }
}

function winpe-RepairRealTimeClockUTC {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    # Test if RealTimeIsUniversal is already set
    $realTimeIsUniversal = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -ErrorAction SilentlyContinue

    if ($realTimeIsUniversal -and ($realTimeIsUniversal.RealTimeIsUniversal -eq 1)) {
        Write-Host -ForegroundColor DarkGray "[✓] RealTime Clock is set to [UTC]"
        return
    }

    if (-not ($Force)) {
        Write-Host -ForegroundColor DarkGray "[!] RealTime Clock is NOT set to [UTC]"
        return
    }

    # Repair
    
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host -ForegroundColor DarkCyan "[→] Set RealTime Clock to [UTC]"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set RealTime Clock to [UTC] failed: $_"
        throw
    }
}

function winpe-RepairTimeService {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    # Time Service StartType
    try {
        # Can we connect to Time Service?
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop

        # Is the Time Service set to Automatic?
        if ($w32timeService.StartType -eq 'Automatic') {
            Write-Host -ForegroundColor DarkGray "[✓] Time Service StartType is set to Automatic"
        }
        else {
            Write-Host -ForegroundColor DarkGray "[!] Time Service StartType is NOT set to Automatic"
        }

        # Repair
        if ($Force -and $w32timeService.StartType -ne 'Automatic') {
            Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop
            Write-Host -ForegroundColor DarkCyan "[→] Time Service StartType has been set to Automatic"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }

    # Time Service Status
    try {
        # Can we connect to Time Service?
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop

        # Is the Time Service Running?
        if ($w32timeService.Status -eq 'Running') {
            Write-Host -ForegroundColor DarkGray "[✓] Time Service is Running (but should be restarted)"

            if ($Force) {
                Restart-Service -Name w32time -ErrorAction Stop
                Write-Host -ForegroundColor DarkCyan "[→] Time Service is being restarted"
            }
        }
        else {
            Write-Host -ForegroundColor DarkGray "[!] Time Service is NOT Running, and should be started"
            if ($Force) {
                Start-Service -Name w32time -ErrorAction Stop
                Write-Host -ForegroundColor DarkCyan "[→] Time Service is being started"
            }
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }
}

function winpe-InstallCurl {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    Write-Host -ForegroundColor Cyan "[>] $($MyInvocation.MyCommand.Name)"

    $curlPath = "$env:SystemRoot\System32\curl.exe"
    
    if ($Force) {
        Write-Host -ForegroundColor DarkCyan "[→] Install Curl -Force"
    }
    elseif (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor DarkGray "[✓] Curl [$($curl.VersionInfo.FileVersion)]"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] Install Curl"
        $tempZip = "$env:TEMP\curl.zip"
        $tempDir = "$env:TEMP\curl"
        
        # Download
        $url = 'https://curl.se/windows/latest.cgi?p=win64-mingw.zip'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        Invoke-WebRequest -UseBasicParsing -Uri $url `
            -OutFile $tempZip -ErrorAction Stop
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'curl.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_ -Destination $curlPath -Force -ErrorAction Stop }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Install Curl failed: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallPackageManagement {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Test if PackageManagement is already installed
    $existingModule = Get-Module -Name PackageManagement -ListAvailable
    
    # If installed, return. Display version number of the latest installed version.
    if ($existingModule) {
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor DarkGray "[✓] PackageManagement [$latestVersion]"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] PackageManagement [1.4.8.1]"
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $url `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempZip -ErrorAction Stop
        }

        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop

        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\1.4.8.1" -Force -ErrorAction Stop

        Import-Module PackageManagement -Force -Scope Global -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] PackageManagement [1.4.8.1] failed: $_"
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallPackageProviderNuget {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Test if NuGet PackageProvider is already installed
    $provider = Get-PackageProvider -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'NuGet' }
    if ($provider) {
        Write-Host -ForegroundColor DarkGray "[✓] Package Provider NuGet [$($provider.Version)]"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] Package Provider NuGet"
        Write-Host -ForegroundColor DarkGray "[>] Install-PackageProvider -Name NuGet -Force -Scope AllUsers"
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Package Provider NuGet failed: $_"
        throw
    }
}

function winpe-InstallNuGet {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $NuGetClientSourceURL = 'https://nuget.org/nuget.exe'
    $NuGetExeName = 'NuGet.exe'
    $nugetPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'

    try {
        $nugetExeFilePath = Join-Path -Path $nugetPath -ChildPath $NuGetExeName
        if (-not (Test-Path -Path $nugetExeFilePath)) {
            Write-Host -ForegroundColor DarkCyan "[→] NuGet [$nugetExeFilePath]"
            Write-Host -ForegroundColor DarkGray "[↓] $NuGetClientSourceURL"
            if (-not (Test-Path -Path $nugetPath)) {
                $null = New-Item -Path $nugetPath -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            
            # Download using curl if available, fallback to Invoke-WebRequest
            $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
            if (Test-Path $curlPath) {
                & $curlPath --fail --location --silent --show-error `
                    $NuGetClientSourceURL `
                    --output $nugetExeFilePath
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path $nugetExeFilePath)) {
                    throw "curl download failed with exit code $LASTEXITCODE"
                }
            }
            else {
                Invoke-WebRequest -UseBasicParsing -Uri $NuGetClientSourceURL -OutFile $nugetExeFilePath -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] NuGet failed: $_"
        throw
    }
}

function winpe-UpdatePackageManagement {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    
    $existingModule = Get-Module -Name PackageManagement -ListAvailable | Where-Object { $_.Version -ge '1.4.8.1' }
    
    if ($existingModule) {
        Write-Host -ForegroundColor DarkGray "[✓] PackageManagement [$($existingModule.Version)]"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] PackageManagement [1.4.8.1]"
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $url `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempZip -ErrorAction Stop
        }

        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop

        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\1.4.8.1" -Force -ErrorAction Stop

        Import-Module PackageManagement -Force -Scope Global -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] PackageManagement [1.4.8.1] failed: $_"
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-UpdatePowerShellGet {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    
    $existingModule = Get-Module -Name PowerShellGet -ListAvailable | Where-Object { $_.Version -ge '2.2.5' }
    
    if ($existingModule) {
        Write-Host -ForegroundColor DarkGray "[✓] PowerShellGet [$($existingModule.Version)]"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] PowerShellGet [2.2.5]"
        $tempZip = "$env:TEMP\powershellget.2.2.5.zip"
        $tempDir = "$env:TEMP\2.2.5"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $url = 'https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $url `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempZip -ErrorAction Stop
        }
        
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
        Write-Host -ForegroundColor Red "[✗] PowerShellGet [2.2.5] failed: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-TrustPSGallery {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $PowerShellGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue

    if (-not $PowerShellGallery) {
        Write-Host -ForegroundColor Red "[✗] PSRepository PSGallery not found"
        return
    }

    if ($PowerShellGallery.InstallationPolicy -eq 'Trusted') {
        Write-Host -ForegroundColor DarkGray "[✓] Trust PSGallery"
        return
    }

    try {
        Write-Host -ForegroundColor DarkCyan "[→] Trust PSGallery"
        Write-Host -ForegroundColor DarkGray "[>] Set-PSRepository -Name PSGallery -InstallationPolicy Trusted"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Trust PSGallery failed: $_"
        throw
    }
}

function winpe-InstallAzCopy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $azcopyPath = "$env:SystemRoot\System32\azcopy.exe"
    
    if ($Force) {
        Write-Host -ForegroundColor DarkCyan "[→] Microsoft AzCopy -Force"
    }
    elseif (Test-Path $azcopyPath) {
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor DarkGray "[✓] Microsoft AzCopy"
        return
    }

    try {
        $tempZip = "$env:TEMP\azcopy.zip"
        $tempDir = "$env:TEMP\azcopy"
        
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
        Write-Host -ForegroundColor DarkCyan "[→] Microsoft AzCopy"
        Write-Host -ForegroundColor DarkGray "[↓] $downloadUrl"

        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $downloadUrl `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $tempZip -ErrorAction Stop
        }
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'azcopy.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_.FullName -Destination $azcopyPath -Force -ErrorAction Stop }
        
        # Write-Host -ForegroundColor Green "[✓] AzCopy installed successfully."
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Microsoft AzCopy failed: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallDotNetCore {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $dotNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.1/dotnet-runtime-10.0.1-win-x64.zip'
    $dotNetCoreZip = Join-Path -Path $env:TEMP -ChildPath 'dotnet-runtime.zip'
    $dotNetCoreDir = Join-Path -Path $env:ProgramFiles -ChildPath 'dotnet'

    try {
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            Write-Host -ForegroundColor DarkCyan "[→] Downloading .NET Runtime with curl"
            & $curlPath --fail --location --silent --show-error `
                $dotNetCoreUrl `
                --output $dotNetCoreZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dotNetCoreZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Write-Host -ForegroundColor DarkCyan "[→] Downloading .NET Runtime with Invoke-WebRequest"
            Invoke-WebRequest -UseBasicParsing -Uri $dotNetCoreUrl -OutFile $dotNetCoreZip -ErrorAction Stop
        }
        Write-Host -ForegroundColor Green "[✓] .NET Runtime downloaded successfully"

        Write-Host -ForegroundColor DarkCyan "[→] Extracting .NET Runtime"
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
                Write-Host -ForegroundColor DarkCyan "[→] Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber [$($GalleryModule.Version)]"
                Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host -ForegroundColor Green "[✓] $Name $($GalleryModule.Version) installed successfully"
                return
            }
            
            # Already installed and current
            Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction SilentlyContinue
            Write-Host -ForegroundColor Green "[✓] $Name $($InstalledModule.Version)"
            return
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Failed to install $Name : $_"
            throw
        }
    }

    # Module not installed or forced, install it
    try {
        Write-Host -ForegroundColor DarkCyan "[→] Installing $Name [AllUsers]"
        $GalleryModule = Find-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        
        if (-not $GalleryModule) {
            throw "Module $Name not found in PowerShell Gallery"
        }

        Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] $Name $($GalleryModule.Version) installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install $Name : $_"
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
        Write-Host -ForegroundColor DarkGray "[↓] $downloadUrl"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $downloadUrl `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $tempZip -ErrorAction Stop
        }
        
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