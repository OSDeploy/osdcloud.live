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
    5. winpe-SetPowerShellProfile
    6. winpe-SetRealTimeClockUTC
    7. winpe-SetTimeServiceAutomatic
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
        Write-Host -ForegroundColor Red "[✗] Transport Layer Security [Tls12] repair failed: $_"
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

    $currentPolicy = Get-ExecutionPolicy

    if ($currentPolicy -eq 'Bypass') {
        Write-Host -ForegroundColor DarkGray "[✓] Execution Policy [Bypass]"
        return
    }

    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] Execution Policy [$currentPolicy] should be set to Bypass"
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor Cyan "[→] Execution Policy [Bypass] repaired"
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Execution Policy [Bypass] repair failed: $_"
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
            Write-Host -ForegroundColor Cyan "[→] User Shell Folder [$item] repaired"
            $null = New-Item -Path $item -ItemType Directory -Force -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] User Shell Folder [$item] repair failed: $_"
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
            Write-Host -ForegroundColor DarkGray "[✓] Registry Environment Variable [$name]"
            continue
        }

        if (-not ($Force)) {
            Write-Host -ForegroundColor Yellow "[!] Registry Environment Variable [$name] is not set to [$value]"
            continue
        }

        # Set in registry for persistence
        try {
            Write-Host -ForegroundColor Cyan "[→] Registry Environment Variable [$name] set to [$value]"
            Set-ItemProperty -Path $registryPath -Name $name -Value $value -Force -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Registry Environment Variable [$name] repair failed: $_"
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
            Write-Host -ForegroundColor Yellow "[!] Session Environment Variable [$name] should be set to [$value] but does not exist"
            continue
        }

        if ($currentValue -match $value) {
            Write-Host -ForegroundColor DarkGray "[✓] Session Environment Variable [$name] is set to [$value]"
            continue
        }

        if (-not ($Force)) {
            Write-Host -ForegroundColor Yellow "[!] Session Environment Variable [$name] is not set to [$value]"
            continue
        }

        try {
            Write-Host -ForegroundColor Cyan "[→] Session Environment Variable [$name] set to [$value]"
            Set-Item -Path "env:$name" -Value $value -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Session Environment Variable [$name] repair failed: $_"
            throw
        }
    }

    <#
    # Check if environment variables are already set
    $envVarsSet = (Get-Item env:LOCALAPPDATA -ErrorAction Ignore) -and 
                  (Get-Item env:APPDATA -ErrorAction Ignore) -and
                  (Get-Item env:HOMEDRIVE -ErrorAction Ignore) -and
                  (Get-Item env:HOMEPATH -ErrorAction Ignore)
    
    if ($envVarsSet) {
        Write-Host -ForegroundColor DarkGray "[✓] Environment Variables [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"
        return
    }

    # Update Environment Variables for current session
    Write-Host -ForegroundColor Cyan "[→] Environment Variables [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $registryPath | ForEach-Object {
        $k = Get-Item $_
        $k.GetValueNames() | ForEach-Object {
            $name = $_
            $value = $k.GetValue($_)
            Set-Item -Path Env:\$name -Value $value
        }
    }

    return

    # Set for current process
    Set-Item -Path "Env:\APPDATA" -Value "$env:UserProfile\AppData\Roaming" -ErrorAction SilentlyContinue
    Set-Item -Path "Env:\HOMEDRIVE" -Value "$env:SystemDrive" -ErrorAction SilentlyContinue
    Set-Item -Path "Env:\HOMEPATH" -Value "$env:UserProfile" -ErrorAction SilentlyContinue
    Set-Item -Path "Env:\LOCALAPPDATA" -Value "$env:UserProfile\AppData\Local" -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor DarkGray "[✓] Environment Variables 3 [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"

    return


    [System.Environment]::SetEnvironmentVariable('APPDATA', "$env:UserProfile\AppData\Roaming", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('HOMEDRIVE', "$env:SystemDrive", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('HOMEPATH', "$env:UserProfile", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('LOCALAPPDATA', "$env:UserProfile\AppData\Local", [System.EnvironmentVariableTarget]::Process)

    return

    Write-Host -ForegroundColor Cyan "[→] Set Environment Variables [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"
    Write-Verbose 'WinPE does not have the LocalAppData System Environment Variable'
    Write-Verbose 'Setting environment variables for this PowerShell session and registry'
    #>
}

function winpe-SetPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    if ($PROFILE.CurrentUserAllHosts -ne "$Home\profile.ps1") {
        Write-Host -ForegroundColor Cyan "[→] Repair path for PowerShell Profile CurrentUserAllHosts"
        $PROFILE.CurrentUserAllHosts = "$Home\profile.ps1"
        Write-Host -ForegroundColor DarkGray "[>] $($PROFILE.CurrentUserAllHosts)"
    }

    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Microsoft.PowerShell_profile.ps1") {
        Write-Host -ForegroundColor Cyan "[→] Repair path for PowerShell Profile CurrentUserCurrentHost"
        $PROFILE.CurrentUserCurrentHost = "$Home\Microsoft.PowerShell_profile.ps1"
        Write-Host -ForegroundColor DarkGray "[>] $($PROFILE.CurrentUserCurrentHost)"
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
                # Write-Host -ForegroundColor DarkGray "[✓] PowerShell Profile"
                return
            }

            Write-Host -ForegroundColor Cyan "[→] Add to existing PowerShell Profile for AllUsersAllHosts"
            Write-Host -ForegroundColor DarkGray "[>] $profilePath"
            Write-Host -ForegroundColor DarkGray "[i] Resolves new environment variables added to Session Manager in the registry"
            Add-Content -Path $profilePath -Value ("`r`n" + $winpePowerShellProfile) -Encoding Unicode -ErrorAction Stop
        }
        else {
            Write-Host -ForegroundColor Cyan "[→] Create new PowerShell Profile for AllUsersAllHosts"
            Write-Host -ForegroundColor DarkGray "[>] $profilePath"
            Write-Host -ForegroundColor DarkGray "[i] Resolves new environment variables added to Session Manager in the registry"
            if (-not (Test-Path $profileDir)) {
                $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }

            $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set PowerShell Profile failed: $_"
        throw
    }
}

function winpe-SetPowerShellProfileOld {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $winpePowerShellProfile = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Environment]::SetEnvironmentVariable('APPDATA',"$env:UserProfile\AppData\Roaming",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('HOMEDRIVE',"$env:SystemDrive",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('HOMEPATH',"$env:UserProfile",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('LOCALAPPDATA',"$env:UserProfile\AppData\Local",[System.EnvironmentVariableTarget]::Process)
'@

    $profileDir = "$PSHome"
    $profilePath = "$PSHome\profile.ps1"

    try {
        if (Test-Path -Path $profilePath) {
            $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop
            $linesToAdd = @()
            
            foreach ($line in $winpePowerShellProfile -split "`n") {
                $trimmedLine = $line.Trim()
                if ($trimmedLine -and -not ($existingContent -match [regex]::Escape($trimmedLine))) {
                    $linesToAdd += $line
                }
            }
            
            if ($linesToAdd.Count -gt 0) {
                Write-Host -ForegroundColor Cyan "[→] Set PowerShell Profile"
                Write-Host -ForegroundColor DarkGray "[i] $profilePath"
                Add-Content -Path $profilePath -Value ("`r`n" + ($linesToAdd -join "`r`n")) -Encoding Unicode -ErrorAction Stop
            }
            else {
                Write-Host -ForegroundColor DarkGray "[✓] PowerShell Profile"
            }
        }
        else {
            Write-Host -ForegroundColor Cyan "[→] Set PowerShell Profile"
            Write-Host -ForegroundColor DarkGray "[i] $profilePath"
            if (-not (Test-Path $profileDir)) {
                $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }

            $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set PowerShell Profile failed: $_"
        throw
    }
}

function winpe-SetRealTimeClockUTC {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Test if RealTimeIsUniversal is already set
    $realTimeIsUniversal = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -ErrorAction SilentlyContinue

    if ($realTimeIsUniversal -and ($realTimeIsUniversal.RealTimeIsUniversal -eq 1)) {
        Write-Host -ForegroundColor DarkGray "[✓] RealTime Clock [UTC]"
        return
    }
    else {
        try {
            Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -Value 1 -Type DWord -ErrorAction Stop
            Write-Host -ForegroundColor Cyan "[→] Set RealTime Clock [UTC]"
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] Set RealTime Clock [UTC] failed: $_"
            throw
        }
    }
}

function winpe-SetTimeServiceAutomatic {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
        if ($w32timeService.StartType -ne 'Automatic') {
            Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop
            Write-Host -ForegroundColor Cyan "[→] Time Service [Automatic]"
        }
        else {
            Write-Host -ForegroundColor DarkGray "[✓] Time Service [Automatic]"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Time Service [Automatic] failed: $_"
        throw
    }

    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
        if ($w32timeService.Status -ne 'Running') {
            Start-Service -Name w32time -ErrorAction Stop
            Write-Host -ForegroundColor DarkGray "[✓] Time Service [Restart]"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Time Service [Restart] failed: $_"
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

    $curlPath = "$env:SystemRoot\System32\curl.exe"
    
    if ($Force) {
        Write-Host -ForegroundColor Cyan "[→] Install Curl -Force"
    }
    elseif (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor DarkGray "[✓] Curl [$($curl.VersionInfo.FileVersion)]"
        return
    }

    try {
        Write-Host -ForegroundColor Cyan "[→] Install Curl"
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
        Write-Host -ForegroundColor Cyan "[→] PackageManagement [1.4.8.1]"
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
        Write-Host -ForegroundColor Cyan "[→] Package Provider NuGet"
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
            Write-Host -ForegroundColor Cyan "[→] NuGet [$nugetExeFilePath]"
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
        Write-Host -ForegroundColor Cyan "[→] PackageManagement [1.4.8.1]"
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
        Write-Host -ForegroundColor Cyan "[→] PowerShellGet [2.2.5]"
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
        Write-Host -ForegroundColor Cyan "[→] Trust PSGallery"
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
        Write-Host -ForegroundColor Cyan "[→] Microsoft AzCopy -Force"
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
        Write-Host -ForegroundColor Cyan "[→] Microsoft AzCopy"
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
            Write-Host -ForegroundColor Cyan "[→] Downloading .NET Runtime with curl"
            & $curlPath --fail --location --silent --show-error `
                $dotNetCoreUrl `
                --output $dotNetCoreZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dotNetCoreZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Write-Host -ForegroundColor Cyan "[→] Downloading .NET Runtime with Invoke-WebRequest"
            Invoke-WebRequest -UseBasicParsing -Uri $dotNetCoreUrl -OutFile $dotNetCoreZip -ErrorAction Stop
        }
        Write-Host -ForegroundColor Green "[✓] .NET Runtime downloaded successfully"

        Write-Host -ForegroundColor Cyan "[→] Extracting .NET Runtime"
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
                Write-Host -ForegroundColor Cyan "[→] Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber [$($GalleryModule.Version)]"
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
        Write-Host -ForegroundColor Cyan "[→] Installing $Name [AllUsers]"
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

        Write-Host -ForegroundColor Cyan "[→] 7-Zip [25.01]"
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