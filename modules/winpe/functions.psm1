<#
.SYNOPSIS
WinPE environment setup and configuration functions.

.DESCRIPTION
Functions for configuring the Windows PE environment, including execution policy,
environment variables, package management, and tool installation.

Recommended execution order for initial setup:
    1. winpe-SetExecutionPolicy
    2. winpe-SetEnvironmentVariable
    3. winpe-SetPowerShellProfile
    4. winpe-SetRealTimeClockUTC
    5. winpe-SetTimeServiceAutomatic
    6. winpe-InstallCurl
    7. winpe-InstallPackageProviderNuget
    8. winpe-InstallNuGet
    9. winpe-UpdatePackageManagement
    10. winpe-UpdatePowerShellGet
    11. winpe-TrustPSGallery
    12. winpe-InstallAzCopy

Additional functions (can be run after the core setup above):
    - winpe-InstallPowerShellModule -Name <ModuleName>
    - winpe-InstallDotNetCore
    - winpe-InstallZip

.NOTES
Functions are designed to be idempotent and can be safely re-run.
Most functions will skip if the target is already configured/installed.
#>

function winpe-SetExecutionPolicy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Get the current execution policy
    $currentPolicy = Get-ExecutionPolicy
    if ($currentPolicy -eq 'Bypass') {
        # Handle the case where the policy is already set to Bypass
        Write-Host -ForegroundColor DarkGray "[✓] Execution Policy [Bypass]"
        return
    }

    try {
        Write-Host -ForegroundColor Cyan "[→] Set Execution Policy [Bypass]"
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Host -ForegroundColor DarkGray "[>] Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set-ExecutionPolicy Failed: $_"
        throw
    }
}

function winpe-SetEnvironmentVariable {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Check if environment variables are already set
    $envVarsSet = (Get-Item env:LOCALAPPDATA -ErrorAction Ignore) -and 
                  (Get-Item env:APPDATA -ErrorAction Ignore) -and
                  (Get-Item env:HOMEDRIVE -ErrorAction Ignore) -and
                  (Get-Item env:HOMEPATH -ErrorAction Ignore)
    
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $registryVarsSet = (Get-ItemProperty -Path $registryPath -Name 'LOCALAPPDATA' -ErrorAction SilentlyContinue) -and
                       (Get-ItemProperty -Path $registryPath -Name 'APPDATA' -ErrorAction SilentlyContinue) -and
                       (Get-ItemProperty -Path $registryPath -Name 'HOMEDRIVE' -ErrorAction SilentlyContinue) -and
                       (Get-ItemProperty -Path $registryPath -Name 'HOMEPATH' -ErrorAction SilentlyContinue)

    if ($envVarsSet -and $registryVarsSet) {
        Write-Host -ForegroundColor DarkGray "[✓] Environment Variables [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"
        return
    }

    Write-Host -ForegroundColor Cyan "[→] Set Environment Variables [APPDATA, HOMEDRIVE, HOMEPATH, LOCALAPPDATA]"
    Write-Verbose 'WinPE does not have the LocalAppData System Environment Variable'
    Write-Verbose 'Setting environment variables for this PowerShell session and registry'
    
    # Set for current process
    [System.Environment]::SetEnvironmentVariable('APPDATA', "$Env:UserProfile\AppData\Roaming", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('HOMEDRIVE', "$Env:SystemDrive", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('HOMEPATH', "$Env:UserProfile", [System.EnvironmentVariableTarget]::Process)
    [System.Environment]::SetEnvironmentVariable('LOCALAPPDATA', "$Env:UserProfile\AppData\Local", [System.EnvironmentVariableTarget]::Process)
    
    # Set in registry for persistence
    try {
        Set-ItemProperty -Path $registryPath -Name 'APPDATA' -Value "$Env:UserProfile\AppData\Roaming" -Force -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name 'HOMEDRIVE' -Value "$Env:SystemDrive" -Force -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name 'HOMEPATH' -Value "$Env:UserProfile" -Force -ErrorAction Stop
        Set-ItemProperty -Path $registryPath -Name 'LOCALAPPDATA' -Value "$Env:UserProfile\AppData\Local" -Force -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Set Environment Variables failed: $_"
        throw
    }
}

function winpe-SetPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $winpePowerShellProfile = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Environment]::SetEnvironmentVariable('APPDATA',"$Env:UserProfile\AppData\Roaming",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('HOMEDRIVE',"$Env:SystemDrive",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('HOMEPATH',"$Env:UserProfile",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable('LOCALAPPDATA',"$Env:UserProfile\AppData\Local",[System.EnvironmentVariableTarget]::Process)
'@

    $profileDir = "$env:PSHome"
    $profilePath = "$profileDir\profile.ps1"

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

    $curlPath = "$Env:SystemRoot\System32\curl.exe"
    
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
        $tempZip = "$Env:TEMP\curl.zip"
        $tempDir = "$Env:TEMP\curl"
        
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
    $nugetPath = Join-Path -Path $Env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'

    try {
        $nugetExeFilePath = Join-Path -Path $nugetPath -ChildPath $NuGetExeName
        if (-not (Test-Path -Path $nugetExeFilePath)) {
            Write-Host -ForegroundColor Cyan "[→] NuGet [$nugetExeFilePath]"
            Write-Host -ForegroundColor DarkGray "[↓] $NuGetClientSourceURL"
            if (-not (Test-Path -Path $nugetPath)) {
                $null = New-Item -Path $nugetPath -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            
            # Download using curl if available, fallback to Invoke-WebRequest
            $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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
        $tempZip = "$Env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$Env:TEMP\1.4.8.1"
        $moduleDir = "$Env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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
        $tempZip = "$Env:TEMP\powershellget.2.2.5.zip"
        $tempDir = "$Env:TEMP\2.2.5"
        $moduleDir = "$Env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $url = 'https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5'
        Write-Host -ForegroundColor DarkGray "[↓] $url"
        $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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

    $azcopyPath = "$Env:SystemRoot\System32\azcopy.exe"
    
    if ($Force) {
        Write-Host -ForegroundColor Cyan "[→] Microsoft AzCopy -Force"
    }
    elseif (Test-Path $azcopyPath) {
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor DarkGray "[✓] Microsoft AzCopy"
        return
    }

    try {
        $tempZip = "$Env:TEMP\azcopy.zip"
        $tempDir = "$Env:TEMP\azcopy"
        
        # Determine download URL based on architecture
        if ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows-arm64'
        }
        elseif ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows'
        }
        else {
            throw "Unsupported processor architecture: $Env:PROCESSOR_ARCHITECTURE"
        }
        Write-Host -ForegroundColor Cyan "[→] Microsoft AzCopy"
        Write-Host -ForegroundColor DarkGray "[↓] $downloadUrl"

        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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
    $dotNetCoreZip = Join-Path -Path $Env:TEMP -ChildPath 'dotnet-runtime.zip'
    $dotNetCoreDir = Join-Path -Path $Env:ProgramFiles -ChildPath 'dotnet'

    try {
        $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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
    $zip7rPath = "$Env:SystemRoot\System32\7zr.exe"
    $zip7aPath = "$Env:SystemRoot\System32\7za.exe"
    
    if ((Test-Path $zip7rPath) -and (Test-Path $zip7aPath)) {
        $zip = Get-Item -Path $zip7rPath
        Write-Host -ForegroundColor DarkGray "[✓] 7-Zip [$($zip.VersionInfo.FileVersion)]"
        return
    }

    try {
        $downloadUrl = 'https://github.com/ip7z/7zip/releases/download/25.01/7z2501-extra.7z'
        $tempZip = "$Env:TEMP\7z2501-extra.7z"
        $tempDir = "$Env:TEMP\7za"

        Write-Host -ForegroundColor Cyan "[→] 7-Zip [25.01]"
        Write-Host -ForegroundColor DarkGray "[↓] $downloadUrl"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $Env:SystemRoot 'System32\curl.exe'
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
        if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            Copy-Item -Path "$tempDir\7za\x64\*" -Destination $Env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }
        elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            Copy-Item -Path "$tempDir\7za\arm64\*" -Destination $Env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
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