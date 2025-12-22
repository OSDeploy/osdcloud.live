function winpe-SetExecutionPolicy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $currentPolicy = Get-ExecutionPolicy
    if ($currentPolicy -eq 'Bypass') {
        Write-Host -ForegroundColor Green "[✓] ExecutionPolicy Bypass"
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Set-ExecutionPolicy Bypass -Scope LocalMachine -Force"
        Set-ExecutionPolicy Bypass -Scope LocalMachine -Force -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] ExecutionPolicy Bypass"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to set ExecutionPolicy: $_"
        throw
    }
}

function winpe-SetEnvironmentVariables {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    
    if (Get-Item env:LOCALAPPDATA -ErrorAction Ignore) {
        Write-Host -ForegroundColor Green "[✓] LocalAppData environment variable exists"
    }
    else {
        Write-Host -ForegroundColor Yellow "[→] Setting environment variables for WinPE"
        Write-Verbose 'WinPE does not have the LocalAppData System Environment Variable'
        Write-Verbose 'Setting environment variables for this PowerShell session (not persistent)'
        
        [System.Environment]::SetEnvironmentVariable('APPDATA', "$env:UserProfile\AppData\Roaming", [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable('HOMEDRIVE', "$env:SystemDrive", [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable('HOMEPATH', "$env:UserProfile", [System.EnvironmentVariableTarget]::Process)
        [System.Environment]::SetEnvironmentVariable('LOCALAPPDATA', "$env:UserProfile\AppData\Local", [System.EnvironmentVariableTarget]::Process)
        
        Write-Host -ForegroundColor Green "[✓] Environment variables set successfully"
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

    $profileDir = "$env:UserProfile\Documents\WindowsPowerShell"
    $profilePath = "$profileDir\Microsoft.PowerShell_profile.ps1"

    try {
        Write-Host -ForegroundColor Yellow "[→] Writing WinPE PowerShell profile"
        if (-not (Test-Path $profileDir)) {
            $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        Write-Host -ForegroundColor Green "[✓] WinPE PowerShell profile updated"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to write WinPE PowerShell profile: $_"
        throw
    }
}

function winpe-InstallPackageManagement {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    
    $existingModule = Get-Module -Name PackageManagement -ListAvailable | Where-Object { $_.Version -ge '1.4.8.1' }
    
    if ($existingModule) {
        Write-Host -ForegroundColor Green "[✓] PackageManagement $($existingModule.Version)"
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Installing PackageManagement 1.4.8.1"
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempZip -ErrorAction Stop

        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop

        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\1.4.8.1" -Force -ErrorAction Stop

        Import-Module PackageManagement -Force -Scope Global -ErrorAction Stop

        Write-Host -ForegroundColor Green "[✓] PackageManagement 1.4.8.1 installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install PackageManagement: $_"
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallPowerShellGet {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    
    $existingModule = Get-Module -Name PowerShellGet -ListAvailable | Where-Object { $_.Version -ge '2.2.5' }
    
    if ($existingModule) {
        Write-Host -ForegroundColor Green "[✓] PowerShellGet $($existingModule.Version)"
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Installing PowerShellGet 2.2.5"
        $tempZip = "$env:TEMP\powershellget.2.2.5.zip"
        $tempDir = "$env:TEMP\2.2.5"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet"
        
        # Download
        $url = 'https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5'
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempZip -ErrorAction Stop
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        $null = New-Item -Path $moduleDir -ItemType Directory -Force -ErrorAction SilentlyContinue
        Move-Item -Path $tempDir -Destination "$moduleDir\2.2.5" -Force -ErrorAction Stop
        
        # Import
        Import-Module PowerShellGet -Force -Scope Global -ErrorAction Stop
        
        Write-Host -ForegroundColor Green "[✓] PowerShellGet 2.2.5 installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install PowerShellGet: $_"
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
        Write-Host -ForegroundColor Green "[✓] PSRepository PSGallery Trusted"
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Set-PSRepository PSGallery Trusted"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] PSRepository PSGallery Trusted"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to trust PSGallery: $_"
        throw
    }
}

function winpe-InstallCurl {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $curlPath = "$env:SystemRoot\System32\curl.exe"
    
    if (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor Green "[✓] Curl $($curl.VersionInfo.FileVersion)"
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Installing Curl from curl.se"
        $tempZip = "$env:TEMP\curl.zip"
        $tempDir = "$env:TEMP\curl"
        
        # Download
        Invoke-WebRequest -UseBasicParsing -Uri 'https://curl.se/windows/latest.cgi?p=win64-mingw.zip' `
            -OutFile $tempZip -ErrorAction Stop
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'curl.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_ -Destination $curlPath -Force -ErrorAction Stop }
        
        Write-Host -ForegroundColor Green "[✓] Curl installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install Curl: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function winpe-InstallAzcopy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $azcopyPath = "$env:SystemRoot\System32\azcopy.exe"
    
    if (Test-Path $azcopyPath) {
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor Green "[✓] AzCopy is already installed."
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Installing AzCopy from Microsoft"
        $tempZip = "$env:TEMP\azcopy.zip"
        $tempDir = "$env:TEMP\azcopy"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                'https://aka.ms/downloadazcopy-v10-windows' `
                --output $tempZip
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tempZip)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            Invoke-WebRequest -UseBasicParsing -Uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile $tempZip -ErrorAction Stop
        }
        
        # Extract
        $null = New-Item -Path $tempDir -ItemType Directory -Force
        Expand-Archive -Path $tempZip -DestinationPath $tempDir -Force -ErrorAction Stop
        
        # Install
        Get-ChildItem $tempDir -Include 'azcopy.exe' -Recurse -ErrorAction Stop | 
            ForEach-Object { Copy-Item -Path $_.FullName -Destination $azcopyPath -Force -ErrorAction Stop }
        
        Write-Host -ForegroundColor Green "[✓] AzCopy installed successfully."
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install AzCopy: $_"
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
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
        Write-Host -ForegroundColor Green "[✓] 7-Zip $($zip.VersionInfo.FileVersion) is already installed."
        return
    }

    try {
        Write-Host -ForegroundColor Yellow "[→] Installing 7-Zip from GitHub"

        $temp7za = "$env:TEMP\7z2501-extra.7z"
        
        $curlPath = Join-Path $env:SystemRoot 'System32/curl.exe'
        if (-not (Test-Path $curlPath)) {
            throw 'curl.exe not found in System32; install curl first'
        }

        & $curlPath --fail --location --silent --show-error `
            'https://github.com/ip7z/7zip/releases/download/25.01/7z2501-extra.7z' `
            --output $temp7za
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $temp7za)) {
            throw "curl download failed with exit code $LASTEXITCODE"
        }
        
        $temp7zaDir = "$env:TEMP\7za"
        $null = New-Item -Path $temp7zaDir -ItemType Directory -Force

        Expand-Archive -Path $temp7za -DestinationPath $temp7zaDir -Force -ErrorAction Stop

        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            Copy-Item -Path "$temp7zaDir\7za\x64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }
        elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            Copy-Item -Path "$temp7zaDir\7za\arm64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }

        Write-Host -ForegroundColor Green "[✓] 7-Zip installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install 7-Zip: $_"
        throw
    }
    finally {
        # Cleanup
        # if (Test-Path $temp7za) { Remove-Item $temp7za -Force -ErrorAction SilentlyContinue }
        # if (Test-Path $temp7zaDir) { Remove-Item $temp7zaDir -Recurse -Force -ErrorAction SilentlyContinue }
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
                Write-Host -ForegroundColor Yellow "[→] Installing $Name $($GalleryModule.Version) [AllUsers]"
                Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
                Write-Host -ForegroundColor Green "[✓] $Name $($GalleryModule.Version) installed successfully"
                return
            }
            
            # Already installed and current
            Import-Module -Name $Name -Force -ErrorAction SilentlyContinue
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
        Write-Host -ForegroundColor Yellow "[→] Installing $Name [AllUsers]"
        $GalleryModule = Find-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        
        if (-not $GalleryModule) {
            throw "Module $Name not found in PowerShell Gallery"
        }

        Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
        Import-Module -Name $Name -Force -ErrorAction Stop
        Write-Host -ForegroundColor Green "[✓] $Name $($GalleryModule.Version) installed successfully"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install $Name : $_"
        throw
    }
}

# Not used

function winpe-InstallNuget {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $NuGetClientSourceURL = 'https://nuget.org/nuget.exe'
    $NuGetExeName = 'NuGet.exe'
    $nugetPaths = @(
        Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
        Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    )

    try {
        # Download NuGet to required locations
        foreach ($path in $nugetPaths) {
            $nugetExeFilePath = Join-Path -Path $path -ChildPath $NuGetExeName
            if (-not (Test-Path -Path $nugetExeFilePath)) {
                Write-Host -ForegroundColor Yellow "[→] Downloading NuGet to $nugetExeFilePath"
                if (-not (Test-Path -Path $path)) {
                    $null = New-Item -Path $path -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }
                Invoke-WebRequest -UseBasicParsing -Uri $NuGetClientSourceURL -OutFile $nugetExeFilePath -ErrorAction Stop
            }
        }

        # Install PackageProvider
        $providerPath = "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"
        if (Test-Path $providerPath) {
            Write-Host -ForegroundColor Green "[✓] NuGet 2.8.5.208+"
        }
        else {
            Write-Host -ForegroundColor Yellow "[→] Installing PackageProvider NuGet"
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
            Write-Host -ForegroundColor Green "[✓] NuGet installed successfully"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install NuGet: $_"
        throw
    }
}

