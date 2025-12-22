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