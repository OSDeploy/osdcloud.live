function oobe-SetPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    $oobePowerShellProfile = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Environment]::SetEnvironmentVariable('Path',$Env:Path + ";$Env:ProgramFiles\WindowsPowerShell\Scripts",'Process')
'@

    $profileDir = "$env:UserProfile\Documents\WindowsPowerShell"
    $profilePath = "$profileDir\Microsoft.PowerShell_profile.ps1"
    $allHostsPath = $Profile.CurrentUserAllHosts

    try {
        Write-Host -ForegroundColor Cyan "[→] Writing OOBE PowerShell profile"
        if (-not (Test-Path $profileDir)) {
            $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        $oobePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        Write-Host -ForegroundColor Green "[✓] OOBE PowerShell profile updated"

        if (-not (Test-Path $allHostsPath)) {
            Write-Host -ForegroundColor Cyan "[→] Writing OOBE PowerShell profile [CurrentUserAllHosts]"
            $null = New-Item $allHostsPath -ItemType File -Force
            $oobePowerShellProfile | Set-Content -Path $allHostsPath -Force -Encoding Unicode
            Write-Host -ForegroundColor Green "[✓] OOBE PowerShell profile [CurrentUserAllHosts] updated"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to write OOBE PowerShell profile: $_"
        throw
    }
}


function oobe-InstallNuget {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    try {
        $providerPath = "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"
        if (Test-Path $providerPath) {
            $installedProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue | 
                Where-Object { $_.Version -ge '2.8.5.201' } | 
                Sort-Object Version -Descending | 
                Select-Object -First 1
            
            if ($installedProvider) {
                Write-Host -ForegroundColor Green "[✓] NuGet $($installedProvider.Version)"
                return
            }
        }

        Write-Host -ForegroundColor Cyan "[→] Installing PackageProvider NuGet"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        
        $installedProvider = Get-PackageProvider -Name NuGet -ErrorAction Stop | 
            Where-Object { $_.Version -ge '2.8.5.201' } | 
            Sort-Object Version -Descending | 
            Select-Object -First 1
        
        if ($installedProvider) {
            Write-Host -ForegroundColor Green "[✓] NuGet $($installedProvider.Version)"
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] Failed to install NuGet: $_"
        throw
    }
}