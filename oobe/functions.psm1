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
        Write-Host -ForegroundColor Yellow "[→] Writing OOBE PowerShell profile"
        if (-not (Test-Path $profileDir)) {
            $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        $oobePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        Write-Host -ForegroundColor Green "[✓] OOBE PowerShell profile updated"

        if (-not (Test-Path $allHostsPath)) {
            Write-Host -ForegroundColor Yellow "[→] Writing OOBE PowerShell profile [CurrentUserAllHosts]"
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