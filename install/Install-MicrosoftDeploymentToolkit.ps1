<#
.SYNOPSIS
Installs Microsoft Deployment Toolkit (MDT) from module metadata.

.DESCRIPTION
Downloads the MDT x64 MSI from the URL defined in module metadata,
validates the SHA256 checksum, and installs it silently using msiexec.

.OUTPUTS
System.Management.Automation.PSCustomObject

.EXAMPLE
Install-MicrosoftDeploymentToolkit

Downloads, verifies, and installs MDT if it is not already installed.

.NOTES
Author:  David Segura
Company: Recast Software

This function is supported only on Windows.
Microsoft Deployment Toolkit (MDT) has an immediate retirement notice from Microsoft:
https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/mdt/mdt-retirement

.LINK
https://learn.microsoft.com/en-us/intune/configmgr/mdt/

.LINK
https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/mdt/mdt-retirement

.LINK
https://web.archive.org/web/20250616094712/https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi
#>
function Install-MicrosoftDeploymentToolkit {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param ()

    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw "[$(Get-Date -format s)] is supported only on Windows."
    }

    $currentPrincipal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "[$(Get-Date -format s)] requires Administrator rights. Re-run PowerShell as Administrator and try again."
    }

    $curl = Get-Command -Name 'curl.exe' -ErrorAction SilentlyContinue
    if (-not $curl) {
        throw "[$(Get-Date -format s)] curl.exe is required but was not found. Ensure curl.exe is available in PATH (included with Windows 10 1803+)."
    }

    $msiExec = Get-Command -Name 'msiexec.exe' -ErrorAction SilentlyContinue
    if (-not $msiExec) {
        throw "[$(Get-Date -format s)] msiexec.exe is required but was not found."
    }

    if (-not $global:OSDeployMDTModule -or -not $global:OSDeployMDTModule.mdt) {
        throw "[$(Get-Date -format s)] OSDeploy module metadata is missing required mdt configuration."
    }

    $mdtConfig = $global:OSDeployMDTModule.mdt
    $retirementUrl = [string]$mdtConfig.retirement
    $mdtUrl = [string]$mdtConfig.msi
    $expectedSha256 = ([string]$mdtConfig.sha256).ToLowerInvariant()

    Write-Warning "[$(Get-Date -format s)] Microsoft Deployment Toolkit (MDT) has an immediate retirement notice from Microsoft."
    Write-Warning "[$(Get-Date -format s)] $retirementUrl"

    if ([string]::IsNullOrWhiteSpace($mdtUrl) -or [string]::IsNullOrWhiteSpace($expectedSha256)) {
        throw "[$(Get-Date -format s)] OSDeploy module metadata mdt is incomplete. Required keys: msi, sha256."
    }

    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $installedMdt = $null
    foreach ($uninstallPath in $uninstallPaths) {
        $installedMdt = Get-ItemProperty -Path $uninstallPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'Microsoft Deployment Toolkit*' } |
            Select-Object -First 1

        if ($installedMdt) {
            break
        }
    }

    if ($installedMdt) {
        Write-Host "[$(Get-Date -format s)] Microsoft Deployment Toolkit is already installed: $($installedMdt.DisplayVersion)" -ForegroundColor Green
        return [pscustomobject]@{
            ProductName    = $installedMdt.DisplayName
            Version        = $installedMdt.DisplayVersion
            WasInstalled   = $false
            SkippedInstall = $false
            InstallerPath  = $null
            InstallerUrl   = $mdtUrl
            Sha256         = $expectedSha256
        }
    }

    $installerPath = Join-Path -Path $env:TEMP -ChildPath 'MicrosoftDeploymentToolkit_x64.msi'
    $skippedInstall = $false

    if ($PSCmdlet.ShouldProcess('Microsoft Deployment Toolkit', 'Download, verify SHA256, and install silently')) {
        Write-Host "[$(Get-Date -format s)] Downloading Microsoft Deployment Toolkit MSI..." -ForegroundColor DarkGray
        & $curl.Source --insecure --location --output $installerPath --url $mdtUrl
        if ($LASTEXITCODE -ne 0) {
            throw "[$(Get-Date -format s)] Failed to download MDT MSI (curl.exe exit code $LASTEXITCODE)."
        }

        $actualSha256 = (Get-FileHash -Path $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSha256 -ne $expectedSha256) {
            throw "[$(Get-Date -format s)] MDT MSI checksum mismatch. Expected $expectedSha256 but got $actualSha256."
        }

        Write-Host "[$(Get-Date -format s)] Installing Microsoft Deployment Toolkit..." -ForegroundColor DarkGray
        $msiArgs = @('/i', $installerPath, '/qn', '/norestart')
        $process = Start-Process -FilePath $msiExec.Source -ArgumentList $msiArgs -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "[$(Get-Date -format s)] MDT installation failed with exit code $($process.ExitCode)."
        }

        $installedMdt = $null
        foreach ($uninstallPath in $uninstallPaths) {
            $installedMdt = Get-ItemProperty -Path $uninstallPath -ErrorAction SilentlyContinue |
                Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'Microsoft Deployment Toolkit*' } |
                Select-Object -First 1

            if ($installedMdt) {
                break
            }
        }

        if (-not $installedMdt) {
            throw "[$(Get-Date -format s)] MDT install completed but product was not found in uninstall registry."
        }

        Write-Host "[$(Get-Date -format s)] Microsoft Deployment Toolkit installed successfully." -ForegroundColor Green

        return [pscustomobject]@{
            ProductName    = $installedMdt.DisplayName
            Version        = $installedMdt.DisplayVersion
            WasInstalled   = $true
            SkippedInstall = $false
            InstallerPath  = $installerPath
            InstallerUrl   = $mdtUrl
            Sha256         = $actualSha256
        }
    }

    $skippedInstall = $true
    [pscustomobject]@{
        ProductName    = 'Microsoft Deployment Toolkit'
        Version        = $null
        WasInstalled   = $false
        SkippedInstall = $skippedInstall
        InstallerPath  = $installerPath
        InstallerUrl   = $mdtUrl
        Sha256         = $expectedSha256
    }
}