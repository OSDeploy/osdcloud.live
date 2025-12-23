<#
.SYNOPSIS
    OSDCloud Live
.DESCRIPTION
    OSDCloud Live
.NOTES
    This module is designed for OOBE
.LINK
    https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/oobe/setup.psm1
.EXAMPLE
    Invoke-Expression (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/OSDeploy/osdcloud.live/main/modules/oobe/setup.psm1')
#>
#=================================================
#region Functions
function oobe-Startup {
    [CmdletBinding()]
    param (
        [System.Management.Automation.SwitchParameter]
        #Install Autopilot Support
        $Autopilot,

        [System.Management.Automation.SwitchParameter]
        #Show Windows Settings Display
        $Display,

        [System.Management.Automation.SwitchParameter]
        #Show Windows Settings Display
        $Language,

        [System.Management.Automation.SwitchParameter]
        #Show Windows Settings Display
        $DateTime,

        [System.Management.Automation.SwitchParameter]
        #Install Azure support
        $Azure,

        [System.Management.Automation.SwitchParameter]
        #Install Azure KeyVault support
        $KeyVault,

        [System.Management.Automation.SwitchParameter]
        $InstallWinGet,

        [System.Management.Automation.SwitchParameter]
        $WinGetUpgrade,

        [System.Management.Automation.SwitchParameter]
        $WinGetPwsh,

        [System.Management.Automation.SwitchParameter]
        $SkipOSD
    )
    if ($Display) {
        osdcloud-SetWindowsDisplay
    }
    if ($Language) {
        osdcloud-SetWindowsLanguage
    }
    if ($DateTime) {
        osdcloud-SetWindowsDateTime
    }
    osdcloud-SetExecutionPolicy
    osdcloud-SetPowerShellProfile
    osdcloud-InstallPackageManagement
    osdcloud-TrustPSGallery
    osdcloud-InstallPowerShellModule -Name Pester
    osdcloud-InstallPowerShellModule -Name PSReadLine

    if ($InstallWinGet) {
        osdcloud-InstallWinGet

        if ($WinGetUpgrade) {
            if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
                Write-Host -ForegroundColor Green "[✓] winget upgrade --all --accept-source-agreements --accept-package-agreements"
                winget upgrade --all --accept-source-agreements --accept-package-agreements
            }
        }

        if ($WinGetPwsh) {
            osdcloud-InstallPwsh
        }
    }

    if ($SkipOSD) {
        # do nothing
    }
    else {
        osdcloud-InstallPowerShellModule -Name OSD
        #Add Azure KeuVault Support
        if ($Azure) {
            osdcloud-InstallPowerShellModule -Name 'Az.Accounts'
            osdcloud-InstallPowerShellModule -Name 'Az.KeyVault'
        }
    
        #Add Azure KeuVault Support
        if ($KeyVault) {
            osdcloud-InstallPowerShellModule -Name 'Az.Accounts'
            osdcloud-InstallPowerShellModule -Name 'Az.KeyVault'
        }
    
        #Get Autopilot information from the device
        $TestAutopilotProfile = osdcloud-TestAutopilotProfile
    
        #If the device has an Autopilot Profile, show the information
        if ($TestAutopilotProfile -eq $true) {
            osdcloud-ShowAutopilotProfile
            $Autopilot = $false
        }
        
        #Install the required Autopilot Modules
        if ($Autopilot) {
            if ($TestAutopilotProfile -eq $false) {
                osdcloud-InstallModuleAutopilot
                osdcloud-InstallPowerShellModule -Name 'AzureAD'
                osdcloud-InstallScriptAutopilot
            }
        }
    }
}
New-Alias -Name 'Start-OOBE' -Value 'oobe-Startup' -Description 'OSDCloud' -Force
#endregion
#=================================================