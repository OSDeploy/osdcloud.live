<#
[Info] Agent Bootstrapper Version: 2.1.0.2
[Info] /help    Displays the help message.
[Info] /?    Alias for displaying the help message
[Info] /forceDownload    Forces the bootstrapper to download the installer file.
[Info] /downloadUrl=    Sets a source URL for the bootstrapper to download the installer.
[Info] /startDeployment    Run ShellAPI deployment after installing the User Agent.
[Info] /waitForDeployment    Wait for the deployment to finish before exiting.
[Info] /zoneOverride=    Writes the zone input to the configuration file before reading it.
[Info] /logPath=    Specify a path to place the log files in. If not specified, current directory will be used.
[Info] /certificate=    Copies the specified certificate file to the Liquit data folder.
[Info] /certificateThumbprint=    Writes the value to the Certificate Thumbprint field in the configuration file.
[Info] /certificateIssuer=    Writes the value to the Certificate Issuer field in the configuration file.
[Info] /uninstall    Uninstalls the Liquit Agent.
[Info] /legacyDownload    Downloads the legacy installer when using the static link.
[Info] /skipOverrideConfig    Don't use the 'OVERRIDE_CONFIG' flag when installing.
[Info] /msiProperties=    Specify properties that are passed along to the installer.[Info] Agent Bootstrapper Version: 2.1.0.2
[Info] /help    Displays the help message.
[Info] /?    Alias for displaying the help message
[Info] /forceDownload    Forces the bootstrapper to download the installer file.
[Info] /downloadUrl=    Sets a source URL for the bootstrapper to download the installer.
[Info] /startDeployment    Run ShellAPI deployment after installing the User Agent.
[Info] /waitForDeployment    Wait for the deployment to finish before exiting.
[Info] /zoneOverride=    Writes the zone input to the configuration file before reading it.
[Info] /logPath=    Specify a path to place the log files in. If not specified, current directory will be used.
[Info] /certificate=    Copies the specified certificate file to the Liquit data folder.
[Info] /certificateThumbprint=    Writes the value to the Certificate Thumbprint field in the configuration file.
[Info] /certificateIssuer=    Writes the value to the Certificate Issuer field in the configuration file.
[Info] /uninstall    Uninstalls the Liquit Agent.
[Info] /legacyDownload    Downloads the legacy installer when using the static link.
[Info] /skipOverrideConfig    Don't use the 'OVERRIDE_CONFIG' flag when installing.
[Info] /msiProperties=    Specify properties that are passed along to the installer.
#>

function winpe-SetupCompleteApplicationWorkspaceAZ {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [String]$agentbootstrapperURL = "https://download.liquit.com/extra/Bootstrapper/AgentBootstrapper-Win-2.1.0.2.exe",
        [String]$containerName = "liquit",
        [String]$DestinationPath = "C:\Windows\Temp",
        [string]$logPath = "C:\Windows\Temp",
        [String]$storageAccountName = "madduxliquit",
        [switch]$StartDeployment = $false,
        [switch]$UseCertificate = $true
    )
    
    Write-Host -ForegroundColor Cyan "[→] Recast Software Application Workspace"
    Write-Host -ForegroundColor DarkGray "[↓] $agentbootstrapperURL"

    #https://madduxliquit.blob.core.windows.net/liquit/agent.json

    # Files to download
    $blobFiles = @(
        "Agent.json",
        "AgentRegistration.cer"
    )

    $InstallerPath = "$DestinationPath\AgentBootstrapper.exe"

    If ($StartDeployment) {$InstallerArguments += " /startDeployment /waitForDeployment"}
    If ($logPath) {$InstallerArguments += " /logPath=$($logPath)"}
    If ($UseCertificate) {$InstallerArguments += " /certificate=$DestinationPath\AgentRegistration.cer"}
    #$InstallerArguments = "/certificate=$DestinationPath\AgentRegistration.cer /startDeployment /waitForDeployment /logPath=$($logPath)"

    if (!(Test-Path $DestinationPath)) {  
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Download Agent Bootstrapper
    Invoke-WebRequest -Uri $agentbootstrapperURL -OutFile $InstallerPath -UseBasicParsing

    # Download Application Workspace Agent files 
    foreach ($blobName in $blobFiles) {
        $localFilePath = Join-Path $DestinationPath $blobName
        $blobUrl = "https://$($storageAccountName).blob.core.windows.net/$($containerName)/$($blobName)"
        #$blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName"                
        #Invoke-WebRequest -Uri $blobUrl -Headers $headers -OutFile $localFilePath
        Invoke-WebRequest -Uri $blobUrl -OutFile $localFilePath

        # Write-Output "Downloading $blobName to $localFilePath..."
        try {
            Write-Host -ForegroundColor DarkGray "[↓] $blobUrl"
            Invoke-RestMethod -Uri $blobUrl -Headers $headers -OutFile $localFilePath
            # Write-Output "$blobName downloaded successfully."
        } catch {
            # Write-Output "Failed to download $blobName $_"
            Write-Host -ForegroundColor Red "[✗] Failed to setup Recast Software Application Workspace: $_"
            throw
        }
    }

    $ScriptsPath = "C:\Windows\Setup\Scripts"
    if (-not (Test-Path $ScriptsPath)) {
        New-Item -Path $ScriptsPath -ItemType Directory -Force -ErrorAction Ignore | Out-Null
    }
    $SetupCompleteCmd = "$ScriptsPath\SetupComplete.cmd"




    $Content = @"
:: ========================================================
:: Recast Software - Application Workspace
:: ========================================================
pushd C:\Windows\Temp
AgentBootstrapper.exe /certificate=AgentRegistration.cer /startDeployment /waitForDeployment
popd
:: ========================================================
"@
    $Content | Out-File -FilePath $SetupCompleteCmd -Append -Encoding ascii -Width 2000 -Force

    <#
        Set-Location $DestinationPath
        # Start the install process
        Write-Host "Starting the installation process..."
        if (Test-Path -Path $InstallerPath) {
            try {
                Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArguments -Wait
                Write-Host "Installation process completed."
            }
            catch {
                Write-Error "Error starting the installer '$InstallerPath': $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Write-Warning "Installer executable not found: '$InstallerPath'"
        }
    #>
}

function winpe-SetupCompleteApplicationWorkspaceGH {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [String]$agentbootstrapperURL = "https://download.liquit.com/extra/Bootstrapper/AgentBootstrapper-Win-2.1.0.2.exe",
        [String]$agentcertificateURL = "https://raw.githubusercontent.com/OSDeploy/osdcloudaw/refs/heads/master/AgentRegistration.cer",
        [String]$agentjsonURL = "https://raw.githubusercontent.com/OSDeploy/osdcloudaw/refs/heads/master/Agent.json",
        [String]$DestinationPath = "C:\Windows\Temp",
        [string]$logPath = "C:\Windows\Temp",
        [switch]$StartDeployment = $false,
        [switch]$UseCertificate = $true
    )
    
    Write-Host -ForegroundColor Cyan "[→] Recast Software Application Workspace"

    $InstallerPath = "$DestinationPath\AgentBootstrapper.exe"

    If ($StartDeployment) {$InstallerArguments += " /startDeployment /waitForDeployment"}
    If ($logPath) {$InstallerArguments += " /logPath=$($logPath)"}
    If ($UseCertificate) {$InstallerArguments += " /certificate=$DestinationPath\AgentRegistration.cer"}
    #$InstallerArguments = "/certificate=$DestinationPath\AgentRegistration.cer /startDeployment /waitForDeployment /logPath=$($logPath)"

    if (!(Test-Path $DestinationPath)) {  
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    # Download Agent Bootstrapper
    Write-Host -ForegroundColor DarkGray "[↓] $agentbootstrapperURL"
    Invoke-WebRequest -Uri $agentbootstrapperURL -OutFile $InstallerPath -UseBasicParsing

    # Download Application Workspace Agent files
    Write-Host -ForegroundColor DarkGray "[↓] $agentcertificateURL"
    Invoke-WebRequest -Uri $agentcertificateURL -OutFile "$DestinationPath\AgentRegistration.cer" -UseBasicParsing
    Write-Host -ForegroundColor DarkGray "[↓] $agentjsonURL"
    Invoke-WebRequest -Uri $agentjsonURL -OutFile "$DestinationPath\Agent.json" -UseBasicParsing

    $ScriptsPath = "C:\Windows\Setup\Scripts"
    if (-not (Test-Path $ScriptsPath)) {
        New-Item -Path $ScriptsPath -ItemType Directory -Force -ErrorAction Ignore | Out-Null
    }
    $SetupCompleteCmd = "$ScriptsPath\SetupComplete.cmd"

    $Content = @"
:: ========================================================
:: Recast Software - Application Workspace
:: ========================================================
pushd C:\Windows\Temp
AgentBootstrapper.exe /certificate=AgentRegistration.cer /startDeployment /waitForDeployment
popd
:: ========================================================
"@
    $Content | Out-File -FilePath $SetupCompleteCmd -Append -Encoding ascii -Width 2000 -Force

    <#
        Set-Location $DestinationPath
        # Start the install process
        Write-Host "Starting the installation process..."
        if (Test-Path -Path $InstallerPath) {
            try {
                Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArguments -Wait
                Write-Host "Installation process completed."
            }
            catch {
                Write-Error "Error starting the installer '$InstallerPath': $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Write-Warning "Installer executable not found: '$InstallerPath'"
        }
    #>
}