param (
  [String]$storageAccountName = "madduxliquit" ,           # Storage Account Name
  [String]$containerName = "liquit" ,                          # Blob Container Name
  [String]$url = "https://download.liquit.com/extra/Bootstrapper/AgentBootstrapper-Win-2.1.0.2.exe",
  [switch]$StartDeployment = $false,
  [string]$logPath = "C:\Windows\Temp",
  [switch]$UseCertificate = $true
)

#https://madduxliquit.blob.core.windows.net/liquit/agent.json
######################
#   Configuration    #
######################

# Files to download
$blobFiles = @(
    "Agent.json",
    "AgentRegistration.cer"
)
$DestinationPath = "C:\InstallFiles"               # Target path in the AIB VM
$InstallerPath = "C:\InstallFiles\AgentBootstrapper.exe"

If ($StartDeployment) {$InstallerArguments += " /startDeployment /waitForDeployment"}
If ($logPath) {$InstallerArguments += " /logPath=$($logPath)"}
If ($UseCertificate) {$InstallerArguments += " /certificate=C:\InstallFiles\AgentRegistration.cer"}
#$InstallerArguments = "/certificate=C:\InstallFiles\AgentRegistration.cer /startDeployment /waitForDeployment /logPath=$($logPath)"


#######################################
#    DOWNLOAD FILES TO DESTINATION    #
#######################################
# Create destination directory
if (!(Test-Path $DestinationPath)) {  
    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
}

# Download Agent Bootstrapper direct from Internet
Invoke-WebRequest -Uri $url -OutFile $InstallerPath -UseBasicParsing

foreach ($blobName in $blobFiles) {
    $localFilePath = Join-Path $DestinationPath $blobName
    $blobUrl = "https://$($storageAccountName).blob.core.windows.net/$($containerName)/$($blobName)"
    #$blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName"                
    #Invoke-WebRequest -Uri $blobUrl -Headers $headers -OutFile $localFilePath
    Invoke-WebRequest -Uri $blobUrl -OutFile $localFilePath

    Write-Output "Downloading $blobName to $localFilePath..."
    try {
        Invoke-RestMethod -Uri $blobUrl -Headers $headers -OutFile $localFilePath
        Write-Output "$blobName downloaded successfully."
    } catch {
        Write-Output "Failed to download $blobName $_"
    }
}

Write-Output "All downloads completed."

# ===============================
set-location $DestinationPath

# Start the install process

Write-Host "Starting the installation process..."

if (Test-Path -Path $InstallerPath) {

   try {

       Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArguments -Wait

       Write-Host "Installation process completed."

   } catch {

       Write-Error "Error starting the installer '$InstallerPath': $($_.Exception.Message)"

       exit 1

   }

} else {

   Write-Warning "Installer executable not found: '$InstallerPath'"

}
