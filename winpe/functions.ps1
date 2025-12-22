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