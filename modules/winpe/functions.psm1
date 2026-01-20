<#
.SYNOPSIS
WinPE environment setup and configuration functions.

.DESCRIPTION
Functions for configuring the Windows PE environment, including execution policy,
environment variables, package management, and tool installation.

Recommended execution order for initial setup:
    1. winpe-RepairExecutionPolicy
    2. winpe-RepairUserShellFolder
    3. winpe-RepairRegistryEnvironment
    4. winpe-RepairSessionEnvironment
    5. winpe-RepairPowerShellProfile
    6. winpe-RepairRealTimeClockUTC
    7. winpe-RepairTimeService
    8. winpe-RepairCurl
    9. winpe-RepairNugetPackageProvider
    10. winpe-RepairNugetExe
    11. winpe-UpdatePackageManagement
    12. winpe-UpdatePowerShellGet
    13. winpe-TrustPSGallery
    14. winpe-InstallAzCopy

Additional functions (can be run after the core setup above):
    - winpe-InstallPowerShellModule -Name <ModuleName>
    - winpe-InstallDotNetCore
    - winpe-InstallZip

.NOTES
Functions are designed to be idempotent and can be safely re-run.
Most functions will skip if the target is already configured/installed.
#>

function winpe-RepairTls {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
        Write-Host "TLS 1.2 is already enabled"
    } else {
        Write-Host "TLS 1.2 is NOT enabled"
    }

    $currentProtocols = [Net.ServicePointManager]::SecurityProtocol
    $hasTls12 = $currentProtocols -band [Net.SecurityProtocolType]::Tls12
    Write-Host "Current protocols: $currentProtocols"
    Write-Host "TLS 1.2 enabled: $($hasTls12 -ne 0)"

    pause

    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol

    if ($SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
        Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [Tls12]"
        return
    }

    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] Transport Layer Security should be set to Tls12"
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor DarkGray "[✓] Transport Layer Security [Tls12] repaired"
        [Net.ServicePointManager]::SecurityProtocol = $SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name) failed: $_"
        throw
    }
}

function winpe-TestExecutionPolicy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()

    # Get the current execution policy
    try {
        $executionPolicy = Get-ExecutionPolicy -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    
    # Success
    if ($executionPolicy -eq 'Bypass') {
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Execution Policy is set to Bypass"
        return
    }

    # Failure
    Write-Host -ForegroundColor Red "[✗] Execution Policy is NOT set to Bypass"
    Write-Host -ForegroundColor DarkGray "The current Execution Policy is: $executionPolicy"
    Write-Host -ForegroundColor DarkGray "OSDCloud scripting will fail if not properly configured to Bypass"
}

function winpe-RepairExecutionPolicy {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Get the current execution policy
    try {
        $executionPolicy = Get-ExecutionPolicy -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    
    # Success
    if ($executionPolicy -eq 'Bypass') {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Execution Policy is set to Bypass"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Execution Policy is set to $executionPolicy"
        Write-Host -ForegroundColor DarkGray "Execution Policy should be set to Bypass for installing Package Providers"
        return
    }

    # Repair
    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Set-ExecutionPolicy -ExecutionPolicy Bypass -Force"
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
}

function winpe-TestUserShellFolder {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    $requiredFolders = @(
        "$env:ProgramFiles\WindowsPowerShell\Modules",
        "$env:ProgramFiles\WindowsPowerShell\Scripts",
        "$env:UserProfile\AppData\Local",
        "$env:UserProfile\AppData\Roaming",
        "$env:UserProfile\Desktop",
        "$env:UserProfile\Documents\WindowsPowerShell",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Scripts"
    )

    # Test for missing folders
    $needsRepair = $false
    foreach ($folder in $requiredFolders) {
        if (-not (Test-Path -Path $folder)) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        Write-Host -ForegroundColor DarkGreen "[✓] Required User Shell Folders exist"
        return
    }

    # Failure
    Write-Host -ForegroundColor Red "[✗] Required User Shell Folders DO NOT exist"
    foreach ($item in $requiredFolders) {
        if (Test-Path -Path $item) {
            continue
        }
        Write-Host -ForegroundColor DarkGray $item
    }
}

function winpe-RepairUserShellFolder {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $requiredFolders = @(
        "$env:ProgramFiles\WindowsPowerShell\Modules",
        "$env:ProgramFiles\WindowsPowerShell\Scripts",
        "$env:UserProfile\AppData\Local",
        "$env:UserProfile\AppData\Roaming",
        "$env:UserProfile\Desktop",
        "$env:UserProfile\Documents\WindowsPowerShell",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Modules",
        "$env:SystemRoot\system32\WindowsPowerShell\v1.0\Scripts"
    )

    # Test for missing folders
    $needsRepair = $false
    foreach ($folder in $requiredFolders) {
        if (-not (Test-Path -Path $folder)) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] Required User Shell Folders exist"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Required User Shell Folders DO NOT exist"
        foreach ($item in $requiredFolders) {
            if (Test-Path -Path $item) {
                continue
            }
            Write-Host -ForegroundColor DarkGray $item
        }
    }

    # Repair
    if ($Force) {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        foreach ($item in $requiredFolders) {
            if (Test-Path -Path $item) {
                continue
            }

            try {
                Write-Host -ForegroundColor DarkGray $item
                $null = New-Item -Path $item -ItemType Directory -Force -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }
    }
}

function winpe-TestRegistryEnvironment {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
        'USERPROFILE'   = "$env:UserProfile"
    }

    # Test if a repair is needed
    $needsRepair = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        Write-Host -ForegroundColor DarkGreen "[✓] Required Environment variables exist in the Registry"
        return
    }

    
    Write-Host -ForegroundColor Red "[✗] Required Environment variables DO NOT exist in the Registry"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            Write-Host -ForegroundColor DarkGray "$name = $value"
        }
    }
}

function winpe-RepairRegistryEnvironment {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
        'USERPROFILE'   = "$env:UserProfile"
    }

    # Test if a repair is needed
    $needsRepair = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        #Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] All required Environment variables exist in the Registry"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "One or more required Environment variables are missing from the Registry:"
        foreach ($item in $requiredEnvironment.GetEnumerator()) {
            $name = $item.Key
            $value = $item.Value

            $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

            if ($currentValue -ne $value) {
                Write-Host -ForegroundColor DarkGray "$name = $value"
            }
        }
        return
    }

    # Repair
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    Write-Host -ForegroundColor DarkGray "Adding missing Environment variables to the Registry:"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        $currentValue = (Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).$name

        if ($currentValue -ne $value) {
            try {
                Write-Host -ForegroundColor DarkGray "$name = $value"
                Set-ItemProperty -Path $registryPath -Name $name -Value $value -Force -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }
    }
}

function winpe-TestSessionEnvironment {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
    }

    # Test if a repair is needed
    $needsRepair = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        Write-Host -ForegroundColor DarkGreen "[✓] Required Environment Variables exist in the current PowerShell Session"
        return
    }

    # Failure
    Write-Host -ForegroundColor Red "[✗] Required Environment Variables DO NOT exist in the current PowerShell Session"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            Write-Host -ForegroundColor DarkGray "$name = $value"
        }
    }
}

function winpe-RepairSessionEnvironment {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $requiredEnvironment = [ordered]@{
        'APPDATA'       = "$env:UserProfile\AppData\Roaming"
        'HOMEDRIVE'     = "$env:SystemDrive"
        'HOMEPATH'      = "\windows\system32\config\systemprofile"
        'LOCALAPPDATA'  = "$env:UserProfile\AppData\Local"
    }

    # Test if a repair is needed
    $needsRepair = $false
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }

        if ($currentValue -ne $value) {
            $needsRepair = $true
            break
        }
    }

    # Success
    if (-not $needsRepair) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] All required Environment variables exist in the current PowerShell Session"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "One or more required Environment variables are missing from the current PowerShell Session:"
        foreach ($item in $requiredEnvironment.GetEnumerator()) {
            $name = $item.Key
            $value = $item.Value

            try {
                $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
            }
            catch {
                $currentValue = $null
            }

            if ($currentValue -ne $value) {
                Write-Host -ForegroundColor DarkGray "$name = $value"
            }
        }
        return
    }

    #Repair
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    Write-Host -ForegroundColor DarkGray "Adding missing Environment variables to the current PowerShell Session:"
    foreach ($item in $requiredEnvironment.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        try {
            $currentValue = Get-Item "env:$name" -ErrorAction Stop | Select-Object -ExpandProperty Value
        }
        catch {
            $currentValue = $null
        }


        if ($currentValue -ne $value) {
            try {
                Write-Host -ForegroundColor DarkGray "$name = $value"
                Set-Item -Path "env:$name" -Value $value -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }
    }
}

function winpe-TestPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    $profileDir = $PSHome
    $profilePath = Join-Path -Path $PSHome -ChildPath 'profile.ps1'

    # Test if a repair is needed
    $needsProfileRepair = $false
    $needsProfileCreated = $false

    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
        $needsProfileRepair = $true
    }
    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
        $needsProfileRepair = $true
    }
    if (-not (Test-Path -Path $profilePath)) {
        $needsProfileCreated = $true
    }
    else {
        $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop
        if (-not ($existingContent -match 'OSDCloud by Recast Software')) {
            $needsProfileCreated = $true
        }
    }

    # Success
    if (-not $needsProfileRepair -and -not $needsProfileCreated) {
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Profiles are properly configured"
        return
    }

    # Failure
    if ($needsProfileRepair) {
        Write-Host -ForegroundColor Red "[✗] PowerShell Profile paths are NOT properly configured"
        if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
            Write-Host -ForegroundColor DarkGray "CurrentUserAllHosts: [$($PROFILE.CurrentUserAllHosts)]"
        }
        if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
            Write-Host -ForegroundColor DarkGray "CurrentUserCurrentHost: [$($PROFILE.CurrentUserCurrentHost)]"
        }
    }
    if ($needsProfileCreated) {
        Write-Host -ForegroundColor Red "[✗] PowerShell Profile is not configured for Registry Environment Variables"
    }
}

function winpe-RepairPowerShellProfile {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $profileDir = $PSHome
    $profilePath = Join-Path -Path $PSHome -ChildPath 'profile.ps1'

    # Test if a repair is needed
    $needsProfileRepair = $false
    $needsProfileCreated = $false

    if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
        $needsProfileRepair = $true
    }
    if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
        $needsProfileRepair = $true
    }
    if (-not (Test-Path -Path $profilePath)) {
        $needsProfileCreated = $true
    }
    else {
        $existingContent = Get-Content -Path $profilePath -Raw -ErrorAction Stop
        if (-not ($existingContent -match 'OSDCloud by Recast Software')) {
            $needsProfileCreated = $true
        }
    }

    # Success
    if (-not $needsProfileRepair -and -not $needsProfileCreated) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Profiles are configured"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        if ($needsProfileRepair) {
            Write-Host -ForegroundColor DarkGray "PowerShell Profile paths are incorrectly configured:"
            if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
                Write-Host -ForegroundColor DarkGray "CurrentUserAllHosts: [$($PROFILE.CurrentUserAllHosts)]"
            }
            if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
                Write-Host -ForegroundColor DarkGray "CurrentUserCurrentHost: [$($PROFILE.CurrentUserCurrentHost)]"
            }
        }
        if ($needsProfileCreated) {
            Write-Host -ForegroundColor Red "[✗] PowerShell Profile is not configured for Registry Environment Variables"
        }
        return
    }

    # Repair
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    if ($needsProfileRepair) {
        Write-Host -ForegroundColor DarkGray "Updating PowerShell Profile paths:"
        if ($PROFILE.CurrentUserAllHosts -ne "$Home\Documents\WindowsPowerShell\profile.ps1") {
            $PROFILE.CurrentUserAllHosts = "$Home\Documents\WindowsPowerShell\profile.ps1"
            Write-Host -ForegroundColor DarkGray "CurrentUserAllHosts: [$($PROFILE.CurrentUserAllHosts)]"
        }
        if ($PROFILE.CurrentUserCurrentHost -ne "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1") {
            $PROFILE.CurrentUserCurrentHost = "$Home\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
            Write-Host -ForegroundColor DarkGray "CurrentUserCurrentHost: [$($PROFILE.CurrentUserCurrentHost)]"
        }
    }
    if (-not $needsProfileCreated) {
        return
    }

    $winpePowerShellProfile = @'
# OSDCloud by Recast Software
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$registryPath | ForEach-Object {
    $k = Get-Item $_
    $k.GetValueNames() | ForEach-Object {
        $name = $_
        $value = $k.GetValue($_)
        Set-Item -Path Env:\$name -Value $value
    }
}
'@

    try {
        if (Test-Path -Path $profilePath) {
            Write-Host -ForegroundColor DarkGray "Add to existing PowerShell Profile for AllUsersAllHosts"
            Write-Host -ForegroundColor DarkGray "Resolves new environment variables added to Session Manager in the registry"
            Add-Content -Path $profilePath -Value ("`r`n" + $winpePowerShellProfile) -Encoding Unicode -ErrorAction Stop
        }
        else {
            Write-Host -ForegroundColor DarkGray "PowerShell Profile does not exist with OSDCloud update for new sessions"
            Write-Host -ForegroundColor DarkGray "Create new PowerShell Profile for AllUsersAllHosts"
            Write-Host -ForegroundColor DarkGray "Resolves new environment variables added to Session Manager in the registry"
            if (-not (Test-Path $profileDir)) {
                $null = New-Item -Path $profileDir -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            $winpePowerShellProfile | Set-Content -Path $profilePath -Force -Encoding Unicode
        }
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
}

function winpe-TestRealTimeClockUTC {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Test if RealTimeIsUniversal is already set
    $realTimeIsUniversal = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -ErrorAction SilentlyContinue

    if ($realTimeIsUniversal -and ($realTimeIsUniversal.RealTimeIsUniversal -eq 1)) {
        Write-Host -ForegroundColor DarkGreen "[✓] RealTime Clock is set to UTC"
    }
    else {
        Write-Host -ForegroundColor Red "[✗] RealTime Clock is NOT set to UTC"
    }
}

function winpe-RepairRealTimeClockUTC {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Test if RealTimeIsUniversal is already set
    $realTimeIsUniversal = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -ErrorAction SilentlyContinue

    if ($realTimeIsUniversal -and ($realTimeIsUniversal.RealTimeIsUniversal -eq 1)) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] RealTime Clock is set to UTC"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "RealTime Clock is NOT set to UTC"
        return
    }

    # Repair
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\TimeZoneInformation' -Name 'RealTimeIsUniversal' -Value 1 -Type DWord -ErrorAction Stop
        Write-Host -ForegroundColor DarkGray "RealTime Clock is set to UTC"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
}

function winpe-TestTimeService {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    # Can we connect to Time Service?
    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    # Test if the Time Service is correctly configured
    if (($w32timeService.StartType -eq 'Automatic') -and ($w32timeService.Status -eq 'Running')) {
        Write-Host -ForegroundColor DarkGreen "[✓] Time Service [w32time] is set to Automatic and is Running"
    }
    else {
        if ($w32timeService.StartType -ne 'Automatic') {
            Write-Host -ForegroundColor Red "[✗] Time Service [w32time] StartType is NOT set to Automatic"
        }
        if ($w32timeService.Status -ne 'Running') {
            Write-Host -ForegroundColor Red "[✗] Time Service [w32time] is NOT Running"
        }
    }
}

function winpe-RepairTimeService {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Can we connect to Time Service?
    try {
        $w32timeService = Get-Service -Name w32time -ErrorAction Stop
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }

    # Test if the Time Service is correctly configured
    if (($w32timeService.StartType -eq 'Automatic') -and ($w32timeService.Status -eq 'Running')) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] Time Service [w32time] is set to Automatic and is Running"
        return
    }

    # Warning
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        if ($w32timeService.StartType -ne 'Automatic') {
            Write-Host -ForegroundColor DarkGray "Time Service [w32time] StartType is NOT set to Automatic"
        }
        if ($w32timeService.Status -ne 'Running') {
            Write-Host -ForegroundColor DarkGray "Time Service [w32time] is NOT Running"
        }
        return
    }

    # Repair
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"

    if ($w32timeService.StartType -ne 'Automatic') {
        try {
            Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop
            Write-Host -ForegroundColor DarkGray "Time Service [w32time] StartType is now set to Automatic"
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }

    if ($w32timeService.Status -eq 'Running') {
        Write-Host -ForegroundColor DarkGray "Time Service [w32time] is being restarted"
        try {
            Restart-Service -Name w32time -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }
    else {
        Write-Host -ForegroundColor DarkGray "Time Service [w32time] is being started"
        try {
            Start-Service -Name w32time -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }
}

function winpe-TestCurl {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param ()
    $curlPath = "$env:SystemRoot\System32\curl.exe"

    # Test if Curl is already installed
    if (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor DarkGreen "[✓] Curl.exe is installed [$($curl.VersionInfo.FileVersion)]"
    }
    else {
        Write-Host -ForegroundColor Red "[✗] Curl is NOT installed at $curlPath"
    }
}

function winpe-RepairCurl {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $curlPath = "$env:SystemRoot\System32\curl.exe"

    # Test if Curl is already installed
    if (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] Curl.exe is installed [$($curl.VersionInfo.FileVersion)]"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Curl is NOT installed at $curlPath"
        return
    }

    # Repair

    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        $tempZip = "$env:TEMP\curl.zip"
        $tempDir = "$env:TEMP\curl"
        
        # Download
        $url = 'https://curl.se/windows/latest.cgi?p=win64-mingw.zip'
        Write-Host -ForegroundColor DarkGray "$url"
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
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    if (Test-Path $curlPath) {
        $curl = Get-Item -Path $curlPath
        Write-Host -ForegroundColor DarkGreen "[✓] Curl.exe is installed [$($curl.VersionInfo.FileVersion)]"
        return
    }
}

function winpe-RepairPackageManagement {
    <#
    .SYNOPSIS
    Installs or updates the PackageManagement module in WinPE.

    .DESCRIPTION
    Checks for the presence of the PackageManagement module. If missing, warns and exits
    unless -Force is specified. With -Force, downloads version 1.4.8.1 from the PowerShell
    Gallery, installs it under Program Files, and imports it globally. If already installed,
    reports the latest installed version and does not reinstall.

    .PARAMETER Force
    When specified, performs installation/repair actions rather than only reporting status.

    .EXAMPLE
    winpe-RepairPackageManagement
    Displays the current status of the PackageManagement module without making changes.

    .EXAMPLE
    winpe-RepairPackageManagement -Force
    Downloads and installs PackageManagement 1.4.8.1, then imports the module.

    .OUTPUTS
    None. Writes status and progress messages to the host.

    .NOTES
    Designed for Windows PE. Uses curl when available, otherwise Invoke-WebRequest.
    Safe to re-run; no changes are made if the desired state is already present.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Test if PackageManagement is already installed
    $existingModule = Get-Module -Name PackageManagement -ListAvailable

    # Success
    if ($existingModule) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor DarkGreen "[✓] PackageManagement PowerShell Module is installed [$latestVersion]"
        return
    }

    # Not installed
    # Warning
    if (-not $Force) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module is NOT installed"
        return
    }
    
    # Repair / Install
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    try {
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Write-Host -ForegroundColor DarkGray $url
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    # Test if PackageManagement is already installed
    $existingModule = Get-Module -Name PackageManagement -ListAvailable

    # Success
    if ($existingModule) {
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor DarkGreen "[✓] PackageManagement PowerShell Module is installed [$latestVersion]"
    }
}

function winpe-RepairNugetPackageProvider {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Test if PackageManagement module is available
    if (-not (Get-Module -Name PackageManagement -ListAvailable)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module is NOT installed"
        return
    }

    # Test if Get-PackageProvider cmdlet is available
    if (-not (Get-Command -Name Get-PackageProvider -ErrorAction SilentlyContinue)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Get-PackageProvider PowerShell Cmdlet is NOT available"
        Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module may not be installed properly"
        return
    }

    # Test if Execution Policy allows installing Package Providers
    $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    if ($executionPolicy -ne 'Bypass' -and $executionPolicy -ne 'Unrestricted') {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Execution Policy is set to $executionPolicy"
        Write-Host -ForegroundColor DarkGray "Execution Policy is blocking installation of Package Providers"
        return
    }

    # Test if NuGet Package Provider is already installed
    $provider = Get-PackageProvider -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'NuGet' }
    if ($provider) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] NuGet Package Provider is installed [$($provider.Version)]"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "NuGet Package Provider is NOT installed"
        return
    }

    # Repair / Install
    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
}

function winpe-RepairNugetExe {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $nugetExeSourceURL = 'https://nuget.org/nuget.exe'
    $nugetFileName = 'NuGet.exe'

    # $env:LOCALAPPDATA may not be set in WinPE, so should not use env:LOCALAPPDATA
    # $nugetPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetPath = Join-Path -Path "$env:UserProfile\AppData\Local" -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
    $nugetExeFilePath = Join-Path -Path $nugetPath -ChildPath $nugetFileName

    # Test if NuGet.exe is already installed
    if (Test-Path -Path $nugetExeFilePath) {
        $nugetExe = Get-Item -Path $nugetExeFilePath
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGreen "[✓] NuGet.exe is installed [$($nugetExe.VersionInfo.FileVersion)]"
        return
    }
    else {
        # Warning only
        if (-not ($Force)) {
            Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor DarkGray "NuGet.exe is NOT installed"
            return
        }

        # Repair / Install
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray $nugetExeSourceURL

        # Create directory if it does not exist
        if (-not (Test-Path -Path $nugetPath)) {
            $null = New-Item -Path $nugetPath -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
        if (Test-Path $curlPath) {
            & $curlPath --fail --location --silent --show-error `
                $nugetExeSourceURL `
                --output $nugetExeFilePath
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $nugetExeFilePath)) {
                throw "curl download failed with exit code $LASTEXITCODE"
            }
        }
        else {
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $nugetExeSourceURL -OutFile $nugetExeFilePath -ErrorAction Stop
            }
            catch {
                Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
                Write-Host -ForegroundColor Red $_
                throw
            }
        }

        if (Test-Path $nugetExeFilePath) {
            $nugetExe = Get-Item -Path $nugetExeFilePath
            Write-Host -ForegroundColor DarkGreen "[✓] NuGet.exe is installed [$($nugetExe.VersionInfo.FileVersion)]"
            return
        }
    }
}

function winpe-UpdatePackageManagement {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    $existingModule = Get-Module -Name PackageManagement -ListAvailable | Where-Object { $_.Version -ge '1.4.8.1' }

    # Success
    if ($existingModule) {
        # Write-Host -ForegroundColor DarkGreen "[✓] $($MyInvocation.MyCommand.Name)"
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        # Write-Host -ForegroundColor DarkGreen "[✓] PackageManagement PowerShell Module is installed [$latestVersion]"
        return
    }

    # Warning only
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "PackageManagement PowerShell Module is NOT updated to version 1.4.8.1 or later"
        return
    }

    # Test if Execution Policy allows installing Package Providers
    $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    if ($executionPolicy -ne 'Bypass' -and $executionPolicy -ne 'Unrestricted') {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Execution Policy is set to $executionPolicy"
        Write-Host -ForegroundColor DarkGray "Execution Policy is blocking installation of Package Providers"
        return
    }

    # Repair / Install
    Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
    try {
        $tempZip = "$env:TEMP\packagemanagement.1.4.8.1.zip"
        $tempDir = "$env:TEMP\1.4.8.1"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement"

        $url = 'https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1'
        Write-Host -ForegroundColor DarkGray $url
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
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
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    
    $existingModule = Get-Module -Name PowerShellGet -ListAvailable | Where-Object { $_.Version -ge '2.2.5' }
    if ($existingModule) {
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShellGet PowerShell Module is installed [$($latestVersion)]"
        return
    }

    # Warning
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "PowerShellGet PowerShell Module is NOT updated to version 2.2.5 or later"
        return
    }

    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        $tempZip = "$env:TEMP\powershellget.2.2.5.zip"
        $tempDir = "$env:TEMP\2.2.5"
        $moduleDir = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet"
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $url = 'https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5'
        Write-Host -ForegroundColor DarkGray $url
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $existingModule = Get-Module -Name PowerShellGet -ListAvailable | Where-Object { $_.Version -ge '2.2.5' }
    if ($existingModule) {
        $latestVersion = ($existingModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShellGet PowerShell Module is installed [$($latestVersion)]"
        return
    }
}

function winpe-TrustPSGallery {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )
    # Test if Execution Policy allows PSGallery trust change
    $executionPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
    if ($executionPolicy -ne 'Bypass' -and $executionPolicy -ne 'Unrestricted') {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Execution Policy is set to $executionPolicy"
        Write-Host -ForegroundColor DarkGray "Execution Policy is blocking enumerating the PowerShell Gallery PSRepository"
        return
    }

    $PowerShellGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $PowerShellGallery) {
        Write-Host -ForegroundColor Red "[✗] PSRepository PSGallery not found"
        return
    }

    if ($PowerShellGallery.InstallationPolicy -eq 'Trusted') {
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Gallery PSRepository Installation Policy is Trusted"
        return
    }

    if (-not $Force) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "PowerShell Gallery PSRepository Installation Policy is NOT Trusted"
        return
    }

    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        Write-Host -ForegroundColor DarkGreen "[✓] PowerShell Gallery PSRepository Installation Policy is Trusted"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
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
    $azcopyPath = "$env:SystemRoot\System32\azcopy.exe"

    # Test if AzCopy is already installed
    if (Test-Path $azcopyPath) {
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor DarkGreen "[✓] Microsoft AzCopy is installed"
        return
    }

    # Warning
    if (-not ($Force)) {
        Write-Host -ForegroundColor Yellow "[!] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor DarkGray "Microsoft AzCopy is NOT installed"
        return
    }
    
    try {
        Write-Host -ForegroundColor Cyan "[→] $($MyInvocation.MyCommand.Name)"
        $tempZip = "$env:TEMP\azcopy.zip"
        $tempDir = "$env:TEMP\azcopy"
        
        # Determine download URL based on architecture
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows-arm64'
        }
        elseif ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $downloadUrl = 'https://aka.ms/downloadazcopy-v10-windows'
        }
        else {
            throw "Unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE"
        }
        Write-Host -ForegroundColor DarkGray $downloadUrl

        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
    }
    finally {
        # Cleanup
        if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path $azcopyPath) {
        $azcopy = Get-Item -Path $azcopyPath
        Write-Host -ForegroundColor DarkGreen "[✓] Microsoft AzCopy is installed"
        return
    }
}

function winpe-InstallDotNetCore {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    $dotNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.1/dotnet-runtime-10.0.1-win-x64.zip'
    $dotNetCoreZip = Join-Path -Path $env:TEMP -ChildPath 'dotnet-runtime.zip'
    $dotNetCoreDir = Join-Path -Path $env:ProgramFiles -ChildPath 'dotnet'

    try {
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
        Write-Host -ForegroundColor DarkGreen "[✓] .NET Runtime downloaded successfully"

        Write-Host -ForegroundColor Cyan "[→] Extracting .NET Runtime"
        if (-not (Test-Path $dotNetCoreDir)) {
            $null = New-Item -Path $dotNetCoreDir -ItemType Directory -Force
        }
        Expand-Archive -Path $dotNetCoreZip -DestinationPath $dotNetCoreDir -Force -ErrorAction Stop
        Write-Host -ForegroundColor DarkGreen "[✓] .NET Runtime installed successfully to $dotNetCoreDir"
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
                Write-Host -ForegroundColor Cyan "[→] Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber"
                Install-Module -Name $Name -Force -Scope AllUsers -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host -ForegroundColor DarkGreen "[✓] $Name is installed [$($GalleryModule.Version)]"
                return
            }
            
            # Already installed and current
            Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction SilentlyContinue
            Write-Host -ForegroundColor DarkGreen "[✓] $Name is installed [$($InstalledModule.Version)]"
            return
        }
        catch {
            Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
            Write-Host -ForegroundColor Red $_
            throw
        }
    }

    # Module not installed or forced, install it
    try {
        Write-Host -ForegroundColor Cyan "[→] Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber"
        $GalleryModule = Find-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
        
        if (-not $GalleryModule) {
            throw "Module $Name not found in PowerShell Gallery"
        }

        Install-Module -Name $Name -Scope AllUsers -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module -Name $Name -Force -DisableNameChecking -ErrorAction Stop
        Write-Host -ForegroundColor DarkGreen "[✓] $Name is installed [$($GalleryModule.Version)]"
    }
    catch {
        Write-Host -ForegroundColor Red "[✗] $($MyInvocation.MyCommand.Name)"
        Write-Host -ForegroundColor Red $_
        throw
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
        Write-Host -ForegroundColor DarkGray "[✓] 7-Zip [$($zip.VersionInfo.FileVersion)]"
        return
    }

    try {
        $downloadUrl = 'https://github.com/ip7z/7zip/releases/download/25.01/7z2501-extra.7z'
        $tempZip = "$env:TEMP\7z2501-extra.7z"
        $tempDir = "$env:TEMP\7za"

        Write-Host -ForegroundColor DarkCyan "[→] 7-Zip [25.01]"
        Write-Host -ForegroundColor DarkGray $downloadUrl
        
        # Download using curl if available, fallback to Invoke-WebRequest
        $curlPath = Join-Path $env:SystemRoot 'System32\curl.exe'
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
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            Copy-Item -Path "$tempDir\7za\x64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }
        elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
            Copy-Item -Path "$tempDir\7za\arm64\*" -Destination $env:SystemRoot\System32 -Recurse -Force -ErrorAction Stop
        }

        Write-Host -ForegroundColor DarkGreen "[✓] 7-Zip [25.01]"
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

Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
  [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@

function Send-SettingChange {
  $HWND_BROADCAST = [IntPtr] 0xffff;
  $WM_SETTINGCHANGE = 0x1a;
  $result = [UIntPtr]::Zero

  [void] ([Win32.Nativemethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", 2, 5000, [ref] $result))
}