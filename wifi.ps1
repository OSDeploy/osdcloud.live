#requires -Version 5.1

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

function Get-WifiNetworks {
    $output = netsh wlan show networks mode=bssid
    if (!$output) { return @() }
    $list = @()
    $current = $null
    foreach ($line in $output) {
        if ($line -match '^SSID\s+\d+\s*:\s*(.+)$') {
            if ($current) { $list += $current }
            $current = [ordered]@{
                SSID = $Matches[1].Trim()
                BSSIDs = @()
                Authentication = $null
                Encryption = $null
                Channels = @()
                Bands = @()
                RadioTypes = @()
                SignalValue = 0
                Signal = $null
            }
            continue
        }
        if (!$current) { continue }
        if ($line -match '^\s*Network type\s*:\s*(.+)$') { continue }
        if ($line -match '^\s*Authentication\s*:\s*(.+)$') { $current.Authentication = $Matches[1].Trim(); continue }
        if ($line -match '^\s*Encryption\s*:\s*(.+)$') { $current.Encryption = $Matches[1].Trim(); continue }
        if ($line -match '^\s*BSSID\s*\d+\s*:\s*(.+)$') { $bssid = $Matches[1].Trim(); $current.BSSIDs += $bssid; continue }
        if ($line -match '^\s*Signal\s*:\s*(.+)$') { 
            $sig = $Matches[1].Trim()
            $current.Signal = $sig
            $num = $sig -replace '[^0-9]',''
            if ([string]::IsNullOrWhiteSpace($num)) { $num = '0' }
            $val = [int]$num
            if ($val -gt $current.SignalValue) { $current.SignalValue = $val }
            continue 
        }
        if ($line -match '^\s*Channel\s*:\s*(.+)$') { $current.Channels += $Matches[1].Trim(); continue }
        if ($line -match '^\s*Radio type\s*:\s*(.+)$') { $current.RadioTypes += $Matches[1].Trim(); continue }
        if ($line -match '^\s*Band\s*:\s*(.+)$') { $current.Bands += $Matches[1].Trim(); continue }
    }
    if ($current) { $list += $current }
    $list | ForEach-Object {
        $bands = ($_.Bands | Where-Object { $_ } | Select-Object -Unique) -join ', '
        $radios = ($_.RadioTypes | Where-Object { $_ } | Select-Object -Unique) -join ', '
        $channels = ($_.Channels | Where-Object { $_ } | Select-Object -Unique) -join ', '
        $sigText = if ($_.SignalValue -gt 0) { "{0}%" -f $_.SignalValue } else { $_.Signal }
        [pscustomobject]@{
            SSID = $_.SSID
            Authentication = $_.Authentication
            Encryption = $_.Encryption
            Signal = $sigText
            SignalValue = $_.SignalValue
            Channel = $channels
            Bands = $bands
            RadioTypes = $radios
            BSSIDCount = ($_.BSSIDs | Measure-Object).Count
        }
    }
}

# Current Wi-Fi connection info (SSID + interface)
function Get-WifiConnectionInfo {
    $output = netsh wlan show interfaces
    if (!$output) { return @() }
    $currentInterface = $null
    $state = $null
    $list = @()
    foreach ($line in $output) {
        if ($line -match '^\s*Name\s*:\s*(.+)$') { $currentInterface = $Matches[1].Trim(); continue }
        if ($line -match '^\s*State\s*:\s*(.+)$') { $state = $Matches[1].Trim(); continue }
        if ($line -match '^\s*SSID\s*:\s*(.+)$') {
            $ssid = $Matches[1].Trim()
            if ($state -and $state -match 'connected') {
                $list += [pscustomobject]@{ SSID = $ssid; Interface = $currentInterface }
            }
            $state = $null
            continue
        }
    }
    $list
}

function New-WifiProfileXml {
    param(
        [Parameter(Mandatory)] [string] $Ssid,
        [Parameter(Mandatory)] [string] $Authentication, # e.g., 'WPA2-Personal' or 'Open'
        [Parameter()] [string] $Encryption = 'AES',
        [Parameter()] [string] $KeyMaterial
    )

    $isOpen = $Authentication -match 'Open'
    $authType = if ($Authentication -match 'WPA2|WPA3') { 'WPA2PSK' } elseif ($isOpen) { 'open' } else { 'WPA2PSK' }
    $cipher = if ($isOpen) { 'none' } else { if ($Encryption -match 'AES') { 'AES' } else { 'TKIP' } }

    $keyXml = ''
    if (!$isOpen -and $KeyMaterial) {
        $keyXml = "<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>$KeyMaterial</keyMaterial></sharedKey>"
    }

    $securityXml = if ($isOpen) {
        "<security><authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption></security>"
    } else {
        "<security><authEncryption><authentication>WPA2PSK</authentication><encryption>$cipher</encryption><useOneX>false</useOneX></authEncryption>$keyXml</security>"
    }

    @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$Ssid</name>
    <SSIDConfig>
        <SSID>
            <name>$Ssid</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    $securityXml
</WLANProfile>
"@
}

function Connect-Wifi {
    param(
        [Parameter(Mandatory)] [string] $Ssid,
        [Parameter()] [string] $KeyMaterial,
        [switch] $SaveProfile,
        [string] $Authentication = 'WPA2-Personal',
        [string] $Encryption = 'AES'
    )

    $xml = New-WifiProfileXml -Ssid $Ssid -Authentication $Authentication -Encryption $Encryption -KeyMaterial $KeyMaterial
    $profilePath = Join-Path (Join-Path $PSScriptRoot 'profiles') ("$Ssid.xml")

    if ($SaveProfile) {
        $xml | Set-Content -Path $profilePath -Encoding UTF8
        netsh wlan add profile filename="$profilePath" | Out-Null
    } else {
        $tmp = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $tmp -Value $xml -Encoding UTF8
        netsh wlan add profile filename="$tmp" | Out-Null
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    netsh wlan connect name="$Ssid" | Out-Null
}

# XAML for Windows 11-like styling
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="ReOSD Wi-Fi" Height="400" Width="640" MinHeight="320" MinWidth="480" Background="#F8F9FB" WindowStartupLocation="CenterScreen" AllowsTransparency="False" WindowStyle="SingleBorderWindow" ResizeMode="CanResize">
    <Border CornerRadius="12" Background="#FFFFFF" BorderBrush="#DADCE0" BorderThickness="1" Padding="12">
        <DockPanel LastChildFill="True">
            <Grid Margin="0">
                <Grid.RowDefinitions>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <!-- List Row (fills) -->
                <ListView x:Name="LvNetworks" Grid.Row="0" Background="#FFFFFF" BorderBrush="#E5E7EB" Foreground="#111827" Margin="0,0,0,8" HorizontalAlignment="Left" VerticalAlignment="Stretch">
                    <ListView.View>
                        <GridView>
                            <GridViewColumn Header="SSID" DisplayMemberBinding="{Binding SSID}" Width="100" />
                            <GridViewColumn Header="Connected" Width="70">
                                <GridViewColumn.CellTemplate>
                                    <DataTemplate>
                                        <Ellipse Width="12" Height="12" VerticalAlignment="Center">
                                            <Ellipse.Style>
                                                <Style TargetType="Ellipse">
                                                    <Setter Property="Fill" Value="#D1D5DB"/>
                                                    <Setter Property="Stroke" Value="#9CA3AF"/>
                                                    <Style.Triggers>
                                                        <DataTrigger Binding="{Binding IsConnected}" Value="True">
                                                            <Setter Property="Fill" Value="#10B981"/>
                                                            <Setter Property="Stroke" Value="#059669"/>
                                                        </DataTrigger>
                                                    </Style.Triggers>
                                                </Style>
                                            </Ellipse.Style>
                                        </Ellipse>
                                    </DataTemplate>
                                </GridViewColumn.CellTemplate>
                            </GridViewColumn>
                            <GridViewColumn Header="Signal" DisplayMemberBinding="{Binding Signal}" Width="64" />
                            <GridViewColumn Header="Auth" DisplayMemberBinding="{Binding Authentication}" Width="100" />
                            <GridViewColumn Header="Bands" DisplayMemberBinding="{Binding Bands}" Width="80" />
                            <GridViewColumn Header="Radio" DisplayMemberBinding="{Binding RadioTypes}" Width="100" />
                            <GridViewColumn Header="Channels" DisplayMemberBinding="{Binding Channel}" Width="100" />
                            <GridViewColumn Header="BSSIDs" DisplayMemberBinding="{Binding BSSIDCount}" Width="60" />
                        </GridView>
                    </ListView.View>
                </ListView>
                <!-- Controls Row -->
                <StackPanel Orientation="Vertical" Grid.Row="1">
                    <TextBlock Text="Password (if secured)" Foreground="#374151" Margin="0,0,0,4"/>
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*" />
                            <ColumnDefinition Width="Auto" />
                        </Grid.ColumnDefinitions>
                        <Grid Grid.Column="0">
                            <PasswordBox x:Name="Pwd" Height="28" Background="#FFFFFF" BorderBrush="#D1D5DB" Foreground="#111827"/>
                            <TextBox x:Name="PwdPlain" Height="28" Background="#FFFFFF" BorderBrush="#D1D5DB" Foreground="#111827" Visibility="Collapsed"/>
                        </Grid>
                        <Button x:Name="BtnShowPwd" Grid.Column="1" Content="Show" Width="56" Height="28" Background="#E5E7EB" Foreground="#111827" Margin="8,0,0,0"/>
                    </Grid>
                    <CheckBox x:Name="ChkSave" Content="Save profile" Foreground="#111827" Margin="0,6,0,0"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
                        <Button x:Name="BtnRefresh" Content="Refresh" Width="96" Height="28" Background="#E5E7EB" Foreground="#111827"/>
                        <Button x:Name="BtnConnect" Content="Connect" Width="96" Height="28" Background="#2563EB" Foreground="#FFFFFF"/>
                    </StackPanel>
                </StackPanel>
            </Grid>
            <!-- Resize grip (optional with standard title bar) -->
            <ResizeGrip DockPanel.Dock="Bottom" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,8,0,0"/>
        </DockPanel>
    </Border>
</Window>
"@

# Load XAML
$reader = New-Object System.Xml.XmlNodeReader([xml]$xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Find controls
$BtnRefresh = $window.FindName('BtnRefresh')
$LvNetworks = $window.FindName('LvNetworks')
$Pwd        = $window.FindName('Pwd')
$PwdPlain   = $window.FindName('PwdPlain')
$ChkSave    = $window.FindName('ChkSave')
$BtnShowPwd = $window.FindName('BtnShowPwd')
$BtnConnect = $window.FindName('BtnConnect')

# Standard title bar handles dragging; no custom drag needed

# Password value helper
function Get-PasswordValue {
    if ($PwdPlain.Visibility -eq 'Visible') { return $PwdPlain.Text }
    return $Pwd.Password
}

# Update Connect/Disconnect button label based on selection
function Update-ConnectButton {
    $sel = $LvNetworks.SelectedItem
    if (-not $BtnConnect) { return }
    if (-not $sel) {
        $BtnConnect.Content = 'Connect'
        return
    }
    $BtnConnect.Content = if ($sel.IsConnected) { 'Disconnect' } else { 'Connect' }
}

# Populate list
function Refresh-Networks {
    $connected = Get-WifiConnectionInfo
    $global:NetworksCache = Get-WifiNetworks |
        ForEach-Object {
            $net = $_
            $connInfo = $connected | Where-Object { $_.SSID -eq $net.SSID } | Select-Object -First 1
            $isConn = [bool]$connInfo
            $iface = if ($connInfo) { $connInfo.Interface } else { $null }
            $txt = if ($isConn) { 'Yes' } else { 'No' }
            $net | Add-Member -NotePropertyName Connected -NotePropertyValue $txt -Force
            $net | Add-Member -NotePropertyName IsConnected -NotePropertyValue $isConn -Force
            $net | Add-Member -NotePropertyName InterfaceName -NotePropertyValue $iface -Force
            $net
        } |
        Sort-Object -Property SignalValue -Descending
    $LvNetworks.Items.Clear()
    foreach ($it in $global:NetworksCache) { $LvNetworks.Items.Add($it) | Out-Null }
    Update-GridColumns
    Update-ConnectButton
}

# Dynamic column sizing based on ListView width
function Update-GridColumns {
    $view = $LvNetworks.View
    if ($view -and $view.Columns.Count -ge 8) {
        $total = [double]$LvNetworks.ActualWidth
        if ($total -le 0) { return }
        $padding = 32 # scrollbar + margins
        $avail = $total - $padding
        if ($avail -le 200) { return }
        # Proportional widths for 8 columns
        $ssidW    = [Math]::Max(160, [int]($avail * 0.30))
        $connW   = [Math]::Max(70,  [int]($avail * 0.08))
        $signalW = [Math]::Max(60,  [int]($avail * 0.08))
        $authW   = [Math]::Max(90,  [int]($avail * 0.12))
        $bandsW  = [Math]::Max(70,  [int]($avail * 0.08))
        $radioW  = [Math]::Max(90,  [int]($avail * 0.12))
        $chanW   = [Math]::Max(120, [int]($avail * 0.15))
        $bssidW  = [Math]::Max(60,  [int]($avail * 0.07))
        # Column order: SSID, Connected, Signal, Auth, Bands, Radio, Channels, BSSIDs
        $view.Columns[0].Width = $ssidW
        $view.Columns[1].Width = $connW
        $view.Columns[2].Width = $signalW
        $view.Columns[3].Width = $authW
        $view.Columns[4].Width = $bandsW
        $view.Columns[5].Width = $radioW
        $view.Columns[6].Width = $chanW
        $view.Columns[7].Width = $bssidW
    }
}

$LvNetworks.Add_SizeChanged({ Update-GridColumns })

# Close handled by standard title bar

# Refresh
$BtnRefresh.Add_Click({ Refresh-Networks })
$BtnShowPwd.Add_Click({
    if ($PwdPlain.Visibility -eq 'Visible') {
        $Pwd.Password = $PwdPlain.Text
        $PwdPlain.Visibility = 'Collapsed'
        $Pwd.Visibility = 'Visible'
        $BtnShowPwd.Content = 'Show'
        $Pwd.Focus() | Out-Null
    } else {
        $PwdPlain.Text = $Pwd.Password
        $Pwd.Visibility = 'Collapsed'
        $PwdPlain.Visibility = 'Visible'
        $BtnShowPwd.Content = 'Hide'
        $PwdPlain.Focus() | Out-Null
        $PwdPlain.SelectAll()
    }
})
$LvNetworks.Add_SelectionChanged({ Update-ConnectButton })
# Sorting by column header clicks
$global:SortState = @{ Property = 'SignalValue'; Ascending = $false }
function Apply-Sort {
    param([string] $Property, [bool] $Ascending)
    if (-not $global:NetworksCache) { return }
    $prop = $Property
    if ($prop -eq 'Signal') { $prop = 'SignalValue' }
    $items = $global:NetworksCache
    $sorted = if ($Ascending) { $items | Sort-Object -Property $prop } else { $items | Sort-Object -Property $prop -Descending }
    $LvNetworks.Items.Clear()
    foreach ($it in $sorted) { $LvNetworks.Items.Add($it) | Out-Null }
    Update-GridColumns
}

$LvNetworks.AddHandler([System.Windows.Controls.GridViewColumnHeader]::ClickEvent,
    [System.Windows.RoutedEventHandler]{
        param($sender,$e)
        $hdr = $e.OriginalSource -as [System.Windows.Controls.GridViewColumnHeader]
        if (-not $hdr -or -not $hdr.Column) { return }
        $text = [string]$hdr.Column.Header
        $map = @{ 'SSID'='SSID'; 'Signal'='SignalValue'; 'Auth'='Authentication'; 'Bands'='Bands'; 'Radio'='RadioTypes'; 'Channels'='Channel'; 'BSSIDs'='BSSIDCount' }
        $map['Connected'] = 'IsConnected'
        if (-not $map.ContainsKey($text)) { return }
        $prop = $map[$text]
        $asc = $true
        if ($global:SortState.Property -eq $prop) { $asc = -not $global:SortState.Ascending }
        else { if ($prop -in @('SignalValue','BSSIDCount','IsConnected')) { $asc = $false } }
        $global:SortState.Property = $prop
        $global:SortState.Ascending = $asc
        Apply-Sort -Property $prop -Ascending:$asc
    })
# No separate details pane; selection remains within table only.

# Connect
$BtnConnect.Add_Click({
    $sel = $LvNetworks.SelectedItem
    if (!$sel) { [System.Windows.MessageBox]::Show('Select a network first.') | Out-Null; return }
    $ssid = $sel.SSID
    $auth = $sel.Authentication
    $enc  = $sel.Encryption
    if ($sel.IsConnected) {
        $iface = $sel.InterfaceName
        if (-not $iface) {
            $ci = Get-WifiConnectionInfo | Where-Object { $_.SSID -eq $ssid } | Select-Object -First 1
            if ($ci) { $iface = $ci.Interface }
        }
        if (-not $iface) { $iface = 'Wi-Fi' }
        netsh wlan disconnect interface="$iface" | Out-Null
        [System.Windows.MessageBox]::Show("Disconnecting from $ssid...") | Out-Null
    } else {
        $pwd  = Get-PasswordValue
        if ($auth -notmatch 'Open' -and (!$pwd -or $pwd.Length -lt 8)) {
            [System.Windows.MessageBox]::Show('Enter a valid password (min 8 chars) for secured networks.') | Out-Null
            return
        }
        Connect-Wifi -Ssid $ssid -KeyMaterial $pwd -SaveProfile:$($ChkSave.IsChecked) -Authentication $auth -Encryption $enc
        [System.Windows.MessageBox]::Show("Connecting to $ssid...") | Out-Null
    }
    Start-Sleep -Seconds 1
    Refresh-Networks
})

# Initial load
Refresh-Networks

# Show window
$window.ShowDialog() | Out-Null
