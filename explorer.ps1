Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Windows.Forms

# ================= PRIVILEGE DETECTION =================
function Get-PrivilegeLevel {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        
        # SYSTEM kontrolü
        if ($identity.Name -eq "NT AUTHORITY\SYSTEM") {
            return "SYSTEM"
        }
        
        # Local Service kontrolü
        if ($identity.Name -eq "NT AUTHORITY\LOCAL SERVICE") {
            return "LOCAL SERVICE"
        }
        
        # Network Service kontrolü
        if ($identity.Name -eq "NT AUTHORITY\NETWORK SERVICE") {
            return "NETWORK SERVICE"
        }
        
        # Administrator kontrolü
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Elevation kontrolü
            try {
                $testPath = "$env:windir\System32\test_priv.tmp"
                $null > $testPath 2>$null
                if (Test-Path $testPath) {
                    Remove-Item $testPath -Force -ErrorAction SilentlyContinue
                    return "ADMINISTRATOR (ELEVATED)"
                } else {
                    return "ADMINISTRATOR (NOT ELEVATED)"
                }
            } catch {
                return "ADMINISTRATOR (LIMITED)"
            }
        }
        
        # Local Service, Network Service grupları kontrolü
        $groups = $identity.Groups
        foreach ($group in $groups) {
            $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value
            switch -Wildcard ($groupName) {
                "*S-1-5-19*" { return "LOCAL SERVICE" }
                "*S-1-5-20*" { return "NETWORK SERVICE" }
            }
        }
        
        # User Groups kontrolü
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::User)) {
            # Power Users
            if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::PowerUser)) {
                return "POWER USER"
            }
            # Backup Operators
            if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::BackupOperator)) {
                return "BACKUP OPERATOR"
            }
            return "STANDARD USER"
        }
        
        # Guest kontrolü
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Guest)) {
            return "GUEST"
        }
        
        return "UNKNOWN"
        
    } catch {
        return "ERROR DETECTING"
    }
}

$PrivilegeText = Get-PrivilegeLevel

# ================= ANTIVIRUS CHECK =================
function Get-AntivirusStatus {
    param($Path)
    
    try {
        # Windows Defender kontrolü
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            if ($defenderStatus.AntivirusEnabled) {
                # Dosyayı Windows Defender ile kontrol et
                $result = Start-Process "powershell" -ArgumentList "Get-MpThreatDetection" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
                if ($result.ExitCode -eq 0) {
                    # Dosyayı taramak için MpCmdRun kullan
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    Copy-Item $Path $tempFile -Force -ErrorAction SilentlyContinue
                    
                    $scanResult = & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File $tempFile -DisableRemediation 2>$null
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    
                    if ($LASTEXITCODE -eq 0) {
                        return "✅ Windows Defender: Clean"
                    } elseif ($LASTEXITCODE -eq 2) {
                        return "⚠️ Windows Defender: Threat Detected!"
                    }
                }
                return "✅ Windows Defender: Enabled"
            } else {
                return "❌ Windows Defender: Disabled"
            }
        }
        
        # Diğer antivirüsleri kontrol et
        $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($avProducts) {
            $activeAV = $avProducts | Where-Object { $_.productState -eq 266240 -or $_.productState -eq 397568 }
            if ($activeAV) {
                $avName = $activeAV.displayName
                return "✅ $($avName): Active"
            }
        }
        
        return "❌ No active antivirus detected"
        
    } catch {
        return "⚠️ Antivirus check failed"
    }
}

# ================= CODE VIEWER =================
function Show-CodeViewer {
    param($Path)
    
    $codeXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Code Viewer" 
        Width="800" 
        Height="600"
        WindowStartupLocation="CenterScreen"
        Background="#1e1e1e">
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="40"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        
        <!-- HEADER -->
        <Border Grid.Row="0" Background="#252526" BorderBrush="#444" BorderThickness="0,0,0,1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="40"/>
                </Grid.ColumnDefinitions>
                
                <TextBlock Grid.Column="0" Text="Code Viewer" 
                         Foreground="White" FontSize="16" FontWeight="Bold"
                         VerticalAlignment="Center" Margin="10,0"/>
                
                <Button Grid.Column="1" Name="CloseBtn" Content="X" 
                       Width="30" Height="30" Margin="5"
                       Background="Transparent" Foreground="White"
                       BorderThickness="0" FontSize="14"/>
            </Grid>
</Window>
'@
    
    try {
        $codeWindow = [Windows.Markup.XamlReader]::Load(
            (New-Object System.Xml.XmlNodeReader ([xml]$codeXaml))
        )
        
        $closeBtn = $codeWindow.FindName("CloseBtn")
        $fileNameLabel = $codeWindow.FindName("FileNameLabel")
        $fileSizeLabel = $codeWindow.FindName("FileSizeLabel")
        $lineCountLabel = $codeWindow.FindName("LineCountLabel")
        $codeTextBox = $codeWindow.FindName("CodeTextBox")
        
        # Dosya bilgileri
        $fileInfo = Get-Item $Path -ErrorAction Stop
        $fileNameLabel.Text = "File: $($fileInfo.Name)"
        $fileSizeLabel.Text = "Size: $(Format-Size $fileInfo.Length)"
        
        # Dosya içeriğini oku
        try {
            $content = Get-Content $Path -Raw -Encoding UTF8 -ErrorAction Stop
            $lineCount = ($content -split "`n").Count
            $lineCountLabel.Text = "Lines: $lineCount"
            
            # Syntax highlighting için temel renklendirme
            $codeTextBox.Text = $content
            
            # Dosya uzantısına göre syntax highlighting
            $ext = [System.IO.Path]::GetExtension($Path).ToLower()
            switch ($ext) {
                '.ps1' { $codeTextBox.Foreground = "#569CD6" }
                '.cs' { $codeTextBox.Foreground = "#569CD6" }
                '.js' { $codeTextBox.Foreground = "#DCDCAA" }
                '.html' { $codeTextBox.Foreground = "#CE9178" }
                '.css' { $codeTextBox.Foreground = "#9CDCFE" }
                '.xml' { $codeTextBox.Foreground = "#CE9178" }
                '.json' { $codeTextBox.Foreground = "#DCDCAA" }
                '.py' { $codeTextBox.Foreground = "#569CD6" }
                '.java' { $codeTextBox.Foreground = "#569CD6" }
                '.cpp' { $codeTextBox.Foreground = "#569CD6" }
                '.c' { $codeTextBox.Foreground = "#569CD6" }
                '.h' { $codeTextBox.Foreground = "#569CD6" }
                '.php' { $codeTextBox.Foreground = "#569CD6" }
                '.sql' { $codeTextBox.Foreground = "#569CD6" }
                '.bat' { $codeTextBox.Foreground = "#DCDCAA" }
                '.cmd' { $codeTextBox.Foreground = "#DCDCAA" }
                '.vbs' { $codeTextBox.Foreground = "#DCDCAA" }
                '.ini' { $codeTextBox.Foreground = "#CE9178" }
                '.config' { $codeTextBox.Foreground = "#CE9178" }
                '.txt' { $codeTextBox.Foreground = "White" }
                '.log' { $codeTextBox.Foreground = "White" }
                default { $codeTextBox.Foreground = "White" }
            }
            
        } catch {
            $codeTextBox.Text = "Cannot read file content. File may be binary or access denied.`n`nError: $_"
            $codeTextBox.Foreground = "#CE9178"
        }
        
        $closeBtn.Add_Click({
            $codeWindow.Close()
        })
        
        $codeWindow.ShowDialog() | Out-Null
        
    } catch {
        [System.Windows.MessageBox]::Show(
            "Error opening code viewer: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

# ================= FOLDER INFORMATION =================
function Show-FolderInformation {
    param($Path)
    
    $folderXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Folder Information" 
        Width="600" 
        Height="700"
        WindowStartupLocation="CenterScreen"
        Background="#1e1e1e">
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="40"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        
        <!-- HEADER -->
        <Border Grid.Row="0" Background="#252526" BorderBrush="#444" BorderThickness="0,0,0,1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="40"/>
                </Grid.ColumnDefinitions>
                
                <StackPanel Grid.Column="0" Orientation="Horizontal" Margin="10,0">
                    <TextBlock Text="📁" FontSize="20" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <TextBlock Text="Folder Information" 
                             Foreground="White" FontSize="16" FontWeight="Bold"
                             VerticalAlignment="Center"/>
                </StackPanel>
                
                <Button Grid.Column="1" Name="CloseBtn" Content="X" 
                       Width="30" Height="30" Margin="5"
                       Background="Transparent" Foreground="White"
                       BorderThickness="0" FontSize="14"/>
            </Grid>
        </Border>
        
        <!-- CONTENT -->
        <ScrollViewer Grid.Row="1" Margin="10">
            <StackPanel>
                <!-- FOLDER BASIC INFO -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="📊 BASIC INFORMATION" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="120"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Folder Name:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" Name="FolderName" Foreground="White"/>
                            
                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Full Path:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="1" Grid.Column="1" Name="FolderPath" Foreground="White" TextWrapping="Wrap"/>
                            
                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Created:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="2" Grid.Column="1" Name="FolderCreated" Foreground="White"/>
                            
                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Modified:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="3" Grid.Column="1" Name="FolderModified" Foreground="White"/>
                            
                            <TextBlock Grid.Row="4" Grid.Column="0" Text="Last Accessed:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="4" Grid.Column="1" Name="FolderAccessed" Foreground="White"/>
                        </Grid>
                    </StackPanel>
                </Border>
                
                <!-- FOLDER STATISTICS -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="📈 FOLDER STATISTICS" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="120"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Total Files:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" Name="TotalFiles" Foreground="White"/>
                            
                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Total Folders:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="1" Grid.Column="1" Name="TotalFolders" Foreground="White"/>
                            
                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Total Size:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="2" Grid.Column="1" Name="TotalSize" Foreground="White"/>
                            
                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Hidden Files:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="3" Grid.Column="1" Name="HiddenFiles" Foreground="White"/>
                            
                            <TextBlock Grid.Row="4" Grid.Column="0" Text="System Files:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="4" Grid.Column="1" Name="SystemFiles" Foreground="White"/>
                        </Grid>
                    </StackPanel>
                </Border>
                
                <!-- FILE TYPE DISTRIBUTION -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="📁 FILE TYPE DISTRIBUTION" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        <TextBlock Name="FileTypes" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>
                
                <!-- PERMISSIONS -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="🔒 PERMISSIONS" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="120"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Owner:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" Name="FolderOwner" Foreground="White"/>
                            
                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Permissions:" Foreground="#AAAAAA"/>
                            <ScrollViewer Grid.Row="1" Grid.Column="1" MaxHeight="80">
                                <TextBlock Name="FolderPermissions" Foreground="White" TextWrapping="Wrap"/>
                            </ScrollViewer>
                        </Grid>
                    </StackPanel>
                </Border>
                
                <!-- ANTIVIRUS CHECK -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="🛡️ ANTIVIRUS STATUS" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        <TextBlock Name="AntivirusStatus" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>
                
                <!-- FOLDER ATTRIBUTES -->
                <Border Background="#252526" CornerRadius="5" Padding="10">
                    <StackPanel>
                        <TextBlock Text="📝 FOLDER ATTRIBUTES" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        <TextBlock Name="FolderAttributes" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>
                
            </StackPanel>
        </ScrollViewer>
    </Grid>
</Window>
'@
    
    try {
        $folderWindow = [Windows.Markup.XamlReader]::Load(
            (New-Object System.Xml.XmlNodeReader ([xml]$folderXaml))
        )
        
        $closeBtn = $folderWindow.FindName("CloseBtn")
        $folderName = $folderWindow.FindName("FolderName")
        $folderPath = $folderWindow.FindName("FolderPath")
        $folderCreated = $folderWindow.FindName("FolderCreated")
        $folderModified = $folderWindow.FindName("FolderModified")
        $folderAccessed = $folderWindow.FindName("FolderAccessed")
        $totalFiles = $folderWindow.FindName("TotalFiles")
        $totalFolders = $folderWindow.FindName("TotalFolders")
        $totalSize = $folderWindow.FindName("TotalSize")
        $hiddenFiles = $folderWindow.FindName("HiddenFiles")
        $systemFiles = $folderWindow.FindName("SystemFiles")
        $fileTypes = $folderWindow.FindName("FileTypes")
        $folderOwner = $folderWindow.FindName("FolderOwner")
        $folderPermissions = $folderWindow.FindName("FolderPermissions")
        $antivirusStatus = $folderWindow.FindName("AntivirusStatus")
        $folderAttributes = $folderWindow.FindName("FolderAttributes")
        
        try {
            $folderInfo = Get-Item $Path -Force -ErrorAction Stop
            
            # Temel bilgiler
            $folderName.Text = $folderInfo.Name
            $folderPath.Text = $folderInfo.FullName
            $folderCreated.Text = $folderInfo.CreationTime.ToString("dd.MM.yyyy HH:mm:ss")
            $folderModified.Text = $folderInfo.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss")
            $folderAccessed.Text = $folderInfo.LastAccessTime.ToString("dd.MM.yyyy HH:mm:ss")
            
            # Klasör istatistikleri
            try {
                $allItems = Get-ChildItem $Path -Recurse -Force -ErrorAction Stop
                $files = $allItems | Where-Object { -not $_.PSIsContainer }
                $folders = $allItems | Where-Object { $_.PSIsContainer }
                
                $totalFiles.Text = $files.Count
                $totalFolders.Text = $folders.Count
                
                $totalSizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
                $totalSize.Text = Format-Size $totalSizeBytes
                
                $hiddenFiles.Text = ($files | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::Hidden }).Count
                $systemFiles.Text = ($files | Where-Object { $_.Attributes -band [System.IO.FileAttributes]::System }).Count
                
                # Dosya tipi dağılımı
                $fileTypeGroups = $files | Group-Object -Property Extension | 
                    Sort-Object -Property Count -Descending | 
                    Select-Object -First 10
                
                $typeText = @()
                foreach ($group in $fileTypeGroups) {
                    $ext = if ($group.Name) { $group.Name } else { "No Extension" }
                    $percent = [math]::Round(($group.Count / $files.Count) * 100, 2)
                    $typeText += "$ext : $($group.Count) files ($percent%)"
                }
                $fileTypes.Text = if ($typeText.Count -gt 0) { $typeText -join "`n" } else { "No files found" }
                
            } catch {
                $totalFiles.Text = "Access Denied"
                $totalFolders.Text = "Access Denied"
                $totalSize.Text = "Access Denied"
                $hiddenFiles.Text = "Access Denied"
                $systemFiles.Text = "Access Denied"
                $fileTypes.Text = "Access Denied"
            }
            
            # İzinler
            try {
                $acl = Get-Acl $Path -ErrorAction Stop
                $folderOwner.Text = $acl.Owner
                
                $permText = @()
                foreach ($rule in $acl.Access) {
                    $permText += "$($rule.IdentityReference) - $($rule.FileSystemRights)"
                    if ($permText.Count -ge 5) { break }
                }
                $folderPermissions.Text = if ($permText.Count -gt 0) { $permText -join "`n" } else { "No permissions found" }
            } catch {
                $folderOwner.Text = "Access Denied"
                $folderPermissions.Text = "Access Denied"
            }
            
            # Antivirüs durumu
            $antivirusStatus.Text = Get-AntivirusStatus $Path
            
            # Klasör özellikleri
            $attr = $folderInfo.Attributes
            $attrList = @()
            
            if ($attr -band [System.IO.FileAttributes]::ReadOnly) { $attrList += "ReadOnly" }
            if ($attr -band [System.IO.FileAttributes]::Hidden) { $attrList += "Hidden" }
            if ($attr -band [System.IO.FileAttributes]::System) { $attrList += "System" }
            if ($attr -band [System.IO.FileAttributes]::Archive) { $attrList += "Archive" }
            if ($attr -band [System.IO.FileAttributes]::Device) { $attrList += "Device" }
            if ($attr -band [System.IO.FileAttributes]::Normal) { $attrList += "Normal" }
            if ($attr -band [System.IO.FileAttributes]::Temporary) { $attrList += "Temporary" }
            if ($attr -band [System.IO.FileAttributes]::SparseFile) { $attrList += "SparseFile" }
            if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { $attrList += "ReparsePoint" }
            if ($attr -band [System.IO.FileAttributes]::Compressed) { $attrList += "Compressed" }
            if ($attr -band [System.IO.FileAttributes]::Offline) { $attrList += "Offline" }
            if ($attr -band [System.IO.FileAttributes]::NotContentIndexed) { $attrList += "NotContentIndexed" }
            if ($attr -band [System.IO.FileAttributes]::Encrypted) { $attrList += "Encrypted" }
            if ($attr -band [System.IO.FileAttributes]::IntegrityStream) { $attrList += "IntegrityStream" }
            if ($attr -band [System.IO.FileAttributes]::NoScrubData) { $attrList += "NoScrubData" }
            
            if ($folderInfo.LinkType) { $attrList += "LinkType: $($folderInfo.LinkType)" }
            
            $folderAttributes.Text = if ($attrList.Count -gt 0) { $attrList -join ", " } else { "No special attributes" }
            
        } catch {
            [System.Windows.MessageBox]::Show(
                "Cannot access folder: $_",
                "Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )
            $folderWindow.Close()
            return
        }
        
        $closeBtn.Add_Click({
            $folderWindow.Close()
        })
        
        $folderWindow.ShowDialog() | Out-Null
        
    } catch {
        [System.Windows.MessageBox]::Show(
            "Error showing folder information: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

# ================= DISK MEMORY CHECK =================
function Is-DiskMemory {
    param($Item)
    if (-not $Item.PSIsContainer) { return $false }
    
    $pathLower = $Item.FullName.ToLower()
    
    # System Volume Information klasörü
    if ($Item.Name -eq "System Volume Information") {
        return $true
    }
    
    # System32\config klasörü ve altındaki dosyalar
    if ($pathLower -like "*\system32\config\*") {
        return $true
    }
    
    # Pagefile ve hiberfile dosyaları
    if ($Item.Name -in @("pagefile.sys", "hiberfil.sys", "swapfile.sys")) {
        return $true
    }
    
    # Registry backup dosyaları
    if ($Item.Extension.ToLower() -in @(".regtrans-ms", ".blf", ".log", ".sav")) {
        if ($pathLower -like "*\system32\config\*") {
            return $true
        }
    }
    
    # Windows memory dump dosyaları
    if ($Item.Name -like "MEMORY.DMP" -or $Item.Name -like "*.dmp") {
        if ($pathLower -like "*\windows\*") {
            return $true
        }
    }
    
    return $false
}

# ================= FILE OWNERSHIP =================
function Get-FileOwner {
    param($Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        return $acl.Owner
    } catch {
        return "Access Denied"
    }
}

# ================= FILE SECURITY INFO =================
function Get-FileSecurityInfo {
    param($Path)
    try {
        $info = @{}
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        
        $info.Owner = $acl.Owner
        $info.AccessRules = @()
        
        foreach ($rule in $acl.Access) {
            $info.AccessRules += "$($rule.IdentityReference) - $($rule.FileSystemRights)"
        }
        
        return $info
    } catch {
        return @{ Owner = "Access Denied"; AccessRules = @() }
    }
}

# ================= GET FILE COLOR =================
function Get-FileColor {
    param($Item)
    
    $attr = $Item.Attributes
    $isHidden     = $attr -band [IO.FileAttributes]::Hidden
    $isSystem     = $attr -band [IO.FileAttributes]::System
    $isJunction   = $Item.LinkType -eq "Junction"
    $isSymlink    = $Item.LinkType -eq "SymbolicLink"
    $hasAccess    = Has-Access $Item
    $hasADS       = Has-ADS $Item $hasAccess
    $isKernel     = $Item.PSIsContainer -and (Is-KernelFolder $Item.FullName)
    $isEncrypted  = Is-Encrypted $Item
    $isReadOnly   = Is-ReadOnly $Item
    $isCompressed = Is-Compressed $Item
    $isArchive    = Is-Archive $Item
    $isTemporary  = Is-Temporary $Item
    $isOffline    = Is-Offline $Item
    $isSparse     = Is-Sparse $Item
    $isDevice     = Is-Device $Item
    $isIntegrity  = Is-IntegrityStream $Item
    $isNoScrub    = Is-NoScrub $Item
    $isDiskMemory = Is-DiskMemory $Item  # Yeni: Disk Memory kontrolü
    $isVideo      = Is-VideoFile $Item
    $isAudio      = Is-AudioFile $Item
    $isDocument   = Is-DocumentFile $Item
    $isDatabase   = Is-DatabaseFile $Item
    $isVM         = Is-VMFile $Item
    $isContainer  = Is-ContainerFile $Item
    $isDev        = Is-DevelopmentFile $Item
    $isImage      = Is-ImageFile $Item

    # Priority order
    if ($hasADS) { return "Black" }
    elseif ($isDiskMemory) { return "#00008B" } # Dark Blue - Disk Memory
    elseif ($isDevice) { return "#4B0082" } # Indigo
    elseif ($isIntegrity) { return "#8A2BE2" } # Blue Violet
    elseif ($isNoScrub) { return "#483D8B" } # Dark Slate Blue
    elseif ($isKernel) { return "DarkGoldenrod" }
    elseif ($isHidden -and $isSystem -and $isJunction -and -not $hasAccess) { return "#8B0000" } # Dark Red
    elseif (-not $hasAccess) { return "#800080" } # Purple
    elseif ($isJunction) { return "Red" }
    elseif ($isSymlink) { return "#FF69B4" } # Hot Pink
    elseif ($isEncrypted) { return "Cyan" }
    elseif ($isSparse) { return "#696969" } # Dim Gray
    elseif ($Item.Extension.ToLower() -in ".exe",".dll",".sys",".ocx",".drv") { return "#2E8B57" } # Sea Green
    elseif ($Item.Extension.ToLower() -in ".ps1",".bat",".cmd",".vbs",".js",".ts") { return "#4682B4" } # Steel Blue
    elseif ($Item.Extension.ToLower() -in ".ini",".cfg",".conf",".config") { return "#FF8C00" } # Dark Orange
    elseif ($Item.Extension.ToLower() -in ".log",".txt",".text") { return "#DC143C" } # Crimson
    elseif ($isVideo) { return "#FF1493" } # Deep Pink
    elseif ($isAudio) { return "#32CD32" } # Lime Green
    elseif ($isDocument) { return "#1E90FF" } # Dodger Blue
    elseif ($isDatabase) { return "#8B4513" } # Saddle Brown
    elseif ($isVM) { return "#9400D3" } # Dark Violet
    elseif ($isContainer) { return "#00FA9A" } # Medium Spring Green
    elseif ($isDev) { return "#FF4500" } # Orange Red
    elseif ($isImage) { return "#FFD700" } # Gold
    elseif ($Item.Extension.ToLower() -in ".zip",".rar",".7z",".tar",".gz",".bz2") { return "LightBlue" }
    elseif ($isHidden -and $isSystem) { return "#00CED1" } # Deep Sky Blue
    elseif ($isCompressed) { return "#8FBC8F" } # Dark Sea Green
    elseif ($isArchive) { return "#DDA0DD" } # Plum
    elseif ($isTemporary) { return "#F0E68C" } # Khaki
    elseif ($isOffline) { return "#A9A9A9" } # Dark Gray
    elseif ($isHidden) { return "Lime" }
    elseif ($isSystem) { return "Goldenrod" }
    elseif ($isReadOnly) { return "Gray" }
    else { return "White" }
}

# ================= GET COLOR MEANING =================
function Get-ColorMeaning {
    param($Color)
    
    $colorMap = @{
        "Black" = "ADS (Alternate Data Stream)"
        "#00008B" = "Disk Memory (System Volume/Config)"  # Güncellendi
        "#8B0000" = "Hidden+System+Junction+No Access"
        "#4B0082" = "Device File"
        "#8A2BE2" = "Integrity Stream"
        "#483D8B" = "No Scrub Data"
        "Red" = "Junction / Reparse Point"
        "#800080" = "Access Denied"
        "#00CED1" = "Hidden + System"
        "Lime" = "Hidden"
        "Goldenrod" = "System"
        "DarkGoldenrod" = "Kernel / Core Windows"
        "LightBlue" = "Archive Files (ZIP/RAR/etc)"
        "Cyan" = "Encrypted"
        "#FF69B4" = "Symbolic Link"
        "#696969" = "Sparse File"
        "Gray" = "ReadOnly"
        "#8FBC8F" = "Compressed (NTFS)"
        "#DDA0DD" = "Archive Flag"
        "#F0E68C" = "Temporary File"
        "#A9A9A9" = "Offline"
        "#2E8B57" = "Executable (EXE/DLL)"
        "#FF8C00" = "Configuration (INI/CFG)"
        "#4682B4" = "Script (PS1/BAT/CMD)"
        "#DC143C" = "Log Files (LOG/TXT)"
        "#FFD700" = "Image Files (JPG/PNG)"
        "#FF1493" = "Video Files (MP4/AVI)"
        "#32CD32" = "Audio Files (MP3/WAV)"
        "#1E90FF" = "Document Files (PDF/DOC)"
        "#8B4513" = "Database Files (DB/SQL)"
        "#9400D3" = "VM Files (VHD/VMDK)"
        "#00FA9A" = "Container Files (Docker/K8s)"
        "#FF4500" = "Dev Files (Code/Projects)"
        "White" = "Normal / Standard"
    }
    
    return $colorMap[$Color]
}

# ================= ADS DETECTION - FIXED =================
function Has-ADS {
    param($Item,$HasAccess)
    
    if (-not $HasAccess) { return $false }
    if ($Item.PSIsContainer) { return $false }
    
    try {
        # Sadece NTFS dosya sisteminde ADS olabilir
        $drive = $Item.FullName.Substring(0, 3)
        $driveInfo = Get-PSDrive -Name $drive -ErrorAction SilentlyContinue
        if (-not $driveInfo -or $driveInfo.Provider.Name -ne "FileSystem") {
            return $false
        }
        
        # Bazı sistem dosyalarını atla (performans için)
        $skipFiles = @(
            "pagefile.sys", "hiberfil.sys", "swapfile.sys",
            "$RECYCLE.BIN", "System Volume Information"
        )
        
        if ($skipFiles -contains $Item.Name) {
            return $false
        }
        
        # Get-Item ile stream kontrolü
        $streams = Get-Item -LiteralPath $Item.FullName -Stream * -ErrorAction Stop
        
        $nonDataStreams = @()
        foreach ($stream in $streams) {
            if ($stream.Stream -ne '::$DATA' -and $stream.Stream -ne '') {
                $nonDataStreams += $stream.Stream
            }
        }
        
        # Gerçek ADS kontrolü
        if ($nonDataStreams.Count -gt 0) {
            # Bazı sistem stream'lerini filtrele
            $systemStreams = @('Zone.Identifier', 'encryptable')
            $filteredStreams = $nonDataStreams | Where-Object { 
                $_ -notin $systemStreams -and 
                -not $_.StartsWith('{') -and # GUID stream'leri
                -not $_.EndsWith(':Bitmap') -and
                -not $_.EndsWith(':SummaryInformation') -and
                -not $_.EndsWith(':DocumentSummaryInformation')
            }
            
            return ($filteredStreams.Count -gt 0)
        }
        
        return $false
        
    } catch [System.Management.Automation.ItemNotFoundException] {
        # Dosya bulunamadı
        return $false
    } catch [System.UnauthorizedAccessException] {
        # Erişim engellendi
        return $false
    } catch {
        # Diğer hatalar
        return $false
    }
}

# ================= ICON =================
function Get-Icon {
    param($Path)
    try {
        if (Test-Path $Path -PathType Container) {
            # Klasör ikonu için default ikon
            return $null
        }
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
        if (-not $icon) { return $null }
        $bmp = $icon.ToBitmap()
        $ms = New-Object IO.MemoryStream
        $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
        $ms.Position = 0
        $img = New-Object Windows.Media.Imaging.BitmapImage
        $img.BeginInit()
        $img.StreamSource = $ms
        $img.CacheOption = "OnLoad"
        $img.EndInit()
        return $img
    } catch { 
        return $null 
    }
}

# ================= ACCESS =================
function Has-Access {
    param($Item)
    try {
        if ($Item.PSIsContainer) {
            # Klasör için sadece varlığını kontrol et
            $null = Get-ChildItem -LiteralPath $Item.FullName -ErrorAction Stop | Select-Object -First 1
            return $true
        } else {
            # Dosya için okuma izni kontrolü
            $fs = [System.IO.File]::Open(
                $Item.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            $fs.Close()
            return $true
        }
    } catch {
        return $false
    }
}

# ================= KERNEL FOLDER =================
function Is-KernelFolder($path) {
    $p = $path.ToLower()
    return (
        $p -like "*\windows\winsxs*" -or
        $p -like "*\windows\servicing*" -or
        $p -like "*\windows\inf*" -or
        $p -like "*\windows\boot*" -or
        $p -like "*\windows\systemresources*" -or
        $p -like "*\windows\system32\config*" -or
        $p -like "*\windows\system32\drivers*" -or
        $p -like "*\windows\csc*" -or
        $p -like "*\windows\assembly*" -or
        $p -like "*\windows\apppatch*" -or
        $p -like "*\windows\catroot*" -or
        $p -like "*\windows\fonts*" -or
        $p -like "*\windows\registration*"
    )
}

# ================= ENCRYPTED =================
function Is-Encrypted {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Encrypted) -ne 0
    } catch { return $false }
}

# ================= SYMLINK =================
function Is-Symlink {
    param($Item)
    try {
        return $Item.LinkType -eq "SymbolicLink"
    } catch { return $false }
}

# ================= READONLY =================
function Is-ReadOnly {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::ReadOnly) -ne 0
    } catch { return $false }
}

# ================= COMPRESSED =================
function Is-Compressed {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Compressed) -ne 0
    } catch { return $false }
}

# ================= ARCHIVE =================
function Is-Archive {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Archive) -ne 0
    } catch { return $false }
}

# ================= TEMPORARY =================
function Is-Temporary {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Temporary) -ne 0
    } catch { return $false }
}

# ================= OFFLINE =================
function Is-Offline {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Offline) -ne 0
    } catch { return $false }
}

# ================= SPARSE =================
function Is-Sparse {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::SparseFile) -ne 0
    } catch { return $false }
}

# ================= DEVICE =================
function Is-Device {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::Device) -ne 0
    } catch { return $false }
}

# ================= INTEGRITY =================
function Is-IntegrityStream {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::IntegrityStream) -ne 0
    } catch { return $false }
}

# ================= NO SCRUB =================
function Is-NoScrub {
    param($Item)
    try {
        $attr = $Item.Attributes
        return ($attr -band [System.IO.FileAttributes]::NoScrubData) -ne 0
    } catch { return $false }
}

# ================= VIDEO FILES =================
function Is-VideoFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $videoExtensions = @('.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg')
    return $videoExtensions -contains $ext
}

# ================= AUDIO FILES =================
function Is-AudioFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $audioExtensions = @('.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a')
    return $audioExtensions -contains $ext
}

# ================= DOCUMENT FILES =================
function Is-DocumentFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $docExtensions = @('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf')
    return $docExtensions -contains $ext
}

# ================= DATABASE FILES =================
function Is-DatabaseFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $dbExtensions = @('.db', '.sqlite', '.mdb', '.accdb', '.sql', '.dbf')
    return $dbExtensions -contains $ext
}

# ================= VIRTUAL MACHINE FILES =================
function Is-VMFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $vmExtensions = @('.vhd', '.vhdx', '.vmdk', '.ova', '.ovf', '.vmx')
    return $vmExtensions -contains $ext
}

# ================= CONTAINER FILES =================
function Is-ContainerFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $containerExtensions = @('.dockerfile', '.yaml', '.yml', '.json', '.toml')
    return $containerExtensions -contains $ext
}

# ================= DEVELOPMENT FILES =================
function Is-DevelopmentFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $devExtensions = @('.cs', '.java', '.py', '.js', '.ts', '.cpp', '.c', '.h', '.php', '.html', '.css', '.xml')
    return $devExtensions -contains $ext
}

# ================= IMAGE FILES =================
function Is-ImageFile {
    param($Item)
    if ($Item.PSIsContainer) { return $false }
    $ext = [System.IO.Path]::GetExtension($Item.FullName).ToLower()
    $imageExtensions = @('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.ico', '.webp', '.svg', '.heic', '.raw', '.psd')
    return $imageExtensions -contains $ext
}

# ================= FILE DETAILS WINDOW =================
function Show-FileDetailsWindow {
    param($Item)
    
    $detailsXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="File Details" 
        Width="500" 
        Height="600"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        Background="#1e1e1e">
    
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="40"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        
        <!-- HEADER -->
        <Border Grid.Row="0" Background="#252526" BorderBrush="#444" BorderThickness="0,0,0,1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="40"/>
                </Grid.ColumnDefinitions>
                
                <TextBlock Grid.Column="0" Text="File Details" 
                         Foreground="White" FontSize="16" FontWeight="Bold"
                         VerticalAlignment="Center" Margin="10,0"/>
                
                <Button Grid.Column="1" Name="CloseBtn" Content="X" 
                       Width="30" Height="30" Margin="5"
                       Background="Transparent" Foreground="White"
                       BorderThickness="0" FontSize="14"/>
            </Grid>
        </Border>
        
        <!-- CONTENT -->
        <ScrollViewer Grid.Row="1" Margin="10">
            <StackPanel>
                <!-- FILE ICON AND NAME -->
                <StackPanel Orientation="Horizontal" Margin="0,0,0,15">
                    <Image Name="FileIcon" Width="32" Height="32" Margin="0,0,10,0"/>
                    <TextBlock Name="FileName" Foreground="White" FontSize="14" FontWeight="Bold"
                             VerticalAlignment="Center"/>
                </StackPanel>
                
                <!-- COLOR INFO -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="COLOR INFORMATION" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,3">
                            <Border Name="ColorBox" Width="20" Height="20" Margin="0,0,5,0" 
                                  BorderBrush="#666" BorderThickness="1"/>
                            <TextBlock Name="ColorMeaning" Foreground="White"/>
                        </StackPanel>
                    </StackPanel>
                </Border>
                
                <!-- BASIC INFO -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <TextBlock Text="BASIC INFORMATION" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="120"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="25"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Full Path:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" Name="FullPath" Foreground="White" TextWrapping="Wrap"/>
                            
                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Type:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="1" Grid.Column="1" Name="FileType" Foreground="White"/>
                            
                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Size:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="2" Grid.Column="1" Name="FileSize" Foreground="White"/>
                            
                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Created:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="3" Grid.Column="1" Name="FileCreated" Foreground="White"/>
                            
                            <TextBlock Grid.Row="4" Grid.Column="0" Text="Modified:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="4" Grid.Column="1" Name="FileModified" Foreground="White"/>
                        </Grid>
                    </StackPanel>
                </Border>
                
                <!-- OWNERSHIP & SECURITY -->
                <Border Background="#252526" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                    <StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                            <TextBlock Text="OWNERSHIP &amp; SECURITY" Foreground="#FFD700" FontWeight="Bold"/>
                            <TextBlock Text="👤" FontSize="16" Margin="5,0,0,0"/>
                        </StackPanel>
                        
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="120"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="25"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Owner:" Foreground="#AAAAAA"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" Name="FileOwner" Foreground="White"/>
                            
                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Permissions:" Foreground="#AAAAAA"/>
                            <ScrollViewer Grid.Row="1" Grid.Column="1" MaxHeight="80">
                                <TextBlock Name="FilePermissions" Foreground="White" TextWrapping="Wrap"/>
                            </ScrollViewer>
                        </Grid>
                    </StackPanel>
                </Border>
                
                <!-- ATTRIBUTES -->
                <Border Background="#252526" CornerRadius="5" Padding="10">
                    <StackPanel>
                        <TextBlock Text="ATTRIBUTES" Foreground="#FFD700" FontWeight="Bold" Margin="0,0,0,5"/>
                        <TextBlock Name="FileAttributes" Foreground="White" TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>
                
            </StackPanel>
        </ScrollViewer>
    </Grid>
</Window>
'@
    
    try {
        $detailsWindow = [Windows.Markup.XamlReader]::Load(
            (New-Object System.Xml.XmlNodeReader ([xml]$detailsXaml))
        )
        
        # Get controls
        $closeBtn = $detailsWindow.FindName("CloseBtn")
        $fileIcon = $detailsWindow.FindName("FileIcon")
        $fileName = $detailsWindow.FindName("FileName")
        $colorBox = $detailsWindow.FindName("ColorBox")
        $colorMeaning = $detailsWindow.FindName("ColorMeaning")
        $fullPath = $detailsWindow.FindName("FullPath")
        $fileType = $detailsWindow.FindName("FileType")
        $fileSize = $detailsWindow.FindName("FileSize")
        $fileCreated = $detailsWindow.FindName("FileCreated")
        $fileModified = $detailsWindow.FindName("FileModified")
        $fileOwner = $detailsWindow.FindName("FileOwner")
        $filePermissions = $detailsWindow.FindName("FilePermissions")
        $fileAttributes = $detailsWindow.FindName("FileAttributes")
        
        try {
            # Dosyayı tekrar al (önceki referans geçersiz olabilir)
            $fileInfo = Get-Item -LiteralPath $Item.FullName -Force -ErrorAction Stop
        } catch {
            # Erişim engelli dosya için orijinal item'i kullan
            $fileInfo = $Item
        }
        
        # File icon
        if (-not $Item.PSIsContainer) {
            $icon = Get-Icon $Item.FullName
            if ($icon) {
                $fileIcon.Source = $icon
            }
        } else {
            # Klasör için varsayılan ikon
            $fileIcon.Source = $null
        }
        
        # File name
        $fileName.Text = $Item.Name
        
        # Color information
        $color = Get-FileColor $Item
        $colorBox.Background = $color
        $colorMeaning.Text = Get-ColorMeaning $color
        
        # Basic info
        $fullPath.Text = $Item.FullName
        $fileType.Text = if ($Item.PSIsContainer) { "Folder" } else { "File" }
        
        if (-not $Item.PSIsContainer) {
            try {
                $fileSize.Text = Format-Size $Item.Length
            } catch {
                $fileSize.Text = "Access Denied"
            }
        } else {
            $fileSize.Text = "N/A"
        }
        
        try {
            $fileCreated.Text = $Item.CreationTime.ToString("dd.MM.yyyy HH:mm:ss")
            $fileModified.Text = $Item.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss")
        } catch {
            $fileCreated.Text = "Access Denied"
            $fileModified.Text = "Access Denied"
        }
        
        # Ownership and security
        try {
            $securityInfo = Get-FileSecurityInfo $Item.FullName
            $fileOwner.Text = $securityInfo.Owner
            
            $permissionsText = ""
            if ($securityInfo.AccessRules.Count -gt 0) {
                $permissionsText = $securityInfo.AccessRules[0]
                for ($i = 1; $i -lt [Math]::Min(3, $securityInfo.AccessRules.Count); $i++) {
                    $permissionsText += "`n" + $securityInfo.AccessRules[$i]
                }
                if ($securityInfo.AccessRules.Count -gt 3) {
                    $permissionsText += "`n... and " + ($securityInfo.AccessRules.Count - 3) + " more"
                }
            } else {
                $permissionsText = "No permissions information available"
            }
            $filePermissions.Text = $permissionsText
        } catch {
            $fileOwner.Text = "Access Denied"
            $filePermissions.Text = "Access Denied"
        }
        
        # Attributes
        try {
            $attr = $Item.Attributes
            $attrList = @()
            
            if ($attr -band [System.IO.FileAttributes]::ReadOnly) { $attrList += "ReadOnly" }
            if ($attr -band [System.IO.FileAttributes]::Hidden) { $attrList += "Hidden" }
            if ($attr -band [System.IO.FileAttributes]::System) { $attrList += "System" }
            if ($attr -band [System.IO.FileAttributes]::Archive) { $attrList += "Archive" }
            if ($attr -band [System.IO.FileAttributes]::Device) { $attrList += "Device" }
            if ($attr -band [System.IO.FileAttributes]::Normal) { $attrList += "Normal" }
            if ($attr -band [System.IO.FileAttributes]::Temporary) { $attrList += "Temporary" }
            if ($attr -band [System.IO.FileAttributes]::SparseFile) { $attrList += "SparseFile" }
            if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { $attrList += "ReparsePoint" }
            if ($attr -band [System.IO.FileAttributes]::Compressed) { $attrList += "Compressed" }
            if ($attr -band [System.IO.FileAttributes]::Offline) { $attrList += "Offline" }
            if ($attr -band [System.IO.FileAttributes]::NotContentIndexed) { $attrList += "NotContentIndexed" }
            if ($attr -band [System.IO.FileAttributes]::Encrypted) { $attrList += "Encrypted" }
            if ($attr -band [System.IO.FileAttributes]::IntegrityStream) { $attrList += "IntegrityStream" }
            if ($attr -band [System.IO.FileAttributes]::NoScrubData) { $attrList += "NoScrubData" }
            
            if ($Item.LinkType) { $attrList += "LinkType: $($Item.LinkType)" }
            
            $fileAttributes.Text = if ($attrList.Count -gt 0) { $attrList -join ", " } else { "No special attributes" }
        } catch {
            $fileAttributes.Text = "Access Denied"
        }
        
        # Close button event
        $closeBtn.Add_Click({
            $detailsWindow.Close()
        })
        
        # Show window
        $detailsWindow.ShowDialog() | Out-Null
        
    } catch {
        [System.Windows.MessageBox]::Show(
            "Error showing file details: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

# ================= MAIN UI =================
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
Title="Advanced PowerShell Explorer"
Width="1500" Height="850"
Background="#1e1e1e">

<Grid>
<Grid.ColumnDefinitions>
<ColumnDefinition/>
<ColumnDefinition Width="420"/>
</Grid.ColumnDefinitions>

<Grid.RowDefinitions>
<RowDefinition Height="40"/>
<RowDefinition/>
</Grid.RowDefinitions>

<!-- TOP BAR -->
<StackPanel Orientation="Horizontal" Margin="5" Grid.ColumnSpan="2">
<Button Name="Back" Content="◀" Width="40"/>
<Button Name="Forward" Content="▶" Width="40" Margin="5,0"/>
<ComboBox Name="Drives" Width="120"/>
<TextBox Name="PathBox" Width="500" Margin="5,0"/>
<Button Name="Go" Content="Go" Width="60"/>
<TextBlock Name="PrivilegeLabel" Margin="15,0"
Foreground="Orange" FontWeight="Bold" FontSize="12"/>
</StackPanel>

<!-- FILE LIST -->
<ListView Name="List" Grid.Row="1" Grid.Column="0" Margin="5"
Background="#252526" Foreground="White">
<ListView.View>
<GridView>
<GridViewColumn Width="40">
<GridViewColumn.CellTemplate>
<DataTemplate>
<Image Width="16" Height="16" Source="{Binding Icon}"/>
</DataTemplate>
</GridViewColumn.CellTemplate>
</GridViewColumn>
<GridViewColumn Header="Name" Width="190" DisplayMemberBinding="{Binding Name}"/>
<GridViewColumn Header="Type" Width="70" DisplayMemberBinding="{Binding Type}"/>
<GridViewColumn Header="Size" Width="70" DisplayMemberBinding="{Binding Size}"/>
<GridViewColumn Header="Modified" Width="120" DisplayMemberBinding="{Binding Modified}"/>
<GridViewColumn Header="Attributes" Width="100" DisplayMemberBinding="{Binding Attributes}"/>
<GridViewColumn Header="Path" Width="330" DisplayMemberBinding="{Binding Path}"/>
</GridView>
</ListView.View>
</ListView>

<!-- RIGHT PANEL -->
<Border Grid.Row="1" Grid.Column="1" Margin="5"
Background="#111" BorderBrush="#444" BorderThickness="1" Padding="10">
<Grid>
<Grid.RowDefinitions>
<RowDefinition Height="*"/>
<RowDefinition Height="Auto"/>
</Grid.RowDefinitions>

<ScrollViewer Grid.Row="0">
<StackPanel>
<TextBlock Text="COLOR MEANINGS" Foreground="#FFD700" FontWeight="Bold" FontSize="14" Margin="0,0,0,10"/>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Black" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="ADS (Alternate Data Stream)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#00008B" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Disk Memory (System Volume/Config)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#8B0000" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Hidden+System+Junction+No Access" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#4B0082" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Device File" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#8A2BE2" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Integrity Stream" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#483D8B" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="No Scrub Data" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Red" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Junction / Reparse Point" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#800080" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Access Denied" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#00CED1" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Hidden + System" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Lime" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Hidden" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Goldenrod" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="System" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#B8860B" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Kernel / Core Windows" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="LightBlue" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Archive Files (ZIP/RAR/etc)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Cyan" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Encrypted" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#FF69B4" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Symbolic Link" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#696969" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Sparse File" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="Gray" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="ReadOnly" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#8FBC8F" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Compressed (NTFS)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#DDA0DD" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Archive Flag" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#F0E68C" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Temporary File" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#A9A9A9" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Offline" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#2E8B57" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Executable (EXE/DLL)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#FF8C00" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Configuration (INI/CFG)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#4682B4" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Script (PS1/BAT/CMD)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#DC143C" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Log Files (LOG/TXT)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#FFD700" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Image Files (JPG/PNG)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#FF1493" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Video Files (MP4/AVI)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#32CD32" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Audio Files (MP3/WAV)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#1E90FF" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Document Files (PDF/DOC)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#8B4513" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Database Files (DB/SQL)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#9400D3" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="VM Files (VHD/VMDK)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#00FA9A" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Container Files (Docker/K8s)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="#FF4500" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Dev Files (Code/Projects)" Foreground="White" FontSize="11"/>
</StackPanel>

<StackPanel Orientation="Horizontal" Margin="0,0,0,3">
<Border Width="20" Height="20" Background="White" Margin="0,0,5,0" BorderBrush="#666" BorderThickness="1"/>
<TextBlock Text="Normal / Standard" Foreground="White" FontSize="11"/>
</StackPanel>

<TextBlock Text="" Margin="0,10,0,0"/>
<TextBlock Text="PRIORITY ORDER:" Foreground="#FFA500" FontWeight="Bold" FontSize="12" Margin="0,10,0,3"/>
<TextBlock Text="1. ADS" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="2. Disk Memory (Dark Blue)" Foreground="#00008B" FontSize="10"/>
<TextBlock Text="3. Special Attributes" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="4. Kernel Folders" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="5. No Access Combinations" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="6. Junction/Symlink" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="7. Encryption/Sparse" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="8. File Types by Category" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="9. Archive Files" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="10. Attribute Combinations" Foreground="#FF6347" FontSize="10"/>
<TextBlock Text="11. Single Attributes" Foreground="#FF6347" FontSize="10"/>
</StackPanel>
</ScrollViewer>

<!-- CREATED BY FOOTER -->
<Border Grid.Row="1" Background="Transparent" Margin="0,10,0,0" Padding="0">
<TextBlock Name="CreatedByText" Text="Created By Arasswys." 
Foreground="#666666" FontSize="10" FontStyle="Italic"
HorizontalAlignment="Right" VerticalAlignment="Bottom"
Opacity="0.7"/>
</Border>
</Grid>
</Border>

</Grid>
</Window>
"@

$Window = [Windows.Markup.XamlReader]::Load(
    (New-Object System.Xml.XmlNodeReader ([xml]$xaml))
)

$List    = $Window.FindName("List")
$Drives  = $Window.FindName("Drives")
$PathBox = $Window.FindName("PathBox")
$Back    = $Window.FindName("Back")
$Forward = $Window.FindName("Forward")
$Go      = $Window.FindName("Go")
$PrivLbl = $Window.FindName("PrivilegeLabel")
$CreatedByText = $Window.FindName("CreatedByText")

$PrivLbl.Text = "Privilege: $PrivilegeText"

# Created By text'e tooltip ekle
$CreatedByText.ToolTip = "Advanced PowerShell Explorer v1.0`nDeveloper: Arasswys"

$BackStack = New-Object System.Collections.Stack
$ForwardStack = New-Object System.Collections.Stack

function Format-Size {
    param($Bytes)
    if ($Bytes -eq $null) { return "" }
    if ($Bytes -eq 0) { return "0 B" }
    $units = @('B','KB','MB','GB','TB')
    $i = 0
    while ($Bytes -ge 1024 -and $i -lt $units.Length-1) {
        $Bytes /= 1024
        $i++
    }
    return "{0:N2} {1}" -f $Bytes, $units[$i]
}

function Get-FileAttributesString {
    param($Item)
    try {
        $attr = $Item.Attributes
        $attrs = @()
        
        if ($attr -band [System.IO.FileAttributes]::ReadOnly) { $attrs += "R" }
        if ($attr -band [System.IO.FileAttributes]::Hidden) { $attrs += "H" }
        if ($attr -band [System.IO.FileAttributes]::System) { $attrs += "S" }
        if ($attr -band [System.IO.FileAttributes]::Archive) { $attrs += "A" }
        if ($attr -band [System.IO.FileAttributes]::Device) { $attrs += "D" }
        if ($attr -band [System.IO.FileAttributes]::Normal) { $attrs += "N" }
        if ($attr -band [System.IO.FileAttributes]::Temporary) { $attrs += "T" }
        if ($attr -band [System.IO.FileAttributes]::SparseFile) { $attrs += "Sp" }
        if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { $attrs += "Rp" }
        if ($attr -band [System.IO.FileAttributes]::Compressed) { $attrs += "C" }
        if ($attr -band [System.IO.FileAttributes]::Offline) { $attrs += "O" }
        if ($attr -band [System.IO.FileAttributes]::NotContentIndexed) { $attrs += "I" }
        if ($attr -band [System.IO.FileAttributes]::Encrypted) { $attrs += "E" }
        if ($attr -band [System.IO.FileAttributes]::IntegrityStream) { $attrs += "IS" }
        if ($attr -band [System.IO.FileAttributes]::NoScrubData) { $attrs += "NS" }
        
        if ($Item.LinkType) { $attrs += $Item.LinkType.Substring(0,3) }
        
        return $attrs -join ""
    } catch { return "" }
}

function Load-Path($Path) {
    if (!(Test-Path $Path)) { return }
    $List.Items.Clear()
    $PathBox.Text = $Path

    Get-ChildItem $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $attr = $_.Attributes
        $isHidden     = $attr -band [IO.FileAttributes]::Hidden
        $isSystem     = $attr -band [IO.FileAttributes]::System
        $isJunction   = $_.LinkType -eq "Junction"
        $isSymlink    = $_.LinkType -eq "SymbolicLink"
        $hasAccess    = Has-Access $_
        $hasADS       = Has-ADS $_ $hasAccess
        $isKernel     = $_.PSIsContainer -and (Is-KernelFolder $_.FullName)
        $isEncrypted  = Is-Encrypted $_
        $isReadOnly   = Is-ReadOnly $_
        $isCompressed = Is-Compressed $_
        $isArchive    = Is-Archive $_
        $isTemporary  = Is-Temporary $_
        $isOffline    = Is-Offline $_
        $isSparse     = Is-Sparse $_
        $isDevice     = Is-Device $_
        $isIntegrity  = Is-IntegrityStream $_
        $isNoScrub    = Is-NoScrub $_
        $isDiskMemory = Is-DiskMemory $_  # Yeni: Disk Memory kontrolü
        $isVideo      = Is-VideoFile $_
        $isAudio      = Is-AudioFile $_
        $isDocument   = Is-DocumentFile $_
        $isDatabase   = Is-DatabaseFile $_
        $isVM         = Is-VMFile $_
        $isContainer  = Is-ContainerFile $_
        $isDev        = Is-DevelopmentFile $_
        $isImage      = Is-ImageFile $_

        $type = if ($isJunction) { "Junction" }
                elseif ($isSymlink) { "Symlink" }
                elseif ($_.PSIsContainer) { "Folder" }
                else { "File" }

        $size = if ($_.PSIsContainer) { "" } else { 
            try { Format-Size $_.Length } catch { "N/A" }
        }
        $modified = try { $_.LastWriteTime.ToString("dd.MM.yyyy HH:mm") } catch { "N/A" }
        $attributes = Get-FileAttributesString $_

        # -------- COLOR PRIORITY --------
        $color = Get-FileColor $_

        $obj = [PSCustomObject]@{
            Icon = Get-Icon $_.FullName
            Name = $_.Name
            Type = $type
            Size = $size
            Modified = $modified
            Attributes = $attributes
            Path = $_.FullName
        }

        $item = New-Object Windows.Controls.ListViewItem
        $item.Content = $obj
        $item.Foreground = $color
        
        # Tooltip
        $tooltipText = "Full Path: $($_.FullName)`nAttributes: $attr`nLinkType: $($_.LinkType)"
        if ($isDiskMemory) {
            $tooltipText += "`n💾 Disk Memory File (System Volume/Config)"
        }
        $item.ToolTip = $tooltipText
        
        $List.Items.Add($item) | Out-Null
    }
}

Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $Drives.Items.Add($_.Root) | Out-Null
}
$Drives.SelectedIndex = 0
Load-Path $Drives.SelectedItem

$Go.Add_Click({
    $BackStack.Push($PathBox.Text)
    Load-Path $PathBox.Text
})

$Drives.Add_SelectionChanged({
    $BackStack.Push($PathBox.Text)
    Load-Path $Drives.SelectedItem
})

$Back.Add_Click({
    if ($BackStack.Count -gt 0) {
        $ForwardStack.Push($PathBox.Text)
        Load-Path $BackStack.Pop()
    }
})

$Forward.Add_Click({
    if ($ForwardStack.Count -gt 0) {
        $BackStack.Push($PathBox.Text)
        Load-Path $ForwardStack.Pop()
    }
})

# ================= FIXED CONTEXT MENU =================
$List.Add_MouseDoubleClick({
    if ($List.SelectedItem) {
        $selectedItem = $List.SelectedItem.Content
        $p = $selectedItem.Path
        
        # Check if it's a folder
        if (Test-Path $p -PathType Container) {
            $BackStack.Push($PathBox.Text)
            Load-Path $p
        } else {
            # Show file details window
            try {
                $fileItem = Get-Item -LiteralPath $p -Force -ErrorAction Stop
                Show-FileDetailsWindow $fileItem
            } catch {
                [System.Windows.MessageBox]::Show(
                    "Cannot access file: $p",
                    "Error",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                )
            }
        }
    }
})

# ================= ENHANCED CONTEXT MENU - FIXED =================
$List.Add_ContextMenuOpening({
    $contextMenu = New-Object Windows.Controls.ContextMenu
    
    if ($List.SelectedItem -and $List.SelectedItem.Content -and $List.SelectedItem.Content.Path) {
        $selectedItem = $List.SelectedItem.Content
        $p = $selectedItem.Path  # ✅ DÜZELTİLDİ: Doğru şekilde alındı
        
        if ($p -and (Test-Path $p)) {
            $isFolder = Test-Path $p -PathType Container
            
            if ($isFolder) {
                # Klasör için menü öğeleri
                # See Code
                $codeItem = New-Object Windows.Controls.MenuItem
                $codeItem.Header = "📁 See Code"
                $codeItem.Add_Click({
                    try {
                        Show-FolderInformation $p
                    } catch {
                        [System.Windows.MessageBox]::Show(
                            "Cannot show folder information: $_",
                            "Error",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Error
                        )
                    }
                })
                
                # Antivirus Check
                $avItem = New-Object Windows.Controls.MenuItem
                $avItem.Header = "🛡️ Antivirus Check"
                $avItem.Add_Click({
                    $avStatus = Get-AntivirusStatus $p
                    [System.Windows.MessageBox]::Show(
                        "Antivirus Status for folder:`n`n$avStatus",
                        "Antivirus Check",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information
                    )
                })
                
                # Folder Information
                $folderInfoItem = New-Object Windows.Controls.MenuItem
                $folderInfoItem.Header = "📊 Folder Information"
                $folderInfoItem.Add_Click({
                    Show-FolderInformation $p
                })
                
                $contextMenu.Items.Add($codeItem) | Out-Null
                $contextMenu.Items.Add($avItem) | Out-Null
                $contextMenu.Items.Add($folderInfoItem) | Out-Null
                
                # Separator
                $separator = New-Object Windows.Controls.Separator
                $contextMenu.Items.Add($separator) | Out-Null
                
                # Copy Path (klasörler için de)
                $copyItem = New-Object Windows.Controls.MenuItem
                $copyItem.Header = "📋 Copy Path"
                $copyItem.Add_Click({
                    try {
                        [System.Windows.Clipboard]::SetText($p)
                    } catch {
                        Set-Clipboard -Value $p -ErrorAction SilentlyContinue
                    }
                })
                $contextMenu.Items.Add($copyItem) | Out-Null
                
            } else {
                # Dosya için menü öğeleri
                $ext = [System.IO.Path]::GetExtension($p).ToLower()
                $isCodeFile = $ext -in @('.ps1', '.cs', '.js', '.html', '.css', '.xml', '.json', '.py', '.java', '.cpp', '.c', '.h', '.php', '.sql', '.bat', '.cmd', '.vbs', '.ini', '.config', '.txt', '.log')
                
                if ($isCodeFile) {
                    # See Code
                    $codeItem = New-Object Windows.Controls.MenuItem
                    $codeItem.Header = "📝 See Code"
                    $codeItem.Add_Click({
                        try {
                            Show-CodeViewer $p
                        } catch {
                            [System.Windows.MessageBox]::Show(
                                "Cannot open code viewer: $_",
                                "Error",
                                [System.Windows.MessageBoxButton]::OK,
                                [System.Windows.MessageBoxImage]::Error
                            )
                        }
                    })
                    $contextMenu.Items.Add($codeItem) | Out-Null
                }
                
                # Antivirus Check
                $avItem = New-Object Windows.Controls.MenuItem
                $avItem.Header = "🛡️ Antivirus Check"
                $avItem.Add_Click({
                    $avStatus = Get-AntivirusStatus $p
                    [System.Windows.MessageBox]::Show(
                        "Antivirus Status:`n`n$avStatus",
                        "Antivirus Check",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information
                    )
                })
                $contextMenu.Items.Add($avItem) | Out-Null
                
                # File Information
                $fileInfoItem = New-Object Windows.Controls.MenuItem
                $fileInfoItem.Header = "📄 File Information"
                $fileInfoItem.Add_Click({
                    try {
                        $fileItem = Get-Item -LiteralPath $p -Force -ErrorAction Stop
                        Show-FileDetailsWindow $fileItem
                    } catch {
                        [System.Windows.MessageBox]::Show(
                            "Cannot show file details: $_",
                            "Error",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Error
                        )
                    }
                })
                $contextMenu.Items.Add($fileInfoItem) | Out-Null
                
                # Separator
                $separator = New-Object Windows.Controls.Separator
                $contextMenu.Items.Add($separator) | Out-Null
                
                # Copy Path - FIXED
                $copyItem = New-Object Windows.Controls.MenuItem
                $copyItem.Header = "📋 Copy Path"
                $copyItem.Add_Click({
                    try {
                        # PowerShell 5.1 için
                        [System.Windows.Clipboard]::SetText($p)
                    } catch {
                        # PowerShell Core için alternatif
                        try {
                            Set-Clipboard -Value $p -ErrorAction Stop
                        } catch {
                            # Son çare
                            $p | Out-Clipboard -ErrorAction SilentlyContinue
                        }
                    }
                })
                $contextMenu.Items.Add($copyItem) | Out-Null
            }
        }
    } else {
        # No item selected - show refresh option
        $refreshItem = New-Object Windows.Controls.MenuItem
        $refreshItem.Header = "🔄 Refresh"
        $refreshItem.Add_Click({
            Load-Path $PathBox.Text
        })
        $contextMenu.Items.Add($refreshItem) | Out-Null
    }
    
    $List.ContextMenu = $contextMenu
})

# ================= KEYBOARD SHORTCUTS =================
$Window.Add_KeyDown({
    param($sender, $e)
    
    if ($e.Key -eq 'F5') {
        Load-Path $PathBox.Text
    }
    elseif ($e.Key -eq 'Back' -and $e.KeyboardDevice.Modifiers -eq 'Ctrl') {
        if ($BackStack.Count -gt 0) {
            $ForwardStack.Push($PathBox.Text)
            Load-Path $BackStack.Pop()
        }
    }
    elseif ($e.Key -eq 'C' -and $e.KeyboardDevice.Modifiers -eq 'Ctrl') {
        if ($List.SelectedItem -and $List.SelectedItem.Content) {
            $selectedItem = $List.SelectedItem.Content
            $p = $selectedItem.Path
            try {
                [System.Windows.Clipboard]::SetText($p)
            } catch {
                Set-Clipboard -Value $p
            }
        }
    }
    elseif ($e.Key -eq 'Enter') {
        if ($List.SelectedItem -and $List.SelectedItem.Content) {
            $selectedItem = $List.SelectedItem.Content
            $p = $selectedItem.Path
        
            if (Test-Path $p -PathType Container) {
                $BackStack.Push($PathBox.Text)
                Load-Path $p
            } else {
                try {
                    $fileItem = Get-Item -LiteralPath $p -Force -ErrorAction Stop
                    Show-FileDetailsWindow $fileItem
                } catch {
                    [System.Windows.MessageBox]::Show(
                        "Cannot access file: $p",
                        "Error",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    )
                }
            }
        }
    }
})

# ================= WINDOW CLOSING =================
$Window.Add_Closing({
    [System.GC]::Collect()
})

$Window.ShowDialog() | Out-Null