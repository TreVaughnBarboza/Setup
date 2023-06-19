Param(
    [switch]$Run
)

# TODO: Either Fix these or find a way to find the id's automatically
$gpuDatabase = @{
    # 40 Series PSID: 127
    "NVIDIA GeForce RTX 4090" = @{
        "PFID" = "995"
        "PSID" = "127"
    }
    "NVIDIA GeForce RTX 4080" = @{
        "PFID" = "999"
        "PSID" = "127"
    }
    "NVIDIA GeForce RTX 4070 Ti" = @{
        "PFID" = "1001"
        "PSID" = "127"
    }
    "NVIDIA GeForce RTX 4070" = @{
        "PFID" = "1015"
        "PSID" = "127"
    }
    "NVIDIA GeForce RTX 4060 Ti" = @{
        "PFID" = "1022"
        "PSID" = "127"
    }
    # 30 Series PSID: 120
    "NVIDIA GeForce RTX 3090 Ti" = @{
        "PFID" = "985"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3090" = @{
        "PFID" = "930"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3080 Ti" = @{
        "PFID" = "964"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3080" = @{
        "PFID" = "929"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3070 Ti" = @{
        "PFID" = "965"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3070" = @{
        "PFID" = "933"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3060 Ti" = @{
        "PFID" = "934"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3060" = @{
        "PFID" = "942"
        "PSID" = "120"
    }
    "NVIDIA GeForce RTX 3050" = @{
        "PFID" = "975"
        "PSID" = "120"
    }
    # 20 Series PSID: 107
    "NVIDIA GeForce RTX 2080 Ti" = @{
        "PFID" = "877"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2080 Super" = @{
        "PFID" = "904"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2080" = @{
        "PFID" = "879"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2070 Super" = @{
        "PFID" = "903"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2070" = @{
        "PFID" = "880"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2060 Super" = @{
        "PFID" = "902"
        "PSID" = "107"
    }
    "NVIDIA GeForce RTX 2060" = @{
        "PFID" = "887"
        "PSID" = "107"
    }
    # 16 Series PSID 112
    "NVIDIA GeForce GTX 1660 Super" = @{
        "PFID" = "910"
        "PSID" = "112"
    }
    "NVIDIA GeForce GTX 1650 Super" = @{
        "PFID" = "911"
        "PSID" = "112"
    }
    "NVIDIA GeForce GTX 1660 Ti" = @{
        "PFID" = "892"
        "PSID" = "112"
    }
    "NVIDIA GeForce GTX 1660" = @{
        "PFID" = "895"
        "PSID" = "112"
    }
    "NVIDIA GeForce GTX 1650" = @{
        "PFID" = "897"
        "PSID" = "112"
    }
    "NVIDIA GeForce GTX 1630" = @{
        "PFID" = "993"
        "PSID" = "112"
    }
    # 10 Series
    "NVIDIA GeForce GTX 1080 Ti" = @{
        "PSID" = "101"
        "PFID" = "845"
    }
    "NVIDIA GeForce GTX 1080" = @{
        "PSID" = "101"
        "PFID" = "815"
    }
    "NVIDIA GeForce GTX 1070 Ti" = @{
        "PSID" = "101"
        "PFID" = "859"
    }
    "NVIDIA GeForce GTX 1070" = @{
        "PSID" = "101"
        "PFID" = "816"
    }
    "NVIDIA GeForce GTX 1060" = @{
        "PSID" = "101"
        "PFID" = "817"
    }
    "NVIDIA GeForce GTX 1050 Ti" = @{
        "PSID" = "101"
        "PFID" = "825"
    }
    "NVIDIA GeForce GTX 1050" = @{
        "PSID" = "101"
        "PFID" = "826"
    }
    "NVIDIA GeForce GTX 1030" = @{
        "PSID" = "101"
        "PFID" = "852"
    }
    "NVIDIA GeForce GTX 1010" = @{
        "PSID" = "101"
        "PFID" = "936"
    }
}

# Functions
function SetRegistryKeysIWS {
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'EnableBalloonTips' -Value 0
    New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoSimpleStartMenu' -Value 1
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSuperHidden' -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'forceguest' -Value 1
    Set-ItemProperty -Path 'HKCU:\Control Panel\PowerCfg' -Name 'CurrentPowerPolicy' -Value 2
    Set-ItemProperty -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value 0
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value 0011

    Set-ItemProperty -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value 0
    
    # Computer Name Host Name
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -Value 'Instr'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -Value 'Instr'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Hostname' -Value 'Instr'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -Name 'NV Hostname' -Value 'Instr'
}

# 450
function SetRegistryKeysGraphics {
    # Password Settings
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -Value 'amos'
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Value 1
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -Value 'Administrator'

    # Desktop
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDesktop' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoTrayItemsDisplay' -Value 1
    Set-ItemProperty -Path 'HKU\.DEFAULT\Control Panel\Colors' -Name 'Background' -Value '128 128 128'
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'Wallpaper' -Value 'c:\windows\dorondrk.bmp'

    # Computer Name Host Name
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -Value 'ChnlName'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -Value 'ChnlName'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -Name 'Hostname' -Value 'ChnlName'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -Name 'NV Hostname' -Value 'ChnlName'
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IpEnableRouter' -Value 1

    # Configuration Settings
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'IncludeRecommendedUpdates' -Value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'ElevateNonAdmins' -Value 0

    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'EnableAutoTray' -Value 1 -Type DWord
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HideSCAHealth' -Value 1 -Type DWord

    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value 1 -Type DWord
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0 -Type DWord

    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSuperHidden' -Value 1 -Type DWord

    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SharingWizardOn' -Value 0 -Type DWord
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder' -Name 'SharingWizardOn' -Value 0 -Type DWord

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0007' -Name 'PnPCapabilities' -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0011' -Name 'PnPCapabilities' -Value 24
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0007' -Name 'PnPCapabilities' -Value 24
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\0011' -Name 'PnPCapabilities' -Value 24

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc' -Name 'Start' -Value 4

    Set-ItemProperty -Path 'HKCU:\Control Panel\PowerCfg' -Name 'CurrentPowerPolicy' -Value 4

    # Environment settings (Center computers only)
    $env:DA_HOST_IP = '192.168.100.2'
    $env:DA_OUR_IP = 'SkillTrakIp'
    $env:SKILLTRAK_MODE = 'ETHERNET'
    $env:DA_CAB_IP = '192.168.101.20'
    $env:DA_CAB_PORT = '5150'
}

function SetEnvironmentVariables {
    param(
        [string]$InstructorMultiviewportConfig = $null,
        [string]$InstructorServerPort = $null,
        [string]$DrivingPositionSerial = $null,
        [string]$DrivingPositionFriendlyName = $null
    )

    $InstructorMultiviewportConfig = Read-Host "Enter The Instructor Multiviewport Configeration: "
    [Environment]::SetEnvironmentVariable("DORON_MULTIVIEWPORT_CONFIG",$InstructorMultiviewportConfig,"User")
    [Environment]::SetEnvironmentVariable("DORON_INSTRUCTOR_SERVER_IP","42000","User")
    $InstructorServerPort = Read-Host "Enter The Instructor Server Port: "
    [Environment]::SetEnvironmentVariable("DORON_INSTRUCTOR_SERVER_PORT",$InstructorServerPort,"User")
    $DrivingPositionSerial = Read-Host "Enter The Driving Position Serial: "
    [Environment]::SetEnvironmentVariable("DORON_DRIVING_POSITION_SERIAL",$DrivingPositionSerial,"User")
    $DrivingPositionFriendlyName = Read-Host "Enter The Driving Position Friendly Name: "
    [Environment]::SetEnvironmentVariable("DORON_DRIVING_POSITION_FRIENDLY_NAME",$DrivingPositionFriendlyName,"User")

    Write-Host "Environments Set successfully"
}

function SetNetAdapters {
    $success = $false
    try {
        # Get all network adapters
        $adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Ethernet*' }

        # Prompt the user to label each adapter
        $adapters | ForEach-Object {
            $adapter = $_
            $currentName = $adapter.Name
            $newName = Read-Host "Please enter a new name for adapter '$currentName'"
            Rename-NetAdapter -Name $currentName -NewName $newName
        }

        Write-Host "Success"
        $success = $true
    } catch {
        Write-Host "Error occurred while setting network adapters: $_"
        $success = $false
    }

    return $success
}

function RemoveDesktopIcons {
    Remove-Item -Path "$HOME\Desktop\*" -Force

    Write-Host "Success"
}

function ListSupportedDrivers {
    $keys = $gpuDatabase.Keys
    foreach ($key in $keys) {
        Write-Host $key
    }
}

function InstallDrivers {
    param (
        [string]$gpuName = ""
    )

    if ($gpuName -eq "") {
        $gpuInfo = Get-WmiObject -Class Win32_VideoController
        $gpuName = $gpuInfo.name
    }

    # Find the PSID and PFID for the specified GPU card
    $targetSeries = $gpuDatabase.GetEnumerator() | Where-Object { $_.key -eq $gpuName }
    if ($targetSeries -eq $null) {
        ListSupportedDrivers
        Write-Host "GPU card not found. Please check the name and try again."
        exit
    }
    $psid = $targetSeries.Value["PSID"]
    $pfid = $targetSeries.Value["PFID"]

    # Fetching the latest Studio driver for the specified GPU card
    $driverUrl = 'https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php' +
        "?func=DriverManualLookup" +
        "&psid=$psid" +
        "&pfid=$pfid" +
        "&osID=57" +  # Windows 10 64-bit
        "&languageCode=1033" +  # en-US; Windows Locale ID in decimal
        "&isWHQL=1" +  # WHQL certified
        "&dch=1" +  # DCH drivers (the new standard)
        "&driverCert=0" +  # Studio drivers
        "&sort1=0" +  # Sort: most recent first
        "&numberOfResults=1"  # Single, most recent result is enough

    $response = Invoke-WebRequest -Uri $driverUrl -Method GET -UseBasicParsing
    $payload = $response.Content | ConvertFrom-Json
    $version = $payload.IDS[0].downloadInfo.Version
    $downloadLink = $payload.IDS[0].downloadInfo.downloadURL

    Write-Host "Latest Studio Driver Version: $version"

    if ($downloadLink -ne $null) {
        #Download
        Write-Host "Downloading Studio driver..."
        $tempDirectory = [System.IO.Path]::GetTempPath()
        $fileName = [System.IO.Path]::GetRandomFileName()
        $tempFilePath = Join-Path -Path $tempDirectory -ChildPath "$fileName.exe"
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadLink, $tempFilePath)
        # TODO: Add loading bar
        Write-Host "Studio driver downloaded successfully"
        
        # Install
        Write-Host "Installing Studio driver..."
        Start-Process -FilePath $tempFilePath -ArgumentList "/silent" -Wait
        Remove-Item -Path $tempFilePath -Force
        Write-Host "Studio driver installed successfully"
    } else {
        Write-Host "Driver search failed for $gpuName"
        exit
    }
}

function InstallNvidiaDrivers {
    # TODO: Find Programically
    $gpuInfo = Get-WmiObject -Class Win32_VideoController
    $gpuName = $gpuInfo.name
    Write-Host "GPU Name: $gpuName"
    $confirmation = Read-Host "Do you want to install drivers for this GPU? (Y/N)"

    if ($confirmation.ToUpper() -eq "Y") {
        InstallDrivers
    } else {
        ListSupportedDrivers
        $gpu = Read-Host "What Drivers would you like to install?"
        InstallDrivers -gpuName $gpu
    }
}

# Not My Code: https://github.com/Sycnex/Windows10Debloater
function Debloat {
    #This function finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
    #Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

    #This is the switch parameter for running this script as a 'silent' script, for use in MDT images or any type of mass deployment without user interaction.

    param (
      [switch]$Debloat, [switch]$SysPrep
    )

    Function Begin-SysPrep {

        param([switch]$SysPrep)
            Write-Verbose -Message ('Starting Sysprep Fixes')
     
            # Disable Windows Store Automatic Updates
           <# Write-Verbose -Message "Adding Registry key to Disable Windows Store Automatic Updates"
            $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
            If (!(Test-Path $registryPath)) {
                Mkdir $registryPath -ErrorAction SilentlyContinue
                New-ItemProperty $registryPath -Name AutoDownload -Value 2 
            }
            Else {
                Set-ItemProperty $registryPath -Name AutoDownload -Value 2 
            }
            #Stop WindowsStore Installer Service and set to Disabled
            Write-Verbose -Message ('Stopping InstallService')
            Stop-Service InstallService 
            #>
     } 

    #Creates a PSDrive to be able to access the 'HKCR' tree
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    Function Start-Debloat {
        
        param([switch]$Debloat)

        #Removes AppxPackages
        #Credit to Reddit user /u/GavinEke for a modified version of my whitelist code
        [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
        Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
        Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
        # Run this again to avoid error on 1803 or having to reboot.
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage -ErrorAction SilentlyContinue
        $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps} 
        ForEach ( $App in $AppxRemoval) {
        
            Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
            
            }
    }

    Function Remove-Keys {
            
        Param([switch]$Debloat)    
        
        #These are the registry keys that it will delete.
            
        $Keys = @(
            
            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing $Key from registry"
            Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
        }
    }
            
    Function Protect-Privacy {
        
        Param([switch]$Debloat)    

        #Creates a PSDrive to be able to access the 'HKCR' tree
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            
        #Disables Windows Feedback Experience
        Write-Output "Disabling Windows Feedback Experience program"
        $Advertising = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
        }
            
        #Stops Cortana from being used as part of your Windows Search Function
        Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
        $Search = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        If (Test-Path $Search) {
            Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
        }
            
        #Stops the Windows Feedback Experience from sending anonymous data
        Write-Output "Stopping the Windows Feedback Experience program"
        $Period1 = 'HKCU:\Software\Microsoft\Siuf'
        $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
        $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
        If (!(Test-Path $Period3)) { 
            mkdir $Period1 -ErrorAction SilentlyContinue
            mkdir $Period2 -ErrorAction SilentlyContinue
            mkdir $Period3 -ErrorAction SilentlyContinue
            New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
        }
                   
        Write-Output "Adding Registry key to prevent bloatware apps from returning"
        #Prevents bloatware applications from returning
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        If (!(Test-Path $registryPath)) {
            Mkdir $registryPath -ErrorAction SilentlyContinue
            New-ItemProperty $registryPath -Name DisableWindowsConsumerFeatures -Value 1 -Verbose -ErrorAction SilentlyContinue
        }          
        
        Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo -Name FirstRunSucceeded -Value 0 -Verbose
        }
        
        #Disables live tiles
        Write-Output "Disabling live tiles"
        $Live = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
        If (!(Test-Path $Live)) {
            mkdir $Live -ErrorAction SilentlyContinue     
            New-ItemProperty $Live -Name NoTileApplicationNotification -Value 1 -Verbose
        }
        
        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
        Write-Output "Turning off Data Collection"
        $DataCollection = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
        If (Test-Path $DataCollection) {
            Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
        }
        
        #Disables People icon on Taskbar
        Write-Output "Disabling People icon on Taskbar"
        $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
        }

        #Disables suggestions on start menu
        Write-Output "Disabling suggestions on the Start Menu"
        $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
        If (Test-Path $Suggestions) {
            Set-ItemProperty $Suggestions -Name SystemPaneSuggestionsEnabled -Value 0 -Verbose
        }
        
        
         Write-Output "Removing CloudStore from registry if it exists"
         $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
         If (Test-Path $CloudStore) {
         Stop-Process -Name explorer -Force
         Remove-Item $CloudStore -Recurse -Force
         Start-Process Explorer.exe -Wait
        }

        #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
        reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
        Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
        reg unload HKU\Default_User
        
        #Disables scheduled tasks that are considered unnecessary 
        Write-Output "Disabling scheduled tasks"
        #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }

    #This includes fixes by xsisbest
    Function FixWhitelistedApps {
        
        Param([switch]$Debloat)
        
        If(!(Get-AppxPackage -AllUsers | Select Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
        
        #Credit to abulgatz for the 4 lines of code
        Get-AppxPackage -allusers Microsoft.Paint3D | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.MSPaint | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.WindowsCalculator | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.Windows.Photos | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} }
    }

    Function CheckDMWService {

      Param([switch]$Debloat)
      
    If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
        Set-Service -Name dmwappushservice -StartupType Automatic}

    If(Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
       Start-Service -Name dmwappushservice} 
      }

    Function CheckInstallService {
      Param([switch]$Debloat)
              If (Get-Service -Name InstallService | Where-Object {$_.Status -eq "Stopped"}) {  
                Start-Service -Name InstallService
                Set-Service -Name InstallService -StartupType Automatic 
                }
            }

    Write-Output "Initiating Sysprep"
    Begin-SysPrep
    Write-Output "Removing bloatware apps."
    Start-Debloat
    Write-Output "Removing leftover bloatware registry keys."
    Remove-Keys
    Write-Output "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
    FixWhitelistedApps
    Write-Output "Stopping telemetry, disabling unneccessary scheduled tasks, and preventing bloatware from returning."
    Protect-Privacy
    #Write-Output "Stopping Edge from taking over as the default PDF Viewer."
    #Stop-EdgePDF
    CheckDMWService
    CheckInstallService
    Write-Output "Finished all tasks."
}

function InstallGraphicsOsLink {
    New-Item -ItemType Directory -Path "C:\InstalledByHand"
    # Install binary
}

function CheckStepSuccess($step) {
    try {
        & $step
        return $true
    } catch {
        Write-Host "Error occurred while executing step '$step': $_"
        return $false
    }
}

function RunSteps($steps) {
    while ($true) {
        $index = 1
        $steps.Keys | ForEach-Object {
            $completionStatus = if ($steps[$_]) { "Done" } else { "Not done" }
            $color = if ($steps[$_]) { "Green" } else { "Red" }
            Write-Host "$index. $_ ($completionStatus)" -ForegroundColor $color
            $index++
        }
        
        $input = Read-Host "Enter 'c' to continue, a step number to execute, or 'q' to exit"
        
        if ($input -eq "q") {
            break
        }
        
        if ($input -eq "c") {
            $continueStep = $null
            foreach ($step in $steps.Keys) {
                if (-not $steps[$step]) {
                    $continueStep = $step
                    break
                }
            }
            if ($continueStep) {
                $stepSuccess = CheckStepSuccess $continueStep
                if ($stepSuccess) {
                    $steps[$continueStep] = $true
                    Write-Host "Step executed successfully"
                } else {
                    Write-Host "Step did not complete successfully"
                }
            } else {
                Write-Host "All steps completed"
            }
            continue
        }
        
        if ($input -ge 1 -and $input -le $steps.Count) {
            $selectedStep = $steps.Keys | Select-Object -Index ($input - 1)
            if (-not $steps[$selectedStep]) {
                $stepSuccess = CheckStepSuccess $selectedStep
                if ($stepSuccess) {
                    $steps[$selectedStep] = $true
                    Write-Host "Step executed successfully"
                } else {
                    Write-Host "Step did not complete successfully"
                }
            } else {
                Write-Host "Step already completed"
            }
        } else {
            Write-Host "Invalid input"
        }
    }
}

# Main Script Code
if ($Run -eq $False) {
    Write-Host "This Script will assist in the setup of a graphics or IWS computer."
    exit
}

$setupType = Read-Host "Would you like to setup a Graphics or IWS computer? (G/I)"
if ($setupType.ToUpper() -eq "G") {
    # Graphics
    $steps = @{
        SetRegistryKeysGraphics = $false
        SetEnvironmentVariables = $false
        SetNetAdapters = $false
        InstallNvidiaDrivers = $false
        Debloat = $false
        RemoveDesktopIcons = $false
    }
    RunSteps($steps)
} else {
    # IWS
    $steps = @{
        SetRegistryKeysIWS = $false
        SetEnvironmentVariables = $false
        SetNetAdapters = $false
        InstallNvidiaDrivers = $false
        Debloat = $false
        RemoveDesktopIcons = $false
    }
    RunSteps($steps)
}

Write-Host "Setup Complete."
exit
