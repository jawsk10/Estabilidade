@ECHO OFF
SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
cd /d "%~dp0"

IF EXIST "C:\Windows\system32\adminrightstest" (
rmdir C:\Windows\system32\adminrightstest
)
mkdir C:\Windows\system32\adminrightstest
if %errorlevel% neq 0 (
POWERSHELL "Start-Process \"%~nx0\" -Verb RunAs"
if !errorlevel! neq 0 (
POWERSHELL "Start-Process '%~nx0' -Verb RunAs"
if !errorlevel! neq 0 (
ECHO You should run this script as Admin in order to allow system changes
)
)
exit
)
rmdir C:\Windows\system32\adminrightstest

:: Services Stop
sc stop EventLog
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop RemoteRegistry
sc stop TrkWks
sc stop WMPNetworkSvc
sc stop SysMain
sc stop wuauserv
sc stop lmhosts
sc stop VSS
sc stop RemoteAccess
sc stop WSearch
sc stop iphlpsvc
sc stop DoSvc
sc stop ClickToRunSvc
sc stop SEMgrSvc
sc stop BDESVC
sc stop TabletInputService
sc stop SstpSvc
sc stop NvTelemetryContainer
sc stop HomeGroupListener
sc stop HomeGroupProvider
sc stop lfsvc
sc stop MapsBroke
sc stop NetTcpPortSharing
sc stop SharedAccess
sc stop WbioSrvc
sc stop WMPNetworkSvc
sc stop wisvc
sc stop TapiSrv
sc stop SmsRouter
sc stop SharedRealitySvc
sc stop ScDeviceEnum
sc stop SCardSvr
sc stop RetailDemo
sc stop PhoneSvc
sc stop perceptionsimulation
sc stop BTAGService
sc stop AJRouter
sc stop CDPSvc
sc stop ShellHWDetection
sc stop RstMwService
sc stop DusmSvc
sc stop BthAvctpSvc
sc stop BITS
sc stop DPS
sc stop Spooler
sc stop RtkAudioUniversalService
sc stop XboxGipSvc
sc stop XboxNetApiSvc
sc stop XblGameSave
sc stop XblAuthManager
sc stop vmicvss
sc stop WalletService
sc stop Fax

:: Services Disable
sc config EventLog start=disabled
sc config DiagTrack start=disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config dmwappushservice start=disabled
sc config RemoteRegistry start=disabled
sc config TrkWks start=disabled
sc config WMPNetworkSvc start=disabled
sc config SysMain start=disabled
sc config wuauserv start=disabled
sc config lmhosts start=disabled
sc config VSS start=disabled
sc config RemoteAccess start=disabled
sc config WSearch start=disabled
sc config iphlpsvc start=disabled
sc config DoSvc start=disabled
sc config ClickToRunSvc start=demand
sc config SEMgrSvc start=disabled
sc config BDESVC start=disabled
sc config TabletInputService start=disabled
sc config SstpSvc start=disabled
sc config NvTelemetryContainer start=disabled
sc config HomeGroupListener start=disabled
sc config HomeGroupProvider start=disabled
sc config lfsvc start=disabled
sc config MapsBroke start=disabled
sc config NetTcpPortSharing start=disabled
sc config SharedAccess start=disabled
sc config WbioSrvc start=disabled
sc config WMPNetworkSvc start=disabled
sc config wisvc start=disabled
sc config TapiSrv start=disabled
sc config SmsRouter start=disabled
sc config SharedRealitySvc start=disabled
sc config ScDeviceEnum start=disabled
sc config SCardSvr start=disabled
sc config RetailDemo start=disabled
sc config PhoneSvc start=disabled
sc config perceptionsimulation start=disabled
sc config BTAGService start=disabled
sc config AJRouter start=disabled
sc config CDPSvc start=disabled
sc config ShellHWDetection start=disabled
sc config RstMwService start=disabled
sc config DusmSvc start=disabled
sc config BthAvctpSvc start=disabled
sc config BITS start=demand
sc config DPS start=disabled
sc config nlasvc depend=NSI/RpcSs/TcpIp/Dhcp
sc config Spooler start=disabled
sc config RtkAudioUniversalService start=disabled
sc config XboxGipSvc start=disabled
sc config XboxNetApiSvc start=disabled
sc config XblGameSave start=disabled
sc config XblAuthManager start=disabled
sc config vmicvss start=disabled
sc config WalletService start=disabled
sc config Fax start=disabled

:: Scheduled Task
schtasks /Change /tN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /tN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /tN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /tN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /tN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /tN "Microsoft\Windows\SystemRestore\SR" /disable
schtasks /Change /tN "Microsoft\Office\Office Automatic Updates 2.0" /disable
schtasks /Change /tN "Microsoft\Office\Office ClickToRun Service Monitor" /disable
schtasks /Change /tN "Microsoft\Office\Office Feature Updates" /disable
schtasks /Change /tN "Microsoft\Office\Office Feature Updates Logon" /disable
schtasks /Change /tN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /tN "MicrosoftEdgeUpdateTaskMachineCore" /disable
schtasks /Change /tN "MicrosoftEdgeUpdateTaskMachineUA" /disable
schtasks /Change /tN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /tN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /tN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /tN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /tN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /tN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable *** Not sure if should bedisabled, maybe related to S.M.A.R.T.
schtasks /Change /tN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /Change /tN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable
schtasks /Change /tN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /tN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

:: Adapter
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /t REG_DWORD /d 1 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /t REG_DWORD /d 0 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /t REG_DWORD /d 1 /f

:: Core 2 Affinity
for /f %%n in ('wmic path win32_networkadapter get PNPDeviceID ^| findstr /L "VEN_"') do (
REG ADD "HKLM\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
)

:: Advanced Adapter
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*InterruptModeration" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*EEE" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "AdvancedEEE" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "PowerSavingMode" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "S5WakeOnLan" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "WolShutdownLinkSpeed" -RegistryValue 2
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*ModernStandbyWoLMagicPacket" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*WakeOnMagicPacket" -RegistryValue 0
POWERSHELL Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*WakeOnPattern" -RegistryValue 0

:: Adapter bindings
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp -ErrorAction SilentlyContinue
:: Link-Layer Topology Discovery Mapper I/O Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio -ErrorAction SilentlyContinue
:: Client for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient -ErrorAction SilentlyContinue
:: Microsoft LLDP Protocol Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr -ErrorAction SilentlyContinue
:: File and Printer Sharing for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue
:: Microsoft Network Adapter Multiplexor Protocol
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat -ErrorAction SilentlyContinue

:: Bindings that are not common
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pppoe -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rdma_ndk -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_ndisuio -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_upper -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_lower -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbt -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbios -ErrorAction SilentlyContinue

:: QoS Packet Scheduler
POWERSHELL Disable-NetAdapterQos -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer -ErrorAction SilentlyContinue

:: Restarting Adapter
POWERSHELL Restart-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue

:: Last Access
fsutil.exe behavior set disableLastAccess 1

:: Name Archive
fsutil.exe 8dot3name set 1

:: Memory Usage
fsutil behavior query memoryusage
fsutil behavior set memoryusage 2

:: Mftzone
fsutil behavior set mftzone 4

:: Notify
fsutil behavior setdisabledeletenotify 0

:: Encrypt Paging File
fsutil behavior set encryptpagingfile 0

:: Get-MMAgent
powershell -Command "Disable-MMAgent -PageCombining"
powershell -Command "Disable-MMAgent -MemoryCompression"

:: Telemetry & Collect Data
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
REG ADD "HKLM\Software\Microsoft\SQMClient\Windows /v "CEIPEnable" /d "0" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d Off /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t REG_SZ /d Off /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f

:: Allow apps to use my advertising ID
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f

:: Smart Screen for Store apps
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f

:: Let websites provide locally
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f

:: Change updates to notify about scheduled restarts
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f

:: P2P Update downlods outside of local network
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f

:: Hide the Search box from the taskbar
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f

:: Jump lists of XAML apps in the start menu
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f

:: Configure Windows Explorer to start in This PC
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f

:: Suggestions in the Start Menu
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f

:: Hibernation
powercfg -h off

:: Virtual Memory
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" delete

:: Superfetch
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f

:: Speed ​​up shutdown
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f

:: All icons in the tray
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explore" /v "EnableAutoTray" /t REG_DWORD /d "1" /f

:: Windows
REG ADD "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d 1 /f
REG ADD "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d 2000 /f
REG ADD "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 0 /f
REG ADD "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d 2000 /f
REG ADD "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "2000" /f
REG ADD "HKCU\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d "a" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowRun" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FolderContentsInfoTip" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowPreviewHandlers" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f

:: Improve wallpaper quality
REG ADD "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "64" /f

:: Game Bar e DVR
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

:: Game Presence Writer
takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Todos:F /c
taskkill /im GameBarPresenceWriter.exe /f
del "%WinDir%\System32\GameBarPresenceWriter.exe"

:: Game Panel
takeown /f "%WinDir%\System32\GamePanel.exe" /a
icacls "%WinDir%\System32\GamePanel.exe" /grant:r Todos:F /c
taskkill /im GamePanel.exe /f
del "%WinDir%\System32\GamePanel.exe"

:: Mob Sync
takeown /f "%WinDir%\System32\mobsync.exe" /a
icacls "%WinDir%\System32\mobsync.exe" /grant:r Todos:F /c
taskkill /im mobsync.exe /f
del "%WinDir%\System32\mobsync.exe"

:: User Account Control
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f

:: Colors on the Start menu and taskbar
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Control Panel\Desktop" /v "AutoColorization " /t REG_DWORD /d "0" /f

:: Command Prompt by default
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /d "1" /f

:: Screen protector
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /d "0" /f

:: SmartScreen
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "-" /f

:: Show file extensions in Explorer
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d "0" /f

:: Reserved Storage
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t  REG_DWORD /d "0" /f

:: Delivery Optimization
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_SZ /d "0" /f

:: Location
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d Deny /f

:: Notifications about files downloaded from the Internet
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Environment" /v "SEE_MASK_NOZONECHECKS" /t REG_SZ /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SEE_MASK_NOZONECHECKS" /t REG_SZ /d "1" /f

:: Automatically internet files
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f

:: Cortana e Websearch
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingEmailAttachments" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AutoIndexSharedFolders" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCorporateCloudSearch" /t REG_DWORD /d "0" /f

:: Automatic Driver Updates
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRInBackground" /t REG_DWORD /d "2" /f

:: Printers
POWERSHELL Disable-WindowsOptionalFeature -Online -FeatureName Printing-PrintToPDFServices-Features -NoRestart
POWERSHELL Disable-WindowsOptionalFeature -Online -FeatureName FaxServicesClientPackage -NoRestart
POWERSHELL Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -NoRestart

:: Resources Windows
Dism /online /Disable-Feature /FeatureName:Windows-Defender-Default-Definitions -NoRestart
Dism /online /Disable-Feature /FeatureName:SearchEngine-Client-Package -NoRestart
Dism /online /Disable-Feature /FeatureName:WorkFolders-Client -NoRestart
Dism /online /Disable-Feature /FeatureName:MSRDC-Infrastructure -NoRestart
Dism /online /Disable-Feature /FeatureName:Printing-Foundation-Features -NoRestart
Dism /online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client -NoRestart
Dism /online /Disable-Feature /FeatureName:SmbDirect -NoRestart
Dism /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 -NoRestart
Dism /online /Disable-Feature /FeatureName:NetFx4-AdvSrvs -NoRestart
Dism /online /Disable-Feature /FeatureName:NetFx3 -NoRestart
Dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer -NoRestart
Dism /online /Disable-Feature /FeatureName:MediaPlayback -NoRestart
Dism /online /Enable-Feature /FeatureName:LegacyComponents -NoRestart
Dism /online /Enable-Feature /FeatureName:DirectPlay -NoRestart

:: Advertisements
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f

:: Accessibility
REG ADD "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f

:: Apps in the Background
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f

:: Automatic Driver Download
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f

:: Edge in the Background
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "SyncFavoritesBetweenIEAndMicrosoftEdge" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f

:: Privacy
PowerShell -Command "Set-WindowsSearchSetting -EnableWebResultsSetting $false"
REG ADD "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Type" /t REG_SZ /d LooselyCoupled /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "InitialAppValue" /t REG_SZ /d Unspecified /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseCredShared" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseOpen" /t REG_DWORD /d "0" /f

:: Win32PrioritySeparation
REG ADD "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "36" /f

:: Windows Services Priority
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f

:: Mouse Improvements
REG ADD "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

:: Mouse & Keyboard
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "ConnectMultiplePorts" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "MaximumPortsServiced" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "SendOutputToAllPorts" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "WppRecorder_UseTimeStamp" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ConnectMultiplePorts" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MaximumPortsServiced" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "SendOutputToAllPorts" /t Reg_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "WppRecorder_UseTimeStamp" /t Reg_DWORD /d "0" /f
REG ADD "HKCU\Control Panel\Keyboard" /v "TypematicDelay" /t REG_DWORD /d "0" /f

:: System Profile
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f

:: Nvidia
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableGR535" /t REG_DWORD /d "0" /f

:: MPO Disable
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_SZ /d "5" /f

:: Bcdedit
bcdedit /set useplatformtick yes
bcdedit /setdisabledynamictick yes
bcdedit /set tscsyncpolicy enhanced
bcdedit /deletevalue useplatformclock

:: Spectre & Meltdown
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f

:: Initialization Delay
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d "0" /f

:: Fast startup
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

:: Fix Error Default app was reset
REG ADD "HKCU\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoOpenWith" /t REG_SZ /d "" /f
REG ADD "HKCU\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f

:: Balloon Notifications
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f

:: Hide all icons in the notification area
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /d "1" /f

:: Security issues for local accounts
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "NoLocalPasswordResetQuestion" /t REG_DWORD /d "1" /f

:: Dark Mode
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f

:: Touchscreen
REG ADD "HKCU\Software\Microsoft\Wisp\Touch" /v "TouchGate" /t REG_DWORD /d "0" /f

:: Transparencies & color effects
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Control Panel\Desktop" /v "AutoColorization" /t REG_DWORD /d "0" /f

:: Remove unnecessary animations
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9032078010000000" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisablePreviewDesktop" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "1" /f

:: DWM
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationBlurBalance" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationGlassAttribute" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "DisablePreviewDesktop" /t REG_DWORD /d "1" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "1" /f

:: Power Efficiency
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalesecingTimerinterval" /t REG_SZ /d "0" /f

:: Power Plan
:: Ultimate Performace
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
:: Settings
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -hibernate-timeout-ac 0
:: Hibernation HDD/SSD
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
:: Selective USB Suspend
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
:: Low Latency & Idle
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 4b92d758-5a24-4851-a470-815d78aee119 100
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 7b224883-b3cc-4d79-819f-8374152cbe7c 100

:: Install .NET Framework 3.5
Dism /online /norestart /Enable-Feature /featureName:"NetFx3"

:: Install Legacy Component
Dism /online /norestart /Enable-Feature /featureName:"LegacyComponents"

:: Install DirectPlay
Dism /online /norestart /Enable-Feature /featureName:"DirectPlay"

:: Dark Mode Windows Win32
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColorInactive" /t REG_DWORD /d "0" /f

:: Launch apps after restarting
REG ADD "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "RestartApps" /t REG_DWORD /d "0" /f

:: Transparent tiles on Start
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v "EnabledState" /t REG_DWORD /d "2" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v "EnabledStateOptions" /t REG_DWORD /d "0" /f

:: Power Throttling
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

:: Game Scheduler
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d True /f

:: Display Scheduler
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d True /f

:: Audio Scheduler
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "2" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d Medium /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d High /f

:: Store Apps
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Get-AppxPackage | where-object {$_.name -notlike '*GamingApp*'} | where-object {$_.name -notlike '*Winget*'} |where-object {$_.name -notlike '*store*'} |  where-object {$_.name -notlike '*DesktopAppInstaller*'} | where-object {$_.name -notlike '*terminal*'} | where-object {$_.name -notlike '*RealtekSemiconductorCorp.RealtekAudioControl*'} | where-object {$_.name -notlike '*NVIDIACorp.NVIDIAControlPanel*'}  |Remove-AppxPackage"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f

:: Storage Reservation
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f

:: Action Center
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f

:: Notification
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f

:: Background Apps
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

:: Solid Color Background
REG ADD "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f

:: Focus Assist
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_ENABLED" /t REG_DWORD /d "0" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_GLEAM_ENABLED" /t REG_DWORD /d "0" /f

REM *** Special Folders ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v FolderType /t REG_SZ /d NotSpecified /f

:: Windows Defender
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d "1" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /d "1" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /d "1" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d "1" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnDisableScanOnRealtimeEnableAccessProtection" /d "1" /t REG_DWORD /f

:: Windows Update
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedFeatureStatus" /d "0" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedQualityStatus" /d "0" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "FlightSettingsMaxPauseDays" /d "3650" /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesEndTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesEndTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f

:: People bar
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /d "1" /t REG_DWORD /f

:: Copilot
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "Microsoft365CopilotChatIconEnabled" /t REG_DWORD /d "0" /f

:: Remote Assistance
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /d "0" /t REG_DWORD /f

:: GPU acceleration scheduling
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "GpuPreference" /d "2" /t REG_DWORD /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /d "2" /t REG_DWORD /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchPriority" /d "1" /t REG_DWORD /f

:: History of Quick Access
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG DELETE "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
REG DELETE "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f

:: Printscreen to open Snipping Tool
REG ADD "HKCU\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled" /d "1" /t REG_DWORD /f

:: Search the web in the search bar
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /d "1" /t REG_DWORD /f

:: SafeSearch
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f

:: Highlights in the Search bar
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /d "0" /t REG_DWORD /f

:: App Launch Monitoring
REG ADD "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f

:: Personal Dictionary
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f

:: Frequency of Comments
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f

:: Activity History
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f

:: Research History
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f

:: Search Spotlight
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f

:: Communication with unpaired Devices
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ  /d 00,00 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ  /d 00,00 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ  /d 00,00 /f

:: Access
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d Deny /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d Deny /f

:: Creating an Edge Shortcut
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d "1" /f

:: Nuclear Isolation
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "1" /f

:: VBS
REG ADD "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /d "1" /t REG_DWORD /f
REG ADD "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /d "1" /t REG_DWORD /f

:: Disable power saving for every device
POWERSHELL "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"

TIMEOUT /t 5
taskkill /f /im explorer.exe
taskkill /f /im dwm.exe
start dwm.exe
start explorer.exe
pause













