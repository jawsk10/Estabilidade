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
sc stop GraphicsPerfSvc
sc stop hidserv

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
sc config GraphicsPerfSvc start=disabled
sc config hidserv start=disabled

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
schtasks /Change /tN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /tN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /Change /tN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /disable
schtasks /Change /tN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /tN "Microsoft\XblGameSave\XblGameSaveTask" /disable

:: Adapter
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f

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
fsutil behavior set disabledeletenotify 0

:: Encrypt Paging File
fsutil behavior set encryptpagingfile 0

:: Get-MMAgent
powershell -Command "Disable-MMAgent -PageCombining"
powershell -Command "Disable-MMAgent -MemoryCompression"

