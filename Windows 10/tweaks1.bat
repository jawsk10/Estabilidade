@ECHO OFF
SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
cd /D "%~dp0"

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

@rem *** Desabilitar alguns servicos ***
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

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config RemoteRegistry start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config SysMain start= disabled
sc config wuauserv start= disabled
sc config lmhosts start= disabled
sc config VSS start= disabled
sc config RemoteAccess start= disabled
sc config WSearch start= disabled
sc config iphlpsvc start= disabled
sc config DoSvc start= disabled
sc config ClickToRunSvc start= demand
sc config SEMgrSvc start= disabled
sc config BDESVC start= disabled
sc config TabletInputService start= disabled
sc config SstpSvc start= disabled
sc config NvTelemetryContainer start= disabled
sc config HomeGroupListener start= disabled
sc config HomeGroupProvider start= disabled
sc config lfsvc start= disabled
sc config MapsBroke start= disabled
sc config NetTcpPortSharing start= disabled
sc config SharedAccess start= disabled
sc config WbioSrvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config wisvc start= disabled
sc config TapiSrv start= disabled
sc config SmsRouter start= disabled
sc config SharedRealitySvc start= disabled
sc config ScDeviceEnum start= disabled
sc config SCardSvr start= disabled
sc config RetailDemo start= disabled
sc config PhoneSvc start= disabled
sc config perceptionsimulation start= disabled
sc config BTAGService start= disabled
sc config AJRouter start= disabled
sc config CDPSvc start= disabled
sc config ShellHWDetection start= disabled
sc config RstMwService start= disabled
sc config DusmSvc start= disabled
sc config BthAvctpSvc start= disabled
sc config BITS start= demand
sc config DPS start= disabled

REM *** Tweaks de tarefas agendadas ***
schtasks /Change /tN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /tN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /tN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /tN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /tN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /tN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /tN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /tN "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks /Change /tN "Microsoft\Office\Office Automatic Updates 2.0" /Disable
schtasks /Change /tN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable
schtasks /Change /tN "Microsoft\Office\Office Feature Updates" /Disable
schtasks /Change /tN "Microsoft\Office\Office Feature Updates Logon" /Disable
schtasks /Change /tN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /tN "MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks /Change /tN "MicrosoftEdgeUpdateTaskMachineUA" /Disable
schtasks /Change /tN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /tN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /tN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /tN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /tN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /tN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
schtasks /Change /tN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /tN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /tN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /tN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

REM *** Desabilitar Ultimo Acesso Arquivos ***
fsutil.exe behavior set disableLastAccess 1

REM *** Desabilitar nome arquivos 8_3 ***
fsutil.exe 8dot3name set 1

@rem *** Remover Telemetria e Coleta de Dados ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Microsoft\SQMClient\Windows /v "CEIPEnable" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d Off /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f

@REM Configuracoes -> Privacidade -> Geral -> Permitir aplicativos usar meu ID de propaganda
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
REM - Smart Screen para aplicativos da Store
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
REM - Let websites provide locally...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

@REM Desabilitar Sensor de Wifi
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f

@REM Mudar updates para notificar o agendamento de reinicializacao
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d 1 /f
@REM Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d 0 /f

@REM *** Desabilitar Cortana e Telemetria ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

REM *** Esconder a caixa de Procura da barra de Tarefas. Voce ainda pode pesquisar apertando Win + o que voce quer pesquisar. ***
REM 0 = esconder completamente, 1 = mostrar apenas ícone, 2 = Mostrar caixa completa
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

REM *** Desabilitar Jump lists dos apps XAML no menu iniciar ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

REM *** Configurar Windows Explorer para iniciar no Este Computador, ao invés de Acesso Rapido ***
REM 1 = Este Computador, 2 = Acesso Rapido
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

REM *** Desabilitar sugestoes no Menu Iniciar ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar hibernacao ***
powercfg -h off 

REM *** Desabilitar memoria virtual ***
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" delete

REM *** Desabilitar Superfetch ***
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f

REM *** Acelerar desligamento ***
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f

REM *** Desabilitar todos os icones na tray ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explore" /v "EnableAutoTray" /t REG_DWORD /d 1 /f

REM *** Tweaks Variados para o Windows ***
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d 2000 /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 5 /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d 3000 /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d 2000 /f
reg add "HKCU\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d 0000000a /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 00000001 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d 00000001 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowRun" /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FolderContentsInfoTip" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /D 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowPreviewHandlers" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f

REM *** Melhorar qualidade papel de parede ***
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 00000064 /f

REM *** Tirar animacoes inuteis ***
reg add "HKCU\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9032078010000000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisablePreviewDesktop" /t REG_DWORD /D 0 /f
reg add "HKCU\Software\Microsoft\Windows\DWM " /v "DisablePreviewDesktop" /t REG_DWORD /D 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /D 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /D 1 /f
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /D 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /D 0 /f

REM *** Melhorias no Mouse ***
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 1 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d 0 /f

REM *** Desabilitar Game Bar e DVR ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /D 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "GameDVR_Enabled" /t REG_DWORD /D 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /D 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /D 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /D 0 /f

REM *** Desabilitar Controle de Conta de Usuario *** Impacta em programas UWP, como XBOX
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /D 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /D 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /D 0 /f

REM *** Cores no iniciar e barra de tarefas ***
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "AutoColorization " /t REG_DWORD /d 0 /f

REM *** Prompt de Comando por padrao ***
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /D 1 /f

REM *** Desabilitar Protetor de tela ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /D 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_DWORD /D 0 /f

REM *** Desabilitar SmartScreen ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /D 0 /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /f

REM *** Mostrar arquivos ocultos no Explorer ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
 
REM *** Mostrar arquivos super ocultos no Explorer ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Mostrar extensoes de arquivos no Explorer ***
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

REM *** Desabilitar Armazenamento Reservado ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t  REG_DWORD /d 0 /f

REM *** Desabilitar Otimizacao de Entrega ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_SZ /d 0 /f

REM *** Desabilitar Localizacao ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d Deny /f

REM *** Desabilitar Avisos de Arquivos baixados na Internet ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Environment" /v "SEE_MASK_NOZONECHECKS" /t REG_SZ /D 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "SEE_MASK_NOZONECHECKS" /t REG_SZ /D 1 /f

REM *** Desbloquear automaticamente arquivos de internet ***
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f

REM *** Desabilitar Cortana e Websearch ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingEmailAttachments" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AutoIndexSharedFolders" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

REM *** Desabilitar Atualizacoes Automaticas de Drivers ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f

REM *** Desabilitar Propagandas ***
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar acessibilidade de teclado ***
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 506 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d 122 /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d 58 /f

REM *** Desabilitar Apps em Segundo Plano ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f

REM *** Desabilitar download automatico de drivers ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

REM *** Desabilitar Edge em Segundo Plano ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "SyncFavoritesBetweenIEAndMicrosoftEdge" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d 0 /f

REM *** Tweaks variados de privacidade ***
PowerShell -Command "Set-WindowsSearchSetting -EnableWebResultsSetting $false"
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Type" /t REG_SZ /d LooselyCoupled /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d Deny /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "InitialAppValue" /t REG_SZ /d Unspecified /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseCredShared" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseOpen" /t REG_DWORD /d 0 /f

REM *** Tweaks para Estabilidade ***
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 36 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 10 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 64 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d 64 /f

REM *** Tweaks para Bcdedit ***
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy enhanced
bcdedit /deletevalue useplatformclock

REM *** Desabilitar Spectre and Meltdown ***
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f

REM *** Desabilitar Delay de Inicializacao ***
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d 0 /f

REM *** Corrigir Erro de app padrao foi resetado ***
reg add "HKCU\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f

REM *** Desabilitar inicializacao rapida ***
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /D 0 /f

REM *** Desabilitar Notificacoes Balao ***
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /D 0 /f

REM *** Ocultar todos os icones na area de notificacao ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\Explorer" /v EnableAutoTray /t REG_DWORD /D 1 /f

REM *** Desabilitar questoes de seguranca para contas locais ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "NoLocalPasswordResetQuestion" /t REG_DWORD /D 1 /f

REM *** Melhorar Scaling ***
REG ADD "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /D 1 /f

REM *** Habilitar Modo Escuro ***
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /D 0 /f

REM *** Desabilitar Hotspot 2.0 ***
REG ADD "HKLM\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v "OsuRegistrationStatus" /t REG_DWORD /D 1 /f
REG ADD "HKLM\SYSTEM\ControlSet001\Services\icssvc" /v "Start" /t REG_DWORD /D 4 /f

REM *** Desabilitar Touchscreen ***
REG ADD "HKCU\Software\Microsoft\Wisp\Touch" /v "TouchGate" /t REG_DWORD /D 0 /f

REM *** Desabilitar Transparencias e efeitos de cores ***
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d 0 /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d 0 /f
Reg Add "HKCU\Control Panel\Desktop" /v "AutoColorization" /t REG_DWORD /d 0 /f

REM *** Plano de Energia ***
ECHO Desempenho Maximo
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
ECHO Marcando configuracoes na tomada
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -hibernate-timeout-ac 0
ECHO Desabilitar hibernacao de HD/SSD
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
ECHO Desabilitar supensao seletiva de usb
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

REM *** Instalar .NET Framework 3.5 ***
Dism /online /norestart /Enable-Feature /featureName:"NetFx3"

REM *** Instalar Componente Legado ***
Dism /online /norestart /Enable-Feature /featureName:"LegacyComponents"

REM *** Instalar DirectPlay (importante para jogos 2D antigos) ***
Dism /online /norestart /Enable-Feature /featureName:"DirectPlay"

REM *** Dark Mode Janelas Win32 ***
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d 0 /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d 0 /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColorInactive" /t REG_DWORD /d 0 /f

REM *** Desabilitar iniciar apps apos reiniciar ***
Reg Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "RestartApps" /t REG_DWORD /d 0 /f

REM *** Tiles transparentes no Iniciar ***
Reg Add "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v "EnabledState" /t REG_DWORD /d 2 /f
Reg Add "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v "EnabledStateOptions" /t REG_DWORD /d 0 /f

REM *** Desabilitar Power Throttling ***
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /D 1 /f

REM *** Otimizar Agendador para Jogos ***
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /D 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /D 18 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /D 6 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /D High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /D High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /D True /f

REM *** Otimizar Agendador para Display ***
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /D 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /D 24 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /D 18 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /D 8 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /D High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /D High /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /D True /f

REM *** Otimizar Agendador para Audio ***
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /D 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /D 8 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /D 2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /D Medium /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /D High /f

REM *** Remover Apps da Store ***
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Get-AppxPackage | where-object {$_.name -notlike '*GamingApp*'} | where-object {$_.name -notlike '*Winget*'} |where-object {$_.name -notlike '*store*'} |  where-object {$_.name -notlike '*DesktopAppInstaller*'} |where-object {$_.name -notlike '*xbox*'} | where-object {$_.name -notlike '*terminal*'} | where-object {$_.name -notlike '*RealtekSemiconductorCorp.RealtekAudioControl*'} | where-object {$_.name -notlike '*NVIDIACorp.NVIDIAControlPanel*'}  |Remove-AppxPackage"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

REM *** Desabilitar reserva de armazenamento ***
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d 0 /f

REM *** Desabilitar centro de notificacoes ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f

REM *** Desabilitar aplicativos em segundo plano ***
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f
Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d 0 /f

REM *** Background em Cor Solida ***
REG ADD "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f

REM *** Desabilitar pastas especiais, como Musica ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v FolderType /t REG_SZ /D NotSpecified /f

REM *** Desabilitar Windows Defender ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d 1 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /d 1 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /d 1 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /d 1 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnDisableScanOnRealtimeEnableAccessProtection" /d 1 /t REG_DWORD /f

REM *** Desabilitar Windows Update ***
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedFeatureStatus" /d 0 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedQualityStatus" /d 0 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "FlightSettingsMaxPauseDays" /d 3650 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesEndTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesEndTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesStartTime" /d "2023-11-06T14:03:37Z" /t REG_SZ /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /d "2033-10-31T14:03:37Z" /t REG_SZ /f

REM *** Desabilitar barra de pessoas ***
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /d 1 /t REG_DWORD /f

REM *** Desabilitar Assistencia Remota ***
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /d 0 /t REG_DWORD /f

REM *** Habilitar agendamento de aceleracao de GPU ***
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /d 2 /t REG_DWORD /f

REM *** Desabilitar Historico do Acesso Rapido ***
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f

REM *** Habilitar Printscreen para abrir Snipping Tool ***
REG ADD "HKCU\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled" /d 1 /t REG_DWORD /f

REM *** Alterar Tamanho de Cache de Icones ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /d 4096 /t REG_SZ  /f

REM *** Desabilitar busca Web na barra de Pesquisa ***
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /d 1 /t REG_DWORD /f

REM *** Desabilitar Highlights na barra de Pesquisa ***
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /d 0 /t REG_DWORD /f

REM *** Desabilitar escrita de Cache de navegadores e streaming ***
taskkill /f /im msedge.exe
REM Google Chrome
del /s /q "%userprofile%\AppData\Local\Google\Chrome\User Data\Default\Cache"
icacls "%userprofile%\AppData\Local\Google\Chrome\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Microsoft Edge
del /s /q "%userprofile%\AppData\Local\Microsoft\Edge\User Data\Default\Cache"
icacls "%userprofile%\AppData\Local\Microsoft\Edge\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Mozilla Firefox
cd "%userprofile%\AppData\Local\Mozilla\Firefox\Profiles\*default-release"
del /s /q cache2
icacls cache2 /deny *S-1-1-0:(F)
REM Spotify
del /s /q "%LocalAppData%\Spotify\Storage"
icacls "%%LocalAppData%\Spotify\Storage" /deny *S-1-1-0:(F)

REM *** Desabilitar Cliente DNS ***
REM reg add "HKLM\System\CurrentControlSet\services\Dnscache" /v "Start" /t REG_DWORD /d 4 /f

REM *** Desabilitar Acompanhamento de Lancamento de Aplicativos ***
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f

REM *** Desabilitar dicionario pessoal ***
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

REM *** Desabilitar frequencia de comentarios ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

REM *** Desabilitar historico de atividades ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f

REM *** Desabilitar historico de pesquisa ***
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar destaque de pesquisa ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d 0 /f

REM *** Desabilitar comunicacao com dispositivos nao pareados ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ  /d 00,00 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ  /d 00,00 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ  /d 00,00 /f

REM *** Desabilitar acessos ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d Deny /f

REM *** Desabilitar Criacao de Atalho do Edge ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d 1 /f

REM *** Habilitar Isolamento de Nucleo ***
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f

REM *** Habilitar VBS ***
REG ADD "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /d 1 /t REG_DWORD /f

TIMEOUT /t 5
taskkill /f /im explorer.exe
start explorer.exe








