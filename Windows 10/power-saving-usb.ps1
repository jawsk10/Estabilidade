$hubs = Get-CimInstance -ClassName Win32_SerialPort | Select-Object Name, DeviceID, Description
$powerMgmt = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi

foreach ($p in $powerMgmt) {
    $IN = $p.InstanceName.ToUpper()
    foreach ($h in $hubs) {
        $PNPDI = $h.PNPDeviceID
        if ($IN -like "*$PNPDI*") {
            Set-CimInstance -InputObject $p -Property @{Enable = $false}
        }
    }
}
