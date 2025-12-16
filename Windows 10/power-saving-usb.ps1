Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB" -Recurse -ErrorAction SilentlyContinue |
Where-Object { $_.PSChildName -eq "Device Parameters" } |
ForEach-Object {
    New-ItemProperty -Path $_.PsPath -Name "SelectiveSuspendEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $_.PsPath -Name "EnhancedPowerManagementEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
}
