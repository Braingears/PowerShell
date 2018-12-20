### Uninstall Single Application (by Identifying Number)
$App = "Google Chrome"
$AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -eq $App} | Select-Object -ExpandProperty "IdentifyingNumber"
    Write-Output ""
    if($AppLocalPackage -eq $null) {write "$($App) Not Installed"} Else {Write-Output "Uninstalling $($App) - msiexec /x $($AppLocalPackage) /qn /norestart"
    msiexec /x $AppLocalPackage /qn /norestart
    Start-Sleep 5
    $AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -eq $App} | Select-Object -ExpandProperty "IdentifyingNumber"
    if($AppLocalPackage -eq $null) {write "$($App) Successfully Uninstalled"} Else {write "$($App) is still installed on this computer"}
    }
