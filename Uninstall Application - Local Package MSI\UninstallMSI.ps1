### Uninstall Single Application (by Local Package MSI)
$App = "Google Chrome"
$AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -eq $App} | Select-Object -ExpandProperty "LocalPackage"
    Write-Output ""
    if($AppLocalPackage -eq $null) {write "$($App) Not Installed"} Else {Write-Output "Uninstalling $($App) - msiexec /x $($AppLocalPackage) /qn /norestart"
    msiexec /x $AppLocalPackage /qn /norestart
    Start-Sleep 10
    $AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -eq $App} | Select-Object -ExpandProperty "LocalPackage"
    if($AppLocalPackage -eq $null) {Write-Host "$($App) Successfully Uninstalled" -ForegroundColor Green} Else {Write-Host "$($App) is still installed on this computer" -ForegroundColor Red}
    }
