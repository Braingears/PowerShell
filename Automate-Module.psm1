<#
.SYNOPSIS
    These PowerShell Functions will Install, Push, Uninstall, and Confirm ConnectWise Automate installations. 
        
.DESCRIPTION
    Functions Included:
        Confirm-Automate
        Uninstall-Automate
        Install-Automate
        Push-Automate
        Get-ADComputerNames
        Install-Chrome
        Install-Manage
        Scan-Network
        
        New-IPRange
        http://powershell.com/cs/media/p/9437.aspx
        
        Invoke-Ping
        https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a
        
        Get-IPv4Subnet
        https://github.com/briansworth/GetIPv4Address/blob/master/GetIPv4Subnet.psm1

.LINK
    https://github.com/Braingears/PowerShell
    
.NOTES
    File Name      : Automate-Module.psm1
    Author         : Chuck Fowler (Chuck@Braingears.com)
    Version        : 1.0
    Creation Date  : 11/10/2019
    Purpose/Change : Initial script development
    Prerequisite   : PowerShell V2
    
    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly. 
    
    
.EXAMPLE
    Confirm-Automate [-Silent]

    Confirm-Automate [-Show]
    
.EXAMPLE
    Uninstall-Automate [-Silent]
    
.EXAMPLE
    Install-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' [-Show]
    
.Example
    To push a single Automate Agent:
    Push-Automate -Computer 'ComputerName' -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    
    For multiple computers, use a | "pipe" into Push-Automate function:
    $Computers | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    - or - 
     Scan-Network | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'   
    - or -
    Get-ADComputerNames | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    - or - 
    "Computer1", "Computer2" | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    
#>
Function Confirm-Automate {
<#
.SYNOPSIS
    This PowerShell Function will confirm If Automate is installed, services running, and checking-in. 

.DESCRIPTION
    This function will automatically start the Automate services (If stopped). It will collect Automate information from the registry.

.PARAMETER Raw
    This will show the Automate registry entries

.PARAMETER Show
    This will display $Automate object

.PARAMETER Silent
    This will hide all output

.LINK
    https://github.com/Braingears/PowerShell
    
.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/16/2019
    Purpose/Change : Initial script development

    Version        : 1.1    
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly. 

    Version        : 1.2    
    Date           : 04/02/2020
    Changes        : Add $Automate.Service -eq $null
                     If the service still exists, the installation is failing with Exit Code 1638.                     
                     
.EXAMPLE
    Confirm-Automate [-Silent]

    Confirm-Automate [-Show]
    
    ServerAddress : https://yourserver.hostedrmm.com
    ComputerID    : 321
    ClientID      : 1
    LocationID    : 2
    Version       : 190.221
    Service       : Running
    Online        : True
    LastHeartbeat : 29
    LastStatus    : 36

    $Automate 
    $Global:Automate
    This output will be saved to $Automate as an object to be used in other functions. 
    

#>
 [CmdletBinding(SupportsShouldProcess=$True)]
    Param (
        [switch]$Raw    = $False,
        [switch]$Show   = $False,
        [switch]$Silent = $False
    )
    $ErrorActionPreference = 'SilentlyContinue'
    if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus) {
        $Online = If ((Test-Path "HKLM:\SOFTWARE\LabTech\Service") -and ((Get-Service ltservice).status) -eq "Running") {((((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus)).TotalSeconds) -lt 600)} Else {Write $False}
    } else {$Online = $False}

    If (Test-Path "HKLM:\SOFTWARE\LabTech\Service") {
        $Global:Automate = New-Object -TypeName psobject
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:ComputerName
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ServerAddress -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").'Server Address')
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ClientID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ClientID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name LocationID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LocationID)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Version -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").Version)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstFolder -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstRegistry -Value $True      
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service LTService).Status)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent) {
            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastHeartbeat -Value ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent)).TotalSeconds)
        }
        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus) {
            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastStatus -Value    ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus)).TotalSeconds)
        }
        Write-Verbose $Global:Automate
        If ($Show) {
            $Global:Automate
        } Else {
            If (!$Silent) {
                Write "Server Address checking-in to    $($Global:Automate.ServerAddress)"
                Write "ComputerID:                      $($Global:Automate.ComputerID)"
                Write "The Automate Agent Online        $($Global:Automate.Online)"        
                Write "Last Successful Heartbeat        $($Global:Automate.LastHeartbeat) seconds"
                Write "Last Successful Status Update    $($Global:Automate.LastStatus) seconds"
            } # End Not Silent
        } # End If
        If ($Raw -eq $True) {Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service"}
    } Else {
        $Global:Automate = New-Object -TypeName psobject
        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerName -Value $env:ComputerName
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstFolder -Value (Test-Path "$($env:windir)\ltsvc")
        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstRegistry -Value $False      
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value ((Test-Path "$($env:windir)\ltsvc") -and (Test-Path "HKLM:\SOFTWARE\LabTech\Service"))
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service ltservice ).status)
        $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
        Write-Verbose $Global:Automate
    } #End If Registry Exists
    If (!$Global:Automate.InstFolder -and !$Global:Automate.InstRegistry -and ($Global:Automate.Service -eq $Null)) {If ($Silent -eq $False) {Write "Automate is NOT Installed"}}
} #End Function Confirm-Automate
########################
Set-Alias -Name LTC -Value Confirm-Automate -Description 'Confirm If Automate is running properly'
########################
Function Uninstall-Automate {
<#
.SYNOPSIS
    This PowerShell Function Uninstall Automate. 

.DESCRIPTION
    This function will download the Automate Uninstaller from Connectwise and completely remove the Automate / LabTech Agent. 
    
.PARAMETER Silent
    This will hide all output

.LINK
    https://github.com/Braingears/PowerShell
    
.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Website        : braingears.com
    Creation Date  : 8/2019
    Purpose        : Create initial function script

    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                     If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.  
                     
    Version        : 1.2    
    Date           : 04/02/2020
    Changes        : Add $Automate.Service -eq $null
                     If the service still exists, the installation is failing with Exit Code 1638. 
                     
.EXAMPLE
    Uninstall-Automate [-Silent]


#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param (
     [switch]$Force,
     [switch]$Raw,
     [switch]$Show,
     [switch]$Silent = $False
     )
$ErrorActionPreference = 'SilentlyContinue'
$Verbose = If ($PSBoundParameters.Verbose -eq $True) { $True } Else { $False }
$DownloadPath = "https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
If ((([Int][System.Environment]::OSVersion.Version.Build) -gt 6000) -and ((get-host).Version.ToString() -ge 3)) {
    $DownloadPath = "https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
} Else {
    $DownloadPath = "http://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
}
$SoftwarePath = "C:\Support\Automate"
$UninstallApps = @(
    "ConnectWise Automate Remote Agent"
    "LabTech® Software Remote Agent"
    )
Write-Debug "Checking if Automate Installed"
Confirm-Automate -Silent -Verbose:$Verbose
    If (($Global:Automate.InstFolder) -or ($Global:Automate.InstRegistry) -or (!($Global:Automate.Service -eq $Null)) -or ($Force)) {
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    If (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
    Set-Location $SoftwarePath
    If ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
    If (!$Silent) {Write-Host "Removing Existing Automate Agent..."}
    Write-Verbose "Closing Open Applications and Stopping Services"
    Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force 
    Stop-Service ltservice,ltsvcmon -Force
    $UninstallExitCode = (Start-Process "cmd" -ArgumentList "/c $($SoftwareFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
    If (!$Silent) {
        If ($UninstallExitCode -eq 0) {
          # Write-Host "The Automate Agent Uninstaller Executed Without Errors" -ForegroundColor Green
            Write-Verbose "The Automate Agent Uninstaller Executed Without Errors"
        } Else {
            Write-Host "Automate Uninstall Exit Code: $($UninstallExitCode)" -ForegroundColor Red
            Write-Verbose "Automate Uninstall Exit Code: $($UninstallExitCode)"
        }
    }
    Write-Verbose "Checking For Removal - Loop 5X"
    While ($Counter -ne 6) {
        $Counter++
        Start-Sleep 10
        Confirm-Automate -Silent -Verbose:$Verbose
        If ((!$Global:Automate.InstFolder) -and (!$Global:Automate.InstRegistry) -and ($Global:Automate.Service -eq $Null)) {
            Write-Verbose "Automate Uninstaller Completed Successfully"
            Break
        }
    }# end While
    If (($Global:Automate.InstFolder) -or ($Global:Automate.InstRegistry) -or (!($Global:Automate.Service -eq $Null))) {
        Write-Verbose "Uninstaller Failed"
        Write-Verbose "Manually Gutting Automate..."
        If (!(($Global:Automate.Service -eq $Null) -or ($Global:Automate.Service -eq "Stopped"))) {
            Write-Verbose "LTService Service not Stopped. Disabling LTService Service"
            Set-Service ltservice -StartupType Disabled
            Stop-Service ltservice,ltsvcmon -Force
        }    
        Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force 
        Write-Verbose "Uninstalling LabTechAD Package"
        $UninstallApps2 = foreach ($App in $UninstallApps) {Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -like $App} | Select-Object -ExpandProperty "Name"}
        $UninstallAppsFound = $UninstallApps2 | Select-Object -Unique
        foreach ($App in $UninstallAppsFound) {
            $AppLocalPackage = Get-WmiObject -Class Win32_Product -ComputerName . | Where-Object -FilterScript {$_.Name -like $App} | Select-Object -ExpandProperty "LocalPackage"
            If ($AppLocalPackage -eq $null) {
                Write-Verbose "$($App) - Not Installed"
            } Else {
                Write-Verbose "Uninstalling: $($App) - msiexec /x $($AppLocalPackage) /qn /norestart"
                msiexec /x $AppLocalPackage /qn /norestart
            }
        }
        Remove-Item "$($env:windir)\ltsvc" -Recurse -Force
        Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service" | Remove-Item -Recurse -Force
        REG Delete HKLM\SOFTWARE\LabTech\Service /f | Out-Null
        Start-Process "cmd" -ArgumentList "/c $($SoftwareFullPath)" -NoNewWindow -Wait -PassThru | Out-Null
        Confirm-Automate -Silent -Verbose:$Verbose
        If ($Global:Automate.InstFolder) {
            If (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "$($env:windir)\ltsvc folder still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "$($env:windir)\ltsvc folder still exists"
            }
        }
        If ($Global:Automate.InstRegistry) {
            If (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "HKLM:\SOFTWARE\LabTech\Service Registry keys still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "HKLM:\SOFTWARE\LabTech\Service Registry keys still exists"
            }
        }
         If (!($Global:Automate.Service -eq $Null)) {
            If (!$Silent) {
                Write-Host "Automate Uninstall Failed" -ForegroundColor Red
                Write-Host "LTService Service still exists" -ForegroundColor Red
            } else {
                Write-Verbose "Automate Uninstall Failed"
                Write-Verbose "LTService Service still exists"
            }
        }
    } Else {
        If (!$Silent) {Write-Host "The Automate Agent Uninstalled Successfully" -ForegroundColor Green}
        Write-Verbose "The Automate Agent Uninstalled Successfully"
    }
} # If Test Install
    Confirm-Automate -Silent:$Silent
} # Function Uninstall-Automate
########################
Set-Alias -Name LTU -Value Uninstall-Automate -Description 'Uninstall Automate Agent'
########################
Function Install-Automate {
<#
.SYNOPSIS
    This PowerShell Function is for Automate Deployments

.DESCRIPTION
    Install the Automate Agent.
    
    This function will qualIfy the If another Autoamte agent is already 
    installed on the computer. If the existing agent belongs to dIfferent 
    Automate server, it will automatically "Rip & Replace" the existing 
    agent. This comparison is based on the server's FQDN. 
    
    This function will also verIfy If the existing Automate agent is 
    checking-in. The Confirm-Automate Function will verIfy the Server 
    address, LocationID, and Heartbeat/Check-in. If these entries are 
    missing or not checking-in properly; this function will automatically 
    attempt to restart the services, and then "Rip & Replace" the agent to 
    remediate the agent. 
    
    $Automate 
    $Global:Automate
    The output will be saved to $Automate as an object to be used in other functions.
    
    Example:
    Install-Automate -Server YOURSERVER.DOMAIN.COM -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Transcript
    
    
    Tested OS:      Windows XP (with .Net 3.5.1 and PowerShell installed)
                    Windows Vista
                    Windows 7
                    Windows 8
                    Windows 10
                    Windows 2003R2
                    Windows 2008R2
                    Windows 2012R2
                    Windows 2016
                    Windows 2019

.PARAMETER Server
    This is the URL to your Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token 'adb68881994ed93960346478303476f4'

.PARAMETER LocationID
    Use LocationID to install the Automate Agent directly to the appropieate client's location / site.
    If parameter is not specIfied, it will automatically assign LocationID 1 (New Computers).

.PARAMETER Token
    Use Token to install the Automate Agent directly to the appropieate client's location / site.
    If parameter is not specIfied, it will automatically attempt to use direct unauthenticated downloads.
    This method in blocked after Automate v20.0.6.178 (Patch 6)
    
.PARAMETER Force
    This will force the Automate Uninstaller prior to installation.
    Essentually, this will be a fresh install and a fresh check-in to the Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Force

.PARAMETER Silent
    This will hide all output (except a failed installation when Exit Code -ne 0)
    The function will exit once the installer has completed.
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Silent
    
.PARAMETER Transcript
    This parameter will save the entire transcript and responsed to:
    $($env:windir)\Temp\AutomateLogon.txt
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token 'adb68881994ed93960346478303476f4' -Transcript -Verbose

.LINK
    https://github.com/Braingears/PowerShell
    
.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/2019
    Purpose/Change : Initial script development
    
    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                     If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.
    
    Version        : 1.2
    Date           : 02/17/2020
    Changes        : Add MSIEXEC Log Files to C:\Windows\Temp\Automate_Agent_(Date).log

    Version        : 1.3
    Date           : 05/26/2020
    Changes        : Look for and replace "Enter the server address here" with the actual Automate Server address. 

    Version        : 1.4
    Date           : 06/29/2020
    Changes        : Added Token Parameter for Deployment 

    Version        : 1.5
    Date           : 06/09/2021
    Changes        : Attempt to Restart the LTService prior to R&R
                     It was found that the Rip & Replace was being too aggressive without at least trying to restart the LTService 
                     and waiting for it to check-in.
                     
.EXAMPLE
    Install-Automate -Server 'automate.domain.com' -LocationID 42 -Token 'adb68881994ed93960346478303476f4'
    This will install the LabTech agent using the provided Server URL, LocationID, and required Token. 


#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=0)]
        [Alias("FQDN","Srv")]
        [string[]]$Server = $Null,
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=1)]
        [AllowNull()]
        [Alias('LID','Location')]
        [int]$LocationID = '1',
        [Parameter(ValueFromPipelineByPropertyName = $True, Position=2)]
        [Alias("InstallerToken")]
        [string[]]$Token = $Null,
        [switch]$Force,
        [Parameter()]
        [AllowNull()]
        [switch]$Show = $False,
        [switch]$Silent,
        [Parameter()]
        [AllowNull()]
        [switch]$Transcript = $False
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $Verbose = If ($PSBoundParameters.Verbose -eq $True) { $True } Else { $False }
    $Error.Clear()
    If ($Transcript) {Start-Transcript -Path "$($env:windir)\Temp\Automate_Deploy.txt" -Force}
    $SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
    $SoftwarePath = "C:\Support\Automate"
    $Filename = "Automate_Agent.msi"
    $SoftwareFullPath = "$SoftwarePath\$Filename"
    $AutomateURL = "https://$($Server)"
    
    Write-Verbose "Checking Operating System (WinXP and Older)"
    If ([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -lt 6000) {
        $OS = ((Get-WmiObject Win32_OperatingSystem).Caption)
        Write-Host "This computer is running $($OS), and is no longer officially supported by ConnectWise Automate" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_Windows_XP_and_Server_2003_End_of_Life" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    Try {
        Write-Verbose "Enabling downloads to use SSL/TLS v1.2"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    Catch {
        Write-Verbose "Failed to enable SSL/TLS v1.2"
        Write-Host "This computer is not configured for SSL/TLS v1.2" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_TLS_1.0_and_1.1_Protocols_Unsupported" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }

    Try {
        $AutomateURLTest = "$($AutomateURL)/LabTech/"
        $TestURL = (New-Object Net.WebClient).DownloadString($AutomateURLTest)
        Write-Verbose "$AutomateURL is Active"
    }
    Catch {
        Write-Verbose "Could not download from $($AutomateURL). Switching to http://$($Server)"
        $AutomateURL = "http://$($Server)"
    }
    
    $DownloadPath = $null
    If ($Token -ne $null) {
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?InstallerToken=$Token"
        Write-Verbose "Downloading from: $($DownloadPath)"
    }
    else {
        Write-Verbose "A -Token <String[]> was not entered"
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$($LocationID)"
        Write-Verbose "Downloading from (Old): $($DownloadPath)"
    }   
    Confirm-Automate -Silent -Verbose:$Verbose
    If (($Global:Automate.Service -eq 'Stopped') -and ($Global:Automate.ServerAddress -like "*$($Server)*") -and !($Force)) {
        Try {
            Write-Verbose "LTService service is Stopped"
            Write-Verbose "LTService service is Restarting"
            Start-Service LTService -ErrorAction Stop
        }
        Catch {
            Write-Verbose "LTService service Restart Failed"
        }            
        If (((Get-Service LTService).Status) -eq "Running") {
            Write-Verbose "LTService was successfully Restarted"
            Write-Verbose "Now waiting for the Automate Agent to attempt to check-in - Loop 10X"
            $Count = 0
            While ($Count -ne 10) {
                $Count++
                Start-Sleep 6
                Confirm-Automate -Silent -Verbose:$Verbose
                If ($Global:Automate.Online) {
                    If (!$Silent) {Write-Host "LTService service was successfully Restarted"}                    
                    Break
                }
            }# End While
        } Else {
            Write-Verbose "LTService service did not return to a running status"
        }
    } # If LTService is Stopped     
    
    Write-Verbose "Checking if server address matches and if Automate Agent is Online"
    Write-Verbose (($Global:Automate.ServerAddress -like "*$($Server)*") -and ($Global:Automate.Online) -and !($Force))
    If (($Global:Automate.ServerAddress -like "*$($Server)*") -and $Global:Automate.Online -and !$Force) {
        If (!$Silent) {
            If ($Show) {
              $Global:Automate
            } Else {
              Write-Host "The Automate Agent is already installed on $($Global:Automate.Computername) ($($Global:Automate.ComputerID)) and checked-in $($Global:Automate.LastStatus) seconds ago to $($Global:Automate.ServerAddress)" -ForegroundColor Green
            }
        }
    } Else {
        If (!$Silent -and $Global:Automate.Online -and (!($Global:Automate.ServerAddress -like "*$($Server)*"))) {
            Write-Host "The Existing Automate Server Does Not Match The Target Automate Server." -ForegroundColor Red
            Write-Host "Current Automate Server: $($Global:Automate.ServerAddress)" -ForegroundColor Red
            Write-Host "New Automate Server:     $($AutomateURL)" -ForegroundColor Green
        } # If Different Server 
        Write-Verbose "Downloading Automate Agent from $($AutomateURL)"
            If (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
            Set-Location $SoftwarePath
            If ((test-path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
            Try {
                Write-Verbose "Downloading from: $($DownloadPath)"
                Write-Verbose "Downloading to:   $($SoftwareFullPath)"
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
                Write-Verbose "Download Complete"
            }
            Catch {
                Write-Host "The Automate Server was inaccessible or the Token Parameters were not entered or valid. Failed to Download:" -ForegroundColor Red
                Write-Host $DownloadPath -ForegroundColor Red
                Write-Host "Help: Get-Help Install-Automate -Full"
                Write-Host "Exiting Installation..."    
                Break                
            }
            
            Write-Verbose "Removing Existing Automate Agent"
            Uninstall-Automate -Force:$Force -Silent:$Silent -Verbose:$Verbose
            If (!$Silent) {Write-Host "Installing Automate Agent to $AutomateURL"}
            Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force -PassThru
            $Date = (get-date -UFormat %Y-%m-%d_%H-%M-%S)
            $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
            $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /L*V $($LogFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
            Write-Verbose "MSIEXEC Log Files: $LogFullPath"
            If ($InstallExitCode -eq 0) {
                If (!$Silent) {Write-Verbose "The Automate Agent Installer Executed Without Errors"}
            } Else {
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Red
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Red
                Write-Host "The Automate MSI failed. Waiting 15 Seconds..." -ForegroundColor Red
                Start-Sleep -s 15
                Write-Host "Installer will execute twice (KI 12002617)" -ForegroundColor Yellow
                $Date = (get-date -UFormat %Y-%m-%d_%H-%M-%S)
                $LogFullPath = "$env:windir\Temp\Automate_Agent_$Date.log"
                $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID) SERVERADDRESS=$($AutomateURL) /L*V $($LogFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Yellow
                Write-Host "Automate Installer Logs: $LogFullPath" -ForegroundColor Yellow
            }# End Else
        If ($InstallExitCode -eq 0) {
            While ($Counter -ne 30) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                If ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                If ($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null) {
                    If (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end If Silent
                    Break
                } # end If
            }# end While
        } Else {
            While ($Counter -ne 3) {
                $Counter++
                Start-Sleep 10
                Confirm-Automate -Silent -Verbose:$Verbose
                If ($Global:Automate.Server -like "Enter the server address here*") {
                    Write-Verbose "The Automate Server Address was not written properly"
                    Write-Verbose "Manually overwriting the Server Address to: $($AutomateURL)"
                    Set-ItemProperty -Path HKLM:\SOFTWARE\LabTech\Service 'Server Address' -Value $AutomateURL –Force
                    Write-Verbose "Restarting LTService after correcting the Server Address"
                    Get-Service LTService | Where {$_.Status -eq "Running"} | Restart-Service -Force
                    Confirm-Automate -Silent -Verbose:$Verbose
                }
                If ($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null) {
                    If (!$Silent) {
                        Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
                        $Global:Automate
                    }#end If Silent
                    Break
                } # end If
            } # end While
        } # end If ExitCode 0
        Confirm-Automate -Silent -Verbose:$Verbose
        If (!($Global:Automate.Online -and $Global:Automate.ComputerID -ne $Null)) {
            If (!$Silent) {
                    Write-Host "The Automate Agent FAILED to Install" -ForegroundColor Red
                    $Global:Automate
            }# end If Silent
        } # end If Not Online
    } # End 
    If ($Transcript) {Stop-Transcript}
} #End Function Install-Automate
########################
Set-Alias -Name LTI -Value Install-Automate -Description 'Install Automate Agent'
########################
Function Push-Automate
{
<#
.SYNOPSIS
    This PowerShell Function is for pushing Automate Deployments

.DESCRIPTION
    Install the Automate Agent.
    
    This function will qualIfy the If another Autoamte agent is already 
    installed on the computer. If the existing agent belongs to dIfferent 
    Automate server, it will automatically "Rip & Replace" the existing 
    agent. This comparison is based on the server's FQDN. 
    
    This function will also verIfy If the existing Automate agent is 
    checking-in. The Confirm-Automate Function will verIfy the Server 
    address, LocationID, and Heartbeat/Check-in. If these entries are 
    missing or not checking-in properly; this function will automatically 
    attempt to restart the services, and then "Rip & Replace" the agent to 
    remediate the agent. 
    
    $AutoResults 
    $Global:AutoResults
    The output will be saved to $AutoResults as an object to be used in other functions.
    
    Example:
    To push a single Automate Agent:
    Push-Automate -Computer 'Computername' -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    
    For multiple computers, use a | "pipe" into Push-Automate function:
    $Computers | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    - or - 
    Get-ADComputerNames | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    - or - 
    "Computer1", "Computer2" | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd'
    
    When pushing to multiple computers, use the actual computer names. If you use IP Address, it will fail when using WINRM Protocols (and use WMI/RCP instead).
                    
.PARAMETER Server
    This is the URL to your Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2

.PARAMETER LocationID
    Use LocationID to install the Automate Agent directly to the appropieate client's location / site.
    If parameter is not specIfied, it will automatically assign LocationID 1 (New Computers).
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token adb68881994ed93960346478303476f4

.PARAMETER Username
    Enter username with Domain Admin rights. When entering username, use 'DOMAIN\USERNAME'

    The function will accept PSCredentials saved to $Credentials prior to running this function. 
    
.PARAMETER Password
    Enter Password for Domain Admin account. 
    
    The function will accept PSCredentials saved to $Credentials prior to running this function. 

.PARAMETER Force
    >>> This Function Is Currently Disabled <<<
    This will force the Automate Uninstaller prior to installation.
    Essentually, this will be a fresh install and a fresh check-in to the Automate server.
    
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Force

.PARAMETER Silent
    >>> This Function Is Currently Disabled <<<
    This will hide all output (except a failed installation when Exit Code -ne 0)
    The function will exit once the installer has completed.
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Silent
    
.PARAMETER Transcript
    >>> This Function Is Currently Disabled <<<
    This parameter will save the entire transcript and responsed to:
    $($env:windir)\Temp\AutomateLogon.txt
        
        Install-Automate -Server 'server.hostedrmm.com' -LocationID 2 -Token adb68881994ed93960346478303476f4 -Transcript -Verbose

.LINK
    https://github.com/Braingears/PowerShell

.NOTES
    Version        : 1.0
    Author         : Chuck Fowler
    Creation Date  : 08/2019
    Purpose/Change : Initial script development
    
    Version        : 1.1
    Date           : 11/15/2019
    Changes        : Add $Automate.InstFolder and $Automate.InstRegistry and check for both to be consdered for $Automate.Installed
                     It was found that the Automate Uninstaller EXE is leaving behind the LabTech registry keys and it was not being detected properly.
                     If the LTSVC Folder or Registry keys are found after the uninstaller runs, the script now performs a manual gutting via PowerShell.
                     
                     
.EXAMPLE
    Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd' -Token adb68881994ed93960346478303476f4 -Computer COMPUTERNAME
    
    Use the -Computer parameter for single computers. 
    
.EXAMPLE
    $Computers | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd' -Token adb68881994ed93960346478303476f4
    
    Use Array to pipe multiple computers into Push=Automate function. 
    
.EXAMPLE
    Get-ADComputerNames | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd' -Token adb68881994ed93960346478303476f4
    
    Use another function to pipe multiple computers into Push=Automate function. Select only computer names. 

.EXAMPLE
    "Computer1", "Computer2" | Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Username 'DOMAIN\USERNAME' -Password 'Ch@ng3P@ssw0rd' -Token adb68881994ed93960346478303476f4
    
    When pushing to multiple computers, use the actual computer names. If you use IP Address, it will fail when using WINRM Protocols (and use WMI/RCP instead).
    This will install the LabTech agent using the provided Server URL, and LocationID.

.EXAMPLE
    $Credential = Get-Credential
    Push-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Token adb68881994ed93960346478303476f4
    
    You can proactivly load PSCredential, then use the Push-Automate function within the same Powershell session. 


#>
[CmdletBinding()]
Param
(
    [Parameter(ValueFromPipeline=$True)]
    [string[]]$Computer = $env:COMPUTERNAME,
    [Parameter()]
    [Alias("FQDN","Srv")]
    [string[]]$Server = $Null,
    [Parameter()]
    [AllowNull()]
    [Alias('LID','Location')]
    [int]$LocationID = '1',
    [Parameter()]
    [Alias("InstallerToken")]
    [string[]]$Token = $Null,
    [Parameter()]
    [AllowNull()]
    [Alias('User')]
    [string[]]$Username,
    [Parameter()]
    [AllowNull()]
    [Alias('Pass')]
    [string[]]$Password,
    [Parameter()]
    [AllowNull()]
    [switch]$Force = $False,
    [Parameter()]
    [AllowNull()]
    [switch]$Show = $False,
    [Parameter()]
    [AllowNull()]
    [switch]$Silent = $False,
    [Parameter()]
    [AllowNull()]
    [switch]$Transcript = $False
)
BEGIN
{
    $ErrorActionPreference = "SilentlyContinue"
    $Verbose = If ($PSBoundParameters.Verbose -eq $True) { $True } Else { $False }

    $AutomateURL = "https://$($Server)"
   
    Write-Verbose "Checking Operating System"
    If ([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -lt 6000) {
        $OS = ((Get-WmiObject Win32_OperatingSystem).Caption)
        Write-Host "This computer is running $($OS), and is no longer officially supported by ConnectWise Automate" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_Windows_XP_and_Server_2003_End_of_Life" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    Try {
        Write-Verbose "Enabling downloads to use SSL/TLS v1.2"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    Catch {
        Write-Verbose "Failed to enable SSL/TLS v1.2"
        Write-Host "This computer is not configured for SSL/TLS v1.2" -ForegroundColor Red
        Write-Host "https://docs.connectwise.com/ConnectWise_Automate/ConnectWise_Automate_Supportability_Statements/Supportability_Statement:_TLS_1.0_and_1.1_Protocols_Unsupported" -ForegroundColor Red
        Write-Host ""
        $AutomateURL = "https://$($Server)"
    }
    
    Try {
        $AutomateURLTest = "$($AutomateURL)/LabTech/"
        $TestURL = (New-Object Net.WebClient).DownloadString($AutomateURLTest)
        Write-Verbose "$AutomateURL is Active"
    }
    Catch {
        Write-Verbose "Could not download from $($AutomateURL). Switching to http://$($Server)"
        $AutomateURL = "http://$($Server)"
    }
    
    $DownloadPath = $null
    If ($Token -ne $null) {
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?InstallerToken=$Token"
        Write-Verbose "Downloading from: $($DownloadPath)"
    }
    else {
        Write-Verbose "A -Token <String[]> was not entered"
        $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$($LocationID)"
        Write-Verbose "Downloading from (Old): $($DownloadPath)"
    }

    $Whoami = whoami
    Write-Verbose "Running Script as: $whoami"
    If (($Username -eq $Null) -and ($Password -eq $Null) -and ($Credential -eq $Null) -and !((whoami) -eq 'nt authority\system'))
        {$Credential = Get-Credential -Message "Enter Domain Admin Credentials for Remote Automate Push"}
    If (($Username -ne $Null) -and ($Password -ne $Null)) {
        $Pass = $Password | ConvertTo-SecureString -asPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($Username,$Pass)
    }
    If ($Credential -eq $Null) {
        If ((whoami) -eq 'nt authority\system') {Write-Host "Running function as $($Whoami)"}
        Write-Host "Credentials Are Missing!" -ForegroundColor Red
        Clear-Variable Computer, Server, Force, Silent
        Break
    }
    Write-Verbose "Credential loaded: $($Credential.Username)"
    $Global:AutoChecks = @()
} #End Begin
PROCESS
{
    # Variables
    $Time = Date
    $CheckAutomateWinRM = {
        Write-Verbose "Invoke Confirm-Automate -Silent"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Braingears/PowerShell/master/Automate-Module.psm1')
        Confirm-Automate -Silent
        Write $Global:Automate
    }
    $InstallAutomateWinRM = {
        $Server = $Args[0]
        $LocationID = $Args[1]
        $Token = $Args[2]
        $Force = $Args[3]
        $Silent = $Args[4]
        $Transcript = $Args[5]
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Braingears/PowerShell/master/Automate-Module.psm1')
        Install-Automate -Server $Server -LocationID $LocationID -Token $Token -Transcript
    }
    $WMICMD = 'powershell.exe -Command "[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072); Invoke-Expression(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/Braingears/PowerShell/master/Automate-Module.psm1''); '
    $WMIPOSH = "Install-Automate -Server $Server -LocationID $LocationID -Token $Token -Transcript"
    $WMIArg = Write-Output "$WMICMD$WMIPOSH"""
    $WinRMConectivity = "N/A"
    $WMICConectivity = "N/A"
    $WinRMDeployed = $False
    $WMIDeployed = $False
    Clear-Variable Automate, ProcessErrorWinRM, ProcessErrorWMIC
    # End Variables
    # Now Trying WinRM 
    If ($Computer -eq $env:COMPUTERNAME) {
        Write-Verbose "Installing Automate on Local Computer - $Computer"
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
        Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Braingears/PowerShell/master/Automate-Module.psm1')
        Install-Automate -Server $Server -LocationID $LocationID -Token $Token -Show:$Show -Transcript:$Transcript
    } Else {        # Remote Computer
        If (!$Silent) {Write-Host "$($Time) - Now Checking $($COMPUTER)"}
        Write-Verbose "Ping Connectivity  - Testing..."
        If (Test-Connection -ComputerName $COMPUTER -Count 1 -Quiet) {
            Write-Verbose "Ping Connectivity  - Passed"
            $PingTest = $True
            Write-Verbose "IP or NetBIOS Name - Testing..."
            If ($Computer -notmatch "[a-z]") {
                Write-Verbose "$Computer is IP Address"
                $ComputerNetBIOS = nbtstat -A $Computer | Where-Object { $_ -match '^\s*([^<\s]+)\s*<00>\s*UNIQUE' } | ForEach-Object { $matches[1] }
                if ($ComputerNetBIOS -eq $Null) {
                    Write-Verbose "$Computer could not query NetBIOS Name"
                    Write-Verbose "$Computer as an IP Address will likely fail WinRM Connectivity"
                } else {
                    Write-Verbose "Replacing $Computer with $ComputerNetBIOS"
                    $Computer = $ComputerNetBIOS
                }
            }
            Try {
                Write-Verbose "Proactively Remote Starting WinRM Service"
                Get-Service WinRM -ComputerName $Computer -ErrorAction Stop | Start-Service
            }
            Catch {Write-Verbose "Start Service      - Failed"}
            Try {
                # The $WinRMConectivity will change to $True if the Invoke-Command has no $Errors
                $WinRMConectivity = $False
                $WinRMFailed = $True
                Write-Verbose "WinRM Connectivity - Testing..."
                $Global:Automate = (Invoke-Command $COMPUTER -Credential $Credential -ScriptBlock $CheckAutomateWinRM -ErrorAction Stop -ErrorVariable ProcessErrorWinRM)
                Write-Verbose "WinRM Connectivity - Passed"
                Write-Verbose "Global Automate: $($Global:Automate)"
                $WinRMConectivity = $True
                $WinRMFailed = $False
            }
            Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                If ($($ProcessErrorWinRM) -like "*Logon failure*") {
                    Write-Verbose "WinRM Connectivity - Credentials Failed"
                    Write-Host    "WinRM Connectivity - Credentials Failed" -ForegroundColor Red
                } else {
                    Write-Verbose "WinRM Connectivity - Failed"
                }
            }
            Catch {
                Write-Verbose "WinRM Connectivity - Failed"
                Write-Verbose "WinRM Errors: $ProcessErrorWinRM.Exception"
                $ProcessErrorWinRM.Exception | Select -Property *
            }
            If (($Global:Automate.ServerAddress -like "*$($Server)*") -and $WinRMConectivity -and $Global:Automate.Online -and !$Force) {
                If ($Show) {
                    $Global:Automate
                } Else {
                    Write-Host "The Automate Agent is already installed on $($Global:Automate.Computername) ($($Global:Automate.ComputerID)) and checked-in $($Global:Automate.LastStatus) seconds ago to $($Global:Automate.ServerAddress)" -ForegroundColor Green
                }
            } Else {
                If ($WinRMConectivity) {
                    Write-Verbose "WinRM Connectivity - Passed"
                    Write-Verbose "Installing Automate..."
                    Invoke-Command $COMPUTER -Credential $Credential -ScriptBlock $InstallAutomateWinRM -ArgumentList $Server, $LocationID, $Token, $Force, $Silent, $Transcript -ErrorAction SilentlyContinue
                    $Global:Automate = (Invoke-Command $COMPUTER -Credential $Credential -ScriptBlock $CheckAutomateWinRM -ErrorAction SilentlyContinue)
                    Write-Verbose "Local Automate:  $($Automate)" 
                    Write-Verbose "Global Automate: $($Global:Automate)"
                    $WinRMDeployed = $True
                }
            }
        #### Now Trying RPC
            If (!$Global:Automate.Online) {
                Write-Verbose "WMIC Connectivity  - Testing..."
                Try {
                    $WMICFailed = $True
                    $WMICConectivity = $False
                    $ComputerWMI = ((Get-WmiObject -ComputerName $Computer -Class Win32_ComputerSystem -Credential $Credential -ErrorAction Stop -ErrorVariable ProcessErrorWMIC).Name)
                    Write-Verbose "WMIC Connectivity  - Passed"
                    $WMICConectivity = $True
                    $WMICFailed = $False
                }
                Catch [System.Runtime.InteropServices.COMException] {
                    Write-Verbose "WMIC Connectivity  - RPC Server is Unavailable"
                }
                Catch [System.UnauthorizedAccessException] {
                    Write-Verbose "WMIC Connectivity  - Credentials Failed"
                    Write-Host    "WMIC Connectivity  - Credentials Failed" -ForegroundColor Red
                }
                Catch {
                    Write-Verbose "WMIC Connectivity  - Failed"
                    Write-Verbose "WMIC Errors: $ProcessErrorWMIC"
                }
                If   ($WMICConectivity) {
                    $Reg = Get-WmiObject -List StdRegProv -Namespace root\default -ComputerName $Computer -Credential $Credential
                    $HKLM = 2147483650
                    $Key = 'SOFTWARE\LabTech\Service\'
                    $Values = $Reg.EnumValues($HKLM,$Key)
                    # Registry types enumerations:
                    $RegTypes = @{
                        1 = 'REG_SZ'
                        2 = 'REG_EXPAND_SZ'
                        3 = 'REG_BINARY'
                        4 = 'REG_DWORD'
                        7 = 'REG_MULTI_SZ'
                    }
                    # Use a for loop to go through the values        
                    $Results = @(
                        for ($i = 0; $i -lt $Values.sNames.count; $i++) {
                            $Name = $Values.sNames[$i]
                            $Type = $RegTypes[$Values.Types[$i]]
                            switch ($Values.Types[$i]) {
                                1 {$Value = $Reg.GetStringValue($HKLM,$Key,$Name).sValue}
                                2 {$Value = $Reg.GetExpandedStringValue($HKLM,$Key,$Name).sValue}
                                3 {$Value = $Reg.GetBinaryValue($HKLM,$Key,$Name).uValue}
                                4 {$Value = $Reg.GetDWORDValue($HKLM,$Key,$Name).uValue}
                                7 {$Value = $Reg.GetMultiStringValue($HKLM,$Key,$Name).sValue}
                            }
                            [pscustomobject]@{
                                Name = $Name
                                Type = $Type
                                Data = $Value
                            }  
                        }
                    ) # $Results - Registry     
                    If ($Results) {
                        Write-Verbose "Confirm Install    - Automate Installed - Registry Keys Found"
                        $Global:Automate = New-Object -TypeName psobject
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerWMI
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name ServerAddress -Value (($Results | Where-Object -Property Name -eq 'Server Address').Data)
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerID -Value (($Results | Where-Object -Property Name -eq 'ID').Data)
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name ClientID -Value (($Results | Where-Object -Property Name -eq 'ClientID').Data)
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name LocationID -Value (($Results | Where-Object -Property Name -eq 'LocationID').Data)
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name Version -Value (($Results | Where-Object -Property Name -eq 'Version').Data)
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstFolder -Value (Test-Path "$($env:windir)\ltsvc")
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name InstRegistry -Value $True                        
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value (Test-Path "$($env:windir)\ltsvc")
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-WmiObject -ComputerName $Computer -Class Win32_Service -Filter "Name='LTService'" -Credential $Credential -ErrorAction SilentlyContinue -ErrorVariable ProcessErrorWMIC).State)
                        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent) {
                            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastHeartbeat -Value ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastSent)).TotalSeconds)
                        }
                        if ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus) {
                            $Global:Automate | Add-Member -MemberType NoteProperty -Name LastStatus -Value    ([int]((Get-Date) - (Get-Date (Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus)).TotalSeconds)
                        }
                        $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value ($Global:Automate.InstFolder -and ($Global:Automate.Service -eq "Running"))
                        Write-Verbose $Global:Automate
                        If (($Global:Automate.ServerAddress -like "*$($Server)*") -and $Global:Automate.Online -and !$Force) {
                            If ($Show) {
                                $Global:Automate
                            } Else {
                                Write-Host "The Automate Agent is already installed on $($Global:Automate.Computername) ($($Global:Automate.ComputerID)) and checked-in $($Global:Automate.LastStatus) seconds ago to $($Global:Automate.ServerAddress)" -ForegroundColor Green
                            }
                        } Else {
                            IF (!($Global:Automate.ServerAddress -like "*$($Server)*")) {
                                Write-Host "The Existing Automate Server Does Not Match The Target Automate Server." -ForegroundColor Red
                                Write-Host "Current Automate Server: $($Global:Automate.ServerAddress)" -ForegroundColor Red
                                }
                            Write-Verbose "Installing Automate..."
                            $WMIExitCode = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $WMIArg -ComputerName $Computer -Impersonation 3 -EnableAllPrivileges -Credential $Credential -ErrorAction SilentlyContinue
                            If ($WMIExitCode.ReturnValue -eq 0) {
                                Write-Host "Installing Automate Agent to https://$($Server) - WMI" -ForegroundColor Green
                                Write-Verbose "When pushing via WMI/RPC, the function will not wait and confirm the installation. "
                                $WMIDeployed = $True
                            } Else {
                                Write-Host "WMI Did NOT Execute Properly." -ForegroundColor Red
                                Write-Host "WMI Return Value: $($WMIExitCode.ReturnValue)" -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Verbose "Confirm Install    - Automate NOT Installed"
                        Write-Verbose "Installing Automate..."
                        $WMIExitCode = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $WMIArg -ComputerName $Computer -Impersonation 3 -EnableAllPrivileges -Credential $Credential -ErrorAction SilentlyContinue
                        If ($WMIExitCode.ReturnValue -eq 0) {
                            Write-Host "Installing Automate Agent to https://$($Server) - WMI" -ForegroundColor Green
                            Write-Verbose "When pushing via WMI, the function will not wait and confirm the installation. "
                            $WMIDeployed = $True
                        } Else {
                            Write-Host "WMI Did NOT Execute Properly." -ForegroundColor Red
                            Write-Host "WMI Return Value: $($WMIExitCode.ReturnValue)" -ForegroundColor Red
                        }
                    }                                
                } #End WMI Connectivity
                If (!$WinRMConectivity -and !$WMICConectivity) {Write-Host "Could Ping, but all protocols are inaccessible on $Computer. Deployment and Confirmations Failed" -ForegroundColor Yellow}
            }
        } Else {
            Write-Verbose "Ping Connectivity  - Failed"
            Write-Host "                      Ping Connectivity  - Failed" -ForegroundColor Yellow
        $PingTest = $False
        } # End Ping Test 
    } # End Else Local Computer
        $Global:AutoChecks += New-Object psobject -Property @{
        Computer      = ($COMPUTER)
        ServerAddress = $Global:Automate.ServerAddress
        ComputerID    = $Global:Automate.ComputerID
        ClientID      = $Global:Automate.ClientID
        Version       = $Global:Automate.Version
        Online        = $Global:Automate.Online
        Ping          = $PingTest
        WinRM         = $WinRMConectivity
        WMI           = $WMICConectivity
        DeployedWinRm = $WinRMDeployed
        DeployedWMI   = $WMIDeployed
        } # End $Global:AutoChecks
        Clear-Variable Automate
        Clear-Variable Automate -Scope Global
        If (!$Silent) {Write-Host " "}
} # End Process

END 
{
    Clear-Variable Username, Pass -ErrorAction SilentlyContinue | Out-Null
    $Global:AutoResults = ($Global:AutoChecks | Select-Object Computer, Online, ServerAddress, ComputerID, ClientID, Ping, WinRM, WMI, DeployedWinRM, DeployedWMI)
    Write-Verbose 'Results have been saved to $Global:AutoResults'
    $ErrorActionPreference = "Continue"
} # End END 
} # End Function Push-Automate
########################
Set-Alias -Name LTP -Value Push-Automate -Description 'Push Automate Agent to Remote Computers'
########################
Function Get-ADComputerNames
{
Param(
    [Parameter()]
    [AllowNull()]
    [Alias('Time')]
    [int]$Months = '1'
    )
$Computer =  $env:COMPUTERNAME
$FilterLastLogonDate = (Get-Date).AddMonths(-$Months)
$ADNames = {
  $Computer =  $env:COMPUTERNAME
  Write-Verbose "Executing from $Computer"
  If (!($Args -eq '[0]')) {$Months = $Args[0]}
  Write-Verbose "Months:               -$Months"
  $FilterLastLogonDate = (Get-Date).AddMonths(-$Months)
  Write-Verbose "Executing from $Computer"
  Write-Verbose 'Importing ''ActiveDirectory'' Module'
  Import-Module ActiveDirectory -ErrorAction SilentlyContinue
  Write-Verbose 'Loading all computers that have logged into'
  Get-ADComputer -Filter 'OperatingSystem -like "Windows*" -and LastLogonDate -ge $FilterLastLogonDate' | Select -ExpandProperty Name | Sort-Object -Unique
#  $Computers = Get-ADComputer -Filter 'OperatingSystem -like "Windows*" -and Name -ne $Computer -and LastLogonDate -ge $FilterLastLogonDate' | Select -ExpandProperty Name | Sort-Object -Unique
#  Write-Verbose $Computers
#  $Computers
  }
$FilterLastLogonDate = (Get-Date).AddMonths(-$Months)
Import-Module ActiveDirectory -ErrorAction SilentlyContinue -ErrorVariable ImportError
If ($ImportError -like "*not loaded*") {
    Write-Verbose "Import Error: $ImportError"
    $LogonSrv = $Env:LOGONSERVER.Substring(2)
    (Invoke-Command $LogonSrv -ScriptBlock $ADNames -ArgumentList $Months -ErrorAction SilentlyContinue -ErrorVariable InvokeDCError)
    If ($InvokeDCError -like "*Access is denied*")
        {Write-Host "Access is Denied. Your credentials will not execute on $LogonSrv" -ForegroundColor Red}
    } Else {
        $FilterLastLogonDate = (Get-Date).AddMonths(-$Months)
        $Computers = Get-ADComputer -Filter 'OperatingSystem -like "Windows*" -and LastLogonDate -ge $FilterLastLogonDate' | Select -ExpandProperty Name | Sort-Object -Unique
#        Write-Verbose $Computers
    }
    
Write-Verbose "Computer Logons > Months:  -$Months"
Write-Verbose "Computer Logins Since:     $FilterLastLogonDate"
Write-Verbose "Server:                    $LogonSrv"
Write-Verbose "Input Error:    $ImportError"
Write-Verbose "Invoke Error:   $InvokeDCError"
$Computers
} # End Get-ADComputerNames
########################
Function Scan-Network
{
  [CmdletBinding(SupportsShouldProcess=$True)]
  Param (
  [Parameter()]
  [AllowNull()]
  [switch]$Show,
  [Parameter()]
  [AllowNull()]
  [switch]$Subnet
    )
  Begin{
  # Load Module
          Function New-IPRange {
        <#
        .SYNOPSIS
            Returns an array of IP Addresses based on a start and end address
        
        .DESCRIPTION
            Returns an array of IP Addresses based on a start and end address
        
        .PARAMETER Start
            Starting IP Address
        
        .PARAMETER End
            Ending IP Address
        
        .PARAMETER Exclude
            Exclude addresses with this final octet
        
            Default excludes 0, 1, and 255
        
            e.g. 5 excludes *.*.*.5
        
        .EXAMPLE
            New-IPRange -Start 192.168.1.5 -End 192.168.20.254
        
            Create an array from 192.168.1.5 to 192.168.20.254, excluding *.*.*.[0,1,255] (default exclusion)
        
        .NOTES
            Source: Dr. Tobias Weltner, http://powershell.com/cs/media/p/9437.aspx
        
        .FUNCTIONALITY
            Network
        #>
        [cmdletbinding()]
        param (
            [parameter( Mandatory = $true,
                        Position = 0 )]
            [System.Net.IPAddress]$Start,
        
            [parameter( Mandatory = $true,
                        Position = 1)]
            [System.Net.IPAddress]$End,
        
            [int[]]$Exclude = @( 0, 1, 255 )
        )
            
            #Provide verbose output.  Some oddities behind casting certain strings to IP.
            #Example: [ipaddress]"192.168.20500"
            Write-Verbose "Parsed Start as '$Start', End as '$End'"
            
            $ip1 = $start.GetAddressBytes()
            [Array]::Reverse($ip1)
            $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
        
            $ip2 = ($end).GetAddressBytes()
            [Array]::Reverse($ip2)
            $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address
        
            for ($x=$ip1; $x -le $ip2; $x++)
            {
                $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
                [Array]::Reverse($ip)
                if($Exclude -notcontains $ip[3])
                {
                    $ip -join '.'
                }
            }
        } # End New-IPRange
        
        Function Invoke-Ping 
        {
        <#
        .SYNOPSIS
            Ping or test connectivity to systems in parallel
            
        .DESCRIPTION
            Ping or test connectivity to systems in parallel
        
            Default action will run a ping against systems
                If Quiet parameter is specIfied, we return an array of systems that responded
                If Detail parameter is specIfied, we test WSMan, RemoteReg, RPC, RDP and/or SMB
        
        .PARAMETER ComputerName
            One or more computers to test
        
        .PARAMETER Quiet
            If specIfied, only return addresses that responded to Test-Connection
        
        .PARAMETER Detail
            Include one or more additional tests as specIfied:
                WSMan      via Test-WSMan
                RemoteReg  via Microsoft.Win32.RegistryKey
                RPC        via WMI
                RDP        via port 3389
                SMB        via \\ComputerName\C$
                *          All tests
        
        .PARAMETER Timeout
            Time in seconds before we attempt to dispose an individual query.  Default is 20
        
        .PARAMETER Throttle
            Throttle query to this many parallel runspaces.  Default is 100.
        
        .PARAMETER NoCloseOnTimeout
            Do not dispose of timed out tasks or attempt to close the runspace If threads have timed out
        
            This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.
        
        .EXAMPLE
            Invoke-Ping Server1, Server2, Server3 -Detail *
        
            # Check for WSMan, Remote Registry, Remote RPC, RDP, and SMB (via C$) connectivity against 3 machines
        
        .EXAMPLE
            $Computers | Invoke-Ping
        
            # Ping computers in $Computers in parallel
        
        .EXAMPLE
            $Responding = $Computers | Invoke-Ping -Quiet
            
            # Create a list of computers that successfully responded to Test-Connection
        
        .LINK
            https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a
        
        .FUNCTIONALITY
            Computers
        
        #>
            [cmdletbinding(DefaultParameterSetName='Ping')]
            param(
                [Parameter( ValueFromPipeline=$true,
                            ValueFromPipelineByPropertyName=$true, 
                            Position=0)]
                [string[]]$ComputerName,
                
                [Parameter( ParameterSetName='Detail')]
                [validateset("*","WSMan","RemoteReg","RPC","RDP","SMB")]
                [string[]]$Detail,
                
                [Parameter(ParameterSetName='Ping')]
                [switch]$Quiet,
                
                [int]$Timeout = 20,
                
                [int]$Throttle = 100,
        
                [switch]$NoCloseOnTimeout
            )
            Begin
            {
        
                #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
                function Invoke-Parallel {
                    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
                    Param (   
                        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                            [System.Management.Automation.ScriptBlock]$ScriptBlock,
        
                        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                        [ValidateScript({test-path $_ -pathtype leaf})]
                            $ScriptFile,
        
                        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                        [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                            [PSObject]$InputObject,
        
                            [PSObject]$Parameter,
        
                            [switch]$ImportVariables,
        
                            [switch]$ImportModules,
        
                            [int]$Throttle = 20,
        
                            [int]$SleepTimer = 200,
        
                            [int]$RunspaceTimeout = 0,
        
                            [switch]$NoCloseOnTimeout = $false,
        
                            [int]$MaxQueue,
        
                        [validatescript({Test-Path (Split-Path $_ -parent)})]
                            [string]$LogFile = "C:\temp\log.log",
        
                            [switch] $Quiet = $false
                    )
            
                    Begin {
                        
                        #No max queue specIfied?  Estimate one.
                        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                        If( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                        {
                            If($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                            Else{ $script:MaxQueue = $Throttle * 3 }
                        }
                        Else
                        {
                            $script:MaxQueue = $MaxQueue
                        }
        
                        Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"
        
                        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                        If ($ImportVariables -or $ImportModules)
                        {
                            $StandardUserEnv = [powershell]::Create().addscript({
        
                                #Get modules and snapins in this clean runspace
                                $Modules = Get-Module | Select -ExpandProperty Name
                                $Snapins = Get-PSSnapin | Select -ExpandProperty Name
        
                                #Get variables in this clean runspace
                                #Called last to get vars like $? into session
                                $Variables = Get-Variable | Select -ExpandProperty Name
                        
                                #Return a hashtable where we can access each.
                                @{
                                    Variables = $Variables
                                    Modules = $Modules
                                    Snapins = $Snapins
                                }
                            }).invoke()[0]
                    
                            If ($ImportVariables) {
                                #Exclude common parameters, bound parameters, and automatic variables
                                Function _temp {[cmdletbinding()] param() }
                                $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                                Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"
        
                                # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                                # One of the veriables that we pass is '$?'. 
                                # There could be other variables with such problems.
                                # Scope 2 required If we move to a real module
                                $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                                Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
        
                            }
        
                            If ($ImportModules) 
                            {
                                $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                                $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                            }
                        }
        
                        #region functions
                    
                            Function Get-RunspaceData {
                                [cmdletbinding()]
                                param( [switch]$Wait )
        
                                #loop through runspaces
                                #If $wait is specIfied, keep looping until all complete
                                Do {
        
                                    #set more to false for tracking completion
                                    $more = $false
        
                                    #Progress bar If we have inputobject count (bound parameter)
                                    If (-not $Quiet) {
                                        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
                                            -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                                            -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                                    }
        
                                    #run through each runspace.           
                                    Foreach($runspace in $runspaces) {
                            
                                        #get the duration - inaccurate
                                        $currentdate = Get-Date
                                        $runtime = $currentdate - $runspace.startTime
                                        $runMin = [math]::Round( $runtime.totalminutes ,2 )
        
                                        #set up log object
                                        $log = "" | select Date, Action, Runtime, Status, Details
                                        $log.Action = "Removing:'$($runspace.object)'"
                                        $log.Date = $currentdate
                                        $log.Runtime = "$runMin minutes"
        
                                        #If runspace completed, end invoke, dispose, recycle, counter++
                                        If ($runspace.Runspace.isCompleted) {
                                    
                                            $script:completedCount++
                                
                                            #check If there were errors
                                            If($runspace.powershell.Streams.Error.Count -gt 0) {
                                        
                                                #set the logging info and move the file to completed
                                                $log.status = "CompletedWithErrors"
                                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                                    Write-Error -ErrorRecord $ErrorRecord
                                                }
                                            }
                                            Else {
                                        
                                                #add logging details and cleanup
                                                $log.status = "Completed"
                                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                            }
        
                                            #everything is logged, clean up the runspace
                                            $runspace.powershell.EndInvoke($runspace.Runspace)
                                            $runspace.powershell.dispose()
                                            $runspace.Runspace = $null
                                            $runspace.powershell = $null
        
                                        }
        
                                        #If runtime exceeds max, dispose the runspace
                                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                                    
                                            $script:completedCount++
                                            $timedOutTasks = $true
                                    
                                            #add logging details and cleanup
                                            $log.status = "TimedOut"
                                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"
        
                                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                            If (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                            $runspace.Runspace = $null
                                            $runspace.powershell = $null
                                            $completedCount++
        
                                        }
                           
                                        #If runspace isn't null set more to true  
                                        ElseIf ($runspace.Runspace -ne $null ) {
                                            $log = $null
                                            $more = $true
                                        }
        
                                        #log the results If a log file was indicated
                                        If($logFile -and $log){
                                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                                        }
                                    }
        
                                    #Clean out unused runspace jobs
                                    $temphash = $runspaces.clone()
                                    $temphash | Where { $_.runspace -eq $Null } | ForEach {
                                        $Runspaces.remove($_)
                                    }
        
                                    #sleep for a bit If we will loop again
                                    If($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }
        
                                #Loop again only If -wait parameter and there are more runspaces to process
                                } while ($more -and $PSBoundParameters['Wait'])
                        
                            #End of runspace function
                            }
        
                        #endregion functions
                
                        #region Init
        
                            If($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                            {
                                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                            }
                            ElseIf($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                            {
                                #Start building parameter names for the param block
                                [string[]]$ParamsToAdd = '$_'
                                If( $PSBoundParameters.ContainsKey('Parameter') )
                                {
                                    $ParamsToAdd += '$Parameter'
                                }
        
                                $UsingVariableData = $Null
                        
        
                                # This code enables $Using support through the AST.
                                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                        
                                If($PSVersionTable.PSVersion.Major -gt 2)
                                {
                                    #Extract using references
                                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    
        
                                    If ($UsingVariables)
                                    {
                                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                                        ForEach ($Ast in $UsingVariables)
                                        {
                                            [void]$list.Add($Ast.SubExpression)
                                        }
        
                                        $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
                
                                        #Extract the name, value, and create replacements for each
                                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                                            Try
                                            {
                                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                                $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                                [pscustomobject]@{
                                                    Name = $Var.SubExpression.Extent.Text
                                                    Value = $Value.Value
                                                    NewName = $NewName
                                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                                }
                                                $ParamsToAdd += $NewName
                                            }
                                            Catch
                                            {
                                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                            }
                                        }
            
                                        $NewParams = $UsingVariableData.NewName -join ', '
                                        $Tuple = [Tuple]::Create($list, $NewParams)
                                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
                
                                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))
        
                                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)
        
                                        Write-Verbose $StringScriptBlock
                                    }
                                }
                        
                                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                            }
                            Else
                            {
                                Throw "Must provide ScriptBlock or ScriptFile"; Break
                            }
        
                            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                            Write-Verbose "Creating runspace pool and session states"
        
                            #If specIfied, add variables and modules/snapins to session state
                            $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                            If ($ImportVariables)
                            {
                                If($UserVariables.count -gt 0)
                                {
                                    foreach($Variable in $UserVariables)
                                    {
                                        $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                                    }
                                }
                            }
                            If ($ImportModules)
                            {
                                If($UserModules.count -gt 0)
                                {
                                    foreach($ModulePath in $UserModules)
                                    {
                                        $sessionstate.ImportPSModule($ModulePath)
                                    }
                                }
                                If($UserSnapins.count -gt 0)
                                {
                                    foreach($PSSnapin in $UserSnapins)
                                    {
                                        [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                                    }
                                }
                            }
        
                            #Create runspace pool
                            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                            $runspacepool.Open() 
        
                            Write-Verbose "Creating empty collection to hold runspace jobs"
                            $Script:runspaces = New-Object System.Collections.ArrayList        
                
                            #If inputObject is bound get a total count and set bound to true
                            $global:__bound = $false
                            $allObjects = @()
                            If( $PSBoundParameters.ContainsKey("inputObject") ){
                                $global:__bound = $true
                            }
        
                            #Set up log file If specIfied
                            If( $LogFile ){
                                New-Item -ItemType file -path $logFile -force | Out-Null
                                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                            }
        
                            #write initial log entry
                            $log = "" | Select Date, Action, Runtime, Status, Details
                                $log.Date = Get-Date
                                $log.Action = "Batch processing started"
                                $log.Runtime = $null
                                $log.Status = "Started"
                                $log.Details = $null
                                If($logFile) {
                                    ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                                }
        
                            $timedOutTasks = $false
        
                        #endregion INIT
                    }
        
                    Process {
        
                        #add piped objects to all objects or set all objects to bound input object parameter
                        If( -not $global:__bound ){
                            $allObjects += $inputObject
                        }
                        Else{
                            $allObjects = $InputObject
                        }
                    }
        
                    End {
                
                        #Use Try/Finally to catch Ctrl+C and clean up.
                        Try
                        {
                            #counts for progress
                            $totalCount = $allObjects.count
                            $script:completedCount = 0
                            $startedCount = 0
        
                            foreach($object in $allObjects){
                
                                #region add scripts to runspace pool
                            
                                    #Create the powershell instance, set verbose If needed, supply the scriptblock and parameters
                                    $powershell = [powershell]::Create()
                            
                                    If ($VerbosePreference -eq 'Continue')
                                    {
                                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                                    }
        
                                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)
        
                                    If ($parameter)
                                    {
                                        [void]$PowerShell.AddArgument($parameter)
                                    }
        
                                    # $Using support from Boe Prox
                                    If ($UsingVariableData)
                                    {
                                        Foreach($UsingVariable in $UsingVariableData) {
                                            Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                                        }
                                    }
        
                                    #Add the runspace into the powershell instance
                                    $powershell.RunspacePool = $runspacepool
            
                                    #Create a temporary collection for each runspace
                                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                                    $temp.PowerShell = $powershell
                                    $temp.StartTime = Get-Date
                                    $temp.object = $object
            
                                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                                    $temp.Runspace = $powershell.BeginInvoke()
                                    $startedCount++
        
                                    #Add the temp tracking info to $runspaces collection
                                    Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                                    $runspaces.Add($temp) | Out-Null
                    
                                    #loop through existing runspaces one time
                                    Get-RunspaceData
        
                                    #If we have more running than max queue (used to control timeout accuracy)
                                    #Script scope resolves odd PowerShell 2 issue
                                    $firstRun = $true
                                    while ($runspaces.count -ge $Script:MaxQueue) {
        
                                        #give verbose output
                                        If($firstRun){
                                            Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                        }
                                        $firstRun = $false
                            
                                        #run get-runspace data and sleep for a short while
                                        Get-RunspaceData
                                        Start-Sleep -Milliseconds $sleepTimer
                            
                                    }
        
                                #endregion add scripts to runspace pool
                            }
                             
                            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                            Get-RunspaceData -wait
        
                            If (-not $quiet) {
                                Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
                            }
        
                        }
                        Finally
                        {
                            #Close the runspace pool, unless we specIfied no close on timeout and something timed out
                            If ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                                Write-Verbose "Closing the runspace pool"
                                $runspacepool.close()
                            }
        
                            #collect garbage
                            [gc]::Collect()
                        }       
                    }
                }
        
                Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
                
                $bound = $PSBoundParameters.keys -contains "ComputerName"
                If(-not $bound)
                {
                    [System.Collections.ArrayList]$AllComputers = @()
                }
            }
            Process
            {
        
                #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
                If($bound)
                {
                    $AllComputers = $ComputerName
                }
                Else
                {
                    foreach($Computer in $ComputerName)
                    {
                        $AllComputers.add($Computer) | Out-Null
                    }
                }
        
            }
            End
            {
        
                #Built up the parameters and run everything in parallel
                $params = @($Detail, $Quiet)
                $splat = @{
                    Throttle = $Throttle
                    RunspaceTimeout = $Timeout
                    InputObject = $AllComputers
                    parameter = $params
                }
                If($NoCloseOnTimeout)
                {
                    $splat.add('NoCloseOnTimeout',$True)
                }
        
                Invoke-Parallel @splat -ScriptBlock {
                
                    $computer = $_.trim()
                    $detail = $parameter[0]
                    $quiet = $parameter[1]
        
                    #They want detail, define and run test-server
                    If($detail)
                    {
                        Try
                        {
                            #ModIfication of jrich's Test-Server function: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Test-Server-e0cdea9a
                            Function Test-Server{
                                [cmdletBinding()]
                                param(
                                    [parameter(
                                        Mandatory=$true,
                                        ValueFromPipeline=$true)]
                                    [string[]]$ComputerName,
                                    [switch]$All,
                                    [parameter(Mandatory=$false)]
                                    [switch]$CredSSP,
                                    [switch]$RemoteReg,
                                    [switch]$RDP,
                                    [switch]$RPC,
                                    [switch]$SMB,
                                    [switch]$WSMAN,
                                    [switch]$IPV6,
                                    [Management.Automation.PSCredential]$Credential
                                )
                                    begin
                                    {
                                        $total = Get-Date
                                        $results = @()
                                        If($credssp -and -not $Credential)
                                        {
                                            Throw "Must supply Credentials with CredSSP test"
                                        }
        
                                        [string[]]$props = write-output Name, IP, Domain, Ping, WSMAN, CredSSP, RemoteReg, RPC, RDP, SMB
        
                                        #Hash table to create PSObjects later, compatible with ps2...
                                        $Hash = @{}
                                        foreach($prop in $props)
                                        {
                                            $Hash.Add($prop,$null)
                                        }
        
                                        function Test-Port{
                                            [cmdletbinding()]
                                            Param(
                                                [string]$srv,
                                                $port=135,
                                                $timeout=3000
                                            )
                                            $ErrorActionPreference = "SilentlyContinue"
                                            $tcpclient = new-Object system.Net.Sockets.TcpClient
                                            $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
                                            $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
                                            If(-not $wait)
                                            {
                                                $tcpclient.Close()
                                                Write-Verbose "Connection Timeout to $srv`:$port"
                                                $false
                                            }
                                            Else
                                            {
                                                Try
                                                {
                                                    $tcpclient.EndConnect($iar) | out-Null
                                                    $true
                                                }
                                                Catch
                                                {
                                                    write-verbose "Error for $srv`:$port`: $_"
                                                    $false
                                                }
                                                $tcpclient.Close()
                                            }
                                        }
                                    }
        
                                    process
                                    {
                                        foreach($name in $computername)
                                        {
                                            $dt = $cdt= Get-Date
                                            Write-verbose "Testing: $Name"
                                            $failed = 0
                                            try{
                                                $DNSEntity = [Net.Dns]::GetHostEntry($name)
                                                $domain = ($DNSEntity.hostname).replace("$name.","")
                                                $ips = $DNSEntity.AddressList | %{
                                                    If(-not ( -not $IPV6 -and $_.AddressFamily -like "InterNetworkV6" ))
                                                    {
                                                        $_.IPAddressToString
                                                    }
                                                }
                                            }
                                            catch
                                            {
                                                $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
                                                $rst.name = $name
                                                $results += $rst
                                                $failed = 1
                                            }
                                            Write-verbose "DNS:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            If($failed -eq 0){
                                                foreach($ip in $ips)
                                                {
                
                                                    $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
                                                    $rst.name = $name
                                                    $rst.ip = $ip
                                                    $rst.domain = $domain
                            
                                                    If($RDP -or $All)
                                                    {
                                                        ####RDP Check (firewall may block rest so do before ping
                                                        try{
                                                            $socket = New-Object Net.Sockets.TcpClient($name, 3389) -ErrorAction stop
                                                            If($socket -eq $null)
                                                            {
                                                                $rst.RDP = $false
                                                            }
                                                            Else
                                                            {
                                                                $rst.RDP = $true
                                                                $socket.close()
                                                            }
                                                        }
                                                        catch
                                                        {
                                                            $rst.RDP = $false
                                                            Write-Verbose "Error testing RDP: $_"
                                                        }
                                                    }
                                                Write-verbose "RDP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                #########ping
                                                If(test-connection $ip -count 2 -Quiet)
                                                {
                                                    Write-verbose "PING:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                    $rst.ping = $true
                        
                                                    If($WSMAN -or $All)
                                                    {
                                                        try{############wsman
                                                            Test-WSMan $ip -ErrorAction stop | Out-Null
                                                            $rst.WSMAN = $true
                                                        }
                                                        catch
                                                        {
                                                            $rst.WSMAN = $false
                                                            Write-Verbose "Error testing WSMAN: $_"
                                                        }
                                                        Write-verbose "WSMAN:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                        If($rst.WSMAN -and $credssp) ########### credssp
                                                        {
                                                            try{
                                                                Test-WSMan $ip -Authentication Credssp -Credential $cred -ErrorAction stop
                                                                $rst.CredSSP = $true
                                                            }
                                                            catch
                                                            {
                                                                $rst.CredSSP = $false
                                                                Write-Verbose "Error testing CredSSP: $_"
                                                            }
                                                            Write-verbose "CredSSP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                        }
                                                    }
                                                    If($RemoteReg -or $All)
                                                    {
                                                        try ########remote reg
                                                        {
                                                            [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ip) | Out-Null
                                                            $rst.remotereg = $true
                                                        }
                                                        catch
                                                        {
                                                            $rst.remotereg = $false
                                                            Write-Verbose "Error testing RemoteRegistry: $_"
                                                        }
                                                        Write-verbose "remote reg:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                    }
                                                    If($RPC -or $All)
                                                    {
                                                        try ######### wmi
                                                        {    
                                                            $w = [wmi] ''
                                                            $w.psbase.options.timeout = 15000000
                                                            $w.path = "\\$Name\root\cimv2:Win32_ComputerSystem.Name='$Name'"
                                                            $w | select none | Out-Null
                                                            $rst.RPC = $true
                                                        }
                                                        catch
                                                        {
                                                            $rst.rpc = $false
                                                            Write-Verbose "Error testing WMI/RPC: $_"
                                                        }
                                                        Write-verbose "WMI/RPC:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                                    }
                                                    If($SMB -or $All)
                                                    {
        
                                                        #Use set location and resulting errors.  push and pop current location
                                                        try ######### C$
                                                        {    
                                                            $path = "\\$name\c$"
                                                            Push-Location -Path $path -ErrorAction stop
                                                            $rst.SMB = $true
                                                            Pop-Location
                                                        }
                                                        catch
                                                        {
                                                            $rst.SMB = $false
                                                            Write-Verbose "Error testing SMB: $_"
                                                        }
                                                        Write-verbose "SMB:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
        
                                                    }
                                                }
                                                Else
                                                {
                                                    $rst.ping = $false
                                                    $rst.wsman = $false
                                                    $rst.credssp = $false
                                                    $rst.remotereg = $false
                                                    $rst.rpc = $false
                                                    $rst.smb = $false
                                                }
                                                $results += $rst    
                                            }
                                        }
                                        Write-Verbose "Time for $($Name): $((New-TimeSpan $cdt ($dt)).totalseconds)"
                                        Write-Verbose "----------------------------"
                                        }
                                    }
                                    end
                                    {
                                        Write-Verbose "Time for all: $((New-TimeSpan $total ($dt)).totalseconds)"
                                        Write-Verbose "----------------------------"
                                        return $results
                                    }
                                }
                            
                            #Build up parameters for Test-Server and run it
                                $TestServerParams = @{
                                    ComputerName = $Computer
                                    ErrorAction = "Stop"
                                }
        
                                If($detail -eq "*"){
                                    $detail = "WSMan","RemoteReg","RPC","RDP","SMB" 
                                }
        
                                $detail | Select -Unique | Foreach-Object { $TestServerParams.add($_,$True) }
                                Test-Server @TestServerParams | Select -Property $( "Name", "IP", "Domain", "Ping" + $detail )
                        }
                        Catch
                        {
                            Write-Warning "Error with Test-Server: $_"
                        }
                    }
                    #We just want ping output
                    Else
                    {
                        Try
                        {
                            #Pick out a few properties, add a status label.  If quiet output, just return the address
                            $result = $null
                            If( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                            {
                                $Output = $result | Select -first 1 -Property Address,
                                                                              IPV4Address,
                                                                              IPV6Address,
                                                                              ResponseTime,
                                                                              @{ label = "STATUS"; expression = {"Responding"} }
        
                                If( $quiet )
                                {
                                    $Output.address
                                }
                                Else
                                {
                                    $Output
                                }
                            }
                        }
                        Catch
                        {
                            If(-not $quiet)
                            {
                                #Ping failed.  I'm likely making inappropriate assumptions here, let me know If this is the case : )
                                If($_ -match "No such host is known")
                                {
                                    $status = "Unknown host"
                                }
                                ElseIf($_ -match "Error due to lack of resources")
                                {
                                    $status = "No Response"
                                }
                                Else
                                {
                                    $status = "Error: $_"
                                }
        
                                "" | Select -Property @{ label = "Address"; expression = {$computer} },
                                                      IPV4Address,
                                                      IPV6Address,
                                                      ResponseTime,
                                                      @{ label = "STATUS"; expression = {$status} }
                            }
                        }
                    }
                }
            }
        } # End Invoke-Ping
        ########################
        ## https://github.com/briansworth/GetIPv4Address/blob/master/GetIPv4Subnet.psm1
        Function Convert-IPv4AddressToBinaryString {
          Param(
            [IPAddress]$IPAddress='0.0.0.0'
          )
          $addressBytes=$IPAddress.GetAddressBytes()
        
          $strBuilder=New-Object -TypeName Text.StringBuilder
          foreach($byte in $addressBytes){
            $8bitString=[Convert]::ToString($byte,2).PadRight(8,'0')
            [void]$strBuilder.Append($8bitString)
          }
          Write-Output $strBuilder.ToString()
        }
        
        Function ConvertIPv4ToInt {
          [CmdletBinding()]
          Param(
            [String]$IPv4Address
          )
          Try{
            $ipAddress=[IPAddress]::Parse($IPv4Address)
        
            $bytes=$ipAddress.GetAddressBytes()
            [Array]::Reverse($bytes)
        
            [System.BitConverter]::ToUInt32($bytes,0)
          }Catch{
            Write-Error -Exception $_.Exception `
              -Category $_.CategoryInfo.Category
          }
        }
        
        Function ConvertIntToIPv4 {
          [CmdletBinding()]
          Param(
            [uint32]$Integer
          )
          Try{
            $bytes=[System.BitConverter]::GetBytes($Integer)
            [Array]::Reverse($bytes)
            ([IPAddress]($bytes)).ToString()
          }Catch{
            Write-Error -Exception $_.Exception `
              -Category $_.CategoryInfo.Category
          }
        }
        
        <#
        .SYNOPSIS
        Add an integer to an IP Address and get the new IP Address.
        
        .DESCRIPTION
        Add an integer to an IP Address and get the new IP Address.
        
        .PARAMETER IPv4Address
        The IP Address to add an integer to.
        
        .PARAMETER Integer
        An integer to add to the IP Address. Can be a positive or negative number.
        
        .EXAMPLE
        Add-IntToIPv4Address -IPv4Address 10.10.0.252 -Integer 10
        
        10.10.1.6
        
        Description
        -----------
        This command will add 10 to the IP Address 10.10.0.1 and return the new IP Address.
        
        .EXAMPLE
        Add-IntToIPv4Address -IPv4Address 192.168.1.28 -Integer -100
        
        192.168.0.184
        
        Description
        -----------
        This command will subtract 100 from the IP Address 192.168.1.28 and return the new IP Address.
        #>
        Function Add-IntToIPv4Address {
          Param(
            [String]$IPv4Address,
        
            [int64]$Integer
          )
          Try{
            $ipInt=ConvertIPv4ToInt -IPv4Address $IPv4Address `
              -ErrorAction Stop
            $ipInt+=$Integer
        
            ConvertIntToIPv4 -Integer $ipInt
          }Catch{
            Write-Error -Exception $_.Exception `
              -Category $_.CategoryInfo.Category
          }
        }
        
        Function CIDRToNetMask {
          [CmdletBinding()]
          Param(
            [ValidateRange(0,32)]
            [int16]$PrefixLength=0
          )
          $bitString=('1' * $PrefixLength).PadRight(32,'0')
        
          $strBuilder=New-Object -TypeName Text.StringBuilder
        
          for($i=0;$i -lt 32;$i+=8){
            $8bitString=$bitString.Substring($i,8)
            [void]$strBuilder.Append("$([Convert]::ToInt32($8bitString,2)).")
          }
        
          $strBuilder.ToString().TrimEnd('.')
        }
        
        Function NetMaskToCIDR {
          [CmdletBinding()]
          Param(
            [String]$SubnetMask='255.255.255.0'
          )
          $byteRegex='^(0|128|192|224|240|248|252|254|255)$'
          $invalidMaskMsg="Invalid SubnetMask specified [$SubnetMask]"
          Try{
            $netMaskIP=[IPAddress]$SubnetMask
            $addressBytes=$netMaskIP.GetAddressBytes()
        
            $strBuilder=New-Object -TypeName Text.StringBuilder
        
            $lastByte=255
            foreach($byte in $addressBytes){
        
              # Validate byte matches net mask value
              if($byte -notmatch $byteRegex){
                Write-Error -Message $invalidMaskMsg `
                  -Category InvalidArgument `
                  -ErrorAction Stop
              }elseif($lastByte -ne 255 -and $byte -gt 0){
                Write-Error -Message $invalidMaskMsg `
                  -Category InvalidArgument `
                  -ErrorAction Stop
              }
        
              [void]$strBuilder.Append([Convert]::ToString($byte,2))
              $lastByte=$byte
            }
        
            ($strBuilder.ToString().TrimEnd('0')).Length
          }Catch{
            Write-Error -Exception $_.Exception `
              -Category $_.CategoryInfo.Category
          }
        }
        
        <#
        .SYNOPSIS
        Get information about an IPv4 subnet based on an IP Address and a subnet mask or prefix length
        
        .DESCRIPTION
        Get information about an IPv4 subnet based on an IP Address and a subnet mask or prefix length
        
        .PARAMETER IPAddress
        The IP Address to use for determining subnet information. 
        
        .PARAMETER PrefixLength
        The prefix length of the subnet.
        
        .PARAMETER SubnetMask
        The subnet mask of the subnet.
        
        .EXAMPLE
        Get-IPv4Subnet -IPAddress 192.168.34.76 -SubnetMask 255.255.128.0
        
        CidrID       : 192.168.0.0/17
        NetworkID    : 192.168.0.0
        SubnetMask   : 255.255.128.0
        PrefixLength : 17
        HostCount    : 32766
        FirstHostIP  : 192.168.0.1
        LastHostIP   : 192.168.127.254
        Broadcast    : 192.168.127.255
        
        Description
        -----------
        This command will get the subnet information about the IPAddress 192.168.34.76, with the subnet mask of 255.255.128.0
        
        .EXAMPLE
        Get-IPv4Subnet -IPAddress 10.3.40.54 -PrefixLength 25
        
        CidrID       : 10.3.40.0/25
        NetworkID    : 10.3.40.0
        SubnetMask   : 255.255.255.128
        PrefixLength : 25
        HostCount    : 126
        FirstHostIP  : 10.3.40.1
        LastHostIP   : 10.3.40.126
        Broadcast    : 10.3.40.127
        
        Description
        -----------
        This command will get the subnet information about the IPAddress 10.3.40.54, with the subnet prefix length of 25.
        
        #>
        Function Get-IPv4Subnet {
          [CmdletBinding(DefaultParameterSetName='PrefixLength')]
          Param(
            [Parameter(Mandatory=$true,Position=0)]
            [IPAddress]$IPAddress,
        
            [Parameter(Position=1,ParameterSetName='PrefixLength')]
            [Int16]$PrefixLength=24,
        
            [Parameter(Position=1,ParameterSetName='SubnetMask')]
            [IPAddress]$SubnetMask
          )
          Begin{}
          Process{
            Try{
              if($PSCmdlet.ParameterSetName -eq 'SubnetMask'){
                $PrefixLength=NetMaskToCidr -SubnetMask $SubnetMask `
                  -ErrorAction Stop
              }else{
                $SubnetMask=CIDRToNetMask -PrefixLength $PrefixLength `
                  -ErrorAction Stop
              }
              
              $netMaskInt=ConvertIPv4ToInt -IPv4Address $SubnetMask     
              $ipInt=ConvertIPv4ToInt -IPv4Address $IPAddress
              
              $networkID=ConvertIntToIPv4 -Integer ($netMaskInt -band $ipInt)
        
              $maxHosts=[math]::Pow(2,(32-$PrefixLength)) - 2
              $broadcast=Add-IntToIPv4Address -IPv4Address $networkID `
                -Integer ($maxHosts+1)
        
              $firstIP=Add-IntToIPv4Address -IPv4Address $networkID -Integer 1
              $lastIP=Add-IntToIPv4Address -IPv4Address $broadcast -Integer -1
        
              if($PrefixLength -eq 32){
                $broadcast=$networkID
                $firstIP=$null
                $lastIP=$null
                $maxHosts=0
              }
        
              $outputObject=New-Object -TypeName PSObject 
        
              $memberParam=@{
                InputObject=$outputObject;
                MemberType='NoteProperty';
                Force=$true;
              }
              Add-Member @memberParam -Name CidrID -Value "$networkID/$PrefixLength"
              Add-Member @memberParam -Name NetworkID -Value $networkID
              Add-Member @memberParam -Name SubnetMask -Value $SubnetMask
              Add-Member @memberParam -Name PrefixLength -Value $PrefixLength
              Add-Member @memberParam -Name HostCount -Value $maxHosts
              Add-Member @memberParam -Name FirstHostIP -Value $firstIP
              Add-Member @memberParam -Name LastHostIP -Value $lastIP
              Add-Member @memberParam -Name Broadcast -Value $broadcast
        
              Write-Output $outputObject
            }Catch{
              Write-Error -Exception $_.Exception `
                -Category $_.CategoryInfo.Category
            }
          }
          End{}
        }

  } # End Begin
  
  Process
{
  $NetworkScan = &{}
    $ErrorActionPreference = "SilentlyContinue"
    $IPAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}).ipaddress[0]
    $SubnetMask = (Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}).ipsubnet[0]
    Write-Verbose "Local Computer IP: $IPAddress"
    Write-Verbose "Local Computer IP: $SubnetMask"
    $Network = (Get-IPv4Subnet -IPAddress $IPAddress -SubnetMask $SubnetMask)
    Write-Verbose "Local Network: $Network"
IF ($Subnet) {
    Write-Verbose "Selecting IP Range for Entire Subnet"
    New-IPRange -Start $Network.FirstHostIP -End $Network.LastHostIP
    } Else {
        $NetworkScan  = New-IPRange -Start $Network.FirstHostIP -End $Network.LastHostIP | Invoke-Ping -Quiet
        Write-Verbose "Scan Local Subnet. Showing Only Devices with Ping"
        Write-Verbose $NetworkScan
        Write-Verbose "Testing FOREACH"
        foreach ($Device in $NetworkScan) {
            If (Test-Connection -ComputerName $Device -Count 1 -Quiet)
            {
                Write-Verbose "Testing if $Device has NetBIOS Name"
                $DeviceNetBIOS = nbtstat -A $Device | Where-Object { $_ -match '^\s*([^<\s]+)\s*<00>\s*UNIQUE' } | ForEach-Object { $matches[1] }
                if ($DeviceNetBIOS -eq $Null)
                {
                    Write-Verbose "NetBIOS Name Did Not Exist"
                    try 
                    {
                       Write-Verbose "Trying DNS"
                        $Device | ForEach-Object {([system.net.dns]::GetHostByAddress($_)).hostname}
                    } catch {
                        Write-Verbose "There was no NetBOIS or DNS. Using original IP Address: $Device"
                        $Device
                    }
                } else {
                $DeviceNetBIOS
                } # Else NetBIOS $False
            } # Ping $True
        } # Foreach Device
    }
    If ($Show) {
        Write-Host "Scanning Local Subnet"
        $Network
        $NetworkScan | Where -Property domain -NE $Null | Select-Object @{Name="Device";Expression={$_.Domain}}, Ping, WSMAN, RPC, SMB, RDP | Sort | FT
    }
}
  End{}
}
########################
Function Install-Manage {
# PowerShell Download & Install - ConnectWise Manage
$SoftwarePath = "C:\Support\ConnectWise"
$DownloadPath = "https://university.connectwise.com/install/ConnectWise-Internet-Client-x64.msi"
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    If (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
    Set-Location $SoftwarePath
    If ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /qn" -NoNewWindow -Wait -PassThru
$LastExitCode
If ($LastExitCode -eq 0) {Write "Install Executed Without Errors"} Else {Write-Verbose "Error Exit Code: $($LastExitCode)"}
}# Function Install-Manage 
########################
Function Install-Chrome {
# PowerShell Download & Install Google Chrome x64
$SoftwarePath = "C:\Support\Google"
$DownloadPath = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    If (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
    Set-Location $SoftwarePath
    If ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /qn" -NoNewWindow -Wait -PassThru
$LastExitCode
If ($LastExitCode -eq 0) {Write "Install Executed Without Errors"} Else {Write-Verbose "Error Exit Code: $($LastExitCode)"}
}#Function Install-Chrome
########################
Function Show-LTErrors {Get-Content -Path 'C:\Windows\LTSVC\LTErrors.txt' -Tail 25 -Wait}
########################
Function New-IPRange {
<#
.SYNOPSIS
    Returns an array of IP Addresses based on a start and end address

.DESCRIPTION
    Returns an array of IP Addresses based on a start and end address

.PARAMETER Start
    Starting IP Address

.PARAMETER End
    Ending IP Address

.PARAMETER Exclude
    Exclude addresses with this final octet

    Default excludes 0, 1, and 255

    e.g. 5 excludes *.*.*.5

.EXAMPLE
    New-IPRange -Start 192.168.1.5 -End 192.168.20.254

    Create an array from 192.168.1.5 to 192.168.20.254, excluding *.*.*.[0,1,255] (default exclusion)

.NOTES
    Source: Dr. Tobias Weltner, http://powershell.com/cs/media/p/9437.aspx

.FUNCTIONALITY
    Network
#>
[cmdletbinding()]
param (
    [parameter( Mandatory = $true,
                Position = 0 )]
    [System.Net.IPAddress]$Start,

    [parameter( Mandatory = $true,
                Position = 1)]
    [System.Net.IPAddress]$End,

    [int[]]$Exclude = @( 0, 1, 255 )
)
    
    #Provide verbose output.  Some oddities behind casting certain strings to IP.
    #Example: [ipaddress]"192.168.20500"
    Write-Verbose "Parsed Start as '$Start', End as '$End'"
    
    $ip1 = $start.GetAddressBytes()
    [Array]::Reverse($ip1)
    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

    $ip2 = ($end).GetAddressBytes()
    [Array]::Reverse($ip2)
    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

    for ($x=$ip1; $x -le $ip2; $x++)
    {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        if($Exclude -notcontains $ip[3])
        {
            $ip -join '.'
        }
    }
} # End New-IPRange
