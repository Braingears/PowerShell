##### Notes #####
##From ConnectWise Control / ScreenConnect
##!ps
##timeout=900000
##maxlength=9000000
#(New-Object Net.WebClient).DownloadString('https://support.braingears.com/Automate-Module.ps1') | iex; Install-Automate -Server autopt-cf.hostedrmm.com -LocationID 2
###From PowerShell
#(New-Object Net.WebClient).DownloadString('https://support.braingears.com/Automate-Module.ps1') | iex; Install-Automate -Server autopt-cf.hostedrmm.com -LocationID 2
###From CMD Prompt: 
#powershell.exe -Command "(New-Object Net.WebClient).DownloadString('https://support.braingears.com/Automate-Module.ps1') | iex; Install-Automate -Server autopt-cf.hostedrmm.com -LocationID 2"
#
Function Confirm-Automate {
<#
.SYNOPSIS
    This PowerShell Function will confirm if Automate is installed, services running, and checking-in. 

.DESCRIPTION
    This function will automatically start the Automate services (if stopped). It will collect Automate information from the registry.

.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Creation Date:  08/16/2019
    Purpose/Change: Initial script development

.PARAMETER Raw
    This will show the Automate registry entries

.PARAMETER Show
    This will display $Automate object

.PARAMETER Silent
    This will hide all output

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
	
.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Website:        braingears.com
    Creation Date:  8/2019
    Purpose:        Create initial function script


.LINK
    http://braingears.com
#>
 [CmdletBinding(SupportsShouldProcess=$True)]
   Param (
     [switch]$Raw,
     [switch]$Show,
     [switch]$Silent
     )
  $ErrorActionPreference = 'SilentlyContinue'
  Write-Debug "Checking for $($env:windir)\ltsvc folder"
  $Online = If (Test-Path "HKLM:\SOFTWARE\LabTech\Service"){((( (Get-Date) - [System.DateTime](Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus).Seconds) -lt 600)} else {Write $False}
  if (Test-Path "HKLM:\SOFTWARE\LabTech\Service") {
    $Global:Automate = New-Object -TypeName psobject
      $Global:Automate | Add-Member -MemberType NoteProperty -Name ServerAddress -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").'Server Address')
      $Global:Automate | Add-Member -MemberType NoteProperty -Name ComputerID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ID)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name ClientID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").ClientID)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name LocationID -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LocationID)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Version -Value ((Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").Version)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value (Test-Path "$($env:windir)\ltsvc")
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service ltservice).status)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
      $Global:Automate | Add-Member -MemberType NoteProperty -Name LastHeartbeat -Value (((Get-Date) - [System.DateTime](Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").HeartbeatLastReceived).Seconds)
      $Global:Automate | Add-Member -MemberType NoteProperty -Name LastStatus -Value (((Get-Date) - [System.DateTime](Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service").LastSuccessStatus).Seconds)
    Write-Verbose $Automate
    if ($Show -eq $True) {$Automate} else {
        if ($Silent -eq $False) {
        Write "Server Address checking-in to    $($Automate.ServerAddress)"
        Write "ComputerID:                      $($Automate.ComputerID)"
        Write "The Automate Agent Service is    $($Automate.Service)"		
        Write "Last Successful Heartbeat        $($Automate.LastHeartbeat) seconds"
        Write "Last Successful Status Update    $($Automate.LastStatus) seconds"
        }#End else
    }#End if
    if ($Raw -eq $True) {Get-ItemProperty "HKLM:\SOFTWARE\LabTech\Service"}
    } else {
      if ($Silent -eq $False) {Write "Automate is NOT Installed"}
	  $Global:Automate = New-Object -TypeName psobject
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Installed -Value (Test-Path "$($env:windir)\ltsvc")
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Online -Value $Online
      $Global:Automate | Add-Member -MemberType NoteProperty -Name Service -Value ((Get-Service ltservice ).status)
    } #End If Test-Path
} #End Function Confirm-Automate
########################
Set-Alias -Name LTC -Value Confirm-Automate -Description 'Confirm if Automate is running properly'
########################
Function Uninstall-Automate {
<#
.SYNOPSIS
    This PowerShell Function Uninstall Automate. 

.DESCRIPTION
    This function will download the Automate Uninstaller from Connectwise and completely remove the Automate / LabTech Agent. 

.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Creation Date:  08/16/2019
    Purpose/Change: Initial script development

.PARAMETER Silent
    This will hide all output

.EXAMPLE
    Uninstall-Automate [-Silent]

.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Website:        braingears.com
    Creation Date:  8/2019
    Purpose:        Create initial function script
#>
[CmdletBinding(SupportsShouldProcess=$True)]
    Param (
     [switch]$Force,
	 [switch]$Raw,
     [switch]$Show,
     [switch]$Silent
     )
$DownloadPath = "https://s3.amazonaws.com/assets-cp/assets/Agent_Uninstall.exe"
$SoftwarePath = "C:\Support\Automate"
$ErrorActionPreference = 'SilentlyContinue'
Write-Debug "Checking for $($env:windir)\ltsvc folder"
if ((Test-Path "$($env:windir)\ltsvc") -or ($Force -eq $True)) {
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    if (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
    Set-Location $SoftwarePath
    if ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
    if ($Silent -eq $False) {Write-Host "Removing Existing Automate Agent..."}
    Write-Verbose "Closing Open Applications and Stopping Services"
    Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force 
    Stop-Service ltservice,ltsvcmon -Force
    $UninstallExitCode = (Start-Process "cmd" -ArgumentList "/c $($SoftwareFullPath)" -NoNewWindow -Wait -PassThru).ExitCode
    if ($Silent -eq $False) {
        if ($UninstallExitCode -eq 0) {
#            Write-Host " "
            Write-Host "The Automate Agent Uninstaller Executed Without Errors" -ForegroundColor Green
            Write-Verbose "The Automate Agent Uninstaller Executed Without Errors"
        } else {
#            Write-Host " "
            Write-Host "Automate Uninstall Exit Code: $($UninstallExitCode)" -ForegroundColor Red
            Write-Verbose "Automate Uninstall Exit Code: $($UninstallExitCode)"
#            Write-Host " "
        } #else
    } #if Silent
    Confirm-Automate -Silent
    if ($Automate.Installed = $False) {
        Write-Verbose "still waiting..."
        Start-Sleep 30
	}#if Installed
    Confirm-Automate -Silent
    if ($Silent -eq $False) {
        if ($Automate.Installed = $False) {
#		    Write-Host " "
            Write-Verbose "$($env:windir)\LTSVC folder still exists" -ForegroundColor Red
        } else {
#		    Write-Host " "
            Write-Host "The Automate Agent Uninstalled Successfully" -ForegroundColor Green
            Write-Verbose "The Automate Agent Uninstalled Successfully"
        } # else Installed
    }# if $Silent
} # if Test-Path
Confirm-Automate -Silent:$Silent
}# Function Uninstall-Automate
########################
Set-Alias -Name LTU -Value Uninstall-Automate -Description 'Uninstall Automate Agent'
########################
Function Install-Automate {
<#
.SYNOPSIS
    This PowerShell Function is for Automate Deployments

.DESCRIPTION
    Install the Automate Agent.
	
	This function will qualify the if another Autoamte agent is already 
	installed on the computer. If the existing agent belongs to different 
	Automate server, it will automatically "Rip & Replace" the existing 
	agent. This comparison is based on the server's FQDN. 
	
	This function will also verify if the existing Automate agent is 
	checking-in. The Confirm-Automate Function will verify the Server 
	address, LocationID, and Heartbeat/Check-in. If these entries are 
	missing or not checking-in properly; this function will automatically 
	attempt to restart the services, and then "Rip & Replace" the agent to 
	remediate the agent. 
    
	$Automate 
	$Global:Automate
    The output will be saved to $Automate as an object to be used in other functions.
	
	Example:
	Install-Automate -Server 'YOURSERVER.DOMAIN.COM' -LocationID 2 -Transcript
	
	
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

.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Creation Date:  08/2019
    Purpose/Change: Initial script development

.PARAMETER Server
    This is the URL to your Automate server.
    example: Install-Automate -Server 'server.hostedrmm.com' -LocationID 2

.PARAMETER LocationID
    Use LocationID to install the Automate Agent directly to the appropieate client's location / site.
	If parameter is not specified, it will automatically assign LocationID 1 (New Computers).

.PARAMETER Force
    This will force the Automate Uninstaller prior to installation.
    Essentually, this will be a fresh install and a fresh check-in to the Automate server.	

.PARAMETER Silent
    This will hide all output (except a failed installation when Exit Code -ne 0)
    The function will exit once the installer has completed.
	
.PARAMETER Transcript
	This parameter will save the entire transcript and responsed to:
	$($env:windir)\Temp\AutomateLogon.txt

.EXAMPLE
    Install-Automate -Server 'automate.domain.com' -LocationID 42
    This will install the LabTech agent using the provided Server URL, and LocationID.

.NOTES
    Version:        1.0
    Author:         Chuck Fowler
    Website:        braingears.com
    Creation Date:  8/2019
    Purpose:        Create initial function script

.LINK
    http://braingears.com
#>
[CmdletBinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(ValueFromPipelineByPropertyName = $True, Position=0)]
	[Alias("FQDN","Srv")]
	[string[]]$Server = $Null,
	[Parameter(ValueFromPipelineByPropertyName = $True)]
	[AllowNull()]
    [Alias('LID','Location')]
	[int]$LocationID = '1',
	[Parameter()]
	[AllowNull()]
	[switch]$Force,
	[switch]$Silent,
	[switch]$Transcript
    )
Write-Verbose "Checking for missing Server parameter. Server entered: $($Server)"
If ($Server -eq $Null) {
    Write-Host "The Automate Server Parameter Was Not Entered" -ForegroundColor Red
	Write-Host "Help: Get-Help Install-Automate -Full"
} Else {
    $ErrorActionPreference = 'SilentlyContinue'
    if ($Transcript) {Start-Transcript -Path "$($env:windir)\Temp\AutomateLogon.txt" -Force}
    Write-Verbose "Checking Operating System (WinXP and Older) for HTTP vs HTTPS"
    if (([int]((Get-WmiObject Win32_OperatingSystem).BuildNumber) -gt 6000)) {$AutomateURL = "https://$($Server)"} else {$AutomateURL = "http://$($Server)"}
    $SoftwarePath = "C:\Support\Automate"
    $DownloadPath = "$($AutomateURL)/Labtech/Deployment.aspx?Probe=1&installType=msi&MSILocations=$($LocationID)"
    $Filename = "Automate_Agent.msi"
    $SoftwareFullPath = "$SoftwarePath\$Filename"
    Confirm-Automate -Silent
    Write-Verbose "If ServerAddress matches, the Automate Agent is currently Online, and Not forced to Rip & Replace then Automate is already installed."
    Write-Verbose (($Automate.ServerAddress -like "*$($Server)*") -and ($Automate.Online) -and !($Force))
    if (($Automate.ServerAddress -like "*$($Server)*") -and $Automate.Online -and !$Force) {
      if (!$Silent) {Write-Host "The Automate Agent is already installed and checked-in $($Automate.LastStatus) seconds ago to $($Automate.ServerAddress)." -ForegroundColor Green}
      Write-Verbose $Automate
      } else {
        if (!$Silent -and $Automate.Online -and (!($Automate.ServerAddress -like "*$($Server)*"))) {
    	    Write-Host "The Existing Automate Server Does Not Match The Target Automate Server." -ForegroundColor Red
    		Write-Host "Current Automate Server: $($Automate.ServerAddress)" -ForegroundColor Red
    		Write-Host "New Automate Server: https://$Server" -ForegroundColor Green
    	}#If Different Server 
        Write-Verbose "Removing Existing Automate Agent"
    	Uninstall-Automate -Force:$Force -Silent:$Silent
    	Write-Verbose "Uninstall-Automate Completed. Waiting 20 Seconds..."
    	Start-Sleep 20
        Write-Verbose "Installing Automate Agent on $($AutomateURL)"
            if (!(Test-Path $SoftwarePath)) {md $SoftwarePath | Out-Null}
            Set-Location $SoftwarePath
            if ((test-path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath | Out-Null}
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
            if (!$Silent) {Write-Host "Installing Automate Agent to $AutomateURL"}
            Stop-Process -Name "ltsvcmon","lttray","ltsvc","ltclient" -Force -PassThru
    		Write-Verbose $(Get-Variable * | Select-Object -Property Name,Value | fl)
            $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID)" -NoNewWindow -Wait -PassThru).ExitCode
            if ($InstallExitCode -eq 0) {
    		    if (!$Silent) {Write-Host "The Automate Agent Installer Executed Without Errors" -ForegroundColor Green}
                } else {
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Red
    			Write-Host "The Automate MSI failed. Waiting 15 Seconds..." -ForegroundColor Red
                Start-Sleep -s 15
                Write-Host "Installer will execute twice (KI 12002617)" -ForegroundColor Yellow
                $InstallExitCode = (Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /quiet /norestart LOCATION=$($LocationID)" -NoNewWindow -Wait -PassThru).ExitCode
                Write-Host "Automate Installer Exit Code: $InstallExitCode" -ForegroundColor Yellow
                }# end else
        While ($Counter -ne 30) {
            $Counter++
            Start-Sleep 10
            Confirm-Automate -Silent
            if ($Automate.Online -and $Automate.ComputerID -ne $Null) {
    	        if (!$Silent) {
    				Write-Host "The Automate Agent Has Been Successfully Installed" -ForegroundColor Green
    			    $Automate
    			}#end if Silent
    	        Break
            } # end if
        }# end While
        # Write-Verbose (Get-Variable * | Select-Object -Property Name,Value | fl)
        # Write-Verbose (Get-ChildItem env: | fl)
      } #end 
      if ($Transcript) {Stop-Transcript}
} #End $Server Null
} #End Function Install-Automate
########################
Set-Alias -Name LTI -Value Install-Automate -Description 'Install Automate Agent'
########################
Function Install-Chrome {
# PowerShell Download & Install Google Chrome
$SoftwarePath = "C:\Support\Google"
$DownloadPath = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    if (!(Test-Path $SoftwarePath)) {md $SoftwarePath}
    Set-Location $SoftwarePath
    if ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
(Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /qn" -NoNewWindow -Wait -PassThru).ExitCode
}#Function Install-Chrome
########################
Function Install-Manage {
# PowerShell Download & Install - ConnectWise Manage
$SoftwarePath = "C:\Support\ConnectWise"
$DownloadPath = "https://university.connectwise.com/install/2019.4/ConnectWise-Manage-Internet-Client.msi"
    $Filename = [System.IO.Path]::GetFileName($DownloadPath)
    $SoftwareFullPath = "$($SoftwarePath)\$Filename"
    if (!(Test-Path $SoftwarePath)) {md $SoftwarePath}
    Set-Location $SoftwarePath
    if ((Test-Path $SoftwareFullPath)) {Remove-Item $SoftwareFullPath}
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($DownloadPath, $SoftwareFullPath)
(Start-Process "msiexec.exe" -ArgumentList "/i $($SoftwareFullPath) /qn" -NoNewWindow -Wait -PassThru).ExitCode
}# Function Install-Manage 
########################
