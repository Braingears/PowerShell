## This script creates a new OU in active directory, creates new user account, then adds the user to Domain Admins security groups. 
## Created by Chuck Fowler - 2018-12-12

# Please assign the following variables. Additional user and MSP defaults can be set in $UserAttributes below. 
$Username = 'juser'
$FirstName = 'Joe'
$LastName = 'User'
$Password = 'ChangeP@sswordH3re'
$CreateOUName = 'IT Support'

# New Active Directory OU
import-module activedirectory
	$RootDNPath = Get-ADDomain | select -ExpandProperty DistinguishedName
	$OUPath = "OU=$($CreateOUName),$($RootDNPath)"
	$RootDomain = (Get-ADForest).RootDomain

$OUAttributes = @{
    Name = $CreateOUName
    #Description = "IT Support"
    Path = Get-ADDomain | select -ExpandProperty DistinguishedName
    ProtectedFromAccidentalDeletion = $False
    }
If (Get-ADOrganizationalUnit -Filter 'Name -eq $CreateOUName') 
	{Write "The Organization Unit '$($CreateOUName)' Already Exists"}
	Else {
		New-ADOrganizationalUnit @OUAttributes
		If (Get-ADOrganizationalUnit -Filter 'Name -eq $CreateOUName') {Write "The Active Directory OU '$($CreateOUName)' was created Successfully!"}
			Else {Write-Warning "The Active Directory OU '$($CreateOUName)' was NOT CREATED"}
		}

# Create Active Directory User Account
$UserAttributes = @{
	Enabled = $true
	ChangePasswordAtLogon = $false
	Path = $OUPath
	UserPrincipalName = (write "$($Username)@$($RootDomain)")
	SamAccountName = $Username
	Name = "$FirstName $LastName"
	GivenName = $FirstName
	Surname = $LastName
	DisplayName = "$FirstName $LastName"
	Initials = "IT"
	Description = "IT Support Services Account"
	#Office = "Remote"
	Company = "MSP Name"
	Department = "IT"
	#Title = "Sr. Network Administrator"
	StreetAddress = "500 Beach Drive"
	City = "St Petersburg"
	State = "Florida"
	PostalCode = "33701"
	OfficePhone = "(813) 555-4114"
	MobilePhone = "(727) 555-4111"
	AccountPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
	}
if (Get-ADUser -Filter {SamAccountName -eq $Username})
	{Write-Warning "A user account '$Username' has already exist in Active Directory."}
	else {
	  New-ADUser @UserAttributes
	  if (Get-ADUser -Filter {SamAccountName -eq $Username}) {Write "The Active Directory User Account '$($Username)' was created Successfully!"}
	  else {Write-Warning "The Active Directory User Account '$($Username)' was NOT CREATED"}
	}

# Add User to Domain Administrative Security Groups
Add-ADGroupMember -Identity "Domain Admins" -Members $Username
Add-ADGroupMember -Identity "Enterprise Admins" -Members $Username
Add-ADGroupMember -Identity "Exchange Organization Administrators" -Members $Username
Add-ADGroupMember -Identity "Schema Admins" -Members $Username
Sleep 5
Write " "
Write "The user account '$($Username)' for $($FirstName) $($LastName) is now a member of:"
(Get-ADPrincipalGroupMembership $Username).Name

