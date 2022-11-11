##########################################################################
# OPS OS hardening script V1.0
# OS: Windows server 2016
# Date: 05 Jan 2018
##########################################################################


#set error-handling
$warningPreference = "SilentlyContinue"

# Varailbes
$filepath="C:\cfg.ini" #file path for secedit output
$indexpath="C:\splunk\Index\OS"
$EnableIndex=$false #to turn on/off generate index file
$EnableFullResult=$false #to show full return result of each check item including Pass and Fail
$bufffile="C:\OS.txt"
$excepfile='C:\excep.txt'
$tmpfile='C:\ostmp.txt'
$computername=$env:computername
$date=get-date
$computerinfo=Get-WmiObject -Class win32_computersystem

#functions
#write result to index file
function WriteToIndex([String]$itm,[String]$res)
{
 if ($EnableIndex){
 $res>>$bufffile}
}
#get username from SID
function GetUsernameFromSID([String]$sid)
{
 if ($sid.trim().Length -gt 0){
 $tsid=$sid.Split(',')
 if ($tsid.Count -gt 0)
 {
   $myArray=@()
   foreach($id in $tsid)
   {
     if ($id.Contains('S-1-')){try{
       $objSID = New-Object System.Security.Principal.SecurityIdentifier ($id.trim())
       $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])}catch{}
       if ($objUser  -ne $null)
       { $myArray+=$objUser.Value}
       else
       {$myArray+=$id}
       }
     else
     {$myArray+=$id}
   }
     $myArray=$myArray -join ','
     $myArray
 }
 else
 {$sid}
}
else
{""}
}

#get folder permissions
function Get-FolderPermission([String] $KeyPath)
{
if (Test-Path $KeyPath -PathType Any)
{
write-output "Folder: $KeyPath"
"Folder: $KeyPath" > $tmpfile
$Path = Get-Acl -filter * -path $KeyPath
$AclList= @()  
foreach ($access in $path.Access)
{
 
$inherFlag = $access.InheritanceFlags.ToString()
$ProgaFlag = $access.PropagationFlags.ToString() 
$folderflag="I:"+$inherFlag+"P:"+$ProgaFlag
if ($ProgaFlag -eq "None")
{
  
  if ($inherFlag -eq "ContainerInherit, ObjectInherit") {$folderflag="This folder, subfolders and files"}
  if ($inherFlag -eq "ContainerInherit") {$folderflag="This folder and subfolders"}
  if ($inherFlag -eq "ObjectInherit") {$folderflag="This folder and files"}
  if ($inherFlag -eq "None") {$folderflag="This folder only"}
}
if ($ProgaFlag -eq "InheritOnly")
{
  
  if ($inherFlag -eq "ContainerInherit, ObjectInherit") {$folderflag="Subfolders and files only"}
  if ($inherFlag -eq "ContainerInherit") {$folderflag="Subfolders only"}
  if ($inherFlag -eq "ObjectInherit") {$folderflag="Files only"}
}
$usrrights=$access.FileSystemRights.ToString()
$usrrights=$usrrights.replace("268435456","FullControl")
$usrrights=$usrrights.replace("-1610612736","ReadAndExecute, Synchronize")
$usrrights=$usrrights.replace("-536805376","Modify, Synchronize")
$usrrights=$usrrights.replace("-2147483648","Read")

$AclList+=@{User=$access.IdentityReference.ToString();Rights=$usrrights;AccessControlType=$access.AccessControlType.ToString();IsInherited=$access.IsInherited.ToString();ApplyTo=$folderflag}     
}
$AclList | % { new-object PSObject -Property $_} | ft -AutoSize
$msg=$AclList | % { new-object PSObject -Property $_} | ft -AutoSize
$msg >>$tmpfile
if (test-path $excepfile){get-content $tmpfile >> $excepfile}
if ($EnableIndex){
if (test-path $bufffile){get-content $tmpfile >> $bufffile}}
}
else
{write-output "Folder: $KeyPath does not exist" 
"Folder: $KeyPath does not exist" > $tmpfile
if (test-path $excepfile){get-content $tmpfile >> $excepfile}
if ($EnableIndex){get-content $tmpfile >>$bufffile}
}
}

#get value from registry key
function Get-RegValue([String] $KeyPath, [String] $ValueName) {
  (Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
}

#Show reult
Function ShowResult($itm,$title,$exp,$val,$res)
{
if ($res)
    {
      write-host "$itm - $title | Expected: $exp | Current: $val | Result: Pass"
      WriteToIndex $itm "$date|$itm|$title|$exp|$val|Pass|"}
    else
    {
      write-host -foregroundcolor red "$itm - $title | Expected: $exp | Current: $val | Result: Fail"
      "$itm - $title | Expected: $exp | Current: $val | Result: Fail" >> $excepfile
      WriteToIndex $itm "$date|$itm|$title|$exp|$val|Fail|"
    }
} 
# list open TCP ports
Function Get-ListeningTCPConnections {            
[cmdletbinding()]            
param(            
)            
            
try {            
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpListeners()            
    foreach($Connection in $Connections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
                    
        $OutputObj = New-Object -TypeName PSobject            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
        $OutputObj            
    }            
            
} catch {            
    Write-Error "Failed to get listening connections. $_"            
}           
}

$dec=@"
***************************************************************
Disclaimer: This verification report is for reference only.
Please use the actual OS Hardening checklist to verify.
***************************************************************
OS Hardening Report(for Windows server 2016)
Script Version: 1.0
OS Hardening Checklist Version: 1.0

"@

write-host $dec

if (test-path $bufffile) {remove-item $bufffile -Force}
if (test-path $excepfile) {remove-item $excepfile -Force}
# List ComputerName, IP address, time
$ip=gwmi Win32_NetworkAdapterConfiguration | Where { $_.IPAddress } |     Select -Expand IPAddress | Where { $_ -notlike "*:*" }
$date=get-date
write-host "Computer: $env:computername | IP Adrress: $ip | Time: $date" 

#OS Hardening Check
write-host "OS Hardening Check..."
write-host "1.1 Security Settings - Account Policies"

# export security settings
secedit /export /cfg $filepath /quiet

#1.1.2 Lockout Duration

$expectation=30
$item="1.1.2"
$title= "AccountLockout Duration(Minutes)"
$Hcheck= cat $filepath | Select-String -pattern "LockoutDuration"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(18).trim() }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.3 Reset account lockout counter after
$expectation=30
$item="1.1.3"
$title="Reset account lockout counter after(Minutes)"
$Hcheck= cat $filepath | Select-String -pattern "ResetLockoutCount"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim()}
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.4 Minimum password length
$expectation=8
$item="1.1.4"
$title="Minimum password length"
$Hcheck= cat $filepath | Select-String -pattern "MinimumPasswordLength"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(23).trim() }
$result=$Hcheck -ge $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.5 Enforce password history
$expectation=24
$item="1.1.5"
$title="Enforce password history"
$Hcheck= cat $filepath | Select-String -pattern "PasswordHistorySize"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(21).trim() }
$result=$Hcheck -ge $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.6 Password must meet complexity requirements
$expectation=1
$item="1.1.6"
$title="Password must meet complexity requirements"
$Hcheck= cat $filepath | Select-String -pattern "PasswordComplexity"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim() }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.7 Store passwords using reversible encryption
$expectation=0
$item="1.1.7"
$title="Store passwords using reversible encryption"
$Hcheck= cat $filepath | Select-String -pattern "ClearTextPassword"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(19).trim() }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.8 Minimum password age
$expectation=1
$item="1.1.8"
$title="Minimum password age(Days)"
$Hcheck= cat $filepath | Select-String -pattern "MinimumPasswordAge"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim() }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.1.9 Maximum password age
$expectation=90
$item="1.1.9"
$title="Maximum password age(Days)"
$Hcheck= cat $filepath | Select-String -pattern "MaximumPasswordAge" |select-object -First 1
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim()} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "`n1.2 Security Settings - Advanced Audit Policy Configurations"

#1.2.6 - [Logon/Logoff] Logoff
$expectation="Success"
$key="Logoff"
$item="1.2.6"
$title="[Logon/Logoff] $key"
$Hcheck=auditpol /get /subcategory:$key|select-string -pattern $key -allmatches -simplematch | Select -last 1
$Hcheck= $Hcheck.tostring().substring($key.length+3).trim()
$result=$Hcheck.ToUpper() -eq $expectation.tostring().ToUpper()
ShowResult $item $title $expectation $Hcheck $result

#1.2.7 - [Logon/Logoff] Logon
$expectation="Success and Failure"
$key="Logon"
$item="1.2.7"
$title="[Logon/Logoff] $key"
$Hcheck=auditpol /get /subcategory:$key|select-string -pattern $key -allmatches -simplematch | Select -last 1
$Hcheck= $Hcheck.tostring().substring($key.length+3).trim()
$result=$Hcheck.ToUpper() -eq $expectation.tostring().ToUpper()
ShowResult $item $title $expectation $Hcheck $result

#1.2.8 - [Logon/Logoff] Special Logon
$expectation="Success"
$key="Special Logon"
$item="1.2.8"
$title="[Logon/Logoff] $key"
$Hcheck=auditpol /get /subcategory:$key|select-string -pattern $key -allmatches -simplematch | Select -last 1
$Hcheck= $Hcheck.tostring().substring($key.length+3).trim()
$result=$Hcheck.ToUpper() -eq $expectation.tostring().ToUpper()
ShowResult $item $title $expectation $Hcheck $result


#1.2.12 - [Policy Change] Authentication Policy Change
$expectation="Success"
$key="Authentication Policy Change"
$item="1.2.12"
$title="[Policy Change] $key"
$Hcheck=auditpol /get /subcategory:$key|select-string -pattern $key -allmatches -simplematch | Select -last 1
$Hcheck= $Hcheck.tostring().substring($key.length+3).trim()
$result=$Hcheck.ToUpper() -eq $expectation.tostring().ToUpper()
ShowResult $item $title $expectation $Hcheck $result



#1.2.17 - [System] Security State Change
$expectation="Success"
$key="Security State Change"
$item="1.2.17"
$title="[System] $key"
$Hcheck=auditpol /get /subcategory:$key|select-string -pattern $key -allmatches -simplematch | Select -last 1
$Hcheck= $Hcheck.tostring().substring($key.length+3).trim()
$result=$Hcheck.ToUpper() -eq $expectation.tostring().ToUpper()
ShowResult $item $title $expectation $Hcheck $result


write-host "`n1.3 Security Settings - Security Options"
write-host "1.3.1 - Accounts"

#1.3.1.1 - Rename administrator account
$expectation="Administrator"
$item="1.3.1.1"
$title="Rename administrator account"
$Hcheck= cat $filepath | Select-String -pattern "NewAdministratorName"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(22).trim().replace("`"","") }
$result=$Hcheck -ne $expectation
ShowResult $item $title "not $expectation" $Hcheck $result

#1.3.1.3 - Limit local account use of blank passwords to console logon only
$expectation="1"
$item="1.3.1.3"
$title="Limit local account use of blank passwords to console logon only"
$Hcheck= cat $filepath | Select-String -pattern "LimitBlankPasswordUse"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(69).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.1.4 - Set Guest account status to disabled
if ($computerinfo.DomainRole -ge 4)
{$expectation=""}else{$expectation="0"}
$item="1.3.1.4"
$title="Set Guest account status to disabled"
$Hcheck= cat $filepath | Select-String -pattern "EnableGuestAccount"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim().replace("`"","")} 
if ($computerinfo.DomainRole -ge 4)
{$result=($Hcheck -eq $expectation) -or ($Hcheck -eq $null)}
else
{
$result=$Hcheck -eq $expectation
}
ShowResult $item $title $expectation $Hcheck $result


write-host "1.3.2 - Audit"


#1.3.2.3 - Shut down system immediately if unable to log security audits
$expectation="0"
$item="1.3.2.3"
$title="Shut down system immediately if unable to log security audits"
$Hcheck= cat $filepath | Select-String -pattern "CrashOnAuditFail"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(64).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "1.3.3 - DCOM"
#1.3.3.1 - Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax
$expectation="Adminitrators and Distributed COM Users"
$item="1.3.3.1"
$title="Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax"
$Hcheck= cat $filepath | Select-String -pattern "MachineLaunchRestriction"

if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(80).trim().replace("`"","") }
$Hcheck= $Hcheck |select-string -Pattern ";;;(.*?)\)" -AllMatches | % { $_.Matches } | % { $_.Value.replace(";;;","").replace(")","") }
$result=$True
$Hcheck_n=""
if ($Hcheck){
$adminuser=Get-WmiObject -Class Win32_GroupUser |  where{$_.GroupComponent -like "*Administrators*"} |% {  
$_.partcomponent –match “.+Domain\=(.+)\,Name\=(.+)$” > $nul  
$matches[1].trim('"') + “\” + $matches[2].trim('"')  
} 
foreach ($f in $Hcheck) {
   $username=(New-Object System.Security.Principal.SecurityIdentifier($f)).Translate( [System.Security.Principal.NTAccount]).Value
   if ($Hcheck_n -eq "")
   {$Hcheck_n=$username}
   else
   {$Hcheck_n=$Hcheck_n+";"+$username}

   if ($f -eq 'S-1-5-7') {$result=$False}
   }
   }
   else
   {
   $Hcheck_n="Not Defined"
   }
ShowResult $item $title $expectation $Hcheck_n $result

write-host "1.3.4 - Devices"

write-host "1.3.5 - Domain Controller"


#1.3.5.7 Synchronize directory service data
$expectation=""
$item="1.3.5.7"
$title="Synchronize directory service data"
$Hcheck= cat $filepath | Select-String -pattern "SeSyncAgentPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(22).trim().replace("*","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result


write-host "1.3.6 - Domain Member"
#1.3.6.1 - Digitally encrypt or sign secure channel data (always)
$expectation="1"
$item="1.3.6.1"
$title="Digitally encrypt or sign secure channel data (always)"
$Hcheck= cat $filepath | Select-String -pattern "RequireSignOrSeal"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(82).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.6.2 - Digitally encrypt secure channel data (when possible)
$expectation="1"
$item="1.3.6.2"
$title="Digitally encrypt secure channel data (when possible)"
$Hcheck= cat $filepath | Select-String -pattern "SealSecureChannel"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(82).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.6.3 - Digitally sign secure channel data (when possible)
$expectation="1"
$item="1.3.6.3"
$title="Digitally sign secure channel data (when possible)"
$Hcheck= cat $filepath | Select-String -pattern "SignSecureChannel"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(82).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.6.4 - Disable machine account password changes
$expectation="0"
$item="1.3.6.4"
$title="Disable machine account password changes"
$Hcheck= cat $filepath | Select-String -pattern "DisablePasswordChange"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(86).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.6.5 - Maximum machine account password age
$expectation="30"
$item="1.3.6.5"
$title="Maximum machine account password age"
$Hcheck= cat $filepath | Select-String -pattern "MaximumPasswordAge" | select -last 1
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(83).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.6.6 - Require strong (Windows 2000 or later) session key
$expectation="1"
$item="1.3.6.6"
$title="Require strong (Windows 2000 or later) session key"
$Hcheck= cat $filepath | Select-String -pattern "RequireStrongKey"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(81).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "1.3.7 - Interactive Logon"


#1.3.7.5 - Do not require CTRL+ALT+DEL
$expectation="0"
$item="1.3.7.5"
$title="Do not require CTRL+ALT+DEL"
$Hcheck= cat $filepath | Select-String -pattern "DisableCAD"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(79).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


#1.3.7.9 - Require Domain Controller authentication to unlock
$expectation="0"
$item="1.3.7.9"
$title="Require Domain Controller authentication to unlock"
$Hcheck= cat $filepath | Select-String -pattern "ForceUnlockLogon"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(81).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result



write-host "1.3.8 - Microsoft Network Client"


#1.3.8.2 -  Digitally sign communications (if server agrees)
$expectation="1"
$item="1.3.8.2"
$title="Digitally sign communications (if server agrees)"
$Hcheck= cat $filepath | Select-String -pattern "LanmanWorkstation\Parameters\EnableSecuritySignature" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(97).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.8.3 - Send unencrypted password to connect to third-party SMB servers
$expectation="0"
$item="1.3.8.3"
$title="Send unencrypted password to connect to third-party SMB servers"
$Hcheck= cat $filepath | Select-String -pattern "EnablePlainTextPassword"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(97).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "1.3.9 - Microsoft Network Server"


#1.3.9.2 - Amount of idle time required before suspending a session
$expectation="15"
$item="1.3.9.2"
$title="Amount of idle time required before suspending a session(Seconds)"
$Hcheck= cat $filepath | Select-String -pattern "AutoDisconnect"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(83).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result



#1.3.9.5 - Disconnect clients when logon hours expire
$expectation="1"
$item="1.3.9.5"
$title="Disconnect clients when logon hours expire"
$Hcheck= cat $filepath | Select-String -pattern "EnableForcedLogOff" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(87).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


#1.3.9.7 - Disable SMB1.0 client
$expectation="Disabled"
$result=$true
$item="1.3.9.7"
$title="Disable SMB1.0 client"
$Hcheck1= Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" "DependOnService"
$Hcheck2= Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
if ($Hcheck1 -match 'mrxsmb10' -and $Hcheck2 -eq '3') {$result=$false}
if ($result) {$Hcheck='Disabled'} else {$Hcheck='Enabled'}
ShowResult $item $title $expectation $Hcheck $result

write-host "1.3.10 - MSS"
#1.3.10.1 - Allow Windows to automatically restart after a system crash
$expectation="1"
$item="1.3.10.1"
$title="Allow Windows to automatically restart after a system crash"
$Hcheck= Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" "AutoReboot"
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


write-host "1.3.11 - Network Access"


#1.3.11.2 - Named pipes that can be accessed anonymously
$expectation=""
$item="1.3.11.2"
$title="Named pipes that can be accessed anonymously"
$Hcheck= cat $filepath | Select-String -pattern "NullSessionPipes"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(85).trim().replace("`"","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null -or $Hcheck -eq "Disabled" 
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.3 - Shares that can be accessed anonymously
$expectation=""
$item="1.3.11.3"
$title="Shares that can be accessed anonymously"
$Hcheck= cat $filepath | Select-String -pattern "NullSessionShares"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(86).trim().replace("`"","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null -or $Hcheck -eq "None" 
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.4 - Allow anonymous SID/name translation
$expectation="0"
$item="1.3.11.4"
$title="Allow anonymous SID/name translation"
$Hcheck= cat $filepath | Select-String -pattern "LSAAnonymousNameLookup"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


#1.3.11.6 - Do not allow anonymous enumeration of SAM accounts
$expectation="1"
$item="1.3.11.6"
$title="Do not allow anonymous enumeration of SAM accounts"
$Hcheck= cat $filepath | Select-String -pattern "RestrictAnonymousSAM=" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(68).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.7 - Let Everyone permissions apply to anonymous users
$expectation="0"
$item="1.3.11.7"
$title="Let Everyone permissions apply to anonymous users"
$Hcheck= cat $filepath | Select-String -pattern "EveryoneIncludesAnonymous"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(73).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.8 - Remotely accessible registry paths and subpaths
$expectation="System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"
$item="1.3.11.8"
$title="Remotely accessible registry paths and subpaths"
$Hcheck= cat $filepath | Select-String -pattern "AllowedPaths\Machine" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(89).trim().replace("`"","")
$Hcheck_n=$Hcheck.Split(",") | sort
$Hcheck_n=$Hcheck_n -join ","
$expectation_n=$expectation.Split(",") | sort
$expectation_n=$expectation_n -join ","
$result=$Hcheck_n -ieq $expectation_n}
else
{$result=$false}
ShowResult $item $title $expectation $Hcheck $result


#1.3.11.9 - Remotely accessible registry paths
$expectation="System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion"
$item="1.3.11.9"
$title="Remotely accessible registry paths"
$Hcheck= cat $filepath | Select-String -pattern "AllowedExactPaths\Machine" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(94).trim().replace("`"","")
$Hcheck_n=$Hcheck.Split(",") | sort
$Hcheck_n=$Hcheck_n -join ","
$expectation_n=$expectation.Split(",") | sort
$expectation_n=$expectation_n -join ","
$result=$Hcheck_n -ieq $expectation_n}
else{$result=$false}
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.10 - Restrict anonymous access to Named Pipes and Shares
$expectation="1"
$item="1.3.11.10"
$title="Restrict anonymous access to Named Pipes and Shares"
$Hcheck= cat $filepath | Select-String -pattern "RestrictNullSessAccess"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(91).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.11.11 - Sharing and security model for local accounts
$expectation="0"
$item="1.3.11.11"
$title="Sharing and security model for local accounts"
$Hcheck= cat $filepath | Select-String -pattern "ForceGuest"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(58).trim().replace("`"","")}
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


###########MS

#1.3.13.1 - Allow automatic administrative logon
$expectation="0"
$item="1.3.13.1"
$title="Allow automatic administrative logon"
$Hcheck= cat $filepath | Select-String -pattern "RecoveryConsole\SecurityLevel" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(91).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

######mMS ENDS


write-host "1.3.12 - Network Security"


#1.3.12.4 - Do not store LAN Manager hash value on next password change
$expectation="1"
$item="1.3.12.4"
$title="Do not store LAN Manager hash value on next password change"
$Hcheck= cat $filepath | Select-String -pattern "NoLMHash"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(56).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


#1.3.12.6 - LDAP client signing requirements
$expectation="1"
$item="1.3.12.6"
$title="LDAP client signing requirements"
$Hcheck= cat $filepath | Select-String -pattern "LDAPClientIntegrity"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(69).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result


write-host "1.3.13 - Recovery Console"

write-host "1.3.14 - Shutdown"

write-host "1.3.15 - System Cryptograhpy"

write-host "1.3.16 - System Object"
#1.3.16.1 - Require case insensitivity for non-Windows subsystems
$expectation="1"
$item="1.3.16.1"
$title="Require case insensitivity for non-Windows subsystems"
$Hcheck= cat $filepath | Select-String -pattern "ObCaseInsensitive"
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(84).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.16.2 - Strengthen default permissions of internal system objects 
$expectation="1"
$item="1.3.16.2"
$title="Strengthen default permissions of internal system objects "
$Hcheck= cat $filepath | Select-String -pattern "Session Manager\ProtectionMode" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(74).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "1.3.17 - System Settings"

write-host "1.3.18 - User Access Control"

ShowResult $item $title $expectation $Hcheck $result

#1.3.18.2 Allow UIAccess applications to prompt for elevation without using the secure desktop
$expectation="0"
$item="1.3.18.2"
$title="Allow UIAccess applications to prompt for elevation without using the secure desktop"
$Hcheck= cat $filepath | Select-String -pattern "EnableUIADesktopToggle" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(91).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.18.5 Detect application installations and prompt for elevation
$expectation="1"
$item="1.3.18.5"
$title="Detect application installations and prompt for elevation"
$Hcheck= cat $filepath | Select-String -pattern "EnableInstallerDetection" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(93).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.18.7 Only elevate UIAccess applications that are installed in secure locations
$expectation="1"
$item="1.3.18.7"
$title="Only elevate UIAccess applications that are installed in secure locations"
$Hcheck= cat $filepath | Select-String -pattern "EnableSecureUIAPaths" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(89).trim().replace("`"","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.18.8 Turn on Admin Approval Mode
$expectation="1"
$item="1.3.18.8"
$title="Turn on Admin Approval Mode"
$Hcheck= cat $filepath | Select-String -pattern "System\EnableLUA" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(78).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.3.18.10 Virtualize file and registry write failures to per-user locations
$expectation="1"
$item="1.3.18.10"
$title="Virtualize file and registry write failures to per-user locations"
$Hcheck= cat $filepath | Select-String -pattern "EnableVirtualization" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(89).trim().replace("`"","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

write-host "`n1.4  Security Settings - User Right Assignments"


#1.4.2 Access Credential Manager as a trusted caller
$expectation=""
$item="1.4.2"
$title="Access Credential Manager as a trusted caller"
$Hcheck= cat $filepath | Select-String -pattern "SeTrustedCredManAccessPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(34).trim().replace("`"","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.3 Access this computer from the network
if ($computerinfo.DomainRole -ge 4)
{$expectation="S-1-5-9,S-1-5-11,S-1-5-32-544"}else{$expectation="S-1-5-11,S-1-5-32-544"}
$item="1.4.3"
$title="Access this computer from the network"
$Hcheck= cat $filepath | Select-String -pattern "SeNetworkLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(22).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.4 Act as part of the operating system
$expectation=""
$item="1.4.4"
$title="Act as part of the operating system"
$Hcheck= cat $filepath | Select-String -pattern "SeTcbPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(17).trim().replace("`"","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.5 Adjust memory quotas for a process
$Hcheck=Get-WmiObject -Class win32_process -Filter "Name='sqlservr.exe'"
if ($Hcheck -ne $null)
{$expectation="S-1-5-19,S-1-5-20,S-1-5-32-544,S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"}
else
{$expectation='S-1-5-19,S-1-5-20,S-1-5-32-544'}
$item="1.4.5"
$title="Adjust memory quotas for a process"
$Hcheck= cat $filepath | Select-String -pattern "SeIncreaseQuotaPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(27).trim().replace("*","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.6 Log on locally
$expectation="S-1-5-32-544"
$item="1.4.6"
$title="Log on locally"
$Hcheck= cat $filepath | Select-String -pattern "SeInteractiveLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result


#1.4.8 Back up files and directories
$expectation="S-1-5-32-544"
$item="1.4.8"
$title="Back up files and directories"
$Hcheck= cat $filepath | Select-String -pattern "SeBackupPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(19).trim().replace("*","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result


#1.4.10 Change the system time
$expectation="S-1-5-19,S-1-5-32-544"
$item="1.4.10"
$title="Change the system time"
$Hcheck= cat $filepath | Select-String -pattern "SeSystemtimePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(24).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.11 Change the time zone
$expectation="S-1-5-19,S-1-5-32-544"
$item="1.4.11"
$title="Change the time zone"
$Hcheck= cat $filepath | Select-String -pattern "SeTimeZonePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(22).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.12 Create a pagefile
$expectation="S-1-5-32-544"
$item="1.4.12"
$title="Create a pagefile"
$Hcheck= cat $filepath | Select-String -pattern "SeCreatePagefilePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(28).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.13 Create a token object
$expectation=""
$item="1.4.13"
$title="Create a token object"
$Hcheck= cat $filepath | Select-String -pattern "SeCreateTokenPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(24).trim().replace("*","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.14 Create global objects
$expectation="S-1-5-19,S-1-5-20,S-1-5-32-544,S-1-5-6"
$item="1.4.14"
$title="Create global objects"
$Hcheck= cat $filepath | Select-String -pattern "SeCreateGlobalPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.15 Create permanent shared objects
$expectation=""
$item="1.4.15"
$title="Create permanent shared objects"
$Hcheck= cat $filepath | Select-String -pattern "SeCreatePermanentPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(28).trim().replace("*","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.16 Create Symbolic Links
$expectation="S-1-5-32-544"
$item="1.4.16"
$title="Create Symbolic Links"
$Hcheck= cat $filepath | Select-String -pattern "SeCreateSymbolicLinkPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(31).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.17 Debug programs
$expectation="S-1-5-32-544"
$item="1.4.17"
$title="Debug programs"
$Hcheck= cat $filepath | Select-String -pattern "SeDebugPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(18).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.18 Deny access to this computer from the network
$expectation="Guests"
$item="1.4.18"
$title="Deny access to this computer from the network"
$Hcheck= cat $filepath | Select-String -pattern "SeDenyNetworkLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("*","") 
$Hcheck=$Hcheck.replace('S-1-5-32-546','Guests')}
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.19 Deny log on as a batch job
$expectation="Guests"
$item="1.4.19"
$title="Deny log on as a batch job"
$Hcheck= cat $filepath | Select-String -pattern "SeDenyBatchLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(23).trim().replace("*","")
$Hcheck=$Hcheck.replace('S-1-5-32-546','Guests')}
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.4.20 Deny log on as a service
$expectation="Guests"
$item="1.4.20"
$title="Deny log on as a service"
$Hcheck= cat $filepath | Select-String -pattern "SeDenyServiceLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("*","")
$Hcheck=$Hcheck.replace('S-1-5-32-546','Guests')} 
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.21 Deny log on locally
$expectation="Guests"
$item="1.4.21"
$title="Deny log on locally"
$Hcheck= cat $filepath | Select-String -pattern "SeDenyInteractiveLogonRight" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(29).trim().replace("*","") 
$Hcheck=$Hcheck.replace('S-1-5-32-546','Guests')}
$result=$Hcheck -eq $expectation
ShowResult $item $title $expectation $Hcheck $result

#1.4.22 Enable computer and user accounts to be trusted for delegation
if ($computerinfo.DomainRole -ge 4)
{$expectation="S-1-5-32-544"}else{$expectation=""}
$item="1.4.22"
$title="Enable computer and user accounts to be trusted for delegation"
$Hcheck= cat $filepath | Select-String -pattern "SeEnableDelegationPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(29).trim().replace("*","") }
if ($computerinfo.DomainRole -ge 4)
{$result=$Hcheck -eq $expectation}
else
{
$result=($Hcheck -eq $expectation) -or ($Hcheck -eq $null)
}
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.23 Force shutdown from a remote system
$expectation="S-1-5-32-544"
$item="1.4.23"
$title="Force shutdown from a remote system"
$Hcheck= cat $filepath | Select-String -pattern "SeRemoteShutdownPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(27).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.24 Generate security audits
$expectation="S-1-5-19,S-1-5-20"
$item="1.4.24"
$title="Generate security audits"
$Hcheck= cat $filepath | Select-String -pattern "SeAuditPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(18).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.25 Impersonate a client after authentication
$expectation="S-1-5-19,S-1-5-20,S-1-5-32-544,S-1-5-6"
$item="1.4.25"
$title="Impersonate a client after authentication"
$Hcheck= cat $filepath | Select-String -pattern "SeImpersonatePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(24).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result


#1.4.27 Increase scheduling priority
$expectation="S-1-5-32-544"
$item="1.4.27"
$title="Increase scheduling priority"
$Hcheck= cat $filepath | Select-String -pattern "SeIncreaseBasePriorityPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(33).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.28 Load and unload device drivers
$expectation="S-1-5-32-544"
$item="1.4.28"
$title="Load and unload device drivers"
$Hcheck= cat $filepath | Select-String -pattern "SeLoadDriverPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(23).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.29 Lock pages in memory
$Hcheck=Get-WmiObject -Class win32_process -Filter "Name='sqlservr.exe'"
if ($Hcheck -ne $null)
{$expectation="S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"}
else
{$expectation=''}
$item="1.4.29"
$title="Lock pages in memory"
$Hcheck= cat $filepath | Select-String -pattern "SeLockMemoryPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(23).trim().replace("*","") }
if ($expectation -eq ''){$result=$Hcheck -eq $expectation -or $Hcheck -eq $null}
else
{$result=$Hcheck -eq $expectation}
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result


#1.4.31 Manage auditing and security log
$expectation="S-1-5-32-544"
$item="1.4.31"
$title="Manage auditing and security log"
$Hcheck= cat $filepath | Select-String -pattern "SeSecurityPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(21).trim().replace("*","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.32 Modify an object label
$expectation=""
$item="1.4.32"
$title="Modify an object label"
$Hcheck= cat $filepath | Select-String -pattern "SeRelabelPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim().replace("*","") }
$result=$Hcheck -eq $expectation -or $Hcheck -eq $null
ShowResult $item $title $expectation $Hcheck $result

#1.4.33 Modify firmware environment values
$expectation="S-1-5-32-544"
$item="1.4.33"
$title="Modify firmware environment values"
$Hcheck= cat $filepath | Select-String -pattern "SeSystemEnvironmentPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(30).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.34 Perform volume maintenance tasks
$expectation="S-1-5-32-544"
$item="1.4.34"
$title="Perform volume maintenance tasks"
$Hcheck= cat $filepath | Select-String -pattern "SeManageVolumePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(25).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.35 Profile single process
$expectation="S-1-5-32-544"
$item="1.4.35"
$title="Profile single process"
$Hcheck= cat $filepath | Select-String -pattern "SeProfileSingleProcessPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(33).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.36 Profile system performance
$expectation="S-1-5-32-544,S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$item="1.4.36"
$title="Profile system performance"
$Hcheck= cat $filepath | Select-String -pattern "SeSystemProfilePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(26).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.37 Remove computer from docking station
$expectation="S-1-5-32-544"
$item="1.4.37"
$title="Remove computer from docking station"
$Hcheck= cat $filepath | Select-String -pattern "SeUndockPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(19).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.38 Replace a process level token
$Hcheck=Get-WmiObject -Class win32_process -Filter "Name='sqlservr.exe'"
if ($Hcheck -ne $null)
{$expectation="S-1-5-19,S-1-5-20,S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430,S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003"}
else
{$expectation='S-1-5-19,S-1-5-20'}
$item="1.4.38"
$title="Replace a process level token"
$Hcheck= cat $filepath | Select-String -pattern "SeAssignPrimaryTokenPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(31).trim().replace("*","")} 
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.39 Restore files and directories
$expectation="S-1-5-32-544"
$item="1.4.39"
$title="Restore files and directories"
$Hcheck= cat $filepath | Select-String -pattern "SeRestorePrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(20).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.40 Shut down the system
$expectation="S-1-5-32-544"
$item="1.4.40"
$title="Shut down the system"
$Hcheck= cat $filepath | Select-String -pattern "SeShutdownPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(21).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result

#1.4.41 Take ownership of files or other objects
$expectation="S-1-5-32-544"
$item="1.4.41"
$title="Take ownership of files or other objects"
$Hcheck= cat $filepath | Select-String -pattern "SeTakeOwnershipPrivilege" -SimpleMatch
if ($Hcheck -ne $null){$Hcheck= $Hcheck.ToString().Substring(26).trim().replace("*","") }
$result=$Hcheck -eq $expectation
ShowResult $item $title $(GetUsernameFromSID $expectation) $(GetUsernameFromSID $Hcheck) $result


write-host "`n2.1 - Administrative Templates - Windows Components"

write-host "`2.1.1 - AutoPaly Policy"



write-host "`2.1.2 - Event Log"


#2.1.2.7 - Logs containing auditing info should be protected from guest access for servers
$expectation="Application=1,System=1,Security=1"
$item="2.1.2.7"
$title="Logs containing auditing info should be protected from guest access for servers"
$Hcheck_1= Get-RegValue "HKLM:\System\CurrentControlSet\Services\EventLog\Application" "RestrictGuestAccess"
$Hcheck_2= Get-RegValue "HKLM:\System\CurrentControlSet\Services\EventLog\System" "RestrictGuestAccess"
$Hcheck_3= Get-RegValue "HKLM:\System\CurrentControlSet\Services\EventLog\Security" "RestrictGuestAccess"
$r1=$Hcheck_1 -eq '1'
$r2=$Hcheck_2 -eq '1'
$r3=$Hcheck_3 -eq '1'
$result= $r1 -and $r2 -and $r3
$Hcheck="Application=$Hcheck_1,System=$Hcheck_2,Security=$Hcheck_3"
ShowResult $item $title $expectation $Hcheck $result

#write-host "2.1.3 - Remote Desktop Services"

#write-host "`2.1.4 - Windows Installer"


write-host "`2.1.11 - Windows Remote Management(WinRM)"





write-host "`n2.5 - LAPS"
#2.5.1 Enable local admin password management
#if ($computerinfo.DomainRole -ge 4)
#{$expectation=""}else{$expectation="1"}
#$item="2.5.1"
#$title="Enable local admin password management"
#$Hcheck= Get-RegValue "HKLM:\Software\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled"
#if ($computerinfo.DomainRole -ge 4)
#{$result=($Hcheck -eq $expectation) -or ($Hcheck -eq $null)}
#else
#{
#$result=$Hcheck -eq $expectation
#}
#ShowResult $item $title $expectation $Hcheck $result

write-host "`n3 - Others"
# Antivirus status
$item="3.1"
$title="anti-virus software"
$dsa_process = GET-Process "dsa"
#Edit by Mohit
#if ($dsa_process -eq $null -or $dsa_process -eq "")
if ($dsa_process -like "*dsa*")
{ 
write-host "Anti Virus Found - DSA"
GET-Process "dsa"
 }else
 {
 write-host "No AntiVirus Found"
}
#Edit by Mohit Ends

#3.2 Windows Updates
$item="3.2"
$title="Windows Updates"
write-host "`n$item - $title"
if ($EnableIndex){"$date|$item|$title|Latest packs are updated|See reference|Manual Check|">>$bufffile}
"$item - $title | Expected: Latest packs are updated|Current: See reference|Result: Manual Check|">>$excepfile
$lastupdated= Get-HotFix -ComputerName $env:computername | Measure-Object InstalledOn -Maximum | select-object Maximum| ft -HideTableHeaders| out-string
$lastupdated=$lastupdated.Replace("`n","")
write-host "Last Windows Update: $lastupdated"
"Last Windows Update: $lastupdated" >> $excepfile
if ($EnableIndex){ "Last Windows Update: $lastupdated">>$bufffile}
#Get All Assigned updates in $SearchResult  
 try{
 $UpdateSession = New-Object -ComObject Microsoft.Update.Session  
 $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()  
 $SearchResult = $UpdateSearcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0")  
 }
 catch{}
#Matrix Results for type of updates that are needed  
 $Critical = $SearchResult.updates | where { $_.MsrcSeverity -eq "Critical" }  
 $important = $SearchResult.updates | where { $_.MsrcSeverity -eq "Important" }  
 $other = $SearchResult.updates | where { $_.MsrcSeverity -eq $null }  
write-host "===== Pending Updates ====="

"===== Pending Updates =====" >> $excepfile
if ($EnableIndex){"===== Pending Updates ====="  >> $bufffile}
if ($SearchResult.Updates.Count -gt 0)
{
 For($i=0;$i -lt $SearchResult.Updates.Count; $i++)  
 {  
   Write-host "$($i + 1): $($SearchResult.Updates.Item($i).Title)" 
   "$($i + 1): $($SearchResult.Updates.Item($i).Title)" >> $excepfile
   if ($EnableIndex){ "$($i + 1): $($SearchResult.Updates.Item($i).Title)" >> $bufffile}
   #Write-Host "Description:"  
   #Write-Host "$($SearchResult.Updates.Item($i).Description)"  
 }}
 else
 {
   write-host "None" 
   "None" >> $bufffile
   "None" >> $excepfile
 }


#3.8 All disk partitions shall be on NTFS volumes
$expectation="NTFS"
$item="3.8"
$title="All disk partitions shall be on NTFS volumes"
$result=$true
$Hcheck_n=""
$Hcheck= Get-WMIObject win32_logicaldisk -filter drivetype=3 | select deviceID,Filesystem
foreach ($s in $Hcheck)
{
  $Hcheck_n+=$s.deviceID + " NTFS,"
  if ($s.Filesystem -ne "NTFS")
  {
    $result=$false
  }
}
if ($Hcheck_n.Length -gt 0) {$Hcheck_n=$Hcheck_n.Substring(0,$Hcheck_n.length-1)}
ShowResult $item $title $expectation $Hcheck_n $result

#3.9 folder permissions
$item="3.9"
$title="Folder Permissions"
write-host "`n$item - $title"
if ($EnableIndex){"$date|$item|$title|Set Proper permissions|See reference|Manual Check|">>$bufffile}
"$item - $title|Expected: Set Proper permissions|Current: See reference|Result: Manual Check|">> $excepfile
Get-FolderPermission "$env:SystemDrive\"
Get-FolderPermission $env:SystemRoot
Get-FolderPermission "$env:SystemRoot\system32"
Get-FolderPermission "$env:SystemRoot\system32\drivers"
Get-FolderPermission "$env:SystemRoot\system32\spool"
Get-FolderPermission "$env:SystemRoot\system32\config"
Get-FolderPermission "$env:SystemRoot\sysvol"
Get-FolderPermission "$env:SystemRoot\security"
