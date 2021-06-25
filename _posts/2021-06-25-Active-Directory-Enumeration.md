---
title: Active Directory Enumeration
author: Muhammad Adel
date: 2021-06-25 18:35:00 +0200
categories: [Active Directory 101]
tags: [active directory, red team]
---

## **Using PowerView**

### **Domain Information**

```c
PS C:\Users> Get-NetDomain
PS C:\Users> Get-NetDomain -Domain m.local
PS C:\Users> Get-NetDomainSID
PS C:\Users> Get-NetDomainController
PS C:\Users> Get-NetDomainController -Domian m.local
PS C:\Users> Find-UserField -SearchField Description -SearchTerm "pass"
```
‌
### **Domain Policy**

```c
PS C:\> Get-DomainPolicy."system access"
PS C:\Users> Get-DomainPolicy."Kerberos Policy"
```

### **Computer Objects**


```c
PS C:\Users> Get-NetComputer
PS C:\Users> Get-NetComputer -FullData
```
‌
### **Users Information**

```c
PS C:\Users\Administrator\Desktop> Get-NetUser
PS C:\Users\Administrator\Desktop> Get-NetUser | select cn
PS C:\Users\Administrator\Desktop> Get-NetUser -Username Student1
PS C:\Users\Administrator\Desktop> Get-UserProperty
PS C:\Users\Administrator\Desktop> Get-UserProperties -Properties admincount
```
### **Groups information**

```c
PS C:\Users> Get-NetGroup -FullData
PS C:\Users> Get-NetGroup -GroupName "*admin*"
PS C:\Users> Get-NetGroupMember -GroupName "Domain Admin"
PS C:\Users> Get-NetGPO
PS C:\Users> Get-NetGPO -GPOname "{}"
PS C:\Users> Get-NetGPOGroup // Restricted Groups
```
‌
### **Organizational units**

```c
PS C:\Users> Get-NetOU
```
‌
### **Shares**

```c
PS C:\Users> Invoke-ShareFinder -verbose
```
‌
### **Sensitive Files**

```c
PS C:\Users> Invoke-FileFinder -Verbose
```
‌

### **ACL**

```c
PS C:\Users> Get-ObjectAcl -SamAccountName fcastle
PS C:\Users> Invoke-ACLScanner // search for intersting ACEs
```

### **Trusts**

```c
 PS C:\Users> Get-NetDomainTrust
 PS C:\Users> Get-NetDomainTrust -Domain  corp.local
```
‌
### **Forest**

```c
PS C:\Users> Get-NetForest
PS C:\Users> Get-NetForest -Forest m.local
PS C:\Users> Get-NetForestDomain // Get all domains in the forest
PS C:\Users> Get-NetForestTrust
PS C:\Users> Get-NetForestCatalog
```

### User Hunting

Its much more **noisy** because it is query information from all domains not just the DC. it is checking if the current user has an admin access in any other machines.

```c
PS C:\Users> Find-LocalAdminAccess -Verbose
PS C:\Users> Invoke-EnumerateLocalAdmin -Verbose // needs Admin privs
PS C:\Users> Invoke-UserHunter
```
‌

## Blood Hound

Bloodhound is a graphical interface that allows you to visually map out the network. This tool along with SharpHound which similar to PowerView takes the user, groups, trusts etc. of the network and collects them into .json files to be used inside of Bloodhound.

```c
PS C:\Users\fcastle> Powershell -e bypass
PS C:\Users\fcastle>  .  .\SharpHound.ps1
PS C:\Users\fcastle> Invoke-BloodHound -CollectionMethod All -Domain Marvel.local -ZipFilename file.zip
------------------------------------------------
Initializing SharpHound at 5:45 AM on 11/15/2020
------------------------------------------------

Resolved Collection Methods: Group, Sessions, LoggedOn, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain MARVEL.LOCAL using path CN=Schema,CN=Configuration,DC=MARVEL,DC=LOCAL

PS C:\Users\fcastle>  [+] Cache File Found! Loaded 100 Objects in cache

[+] Pre-populating Domain Controller SIDS

Status:  0 objects finished (+0)  -- Using 82 MB RAM
Status:  64 objects finished (+64  64)/s -- Using 84 MB RAM
Enumeration finished in 00:00:01.7307250
Compressing data to C:\Users\fcastle\20201115054520_file.zip
You can upload this file directly to the UI
SharpHound Enumeration Completed at 5:45 AM on 11/15/2020! Happy Graphing!
```
‌
After importing the grabbed files into blood hound. you can now map the whole active directory with a graphical view.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMB9qGZwjg0L65H4FYo%2FBllod.png?alt=media&token=55e8affe-4aa5-40b5-9934-c8810bab1d65)


![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MMAuubtIy2cAbBneLQr%2F-MMB9to_eBNQv0AM-YyI%2Fblood.png?alt=media&token=0ad1a4f1-a77d-4678-bd27-bd8a9efb6593)
