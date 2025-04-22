---
title: Active Directory Basics
author: Muhammad Adel
date: 2021-06-25 17:20:00 +0200
categories: [Active Directory 101]
tags: [active directory, redteaming]
---

## **Active directory overview**
#### **what is Active directory?**
Active Directory is a collection of machines and servers connected inside of domains, that are a collective part of a bigger forest of domains, that make up the Active Directory network.
#### **why using active directory?**
it allows for the control and monitoring of their user's computers through a single domain controller. It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine.

## **Physical AD Components**

![Physical AD Components](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLaxK2piSYZmrXIAN0o%2F-MLb7b35ZFHBHU6Gt4KJ%2Fphysicall.png?alt=media&token=a57f5c1b-d0cf-45f1-b579-ca3a3fcc227e)

### **Domain Controllers**
A domain controller is a Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. Domain controllers are the center of Active Directory -- they control the rest of the domain. 

Domain Controllers Functions: 

- holds the AD DS data store.
- handles authentication and authorization services.
- replicate updates from other domain controllers in the forest.
- Allows admin access to manage domain resources.

### **AD DS Data Store**
The Active Directory Data Store holds the databases and processes needed to store and manage directory information such as users, groups, and services. 

AD DS Data Store Functions:

- Contains the NTDS.dit - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users.
- Stored by default in %SystemRoot%\NTDS.
- accessible only by the domain controller.

## **Logical AD Components**

![Logical AD Components](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLaxK2piSYZmrXIAN0o%2F-MLbAgpmd4B9doVtnp7o%2Fall.png?alt=media&token=67fd159e-3d7f-4afd-b6f5-ec08c0aa248c)

- **Trees** - A hierarchy of domains in Active Directory Domain Services.
- **Domains** - Used to group and manage objects .
- **Organizational Units (OUs)** - Containers for groups, computers, users, printers and other OUs.
- **Trusts** - Allows users to access resources in other domains.
- **Objects** - users, groups, printers, computers, shares.
- **Domain Schema** - Rules for object creation.

### **AD Schema**

The Active Directory (AD) schema is the foundational framework that defines the structure and rules for all data stored in the directory. It acts as a blueprint, specifying:

- **What types of objects** can be created (e.g., users, groups, computers).
- **What attributes** those objects can have (e.g., **`sAMAccountName`**, **`mail`**, **`department`**).
- **How objects relate to each other** through inheritance and class hierarchies.

The schema is stored in a dedicated **Schema Partition**, which replicates across all Domain Controllers (DCs) in the forest. Changes to the schema are rare and high-impact, as they affect the entire forest. For example, installing Microsoft Exchange extends the schema by adding new classes (**`msExchMailbox`**) and attributes (**`msExchHomeServerName`**). Schema modifications require **Schema Admin** privileges and are mostly irreversible—attributes can be deactivated but not deleted.

### **AD Objects**

Objects in AD are instances of classes defined in the schema. Each object represents a network resource, identity, or container and includes:

- A **Distinguished Name (DN)**, which defines its location in the directory (e.g., **`CN=JohnDoe,OU=Users,DC=corp,DC=com`**).
- A **Globally Unique Identifier (GUID)**, which persists even if the object is renamed or moved.
- **Attributes**, which store data (e.g., a user’s **`displayName`** or a group’s **`member`** list).

**Key Object Types:**

- **Security Principals** (objects with a **Security Identifier [SID]**):
    - **Users** – Human or service accounts (**`sAMAccountName`**, **`userPrincipalName`**).
    - **Groups** – Collections of users/computers for access control (**`groupType`**, **`member`**).
    - **Computers** – Domain-joined machines (**`dNSHostName`**, **`operatingSystemVersion`**).
- **Non-Security Principals** (objects without SIDs):
    - **Organizational Units (OUs)** – Used for organizing objects and applying Group Policy.
    - **Contacts** – Non-authenticable entries (e.g., external email contacts).

**Security Identifiers (SIDs)**

a unique value that is used to identify any security entity that the Windows operating system (OS) can authenticate. A security entity can be a security principal -- a user account, a computer account or a process started by those accounts -- or it can be a security group.

**How do SIDs work?**

Microsoft Windows security depends on SIDs for authentication. Windows server OSes use SIDs to uniquely identify accounts on the local computer in a persistent way: A user account name could change, but since the SID stays the same, that account can still be identified.

When a computer joins a domain, the domain controller grants it a Domain SID for authentication purposes in the domain. ACLs include lists of SIDs for security principals and groups that are authorized for access to that domain.

There are also well-known SIDs, which are identifiers for generic groups and users that are valid and persistent on all Windows systems. For example, two commonly used well-known SIDs specify the all users group or the Null SID, which is a group that has no members.

**The Format of SIDs**

  **`S-R-X-Y1-Y2-Yn-1-Yn` - `S-1-5-21-1004336348-1177238915-682003330-512`**

- **SID (S):** Indicates that the string is a SID.
- **Revision (R):** is the version level of the SID and is required to be initialized as **`0x01`**.
- **Identifier Authority (X):** Identifies the highest level of authority that can issue SIDs for a particular type of security principal.
- **Sub Authority (Y):** which is contained in a series of one or more sub authority values. All values up to, but not including, the last value in the series collectively identify a domain in an enterprise**.**
- **Relative Identifier (RID):** The last item in the series of sub authority values (-Y*n*) It distinguishes one account or group from all other accounts and groups in the domain. No two accounts or groups in any domain share the same RID.

### **Domain Services**
services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller; however, we'll only be going over the default services that come when you set up a Windows server as a domain controller. Outlined below are the default domain services: 

- **LDAP** - Lightweight Directory Access Protocol; provides communication between applications and directory services.
- **Certificate Services** - allows the domain controller to create, validate, and revoke public key certificates.
- **DNS, LLMNR, NBT-NS** - Domain Name Services for identifying IP hostnames.

### **Domain Authentication**
The most important part of Active Directory -- as well as the most vulnerable part of Active Directory -- is the authentication protocols set in place. There are two main types:

- **Kerberos** - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.
- **NTLM** - default Windows authentication protocol uses an encrypted challenge/response protocol.


## **AD Users**

![AD Users](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLbJOwrqUsd9hIx-ztJ%2F-MLbL6t6OzFWKxiyatYY%2Fusers1.png?alt=media&token=d648d8bc-2d88-49f3-99e8-1971361681b0)

Users are the core to Active Directory; without users why have Active Directory in the first place? There are four main types of users you'll find in an Active Directory network; however, there can be more depending on how a company manages the permissions of its users. The four types of users are:

- **Domain Admins** - This is the big boss: they control the domains and are the only ones with access to the domain controller.
- **Service Accounts** (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
- **Local Administrators** - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
- **Domain** **Users** - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

## **AD Machines**

Machines are another type of object within Active Directory; for every computer that joins the Active Directory domain, a machine object will be created. Machines are also considered "security principals" and are assigned an account just as any regular user. This account has somewhat limited rights within the domain itself.

The machine accounts themselves are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in.

**Note:** Machine Account passwords are automatically rotated out and are generally comprised of 120 random characters.

Identifying machine accounts is relatively easy. They follow a specific naming scheme. The machine account name is the computer's name followed by a dollar sign. For example, a machine named `DC01` will have a machine account called `DC01$`.

## **AD Groups**
 
![AD Groups](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLbJOwrqUsd9hIx-ztJ%2F-MLbL9zRXeA16VGwZ8Dc%2Fgroups.png?alt=media&token=f24e1370-4531-4e6b-800a-693e097b295d) 

Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions. There are two overarching types of Active Directory groups:

- **Security Groups** - These groups are used to specify permissions for a large number of users
- **Distribution Groups** - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration.

### **Default Security Groups**

- **Domain Controllers** - All domain controllers in the domain
- **Domain Guests** - All domain guests
- **Domain Users** - All domain users
- **Domain Computers** - All workstations and servers joined to the domain
- **Domain Admins** - Designated administrators of the domain
- **Enterprise Admins** - Designated administrators of the enterprise
- **Schema Admins** - Designated administrators of the schema
- **DNS Admins** - DNS Administrators Group
- **DNS Update Proxy** - DNS clients who are permitted to perform dynamic updates on - behalf of some other clients (such as DHCP servers).
- **Allowed RODC Password Replication Group** - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
- **Group Policy Creator Owners** - Members in this group can modify group policy for the domain
- **Denied RODC Password Replication Group** - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
- **Protected Users** - Members of this group are afforded additional protections against authentication security threats. 
- **Cert Publishers** - Members of this group are permitted to publish certificates to the directory
- **Read-Only Domain Controllers** - Members of this group are Read-Only Domain Controllers in the domain
- **Enterprise Read-Only Domain Controllers** - Members of this group are Read-Only Domain Controllers in the enterprise
- **Key Admins** - Members of this group can perform administrative actions on key objects within the domain.
- **Enterprise Key Admins** - Members of this group can perform administrative actions on key objects within the forest.
- **Cloneable Domain Controllers** - Members of this group that are domain controllers may be cloned.
- **RAS and IAS Servers** - Servers in this group can access remote access properties of users


## **AD Trusts**

![AD Trusts](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLbLDHeDsEhkuV9lE52%2F-MLbQ1Iwr2_aFHTPbyYO%2Ftrusts.jpg?alt=media&token=ff5c94ea-2f6a-4ec5-b8c7-cf9a3418a3ef)

**Trusts** are a mechanism in place for users in the network to gain access to other resources in the domain. For the most part, trusts outline the way that the domains inside of a forest communicate to each other, in some environments trusts can be extended out to external domains and even forests in some cases.

There are two types of trusts that determine how the domains communicate:

- **Directional** - The direction of the trust flows from a trusting domain to a trusted domain.
- **Transitive** - The trust relationship expands beyond just two domains to include other trusted domains.

The type of trusts put in place determines how the domains and trees in a forest are able to communicate and send data to and from each other when attacking an Active Directory environment you can sometimes abuse these trusts in order to move laterally throughout the network.

### **Trust Direction**
**One-way Trust - Unidirectional**

Users in the trusted domain can access resources in the trusting domain but the revers is not true.

![One-way Trust](/assets/AD-Bascis/trust_direction_one_way.png)


**Two-way Trust - Bi-directional**

Users of both domains can access resources in the other domain.

### **Trust Transitivity**
**Transitive Trust**

A two-way relationship automatically created between parent and child domains in a Microsoft Active Directory forest. When a new domain is created, it shares resources with its parent domain by default, enabling an authenticated user to access resources in both the child and parent. 

![Transitive Trust](/assets/AD-Bascis/tt.jpg)

**Non-transitive Trust**

A trust that will not extend past the domains it was created with. If domain A was connected to domain B and domain B connected to domain C using non-transitive trusts the following would occur. Domain A and domain B would be able to access each other. Domain B could access domain C. Domain A, however, could not access domain C. Even though the domains are indirectly connected, since the trust is non-transitive the connection will stop once it gets to domain B. In order for domain A and domain C to communicate using non-transitive trust you would need to create another trust between domain A and domain C.

![Non Transitive Trust](/assets/AD-Bascis/ntt.jpg)

### **Domain Trusts**

**Default/Automatic trust**

1.  **parent-child trust:** When new child domains are added, two-way transitive trust is automatically established by Active Directory between the child domain and its parent.

2.  **Tree-Root Trust:** This type of trust is created when new root domains are added to an Active Directory forest. These are two-way transitive trusts and only domains at the top of each tree are part of this trust type.

![image.png](/assets/AD-Bascis/dtrust.png)

**Shortcut Trust**

A shortcut trust manually establishes a trust relationship between domains in large Active Directory forests that allows authentication times to improve by shortening the trust path between domains.

![image.png](/assets/AD-Bascis/strust.png)

**External Trust**

External trusts are non-transitive trusts created between Active Directory domains and those located in a different forest, or between an AD forest and a pre-Windows Server 2000 domain such as Windows NT.

**Forest Trust**

Forest trusts is established between forest root domains. it cannot be extended to a third forest. it can be two-way or one-way etc.

![image.png](/assets/AD-Bascis/ftrust.png)

## **AD Polices**

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a whole. They simply act as a ***rulebook for Active Directory*** that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network.

![image.png](/assets/AD-Bascis/gp-editor.png)

There are three types of GPOs:
**• Starter GPOs:** This allows a golden image GPO which can then be further tweaked and deployed between different container objects (=groups) in AD.
**• Local GPOs:** These GPOs only apply to local computers, and are thus not domain dependent. These GPOs can be set on each computer individually and don’t require a computer to be domain joined.
**• Non-Local GPOs:** These GPOs are the most interesting and most encountered ones; These get pushed from the domain controller to all the applicable endpoints

Examples:

- **Disable Windows Defender:** - Disables windows defender across all machine on the domain.
- **Digitally Sign Communication (Always):** - Can disable or enable SMB signing on the domain controller.


## **Access Control List (ACL)**

**An access control list (ACL)** are lists that define *(who has access to which asset/resource - the level of access they are provisioned)* The settings themselves in an ACL are called `Access Control Entries` (`ACEs`). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD. ACLs can also be used for auditing access within AD.

![image.png](/assets/AD-Bascis/acl.png)

**DACL**

**A discretionary access control list (DACL):** identifies the trustees that are allowed or denied access to a securable object. When a process tries to access a securable object, the system checks the ACEs in the object’s DACL to determine whether to grant access to it. If the object does not have a DACL, the system grants full access to everyone. If the object’s DACL has no ACEs, the system denies all attempts to access the object because the DACL does not allow any access rights. The system checks the ACEs in sequence until it finds one or more ACEs that allow all the requested access rights, or until any of the requested access rights are denied.

**SACL**

**A system access control list (SACL):** enables administrators to log attempts to access a secured object. Each ACE specifies the types of access attempts by a specified trustee that cause the system to generate a record in the security event log. An ACE in a SACL can generate audit records when an access attempt fails, when it succeeds, or both. 

### **Access Control Entries (ACEs)**

There are `three` main types of ACEs that can be applied to all securable objects in AD:

| **ACE** | **Description** |
| --- | --- |
| Access denied ACE | Used within a DACL to show that a user or group is explicitly denied access to an object |
| Access allowed ACE | Used within a DACL to show that a user or group is explicitly granted access to an object |
| System audit ACE | Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred |

Each ACE is made up of the following `four` components:

1. **security identifier (SID)** of the user/group that has access to the object (or principal name graphically).
2. **A flag denoting the type of ACE** (access denied, allowed, or system audit ACE).
3. **A set of flags** that specify whether or not child containers/objects **can inherit the given ACE** entry from the primary or parent object.
    
    
    | **Option** | **Technical Name** | **Effect** |
    | --- | --- | --- |
    | **This object only** | **`ADS_ACETYPE_ACCESS_ALLOWED_OBJECT`** (no inheritance) | Permissions apply **only** to the selected object (e.g., a single folder or AD user). |
    | **This object and all descendant objects** | **`ADS_ACETYPE_ACCESS_ALLOWED`** + **`CONTAINER_INHERIT_ACE`** | Permissions apply to **the object + everything inside it** (e.g., a folder and all its files/subfolders). |
    | **All descendant objects** | **`CONTAINER_INHERIT_ACE`** + **`INHERIT_ONLY_ACE`** | Permissions apply **only to child objects**, not the parent itself. |
    | **Only specific object types** | **`ADS_ACETYPE_ACCESS_ALLOWED_OBJECT`** + **`ObjectType`** GUID | Permissions apply **only to a defined class** (e.g., only **`user`** objects, not groups). |
4. An [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) which is a `32-bit` value that defines the rights granted to an object.
