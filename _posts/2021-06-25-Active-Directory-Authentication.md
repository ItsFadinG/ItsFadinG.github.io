---
title: Active Directory Authentication
author: Muhammad Adel
date: 2021-06-25 18:30:00 +0200
categories: [Active Directory 101]
tags: [active directory, Android Security]
---

## **Local Windows Authentication**

![Untitled](/assets/AD-Auth/Untitled.png)

![Untitled](/assets/AD-Auth/Untitled%201.png)

This graphical representation should help you to make more sense in terms of how authentication flows on Windows based systems. 

1. The user starts their computer. Depending on the system configuration, they may also need to press `Ctrl+Alt+Del`.
2. In the background, the `winlogon.exe` process runs under the SYSTEM context and waits for user credentials.
3. `winlogon.exe` communicates with credential providers (such as LSASS) to gather information like which users are already logged in or who last logged in. This improves user experience by pre-selecting the account, so users often only need to enter their password.
4. The gathered information is passed to the Logon UI, which is then presented to the user.
5. The user selects his/her profile or chooses 'different user' and provides their credentials to the UI. 
6. The logon UI sends the credentials back to `CredUI.DLL` 
7. `CredUI.DLL` is a proxy at this point, simply forwarding the credentials back to the credential provider. 
8. And the `Winlogon.exe` process, which ultimately: 
9. Initializes LSA on the user's behalf and authenticates the user.

## **NTLM Authentication**

when Kerberos authentication is not possible, Windows will fall back to NTLM authentication. This can even happen between machines that are members of the same domain, but when all necessary conditions to use Kerberos are not in place. For example, Kerberos works with so-called service names. If we don't have a name, Kerberos cannot be used. This is the case when we access a share on a file server by using the IP address of the server instead of its server name. NTLM authentication is a two-party authentication: the client and the server. It takes three steps:

![Untitled](/assets/AD-Auth/ntlm.png)

1. **Negotiate:** the client sends a negotiate packet to the server to request the authentication. There are different parameters and versions for NTLM, and the client has to inform the server what it is capable of. This is done with a negotiate packet.
2. **Challenge:** the server sends a challenge packet to the client. This challenge includes a so-called "nonce". A **nonce** is a random number of 16 bytes.
3. **Response:** the client sends the response to the server: it calculates a response by hasing the nonce with the NT hash of the user’s passwrod and sends that to the server. Using a nonce allows the two parties to perform authentication without having to send the password (cleartext or encrypted) over the network. The server checks the credentials of the client by performing the same calculation as the client for the response, and if the response calculated by the server is the same as the response calculated by the client, then the client is authenticated to the server.

## **Kerberos Authentication**

**Overview**: 

-   **Ticket Granting Ticket (TGT)** - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.

-   **Key Distribution Center (KDC)** - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.

-   **Authentication Service (AS)** - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.

-   **Ticket Granting Service (TGS)** - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.

-   **Service Principal Name (SPN)** - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set. **SPN Format** are serviceclass/host:port servicename like, MSSQLSvc/SQLSERVER2.corp. local:1433

-   **KDC Long Term Secret Key (KDC LT Key)** - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.

-   **Client Long Term Secret Key (Client LT Key)** - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.

-   **Service Long Term Secret Key (Service LT Key)** - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.

-   **Session Key** - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.

-   **Privilege Attribute Certificate (PAC)** - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user. The authorization step depends on it.

**KRBTGT Account**

Every active directory domain has something called krbtgt account. By default, the **krbtgt** account is not visible in the user’s container. However, you can reveal it by accessing “View” and then selecting “Advanced Features” in the menu. After doing this, you will see the **krbtgt** account listed. This account is referred to as the key distribution center service account, which plays a significant role in Kerberos.

![](https://miro.medium.com/v2/resize:fit:624/1*3HZ5F-rNxUcx505YH6mAtA.png)

The term **“key distribution center” (KDC)** is commonly used to describe the central database that stores user credentials and manages incoming ticket requests. ***In the context of Active Directory, each domain controller essentially functions as a KDC.*** Therefore, when you encounter the term DC (domain controller) or KDC in Kerberos language, you can equate it to the key distribution center.

While the **krbtgt** account appears as a user account, it cannot be used for regular logins. By default, it is disabled and cannot be enabled. Its password is set by the system and is highly complex. You need not be concerned about the specifics of this password, as you will never need to use this account for login purposes. The system keeps the password secure, and no other entity should ever be aware of it.

**Kerberos Deep Drive**

![Untitled](/assets/AD-Auth/Untitled%203.png)

### **Authentication Server Request (AS-REQ)**

 **1.** The user requests a Ticket-Granting Ticket (TGT) from the Key Distribution Center (KDC)

 **IF Pre-authenticaion Disabled**

the client can send the AS-REQ **without first encrypting a timestamp**. The KDC responds directly with an encrypted TGT and a message encrypted with the user password. ( The following images assume that pre-auth is disabled )

**IF Pre-authenticaion Enabled**

User sends encrypted data known as “pre-authentication data”. **The user sends the current time encrypted with their password to the domain controller**. Since the domain controller can access everyone’s passwords, it decrypts the timestamp using the user’s password to verify its accuracy.

![Untitled](/assets/AD-Auth/Untitled%204.png)

### **Authentication Server Response (AS-REP)**

**2.** The **Authentication Server (AS)** as part of the **Key Distribution Center (KDC)** checks if the provided user is in the database.

![Untitled](/assets/AD-Auth/Untitled%205.png)

**3.** If the user is a valid domain user, The **Authentication Server (AS)** will generate the user secret key by hashing the user’s password. Then, the **Authentication Server (AS)** sends two messages to the User:

**The First Message:** is encrypted by the user/client secret key and contains the ID of the **Ticket Granting Server (TGS)** and **TGS** session key which is a randomly generated session key.
**The Second Message:** is the **Ticket Granting Ticket (TGT)** encrypted by TGS secret key, so it’s content can only be deciphered by the TGS. it contains *user ID*, *user network address*, *lifetime*, *timestamp* and the *TGS session key*.

![Untitled](/assets/AD-Auth/Untitled%206.png)

### **Ticket Granting Server Request (TGS-REQ)**

**4.** the user decrypt the first message by authenticating with his password to obtain the TGS session key.

![Untitled](/assets/AD-Auth/Untitled%207.png)

**5**. the user create two new messages:

- **The First One:** contains the service that the user want to access.
- **The Second One** is the **User Authenticator** encrypted by the TGS Session key which contains the user’s username. 
- Finally, the server sends these two messages along with the TGT to the **Ticket Granting Server (TGS)**.

![Untitled](/assets/AD-Auth/Untitled%208.png)


### **Ticket Granting Server Response (TGS-REP)**

**6**. The TGS first checks the service ID if it is available in their database or not. then the TGS will grab a copy of the service secret key to encrypt the service ticket with it.

![Untitled](/assets/AD-Auth/Untitled%209.png)

**7**. The TGS will decrypt the TGT with *the TGS secret key* which contains the TGS Session key. Then the User Authenticator will be decrypted by the TGS Session Key. Finally, the TGS will check if the information in TGT matches with the User Authenticator if it match the TGS will add it to its cache.

![Untitled](/assets/AD-Auth/Untitled%2010.png)

**8**. The TGS will create its own messages and send it back to the user:

- **The First Message:** contains the service ID *(that the user want to access)* and the **Service Session Key** the message will be encrypted by TGS Session Key.
- **The Second Message:** is the **Service Ticket** **(TGS Tickets)** which will be encrypted by Service Secret Key. It contains the *user’s ID, service name and the service session key.*

![Untitled](/assets/AD-Auth/Untitled%2011.png)

### **The 2nd part User<-> Service**

**9**. Since the user has the TGS session key from the **AS-REP** phase, he will decrypt the first message. Now the user has access to the Service Session key. So he will create a **User Authenticator Message** and encrypt it with the Service Session Key. Then he will send both the User Authenticator and the Service Ticket to the Service.

![Untitled](/assets/AD-Auth/Untitled%2012.png)

**10**. Now the steps will happen again. The service will decrypt the Service Ticket using its secret key. As a result, it will have access to the Service Session Key to decrypt the User Authenticator. Lastly The service will **check** the matching between the two messages, if they are matched it will **add** the User Authenticator to the its cache and then **create** a Service Authenticator Message encrypted by the Service Session Key and send it to the user.

![Untitled](/assets/AD-Auth/Untitled%2013.png)

**11**. Finally, the User will decrypt the Service Authenticator using the Service Session Key and validate the service name. The mutual authentication is now complete. The Kerberos client can now start issuing service requests, and the Kerberos service can provide the requested services for the client.



Now, you can see the whole walk-through in one image thanks to [DestCert](https://drive.google.com/file/d/1Lc9IzvvB4ZharVIqWMOaXjngXro0c6hd/view).