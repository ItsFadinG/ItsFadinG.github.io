---
title: Active Directory Authentication
author: Muhammad Adel
date: 2021-06-25 18:30:00 +0200
categories: [Active Directory 101]
tags: [active directory, red team]
---

## Kerberos Overview

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

‌

## **Kerberos in details**

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLlr1TRs1djcaI6suf7%2F1.png?alt=media&token=a150d190-c360-4fe3-be91-c70e819ab9ce)


### **AS-REQ**

**1**.A Kerberos client sends its user ID in a clear-text message to the AS. The message does not include the client's password, nor its secret key based on the password.

![User's Message](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLlsLFgJYfer90yh6ef%2FUsers%20Message%201%20to%20the%20kdc.png?alt=media&token=0739bccb-98e0-4cec-a085-54ca10e66576)



![From User to AS](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLm5jn9Hbpj1VtgNnWU%2F1%20-%20Users%20Message%20kdc%202.png?alt=media&token=a8b259b6-25f7-4b31-b832-a3f99de04f78)

**2**.The AS checks if the client is in the user database.

![](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLlt_gfHgAOdGPQA7l7%2F2%20-%20AS%20Checks.png?alt=media&token=aed3a457-837e-4f1f-9337-6e83155b64d2)


### **AS-REP**


**3**. The AS generates the client secret key for the client by hashing the client's password. Then, the AS sends two messages to the User. **the first message**, encrypted by the client secret key, contains the ID of the TGS and TGS session key which a randomly generated session key. **the second message** is the TGT ticket encrypted by TGS secret key, so it's contents can only be deciphered by the TGS. it contains client ID, client network address, lifetime, timestamp and the TGS session key.

![From AS to User](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLm5spkt9V2vlC9l0KM%2F3%20-%20AS%20to%20the%20user.png?alt=media&token=b0b518a5-102b-49d9-91ad-f3bc17306afc)

**4**. the client decrypt the first message by authentication with his password to obtain the TGS session key.

![the user decrypt the AS first message](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmAAEPkWB9QOGvNpVK%2F4%20-%20decrypt%20the%20message.png?alt=media&token=2e07eabb-c365-4618-8fac-45353237d0c2)


### **TGS-REQ**

**5**. the user create two new messages. **the first one** contains the service that the user want to access. **the second** is the User Authenticator **encrypted** by the TGS Session key which contains the user/id. then the server send these two messages along with TGT to the TGS.

![From User to TGT](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmBfOvr7TahzDKtIgq%2F5%20-%20USER%20to%20TGT.png?alt=media&token=620beda8-59f3-4bb0-9253-9a8172937455)

**6**. The TGS first checks the service ID if it is available in their database or not. then the TGS will grab a copy of the service secret key.

![TGS Database](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmS-olkx8n9iOW9w51%2FTGS%20secret%20key.png?alt=media&token=f9c7c690-3e8e-49e0-8e5c-69be17bcd60e)

**7**. The TGS will decrypt the TGT which contains the TGS Session key with the TGS secret key. Then the User Authenticator will be decrypted by the TGS Session Key. finally, the TGS will check if the information in TGT matches with the User Authenticator if it match the TGS will add it to its cache.

![TGS Functions](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmTi04B_Xu32LhVqJb%2F7%20-%20TGS%20Function.png?alt=media&token=11216091-8215-4a97-aba7-8443f92d1ed6)


### **TGS-REP**

**8**. Then, The TGS will create it own messages and send it back to the user. **The first message** contains the service ID that the user want to access and the message will be encrypted by TGS Session Key. **The second message** is the service ticket which will be encrypted by Service Secret Key. it contains the id and name of the service and the user name. Also both messages will contain Service Session Key.

![From TGS to User](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmX1-9Wa7aNS9QS_i_%2F8%20-%20TGS%20to%20User.png?alt=media&token=bfc57c13-d383-40aa-a54a-e1384b8c3468)

**The 2nd part Client <-> Service**

**9**. Since the user has the TGS session key before from the AS, he will **decrypt** the first message using its key. Now the user has access to the Service Session key. So he will create a User Authenticator Message and **encrypted** with the Service Session Key. Then he will send both the User Authenticator and the Service Ticket to the Service.

![From User to Service](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLmYiQ3MvFE4GNjUH2m%2F9%20-%20From%20User%20to%20Serivce.png?alt=media&token=c246217c-d3b4-454f-8505-4aaad3e678a5)

**10**. Now the steps will happen again. the Service will **decrypt** the Service Ticket with its key. The it will have access to the Service Session Key to use it to **decrypt** the User Authenticator. lastly The Service will **check** the matching between the two messages, if they are it will **add** the User Authenticator to the its cache and then **create** a Service Authenticator Message **encrypted** by the Service Session Key and **send** it to the user.

![From Service to User](https://gblobscdn.gitbook.com/assets%2F-MGT2pXneep03jo0FJjo%2F-MLleHggLGDNZw31DXUz%2F-MLma9R18_l8bSo6hff0%2F10%20-%20From%20Service%20to%20User.png?alt=media&token=3e6cf7d0-12e4-41ba-b303-47ca90a0a8da)

**11**. Finally, the User will decrypt the Service Authenticator using the Service Session Key and validate the service name. The mutual authentication is now complete. The Kerberos client can now start issuing service requests, and the Kerberos service can provide the requested services for the client.


Now, you can see the whole walk-through in one image thanks to [DestCert](https://drive.google.com/file/d/1Lc9IzvvB4ZharVIqWMOaXjngXro0c6hd/view).