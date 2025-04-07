---
title: Cybertalents catchMomen Web Challenge Writeup
author: Muhammad Adel
date: 2021-08-12 18:20:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---
## **Description**

Don't Try To 3scape From Your Destiny ! 

**Difficulty:** Medium

**Challenge Link:**  <http://3.126.138.80/catch/>

## **Solution**

### **Exploring**

It seems like a normal website for a company. there is only one interesting login function which maybe will be our attack vector.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNcoro05eSkUxlI_VE%2F1.png?alt=media&token=6e7b7024-376e-4465-bca5-2d1f3c5c0f48)

while looking through the source code I found a credential which maybe will allow me to login but unfortunately it is not working. it gives me an error message "User not found".

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNdJC_iy46o-bIzIh8%2F2.png?alt=media&token=64bc75ca-2be7-4a22-973d-f25bbb217f05)

Now it is the time to try SQL injection, I fired up burp suite and choose some payloads from payload all the things and add it to the intruder tab to see what it will give us.

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNdq8zOPPjYax-y6fa%2F3.png?alt=media&token=dedbf8b5-e8db-473a-8bdb-75486a0e3457)

I noticed that there are three types of responses ( User not Found - Forbidden - nothing). From the response we can conclude that there are some SQL queries that has been triggered by the WAF and blocked. Let's try to observe what exactly is being blocked.


### **WAF Bypass**

Let's enter a normal SQL query like the following:
```
uname=GG_Homie!&pass=GG_Homie!'+OR+1=1+#
```
But unfortunately it blocked. let's add word by word before forming our whole query. let's first start by something like that:
```
uname=GG_Homie!&pass=GG_Homie!'+
```
The WAF accepts the query, let's continue and add `OR`to it:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNf_IerOP6nk_9G5gd%2F4.png?alt=media&token=922afc83-dc1f-4501-af9c-3af618f728a5)

Hmm! It seems that `OR`is blocked. we need to search for an equivalent for it. in the same resource payload all the things it has this table:
```
AND   -> &&
OR    -> ||
=     -> LIKE,REGEXP, BETWEEN, not < and not >
> X   -> not between 0 and X
WHERE -> HAVING
```
Great! we can now use `||` instead of `OR`. and it success:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNgP7AQs0rXGJYNsQQ%2F5.png?alt=media&token=d4d8a6f0-bf89-403d-897e-eeb9683299b8)

Let's continue our payload and 1=1 to be able to login successfully. but wait it is also blocked:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNgsNwJHKWCpu0CCkI%2F6.png?alt=media&token=fdac39c2-e264-40ec-b191-dc975551f498)

but how we are going to escape this? I thought about changing `1=1` to anther true condition I tried `3>2` but it didn't work. but when I tried `4!=2` which should be treated as true and I was able to get the flag!

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfNatsEZhBdO5QEfNjk%2F-MfNiaCM-MAOUpzUvVbt%2F7.png?alt=media&token=a388fe08-cc23-4c83-a6e5-d2cf821fd470)