---
title: Cybertalents SkiddyKill3r Web Challenge Writeup
author: Muhammad Adel
date: 2021-06-26 18:00:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---

## **Description**

Creative Thinking will make getting the flag so much easier

**Difficulty**: Easy

[Challenge-Link](https://cybertalents.com/challenges/web/skiddykill3r)


## **Solution**


### **Exploring**

The homepage contains a simple page that has only one function mage by result.php which accepts a name as a user input. After viewing the source code of this you find the following hint.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEpDICJj6BEiBGoOsQ%2F1.png?alt=media&token=38bfb20c-dd79-4107-9550-50bf8a64d8f3)

So we can go back to the first page and add **Momen** as a name. you will find again anther hint which says:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEpG-gAyXNj_9bVTfp%2F2.png?alt=media&token=b922f841-75f1-4530-8531-97416a33b00d)


### **Parameter BruteForce**

Moving to **hint.php** you will see hint that tells you:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEpI4pHnUmL2m-TQfX%2F3.png?alt=media&token=b49cc1ab-6b83-4e3c-a595-563f87a579f7)

So, I think here we need to make some parameter bruter forcing with the value of True. I will use the following list and add it to the burp intruder.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEpLWmhsFoKPWwagBf%2F4.png?alt=media&token=094c61e2-ba4b-4a2c-8006-ac788ffbf2c5)

the show parameter appears to be the right one. next we will see the following code that contains some condition that we need to do to get the flag.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEpkQ1tkick-qDvj01%2F5.png?alt=media&token=7e0db28f-a06a-411f-b60b-0a611a28ebaa)

The first case is easy we need only to add the **refferer** header with the value of **http://cyberguy**

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEqKNaoGvGa3Ytu-Pe%2F6.png?alt=media&token=7bab4d4a-1aaf-4516-9481-b86b92b0d56d)


### **Type Juggling**

The second case is appears to be a type juggling attack after a lot of search about this I found a hint to it in the php documentation website.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEqrfZ1NeEZS_rNa5j%2F7.png?alt=media&token=2b3f2703-2f75-4ffd-b319-25de72943f33)

Adding the following cookie will let us receive the second part of the flag.


```php
Cookie: flag=240610708; flag1=QNKCDZO
```

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEr9P2p1HPdvgByETv%2F8.png?alt=media&token=f0cfb5ed-e86c-449e-b413-c0751d55160f)

The last case is will give us a hint to the full flag. it easy to apply by changing the value of the parameter and the cookie to:


```php
/skiddy/hint.php?show=True&flag=HiNt
Cookie: flag=True
```

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McErsqA7lPL8JrwwMkN%2F9.png?alt=media&token=f52d639a-f70f-4789-8dcb-22314334af90)

Moving to robots.txt we will find anther hint:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEsDAyOZwSOGM3zg6-%2F10.png?alt=media&token=ff82d646-3cb1-4da1-8358-47d055a36162)

### **403 Bypass**
‌
After browsing to this file it gives us 403 forbidden. So we need to find a way to bypass this.

After lots of trial and error I found that we should add a referrer header with the same value of the website URL and also add the cookie value of the second case and changing the request method to **PUT**. The request should look something like that:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEtHeLmZbU6tWx0KN-%2F11.png?alt=media&token=f0ad0e6b-5bda-429f-876d-c7c408d558cd)

Anther hint which tell us to access the **user_check.php** with the following **User-Agent** `G3t_My_Fl@g_N0w()`

And Finally we will get the whole flag.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEuSnv7Ibr-GIpZaZq%2F12.png?alt=media&token=11a38eba-0356-42bd-a856-b9c63605b26c)