---
title: Cybertalents xCorp Web Challenge Writeup
author: Muhammad Adel
date: 2021-06-26 17:45:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---

## **Description**

X corp made a new filtration for input data, prove it is secure enough.

**‌Difficulty**: Easy

**Challenge Link:** [https://cybertalents.com/challenges/web/x-corp](https://cybertalents.com/challenges/web/x-corp)

## **Solution**

It an easy challenge will make you encounter with a reflected XSS vulnerability.

First, you have a parameter called name which the only one in the page. we can add a random value and see where it reflects.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEgejQNrfqO358gvTA%2F1.png?alt=media&token=05fef233-b321-45b9-a76d-004ad27501e5)

we notice here that our payload is reflected in an image attribute and also it missing a single quote.

What we can do here to trigger an XSS simply we can fix the tag and our own attribute.

like this:

```javascript
name=itsfading'onload(alert(0))
```

And we will get the flag once we trigger the alert.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McEIssKZgDg2fgcbjFB%2F-McEhwKQGE6_45ymcszE%2F2.png?alt=media&token=febb217a-5983-4ffc-8807-0cba6d85591d)