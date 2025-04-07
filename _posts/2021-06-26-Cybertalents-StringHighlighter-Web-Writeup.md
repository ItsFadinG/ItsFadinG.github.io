---
title: Cybertalents String highlighter Web Challenge Writeup
author: Muhammad Adel
date: 2021-06-26 18:20:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---

## **Description**

Flag is hidden somewhere in the directory.

**Difficulty**: Hard

**Challenge Link:** [https://cybertalents.com/challenges/web/string-highlighter](https://cybertalents.com/challenges/web/string-highlighter)
‌
## **Solution**

### **Exploring**

From the name of the challenge we can assume it maybe contains a command injection. Once you open it your will find the following web page that highlight any string that give to it:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-Mcef5u_a_cwdeUXE3qG%2F1.png?alt=media&token=72fec17f-ec49-40e2-867a-3930cc8cbd4e)

So, it maybe not sanitized well. I tried XSS and it worked I have triggered an alert.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-McefNvhzMH6QKBoK4m6%2F2.png?alt=media&token=64c3e9e0-4cd0-4f29-8f34-f30906449eb7)

but XSS is not here useful here. we need to search for some server side vulnerability. I noticed that the website is using php, so I entered a php code but it filtered any some php functions and give me this message:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-McegLIGfIBND-PjB-eR%2F3.png?alt=media&token=6b751a9f-a186-434c-a301-d5ead8f4abfc)

I tried different forms of PHP commands and functions but it didn't works. I decided to open burp and I noticed an added parameter to it `red` which identify the color of the highlighted text.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-McehAdSBX6BCJ2jJfFU%2F4.png?alt=media&token=3723d3cf-2894-452a-b856-aa9865685c0d)

I removed and entered a simple php echo and it worked!

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-McehExqRme8cJIIE_7u%2F5.png?alt=media&token=93b48ae9-78ee-466e-b73b-cc46d16513ea)


### **Exploitation**

But the problem still exists I can't execute any functions like:


```php
shell_exec();
system();
escapeshellarg();
escapeshellcmd();
exec();
passthru();
```

I tried to search more about how to bypass disabled functions in PHP. and I found this awesome resource which was exactly what I needed.

[https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass](https://book.hacktricks.xyz/pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass)


it seems that you can execute shell commands in php without functions only by using backticks ``. Let's try it.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-MceipX4dMkPsKSX1WVX%2F6.png?alt=media&token=4948458d-012e-4787-855a-038ecd215dc7)

Voila! it worked and here is the flag.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-Mce_Aovt-9zW3Kr6fuu%2F-McejZHnDoHPM05uXS4L%2F7.png?alt=media&token=3a1a7784-e064-447f-86e1-fb4f99bfd125)