---
title: ASCWGs Qualifications 2022 CTF Web Challenges Writeup
author: Muhammad Adel
date: 2022-08-08 07:40:00 +0200
categories: [CTF]
tags: [web, writeups]
---
Peace be upon all of you, on this writeup I am going to cover the solutions of all web challenges for Arab Security Cyber Wargames 2022 qualification phase. My team [0xCha0s](https://ctftime.org/team/168238) achieved the 5 place between more than 700 teams.

![](https://pbs.twimg.com/media/FZoxLw4WAAAmfkg?format=jpg&name=large)

## **Drunken Developer**
**Difficulty:** Warmup


**Description:** Developer have to disable his personal things

Browsing through the website, We noticed that we only have a login and rest password functionality.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2Fpmz0sOyKLU2U1KGcEQph%2F1.png?alt=media&token=5f7f3bfa-9da5-45d7-90f8-c4d8bf5a2cd1)
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F5u7IMiWFDKK5pmAiwVLw%2F2.png?alt=media&token=f6405b91-f5e0-47b2-a15d-7753c778c6f2)

Viewing the page source, we will found an email added in the HTML comments.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FrdaW1plZMDintwxq3eE3%2F3.png?alt=media&token=0158727e-7447-467e-a1b6-a657e2819d45)
I tried to login with this email by entering an easy password, but it didn't work. Maybe we could rest this email password?
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FEzA5R43C1dnwUOmf0ftL%2Fimage.png?alt=media&token=fc0799a5-a551-4bca-a761-919ae5c64e40)
Hmm! It needs a token to resent its password. So, after some trying I had an idea to replace the token part instead of passing a string I will pass a Boolean value.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FTsyWY74Y1vALA7IQ8I2K%2Fimage.png?alt=media&token=1e2ca00a-cfe6-4e25-84a4-95aed3361657)
And it worked! So let's login with the previously discovered email and get the flag.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F8qejum5lcz5XlqxiZVeN%2Fimage.png?alt=media&token=b4091ba3-d6b8-4314-8719-4a027d939f20)

## **Konan**

**Difficulty:** Easy 


**Description:** change yourself

The challenge begins with a login page that you have to enter only the username.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FlyJIwFCm6fOrXZTgOs5P%2Fimage.png?alt=media&token=c29a9ca8-3214-4e43-86de-7fb30555e603)
I have tried to guess some username like and found admin and root. Then we will be redirected to a page that we have to enter the OTP to be able to login.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F3pE7H8XCuK8q0e5buWCJ%2Fimage.png?alt=media&token=c82b58ad-98a1-42fe-924e-9a2e4df979fb)
Let's examine the OTP request in burp suite.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2Fdr0jfas2499fP1r6dhjB%2Fimage.png?alt=media&token=a68ae427-1b18-4ee2-a71c-988faf1c9ebb)
I tried to change it to True as the previous challenge, but it didn't work. And brute forcing is prohibited. So maybe a response manipulation will work. We will intercept the response of the OTP request through burp and the Cheng the response to the following:
```JSON
// will change this

{"errors":true,"reason":"Invalid OTP"}

// to

{"errors":false}
```
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FWie8bKsCQJ4FyMKzdfUa%2Fimage.png?alt=media&token=3b02b707-3a67-4457-97b3-eecc99bd76a7)
and we got the flag:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FG7p78ARZlgDgV2dmnCL0%2Fimage.png?alt=media&token=d326097c-02d3-4918-9000-4e9a30878021)

## **Evil Volunteer**

**Difficulty:** medium

**Description:** The fox is guarding the hen house

We have a login and register page and after logging we will find a file upload functionality.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FBneb1r7VFxLHJqa5JqOk%2Fimage.png?alt=media&token=8922e97a-cae3-4ea7-8f99-23fde1bd9f30)
Let's upload an arbitrary image and then click view.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FWyVQLdGl90BBcs8I7y9E%2Fimage.png?alt=media&token=ca8d2f0c-6efa-4954-8ec3-6da30fc530b2)
You will notice in the header above that there is a parameter called handle=base64encode let's remove its value and see what will happen.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FSszYgX1vmEBYGdlL6wle%2Fimage.png?alt=media&token=631287aa-65f5-423c-9605-233787ba8002)
Removing the filter will allow us to view the content of the image. Interesting! Since this a PHP page, let's try to inject a PHP command inside the content of the image. The page may interpret this as a valid PHP code and execute it.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F31GDvaDH2BKEZdlkjMnc%2Fimage.png?alt=media&token=9c49766b-bf18-4b26-8ca1-db8b88281e81)
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FmtX51xWbzhXQ6dN3pvqL%2Fimage.png?alt=media&token=ab8da492-cf29-4d1a-80c5-61a96fdacfeb)
Great! our code have executed let's get the content of flag.php.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FHwalc3P1iL2rfPreInts%2Fimage.png?alt=media&token=9801568d-1c56-44f6-a99e-7b92c8a6d61f)

## **Doctor X**

**Difficulty:** medium 


**Description:** Everywhere syringe

As other challenges, we login and register functionalities let's create an account.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FPHGSu0b6JlPWTy0OOoE6%2Fimage.png?alt=media&token=4def9b09-f652-4edd-b275-98f72b6e0a4e)
We have nothing except a welcome message and in the security tab it is only responsible for changing passwords.

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2Fngzaoc1Twk7I8AMkcFPz%2Fimage.png?alt=media&token=c242c431-7762-47d9-9ff2-3de590894892)

Let's go one step back and examine the login request:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FkaWqFJAg6Mx8KuKcewSy%2Fimage.png?alt=media&token=17f58779-b1fb-42c0-a87d-e337f48a0871)
What is interesting here is a JWT token, but I have tried to crack it or change the ID value to 1 but nothing worked. Guess what worked for me, Response Manipulation Again?!! I really didn't except this to work at all. But when I have changed the ID on the response to 1 I became logged in as admin.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F5Hno6e7hVfItTW9fDbH8%2FAdmin%20Access.png?alt=media&token=d1116106-29f4-411b-982f-311e950aea02)
As we see here, new tabs appears as admin and admin search. Let's browse to admin search and intercept its request.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FwVYtQM7cxeeu9sLUuvRA%2FadminSearch.png?alt=media&token=a3424383-3f6e-46c5-8654-52bb47c2b615)
I have added my username and searched for it. It appears that this endpoint is returning sensitive information about the registered users. I have entered my name, and it returned my password and token.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FVzamftgSCPpTdzovqaaG%2Fimage.png?alt=media&token=4f4156d5-d0bd-4279-bf98-aa440eda676c)
What We can do here is search for the admin username, but:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FhrOdhcfNYyGbHPSSVEuX%2Fimage.png?alt=media&token=154095e7-b0b9-4c57-9144-2a3007cba46e)
There is no flag associated with it. After digging deeper for some time, I have stumbled upon this error while editing the JSON request, which may have something interesting.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FhqhgTPaYfPqxgP7kkdQ4%2FNoSQL.png?alt=media&token=5197d4f1-6d8f-4c54-95d0-db88d410ea74)
Notice the word `Nosql`. let's take some payloads from payload all the things for NoSQL Injection and try it. After some trying, this payload works with me `{"$gt":""}`
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FThrClQfYCewMhVHQPKGh%2FFlag.png?alt=media&token=4b8cd841-7dfc-47bf-ace9-959f98c2c562)
This payload retrieved all the data from database, and we found the flag is associated with the description of a user called **ZXQW_Admin_Hidden_flag**.

## **Kenzy**

**Difficulty:** Hard 


**Description:** captcha is not that secure

My team mate **0xMesbaha** have written a writeup for it got check it out from the following link:

[https://hussienmisbah.github.io/post/kenzy/](https://hussienmisbah.github.io/post/kenzy/)