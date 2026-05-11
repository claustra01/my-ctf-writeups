---
title: SECCON Beginners CTF 2023 Writeup
date: 2023-06-04
layout: writeup
rank: 255
total_teams: 778
language: ja
tags:
  - Crypto
  - Rev
---

# はじめに

試験に追われ微分方程式の単位の心配をする季節になりましたが，SECCON Beginnersなるものに初めて参加してみました．常設ではないCTFに参加するのは初めてです．私用もあって問題と向き合っていたのは一日目の夜まででsolveも簡単なものだけですが，折角なので記録に残してみようと思います．

# WriteUp

最終的に解けたものは

- Welcome
- Half (reversing/beginner)
- CoughingFox2 (crypto/beginner)
- aiwaf (reversing/beginner)
- Three (reversing/easy)
- Conquer (crypto/easy)

の6問．方針は立ったけどそこから先で詰まって断念したのが

- Forbidden (web/beginner)
- poem (pwn/beginner)
- polyglot4b (misc/easy)

の3問でした．Forbiddenが解けなかったのがかなり堪えましたね……

## Welcome

Discordサーバーのannouncementsチャンネルで公開されているとのことで，確認．
Flagは`ctf4b{Welcome_to_SECCON_Beginners_CTF_2023!!!}`でした．

## CoughingFox2

cryptoのbeginner問題．配布されたソースコードはこれ．

```python
# coding: utf-8
import random
import os

flag = b"ctf4b{xxx___censored___xxx}"

# Please remove here if you wanna test this code in your environment :)
flag = os.getenv("FLAG").encode()

cipher = []

for i in range(len(flag)-1):
    c = ((flag[i] + flag[i+1]) ** 2 + i)
    cipher.append(c)

random.shuffle(cipher)

print(f"cipher = {cipher}")
```

`random.shuffle(cipher)`でシャッフルされており，一瞬総当たりが頭をよぎりましたが，そんなわけはなくて`c = ((flag[i] + flag[i+1]) ** 2 + i)`がポイント．
cからiを引くと平方数になるので，そのiを特定すれば順番通りに並べ替えることができます．Flagは`ctf4b{`から始まることが分かっているのであとは計算するだけでOK．Solverはこんな感じ．

```Python
import math
import random

cipher = [4396, 22819, 47998, 47995, 40007, 9235, 21625, 25006, 4397, 51534, 46680, 44129, 38055, 18513, 24368, 38451, 46240, 20758, 37257, 40830, 25293, 38845, 22503, 44535, 22210, 39632, 38046, 43687, 48413, 47525, 23718, 51567, 23115, 42461, 26272, 28933, 23726, 48845, 21924, 46225, 20488, 27579, 21636]
cipher.reverse()

plain = [0] * len(cipher)
flag = ""

for i in range(len(cipher)):
    for j in range(len(cipher)):
        p = math.sqrt(cipher[j] - i)
        if p.is_integer():
            plain[i] = int(p)
            break

c = ord('c')
for i in range(len(plain)):
    flag += chr(c)
    c = plain[i] - c

flag += '}'
print(flag)
```

Flagは`ctf4b{hi_b3g1nner!g00d_1uck_4nd_h4ve_fun!!!}`でした．

## Conquer

cryptoのeasy問題．配布されたソースコードはこれ．

```python
from Crypto.Util.number import *
from random import getrandbits
from flag import flag


def ROL(bits, N):
    for _ in range(N):
        bits = ((bits << 1) & (2**length - 1)) | (bits >> (length - 1))
    return bits


flag = bytes_to_long(flag)
length = flag.bit_length()

key = getrandbits(length)
cipher = flag ^ key

for i in range(1):
    key = ROL(key, pow(cipher, 3, length))
    cipher ^= key

print("key =", key)
print("cipher =", cipher)
```

keyを何ビットか右にスライドさせてFlagとのXORをとるという暗号化作業を32回繰り返していることが分かります．よって全く逆の操作を32回繰り返せば復号できることになります．Solverはこんな感じ．

```Python
from Crypto.Util.number import *
from random import getrandbits


def ROL(bits, N):
    for _ in range(N):
        bits = ((bits << 1) & (2**length - 1)) | (bits >> (length - 1))
    return bits

key = 364765105385226228888267246885507128079813677318333502635464281930855331056070734926401965510936356014326979260977790597194503012948
cipher = 92499232109251162138344223189844914420326826743556872876639400853892198641955596900058352490329330224967987380962193017044830636379

length = key.bit_length()+1

for i in range(32):
    cipher = cipher ^ key
    key = ROL(key, length - pow(cipher, 3, length))

flag = cipher ^ key
print(long_to_bytes(flag))
```

`length = key.bit_length()+1`とするのに中々気付けずかなり時間を無駄にしてしまいました．
Flagは`ctf4b{SemiCIRCLErCanalsHaveBeenConqueredByTheCIRCLE!!!}`でした．

## aiwaf

webのeasy問題．配布されたソースコードはこれ．

```JavaScript
import uuid
import openai
import urllib.parse
from flask import Flask, request, abort

# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

##################################################
# OpenAI API key
KEY = "****REDACTED****"
##################################################

app = Flask(__name__)
app.config["RATELIMIT_HEADERS_ENABLED"] = True

# limiter = Limiter(get_remote_address, app=app, default_limits=["3 per minute"])

openai.api_key = KEY

top_page = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="utf-8" />
    <title>亞空文庫</title>
</head>

<body>
    <h1>亞空文庫</h1>
    AIにセキュリティの物語を書いてもらいました。<br>
    内容は正しいかどうかわかりません。<br>
<ul>
    <li><a href="/?file=book0.txt">あ書</a></li>
    <li><a href="/?file=book1.txt">い書</a></li>
    <li><a href="/?file=book2.txt">う書</a></li>
    <!-- <li><a href="/?file=book3.txt">え書</a></li> -->
</ul>

※セキュリティのためAI-WAFを導入しています。<br>
© 2023 ももんがの書房
</body>

</html>
"""


@app.route("/")
def top():
    file = request.args.get("file")
    if not file:
        return top_page
    if file in ["book0.txt", "book1.txt", "book2.txt"]:
        with open(f"./books/{file}", encoding="utf-8") as f:
            return f.read()
    # AI-WAF
    puuid = uuid.uuid4()
    prompt = f"""\
以下の{puuid}に囲まれた部分のURLクエリはパストラバーサル攻撃でしょうか？
そうである場合Yesを、違う場合Noを返してください。
../やflagという文字列が含まれていた場合もYesを返してください。

{puuid}
{urllib.parse.unquote(request.query_string)[:50]}
{puuid}
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )
        result = response.choices[0]["message"]["content"].strip()
    except:
        return abort(500, "OpenAI APIのエラーです。\n少し時間をおいてアクセスしてください。")
    if "No" in result:
        with open(f"./books/{file}", encoding="utf-8") as f:
            return f.read().replace(KEY, "")
    return abort(403, "AI-WAFに検知されました👻")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=31415)

```

Flagは`/flag`に置いてあることがディレクトリ構造から分かりますが，`?file=../flag`のようにそのままアクセスするとaiwafに検知されてしまいます．ここでポイントとなるのが`{urllib.parse.unquote(request.query_string)[:50]}`の部分で，どうやらクエリの最初50文字しか見てない様子．よって

```
?test=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&file=../flag
```

といった感じで50文字以上適当なクエリを挟んであげれば`/flag`にアクセスすることができます．
Flagは`ctf4b{pr0mp7_1nj3c710n_c4n_br34k_41_w4f}`でした．

## Half

reversingのbeginner問題．revの最初の問題ということでとりあえずstringsコマンドを実行してみると，案の定Flagっぽい文字列が2行に分けて出てきた．
Flagは`ctf4b{ge4_t0_kn0w_the_bin4ry_fi1e_with_s4ring3}`でした．

## Three

reversingのeasy問題．とりあえず解析ツールにかけてデコンパイルしてみる．
[Decompiler Explorer](https://dogbolt.org/)というサイトがオンラインで実行できて，複数のツールの解析結果を比べながら見ることができるので便利．
するとflag_0，flag_1，flag_2の3つの配列にFlagが分解されて格納されていることが分かった．
どうやらスキュタレー暗号っぽいので簡単なSolverを書く．

```Python
flag_0 = [99, 52, 99, 95, 117, 98, 95, 95, 100, 116, 95, 114, 95, 49, 95, 52, 125, 0]
flag_1 = [116, 98, 52, 121, 95, 49, 116, 117, 48, 52, 116, 101, 115, 105, 102, 103]
flag_2 = [102, 123, 110, 48, 97, 101, 48, 110, 95, 101, 52, 101, 112, 116, 49, 51]

flag = ""

for i in range(49):
    if i%3 == 0:
        flag += chr(flag_0[i//3])
    elif i%3 == 1:
        flag += chr(flag_1[i//3])
    else:
        flag += chr(flag_2[i//3])

print(flag)
```

Flagは`ctf4b{c4n_y0u_ab1e_t0_und0_t4e_t4ree_sp1it_f14g3}`でした．

# おわりに

![](/assets/img/seccon_beginners_ctf_2023/bdde87c14df5-20230604.png)
最終結果としては6問solveして375ptで778チーム中255位．あまり時間が取れなかったというのもあるが，中々悔いの残る結果に．特にForbiddenとpoemは方針まで合っていたのにあと一歩が思いつかなかったからとても悔しい．なんで試しすらしなかったんだろうなぁ……
まぁ，数時間にしてはそこそこ解けたかなという感触なので，機会があればこんな感じの比較的低難易度なCTFに時間一杯まで参加してみたいですね．このWriteUpも30分余りで書き上げてしまったので，願わくば次はもっと執筆に時間がかかりますように．
