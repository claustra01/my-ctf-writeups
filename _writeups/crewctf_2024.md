---
title: CrewCTF 2024 Writeup
date: 2024-08-28
layout: writeup
rank: 112
total_teams: 575
team: kanimiso
language: ja
tags:
  - Forensics
  - Crypto
---

# まえがき

大学はもっぱら試験期間ですが、試験を犠牲にしてチームkanimisoでCrewCTFに参加してきました。時間がなかったので半日ほどしか参加出来ず、575チーム中112位という結果に終わりました。
![](/assets/img/crewctf_2024/04d14d573864-20240806.png)

# WriteUp

最終的に私が解けた問題は

- Welcome
- Feedback
- Recursion (Forensics/217solves)
- double-leaks (Crypto/90solves)

の4問でした。

## Welcome

Discordサーバーのannouncementsチャンネルを確認。
Flagは`crew{welcome_to_crew_ctf_2024}`でした。

## Feedback

アンケートに答えると以下のような文字列が表示されました。base64とあるので言われた通りにdecodeしてみるとFlagが得られます。
![](/assets/img/crewctf_2024/3e62ade0f51b-20240806.png)
Flagは`crew{C4nt_Re4d_It_Thr0ugh_Inspect_or_maybe_can}`でした。

## Recursion

pcapngファイルが配布されます。とりあえずwiresharkで開いてみるとUSBプロトコルでファイルをやりとりしている様子。
ファイルをやりとりしているであろうやたらサイズの大きいパケットがあり、その中にlayer4.pcapngという文字列があったのでこれがやりとりしているファイルの名前だとあたりをつけてbinwalkで抽出します。
binwalkって`-e`のオプションをつけるとその部分だけ抽出できるんですね。便利。

```sh
binwalk -e usb.pcapng
```

このlayer4.pcapngもbinwalkで調べてみると7z形式のファイルが見つかったので、抽出を試みましたが上手くいかず。ddコマンドで切り出して展開するとlayer3.pcapngというファイルが出てきました。だんだん分かってきましたね。

あとは展開と抽出を繰り返してlayer1.pcapngまで潜っていきます。layer1.pcapngからは何も出てこなかったのでstringsコマンドで調べてみるとFlagが出てきました。
最終的なソルバは以下の通り。

```sh
#!/bin/bash

binwalk usb.pcapng
if [ ! -d "_usb.pcapng.extracted" ]; then
  binwalk -e usb.pcapng
fi

cd _usb.pcapng.extracted
binwalk layer4.pcapng
if [ ! -f layer3.pcapng ]; then
  dd if=layer4.pcapng of=extracted.7z bs=1 skip=14095
  7z e extracted.7z
fi

binwalk layer3.pcapng
if [ ! -d _layer3.pcapng.extracted ]; then
  binwalk -e layer3.pcapng
fi

cd _layer3.pcapng.extracted
binwalk layer2.pcapng
if [ ! -d _layer2.pcapng.extracted ]; then
  binwalk -e layer2.pcapng
fi

cd _layer2.pcapng.extracted
binwalk layer1.pcapng
strings layer1.pcapng | grep "crew{"
```

Flagは`crew{l00ks_l1ke_y0u_mad3_1t!}`でした。

## 4ES

問題名から薄々勘付いていましたが、AESで4回暗号化をする問題でした。Flagを暗号化した文字列`enc_flag`の他、ヒントとしてある文字列`pt`とその暗号文`ct`が渡されます。
ソースコードは以下の通り。

```py
#!/usr/bin/env python3

from hashlib import sha256
from random import choices

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


with open('flag.txt', 'rb') as f:
    FLAG = f.read().strip()

chars = b'crew_AES*4=$!?'
L = 3

w, x, y, z = (
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
)

k1 = sha256(w).digest()
k2 = sha256(x).digest()
k3 = sha256(y).digest()
k4 = sha256(z).digest()

print(w.decode(), x.decode(), y.decode(), z.decode())

pt = b'AES_AES_AES_AES!'
ct = AES.new(k4, AES.MODE_ECB).encrypt(
         AES.new(k3, AES.MODE_ECB).encrypt(
             AES.new(k2, AES.MODE_ECB).encrypt(
                 AES.new(k1, AES.MODE_ECB).encrypt(
                     pt
                 )
             )
         )
     )

key = sha256(w + x + y + z).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(pad(FLAG, AES.block_size))

with open('output.txt', 'w') as f:
    f.write(f'pt = {pt.hex()}\nct = {ct.hex()}\nenc_flag = {enc_flag.hex()}')
```

AESは秘密鍵を使用した可逆的な暗号になるので、秘密鍵が分かれば復号することが可能です。
この鍵は`crew_AES*4=$!?`という文字列の中から取り出した3文字をsha256にかけたものになるので、総当たりでも高々14^3通りになります。2回暗号化してもその鍵の組み合わせは総当たりで14^6通りなので、この程度であれば現実的な計算が可能です。`pt`と`ct`が与えられていることから、この問題は4段階の暗号化を2段階ずつに分ける中間一致攻撃によって（現実的な時間で）秘密鍵が求められます。
実際のソルバは以下の通りです。

```py
from itertools import permutations
from hashlib import sha256
from Crypto.Cipher import AES

pt = bytes.fromhex("4145535f4145535f4145535f41455321")
ct = bytes.fromhex("edb43249be0d7a4620b9b876315eb430")
enc_flag = bytes.fromhex("e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b")

assert pt == b'AES_AES_AES_AES!'

chars = b'crew_AES*4=$!?'
mt_table = {}

count = 0
for w in [list(wl) for wl in permutations(chars, 3)]:
  for x in [list(xl) for xl in permutations(chars, 3)]:
    k1 = sha256(bytes(w)).digest()
    k2 = sha256(bytes(x)).digest()

    mt = AES.new(k2, AES.MODE_ECB).encrypt(
      AES.new(k1, AES.MODE_ECB).encrypt(
        pt
      )
    )

    mt_table[mt.hex()] = (w, x)

    print("encoding...", "{:3.2f}".format(100*count/(14**6)))
    count += 1


count = 0
for y in [list(yl) for yl in permutations(chars, 3)]:
  for z in [list(zl) for zl in permutations(chars, 3)]:
    k3 = sha256(bytes(y)).digest()
    k4 = sha256(bytes(z)).digest()

    mt = AES.new(k3, AES.MODE_ECB).decrypt(
      AES.new(k4, AES.MODE_ECB).decrypt(
        ct
      )
    )

    print("decoding...", "{:3.2f}".format(100*count/(14**6)))
    count += 1

    if mt.hex() in mt_table:
      w, x = mt_table[mt.hex()]
      print(bytes(w).decode(), bytes(x).decode(), bytes(y).decode(), bytes(z).decode())
      key = sha256(bytes(w) + bytes(x) + bytes(y) + bytes(z)).digest()
      flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)
      print(flag)
      exit()
```

少し時間がかかるので、現在の進捗を出力するようにしてみました。
Flagは`crew{m1tm_at74cK_1s_g0lD_4nd_py7h0n_i5_sl0w!!}`でした。

# あとがき

今回は時間が取れなかったというのもありますが、Web問がRustだったりWindowsだったりC++だったりでまともに読む気分になれなかったので他のジャンルをつまみ食いしていました。個人的にはちょっと長めのソルバが書けたのである程度満足しています。
CrewCTFに参加してからこのWriteUpを書くまで1か月ほど経ってしまいましたが、その間に色々なことがあったのでもうちょっとCTFを頑張りたいなというモチベが高いこの頃です。他のタスクの進捗次第ですが、近々またCTFに参加すると思います。それでは。
