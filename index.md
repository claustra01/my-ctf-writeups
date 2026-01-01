---
layout: default
title: CTF Writeups
permalink: /
---

# CTF Writeups

Notes from events, quals, and finals. Each post is a walkthrough so future-me (and teammates) can replay the path from idea to exploit.

## Recent writeups

{% assign sorted = site.writeups | sort: "date" | reverse %}
{% if sorted and sorted != empty %}
{% for writeup in sorted %}
- **[{{ writeup.title }}]({{ writeup.url | relative_url }})** — {{ writeup.event }} {{ writeup.year }}{% if writeup.category %} • {{ writeup.category }}{% endif %}{% if writeup.tags and writeup.tags != empty %} • tags: {{ writeup.tags | join: ", " }}{% endif %}{% if writeup.date %} • {{ writeup.date | date: "%Y-%m-%d" }}{% endif %}
  {{ writeup.summary | default: writeup.excerpt | strip_html | truncate: 140 }}
{% endfor %}
{% else %}
No writeups yet. Drop Markdown files into `_writeups/` to populate this list.
{% endif %}
