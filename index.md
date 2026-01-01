---
layout: default
title: CTF Writeups
permalink: /
---

<h2 class="section-title">Recent writeups</h2>
<div class="card-grid">
{% assign sorted = site.writeups | sort: "date" | reverse %}
{% if sorted and sorted != empty %}
  {% for writeup in sorted %}
  <article class="card">
    <div class="card-meta">{{ writeup.event }} {{ writeup.year }}{% if writeup.category %} · {{ writeup.category }}{% endif %}</div>
    <h2><a href="{{ writeup.url | relative_url }}">{{ writeup.title }}</a></h2>
    <p class="card-summary">{{ writeup.summary | default: writeup.excerpt | strip_html | truncate: 150 }}</p>
    <div class="card-footer">
      <span>{% if writeup.date %}{{ writeup.date | date: "%Y-%m-%d" }}{% else %}No date{% endif %}</span>
    </div>
  </article>
  {% endfor %}
{% else %}
  <p class="muted">まだWriteupがありません。`_writeups/` にMarkdownを追加してください。</p>
{% endif %}
</div>
