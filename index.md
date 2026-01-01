---
layout: default
title: CTF Writeups
permalink: /
---

<section class="hero">
  <p class="eyebrow">CTF note-log</p>
  <h1>Writeups for quals &amp; finals</h1>
  <p class="lede">試行錯誤を後から再現できるよう、手順と判断のログを短くまとめています。機材や環境の差分もできるだけ明記。</p>
  <div class="hero-meta">
    <span>Custom domain: writeups.claustra01.net</span>
    <span>Maintainer: claustra01</span>
  </div>
</section>

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
