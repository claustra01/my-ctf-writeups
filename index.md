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
    <div class="card-meta">{{ writeup.event }} {{ writeup.year }}{% if writeup.language %} · {{ writeup.language }}{% endif %}</div>
    <h2><a href="{{ writeup.url | relative_url }}">{{ writeup.title }}</a></h2>
    <p class="card-summary">{{ writeup.summary | default: writeup.excerpt | strip_html | truncate: 150 }}</p>
    {% if writeup.rank or writeup.total_teams or writeup.language or writeup.tags %}
    <div class="meta-chips">
      {% if writeup.rank %}<span class="pill stat">#{{ writeup.rank }}</span>{% endif %}
      {% if writeup.total_teams %}<span class="pill subtle">{{ writeup.total_teams }} teams</span>{% endif %}
      {% if writeup.language %}<span class="pill subtle">{{ writeup.language }}</span>{% endif %}
      {% if writeup.tags %}
        {% for tag in writeup.tags %}
        <span class="pill ghost">{{ tag }}</span>
        {% endfor %}
      {% endif %}
    </div>
    {% endif %}
    <div class="card-footer">
      <span>{% if writeup.date %}{{ writeup.date | date: "%Y-%m-%d" }}{% else %}No date{% endif %}</span>
    </div>
  </article>
  {% endfor %}
{% else %}
  <p class="muted">まだWriteupがありません。`_writeups/` にMarkdownを追加してください。</p>
{% endif %}
</div>
