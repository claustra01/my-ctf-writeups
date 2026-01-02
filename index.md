---
layout: default
title: CTF Writeups
permalink: /
---

<h2>Recent writeups</h2>
{% assign sorted = site.writeups | sort: "date" | reverse %}
{% if sorted and sorted != empty %}
<ul>
{% for writeup in sorted %}
  <li>
    <a href="{{ writeup.url | relative_url }}">{{ writeup.title }}</a>
    {% assign official = writeup.official %}
    {% if official or writeup.rank or writeup.total_teams %}
    <div>
      {% if official %}
      Official writeup
      {% else %}
      {% if writeup.rank %}#{{ writeup.rank }}{% endif %}{% if writeup.total_teams %}{% if writeup.rank %} / {% endif %}{{ writeup.total_teams }} teams{% endif %}
      {% endif %}
    </div>
    {% endif %}
    {% if writeup.language %}
    <div>Language: {{ writeup.language }}</div>
    {% endif %}
    {% if writeup.tags %}
    <div>Tags: {% for tag in writeup.tags %}{{ tag }}{% unless forloop.last %}, {% endunless %}{% endfor %}</div>
    {% endif %}
    <div>{% if writeup.date %}{{ writeup.date | date: "%Y-%m-%d" }}{% else %}No date{% endif %}</div>
  </li>
{% endfor %}
</ul>
{% else %}
<p>まだWriteupがありません。`_writeups/` にMarkdownを追加してください。</p>
{% endif %}
