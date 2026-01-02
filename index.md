---
layout: default
title: CTF Writeups
permalink: /
---

{% assign sorted = site.writeups | sort: "date" | reverse %}
{% if sorted and sorted != empty %}
<section class="section">
  <div class="section-head">
    <h1 class="section-title">Writeups</h1>
  </div>

  <div class="card-grid">
    {% for writeup in sorted %}
    <article class="card">
      <div class="meta-row">
        {% assign official = writeup.official %}
        {% if official %}
        <span class="pill pill-flag">Official</span>
        {% endif %}

        {% if writeup.rank or writeup.total_teams %}
        <span class="pill pill-outline">
          {% if writeup.rank %}#{{ writeup.rank }}{% endif %}{% if writeup.total_teams %}{% if writeup.rank %} / {% endif %}{{ writeup.total_teams }} teams{% endif %}
        </span>
        {% endif %}

        {% if writeup.language %}
        <span class="pill pill-ghost">{{ writeup.language }}</span>
        {% endif %}
      </div>

      <h3 class="card-title">
        <a href="{{ writeup.url | relative_url }}">{{ writeup.title }}</a>
      </h3>

      <div class="card-meta">
        {% if writeup.date %}
        <span>{{ writeup.date | date: "%Y-%m-%d" }}</span>
        {% else %}
        <span>No date</span>
        {% endif %}
      </div>

      {% if writeup.tags %}
      <div class="tag-row">
        {% for tag in writeup.tags %}
        <span class="tag">{{ tag }}</span>
        {% endfor %}
      </div>
      {% endif %}
    </article>
    {% endfor %}
  </div>
</section>
{% else %}
<section class="section">
  <div class="empty-state">
    <p class="empty-title">No writeups</p>
  </div>
</section>
{% endif %}
