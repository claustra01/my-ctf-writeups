---
layout: default
title: CTF Writeups
permalink: /
---

{% assign sorted = site.writeups | sort: "date" | reverse %}
{% if sorted and sorted != empty %}
<section class="section">
  <div class="section-head">
    <h1 class="section-title">Recently</h1>
  </div>

  <div class="card-grid">
    {% for writeup in sorted %}
    <article class="card">
      <div class="meta-row">
        {% assign official = writeup.official %}
        {% if official %}
        <span class="pill pill-flag">Official writeup</span>
        {% endif %}

        {% if writeup.rank or writeup.total_teams %}
        {% assign rank_classes = "pill pill-rank" %}
        {% if writeup.rank %}
        {% assign rank_number = writeup.rank | plus: 0 %}
        {% if rank_number == 1 %}
        {% assign rank_classes = rank_classes | append: " pill-rank-gold" %}
        {% elsif rank_number == 2 %}
        {% assign rank_classes = rank_classes | append: " pill-rank-silver" %}
        {% elsif rank_number == 3 %}
        {% assign rank_classes = rank_classes | append: " pill-rank-bronze" %}
        {% endif %}
        {% endif %}
        <span class="{{ rank_classes }}">
          {% if writeup.rank %}# {{ writeup.rank }}{% endif %}{% if writeup.total_teams %}{% if writeup.rank %} / {% endif %}{{ writeup.total_teams }} Teams{% endif %}
        </span>
        {% endif %}

        {% if writeup.language %}
        <span class="pill pill-ghost">Lang: {{ writeup.language }}</span>
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
        {% assign tag_class = "tag" %}
        {% if tag == "Quals" %}
        {% assign tag_class = tag_class | append: " tag-quals" %}
        {% elsif tag == "Finals" %}
        {% assign tag_class = tag_class | append: " tag-finals" %}
        {% endif %}
        <span class="{{ tag_class }}">{{ tag }}</span>
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
