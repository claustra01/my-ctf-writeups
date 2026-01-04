---
layout: default
title: CTF Writeups
permalink: /
tab: recent
---

{% assign sorted = site.writeups | sort: "date" | reverse %}
{% assign recent = sorted | slice: 0, 10 %}
{% if recent and recent != empty %}
<section class="section">
  <div class="section-head">
    <h1 class="section-title">Recently</h1>
    {% include writeup_tabs.html %}
  </div>

  {% include writeup_cards.html writeups=recent %}
</section>
{% else %}
<section class="section">
  <div class="section-head">
    <h1 class="section-title">Recently</h1>
    {% include writeup_tabs.html %}
  </div>

  <div class="empty-state">
    <p class="empty-title">No writeups or results yet</p>
  </div>
</section>
{% endif %}
