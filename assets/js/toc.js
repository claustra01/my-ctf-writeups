(function () {
  function buildToc() {
    var toc = document.querySelector('.toc');
    if (!toc) return;

    var list = toc.querySelector('.toc-list');
    if (!list) return;

    var headings = document.querySelectorAll('article.prose h1, article.prose h2');
    if (!headings.length) {
      toc.remove();
      return;
    }

    var used = Object.create(null);
    var autoIndex = 1;

    headings.forEach(function (heading) {
      var text = (heading.textContent || '').trim();
      if (!text) return;

      var id = heading.getAttribute('id');
      if (!id) {
        id = 'section-' + autoIndex;
        autoIndex += 1;
      }

      var baseId = id;
      var suffix = 2;
      while (used[id]) {
        id = baseId + '-' + suffix;
        suffix += 1;
      }
      used[id] = true;

      if (heading.getAttribute('id') !== id) {
        heading.setAttribute('id', id);
      }

      var item = document.createElement('li');
      item.className = heading.tagName === 'H2' ? 'toc-item toc-level-2' : 'toc-item toc-level-1';
      var link = document.createElement('a');
      link.className = 'toc-link';
      link.href = '#' + id;
      link.textContent = text;
      item.appendChild(link);
      list.appendChild(item);
    });

    if (!list.children.length) {
      toc.remove();
      return;
    }

    toc.hidden = false;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildToc);
  } else {
    buildToc();
  }
})();
