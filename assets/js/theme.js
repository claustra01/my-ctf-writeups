(function () {
  var storageKey = 'theme-preference';
  var root = document.documentElement;
  var toggle = document.querySelector('[data-theme-toggle]');
  var label = document.querySelector('[data-theme-label]');
  var icon = document.querySelector('.theme-toggle-icon');
  var systemQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function readStoredPreference() {
    try {
      var stored = localStorage.getItem(storageKey);
      if (stored === 'light' || stored === 'dark') {
        return stored;
      }
    } catch (e) {
      /* ignore */
    }
    return null;
  }

  function persistPreference(value) {
    try {
      if (value) {
        localStorage.setItem(storageKey, value);
      } else {
        localStorage.removeItem(storageKey);
      }
    } catch (e) {
      /* ignore */
    }
  }

  function updateToggleUI(mode) {
    if (!toggle || !label || !icon) return;

    var resolved = mode || 'system';
    var text = 'テーマ: 自動';
    var iconText = '🌗';

    if (resolved === 'light') {
      text = 'テーマ: ライト';
      iconText = '☀️';
    } else if (resolved === 'dark') {
      text = 'テーマ: ダーク';
      iconText = '🌙';
    }

    label.textContent = text;
    icon.textContent = iconText;
    toggle.setAttribute('aria-label', text);
  }

  function applyTheme(mode) {
    if (mode === 'light' || mode === 'dark') {
      root.setAttribute('data-theme', mode);
      persistPreference(mode);
    } else {
      root.removeAttribute('data-theme');
      persistPreference(null);
    }
    updateToggleUI(mode);
  }

  function cycleTheme() {
    var current = root.getAttribute('data-theme');
    var next = 'light';

    if (current === 'light') {
      next = 'dark';
    } else if (current === 'dark') {
      next = null;
    }

    applyTheme(next);
  }

  applyTheme(readStoredPreference());

  if (typeof systemQuery.addEventListener === 'function') {
    systemQuery.addEventListener('change', function () {
      if (!readStoredPreference()) {
        applyTheme(null);
      }
    });
  } else if (typeof systemQuery.addListener === 'function') {
    systemQuery.addListener(function () {
      if (!readStoredPreference()) {
        applyTheme(null);
      }
    });
  }

  if (toggle) {
    toggle.addEventListener('click', cycleTheme);
  }
})();
