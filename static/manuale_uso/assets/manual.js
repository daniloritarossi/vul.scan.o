/* VUL.SCAN.O user manual — language + theme switching, TOC, lightbox.
   State lives in localStorage so it survives navigation between chapters. */
(function () {
  var LANG_KEY = 'vfaman-lang';
  var THEME_KEY = 'vfaman-theme';
  var root = document.documentElement;

  function setLang(l) {
    root.setAttribute('data-lang', l);
    root.setAttribute('lang', l);
    try { localStorage.setItem(LANG_KEY, l); } catch (e) { }
    document.querySelectorAll('[data-lang-btn]').forEach(function (b) {
      b.classList.toggle('on', b.getAttribute('data-lang-btn') === l);
    });
    document.title = (root.getAttribute('data-title-' + l) || document.title);
  }

  function setTheme(t) {
    root.setAttribute('data-theme', t);
    try { localStorage.setItem(THEME_KEY, t); } catch (e) { }
    document.querySelectorAll('[data-theme-btn]').forEach(function (b) {
      b.classList.toggle('on', b.getAttribute('data-theme-btn') === t);
    });
  }

  var lang = 'en', theme = 'dark';
  try { lang = localStorage.getItem(LANG_KEY) || 'en'; } catch (e) { }
  try { theme = localStorage.getItem(THEME_KEY) || 'dark'; } catch (e) { }
  setLang(lang);
  setTheme(theme);

  document.addEventListener('click', function (e) {
    var lb = e.target.closest('[data-lang-btn]');
    if (lb) { setLang(lb.getAttribute('data-lang-btn')); return; }
    var tb = e.target.closest('[data-theme-btn]');
    if (tb) { setTheme(tb.getAttribute('data-theme-btn')); return; }

    // Lightbox on screenshots.
    var img = e.target.closest('figure img');
    if (img) {
      var box = document.getElementById('lightbox');
      if (box) {
        box.querySelector('img').src = img.src;
        box.classList.add('on');
      }
      return;
    }
    if (e.target.closest('#lightbox')) {
      document.getElementById('lightbox').classList.remove('on');
    }
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var box = document.getElementById('lightbox');
      if (box) box.classList.remove('on');
    }
  });

  // TOC filter.
  var box = document.getElementById('tocSearch');
  if (box) {
    box.addEventListener('input', function () {
      var q = box.value.trim().toLowerCase();
      document.querySelectorAll('nav.toc li').forEach(function (li) {
        li.style.display = !q || li.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
      });
    });
  }

  // Scroll-spy for in-page anchors listed in the sidebar.
  var links = [].slice.call(document.querySelectorAll('nav.toc a[href^="#"]'));
  if (links.length) {
    var map = {};
    links.forEach(function (a) { map[a.getAttribute('href').slice(1)] = a; });
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        var a = map[en.target.id];
        if (a && en.isIntersecting) {
          links.forEach(function (x) { x.classList.remove('active'); });
          a.classList.add('active');
        }
      });
    }, { rootMargin: '-8% 0px -78% 0px' });
    document.querySelectorAll('section.block').forEach(function (s) { obs.observe(s); });
  }

  // Mark screenshots as zoomable once loaded.
  document.querySelectorAll('figure img').forEach(function (i) { i.classList.add('zoomable'); });
})();
