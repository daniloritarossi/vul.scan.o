/*
 * vfa-ui.js — shared UI runtime loaded on every in-app page (via topbar).
 *
 * Exposes:
 *   window.vfaToast(message, ok = true, opts)
 *       Unified toast. `ok` true -> success, false -> error, 'info' -> neutral.
 *       opts: { timeout (ms, default 4000), icon (Material Symbol name) }.
 *       Announced to assistive tech via an aria-live region.
 *
 *   window.vfaEmptyState(el, { icon, title, hint })
 *       Renders a consistent empty-state block into `el`.
 *
 * Both are defensive: safe to call before/after DOMContentLoaded, and a
 * missing container is created on demand.
 */
(function () {
  'use strict';

  function wrap() {
    var w = document.getElementById('vfa-toast-wrap');
    if (!w) {
      w = document.createElement('div');
      w.id = 'vfa-toast-wrap';
      // Polite live region: new toasts are read out without stealing focus.
      w.setAttribute('role', 'status');
      w.setAttribute('aria-live', 'polite');
      w.setAttribute('aria-atomic', 'false');
      (document.body || document.documentElement).appendChild(w);
    }
    return w;
  }

  var ICON = { ok: 'check_circle', err: 'error', info: 'info' };

  window.vfaToast = function (message, ok, opts) {
    opts = opts || {};
    var kind = ok === false ? 'err' : (ok === 'info' ? 'info' : 'ok');
    var el = document.createElement('div');
    el.className = 'vfa-toast vfa-toast--' + kind;

    var icon = document.createElement('span');
    icon.className = 'vfa-toast__icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = opts.icon || ICON[kind];

    var txt = document.createElement('span');
    txt.style.flex = '1 1 auto';
    txt.textContent = message == null ? '' : String(message);

    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'vfa-toast__close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';

    el.appendChild(icon);
    el.appendChild(txt);
    el.appendChild(close);
    wrap().appendChild(el);

    // Force reflow so the enter transition runs.
    void el.offsetWidth;
    el.classList.add('vfa-in');

    var timer;
    function dismiss() {
      clearTimeout(timer);
      el.classList.remove('vfa-in');
      el.addEventListener('transitionend', function () { el.remove(); }, { once: true });
      // Fallback if transitionend never fires (e.g. reduced-motion).
      setTimeout(function () { el.remove(); }, 300);
    }
    close.addEventListener('click', dismiss);
    var ms = typeof opts.timeout === 'number' ? opts.timeout : (kind === 'err' ? 6000 : 4000);
    if (ms > 0) timer = setTimeout(dismiss, ms);
    return dismiss;
  };

  window.vfaEmptyState = function (el, o) {
    if (!el) return;
    o = o || {};
    el.innerHTML =
      '<div class="flex flex-col items-center justify-center gap-2 py-12 text-center">' +
      '<span class="material-symbols-outlined text-4xl text-slate-300" aria-hidden="true">' +
      (o.icon || 'inbox') + '</span>' +
      '<p class="font-label-caps text-label-caps text-slate-500">' + (o.title || '') + '</p>' +
      (o.hint ? '<p class="font-code-sm text-[12px] text-slate-400">' + o.hint + '</p>' : '') +
      '</div>';
  };

  // ── Severity → distinct shape (WCAG 1.4.1: severity not conveyed by colour
  //    alone). Each level maps to a differently-shaped Material Symbol so it is
  //    tellable apart without relying on hue (red/orange confusion). ──────────
  var SEV_GLYPH = {
    CRITICAL: 'error', HIGH: 'warning', MEDIUM: 'arrow_upward',
    LOW: 'arrow_downward', UNKNOWN: 'help'
  };
  window.vfaSevGlyph = function (sev) {
    return SEV_GLYPH[String(sev == null ? 'UNKNOWN' : sev).toUpperCase()] || 'help';
  };
  // Leading icon span meant to prefix a severity badge's text label.
  window.vfaSevIcon = function (sev) {
    return '<span class="material-symbols-outlined text-[11px] leading-none align-middle mr-0.5" ' +
      'aria-hidden="true" style="font-variation-settings:\'FILL\' 1">' +
      window.vfaSevGlyph(sev) + '</span>';
  };

  // ── Loading skeleton. Fills a table <tbody> with shimmer rows (cols > 0) or a
  //    generic block with shimmer lines (cols = 0) while data is in flight, so a
  //    pending page reads as "loading", not "broken/empty". render() overwrites. */
  window.vfaSkeleton = function (el, o) {
    if (!el) return;
    o = o || {};
    var rows = o.rows || 5, cols = o.cols == null ? 1 : o.cols, html = '';
    var cell = '<span class="vfa-skel"></span>';
    for (var i = 0; i < rows; i++) {
      if (cols > 0) {
        html += '<tr class="vfa-skel-row" aria-hidden="true">';
        for (var c = 0; c < cols; c++) html += '<td class="px-4 py-3">' + cell + '</td>';
        html += '</tr>';
      } else {
        html += '<div class="py-2" aria-hidden="true">' + cell + '</div>';
      }
    }
    el.setAttribute('aria-busy', 'true');
    el.innerHTML = html;
  };
})();
