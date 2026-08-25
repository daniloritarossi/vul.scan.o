/*
 * vfa-auth.js — self-contained helpers for the auth pages (login, activate,
 * change-password). No dependencies beyond Material Symbols (already loaded).
 *
 *   - Show/hide toggle: added to every <input type="password"> automatically.
 *   - Strength meter: added to inputs marked data-vfa-strength.
 *
 * Runs on DOMContentLoaded; also exported as window.vfaAuth for manual use.
 */
(function () {
  'use strict';

  function attachToggle(input) {
    if (input.dataset.vfaEye) return;
    input.dataset.vfaEye = '1';
    // Wrap only the input so the eye button centres on it (not on the label).
    const holder = document.createElement('div');
    holder.style.position = 'relative';
    input.parentNode.insertBefore(holder, input);
    holder.appendChild(input);
    input.style.paddingRight = '2.6rem';

    const b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('aria-label', 'Show password');
    b.setAttribute('aria-pressed', 'false');
    b.style.cssText = 'position:absolute;right:.6rem;top:50%;transform:translateY(-50%);' +
      'display:inline-flex;align-items:center;color:#5f7f92;background:none;border:0;cursor:pointer;padding:0';
    b.innerHTML = '<span class="material-symbols-outlined" style="font-size:18px;line-height:1">visibility</span>';
    b.addEventListener('mouseenter', function () { b.style.color = '#2ee6ff'; });
    b.addEventListener('mouseleave', function () { b.style.color = '#5f7f92'; });
    b.addEventListener('click', function () {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      b.setAttribute('aria-pressed', show ? 'true' : 'false');
      b.querySelector('span').textContent = show ? 'visibility_off' : 'visibility';
      input.focus();
    });
    holder.appendChild(b);
  }

  // Coarse strength heuristic (length + character variety) → 0..4.
  function scorePw(pw) {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8) s++;
    if (pw.length >= 12) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(s, 4);
  }
  const COLORS = ['#33505f', '#ff416b', '#ffb038', '#2ee6ff', '#3df5b0'];
  const EMPTY = 'rgba(46,230,255,.16)';   // segmento non ancora raggiunto
  function label(sc) {
    const key = ['', 'auth.pw_weak', 'auth.pw_fair', 'auth.pw_good', 'auth.pw_strong'][sc];
    const fb = ['', 'Weak', 'Fair', 'Good', 'Strong'][sc];
    return (typeof window.t === 'function' && key) ? (window.t(key) === key ? fb : window.t(key)) : fb;
  }

  function attachMeter(input) {
    if (input.dataset.vfaMeter) return;
    input.dataset.vfaMeter = '1';
    const wrap = document.createElement('div');
    wrap.style.marginTop = '0.5rem';
    wrap.innerHTML =
      '<div style="display:flex;gap:4px;margin-bottom:4px">' +
      '<span class="vfa-seg"></span><span class="vfa-seg"></span><span class="vfa-seg"></span><span class="vfa-seg"></span>' +
      '</div><span class="vfa-str-label" aria-live="polite" ' +
      'style="font:700 10.5px/1.4 Inter,system-ui,sans-serif;letter-spacing:.16em;text-transform:uppercase;color:#33505f"></span>';
    const anchor = input.closest('div') || input;
    anchor.parentNode.insertBefore(wrap, anchor.nextSibling);
    const segs = wrap.querySelectorAll('.vfa-seg');
    segs.forEach(function (s) {
      s.style.cssText = 'height:3px;flex:1;border-radius:9999px;background:' + EMPTY + ';transition:background .2s';
    });
    const lab = wrap.querySelector('.vfa-str-label');
    function upd() {
      const sc = scorePw(input.value);
      segs.forEach(function (s, i) { s.style.background = i < sc ? COLORS[sc] : EMPTY; });
      lab.textContent = input.value ? label(sc) : '';
      lab.style.color = input.value ? COLORS[sc] : '#33505f';
    }
    input.addEventListener('input', upd);
    upd();
  }

  function init() {
    document.querySelectorAll('input[type="password"]').forEach(attachToggle);
    document.querySelectorAll('input[data-vfa-strength]').forEach(attachMeter);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
  window.vfaAuth = { attachToggle, attachMeter, init };
})();
