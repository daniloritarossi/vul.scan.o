/*
 * vfa-field.js — il campo a lunga esposizione delle schermate di accesso.
 *
 * Tre strati di punti con parallasse: ogni punto e' un finding, il colore ne
 * e' lo stato (KEV / SLA violata / aperta / risolta) e la luminosita' segue
 * una distribuzione tipo EPSS — pochi molto probabili, moltissimi improbabili.
 *
 * Tutto GENERATO da un seed fisso: nessuna richiesta, nessun dato reale. La
 * pagina di accesso e' pubblica, e un conteggio di asset o di finding sarebbe
 * ricognizione gratuita per chiunque la apra.
 *
 * Cerca <canvas id="sky">; se non c'e', non fa nulla.
 */
(function () {
  'use strict';
  var cv = document.getElementById('sky');
  if (!cv) return;

  var ctx = cv.getContext('2d');
  var reduce = matchMedia('(prefers-reduced-motion:reduce)').matches;
  var DPR = Math.min(devicePixelRatio || 1, 2);
  var W, H, mx = 0, my = 0, tx = 0, ty = 0, stars = [];
  var seed = 20260824;
  function rnd() { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; }

  var PAL = [
    { c: '#ff416b', w: 0.07 },   // KEV, sfruttata attivamente
    { c: '#ffb038', w: 0.15 },   // SLA violata
    { c: '#2ee6ff', w: 0.52 },   // aperta, entro SLA
    { c: '#3df5b0', w: 0.26 }    // risolta, sigillata in catena
  ];
  function pick() {
    var r = rnd(), a = 0;
    for (var i = 0; i < PAL.length; i++) { a += PAL[i].w; if (r <= a) return PAL[i].c; }
    return PAL[2].c;
  }

  function build() {
    stars = [];
    var n = Math.round(Math.min(W, 1900) * 0.42);
    for (var i = 0; i < n; i++) {
      var depth = 1 + Math.floor(rnd() * 3);          // 1 vicino … 3 lontano
      stars.push({
        x: rnd() * W, y: rnd() * H, depth: depth,
        r: (3.2 - depth * 0.7) * (0.45 + rnd() * 0.8),
        c: pick(),
        a: 0.18 + Math.pow(rnd(), 1.9) * 0.82,        // quasi tutti deboli
        tw: rnd() * 6.28,
        sp: (0.09 / depth) * (0.5 + rnd())
      });
    }
  }

  function resize() {
    // clientWidth/clientHeight sono in sola lettura: assegnarli qui (modulo in
    // strict mode) lancia, e l'eccezione fermerebbe il resto del file.
    W = innerWidth; H = innerHeight;
    cv.style.width = W + 'px'; cv.style.height = H + 'px';
    cv.width = W * DPR; cv.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    build();
  }
  resize();
  addEventListener('resize', resize);
  addEventListener('pointermove', function (e) { mx = e.clientX / W - 0.5; my = e.clientY / H - 0.5; });

  function frame(now) {
    ctx.clearRect(0, 0, W, H);
    tx += (mx - tx) * 0.045; ty += (my - ty) * 0.045;

    for (var i = 0; i < stars.length; i++) {
      var s = stars[i];
      if (!reduce) s.x -= s.sp;
      if (s.x < -4) { s.x = W + 4; s.y = rnd() * H; }
      var px = s.x - tx * (26 / s.depth), py = s.y - ty * (26 / s.depth);
      var tw = reduce ? 1 : 0.7 + 0.3 * Math.sin(now * 0.0012 + s.tw);
      ctx.globalAlpha = s.a * tw * (s.depth === 3 ? 0.5 : s.depth === 2 ? 0.78 : 1);
      ctx.fillStyle = s.c;
      ctx.shadowBlur = s.depth === 1 ? 10 : 4; ctx.shadowColor = s.c;
      ctx.beginPath(); ctx.arc(px, py, s.r, 0, 6.28); ctx.fill();
    }
    ctx.globalAlpha = 1; ctx.shadowBlur = 0;

    // un transito lento attraversa il campo, all'incirca ogni 26 secondi
    if (!reduce) {
      var t = (now % 26000) / 26000;
      var x = t * (W + 200) - 100, y = H * 0.34 + Math.sin(t * 3.1) * H * 0.06;
      var g = ctx.createLinearGradient(x - 90, y, x, y);
      g.addColorStop(0, 'rgba(46,230,255,0)'); g.addColorStop(1, 'rgba(46,230,255,.5)');
      ctx.strokeStyle = g; ctx.lineWidth = 1.1;
      ctx.beginPath(); ctx.moveTo(x - 90, y); ctx.lineTo(x, y); ctx.stroke();
      ctx.fillStyle = 'rgba(207,238,248,.9)'; ctx.shadowBlur = 12; ctx.shadowColor = '#2ee6ff';
      ctx.beginPath(); ctx.arc(x, y, 1.6, 0, 6.28); ctx.fill(); ctx.shadowBlur = 0;
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();

/* Selettore di lingua delle pagine di accesso: qui non c'e' la topbar, e lo
   switch automatico di i18n.js marca il pulsante attivo con classi Tailwind
   che il tema scuro ricolora — su questo fondo litigavano. */
(function () {
  'use strict';
  function sync() {
    var btns = document.querySelectorAll('.langs .lang');
    if (!btns.length || !window.i18n) return;
    btns.forEach(function (b) { b.classList.toggle('on', b.dataset.lang === window.i18n.lang); });
  }
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.langs .lang').forEach(function (b) {
      b.addEventListener('click', function () { window.i18n.setLang(b.dataset.lang); sync(); });
    });
    sync();
  });
})();
