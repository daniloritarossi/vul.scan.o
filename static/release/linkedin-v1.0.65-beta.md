# LinkedIn — VUL.SCAN.O v1.0.65-beta

Immagine da allegare: `banner-v1.0.65-beta.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Nota: i lettori di schermo leggono male questi caratteri
e la ricerca interna non li indicizza — per questo il grassetto è solo sui punti
che contano davvero, non su intere frasi.

Angolo del post: le ultime cinque release nascono tutte dallo stesso difetto —
il registro di audit dichiarava più di quanto potesse dimostrare. Raccontarlo
apertamente è più credibile di un elenco di funzionalità, e per un prodotto di
compliance l'onestà del verdetto *è* la funzionalità.

---

## Post — inglese

I ran an audit on my own audit trail. It failed.

The endpoint that verifies the ledger answered 𝗼𝗸: 𝘁𝗿𝘂𝗲 while it had verified 𝟮 𝗿𝗼𝘄𝘀 𝗼𝘂𝘁 𝗼𝗳 𝟭𝟬𝟲. The other 104 predated the hash chain, were skipped, and could still be rewritten without leaving a trace. The posture ledger — the one holding the point-in-time counts an auditor asks for — was unsigned at 100% and also answered 𝗼𝗸: 𝘁𝗿𝘂𝗲.

Nothing was broken. "ok" simply meant "nothing I could check failed", and the response said that nowhere.

Today I'm releasing 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟲𝟱-𝗯𝗲𝘁𝗮. Five releases went into one idea: an audit trail is only worth what it can prove, so it has to say how much that is.

What changed:

→ 𝗜𝘁 𝗻𝗼𝘄 𝘀𝗮𝘆𝘀 𝘄𝗵𝗼 𝗱𝗶𝗱 𝘄𝗵𝗮𝘁. Sign-ins and failed sign-ins, refused requests, role changes, group membership, asset assignments, configuration writes, exports. Before, an admin could create an account, grant themselves a role, export the whole inventory — and the ledger showed nothing.

→ 𝗧𝗵𝗲 𝘃𝗲𝗿𝗱𝗶𝗰𝘁 𝗰𝗮𝗿𝗿𝗶𝗲𝘀 𝗶𝘁𝘀 𝗰𝗼𝘃𝗲𝗿𝗮𝗴𝗲. Three states instead of a green tick: 𝗶𝗻𝘁𝗮𝗰𝘁, 𝗽𝗮𝗿𝘁𝗶𝗮𝗹 (nothing broken, but part of it cannot be proven), 𝘁𝗮𝗺𝗽𝗲𝗿𝗲𝗱 — with the share actually proven next to it.

→ 𝗗𝗲𝗹𝗲𝘁𝗲𝗱 𝗿𝗼𝘄𝘀 𝘀𝗵𝗼𝘄 𝘂𝗽. Cut the last entries off a hash chain and what remains verifies perfectly: a chain does not know how long it should be. A witness kept outside the database now remembers where each ledger ended, so a truncated tail is detectable.

→ 𝗔𝗻𝗰𝗵𝗼𝗿𝗲𝗱 𝗶𝘀 𝗻𝗼𝘁 𝗽𝗿𝗼𝘃𝗲𝗻. Rows written before the chain existed can be anchored — any later change is detected — but that says nothing about what they contained before. The signed report prints 𝗽𝗿𝗼𝘃𝗲𝗻 and 𝗽𝗿𝗼𝘁𝗲𝗰𝘁𝗲𝗱 side by side and never adds them together.

→ 𝗧𝗵𝗲 𝗻𝘂𝗺𝗯𝗲𝗿𝘀 𝗮𝗿𝗲 𝗿𝗲𝗮𝗱𝗮𝗯𝗹𝗲. Posture runs are now browsable in the audit page, each with its actor, its 𝘀𝗲𝗮𝗹𝗲𝗱 totals and the per-asset breakdown. They had a proof and no document to read it from.

The uncomfortable part is that this list only exists because I looked for the ways my own tool could mislead someone, and wrote down what I found. Every limit above is stated in the product and in the docs, including the ones I can't fix: a witness on the same host doesn't survive that host being compromised, and no hash chain can prove what a row contained before it was signed.

For a compliance tool, a verdict you can trust is the feature. Everything else is decoration.

Self-hosted, Apache-2.0, local AI option through Ollama, no personal data in prompts.

Code and full release notes here — feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #compliance #auditing

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟲𝟱-𝗯𝗲𝘁𝗮 — the audit trail stopped overstating itself.

It used to answer 𝗼𝗸: 𝘁𝗿𝘂𝗲 having verified 2 rows out of 106. It now answers 𝗶𝗻𝘁𝗮𝗰𝘁, 𝗽𝗮𝗿𝘁𝗶𝗮𝗹 or 𝘁𝗮𝗺𝗽𝗲𝗿𝗲𝗱, with the share it can actually prove — and it notices when rows go missing.

Self-hosted vulnerability management, from the first scan to signed evidence.

github.com/daniloritarossi/vul.scan.o

---

## Riferimenti alle release citate

| Release | Cosa ha chiuso |
|---|---|
| 1.0.58 | registro attività: chi ha fatto cosa (auth, RBAC, utenti, config, export) |
| 1.0.61 | verdetto a tre stati con la copertura reale; ancoraggio delle righe pre-catena |
| 1.0.63 | troncamento della coda e declassamento a "legacy" rilevati |
| 1.0.64 | report firmato: ancorato ≠ dimostrato, vuoto ≠ integro |
| 1.0.65 | run di postura sfogliabili nel registro di audit |
