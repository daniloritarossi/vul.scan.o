# LinkedIn — VUL.SCAN.O v1.0.75-beta

Immagine da allegare: `banner-v1.0.75-beta.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Nota: i lettori di schermo leggono male questi caratteri
e la ricerca interna non li indicizza — per questo il grassetto è solo sui punti
che contano davvero, non su intere frasi.

Angolo del post: l'annuncio c'è, ma il corpo è il bug trovato mentre costruivo la
funzionalità. Non "abbiamo aggiunto l'import CSV" — che non interessa a nessuno —
ma "un IP scritto male si travestiva da host spento", che è un modo di sbagliare
che chiunque gestisca un inventario riconosce. Stesso registro della 1.0.65:
raccontare il difetto trovato è più credibile di un elenco di funzionalità.

---

## Post — inglese

𝗜'𝗺 𝗲𝘅𝗰𝗶𝘁𝗲𝗱 𝘁𝗼 𝗮𝗻𝗻𝗼𝘂𝗻𝗰𝗲 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟱-𝗯𝗲𝘁𝗮 — and to tell you about the bug I found while building it.

The new feature imports an asset perimeter from a CSV or XLSX file. Before writing anything, it probes every host the file names and actually tries every credential it carries. Straightforward.

Then I fed it 𝟵𝟵𝟵.𝟵𝟵𝟵.𝟵𝟵𝟵.𝟵𝟵𝟵.

It passed.

DNS labels are allowed to be numeric, so that string was read as a perfectly valid 𝗵𝗼𝘀𝘁𝗻𝗮𝗺𝗲. It got probed. It did not answer — obviously. And it reached the operator as a mild, believable 𝗵𝗼𝘀𝘁 𝗶𝘀 𝗼𝗳𝗳 warning. Click "import anyway", which is a reasonable thing to do because a host can genuinely be switched off today, and an asset that can 𝗻𝗲𝘃𝗲𝗿 be scanned is now sitting in your inventory looking exactly like the others.

The failure was not the missing error. It was that the failure disguised itself as a plausible warning.

RFC 1123 §2.1 has forbidden this since 1989 — a hostname's rightmost label must not be all-numeric, precisely so that a name is never mistaken for an address. 192.0.2.300, 192.0.2 and 008.8.8.8 go the same way, and such a row is no longer probed at all: knocking on an address that cannot exist produces "did not answer", which is the wrong answer to the wrong question.

What the release does:

→ 𝗜𝘁 𝗰𝗵𝗲𝗰𝗸𝘀 𝗯𝗲𝗳𝗼𝗿𝗲 𝗶𝘁 𝘄𝗿𝗶𝘁𝗲𝘀. Every importable row gets a TCP probe; every row with a complete credential gets a real SSH login attempt. No login is tried against a host that stayed silent — the result would say something about the host, not about the credential.

→ 𝗧𝗵𝗿𝗲𝗲 𝘃𝗲𝗿𝗱𝗶𝗰𝘁𝘀, 𝗻𝗼𝘁 𝗼𝗻𝗲. Malformed data is an 𝗲𝗿𝗿𝗼𝗿 and 𝗻𝗲𝘃𝗲𝗿 enters, confirmed or not — no amount of "import anyway" makes an IP that does not exist valid. A repeated IP never enters either. Only a network warning is left to you, because that one is genuinely a judgement call.

→ 𝗢𝘃𝗲𝗿𝗿𝗶𝗱𝗶𝗻𝗴 𝗶𝘀 𝗼𝗻 𝘁𝗵𝗲 𝗿𝗲𝗰𝗼𝗿𝗱. If you force warned rows in, the ledger records that you did — and whether the probes were even run, so a "0 warnings" there reads as "not asked" rather than "nothing wrong".

→ 𝗧𝗵𝗲 𝘁𝗲𝗺𝗽𝗹𝗮𝘁𝗲 𝗰𝗮𝗻𝗻𝗼𝘁 𝗱𝗿𝗶𝗳𝘁. The columns come from the server, so the file you carefully fill in cannot disagree with the validator that rejects it.

None of this is clever. It is just the difference between a tool that tells you what it found and a tool that tells you what it did not check.

Self-hosted, Apache-2.0, local AI through Ollama, no personal data in prompts.

Code and full release notes — feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #assetmanagement #devsecops

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟱-𝗯𝗲𝘁𝗮 — you can now import an asset perimeter from CSV or XLSX.

The interesting part is what happens before the write: every host is probed, every credential is actually tried, and 𝟵𝟵𝟵.𝟵𝟵𝟵.𝟵𝟵𝟵.𝟵𝟵𝟵 is an 𝗲𝗿𝗿𝗼𝗿 instead of a believable 𝗵𝗼𝘀𝘁 𝗶𝘀 𝗼𝗳𝗳 warning.

Bad data never enters. Only the network is your call — and forcing it is on the record.

Self-hosted vulnerability management, from the first scan to signed evidence.

github.com/daniloritarossi/vul.scan.o

---

## Primo commento (da pubblicare subito sotto il post)

One more case, because it is the kind that bites months later: 𝗵𝗮𝗹𝗳 𝗮 𝗰𝗿𝗲𝗱𝗲𝗻𝘁𝗶𝗮𝗹 — a username with no password — is an 𝗲𝗿𝗿𝗼𝗿, not a blank.

Treat it as a blank and the asset enters as unauthenticated. Nothing fails. You just quietly get a banner grab instead of the full package inventory you were counting on, on an asset you believed was covered.

---

## Nota per i commenti (se qualcuno chiede "perché non lo normalizzi e basta?")

Perché normalizzare in silenzio un file da 200 righe è indovinare, e su un
inventario di sicurezza indovinare significa scansionare l'host sbagliato con le
credenziali di un altro. Il form manuale normalizza le URL perché c'è una persona
che vede il risultato subito; un import massivo no.

---

## Riferimenti

| Cosa | Dove |
|---|---|
| Release | github.com/daniloritarossi/vul.scan.o/releases/tag/v1.0.75-beta |
| Capitolo della guida | `/static/manuale_uso/04-assets.html#import` (EN/IT) |
| Regola citata | RFC 1123 §2.1 — l'etichetta più a destra di un hostname non può essere tutta numerica |
| Rete degli esempi | RFC 5737 — 192.0.2.0/24, riservata alla documentazione, non instradabile |
