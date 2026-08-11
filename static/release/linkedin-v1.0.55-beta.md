# LinkedIn — VUL.SCAN.O v1.0.55-beta

Immagine da allegare: `banner-product.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Nota: i lettori di schermo leggono male questi caratteri
e la ricerca interna non li indicizza — per questo il grassetto è solo sui punti
che contano davvero, non su intere frasi.

---

## Post — italiano

Un auditor non ti chiede quante vulnerabilità hai oggi.

Ti chiede quante ne avevi 𝗶𝗹 𝟯𝟭 𝗺𝗮𝗿𝘇𝗼, e di dimostrarlo.

È la domanda da cui è nato 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢, di cui rilascio oggi la 𝘃𝟭.𝟬.𝟱𝟱-𝗯𝗲𝘁𝗮: vulnerability management self-hosted per audit autorizzati, dalla prima scansione fino all'evidenza firmata che un auditor accetta.

Cosa lo distingue:

→ 𝗜𝗱𝗲𝗻𝘁𝗶𝗳𝗶𝗰𝗮 𝘀𝗲𝗻𝘇𝗮 𝗖𝗩𝗘. Descrivi il software a parole tue e lui risale a quello vulnerabile dietro. Non serve partire da un identificativo che spesso non hai.

→ 𝗧𝘂𝘁𝘁𝗲 𝗹𝗲 𝗳𝗼𝗻𝘁𝗶 𝗰𝗵𝗲 𝗰𝗼𝗻𝘁𝗮𝗻𝗼. OSV, NVD, MSRC, EPSS, CISA KEV. Ogni risultato dichiara da dove viene: una versione di fix senza provenienza verificabile è un'affermazione, non un'indicazione.

→ 𝗥𝗶𝘀𝗰𝗵𝗶𝗼 𝗰𝗵𝗲 𝗰𝗼𝗻𝗼𝘀𝗰𝗲 𝗶𝗹 𝘁𝘂𝗼 𝗰𝗼𝗻𝘁𝗲𝘀𝘁𝗼. Sfruttabilità reale, raggiungibilità misurata in quel momento e criticità di business, invece del CVSS grezzo che mette sullo stesso piano il server esposto e il portatile in magazzino.

→ 𝗘𝘃𝗶𝗱𝗲𝗻𝘇𝗮 𝗱𝗮 𝗮𝘂𝗱𝗶𝘁. Registro append-only con catena di hash, conteggi sigillati per data, export firmato. Rispondi a "al 31 marzo quante critiche erano aperte" con un numero che qualcun altro può verificare.

→ 𝗜𝗻𝘁𝗲𝗿𝗮𝗺𝗲𝗻𝘁𝗲 𝘁𝘂𝗼. Self-hosted, l'analisi AI può girare in locale con Ollama, nessun dato personale nei prompt. Apache-2.0.

Nelle ultime release:

𝟭.𝟬.𝟱𝟱 — RBAC a sei ruoli. Permesso di scrivere e visibilità sugli asset diventano due assi indipendenti: il nuovo ruolo 𝘀𝘁𝗮𝗸𝗲𝗵𝗼𝗹𝗱𝗲𝗿 dà all'owner di un sistema i suoi host in sola lettura, e nient'altro. Senza assegnazioni l'inventario è vuoto — il cono fallisce in chiusura.

𝟭.𝟬.𝟱𝟰 — Piano di fix multi-sorgente OSV → MSRC → NVD. Nato da un bug vero: su inventario Windows la risoluzione era rotta, perché OSV ragiona per ecosistemi di pacchetti e Windows non è uno di quelli. Ora i prodotti Microsoft passano da MSRC e tornano con il numero di 𝗞𝗕, che è la remediation reale.

𝟭.𝟬.𝟱𝟯 — Evidenza point-in-time: registro a prova di manomissione, conteggi sigillati, report firmato.

𝟭.𝟬.𝟱𝟮 — Manuale d'uso completo, bilingue, pagina per pagina.

Il codice è qui, i feedback sono benvenuti:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #compliance

---

## Post — inglese

An auditor doesn't ask how many vulnerabilities you have today.

They ask how many you had 𝗼𝗻 𝟯𝟭 𝗠𝗮𝗿𝗰𝗵, and to prove it.

That question is why 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 exists. Today I'm releasing 𝘃𝟭.𝟬.𝟱𝟱-𝗯𝗲𝘁𝗮: self-hosted vulnerability management for authorized audits, from the first scan to the signed evidence an auditor will accept.

What sets it apart:

→ 𝗜𝗱𝗲𝗻𝘁𝗶𝗳𝘆 𝘄𝗶𝘁𝗵𝗼𝘂𝘁 𝗮 𝗖𝗩𝗘. Describe the software in your own words and it works back to the vulnerable thing behind it. No need to start from an identifier you often don't have.

→ 𝗘𝘃𝗲𝗿𝘆 𝘀𝗼𝘂𝗿𝗰𝗲 𝘁𝗵𝗮𝘁 𝗺𝗮𝘁𝘁𝗲𝗿𝘀. OSV, NVD, MSRC, EPSS, CISA KEV. Every result declares where it came from: a fix version without checkable provenance is an assertion, not an instruction.

→ 𝗥𝗶𝘀𝗸 𝘁𝗵𝗮𝘁 𝗸𝗻𝗼𝘄𝘀 𝘆𝗼𝘂𝗿 𝗰𝗼𝗻𝘁𝗲𝘅𝘁. Real exploitability, reachability measured at that moment, and business criticality — instead of raw CVSS, which ranks the internet-facing server and the laptop in the storeroom the same way.

→ 𝗔𝘂𝗱𝗶𝘁-𝗴𝗿𝗮𝗱𝗲 𝗲𝘃𝗶𝗱𝗲𝗻𝗰𝗲. Append-only ledger with a hash chain, counts sealed per date, signed export. You answer "how many criticals were open on 31 March" with a number someone else can verify.

→ 𝗘𝗻𝘁𝗶𝗿𝗲𝗹𝘆 𝘆𝗼𝘂𝗿𝘀. Self-hosted, AI analysis can run locally through Ollama, no personal data in the prompts. Apache-2.0.

In the recent releases:

𝟭.𝟬.𝟱𝟱 — Six-role RBAC. Permission to write and visibility over assets become two independent axes: the new 𝘀𝘁𝗮𝗸𝗲𝗵𝗼𝗹𝗱𝗲𝗿 role gives a system owner their own hosts, read-only, and nothing else. With no assignment the inventory is empty — the cone fails closed.

𝟭.𝟬.𝟱𝟰 — Multi-source fix plan, OSV → MSRC → NVD. It came out of a real bug: resolution was broken across the whole Windows inventory, because OSV reasons in package ecosystems and Windows isn't one. Microsoft products now go through MSRC and come back with a 𝗞𝗕 number, which is the actual remediation.

𝟭.𝟬.𝟱𝟯 — Point-in-time evidence: tamper-evident ledger, sealed counts, signed report.

𝟭.𝟬.𝟱𝟮 — Complete bilingual user manual, page by page.

The code is here, feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #compliance

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟱𝟱-𝗯𝗲𝘁𝗮 — RBAC a sei ruoli.

Scrivere e vedere sono due assi indipendenti, non uno solo. Il nuovo ruolo 𝘀𝘁𝗮𝗸𝗲𝗵𝗼𝗹𝗱𝗲𝗿 dà all'owner di un sistema i suoi host in sola lettura, e nient'altro: senza assegnazioni l'inventario è vuoto, il cono fallisce in chiusura.

Vulnerability management self-hosted, dalla prima scansione all'evidenza firmata.

github.com/daniloritarossi/vul.scan.o
