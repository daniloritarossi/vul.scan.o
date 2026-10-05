# LinkedIn — VUL.SCAN.O v1.0.78-beta

Immagine da allegare: `banner-v1.0.78-beta.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Come sempre, solo sui punti che contano: i lettori di
schermo leggono male questi caratteri e la ricerca interna non li indicizza.

Angolo del post: la 1.0.76 raccontava un difetto trovato da un utente. Qui il
difetto l'ho trovato io, scrivendo il controllo di licenza, ed è peggio: il mio
installatore poteva scrivere lo schema sul database sbagliato e dichiarare
«fatto». Il tema vero però è un altro e vale per chiunque venda software
on-premise: un limite contrattuale che il cliente può aggirare in dieci secondi
non si «impone», si misura e si dichiara. Fingere il contrario è teatro.

Da NON fare: trasformarlo in «abbiamo aggiunto le licenze». Il prodotto resta
Apache-2.0; la notizia è come si installa una cosa a pagamento sopra una cosa
libera senza mentire a nessuno dei due.

---

## Post — inglese

𝗜'𝗺 𝗲𝘅𝗰𝗶𝘁𝗲𝗱 𝘁𝗼 𝗮𝗻𝗻𝗼𝘂𝗻𝗰𝗲 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟴-𝗯𝗲𝘁𝗮 — the release where I had to install something I'm selling on top of something I give away, and discovered my own installer was willing to lie.

The core stays Apache-2.0 and always will. On top of it there is now an optional, separately licensed analysis add-on. That meant writing the one piece of code nobody enjoys: a licence check.

Three things went wrong before anything went right.

𝗧𝗵𝗲 𝘃𝗲𝗿𝗶𝗳𝗶𝗲𝗿 𝗹𝗶𝘃𝗲𝘀 𝗶𝗻𝘀𝗶𝗱𝗲 𝘁𝗵𝗲 𝗽𝗮𝗰𝗸𝗮𝗴𝗲. The signature it checks is the add-on's own, so you cannot verify a key before installing the thing that verifies it. The order on screen is still licence first — it is the gate — but the check runs after the install, and a key that fails takes the package back out with it. Nothing half-installed, your configuration untouched. The alternative was copying the public key into the open source repo: two sources of truth for a signature, which is how signatures die.

𝗧𝗵𝗲 𝗹𝗶𝗰𝗲𝗻𝗰𝗲 𝘀𝗲𝗹𝗹𝘀 𝗮𝗻 𝗮𝘀𝘀𝗲𝘁 𝗰𝗲𝗶𝗹𝗶𝗻𝗴, 𝗮𝗻𝗱 𝗻𝗼𝗯𝗼𝗱𝘆 𝘄𝗮𝘀 𝗰𝗼𝘂𝗻𝘁𝗶𝗻𝗴. A claim nobody enforces is a number on an invoice. So the installer counts the real inventory and states it on screen — 𝟭𝟯 𝗼𝗳 𝟭𝟬𝟬 𝗵𝗼𝘀𝘁𝘀 — before the key is saved, and asks you to confirm if you are over. Distinct hosts, not rows: the same host entered twice is an inventory mistake, not an asset to pay for.

But here is the part I want to be honest about: this is a commercial term, not a security control. On a machine you own, you can get around it. So it is 𝗺𝗲𝗮𝘀𝘂𝗿𝗲𝗱 𝗮𝗻𝗱 𝘀𝘁𝗮𝘁𝗲𝗱, never pretended to be enforced. Pretending would insult the customer and fool nobody.

𝗔𝗻𝗱 𝗺𝘆 𝗶𝗻𝘀𝘁𝗮𝗹𝗹𝗲𝗿 𝗻𝗲𝗮𝗿𝗹𝘆 𝘄𝗿𝗼𝘁𝗲 𝘁𝗼 𝘁𝗵𝗲 𝘄𝗿𝗼𝗻𝗴 𝗱𝗮𝘁𝗮𝗯𝗮𝘀𝗲. The application talks to PostgREST over HTTP; migrations need SQL, which went straight to the local Docker container. Two roads that are normally the same database — and nothing checked. Point the app at a hosted database, leave a dev stack running, and the installer creates its tables in the wrong place and prints a green tick.

It now proves it is talking to your database before writing a byte, and when it cannot, it prints the exact SQL files for you to apply instead. 𝗔𝗻 𝗲𝘅𝗽𝗹𝗶𝗰𝗶𝘁 𝗶𝗻𝘀𝘁𝗿𝘂𝗰𝘁𝗶𝗼𝗻 𝗯𝗲𝗮𝘁𝘀 𝗮 𝗴𝗿𝗲𝗲𝗻 𝘁𝗶𝗰𝗸 𝗼𝘃𝗲𝗿 𝗮 𝗱𝗮𝘁𝗮𝗯𝗮𝘀𝗲 𝗻𝗼𝗯𝗼𝗱𝘆 𝘄𝗿𝗼𝘁𝗲 𝘁𝗼.

What shipped:

→ 𝗜𝗻𝘀𝘁𝗮𝗹𝗹, 𝘂𝗽𝗱𝗮𝘁𝗲 𝗮𝗻𝗱 𝗿𝗲𝗺𝗼𝘃𝗲 𝗳𝗿𝗼𝗺 𝗼𝗻𝗲 𝗺𝗲𝗻𝘂. `./start.sh update` → Analysis add-on. Licence, package path, migrations, schema reload. The path you used is remembered.

→ 𝗢𝗳𝗳𝗹𝗶𝗻𝗲 𝗯𝘆 𝗱𝗲𝘀𝗶𝗴𝗻. Point it at a folder holding the wheel and its dependencies; nothing is downloaded. A security product that fetched and executed remote code at run time would not survive your own review.

→ 𝗥𝗲𝗺𝗼𝘃𝗮𝗹 𝗸𝗲𝗲𝗽𝘀 𝘄𝗵𝗮𝘁 𝗽𝗲𝗼𝗽𝗹𝗲 𝘀𝗶𝗴𝗻𝗲𝗱. Uninstalling clears the key and the package, and keeps the analyses produced and the drafts people approved. Dropping those is a separate question you answer by typing DROP in full.

→ 𝗘𝘅𝗽𝗶𝗿𝘆 𝗱𝗲𝗴𝗿𝗮𝗱𝗲𝘀, 𝗶𝘁 𝗻𝗲𝘃𝗲𝗿 𝗯𝗹𝗼𝗰𝗸𝘀. New analyses stop, everything already produced stays readable, and there is a 14-day tolerance for slow renewals and clocks that disagree.

The add-on is still work in progress and the manual says so on the page, in both languages. What I am confident about is the shape: the licence gates the paid module and nothing else, and the free core runs identically whether you buy it or not.

Self-hosted, Apache-2.0, local AI through Ollama, no personal data in prompts.

Code and full release notes — feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #devsecops #licensing

---

## Primo commento (da pubblicare subito sotto il post)

The detail that took longest to get right is the smallest one: what the installer does when it 𝗰𝗮𝗻𝗻𝗼𝘁 reach your database.

The easy version says "database not running" and moves on. That sentence was false in the case that mattered — a hosted database, perfectly alive, just not the container on this machine — and it sent whoever read it to debug the wrong thing.

Now it names what it found, prints the files to apply by hand, and says plainly that the Agent pages will fail until they are. Error messages are documentation written at the worst possible moment: they should be the most accurate text in the product, not the least.

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟴-𝗯𝗲𝘁𝗮 — a licensed add-on on top of an Apache-2.0 core, installed without lying to anyone.

The key is verified before it is saved, and if it fails the package is uninstalled again. The asset ceiling is counted against your real inventory and stated on screen — measured, not pretended: on-premise, a commercial term is not a security control. And the installer now proves it is talking to 𝘆𝗼𝘂𝗿 database before writing its schema.

The free core runs identically whether you buy the add-on or not.

github.com/daniloritarossi/vul.scan.o

---

## Se qualcuno chiede «state chiudendo il progetto open source?»

No, e la risposta sta nel codice: il gancio nel core sono quattro righe dentro un
try/except. Senza il pacchetto non cambia niente, nessuna funzione esistente è
stata spostata dietro la licenza, e il core resta Apache-2.0. L'add-on aggiunge
analisi nuove, non riprende cose già regalate.

## Se qualcuno chiede «perché non bloccate l'installazione sopra il tetto?»

Perché su una macchina del cliente il blocco è aggirabile in dieci secondi, e un
controllo che finge di essere invalicabile insegna al cliente che il resto del
prodotto potrebbe fingere altrettanto. Si misura, si dichiara, si fa decidere a
una persona — e il numero resta visibile anche dopo.

---

## Riferimenti

| Cosa | Dove |
|---|---|
| Release | github.com/daniloritarossi/vul.scan.o/releases/tag/v1.0.78-beta |
| Capitolo della guida | `/static/manuale_uso/13-agent.html` (EN/IT, marcato work in progress) |
| Installazione | `./start.sh update` → Analysis add-on (vfa-agent) |
| Degrado alla scadenza | 14 giorni di tolleranza, poi analisi sospese e lettura intatta |
