# LinkedIn — VUL.SCAN.O v1.0.76-beta

Immagine da allegare: `banner-v1.0.76-beta.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Nota: i lettori di schermo leggono male questi caratteri
e la ricerca interna non li indicizza — per questo il grassetto è solo sui punti
che contano davvero, non su intere frasi.

Angolo del post: come nella 1.0.65 e nella 1.0.75, il corpo è il difetto trovato,
non l'elenco di funzionalità. Qui però è più forte perché il difetto NON l'ho
trovato io: l'ha trovato una domanda banale di chi usava il prodotto («perché
questo contatore non si muove?»). Raccontare che la domanda dell'utente ha
scoperto un vicolo cieco che avevo lasciato aperto è più credibile di qualunque
changelog — e chiunque gestisca vulnerabilità riconosce la situazione.

Da NON fare: trasformarlo in «ascoltiamo i nostri utenti». Il punto non è
l'ascolto, è che metà del ragionamento era rimasta a metà.

---

## Post — inglese

𝗜'𝗺 𝗲𝘅𝗰𝗶𝘁𝗲𝗱 𝘁𝗼 𝗮𝗻𝗻𝗼𝘂𝗻𝗰𝗲 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟲-𝗯𝗲𝘁𝗮 — which exists because somebody asked me why a number wasn't moving.

They opened a remediation ticket from the findings page. The counters didn't move. They closed the ticket. Still nothing.

Half of that was correct, and I had simply never written it down anywhere: those counters track the 𝘄𝗼𝗿𝗸𝗳𝗹𝗼𝘄 𝘀𝘁𝗮𝘁𝘂𝘀 of a finding, and a ticket is not a status. A ticket gets closed as 𝘄𝗼𝗻'𝘁 𝗳𝗶𝘅, because a sprint ended, or by mistake. If the application closed the finding on its own, it would be declaring a vulnerability resolved on the strength of somebody's click in another system — and that declaration then travels into a signed evidence export.

So the finding stays open on purpose. Fine.

The other half was not fine, and the question is what exposed it: 𝗶𝗳 𝘁𝗵𝗲 𝗳𝗶𝗻𝗱𝗶𝗻𝗴 𝗹𝗲𝗴𝗶𝘁𝗶𝗺𝗮𝘁𝗲𝗹𝘆 𝘀𝘁𝗮𝘆𝘀 𝗼𝗽𝗲𝗻, 𝘄𝗵𝗲𝗿𝗲 𝗱𝗼𝗲𝘀 𝘁𝗵𝗲 𝘄𝗼𝗿𝗸 𝗴𝗼?

𝗻𝗼𝘄𝗵𝗲𝗿𝗲. The endpoint refused to create a second ticket, the button disappeared once a reference existed, and nothing could clear it. The worst case wasn't even misuse — a vulnerability genuinely fixed, its ticket properly closed, reappearing in a scan months later and reopened automatically. The one moment you obviously need a new ticket was the one moment the product refused it.

What shipped:

→ 𝗔 𝘁𝗶𝗰𝗸𝗲𝘁 𝗶𝘀 𝗻𝗼𝘁 𝗮 𝘀𝘁𝗮𝘁𝘂𝘀. The counters now say what they count — in a line above them, not a tooltip: hiding it behind a hover would reproduce the confusion it exists to fix.

→ 𝗔 𝘀𝗲𝗰𝗼𝗻𝗱 𝘁𝗶𝗰𝗸𝗲𝘁, 𝘂𝗻𝗱𝗲𝗿 𝗮 𝗿𝘂𝗹𝗲. Allowed only where the current ticket can no longer carry work: closed while the finding is still open, closed without a fix, or sitting on a tracker no longer configured. Refused beside a ticket that is still open: two tickets on one vulnerability is duplicated work, found downstream.

→ 𝗡𝗼𝘁𝗵𝗶𝗻𝗴 𝗶𝘀 𝗿𝗲𝗼𝗽𝗲𝗻𝗲𝗱 𝗼𝗻 𝘁𝗵𝗲 𝘁𝗿𝗮𝗰𝗸𝗲𝗿. The application writes there once, at creation, and reads from then on. Reopening somebody else's issue is a write that isn't mine to make.

→ 𝗔𝗿𝗰𝗵𝗶𝘃𝗲𝗱, 𝗻𝗲𝘃𝗲𝗿 𝗼𝘃𝗲𝗿𝘄𝗿𝗶𝘁𝘁𝗲𝗻. A ticket closed as 𝘄𝗼𝗻'𝘁 𝗳𝗶𝘅 records that a person decided not to act, and when. For a compliance tool that fact 𝗶𝘀 the evidence, and overwriting the reference would erase it.

→ 𝗔 𝘁𝗶𝗺𝗲𝗹𝗶𝗻𝗲 𝗿𝗲𝗮𝗱𝘀 𝗶𝘁 𝗯𝗮𝗰𝗸. Every ticket the finding has had, each superseded by the next, with its state, reason and dates.

The uncomfortable part is that I had defended the first half of this reasoning in writing, and never finished it. It took somebody using the thing to notice.

Self-hosted, Apache-2.0, local AI through Ollama, no personal data in prompts.

Code and full release notes — feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #devsecops #compliance

---

## Primo commento (da pubblicare subito sotto il post)

One detail that says more than the feature does: the rule 𝗻𝗲𝘃𝗲𝗿 lets you open a second ticket when the current one's state has never been read back from the tracker.

Not because it's dangerous — because the app would be guessing. It doesn't know whether that ticket is alive, and a guess there means a duplicate landing on a colleague's board. Refresh first, then decide.

Refusing to act on unknown state is the whole product in one rule.

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟲-𝗯𝗲𝘁𝗮 — closing a ticket doesn't close a vulnerability, and the tool now handles what comes next.

The finding stays open on purpose (𝘄𝗼𝗻'𝘁 𝗳𝗶𝘅, wrong sprint, plain mistake). But it used to have 𝗻𝗼𝘄𝗵𝗲𝗿𝗲 for the work to go: no second ticket, no way to clear the reference. A vulnerability that regressed was stuck pointing at a dead issue forever.

Now it gets a new ticket — only where the old one can't carry work — and the old reference is archived with its reason, not overwritten.

github.com/daniloritarossi/vul.scan.o

---

## Se qualcuno chiede «perché non chiudete il finding automaticamente?»

Perché la chiusura di un finding finisce nell'export di evidenza firmato. Chiuderlo
sulla fede del click di qualcuno su Jira significa che il documento dichiara risolta
una vulnerabilità senza che nessuno lo abbia mai affermato. La decisione resta di una
persona, e il registro annota quale.

---

## Riferimenti

| Cosa | Dove |
|---|---|
| Release | github.com/daniloritarossi/vul.scan.o/releases/tag/v1.0.76-beta |
| Capitolo della guida | `/static/manuale_uso/07-findings.html#kpi` (EN/IT) |
| Chiusura «non risolta» | GitHub `state_reason: not_planned` — riportato chiuso, esplicitamente non done |
