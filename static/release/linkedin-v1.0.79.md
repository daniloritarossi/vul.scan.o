# LinkedIn — VUL.SCAN.O v1.0.79

Immagine da allegare: `banner-v1.0.79.png` (2400×1260, 1200×630 @2x).

Il grassetto è in caratteri Unicode: LinkedIn non accetta markdown né HTML, quindi
va incollato così com'è. Come sempre, solo sui punti che contano: i lettori di
schermo leggono male questi caratteri e la ricerca interna non li indicizza.

Angolo del post: è la prima release stabile, e il motivo per cui la chiamo
stabile è un difetto che ho trovato io, mettendomi dalla parte di chi attacca.
Ogni installazione nasceva con le stesse chiavi del proprio database, perché
stavano nel repository. Il tema che vale per chiunque distribuisca software
self-hosted: «solo per uso locale» scritto in un commento non è un controllo di
sicurezza, ed è il default che il cliente non cambierà mai.

Da NON fare: elencare gli altri punti emersi dal test di sicurezza. Non sono
ancora corretti: si raccontano quando lo saranno, non prima. E non presentarlo
come «abbiamo aggiunto la sicurezza»: la notizia è che un default condiviso è
stato tolto, e che le installazioni esistenti si sistemano da sole.

---

## Post — inglese

𝗜'𝗺 𝗵𝗮𝗽𝗽𝘆 𝘁𝗼 𝗮𝗻𝗻𝗼𝘂𝗻𝗰𝗲 𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟵 — 𝘁𝗵𝗲 𝗳𝗶𝗿𝘀𝘁 𝗿𝗲𝗹𝗲𝗮𝘀𝗲 𝘄𝗶𝘁𝗵𝗼𝘂𝘁 "-𝗯𝗲𝘁𝗮" 𝗶𝗻 𝗶𝘁𝘀 𝗻𝗮𝗺𝗲. And the reason I am comfortable calling it stable is a flaw I found in my own project.

Before dropping the label, I tested the application the way an attacker would: every one of the six roles, from an anonymous visitor to the admin. Role matrix, visibility cones, forged sessions, cross-user access. Most of it held.

One thing did not, and it was not in the application code at all.

𝗘𝘃𝗲𝗿𝘆 𝗶𝗻𝘀𝘁𝗮𝗹𝗹𝗮𝘁𝗶𝗼𝗻 𝘀𝗵𝗶𝗽𝗽𝗲𝗱 𝘄𝗶𝘁𝗵 𝘁𝗵𝗲 𝘀𝗮𝗺𝗲 𝗸𝗲𝘆𝘀 𝘁𝗼 𝗶𝘁𝘀 𝗼𝘄𝗻 𝗱𝗮𝘁𝗮𝗯𝗮𝘀𝗲. The local Supabase stack had its JWT secret, service key and Postgres password in a file committed to the repository, with a comment saying "demo keys, local use only". Comments do not enforce anything. Anyone who had read the repository held the keys to every installation that had never changed them — which, realistically, is all of them.

The service key bypasses the application's access control entirely. That was the finding.

What v1.0.79 does about it:

→ 𝗘𝘃𝗲𝗿𝘆 𝗶𝗻𝘀𝘁𝗮𝗹𝗹𝗮𝘁𝗶𝗼𝗻 𝗴𝗲𝗻𝗲𝗿𝗮𝘁𝗲𝘀 𝗶𝘁𝘀 𝗼𝘄𝗻 𝘀𝗲𝗰𝗿𝗲𝘁𝘀. JWT secret, anon and service keys, database password: created on first start, stored with owner-only permissions, never committed. Two installations no longer share a single value.

→ 𝗘𝘅𝗶𝘀𝘁𝗶𝗻𝗴 𝗶𝗻𝘀𝘁𝗮𝗹𝗹𝗮𝘁𝗶𝗼𝗻𝘀 𝗺𝗶𝗴𝗿𝗮𝘁𝗲 𝗯𝘆 𝘁𝗵𝗲𝗺𝘀𝗲𝗹𝘃𝗲𝘀. The shipped secrets are recognised by fingerprint — not by value, so the public key does not go back into the code — and replaced on the next start. Data stays where it is.

→ 𝗘𝘃𝗲𝗿𝘆 𝗱𝗮𝘁𝗮𝗯𝗮𝘀𝗲 𝗹𝗼𝗴𝗶𝗻 𝗶𝘀 𝗿𝗼𝘁𝗮𝘁𝗲𝗱, 𝘀𝘂𝗽𝗲𝗿𝘂𝘀𝗲𝗿 𝗶𝗻𝗰𝗹𝘂𝗱𝗲𝗱. This was the part that is easy to get wrong. Postgres applies its password only when the data volume is created; on an existing volume, changing the configuration changes nothing. So the setup script now resets all nine login roles, not just the one the application uses.

→ 𝗜𝘁 𝘀𝘂𝗿𝘃𝗶𝘃𝗲𝘀 𝗮 𝗣𝘆𝘁𝗵𝗼𝗻 𝘂𝗽𝗴𝗿𝗮𝗱𝗲. Unrelated, but it bit me the same week: the distribution moved from Python 3.12 to 3.14 and the virtualenv silently broke. The start script now notices, rebuilds it and reinstalls the add-on.

If you run it: 𝘂𝗽𝗱𝗮𝘁𝗲 𝗮𝗻𝗱 𝗿𝗲𝘀𝘁𝗮𝗿𝘁. That is the whole procedure.

"Stable" does not mean finished. It means I am confident enough in the foundations to stop hiding behind the label — and that when I find something, it goes in the release notes.

Self-hosted, Apache-2.0, local AI through Ollama, no personal data in prompts.

Code and full release notes — feedback welcome:
github.com/daniloritarossi/vul.scan.o

#vulnerabilitymanagement #appsec #opensource #devsecops #selfhosted

---

## Primo commento (da pubblicare subito sotto il post)

The detail I almost got wrong was in my own test. To check that the old database password no longer worked, I connected from inside the container — and it was accepted. Every role, every time.

It looked like the rotation had failed. It had not: inside the container, connections from localhost are trusted without a password, so 𝗮𝗻𝘆 password is "correct" there. Testing from the host, through the published port, told the truth: old password rejected on all nine roles, new one accepted.

A test that cannot fail is not a test. Worth checking which side of the door you are knocking from.

---

## Variante corta (commento, repost, o post di richiamo)

𝗩𝗨𝗟.𝗦𝗖𝗔𝗡.𝗢 𝘃𝟭.𝟬.𝟳𝟵 — 𝗼𝘂𝘁 𝗼𝗳 𝗯𝗲𝘁𝗮.

Before calling it stable I tested it as an attacker would, across all six roles. The flaw that mattered was not in the code: every installation shipped with the same database keys. Now each one generates its own, existing installations migrate on the next start, and every Postgres login — superuser included — is rotated.

Update and restart. Your data stays put.

github.com/daniloritarossi/vul.scan.o

---

## Se qualcuno chiede «quindi le installazioni precedenti erano esposte?»

Sì, nella misura in cui qualcuno raggiungeva il gateway (8001) o Postgres (5432).
Di default entrambi ascoltano solo su 127.0.0.1, quindi serviva già un accesso
alla macchina, o una pagina web aperta dal browser su quella macchina. Non è un
«nessun rischio» e non va venduto così: è il motivo per cui la migrazione è
automatica invece di essere un'istruzione nelle note di rilascio.

## Se qualcuno chiede «cosa è emerso d'altro dal test?»

«Altri punti, minori, che sistemo nelle prossime release e che racconterò quando
saranno chiusi.» Non elencarli prima della correzione.

---

## Riferimenti

| Cosa | Dove |
|---|---|
| Release | github.com/daniloritarossi/vul.scan.o/releases/tag/v1.0.79 |
| Generatore dei segreti | `supabase/gen_secrets.py` (chiamato da `supabase/setup.sh`) |
| Modello del file | `supabase/.env.example` (il `.env` vero non è più versionato) |
| Rotazione manuale | cancella `supabase/.env` e rilancia `./supabase/setup.sh` |
| Documentazione | README → sezione Supabase, «Secrets are per installation» |
