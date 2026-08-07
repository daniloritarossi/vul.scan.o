# VUL.SCAN.O — User Manual · Manuale d'uso

**EN** — Complete, bilingual, screenshot-illustrated user manual for VUL.SCAN.O.
**IT** — Manuale d'uso completo, bilingue e illustrato con screenshot per VUL.SCAN.O.

---

## How to open it · Come aprirlo

**EN**

- Locally: open [`index.html`](./index.html) in a browser.
- With the app running: <http://localhost:8000/static/manuale_uso/index.html>
- Switch language and theme with the **EN / IT / DARK / LIGHT** buttons in the sidebar. The choice is remembered
  across chapters.
- Click any screenshot to enlarge it. Press <kbd>Esc</kbd> to close.
- Every chapter prints cleanly (`Ctrl/Cmd + P`) — the sidebar and navigation are hidden in print.

**IT**

- In locale: apri [`index.html`](./index.html) in un browser.
- Con l'app in esecuzione: <http://localhost:8000/static/manuale_uso/index.html>
- Cambia lingua e tema con i pulsanti **EN / IT / DARK / LIGHT** nella barra laterale. La scelta viene ricordata fra i
  capitoli.
- Clicca uno screenshot per ingrandirlo. Premi <kbd>Esc</kbd> per chiudere.
- Ogni capitolo si stampa correttamente (`Ctrl/Cmd + P`) — barra laterale e navigazione sono nascoste in stampa.

---

## Chapters · Capitoli

| # | File | EN | IT |
|---|---|---|---|
| 00 | [index.html](./index.html) | Overview, core concepts, quick start, page map | Panoramica, concetti chiave, avvio rapido, mappa delle pagine |
| 01 | [01-shell.html](./01-shell.html) | Application shell: top bar, navigation, command palette, theme, language | Interfaccia comune: barra superiore, navigazione, command palette, tema, lingua |
| 02 | [02-auth.html](./02-auth.html) | `/login`, `/activate`, `/change-password`, credential model | `/login`, `/activate`, `/change-password`, modello delle credenziali |
| 03 | [03-dashboard.html](./03-dashboard.html) | `/` — KPIs, scan console, product graph, exploitability | `/` — KPI, console di scansione, grafo prodotti, exploitability |
| 04 | [04-assets.html](./04-assets.html) | `/assets` — inventory, health check, visibility cones | `/assets` — inventario, health check, coni di visibilità |
| 05 | [05-posture.html](./05-posture.html) | `/intel` — SCA runs, six charts, CVE graphs, fix planner | `/intel` — run SCA, sei grafici, grafi CVE, pianificatore fix |
| 06 | [06-risk.html](./06-risk.html) | `/risk` — EPSS, KEV, reachability, business context | `/risk` — EPSS, KEV, raggiungibilità, contesto di business |
| 07 | [07-findings.html](./07-findings.html) | `/findings` — import, dedup, workflow, SLA, ticketing | `/findings` — import, dedup, workflow, SLA, ticketing |
| 08 | [08-sbom.html](./08-sbom.html) | `/sbom` — components, licences, CycloneDX / SPDX export | `/sbom` — componenti, licenze, export CycloneDX / SPDX |
| 09 | [09-audit.html](./09-audit.html) | `/audit` — tamper-evident history, integrity, actors | `/audit` — storico a prova di manomissione, integrità, attori |
| 10 | [10-admin.html](./10-admin.html) | `/admin` — users, groups, roles, invitations | `/admin` — utenti, gruppi, ruoli, inviti |
| 11 | [11-settings.html](./11-settings.html) | `/settings` — AI, OSINT, scanner, SMTP, ticketing | `/settings` — AI, OSINT, scanner, SMTP, ticketing |
| 12 | [12-reference.html](./12-reference.html) | Permission matrix, REST API, formulas, workflows, troubleshooting, glossary | Matrice permessi, API REST, formule, flussi, risoluzione problemi, glossario |

---

## Structure of every chapter · Struttura di ogni capitolo

**EN** — Each page chapter follows the same four-part structure:

| Section | Contents |
|---|---|
| **Page Overview** | Purpose of the page, when to open it, which endpoints feed it, who is allowed in |
| **Features Breakdown** | One entry per control — button, field, filter, badge, column, chart, shortcut — with its behaviour, the API it calls, its states and error messages, each illustrated by its own screenshot |
| **How It Works** | A numbered procedure you can follow from a cold start |
| **Expected Outcome** | What must appear on screen and what is persisted — your verification checklist — plus the failure modes |

**IT** — Ogni capitolo di pagina segue la stessa struttura in quattro parti:

| Sezione | Contenuto |
|---|---|
| **Page Overview** | Scopo della pagina, quando aprirla, quali endpoint la alimentano, chi può accedervi |
| **Features Breakdown** | Una voce per ogni controllo — pulsante, campo, filtro, badge, colonna, grafico, scorciatoia — con comportamento, API chiamata, stati e messaggi di errore, ciascuno illustrato dal proprio screenshot |
| **How It Works** | Una procedura numerata seguibile da zero |
| **Expected Outcome** | Cosa deve comparire a schermo e cosa viene salvato — la checklist di verifica — più le modalità di errore |

---

## Files · File

```
static/manuale_uso/
├── index.html            00 · overview + quick start
├── 01-shell.html … 12-reference.html
├── assets/
│   ├── manual.css        theme (dark/light), bilingual switching, print rules
│   └── manual.js         language + theme state, TOC filter, scroll-spy, lightbox
├── img/                  95 dark-theme screenshots (WebP, ~3.8 MB total)
└── README.md             this file
```

**EN** — The bilingual mechanism is CSS-only: every text node exists twice, marked `lang="en"` and `lang="it"`, and
`html[data-lang]` hides the inactive one. No build step, no JSON catalogue, and the page works with JavaScript disabled
(it then shows English).

**IT** — Il meccanismo bilingue è solo CSS: ogni testo esiste due volte, marcato `lang="en"` e `lang="it"`, e
`html[data-lang]` nasconde quello inattivo. Nessuno step di build, nessun catalogo JSON, e la pagina funziona anche con
JavaScript disabilitato (in quel caso mostra l'inglese).

---

## Screenshots · Screenshot

**EN** — All 95 screenshots were captured from a live installation with real scan data, in **dark theme**
(`?theme=dark`), at 2× pixel density, then converted to WebP. Individual features are cropped to the panel they
describe rather than shown as full pages, so a caption always points at something visible.

Personal data (email addresses) is blurred in the `/admin` screenshots. If you plan to distribute this manual outside
your organisation, review `img/admin-*.webp`, `img/assets-*.webp` and `img/risk-*.webp` first — they contain your real
host names and IP addresses.

**IT** — Tutti i 95 screenshot sono stati catturati da un'installazione reale con dati di scansione veri, in **tema
scuro** (`?theme=dark`), a densità 2×, poi convertiti in WebP. Le singole funzionalità sono ritagliate sul pannello che
descrivono invece di essere mostrate a pagina intera, così una didascalia punta sempre a qualcosa di visibile.

I dati personali (indirizzi email) sono sfocati negli screenshot di `/admin`. Se prevedi di distribuire questo manuale
fuori dalla tua organizzazione, controlla prima `img/admin-*.webp`, `img/assets-*.webp` e `img/risk-*.webp` — contengono
i nomi host e gli indirizzi IP reali.

---

## Quick reference · Riferimento rapido

### Roles · Ruoli

| Role · Ruolo | EN | IT |
|---|---|---|
| `admin` | Everything, including configuration and user management | Tutto, inclusi configurazione e gestione utenti |
| `manager` | Everything except writing configuration and managing users | Tutto tranne scrivere la configurazione e gestire gli utenti |
| `editor` | Only inside their visibility cone (assigned assets) | Solo dentro il proprio cono di visibilità (asset assegnati) |
| `viewer` | Read-only; no scans, imports, exports or audit | Sola lettura; niente scansioni, import, export o audit |

Full matrix · Matrice completa → [12-reference.html#matrix](./12-reference.html#matrix)

### Score formulas · Formule degli score

```
# Posture score (0–100, higher is better · più alto è meglio)
SEV_WEIGHT = { CRITICAL: 1.0, HIGH: 0.7, MEDIUM: 0.4, LOW: 0.2, UNKNOWN: 0.5 }
score = max(0, round(100 * (1 - min(1.0, weighted / total * 1.3))))

# Contextual risk index (0–100, higher is worse · più alto è peggio)
finding_risk = SEV_WEIGHT[sev] * (1.0 + 1.5*in_KEV + max(EPSS)) * (1.4 if port_open else 1.0)
risk_index   = round(100 * (1 - exp(-(sum(finding_risk) * ctx_mult) / 8.0)))
# >= 75 CRITICAL RISK · 45..74 HIGH RISK
```

Details · Dettagli → [12-reference.html#formulas](./12-reference.html#formulas)

### Remediation SLA · SLA di remediation

| Severity · Severità | Days · Giorni |
|---|---|
| Critical | 7 |
| High | 30 |
| Medium | 90 |
| Low | 180 |
| Unknown | 90 |

Configurable in · Configurabile in `config.json` → `sla`

### First five minutes · Primi cinque minuti

**EN**

1. Sign in with `admin` / `admin` and change the password when forced.
2. Add an asset in `/assets` (IP, SSH credentials, operating system).
3. Confirm the **ACTIVE** column shows `AVAILABLE` or `SSH OK`.
4. Press **RUN POSTURE SCAN** on the Dashboard.
5. Read `/risk` for the ranked list and `/findings` for the SLA queue.

**IT**

1. Accedi con `admin` / `admin` e cambia la password quando ti viene imposto.
2. Aggiungi un asset in `/assets` (IP, credenziali SSH, sistema operativo).
3. Verifica che la colonna **ACTIVE** mostri `AVAILABLE` o `SSH OK`.
4. Premi **RUN POSTURE SCAN** sulla Dashboard.
5. Leggi `/risk` per la classifica e `/findings` per la coda SLA.

---

## Responsible use · Uso responsabile

> **EN** — Only scan or authenticate against assets you own or are explicitly authorized to test. Real SSH logins, the
> deep version probe and the reachability probe all generate traffic on the target. Scanning third-party systems without
> permission is illegal.
>
> **IT** — Esegui scansioni o autenticazioni solo su asset di tua proprietà o per cui hai autorizzazione esplicita. I
> login SSH reali, la sonda di versione approfondita e la sonda di raggiungibilità generano traffico sul target.
> Scansionare sistemi di terzi senza permesso è illegale.

---

**EN** — This manual documents the application as an operator sees it. Installation, the `start.sh` wizard, Docker test
machines and deployment live in the project [`README.md`](../../README.md).

**IT** — Questo manuale documenta l'applicazione dal punto di vista dell'operatore. Installazione, wizard `start.sh`,
macchine di test Docker e deployment sono nel [`README.md`](../../README.md) del progetto.
