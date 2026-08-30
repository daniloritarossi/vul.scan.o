"""
ticketing.py
------------
Integrazione ticketing (capability ASPM: remediation workflow).

Crea un ticket di remediation per un finding su:

  - GitHub Issues  (token PAT + repo 'owner/repo')
  - Jira Cloud     (email + API token + project key)

Configurazione in config.json, sezione 'ticketing':

    "ticketing": {
      "provider": "github" | "jira" | "",   // "" = disabilitato
      "github_token": "", "github_repo": "owner/repo",
      "jira_url": "https://org.atlassian.net", "jira_email": "",
      "jira_api_token": "", "jira_project_key": ""
    }

Filosofia best-effort: errori di rete/credenziali tornano come TicketError con
messaggio leggibile; nessun crash sul percorso HTTP. La chiave/token non viene
mai loggata ne' esposta nelle risposte.
"""

import json

import requests

TIMEOUT = 20


class TicketError(RuntimeError):
    """Creazione ticket fallita (config mancante, rete, credenziali)."""


def _finding_body(f: dict) -> str:
    """Corpo del ticket in markdown (GitHub) / testo (Jira)."""
    cves = ", ".join(f.get("cve_ids") or []) or "-"
    lines = [
        f"**Severity:** {f.get('severity') or 'UNKNOWN'}",
        f"**Asset:** {f.get('asset_ip') or '-'}",
        f"**Package:** {f.get('package') or '-'} {f.get('version') or ''}".rstrip(),
        f"**Location:** {f.get('location') or '-'}",
        f"**CVE:** {cves}",
        f"**Source:** {f.get('source') or '-'}",
        f"**First seen:** {f.get('first_seen') or '-'}",
        f"**SLA due:** {f.get('sla_due') or '-'}",
        "",
        (f.get("detail") or "").strip(),
        "",
        "_Created by Vulnerability Feed Aggregator (finding "
        f"#{f.get('id')}, fingerprint {f.get('fingerprint')})_",
    ]
    return "\n".join(lines)


def _ticket_title(f: dict) -> str:
    sev = (f.get("severity") or "UNKNOWN").upper()
    return f"[{sev}] {f.get('title') or 'Security finding'}"[:200]


DEFAULT_JIRA_ISSUE_TYPE = "Task"


def _jira_issue_types(base: str, auth, project: str):
    """
    Tipi di issue creabili in quel progetto: [{"id", "name", "subtask"}].

    None (non lista vuota) quando l'istanza non lascia leggere il createmeta:
    su alcune configurazioni richiede un permesso che l'utente non ha, mentre
    la creazione resta consentita. La differenza conta — "non lo so" non e'
    "non ce ne sono", e trattarli allo stesso modo boccerebbe configurazioni
    valide.
    """
    head = {"Accept": "application/json"}
    # L'endpoint per progetto e' quello attuale; il createmeta globale e'
    # deprecato ma vive ancora sulle istanze piu' vecchie.
    attempts = (
        (f"{base}/rest/api/3/issue/createmeta/{project}/issuetypes", None),
        (f"{base}/rest/api/3/issue/createmeta",
         {"projectKeys": project, "expand": "projects"}),
    )
    for url, params in attempts:
        try:
            r = requests.get(url, params=params, auth=auth, headers=head,
                             timeout=CHECK_TIMEOUT)
        except requests.RequestException:
            return None
        if r.status_code != 200:
            continue
        data = _json_or_none(r)
        if data is None:
            continue
        # La risposta per progetto usa "issueTypes" (o "values" su alcune
        # versioni); quella globale annida i tipi dentro "projects".
        raw = data.get("issueTypes") or data.get("values")
        if raw is None:
            raw = [t for p in (data.get("projects") or [])
                   for t in (p.get("issuetypes") or [])]
        return [{"id": str(t.get("id") or ""), "name": t.get("name") or "",
                 "subtask": bool(t.get("subtask"))}
                for t in raw if t.get("name")]
    return None


def _pick_issue_type(types, wanted: str):
    """Il tipo che corrisponde al nome chiesto, o None. I sotto-task sono
    esclusi: non esistono come issue di primo livello."""
    want = (wanted or "").strip().lower()
    for t in types:
        if not t["subtask"] and t["name"].strip().lower() == want:
            return t
    return None


def _issue_type_names(types) -> str:
    return ", ".join(t["name"] for t in types if not t["subtask"])


def create_github_issue(cfg: dict, f: dict) -> dict:
    token = (cfg.get("github_token") or "").strip()
    repo = (cfg.get("github_repo") or "").strip()
    if not token or "/" not in repo:
        raise TicketError("Ticketing GitHub non configurato (token o repo mancanti)")
    labels = ["security", (f.get("severity") or "unknown").lower()]
    try:
        resp = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": _ticket_title(f), "body": _finding_body(f),
                  "labels": labels},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise TicketError(f"GitHub non raggiungibile: {exc}") from exc
    if resp.status_code != 201:
        detail = ""
        try:
            detail = (resp.json().get("message") or "")[:120]
        except json.JSONDecodeError:
            pass
        raise TicketError(f"GitHub HTTP {resp.status_code}: {detail}")
    data = resp.json()
    return {"provider": "github", "ref": f"#{data.get('number')}",
            "url": data.get("html_url") or ""}


def create_jira_issue(cfg: dict, f: dict) -> dict:
    base = (cfg.get("jira_url") or "").strip().rstrip("/")
    email = (cfg.get("jira_email") or "").strip()
    token = (cfg.get("jira_api_token") or "").strip()
    project = (cfg.get("jira_project_key") or "").strip()
    wanted = (cfg.get("jira_issue_type") or DEFAULT_JIRA_ISSUE_TYPE).strip()
    if not (base and email and token and project):
        raise TicketError("Ticketing Jira non configurato (url/email/token/project)")
    # Corpo in Atlassian Document Format (richiesto dalla API v3).
    body_adf = {
        "type": "doc", "version": 1,
        "content": [{"type": "paragraph",
                     "content": [{"type": "text",
                                  "text": _finding_body(f).replace("**", "")}]}],
    }
    # Il tipo si risolve in ID prima di creare. Per nome funziona solo finche'
    # quel nome esiste globalmente: i tipi di un progetto Jira Service
    # Management sono definiti NEL progetto (scope PROJECT), e l'ID e' l'unico
    # riferimento che li identifica senza ambiguita'. Se il createmeta non e'
    # leggibile si ripiega sul nome, che e' comunque meglio di non provare.
    types = _jira_issue_types(base, (email, token), project)
    if types is not None:
        hit = _pick_issue_type(types, wanted)
        if hit is None:
            raise TicketError(
                f"Il progetto {project} non ha un tipo di issue '{wanted}'. "
                f"Disponibili: {_issue_type_names(types) or 'nessuno'}")
        issuetype = {"id": hit["id"]}
    else:
        issuetype = {"name": wanted}
    try:
        resp = requests.post(
            f"{base}/rest/api/3/issue",
            auth=(email, token),
            json={"fields": {
                "project": {"key": project},
                "issuetype": issuetype,
                "summary": _ticket_title(f),
                "description": body_adf,
                "labels": ["security", (f.get("severity") or "unknown").lower()],
            }},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise TicketError(f"Jira non raggiungibile: {exc}") from exc
    if resp.status_code not in (200, 201):
        raise TicketError(f"Jira HTTP {resp.status_code}: {resp.text[:120]}")
    data = resp.json()
    key = data.get("key") or ""
    return {"provider": "jira", "ref": key, "url": f"{base}/browse/{key}"}


def create_ticket(cfg_ticketing: dict, finding: dict) -> dict:
    """
    Crea il ticket con il provider configurato.
    Ritorna {provider, ref, url}. TicketError se disabilitato o fallito.
    """
    provider = (cfg_ticketing.get("provider") or "").strip().lower()
    if provider == "github":
        return create_github_issue(cfg_ticketing, finding)
    if provider == "jira":
        return create_jira_issue(cfg_ticketing, finding)
    raise TicketError("Ticketing disabilitato: configura il provider in Settings")


# ---------------------------------------------------------------------------
# Verifica della configurazione (nessun ticket creato)
# ---------------------------------------------------------------------------
#
# Il pulsante CHECK CONNECTION deve rispondere a una domanda precisa: se
# adesso premo "crea ticket", funziona? Provarlo creando un ticket vero non e'
# accettabile (sporca il progetto altrui), quindi si percorre la stessa catena
# in sola lettura: raggiungibilita' -> credenziali -> risorsa -> permesso di
# scrittura. Ogni anello e' un passo distinto, perche' "non funziona" e'
# inutile: quello che serve sapere e' QUALE anello si e' rotto e quale campo
# della form lo governa.
#
# I messaggi tornano come CODICE, non come frase: la stessa diagnosi deve
# poter essere letta in inglese e in italiano, e la traduzione sta in i18n.js
# insieme a tutto il resto dell'interfaccia.

CHECK_TIMEOUT = 12


def _fail(code: str, field: str = "", detail: str = "", steps=None) -> dict:
    return {"ok": False, "code": code, "field": field,
            "detail": (detail or "")[:200], "steps": steps or []}


def _net_failure(exc: Exception, field: str, steps: list) -> dict:
    """Traduce l'eccezione di rete nella causa che l'utente puo' correggere."""
    if isinstance(exc, requests.exceptions.SSLError):
        return _fail("tls", field, str(exc), steps)
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return _fail("timeout", field, str(exc), steps)
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return _fail("timeout", field, str(exc), steps)
    if isinstance(exc, requests.exceptions.ConnectionError):
        text = str(exc)
        # requests impacchetta dentro ConnectionError sia il DNS sia il rifiuto
        # della connessione: la distinzione conta, perche' la prima e' un
        # dominio sbagliato e la seconda un firewall o una porta chiusa.
        low = text.lower()
        if "name or service not known" in low or "nodename nor servname" in low \
                or "failed to resolve" in low or "getaddrinfo" in low:
            return _fail("dns", field, text, steps)
        if "refused" in low:
            return _fail("refused", field, text, steps)
        return _fail("network", field, text, steps)
    return _fail("network", field, str(exc), steps)


def _json_or_none(resp):
    """Il corpo come JSON, o None se il server ha risposto altro (tipico di un
    URL che non e' l'API attesa: portale SSO, proxy, pagina 404 in HTML)."""
    try:
        return resp.json()
    except ValueError:
        return None


def check_github(cfg: dict) -> dict:
    steps: list = []
    token = (cfg.get("github_token") or "").strip()
    repo = (cfg.get("github_repo") or "").strip().strip("/")

    if not token:
        return _fail("missing_token", "github_token", steps=steps)
    if not repo:
        return _fail("missing_repo", "github_repo", steps=steps)
    if repo.count("/") != 1 or not all(repo.split("/")):
        return _fail("repo_format", "github_repo", repo, steps)
    steps.append({"key": "config", "ok": True})

    head = {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}

    # 1. il token e' valido? /user e' la prova piu' economica.
    try:
        r = requests.get("https://api.github.com/user", headers=head,
                         timeout=CHECK_TIMEOUT)
    except requests.RequestException as exc:
        return _net_failure(exc, "github_token", steps)
    if r.status_code == 401:
        return _fail("bad_token", "github_token",
                     (_json_or_none(r) or {}).get("message", ""), steps)
    if r.status_code == 403 and "rate limit" in r.text.lower():
        return _fail("rate_limited", "github_token", "", steps)
    if r.status_code >= 500:
        return _fail("server_error", "", f"HTTP {r.status_code}", steps)
    if r.status_code != 200:
        return _fail("bad_token", "github_token",
                     (_json_or_none(r) or {}).get("message", ""), steps)
    login = (_json_or_none(r) or {}).get("login") or ""
    # I PAT classici dichiarano i propri scope in un header; i fine-grained no,
    # e per quelli l'unica verifica possibile e' il permesso sul repo (sotto).
    scopes = (r.headers.get("x-oauth-scopes") or "").strip()
    steps.append({"key": "auth", "ok": True, "info": login})

    # 2. il repository esiste ed e' visibile a QUESTO token?
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}", headers=head,
                         timeout=CHECK_TIMEOUT)
    except requests.RequestException as exc:
        return _net_failure(exc, "github_repo", steps)
    if r.status_code == 404:
        # GitHub risponde 404 anche quando il repo esiste ma il token non lo
        # vede: e' deliberato (non rivela repository privati), e va detto.
        return _fail("repo_not_found", "github_repo", repo, steps)
    if r.status_code == 403:
        return _fail("repo_forbidden", "github_token",
                     (_json_or_none(r) or {}).get("message", ""), steps)
    if r.status_code != 200:
        return _fail("repo_error", "github_repo", f"HTTP {r.status_code}", steps)
    data = _json_or_none(r) or {}
    steps.append({"key": "repo", "ok": True, "info": data.get("full_name") or repo})

    # 3. le tre condizioni che fanno fallire la creazione a runtime anche con
    #    token e repo perfetti.
    if data.get("archived"):
        return _fail("repo_archived", "github_repo", repo, steps)
    if data.get("has_issues") is False:
        return _fail("issues_disabled", "github_repo", repo, steps)
    perms = data.get("permissions") or {}
    if perms and not (perms.get("push") or perms.get("admin") or
                      perms.get("maintain") or perms.get("triage")):
        return _fail("no_write", "github_token", repo, steps)
    if scopes and not any(s in scopes for s in ("repo", "public_repo")):
        return _fail("token_no_scope", "github_token", scopes, steps)
    steps.append({"key": "issues", "ok": True})

    return {"ok": True, "provider": "github", "steps": steps,
            "account": login, "target": data.get("full_name") or repo}


def check_jira(cfg: dict) -> dict:
    steps: list = []
    base = (cfg.get("jira_url") or "").strip().rstrip("/")
    email = (cfg.get("jira_email") or "").strip()
    token = (cfg.get("jira_api_token") or "").strip()
    project = (cfg.get("jira_project_key") or "").strip()
    wanted = (cfg.get("jira_issue_type") or DEFAULT_JIRA_ISSUE_TYPE).strip()

    if not base:
        return _fail("missing_url", "jira_url", steps=steps)
    if not base.startswith(("http://", "https://")) or "." not in base.split("//", 1)[-1]:
        return _fail("url_format", "jira_url", base, steps)
    if not email:
        return _fail("missing_email", "jira_email", steps=steps)
    if "@" not in email:
        return _fail("email_format", "jira_email", email, steps)
    if not token:
        return _fail("missing_token", "jira_api_token", steps=steps)
    if not project:
        return _fail("missing_project", "jira_project_key", steps=steps)
    steps.append({"key": "config", "ok": True})

    head = {"Accept": "application/json"}

    # 1. l'URL e' un Jira, e la coppia email+token e' valida?
    try:
        r = requests.get(f"{base}/rest/api/3/myself", auth=(email, token),
                         headers=head, timeout=CHECK_TIMEOUT)
    except requests.RequestException as exc:
        return _net_failure(exc, "jira_url", steps)
    body = _json_or_none(r)
    # L'ordine conta: su credenziali sbagliate Jira risponde 401 con una
    # pagina HTML, non con JSON. Se si guardasse prima la forma del corpo,
    # ogni password errata verrebbe diagnosticata come "dominio sbagliato".
    if r.status_code == 401:
        return _fail("bad_credentials", "jira_api_token",
                     (body or {}).get("message", ""), steps)
    if r.status_code == 403:
        return _fail("forbidden", "jira_api_token",
                     (body or {}).get("message", ""), steps)
    if r.status_code == 429:
        return _fail("rate_limited", "", "", steps)
    if r.status_code >= 500:
        return _fail("server_error", "jira_url", f"HTTP {r.status_code}", steps)
    if r.status_code == 404:
        # atlassian.net e' un wildcard DNS: un sito inesistente si risolve e
        # risponde 404. Il dominio non e' irraggiungibile, semplicemente non
        # esiste quell'istanza — ed e' esattamente quello che va detto.
        return _fail("site_not_found", "jira_url", f"HTTP {r.status_code}", steps)
    if body is None:
        # Il dominio risponde ma non parla l'API di Jira: quasi sempre e' il
        # dominio sbagliato (portale SSO, sito aziendale, proxy).
        return _fail("not_jira", "jira_url", f"HTTP {r.status_code}", steps)
    if r.status_code != 200:
        return _fail("auth_error", "jira_api_token", f"HTTP {r.status_code}", steps)
    who = (body or {}).get("displayName") or (body or {}).get("emailAddress") or ""
    steps.append({"key": "auth", "ok": True, "info": who})

    # 2. il progetto esiste e questo account lo vede?
    try:
        r = requests.get(f"{base}/rest/api/3/project/{project}",
                         auth=(email, token), headers=head, timeout=CHECK_TIMEOUT)
    except requests.RequestException as exc:
        return _net_failure(exc, "jira_project_key", steps)
    if r.status_code in (401, 403):
        return _fail("project_forbidden", "jira_project_key", project, steps)
    if r.status_code == 404:
        return _fail("project_not_found", "jira_project_key", project, steps)
    if r.status_code != 200:
        return _fail("project_error", "jira_project_key",
                     f"HTTP {r.status_code}", steps)
    pdata = _json_or_none(r) or {}
    steps.append({"key": "project", "ok": True,
                  "info": pdata.get("name") or project})

    # 3. il tipo di issue configurato esiste in QUEL progetto? E' la
    #    condizione che manda a vuoto la creazione anche con credenziali,
    #    progetto e permessi perfetti — un progetto Jira Service Management
    #    non ha "Task", offre "Email request" o simili.
    types = _jira_issue_types(base, (email, token), project)
    if types is not None:
        hit = _pick_issue_type(types, wanted)
        if hit is None:
            # Il messaggio deve dire sia che cosa e' stato chiesto sia che cosa
            # c'e': senza la seconda meta' l'utente non sa cosa scrivere.
            out = _fail("issue_type_not_found", "jira_issue_type",
                        _issue_type_names(types) or "-", steps)
            out["params"] = {"w": wanted,
                             "n": _issue_type_names(types) or "-"}
            return out
        steps.append({"key": "issuetype", "ok": True,
                      "info": f"{hit['name']} (id {hit['id']})"})
    # Un createmeta illeggibile non e' una bocciatura: su alcune istanze
    # richiede un permesso che l'utente non ha, mentre la creazione resta
    # consentita. Si tace, invece di dichiarare un errore che non c'e'.

    return {"ok": True, "provider": "jira", "steps": steps,
            "account": who, "target": f"{project} · {pdata.get('name') or ''}".strip(" ·")}


def check_connection(cfg_ticketing: dict) -> dict:
    """
    Verifica la configurazione ticketing SENZA creare nulla.
    Ritorna {ok, provider, steps[...]} oppure {ok:false, code, field, detail}.
    """
    provider = (cfg_ticketing.get("provider") or "").strip().lower()
    if provider == "github":
        out = check_github(cfg_ticketing)
    elif provider == "jira":
        out = check_jira(cfg_ticketing)
    else:
        return _fail("provider_off", "provider")
    out.setdefault("provider", provider)
    return out
