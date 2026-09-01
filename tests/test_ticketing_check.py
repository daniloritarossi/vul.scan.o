"""
test_ticketing_check.py
-----------------------
Verifica della configurazione ticketing (POST /api/settings/ticketing/check).

Il pulsante CHECK CONNECTION esiste per rispondere a "se premo crea ticket,
funziona?" senza creare nulla. Due proprieta' vanno protette da regressioni:

  1. la diagnosi e' SPECIFICA — ogni fallimento nomina il codice e il campo
     della form che lo governa, perche' "non funziona" non e' una risposta;
  2. il token non esce mai dall'endpoint, ne' nella risposta ne' nel registro.

Le risposte dei provider sono simulate: i rami interessanti (repo archiviato,
issue disabilitate, token senza scope) non sono raggiungibili con credenziali
vere, e la suite non deve dipendere dalla rete.
"""
import json

import pytest

import ticketing


class FakeResponse:
    def __init__(self, status, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(body or {})

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


@pytest.fixture
def fake_get(monkeypatch):
    """Sostituisce requests.get con una coda di risposte preconfezionate."""
    def install(*responses):
        queue = list(responses)

        def _get(url, **kwargs):
            assert queue, f"richiesta non prevista: {url}"
            return queue.pop(0)

        monkeypatch.setattr(ticketing.requests, "get", _get)
    return install


GH_CFG = {"github_token": "ghp_x", "github_repo": "acme/app"}
GH_USER_OK = FakeResponse(200, {"login": "acme-bot"}, {"x-oauth-scopes": "repo"})
GH_REPO_OK = FakeResponse(200, {"full_name": "acme/app", "has_issues": True,
                                "archived": False, "permissions": {"push": True}})


# ── GitHub ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cfg,code,field", [
    ({"github_token": "", "github_repo": "acme/app"}, "missing_token", "github_token"),
    ({"github_token": "ghp_x", "github_repo": ""}, "missing_repo", "github_repo"),
    ({"github_token": "ghp_x", "github_repo": "https://github.com/acme/app"},
     "repo_format", "github_repo"),
])
def test_github_config_errors_name_the_field(cfg, code, field):
    """Gli errori di forma non spendono una chiamata di rete."""
    out = ticketing.check_github(cfg)
    assert out["ok"] is False
    assert out["code"] == code
    assert out["field"] == field


def test_github_rejects_bad_token(fake_get):
    fake_get(FakeResponse(401, {"message": "Bad credentials"}))
    out = ticketing.check_github(GH_CFG)
    assert (out["code"], out["field"]) == ("bad_token", "github_token")


def test_github_missing_repo_is_not_reported_as_a_token_problem(fake_get):
    """GitHub risponde 404 sia per repo inesistente sia per repo invisibile:
    la diagnosi deve puntare al repository, non alle credenziali."""
    fake_get(GH_USER_OK, FakeResponse(404, {"message": "Not Found"}))
    out = ticketing.check_github(GH_CFG)
    assert (out["code"], out["field"]) == ("repo_not_found", "github_repo")


@pytest.mark.parametrize("repo_body,code", [
    ({"full_name": "acme/app", "has_issues": True, "archived": True,
      "permissions": {"push": True}}, "repo_archived"),
    ({"full_name": "acme/app", "has_issues": False, "archived": False,
      "permissions": {"push": True}}, "issues_disabled"),
    ({"full_name": "acme/app", "has_issues": True, "archived": False,
      "permissions": {"pull": True, "push": False}}, "no_write"),
])
def test_github_catches_what_only_fails_at_creation_time(fake_get, repo_body, code):
    """Token e repo validi non bastano: sono i tre casi in cui la creazione
    fallirebbe comunque, ed e' il motivo per cui la verifica esiste."""
    fake_get(GH_USER_OK, FakeResponse(200, repo_body))
    out = ticketing.check_github(GH_CFG)
    assert out["code"] == code


def test_github_classic_pat_without_repo_scope(fake_get):
    fake_get(FakeResponse(200, {"login": "acme-bot"}, {"x-oauth-scopes": "gist"}),
             GH_REPO_OK)
    assert ticketing.check_github(GH_CFG)["code"] == "token_no_scope"


def test_github_fine_grained_pat_has_no_scope_header_and_passes(fake_get):
    """I PAT fine-grained non dichiarano scope: assumere il contrario
    boccerebbe una configurazione perfettamente valida."""
    fake_get(FakeResponse(200, {"login": "acme-bot"}, {}), GH_REPO_OK)
    out = ticketing.check_github(GH_CFG)
    assert out["ok"] is True
    assert [s["key"] for s in out["steps"]] == ["config", "auth", "repo", "issues"]


# ── Jira ──────────────────────────────────────────────────────────────────

JIRA_CFG = {"jira_url": "https://acme.atlassian.net", "jira_email": "bot@acme.io",
            "jira_api_token": "tok", "jira_project_key": "SEC"}
JIRA_ME_OK = FakeResponse(200, {"displayName": "Acme Bot"})
JIRA_PROJECT_OK = FakeResponse(200, {"name": "Security"})


@pytest.mark.parametrize("override,code,field", [
    ({"jira_url": ""}, "missing_url", "jira_url"),
    ({"jira_url": "acme.atlassian.net"}, "url_format", "jira_url"),
    ({"jira_email": "acme"}, "email_format", "jira_email"),
    ({"jira_api_token": ""}, "missing_token", "jira_api_token"),
    ({"jira_project_key": ""}, "missing_project", "jira_project_key"),
])
def test_jira_config_errors_name_the_field(override, code, field):
    out = ticketing.check_jira({**JIRA_CFG, **override})
    assert (out["code"], out["field"]) == (code, field)


def test_jira_bad_credentials_are_not_mistaken_for_a_wrong_domain(fake_get):
    """Su 401 Jira risponde HTML, non JSON. Guardando prima la forma del corpo
    ogni password sbagliata verrebbe diagnosticata come dominio errato."""
    fake_get(FakeResponse(401, None, text="<html>login</html>"))
    out = ticketing.check_jira(JIRA_CFG)
    assert (out["code"], out["field"]) == ("bad_credentials", "jira_api_token")


def test_jira_unknown_site_is_reported_as_such(fake_get):
    """atlassian.net e' un wildcard DNS: un sito inesistente non da' errore di
    risoluzione, risponde 404."""
    fake_get(FakeResponse(404, {"message": "not found"}))
    assert ticketing.check_jira(JIRA_CFG)["code"] == "site_not_found"


def test_jira_non_jira_domain(fake_get):
    fake_get(FakeResponse(200, None, text="<html>corporate portal</html>"))
    out = ticketing.check_jira(JIRA_CFG)
    assert (out["code"], out["field"]) == ("not_jira", "jira_url")


def test_jira_unknown_project_key(fake_get):
    fake_get(JIRA_ME_OK, FakeResponse(404, {"message": "No project"}))
    out = ticketing.check_jira(JIRA_CFG)
    assert (out["code"], out["field"]) == ("project_not_found", "jira_project_key")


def _types(*names):
    """Risposta dell'endpoint createmeta per progetto (formato attuale)."""
    return FakeResponse(200, {"issueTypes": [
        {"id": str(10000 + i), "name": n, "subtask": False}
        for i, n in enumerate(names)]})


def test_jira_project_without_the_configured_issue_type(fake_get):
    """Un progetto Service Management non ha 'Task': la configurazione e'
    valida in ogni altro senso e la creazione fallirebbe comunque."""
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, _types("Email request"))
    out = ticketing.check_jira(JIRA_CFG)          # jira_issue_type non impostato -> Task
    assert out["code"] == "issue_type_not_found"
    assert out["field"] == "jira_issue_type"
    # Il messaggio deve poter dire sia il tipo chiesto sia quelli disponibili.
    assert out["params"] == {"w": "Task", "n": "Email request"}


def test_jira_accepts_a_service_management_issue_type(fake_get):
    """E' il caso che ha motivato il campo: nessun 'Task' in vista, e la
    configurazione e' comunque corretta."""
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, _types("Email request"))
    out = ticketing.check_jira({**JIRA_CFG, "jira_issue_type": "Email request"})
    assert out["ok"] is True
    assert [s["key"] for s in out["steps"]] == ["config", "auth", "project", "issuetype"]
    assert "10000" in out["steps"][-1]["info"]    # riporta l'id risolto


def test_jira_issue_type_match_ignores_case(fake_get):
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, _types("Email request"))
    assert ticketing.check_jira({**JIRA_CFG, "jira_issue_type": "email REQUEST"})["ok"] is True


def test_jira_empty_issue_type_falls_back_to_task(fake_get):
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, _types("Task", "Bug"))
    assert ticketing.check_jira({**JIRA_CFG, "jira_issue_type": ""})["ok"] is True


def test_jira_all_good(fake_get):
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, _types("Task"))
    out = ticketing.check_jira(JIRA_CFG)
    assert out["ok"] is True
    assert [s["key"] for s in out["steps"]] == ["config", "auth", "project", "issuetype"]


def test_jira_createmeta_denied_is_not_a_failure(fake_get):
    """Su alcune istanze createmeta richiede un permesso che l'utente non ha,
    mentre la creazione resta consentita: non e' una bocciatura. Entrambi gli
    endpoint vanno consumati prima di rinunciare."""
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK,
             FakeResponse(403, {"message": "no"}), FakeResponse(403, {"message": "no"}))
    out = ticketing.check_jira(JIRA_CFG)
    assert out["ok"] is True
    assert [s["key"] for s in out["steps"]] == ["config", "auth", "project"]


# ── Risoluzione del tipo di issue ─────────────────────────────────────────

def test_issue_types_read_from_the_per_project_endpoint(fake_get):
    fake_get(_types("Task", "Bug"))
    got = ticketing._jira_issue_types("https://acme.atlassian.net", ("a", "b"), "SEC")
    assert [t["name"] for t in got] == ["Task", "Bug"]
    assert got[0]["id"] == "10000"


def test_issue_types_fall_back_to_the_deprecated_endpoint(fake_get):
    """Le istanze piu' vecchie non hanno l'endpoint per progetto."""
    fake_get(FakeResponse(404, {"message": "gone"}),
             FakeResponse(200, {"projects": [{"issuetypes": [
                 {"id": "3", "name": "Task", "subtask": False}]}]}))
    got = ticketing._jira_issue_types("https://acme.atlassian.net", ("a", "b"), "SEC")
    assert got == [{"id": "3", "name": "Task", "subtask": False}]


def test_issue_types_unreadable_is_none_not_empty(fake_get):
    """None significa 'non lo so'; [] significherebbe 'non ce ne sono', e
    boccerebbe una configurazione valida."""
    fake_get(FakeResponse(403, {}), FakeResponse(403, {}))
    assert ticketing._jira_issue_types("https://acme.atlassian.net", ("a", "b"), "SEC") is None


def test_subtask_types_are_not_selectable():
    types = [{"id": "1", "name": "Sub-task", "subtask": True},
             {"id": "2", "name": "Task", "subtask": False}]
    assert ticketing._pick_issue_type(types, "Sub-task") is None
    assert ticketing._pick_issue_type(types, "Task")["id"] == "2"


# ── Creazione: il tipo viaggia come ID ────────────────────────────────────

def _capture_post(monkeypatch):
    sent = {}

    def _post(url, **kwargs):
        sent["json"] = kwargs.get("json")
        return FakeResponse(201, {"key": "SEC-1"})

    monkeypatch.setattr(ticketing.requests, "post", _post)
    return sent


def test_create_sends_the_resolved_id_not_the_name(fake_get, monkeypatch):
    """I tipi di un progetto Service Management sono definiti nel progetto
    (scope PROJECT): l'id e' l'unico riferimento non ambiguo."""
    fake_get(_types("Email request"))
    sent = _capture_post(monkeypatch)
    out = ticketing.create_jira_issue(
        {**JIRA_CFG, "jira_issue_type": "Email request"}, {"id": 1, "severity": "HIGH"})
    assert sent["json"]["fields"]["issuetype"] == {"id": "10000"}
    assert out["ref"] == "SEC-1"


def test_create_falls_back_to_the_name_when_createmeta_is_unreadable(fake_get, monkeypatch):
    fake_get(FakeResponse(403, {}), FakeResponse(403, {}))
    sent = _capture_post(monkeypatch)
    ticketing.create_jira_issue({**JIRA_CFG, "jira_issue_type": "Task"}, {"id": 1})
    assert sent["json"]["fields"]["issuetype"] == {"name": "Task"}


def test_create_refuses_a_type_the_project_does_not_have(fake_get, monkeypatch):
    """Meglio un errore che nomina i tipi disponibili di un HTTP 400 di Jira."""
    fake_get(_types("Email request"))
    monkeypatch.setattr(ticketing.requests, "post",
                        lambda *a, **k: pytest.fail("non deve nemmeno provare"))
    with pytest.raises(ticketing.TicketError) as exc:
        ticketing.create_jira_issue({**JIRA_CFG, "jira_issue_type": "Task"}, {"id": 1})
    assert "Email request" in str(exc.value)


# ── Rete ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc,code", [
    (ticketing.requests.exceptions.SSLError("bad cert"), "tls"),
    (ticketing.requests.exceptions.ConnectTimeout("slow"), "timeout"),
    (ticketing.requests.exceptions.ConnectionError(
        "Failed to resolve 'nope.example'"), "dns"),
    (ticketing.requests.exceptions.ConnectionError("Connection refused"), "refused"),
])
def test_network_failures_are_told_apart(monkeypatch, exc, code):
    """Un dominio sbagliato e un firewall si correggono in modi diversi."""
    def _boom(url, **kwargs):
        raise exc
    monkeypatch.setattr(ticketing.requests, "get", _boom)
    assert ticketing.check_jira(JIRA_CFG)["code"] == code


def test_provider_off():
    assert ticketing.check_connection({"provider": ""})["code"] == "provider_off"


# ── Endpoint: permessi e segreti ──────────────────────────────────────────

def test_check_is_admin_only(role_clients):
    """Spende le credenziali del prodotto verso un servizio esterno: stesso
    privilegio della scrittura di configurazione, non della sua lettura."""
    for role in ("manager", "editor", "auditor", "viewer", "stakeholder"):
        r = role_clients[role].post("/api/settings/ticketing/check",
                                    json={"provider": ""})
        assert r.status_code == 403, f"{role} non deve poter verificare"
    r = role_clients["admin"].post("/api/settings/ticketing/check",
                                   json={"provider": ""})
    assert r.status_code == 200


def test_check_never_echoes_the_token(role_clients, monkeypatch):
    secret = "super-secret-jira-token"
    monkeypatch.setattr(ticketing.requests, "get",
                        lambda url, **kw: FakeResponse(401, None, text="<html/>"))
    r = role_clients["admin"].post("/api/settings/ticketing/check", json={
        "provider": "jira", "jira_url": "https://acme.atlassian.net",
        "jira_email": "bot@acme.io", "jira_api_token": secret,
        "jira_project_key": "SEC"})
    assert r.status_code == 200
    assert secret not in r.text
    assert r.json()["code"] == "bad_credentials"


def test_masked_token_falls_back_to_the_stored_one(role_clients, monkeypatch):
    """Il frontend rimanda '••••••••' per il campo mascherato: la verifica deve
    usare il valore salvato, altrimenti controllerebbe il placeholder."""
    seen = {}

    def _get(url, **kwargs):
        seen["auth"] = kwargs.get("auth")
        return FakeResponse(401, None, text="<html/>")

    monkeypatch.setattr(ticketing.requests, "get", _get)
    monkeypatch.setattr("app.load_config", lambda: {"ticketing": {
        "provider": "jira", "jira_url": "https://acme.atlassian.net",
        "jira_email": "bot@acme.io", "jira_api_token": "stored-token",
        "jira_project_key": "SEC"}})
    role_clients["admin"].post("/api/settings/ticketing/check", json={
        "provider": "jira", "jira_api_token": "••••••••"})
    assert seen["auth"] == ("bot@acme.io", "stored-token")


# ── Stato dei ticket gia' aperti ──────────────────────────────────────────

def _jira_search(*pairs):
    """Risposta di POST /rest/api/3/search/jql per (key, status, category)."""
    return FakeResponse(200, {"issues": [
        {"key": k, "fields": {"status": {"name": name,
                                         "statusCategory": {"key": cat}},
                              "resolution": None}}
        for k, name, cat in pairs]})


@pytest.fixture
def fake_post(monkeypatch):
    def install(*responses):
        queue = list(responses)

        def _post(url, **kwargs):
            assert queue, f"richiesta non prevista: {url}"
            install.last = kwargs
            return queue.pop(0)

        monkeypatch.setattr(ticketing.requests, "post", _post)
    install.last = None
    return install


def test_jira_status_maps_the_category_not_the_label(fake_post):
    """La categoria e' sempre una di tre; il nome dello stato lo decide il
    workflow e puo' essere in qualunque lingua."""
    fake_post(_jira_search(("SEC-1", "Pronto per il collaudo", "indeterminate"),
                           ("SEC-2", "Fatto", "done"),
                           ("SEC-3", "Da fare", "new")))
    out = ticketing.fetch_ticket_status({**JIRA_CFG, "provider": "jira"},
                                        ["SEC-1", "SEC-2", "SEC-3"])
    assert out["SEC-1"]["state"] == ticketing.STATE_DOING
    assert out["SEC-2"]["state"] == ticketing.STATE_DONE
    assert out["SEC-3"]["state"] == ticketing.STATE_TODO
    # l'etichetta resta quella del provider: e' quella che l'utente riconosce
    assert out["SEC-1"]["status"] == "Pronto per il collaudo"


def test_jira_unknown_category_is_not_guessed(fake_post):
    fake_post(_jira_search(("SEC-9", "Boh", "weird")))
    out = ticketing.fetch_ticket_status({**JIRA_CFG, "provider": "jira"}, ["SEC-9"])
    assert out["SEC-9"]["state"] == ticketing.STATE_UNKNOWN


def test_jira_status_is_one_call_per_chunk(fake_post, monkeypatch):
    """Una JQL con troppe chiavi supera i limiti: si spezza, ma resta una
    chiamata per blocco e non una per ticket."""
    monkeypatch.setattr(ticketing, "JIRA_STATUS_CHUNK", 2)
    fake_post(_jira_search(("A-1", "Done", "done"), ("A-2", "Done", "done")),
              _jira_search(("A-3", "To Do", "new")))
    out = ticketing.fetch_ticket_status({**JIRA_CFG, "provider": "jira"},
                                        ["A-1", "A-2", "A-3"])
    assert set(out) == {"A-1", "A-2", "A-3"}


def test_github_open_and_closed(fake_get):
    fake_get(FakeResponse(200, {"state": "open", "state_reason": None}),
             FakeResponse(200, {"state": "closed", "state_reason": "completed"}))
    out = ticketing.fetch_ticket_status({**GH_CFG, "provider": "github"}, ["#1", "#2"])
    assert out["#1"]["state"] == ticketing.STATE_TODO
    assert out["#2"]["state"] == ticketing.STATE_DONE


def test_github_not_planned_is_closed_but_not_done(fake_get):
    """Chiuso non vuol dire risolto: dire 'done' di un 'not planned' sarebbe
    la lettura che porta a chiudere un finding che nessuno ha corretto."""
    fake_get(FakeResponse(200, {"state": "closed", "state_reason": "not_planned"}))
    out = ticketing.fetch_ticket_status({**GH_CFG, "provider": "github"}, ["#3"])
    assert out["#3"]["state"] == ticketing.STATE_UNKNOWN
    assert "not planned" in out["#3"]["status"]


def test_github_deleted_issue_is_reported_missing_not_fatal(fake_get):
    fake_get(FakeResponse(404, {"message": "Not Found"}),
             FakeResponse(200, {"state": "open", "state_reason": None}))
    out = ticketing.fetch_ticket_status({**GH_CFG, "provider": "github"}, ["#7", "#8"])
    assert out["#7"]["missing"] is True
    assert out["#8"]["state"] == ticketing.STATE_TODO


def test_status_without_provider_is_refused():
    with pytest.raises(ticketing.TicketError):
        ticketing.fetch_ticket_status({"provider": ""}, ["SEC-1"])


def test_status_of_nothing_costs_no_call(monkeypatch):
    monkeypatch.setattr(ticketing.requests, "post",
                        lambda *a, **k: pytest.fail("non deve chiamare nulla"))
    assert ticketing.fetch_ticket_status({"provider": "jira"}, []) == {}


def test_ticket_refresh_is_writer_only(role_clients, monkeypatch):
    """La matrice RBAC del manuale dichiara writer si', lettori no: qui la si
    verifica invece di fidarsene."""
    for role in ("auditor", "viewer", "stakeholder"):
        r = role_clients[role].post("/api/findings/tickets/refresh")
        assert r.status_code == 403, f"{role} non deve poter aggiornare"
    # I ruoli che scrivono passano il controllo di ruolo. Il provider e'
    # neutralizzato: qui si verifica il permesso, non la rete.
    monkeypatch.setattr(ticketing.requests, "post",
                        lambda *a, **k: FakeResponse(200, {"issues": []}))
    monkeypatch.setattr(ticketing.requests, "get",
                        lambda *a, **k: FakeResponse(200, {"state": "open"}))
    for role in ("admin", "manager", "editor"):
        r = role_clients[role].post("/api/findings/tickets/refresh")
        assert r.status_code == 200, f"{role} deve poter aggiornare ({r.text[:80]})"
