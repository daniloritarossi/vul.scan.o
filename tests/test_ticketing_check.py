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


def test_jira_project_without_task_issue_type(fake_get):
    """create_jira_issue() chiede un issue type 'Task': senza, la
    configurazione e' valida e la creazione fallisce comunque."""
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK,
             FakeResponse(200, {"projects": [{"issuetypes": [{"name": "Email request"}]}]}))
    out = ticketing.check_jira(JIRA_CFG)
    assert out["code"] == "no_task_type"
    assert "Email request" in out["detail"]      # dice quali tipi ci sono


def test_jira_all_good(fake_get):
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK,
             FakeResponse(200, {"projects": [{"issuetypes": [{"name": "Task"}]}]}))
    out = ticketing.check_jira(JIRA_CFG)
    assert out["ok"] is True
    assert [s["key"] for s in out["steps"]] == ["config", "auth", "project", "issuetype"]


def test_jira_createmeta_denied_is_not_a_failure(fake_get):
    """Su alcune istanze createmeta richiede un permesso che l'utente non ha,
    mentre la creazione resta consentita: non e' una bocciatura."""
    fake_get(JIRA_ME_OK, JIRA_PROJECT_OK, FakeResponse(403, {"message": "no"}))
    assert ticketing.check_jira(JIRA_CFG)["ok"] is True


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
