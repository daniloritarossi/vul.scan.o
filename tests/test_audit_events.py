"""
Registro delle ATTIVITA' (audit_events): copertura e integrita'.

Il registro di audit copriva solo le scansioni: accessi, cambi ruolo,
amministrazione utenti/gruppi, assegnazioni, configurazione ed export non
lasciavano traccia, e "chi ha fatto cosa" era una domanda senza risposta per
tutto tranne la scansione. Questi test verificano che ogni azione rilevante
finisca nel registro, con l'attore giusto e l'esito giusto, e che la catena
hash se ne accorga se qualcuno la ritocca.

Richiede lo stack Supabase locale (vedi conftest.py). Le righe scritte sono
tutte marcate '_ftest_' e vengono ripulite dalla fixture 'audit_cleanup'.
"""

import json
from pathlib import Path

import pytest

import db
from conftest import ROLE_PASSWORD, USERNAME


# --------------------------------------------------------------------- helper

def _events(client, **params):
    """Eventi visibili al client indicato (default: tutto, non paginato)."""
    params.setdefault("page_size", 0)
    r = client.get("/api/audit/events", params=params)
    assert r.status_code == 200, r.text
    return r.json()["events"]


def _find(events, action, **match):
    """Primo evento con quell'azione (e gli eventuali campi indicati)."""
    for e in events:
        if e.get("action") != action:
            continue
        if all(e.get(k) == v for k, v in match.items()):
            return e
    return None


# La pulizia del registro e' in conftest (teardown di 'role_user_ids'): e'
# l'ultimo finalizer a scattare, e anche i teardown delle altre fixture
# scrivono eventi (cancellazione di asset e gruppi di test).


# ------------------------------------------------- redazione dei dati sensibili

def test_secret_values_never_enter_the_ledger():
    """Il registro dice CHE una chiave e' cambiata, mai con quale valore."""
    detail = db._redact({
        "changed": {"ai": {"claude_api_key": {"from": "old", "to": "sk-live-123"}},
                    "smtp": {"password": "hunter2", "host": "smtp.example.org"},
                    "ticketing": {"github_token": "ghp_live", "provider": "github"}},
        "username": "alice",
    })
    dumped = json.dumps(detail)
    assert "sk-live-123" not in dumped
    assert "hunter2" not in dumped
    assert "ghp_live" not in dumped
    assert detail["changed"]["smtp"]["host"] == "smtp.example.org"   # non sensibile
    assert detail["changed"]["ticketing"]["provider"] == "github"
    assert detail["username"] == "alice"


def test_redaction_does_not_swallow_non_secret_flags():
    """
    Il match e' sul nome ESATTO della chiave: 'must_change_password' e'
    un flag, non una credenziale, e oscurarlo toglieva informazione al
    registro senza proteggere niente.
    """
    detail = db._redact({"must_change_password": True, "credentials_rotated": True,
                         "jira_project_key": "OPS", "password": "hunter2"})
    assert detail["must_change_password"] is True
    assert detail["credentials_rotated"] is True
    assert detail["jira_project_key"] == "OPS"
    assert detail["password"] == "[redacted]"


# ----------------------------------------------------------- catena tamper-evident

def test_hash_covers_the_detail_of_the_action():
    """
    Il dettaglio (ruolo prima/dopo, chiavi toccate) entra nell'hash: e'
    esattamente il campo che avrebbe senso ritoccare a posteriori.
    """
    row = {"category": "user", "action": "user.role_change", "outcome": "success",
           "actor_id": 1, "actor_name": "admin", "actor_role": "admin",
           "target_type": "user", "target_id": "7", "target_label": "bob",
           "detail": {"from": "viewer", "to": "admin"},
           "src_ip": "10.0.0.1", "event_ts": "2026-08-13T10:00:00+00:00"}
    original = db._aevent_hash(row, "prev")
    tampered = db._aevent_hash({**row, "detail": {"from": "admin", "to": "admin"}}, "prev")
    assert original != tampered
    assert db._aevent_hash(row, "prev") == original          # deterministico


def test_chain_verifies_after_the_suite_writes_to_it(role_clients):
    """
    Le scritture di QUESTA sessione non rompono la catena.

    Attenzione a cosa si puo' pretendere qui. La suite gira contro
    l'installazione locale, e purge_test_ledger() cancella davvero le righe
    marcate '_ftest_'. Se fra una riga di test e la successiva riga reale c'e'
    stata attivita' vera, la cancellazione lascia un BUCO permanente: la riga
    reale che segue punta a un hash che non esiste piu' e resta 'broken' per
    sempre. E' una rottura autentica — il rilevamento e' corretto — ma
    appartiene alle esecuzioni precedenti, non a questa.

    Quindi si verifica cio' che questo test puo' onestamente affermare: gli
    eventi scritti da ORA in avanti si concatenano correttamente. Per una
    catena senza cicatrici serve un database dedicato ai test (vedi conftest).
    """
    before = db.verify_events_chain()
    assert before is not None, "Supabase non raggiungibile"
    scars = set(before["broken"])

    role_clients["admin"].get("/api/audit/events?page_size=1")
    role_clients["admin"].get("/api/users")          # genera altri eventi reali
    db._head_touch("audit_events", rewind=True)

    after = db.verify_events_chain()
    new_breaks = set(after["broken"]) - scars
    assert not new_breaks, f"la suite ha rotto la catena: {sorted(new_breaks)}"
    assert after["total"] >= before["total"]
    assert after["downgraded"] == [], "righe declassate a non firmate"


# ------------------------------------------------------------------ autenticazione

def test_successful_login_is_recorded(client, role_clients, role_user_ids):
    from fastapi.testclient import TestClient
    import app as app_module

    c = TestClient(app_module.app)
    r = c.post("/api/login", json={"username": USERNAME(role="viewer"),
                                   "password": ROLE_PASSWORD})
    assert r.status_code == 200
    ev = _find(_events(role_clients["admin"], category="auth"),
               "auth.login", actor_name=USERNAME(role="viewer"), outcome="success")
    assert ev is not None, "login riuscito non registrato"
    assert ev["actor_id"] == role_user_ids["viewer"]
    assert ev["actor_role"] == "viewer"


def test_failed_login_is_recorded_with_the_reason(client, role_clients):
    from fastapi.testclient import TestClient
    import app as app_module

    c = TestClient(app_module.app)
    bad = c.post("/api/login", json={"username": USERNAME(role="viewer"),
                                     "password": "wrong-on-purpose"})
    ghost = c.post("/api/login", json={"username": "_ftest_ghost",
                                       "password": "whatever"})
    assert bad.status_code == 401 and ghost.status_code == 401

    events = _events(role_clients["admin"], category="auth", outcome="failure")
    wrong_pw = _find(events, "auth.login", actor_name=USERNAME(role="viewer"))
    unknown = _find(events, "auth.login", actor_name="_ftest_ghost")
    assert wrong_pw is not None and wrong_pw["detail"]["reason"] == "bad_password"
    # La risposta HTTP e' identica nei due casi (no enumeration); il registro
    # invece li distingue, altrimenti un attacco a credenziali e una
    # enumerazione di utenti sarebbero indistinguibili in audit.
    assert unknown is not None and unknown["detail"]["reason"] == "unknown_user"
    # La password tentata non deve MAI comparire, in nessun campo.
    assert "wrong-on-purpose" not in json.dumps(events)


def test_logout_is_recorded(role_clients):
    from fastapi.testclient import TestClient
    import app as app_module

    c = TestClient(app_module.app)
    c.post("/api/login", json={"username": USERNAME(role="auditor"),
                               "password": ROLE_PASSWORD})
    c.get("/logout", follow_redirects=False)
    ev = _find(_events(role_clients["admin"], category="auth"),
               "auth.logout", actor_name=USERNAME(role="auditor"))
    assert ev is not None, "logout non registrato"


# ------------------------------------------------------------------ autorizzazione

def test_denied_request_is_recorded(role_clients):
    """Un 403 e' meta' del valore di un audit: dice chi ha provato a uscire
    dal proprio ruolo."""
    r = role_clients["viewer"].get("/api/users")
    assert r.status_code == 403
    ev = _find(_events(role_clients["admin"], category="authz"),
               "authz.denied", actor_name=USERNAME(role="viewer"))
    assert ev is not None, "403 non registrato"
    assert ev["outcome"] == "denied"
    assert ev["target_id"] == "/api/users"


# --------------------------------------------------------- amministrazione utenti

def test_user_create_and_role_change_are_recorded(role_clients):
    admin = role_clients["admin"]
    r = admin.post("/api/users", json={"username": "_ftest_audited_user",
                                       "password": ROLE_PASSWORD, "role": "viewer"})
    assert r.status_code == 200, r.text
    new_id = r.json()["id"]
    try:
        up = admin.put(f"/api/users/{new_id}", json={"role": "manager"})
        assert up.status_code == 200, up.text

        events = _events(admin, category="user")
        created = _find(events, "user.create", target_id=str(new_id))
        assert created is not None, "creazione utente non registrata"
        assert created["detail"]["role"] == "viewer"
        assert created["actor_name"] == USERNAME(role="admin")

        promoted = _find(events, "user.role_change", target_id=str(new_id))
        assert promoted is not None, "cambio ruolo non registrato"
        # Il prima/dopo e' il punto: "ora e' manager" non e' una prova d'audit.
        assert promoted["detail"]["from"] == "viewer"
        assert promoted["detail"]["to"] == "manager"
    finally:
        admin.delete(f"/api/users/{new_id}")

    deleted = _find(_events(admin, category="user"), "user.delete",
                    target_id=str(new_id))
    assert deleted is not None, "eliminazione utente non registrata"
    # La riga utente non esiste piu': ruolo ed email sopravvivono solo qui.
    assert deleted["detail"]["role"] == "manager"


def test_admin_password_reset_of_another_account_is_recorded(role_clients,
                                                             role_user_ids):
    admin = role_clients["admin"]
    target = role_user_ids["viewer"]
    r = admin.post(f"/api/users/{target}/reset")
    assert r.status_code == 200, r.text
    ev = _find(_events(admin, category="user"), "user.password_reset",
               target_id=str(target))
    assert ev is not None, "reset password amministrativo non registrato"
    assert ev["target_label"] == USERNAME(role="viewer")


# ------------------------------------------------------------- gruppi e assegnazioni

def test_group_membership_change_is_recorded_as_a_delta(role_clients,
                                                        role_user_ids,
                                                        cone_fixture):
    admin = role_clients["admin"]
    gid = cone_fixture["group_out"]
    added = role_user_ids["stakeholder"]
    r = admin.put(f"/api/groups/{gid}/members", json={"user_ids": [added]})
    assert r.status_code == 200, r.text
    try:
        ev = _find(_events(admin, category="group"), "group.members_set",
                   target_id=str(gid))
        assert ev is not None, "cambio membership non registrato"
        assert added in ev["detail"]["added"]
        assert ev["detail"]["to"] == [added]
    finally:
        admin.put(f"/api/groups/{gid}/members", json={"user_ids": []})


def test_asset_assignment_is_recorded_with_before_and_after(role_clients,
                                                            role_user_ids,
                                                            cone_fixture):
    admin = role_clients["admin"]
    asset = cone_fixture["asset_out"]
    uid = role_user_ids["editor"]
    r = admin.put(f"/api/assets/{asset}/assignments",
                  json={"user_ids": [uid], "group_ids": []})
    assert r.status_code == 200, r.text
    try:
        ev = _find(_events(admin, category="assignment"), "assignment.set",
                   target_id=str(asset))
        assert ev is not None, "assegnazione non registrata"
        assert ev["detail"]["from"]["user_ids"] == []
        assert ev["detail"]["to"]["user_ids"] == [uid]
    finally:
        admin.put(f"/api/assets/{asset}/assignments",
                  json={"user_ids": [], "group_ids": []})


# ------------------------------------------------------------------ asset e config

def test_asset_lifecycle_is_recorded(role_clients):
    admin = role_clients["admin"]
    r = admin.post("/api/assets", json={"ip": "10.99.0.77", "os_type": "linux"})
    assert r.status_code == 200, r.text
    aid = r.json()["index"]
    admin.patch(f"/api/assets/{aid}/enabled", json={"enabled": False})
    admin.delete(f"/api/assets/{aid}")

    events = _events(admin, category="asset")
    assert _find(events, "asset.create", target_id=str(aid)) is not None
    toggled = _find(events, "asset.enabled_change", target_id=str(aid))
    assert toggled is not None and toggled["detail"]["enabled"] is False
    removed = _find(events, "asset.delete", target_id=str(aid))
    assert removed is not None and removed["target_label"] == "10.99.0.77"


def test_config_write_is_recorded_with_the_changed_keys(role_clients):
    admin = role_clients["admin"]
    cfg_path = Path(__file__).parent.parent / "config.json"
    before = json.loads(cfg_path.read_text(encoding="utf-8"))
    original = before["osv"]["timeout"]
    try:
        r = admin.post("/api/settings", json={"osv": {"timeout": original + 1}})
        assert r.status_code == 200, r.text
        ev = _find(_events(admin, category="config"), "config.update")
        assert ev is not None, "scrittura di configurazione non registrata"
        assert ev["detail"]["changed"]["osv"]["timeout"] == {
            "from": original, "to": original + 1}
    finally:
        admin.post("/api/settings", json={"osv": {"timeout": original}})
        assert json.loads(cfg_path.read_text(encoding="utf-8")) == before


def test_sbom_export_is_recorded(role_clients):
    """Un export porta dati fuori dall'applicativo: e' un evento d'audit."""
    r = role_clients["auditor"].get("/api/sbom/export?format=cyclonedx")
    assert r.status_code == 200, r.text
    ev = _find(_events(role_clients["admin"], category="export"), "export.sbom")
    assert ev is not None, "export SBOM non registrato"
    assert ev["detail"]["format"] == "cyclonedx"
    assert ev["actor_name"] == USERNAME(role="auditor")


# ------------------------------------------------------------------------- RBAC

@pytest.mark.parametrize("role", ["admin", "manager", "auditor", "editor"])
def test_activity_ledger_is_readable_by_the_audit_roles(role_clients, role):
    assert role_clients[role].get("/api/audit/events").status_code == 200
    assert role_clients[role].get("/api/audit/events/verify").status_code == 200


@pytest.mark.parametrize("role", ["viewer", "stakeholder"])
def test_activity_ledger_is_denied_to_non_audit_roles(role_clients, role):
    """Il registro attribuisce attivita' a persone identificate: e' una classe
    di dati diversa dai conteggi di vulnerabilita'."""
    assert role_clients[role].get("/api/audit/events").status_code == 403
    assert role_clients[role].get("/api/audit/events/verify").status_code == 403


@pytest.mark.parametrize("role", ["manager", "editor", "auditor", "viewer",
                                  "stakeholder"])
def test_anchoring_the_ledger_is_admin_only(role_clients, role):
    """
    L'ancoraggio dichiara "questo era lo stato al momento T" e cambia il
    verdetto di integrita': non e' una lettura, e nemmeno una scrittura
    ordinaria. Nemmeno l'auditor puo' farlo — legge le prove, non le fabbrica.
    """
    assert role_clients[role].post("/api/audit/anchor").status_code == 403


def test_anchoring_is_recorded_with_who_did_it(role_clients, monkeypatch):
    """
    Percorso admin con la scrittura simulata: il test non deve ancorare il
    registro reale dell'installazione, che e' una decisione dell'operatore.
    """
    import app as app_module

    calls = []

    def _fake_anchor(chain, actor=None, note=""):
        calls.append((chain, (actor or {}).get("name")))
        return {"chain": chain, "through_id": 42, "row_count": 7,
                "digest": "d" * 64}

    monkeypatch.setattr(app_module.db, "create_ledger_anchor", _fake_anchor)
    # L'endpoint stabilisce anche la baseline del testimone della coda: qui non
    # deve toccare quella dell'installazione reale.
    monkeypatch.setattr(app_module.db, "_head_touch", lambda chain, **kw: None)
    logged = []
    monkeypatch.setattr(app_module.db, "log_audit_event",
                        lambda action, **kw: logged.append((action, kw)) or True)

    r = role_clients["admin"].post("/api/audit/anchor",
                                   json={"chains": ["scans"], "note": "baseline"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["anchored"] == [{"chain": "scans", "through_id": 42,
                                 "row_count": 7, "digest": "d" * 64}]
    assert calls == [("scans", USERNAME(role="admin"))]
    actions = [a for a, _ in logged]
    assert "audit.anchor" in actions, "ancoraggio non registrato"


def test_anchoring_rejects_unknown_chains(role_clients):
    r = role_clients["admin"].post("/api/audit/anchor",
                                   json={"chains": ["users"]})
    assert r.status_code == 400
    assert "users" in r.text


def test_editor_sees_only_its_own_activity(role_clients):
    """Un ruolo scoped non legge l'attivita' amministrativa altrui."""
    role_clients["admin"].get("/api/me")            # attivita' di un altro attore
    r = role_clients["editor"].get("/api/audit/events?page_size=0")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["scoped"] is True
    others = {e["actor_name"] for e in data["events"]
              if e["actor_name"] != USERNAME(role="editor")}
    assert not others, f"l'editor vede attivita' altrui: {others}"
