"""
test_findings_export.py
-----------------------
Contesto di audit dell'export findings (POST /api/findings/export).

Il foglio dei dati lo costruisce il browser; il server aggiunge cio' che il
browser non puo' sapere e senza cui il file non prova nulla. Le proprieta' da
proteggere sono tre:

  1. il conteggio "nel cono" e' calcolato lato server, non accettato dal
     client: e' la sola cifra che dice quanto e' stato ESCLUSO;
  2. ogni ruolo autenticato puo' esportare — un auditor che non potesse
     estrarre l'evidenza sarebbe un controsenso — ma dentro il proprio cono;
  3. l'export lascia traccia: chi, quanto, con quali filtri.
"""
import app as app_module
import db


def _ctx(client, **body):
    r = client.post("/api/findings/export", json=body)
    assert r.status_code == 200, r.text
    return r.json()["context"]


def test_every_authenticated_role_can_export(role_clients):
    """Anche i soli lettori: l'evidenza serve soprattutto a loro."""
    for role in ("admin", "manager", "editor", "auditor", "viewer", "stakeholder"):
        r = role_clients[role].post("/api/findings/export", json={"rows": 0})
        assert r.status_code == 200, f"{role} deve poter esportare ({r.text[:80]})"


def test_anonymous_cannot_export(anon_client):
    r = anon_client.post("/api/findings/export", json={"rows": 0})
    assert r.status_code in (401, 403)


def test_scope_is_reported_and_not_taken_from_the_client(role_clients, cone_fixture):
    """Un ruolo scoped riceve il proprio cono, non l'inventario."""
    admin = _ctx(role_clients["admin"], rows=0)
    editor = _ctx(role_clients["editor"], rows=0)
    assert admin["scope"]["kind"] == "all"
    assert editor["scope"]["kind"] == "cone"
    assert isinstance(editor["scope"]["assets"], int)
    # "in scope" e' ricalcolato dal server: l'editor non puo' vedere piu'
    # righe dell'admin.
    assert editor["rows_in_scope"] <= admin["rows_in_scope"]


def test_rows_exported_is_echoed_but_in_scope_is_computed(role_clients):
    """Il client dichiara quante righe ha scritto; quante ne ESISTONO lo
    stabilisce il server, altrimenti il rapporto fra le due non direbbe nulla."""
    ctx = _ctx(role_clients["admin"], rows=999999)
    assert ctx["rows_exported"] == 999999
    assert ctx["rows_in_scope"] != 999999


def test_context_carries_what_makes_the_file_evidence(role_clients):
    ctx = _ctx(role_clients["admin"], rows=3, filters={"severity": "CRITICAL"})
    assert ctx["exported_by"] and ctx["exported_by_role"] == "admin"
    assert ctx["exported_at"].endswith("+00:00")      # UTC esplicito
    assert ctx["app_version"]
    assert ctx["filters"] == {"severity": "CRITICAL"}
    # I quattro registri sono nominati sempre, anche quando il verdetto e'
    # "non verificabile": tacerne uno lo farebbe sembrare inesistente.
    assert set(ctx["integrity"]) == {
        "scan_ledger", "finding_events", "posture_runs", "activity_ledger"}
    for verdict in ctx["integrity"].values():
        assert "ok" in verdict


def test_unverifiable_ledger_is_said_not_hidden(role_clients, monkeypatch):
    """DB muto non significa 'catena intatta'."""
    monkeypatch.setattr(db, "verify_audit_chain", lambda: None)
    ctx = _ctx(role_clients["admin"], rows=0)
    assert ctx["integrity"]["scan_ledger"]["ok"] is None
    assert ctx["integrity"]["scan_ledger"]["note"] == "not verifiable"


def test_a_broken_verifier_does_not_break_the_export(role_clients, monkeypatch):
    """Il contesto e' best-effort: se un verificatore esplode, l'export deve
    comunque uscire dicendo che quel registro non e' verificabile."""
    def _boom():
        raise RuntimeError("supabase down")
    monkeypatch.setattr(db, "verify_posture_chain", _boom)
    ctx = _ctx(role_clients["admin"], rows=0)
    assert ctx["integrity"]["posture_runs"]["ok"] is None


def test_export_is_recorded_in_the_activity_ledger(role_clients, monkeypatch):
    """Chi ha portato fuori quali dati e' esattamente cio' che un audit chiede
    a valle: l'export e' esso stesso un evento."""
    seen = []
    real = app_module._audit

    def _spy(action, *a, **kw):
        seen.append((action, kw.get("detail") or {}))
        return real(action, *a, **kw)

    monkeypatch.setattr(app_module, "_audit", _spy)
    role_clients["admin"].post("/api/findings/export",
                               json={"rows": 7, "filters": {"ticket": "done"}})
    exports = [d for a, d in seen if a == "finding.export"]
    assert exports, "l'export deve lasciare traccia"
    assert exports[0]["rows_exported"] == 7
    assert exports[0]["filters"] == {"ticket": "done"}


def test_empty_filters_are_not_recorded_as_noise(role_clients, monkeypatch):
    seen = []
    real = app_module._audit
    monkeypatch.setattr(app_module, "_audit",
                        lambda action, *a, **kw: (seen.append((action, kw.get("detail") or {})),
                                                  real(action, *a, **kw))[1])
    role_clients["admin"].post("/api/findings/export",
                               json={"rows": 1, "filters": {"severity": "", "ticket": "any"}})
    detail = [d for a, d in seen if a == "finding.export"][0]
    assert detail["filters"] == {"ticket": "any"}


def test_malformed_body_does_not_500(role_clients):
    r = role_clients["admin"].post("/api/findings/export",
                                   content=b"not json",
                                   headers={"Content-Type": "application/json"})
    assert r.status_code == 200
