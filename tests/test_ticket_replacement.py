"""
test_ticket_replacement.py
--------------------------
Secondo ticket sullo stesso finding.

Nasce da un vicolo cieco reale: un ticket chiuso NON chiude la vulnerabilita',
ma finche' il finding restava agganciato a quel ticket non poteva averne un
altro — ne' dalla UI (il pulsante spariva) ne' dall'API (usciva 'already').
Il caso peggiore non e' nemmeno un errore d'uso: un finding risolto davvero,
ticket chiuso come si deve, che mesi dopo rientra in una scansione e viene
riaperto in automatico. E' esattamente quando serve un ticket nuovo, ed era
l'unico momento in cui il prodotto lo negava.

Le proprieta' da proteggere sono tre:

  1. si apre un secondo ticket SOLO quando il primo non puo' piu' portare
     lavoro — mai accanto a uno ancora aperto, che sarebbe lavoro duplicato
     scoperto a valle da un'altra persona;
  2. il riferimento precedente non si perde: sovrascriverlo cancellerebbe il
     fatto che qualcuno aveva deciso di non intervenire, e quel fatto E'
     l'evidenza;
  3. serve una conferma esplicita: la creazione tocca un sistema di terzi e
     non e' annullabile da qui.
"""
import app as app_module
import db
import pytest


def _f(**kw):
    """Finding sintetico: la regola guarda solo questi campi."""
    base = {"status": "open", "ticket_ref": "#7",
            "ticket_url": "https://github.com/o/r/issues/7",
            "ticket_state": "done"}
    base.update(kw)
    return base


# ------------------------------------------------- quando SI puo'

def test_a_closed_ticket_on_an_open_finding_can_be_replaced():
    """Il caso base: il ticket e' chiuso, la vulnerabilita' no."""
    assert app_module.ticket_replacement(_f(ticket_state="done"), "github") == (True, "closed")


def test_a_wont_fix_closure_is_named_as_such():
    """'not_planned' su GitHub e' la decisione di non agire, non una
    remediation: il motivo archiviato deve dirlo, altrimenti a valle sembra
    una vulnerabilita' risolta due volte."""
    assert app_module.ticket_replacement(_f(ticket_state="unknown"), "github") == (True, "wont_fix")


def test_a_ticket_on_a_previous_tracker_can_be_replaced():
    """Su quel riferimento non si puo' piu' ne' leggere ne' lavorare."""
    ok, code = app_module.ticket_replacement(_f(ticket_ref="SEC-1", ticket_state="done"), "github")
    assert (ok, code) == (True, "foreign_provider")


def test_a_foreign_ticket_is_replaceable_even_while_open():
    """Congelato e aperto restano ingiocabili allo stesso modo: il tracker
    non e' piu' interrogabile, quindi 'in corso' e' solo l'ultimo stato letto."""
    ok, _ = app_module.ticket_replacement(
        _f(ticket_ref="SEC-1", ticket_state="in_progress"), "github")
    assert ok is True


def test_a_reopened_finding_can_get_a_new_ticket():
    """La regressione: risolto, ticket chiuso, rientra in scansione."""
    ok, code = app_module.ticket_replacement(
        _f(status="open", ticket_state="done", reopened=2), "github")
    assert (ok, code) == (True, "closed")


# ------------------------------------------------- quando NON si puo'

def test_no_second_ticket_next_to_an_open_one():
    """Due ticket aperti sulla stessa vulnerabilita' sono lavoro duplicato che
    si scopre solo a valle, in mano a un'altra persona."""
    for state in ("todo", "in_progress"):
        ok, code = app_module.ticket_replacement(_f(ticket_state=state), "github")
        assert (ok, code) == (False, "ticket_open"), state


@pytest.mark.parametrize("status", ["fixed", "accepted"])
def test_no_ticket_for_a_finding_with_nothing_left_to_do(status):
    ok, code = app_module.ticket_replacement(_f(status=status), "github")
    assert (ok, code) == (False, "finding_closed")


def test_an_unread_state_is_refused_rather_than_guessed():
    """Senza aver mai riletto il tracker non si sa se quel ticket sia aperto:
    aprirne un altro alla cieca puo' affiancarlo a uno vivo."""
    ok, code = app_module.ticket_replacement(_f(ticket_state=None), "github")
    assert (ok, code) == (False, "state_unknown")
    assert app_module.ticket_replacement(_f(ticket_state=""), "github")[1] == "state_unknown"


# ------------------------------------------------- l'endpoint

def test_without_confirmation_nothing_is_created(role_clients, monkeypatch, findings_fixture):
    """La conferma non e' cerimonia: la creazione apre una issue vera su un
    sistema di terzi e da qui non si annulla."""
    called = []
    monkeypatch.setattr(app_module, "create_ticket",
                        lambda *a, **k: called.append(1) or {"ref": "#9", "url": "u"})
    monkeypatch.setattr(app_module, "fetch_finding",
                        lambda fid: _f(asset_ip="10.99.0.1", id=fid))
    r = role_clients["admin"].post("/api/findings/1/ticket", json={})
    assert r.status_code == 200
    assert r.json()["already"] is True
    assert called == [], "nessun ticket va creato senza conferma"


def test_the_answer_says_whether_another_one_is_possible(role_clients, monkeypatch):
    """La riga deve poterlo dire senza doverlo chiedere."""
    monkeypatch.setattr(app_module, "fetch_finding",
                        lambda fid: _f(asset_ip="10.99.0.1", ticket_state="done"))
    d = role_clients["admin"].post("/api/findings/1/ticket", json={}).json()
    assert d["replaceable"] is True and d["reason"] == "closed"


def test_confirmation_on_a_refused_case_still_creates_nothing(role_clients, monkeypatch):
    """Il client puo' chiedere quel che vuole: se la regola dice no, il
    ticket non si crea. La UI e' un suggerimento, non l'autorita'."""
    called = []
    monkeypatch.setattr(app_module, "create_ticket",
                        lambda *a, **k: called.append(1) or {"ref": "#9", "url": "u"})
    monkeypatch.setattr(app_module, "fetch_finding",
                        lambda fid: _f(asset_ip="10.99.0.1", ticket_state="todo"))
    d = role_clients["admin"].post("/api/findings/1/ticket", json={"replace": True}).json()
    assert d["already"] is True and d["replaceable"] is False
    assert called == []


def test_the_previous_ticket_is_archived_not_overwritten(role_clients, monkeypatch):
    saved = {}
    monkeypatch.setattr(app_module, "create_ticket",
                        lambda *a, **k: {"ref": "#42", "url": "https://x/42"})
    monkeypatch.setattr(app_module, "fetch_finding",
                        lambda fid: _f(asset_ip="10.99.0.1", ticket_state="unknown",
                                       ticket_history=[]))
    monkeypatch.setattr(app_module.db, "replace_finding_ticket",
                        lambda fid, prev, ref, url, reason: saved.update(
                            prev=prev, ref=ref, reason=reason) or True)
    d = role_clients["admin"].post("/api/findings/1/ticket", json={"replace": True}).json()
    assert d["already"] is False and d["ref"] == "#42"
    assert d["replaced"] == "#7"
    assert saved["prev"]["ticket_ref"] == "#7"
    assert saved["reason"] == "wont_fix", "il motivo va archiviato, non dedotto dopo"


def test_a_first_ticket_still_works_untouched(role_clients, monkeypatch):
    """La strada normale non deve essere cambiata da tutto questo."""
    monkeypatch.setattr(app_module, "create_ticket",
                        lambda *a, **k: {"ref": "#1", "url": "https://x/1"})
    monkeypatch.setattr(app_module, "fetch_finding",
                        lambda fid: {"status": "open", "asset_ip": "10.99.0.1"})
    monkeypatch.setattr(app_module, "set_finding_ticket", lambda *a: True)
    d = role_clients["admin"].post("/api/findings/1/ticket", json={}).json()
    assert d["already"] is False and d["ref"] == "#1" and d["replaced"] is None


@pytest.mark.parametrize("role", ["auditor", "viewer", "stakeholder"])
def test_readers_cannot_open_a_second_ticket(role_clients, role):
    r = role_clients[role].post("/api/findings/1/ticket", json={"replace": True})
    assert r.status_code == 403


# ------------------------------------------------- la cronologia

class _FakeTable:
    """Cattura l'UPDATE senza toccare il database."""
    def __init__(self, sink): self.sink = sink
    def update(self, payload): self.sink["payload"] = payload; return self
    def eq(self, *a): return self
    def execute(self): return type("R", (), {"data": [{"id": 1}]})()


def _fake_client(sink):
    return type("C", (), {"table": lambda self, name: _FakeTable(sink)})()


def test_the_history_entry_carries_what_a_reader_needs(monkeypatch):
    """Riferimento, stato al momento della sostituzione, motivo e date: senza
    uno solo di questi la voce non racconta piu' nulla."""
    sink = {}
    monkeypatch.setattr(db, "_get_client", lambda: _fake_client(sink))
    prev = {"ticket_ref": "#2", "ticket_url": "https://x/2", "ticket_status": "closed",
            "ticket_state": "done", "ticket_checked_at": "2026-09-01T00:00:00+00:00",
            "ticket_opened_at": "2026-08-30T00:00:00+00:00", "ticket_history": []}
    assert db.replace_finding_ticket(1, prev, "#5", "https://x/5", "wont_fix")
    entry = sink["payload"]["ticket_history"][-1]
    assert entry["ref"] == "#2" and entry["url"] == "https://x/2"
    assert entry["state"] == "done" and entry["reason"] == "wont_fix"
    assert entry["opened_at"] == "2026-08-30T00:00:00+00:00"
    assert entry["superseded_by"] == "#5" and entry["superseded_at"]


def test_the_chain_is_appended_never_replaced(monkeypatch):
    """Il terzo ticket non deve cancellare il primo: la catena e' la storia."""
    sink = {}
    monkeypatch.setattr(db, "_get_client", lambda: _fake_client(sink))
    prev = {"ticket_ref": "#5", "ticket_url": "u", "ticket_state": "done",
            "ticket_history": [{"ref": "#2", "reason": "closed"}]}
    db.replace_finding_ticket(1, prev, "#6", "u6", "closed")
    hist = sink["payload"]["ticket_history"]
    assert [h["ref"] for h in hist] == ["#2", "#5"]


def test_the_new_ticket_starts_without_the_old_state(monkeypatch):
    """Lo stato riletto apparteneva al ticket vecchio: lasciarlo farebbe
    apparire gia' chiuso un ticket appena aperto."""
    sink = {}
    monkeypatch.setattr(db, "_get_client", lambda: _fake_client(sink))
    db.replace_finding_ticket(1, {"ticket_ref": "#5", "ticket_state": "done",
                                  "ticket_status": "closed", "ticket_history": []},
                              "#6", "u6", "closed")
    p = sink["payload"]
    assert p["ticket_status"] is None and p["ticket_state"] is None
    assert p["ticket_checked_at"] is None
    assert p["ticket_opened_at"], "il ticket nuovo deve avere la sua data di apertura"


def test_a_first_ticket_records_when_it_was_opened(monkeypatch):
    sink = {}
    monkeypatch.setattr(db, "_get_client", lambda: _fake_client(sink))
    assert db.set_finding_ticket(1, "#1", "https://x/1")
    assert sink["payload"]["ticket_opened_at"]
