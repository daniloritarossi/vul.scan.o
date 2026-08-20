"""
Scheda POSTURE del registro di audit (GET /api/audit/posture).

Il registro mostrava soltanto le query di threat intelligence. Le run di
postura — che reggono i conteggi point-in-time, cioe' i numeri che un audit
contesta per primi — avevano gia' catena hash, sigillo dei totali e endpoint di
verifica, ma nessuna vista sfogliabile: esisteva la prova, non il documento.

Qui si verifica che la vista dica per ogni run chi l'ha lanciata, quali totali
porta e quanto sono dimostrabili, e che il cono di visibilita' non trasformi i
totali sigillati in cifre diverse da quelle firmate.
"""

import pytest

import app as app_module
import db


# ------------------------------------------------------- stato della singola run

def _verdict(broken=(), finals_broken=(), anchor=None):
    return {"broken": list(broken), "finals_broken": list(finals_broken),
            "anchor": anchor or {"present": False}}


def test_a_sealed_run_is_stronger_than_a_verified_one():
    """
    'sealed' significa che anche i TOTALI sono coperti: e' la differenza fra
    "la run e' stata creata da questo attore" e "questi numeri sono quelli".
    """
    run = {"id": 7, "row_hash": "h", "final_hash": "f"}
    assert app_module._posture_run_state(run, _verdict()) == "sealed"
    assert app_module._posture_run_state({"id": 7, "row_hash": "h"},
                                         _verdict()) == "verified"


def test_a_broken_run_is_tampered_whatever_else_it_carries():
    run = {"id": 7, "row_hash": "h", "final_hash": "f"}
    assert app_module._posture_run_state(run, _verdict(broken=[7])) == "tampered"
    assert app_module._posture_run_state(run, _verdict(finals_broken=[7])) == "tampered"


def test_an_unsigned_run_is_anchored_only_within_the_anchor_range():
    """
    L'ancora copre le righe fino a through_id: una run successiva resta
    riscrivibile, e chiamarla 'ancorata' sarebbe una rassicurazione falsa.
    """
    anchor = {"present": True, "digest_ok": True, "self_hash_ok": True,
              "through_id": 52}
    inside = {"id": 40, "row_hash": None}
    outside = {"id": 53, "row_hash": None}
    assert app_module._posture_run_state(inside, _verdict(anchor=anchor)) == "anchored"
    assert app_module._posture_run_state(outside, _verdict(anchor=anchor)) == "unsigned"


def test_a_mismatching_anchor_protects_nothing():
    anchor = {"present": True, "digest_ok": False, "self_hash_ok": True,
              "through_id": 52}
    assert app_module._posture_run_state({"id": 40, "row_hash": None},
                                         _verdict(anchor=anchor)) == "unsigned"


# ------------------------------------------------------------------- endpoint

@pytest.mark.parametrize("role", ["admin", "manager", "auditor", "editor"])
def test_the_audit_roles_can_read_the_posture_history(role_clients, role):
    assert role_clients[role].get("/api/audit/posture").status_code == 200


@pytest.mark.parametrize("role", ["viewer", "stakeholder"])
def test_the_other_roles_cannot(role_clients, role):
    """Stesso confine delle altre schede: il registro attribuisce attivita' a
    persone identificate."""
    assert role_clients[role].get("/api/audit/posture").status_code == 403


def test_every_run_carries_its_integrity_state(role_clients):
    r = role_clients["auditor"].get("/api/audit/posture?page_size=0")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"runs", "total", "kpis", "actors", "integrity", "scoped"}
    valid = {"sealed", "verified", "anchored", "unsigned", "tampered"}
    assert all(run["state"] in valid for run in body["runs"])
    # Il verdetto di catena accompagna l'elenco: numeri e prova insieme, come
    # nel report di evidenza.
    assert body["integrity"]["verdict"] in ("intact", "partial", "tampered", "empty")
    assert "coverage" in body["integrity"]


def test_the_kpis_count_what_is_actually_sealed(role_clients):
    body = role_clients["auditor"].get("/api/audit/posture?page_size=0").json()
    sealed = sum(1 for r in body["runs"] if r["state"] == "sealed")
    assert body["kpis"]["sealed"] == sealed
    assert body["kpis"]["runs"] == body["total"]


def test_filtering_by_integrity_state(role_clients):
    body = role_clients["auditor"].get(
        "/api/audit/posture?page_size=0&state=sealed").json()
    assert all(r["state"] == "sealed" for r in body["runs"])


def test_pagination_returns_a_slice_of_the_same_total(role_clients):
    full = role_clients["auditor"].get("/api/audit/posture?page_size=0").json()
    page = role_clients["auditor"].get("/api/audit/posture?page_size=2").json()
    assert page["total"] == full["total"]
    assert len(page["runs"]) <= 2


# --------------------------------------------------------------- cono editor

def test_an_editor_only_sees_the_assets_of_its_cone(role_clients, cone_fixture):
    """
    L'editor vede le run, ma solo gli asset assegnati a lui. I TOTALI della run
    restano quelli sigillati: ricalcolarli sul sottoinsieme significherebbe
    presentare come 'sigillata' una cifra diversa da quella firmata.
    """
    body = role_clients["editor"].get("/api/audit/posture?page_size=0").json()
    assert body["scoped"] is True
    ips = {a["ip"] for run in body["runs"] for a in (run["posture_assets"] or [])}
    assert ips <= {"10.99.0.1"}, f"asset fuori dal cono: {ips}"
    for run in body["runs"]:
        assert run["assets_scanned"] >= len(run["posture_assets"])


def test_an_auditor_is_not_scoped(role_clients):
    assert role_clients["auditor"].get("/api/audit/posture").json()["scoped"] is False


def test_the_db_query_carries_the_fields_the_page_needs(role_clients):
    """
    fetch_posture_runs (selettore della pagina postura) seleziona cinque
    colonne e basta: se la vista di audit usasse quella, mostrerebbe le run
    senza attore ne' hash.
    """
    runs = db.fetch_posture_history(limit=1)
    if not runs:
        pytest.skip("nessuna run di postura nell'installazione")
    assert {"actor_name", "row_hash", "final_hash", "posture_assets"} <= set(runs[0])
