"""
Verdetto di integrita': copertura reale, non "nessun controllo fallito".

Su un'installazione reale /api/audit/verify rispondeva
{"total":106,"verified":2,"legacy":104,"ok":true}: la catena copriva il 2%
delle righe e la risposta diceva "ok". Le altre 104 erano riscrivibili senza
lasciare traccia, e le run di postura — che reggono i conteggi point-in-time —
erano non firmate al 100%.

Qui si verifica che 'ok' significhi ora cio' che un lettore assume che
significhi, che copertura parziale e manomissione restino due esiti distinti, e
che l'ancoraggio protegga davvero le righe non firmate.

Logica pura: nessun DB, nessuna rete.
"""

import pytest

import db
import evidence


@pytest.fixture(autouse=True)
def no_db(monkeypatch):
    """
    _chain_verdict consulta le ancore: qui non c'e' DB, quindi nessuna.

    Il testimone della coda e' invece dato per presente e concorde: qui si
    misura la COPERTURA, e senza testimone ogni verdetto sarebbe 'partial' per
    un motivo diverso. Il testimone ha i suoi test in test_chain_truncation.py.
    """
    monkeypatch.setattr(db, "_get_client", lambda: object())
    monkeypatch.setattr(db, "_anchor_status", lambda c, ch: {"present": False})
    monkeypatch.setattr(db, "_head_state", lambda c, ch, rows: {
        "present": True, "ok": True, "reasons": [], "expected": {}})


def _verdict(total, verified, broken=(), unsigned=0, extra=None):
    return db._chain_verdict("scans", total, verified, list(broken), unsigned,
                             extra or {})


# --------------------------------------------------------------- il verdetto

def test_partial_coverage_is_not_ok():
    """Il caso della segnalazione: 2 righe verificate su 106."""
    r = _verdict(total=106, verified=2, unsigned=104)
    assert r["verdict"] == "partial"
    assert r["ok"] is False
    assert r["unprotected"] == 104
    assert r["coverage"] == pytest.approx(0.0189, abs=1e-4)
    # Nessuna manomissione rilevata: e' un limite di copertura, non un incidente.
    assert r["tamper_free"] is True


def test_full_coverage_is_intact():
    r = _verdict(total=58, verified=58)
    assert r["verdict"] == "intact"
    assert r["ok"] is True
    assert r["coverage"] == 1.0


def test_a_broken_row_is_tampered_not_partial():
    r = _verdict(total=10, verified=9, broken=[7])
    assert r["verdict"] == "tampered"
    assert r["ok"] is False
    assert r["tamper_free"] is False


def test_an_empty_ledger_is_not_a_lie():
    r = _verdict(total=0, verified=0)
    assert r["verdict"] == "empty"
    assert r["ok"] is True
    assert r["coverage"] is None


def test_unsealed_final_values_keep_the_verdict_partial():
    """
    Una scansione senza sigillo ha version e conteggio CVE ancora alterabili:
    la catena e' integra, la cifra no.
    """
    r = _verdict(total=4, verified=4, extra={"finals_verified": 2,
                                             "finals_pending": 2,
                                             "finals_broken": []})
    assert r["verdict"] == "partial"
    assert r["ok"] is False


def test_a_broken_seal_is_tampering():
    r = _verdict(total=4, verified=4, extra={"finals_verified": 3,
                                             "finals_pending": 0,
                                             "finals_broken": [2]})
    assert r["verdict"] == "tampered"
    assert r["tamper_free"] is False


# ------------------------------------------------------------- l'ancoraggio

def test_a_valid_anchor_covers_the_unsigned_rows(monkeypatch):
    monkeypatch.setattr(db, "_get_client", lambda: object())
    monkeypatch.setattr(db, "_anchor_status", lambda c, ch: {
        "present": True, "at": "2026-08-14T00:00:00+00:00", "through_id": 104,
        "row_count": 104, "digest_ok": True, "self_hash_ok": True, "actor": "admin"})
    r = _verdict(total=106, verified=2, unsigned=104)
    assert r["anchored"] == 104
    assert r["unprotected"] == 0
    assert r["coverage"] == 1.0
    assert r["verdict"] == "intact"


def test_changing_an_anchored_row_is_detected(monkeypatch):
    """
    E' il punto dell'ancoraggio: le righe non si possono firmare a posteriori,
    ma da quando sono ancorate ogni modifica salta fuori.
    """
    monkeypatch.setattr(db, "_get_client", lambda: object())
    monkeypatch.setattr(db, "_anchor_status", lambda c, ch: {
        "present": True, "at": "2026-08-14T00:00:00+00:00", "through_id": 104,
        "row_count": 104, "digest_ok": False, "self_hash_ok": True})
    r = _verdict(total=106, verified=2, unsigned=104)
    assert r["verdict"] == "tampered"
    assert r["tamper_free"] is False
    assert r["anchored"] == 0          # un'ancora che non torna non protegge nulla


def test_a_replaced_anchor_is_detected(monkeypatch):
    """L'ancora stessa e' firmata: sostituirla non ripristina il verde."""
    monkeypatch.setattr(db, "_get_client", lambda: object())
    monkeypatch.setattr(db, "_anchor_status", lambda c, ch: {
        "present": True, "at": "x", "through_id": 104, "row_count": 104,
        "digest_ok": True, "self_hash_ok": False})
    assert _verdict(total=106, verified=2, unsigned=104)["verdict"] == "tampered"


def test_the_digest_notices_any_edit_to_the_covered_rows():
    rows = [{"id": 1, "description": "apache", "product": "apache",
             "version": "2.4", "source": "local", "created_at": "t",
             "actor_id": None, "actor_name": None, "cve_count": 3,
             "cve_ids": ["CVE-1", "CVE-2"]}]
    base = db._anchor_digest("scans", rows)
    assert db._anchor_digest("scans", rows) == base          # deterministico
    edited = [{**rows[0], "cve_count": 0}]
    assert db._anchor_digest("scans", edited) != base
    # L'ordine degli id non deve cambiare il digest, il contenuto si'.
    two = rows + [{**rows[0], "id": 2, "description": "nginx"}]
    assert db._anchor_digest("scans", two) == db._anchor_digest("scans", two[::-1])


# ------------------------------------------------------ il report di evidenza

CHAIN_PARTIAL = {"total": 106, "verified": 2, "broken": [], "unsigned": 104,
                 "anchored": 0, "unprotected": 104, "coverage": 0.0189,
                 "verdict": "partial", "ok": False, "tamper_free": True,
                 "anchor": {"present": False}}
CHAIN_INTACT = {"total": 58, "verified": 58, "broken": [], "unsigned": 0,
                "anchored": 0, "unprotected": 0, "coverage": 1.0,
                "verdict": "intact", "ok": True, "tamper_free": True,
                "anchor": {"present": False}}


def _report(chains):
    return evidence.build_report(
        state={"as_of": "2026-06-30T23:59:59+00:00", "total": 10,
               "unresolved": 3, "by_status": {}, "by_severity": {}},
        before=None, delta=None, chains=chains, actor="auditor", scope="all")


def test_a_report_never_claims_integrity_on_partial_coverage():
    r = _report({"scans": CHAIN_PARTIAL, "finding_events": CHAIN_INTACT})
    assert r["integrity_ok"] is False
    assert r["integrity_verdict"] == "partial"
    # La cifra su cui si regge il verdetto e' nel documento, non solo a schermo.
    assert r["coverage"]["scans"] == 0.0189
    assert r["integrity_checks"]["scans"]["unprotected"] == 104


def test_a_report_separates_partial_from_tampered():
    broken = {**CHAIN_INTACT, "verdict": "tampered", "ok": False,
              "tamper_free": False, "broken": [3]}
    assert _report({"a": broken})["integrity_verdict"] == "tampered"
    assert _report({"a": CHAIN_INTACT})["integrity_verdict"] == "intact"


def test_the_printable_report_states_the_coverage():
    html = evidence.to_html(_report({"scans": CHAIN_PARTIAL}))
    assert "PARTIAL COVERAGE" in html
    assert "1.9%" in html
    assert "cannot be proven intact" in html
    assert "all chains intact" not in html


def test_the_csv_carries_coverage_and_unprotected_rows():
    rows = dict(((sec, key), val) for sec, key, val in
                evidence._rows(_report({"scans": CHAIN_PARTIAL})))
    assert rows[("integrity_checks", "scans_coverage")] == 0.0189
    assert rows[("integrity_checks", "scans_unprotected")] == 104
    assert rows[("integrity", "overall_verdict")] == "partial"
