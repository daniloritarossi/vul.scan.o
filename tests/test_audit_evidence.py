"""
Report di evidenza firmato + catena delle run di postura.

Il report e' il documento che si consegna a un audit esterno: deve contenere i
numeri E la prova che i registri da cui vengono non sono stati toccati, e deve
accorgersi se qualcuno ne ritocca una cifra dopo l'export.

Funzioni pure (evidence.py) e funzioni di hash (db.py): nessun DB.
"""

from datetime import datetime, timezone

import db
import evidence

KEY = b"test-instance-secret"
GEN_AT = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)

STATE_TO = {"as_of": "2026-06-30T23:59:59+00:00", "total": 40, "unresolved": 12,
            "by_status": {"open": 10, "triaged": 2, "accepted": 3, "fixed": 25},
            "by_severity": {"CRITICAL": 1, "HIGH": 4, "MEDIUM": 5, "LOW": 2,
                            "UNKNOWN": 0},
            "proven": 38, "estimated": 2}
STATE_FROM = {"as_of": "2026-03-31T23:59:59+00:00", "total": 33, "unresolved": 19,
              "by_status": {"open": 17, "triaged": 2, "accepted": 1, "fixed": 13},
              "by_severity": {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 6, "LOW": 2,
                              "UNKNOWN": 0},
              "proven": 30, "estimated": 3}
DELTA = {"unresolved_before": 19, "unresolved_after": 12, "resolved": 9,
         "accepted": 2, "vanished": 0, "new": 4, "still_open": 8}
CHAIN_OK = {"total": 5, "verified": 5, "legacy": 0, "broken": [],
            "finals_verified": 5, "finals_pending": 0, "finals_broken": [],
            "ok": True}


def _report(chains=None):
    return evidence.build_report(
        state=STATE_TO, before=STATE_FROM, delta=DELTA,
        chains=chains or {"scans": CHAIN_OK, "finding_events": CHAIN_OK,
                          "posture_runs": CHAIN_OK},
        actor="auditor", scope="all assets", generated_at=GEN_AT)


# ------------------------------------------------------- contenuto del report

def test_report_carries_figures_and_their_integrity_proof():
    r = _report()
    assert r["period"] == {"from": STATE_FROM["as_of"], "to": STATE_TO["as_of"]}
    assert r["counts"]["at_from"]["unresolved"] == 19
    assert r["counts"]["at_to"]["unresolved"] == 12
    assert r["delta"]["resolved"] == 9
    assert r["integrity_ok"] is True
    assert set(r["integrity_checks"]) == {"scans", "finding_events", "posture_runs"}


def test_broken_chain_makes_the_whole_report_not_ok():
    bad = {**CHAIN_OK, "broken": [7], "ok": False}
    r = _report({"scans": bad, "finding_events": CHAIN_OK, "posture_runs": CHAIN_OK})
    assert r["integrity_ok"] is False
    assert r["integrity_checks"]["scans"]["broken"] == [7]


def test_unreachable_db_is_not_reported_as_a_clean_chain():
    """Verifica non eseguita != verifica superata: confonderli falsa il report."""
    r = _report({"scans": None, "finding_events": CHAIN_OK, "posture_runs": CHAIN_OK})
    assert r["integrity_checks"]["scans"]["available"] is False
    assert r["integrity_checks"]["scans"]["ok"] is False
    # Le catene non verificate non contano nel giudizio complessivo...
    assert r["integrity_ok"] is True
    # ...ma restano visibili come "non controllate" nel documento.
    assert r["integrity_checks"]["scans"]["detail"] == "DB unreachable"


def test_report_with_nothing_verifiable_is_not_declared_intact():
    r = _report({"scans": None, "finding_events": None, "posture_runs": None})
    assert r["integrity_ok"] is False


def test_delta_never_leaks_the_fingerprint_list():
    r = evidence.build_report(
        state=STATE_TO, before=STATE_FROM,
        delta={**DELTA, "fingerprints": {"fixed": ["deadbeef"]}},
        chains={"scans": CHAIN_OK}, actor="a", scope="s", generated_at=GEN_AT)
    assert "fingerprints" not in r["delta"]


# ---------------------------------------------------------------------- firma

def test_signature_roundtrip():
    r = evidence.sign(_report(), KEY)
    assert evidence.verify(r, KEY)["ok"] is True


def test_signature_detects_a_single_edited_figure():
    r = evidence.sign(_report(), KEY)
    r["counts"]["at_to"]["unresolved"] = 0
    assert evidence.verify(r, KEY)["ok"] is False


def test_signature_detects_a_forged_integrity_verdict():
    r = evidence.sign(_report(), KEY)
    r["integrity_ok"] = True
    r["integrity_checks"]["scans"]["ok"] = False
    assert evidence.verify(r, KEY)["ok"] is False


def test_report_from_another_instance_is_rejected():
    r = evidence.sign(_report(), KEY)
    assert evidence.verify(r, b"another-instance-secret")["ok"] is False


def test_unsigned_report_is_rejected():
    assert evidence.verify(_report(), KEY)["ok"] is False
    assert evidence.verify({}, KEY)["ok"] is False


def test_signature_is_stable_across_runs_on_identical_data():
    a = evidence.sign(_report(), KEY)["integrity"]["signature"]
    b = evidence.sign(_report(), KEY)["integrity"]["signature"]
    assert a == b


# --------------------------------------------------------------------- output

def test_csv_contains_the_headline_numbers():
    out = evidence.to_csv(evidence.sign(_report(), KEY))
    assert "section,key,value" in out.splitlines()[0]
    assert "delta,resolved,9" in out
    assert "counts_at_from,unresolved,19" in out
    assert "counts_at_to,unresolved,12" in out
    assert "integrity,signature," in out


def test_html_is_printable_and_states_the_verdict():
    out = evidence.to_html(evidence.sign(_report(), KEY))
    assert out.startswith("<!doctype html>")
    assert "@media print" in out
    assert "Audit evidence report" in out
    assert "all chains intact" in out


def test_html_escapes_report_values():
    r = evidence.build_report(state=STATE_TO, before=None, delta=None,
                              chains={"scans": CHAIN_OK},
                              actor="<script>alert(1)</script>", scope="s",
                              generated_at=GEN_AT)
    out = evidence.to_html(evidence.sign(r, KEY))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


# ---------------------------------------------- catena hash delle run postura

def test_posture_seal_covers_the_run_totals():
    totals = {"assets_scanned": 3, "total_packages": 900, "total_vulnerable": 12,
              "total_vulns": 40, "avg_score": 71,
              "final_ts": "2026-08-07T12:00:00+00:00"}
    sealed = db._posture_final_hash(totals, "rowhash")
    assert sealed != db._posture_final_hash({**totals, "total_vulns": 0}, "rowhash")
    assert sealed != db._posture_final_hash({**totals, "assets_scanned": 99}, "rowhash")
    assert sealed != db._posture_final_hash(totals, "other-rowhash")


def test_posture_run_hash_links_to_the_previous_run():
    row = {"actor_id": 4, "hash_ts": "2026-08-07T12:00:00+00:00"}
    first = db._posture_hash(row, "")
    assert first != db._posture_hash(row, first)          # la linkatura conta
    assert first != db._posture_hash({**row, "actor_id": 9}, "")
