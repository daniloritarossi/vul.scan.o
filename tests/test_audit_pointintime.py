"""
Evidenza point-in-time per audit esterno.

Verifica cio' che un auditor chiede di dimostrare: a una certa data avevo N
vulnerabilita' aperte, a una data successiva ne ho risolte K, e i numeri non
sono alterabili a posteriori senza rompere una catena hash.

Tutte funzioni pure (findings.py) e funzioni di hash (db.py): nessun DB.
"""

from datetime import datetime, timezone

import db
from findings import (compare_states, lifecycle_events, parse_as_of,
                      reconstruct_as_of)

T_JAN = datetime(2026, 1, 1, tzinfo=timezone.utc)
T_MAR = datetime(2026, 3, 1, tzinfo=timezone.utc)
T_JUN = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _ev(fp, event, to_status, ts, from_status=None, sev="HIGH", ip="10.0.0.1"):
    return {"fingerprint": fp, "event": event, "from_status": from_status,
            "to_status": to_status, "severity": sev, "asset_ip": ip,
            "event_ts": ts}


def _finding(fp, status, first_seen, changed, sev="HIGH", ip="10.0.0.1"):
    return {"fingerprint": fp, "status": status, "severity": sev, "asset_ip": ip,
            "title": fp, "first_seen": first_seen, "status_changed_at": changed}


# --------------------------------------------------------------- eventi

def test_lifecycle_events_marks_creation_and_reopen_only():
    existing = {
        "known": {"id": 2, "status": "open"},
        "closed": {"id": 3, "status": "fixed"},
    }
    rows = [
        {"fingerprint": "brand-new", "status": "open", "severity": "HIGH"},
        {"fingerprint": "known", "status": "open", "severity": "HIGH"},
        {"fingerprint": "closed", "status": "open", "severity": "LOW"},
    ]
    events = {e["fingerprint"]: e for e in lifecycle_events(rows, existing)}
    assert set(events) == {"brand-new", "closed"}     # la riosservazione non emette
    assert events["brand-new"]["event"] == "created"
    assert events["brand-new"]["from_status"] is None
    assert events["closed"]["event"] == "reopened"
    assert events["closed"]["from_status"] == "fixed"


def test_lifecycle_events_records_actor():
    rows = [{"fingerprint": "x", "status": "open", "severity": "LOW"}]
    ev = lifecycle_events(rows, {}, {"id": 7, "name": "nilo"})[0]
    assert ev["actor"] == {"id": 7, "name": "nilo"}


# ------------------------------------------------- ricostruzione a una data

def test_bare_date_means_end_of_day():
    assert parse_as_of("2026-03-31").isoformat() == "2026-03-31T23:59:59+00:00"


def test_state_replays_events_up_to_the_date():
    events = [
        _ev("a", "created", "open", "2026-01-05T10:00:00+00:00"),
        _ev("b", "created", "open", "2026-01-05T10:00:00+00:00", sev="CRITICAL"),
        _ev("a", "status_change", "fixed", "2026-04-10T09:00:00+00:00",
            from_status="open"),
    ]
    current = [_finding("a", "fixed", "2026-01-05T10:00:00+00:00",
                        "2026-04-10T09:00:00+00:00"),
               _finding("b", "open", "2026-01-05T10:00:00+00:00",
                        "2026-01-05T10:00:00+00:00", sev="CRITICAL")]

    march = reconstruct_as_of(events, current, T_MAR)
    assert march["unresolved"] == 2                 # 'a' era ancora aperta a marzo
    assert march["by_status"]["fixed"] == 0

    june = reconstruct_as_of(events, current, T_JUN)
    assert june["unresolved"] == 1
    assert june["by_status"]["fixed"] == 1


def test_finding_not_yet_born_is_absent():
    events = [_ev("late", "created", "open", "2026-05-01T08:00:00+00:00")]
    current = [_finding("late", "open", "2026-05-01T08:00:00+00:00",
                        "2026-05-01T08:00:00+00:00")]
    assert reconstruct_as_of(events, current, T_MAR)["total"] == 0
    assert reconstruct_as_of(events, current, T_JUN)["total"] == 1


def test_legacy_findings_are_estimated_not_proven():
    """Senza eventi lo stato e' dedotto: va contato a parte, non spacciato per prova."""
    current = [_finding("old", "fixed", "2025-11-01T00:00:00+00:00",
                        "2026-02-01T00:00:00+00:00")]
    state = reconstruct_as_of([], current, T_JUN)
    assert state["proven"] == 0
    assert state["estimated"] == 1
    assert state["findings"][0]["basis"] == "estimated"
    # Prima della transizione registrata il finding risulta aperto.
    assert reconstruct_as_of([], current, T_JAN)["unresolved"] == 1


# ------------------------------------------------------------------ delta

def test_delta_answers_the_audit_question():
    events = [
        _ev("a", "created", "open", "2026-01-05T10:00:00+00:00"),
        _ev("b", "created", "open", "2026-01-05T10:00:00+00:00"),
        _ev("a", "auto_fixed", "fixed", "2026-04-10T09:00:00+00:00",
            from_status="open"),
        _ev("c", "created", "open", "2026-05-01T08:00:00+00:00"),
    ]
    current = [
        _finding("a", "fixed", "2026-01-05T10:00:00+00:00", "2026-04-10T09:00:00+00:00"),
        _finding("b", "open", "2026-01-05T10:00:00+00:00", "2026-01-05T10:00:00+00:00"),
        _finding("c", "open", "2026-05-01T08:00:00+00:00", "2026-05-01T08:00:00+00:00"),
    ]
    delta = compare_states(reconstruct_as_of(events, current, T_MAR),
                           reconstruct_as_of(events, current, T_JUN))
    assert delta["unresolved_before"] == 2
    assert delta["resolved"] == 1
    assert delta["new"] == 1
    assert delta["still_open"] == 1
    assert delta["fingerprints"]["fixed"] == ["a"]


def test_accepted_is_not_counted_as_resolved():
    events = [
        _ev("a", "created", "open", "2026-01-05T10:00:00+00:00"),
        _ev("a", "status_change", "accepted", "2026-04-10T09:00:00+00:00",
            from_status="open"),
    ]
    current = [_finding("a", "accepted", "2026-01-05T10:00:00+00:00",
                        "2026-04-10T09:00:00+00:00")]
    delta = compare_states(reconstruct_as_of(events, current, T_MAR),
                           reconstruct_as_of(events, current, T_JUN))
    assert delta["resolved"] == 0
    assert delta["accepted"] == 1


# --------------------------------------------------------- catene hash

def test_final_hash_seals_the_cve_count():
    row = {"version": "1.2.3", "cve_count": 7,
           "cve_ids": ["CVE-2026-2", "CVE-2026-1"],
           "final_ts": "2026-08-07T10:00:00+00:00"}
    sealed = db._scan_final_hash(row, "rowhash")
    assert sealed != db._scan_final_hash({**row, "cve_count": 0}, "rowhash")
    assert sealed != db._scan_final_hash(row, "altered-rowhash")
    # L'ordine degli id non e' semantico: non deve produrre falsi allarmi.
    assert sealed == db._scan_final_hash(
        {**row, "cve_ids": ["CVE-2026-1", "CVE-2026-2"]}, "rowhash")


def test_event_hash_detects_rewritten_transition_and_broken_link():
    ev = {"fingerprint": "f1", "event": "status_change", "from_status": "open",
          "to_status": "fixed", "severity": "HIGH", "actor_id": 3,
          "event_ts": "2026-08-07T10:00:00+00:00"}
    h = db._fevent_hash(ev, "")
    assert h != db._fevent_hash({**ev, "to_status": "open"}, "")
    assert h != db._fevent_hash({**ev, "actor_id": 9}, "")
    assert h != db._fevent_hash(ev, "different-prev")
