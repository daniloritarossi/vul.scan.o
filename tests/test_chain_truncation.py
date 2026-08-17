"""
Troncamento della coda e declassamento a "legacy".

Due attacchi che l'algoritmo di verifica non vedeva, entrambi riprodotti qui
come li descriveva il report:

  265  cancella le ultime righe -> catena piu' corta, tutti i link tornano,
       {'verified':3,'broken':[],'ok':True}. Una catena non sa quanto dovrebbe
       essere lunga.
  266  azzera row_hash/prev_hash di una riga e riscrivila -> diventa
       indistinguibile da una riga pre-migrazione e viene saltata,
       {'verified':3,'legacy':1,'ok':True}.

Le due difese sono complementari: una riga non firmata che segue una firmata e'
un'anomalia rilevabile guardando solo il database, mentre per la coda serve un
testimone che stia FUORI dal database, perche' chi cancella le righe cancella
anche qualsiasi contatore tenuto accanto a loro.

Nessun DB, nessuna rete: le righe sono costruite in memoria.
"""

import pytest

import db
import ledger_head


@pytest.fixture(autouse=True)
def isolated_head(tmp_path, monkeypatch):
    """Testimone su file temporaneo: i test non toccano quello reale."""
    monkeypatch.setattr(ledger_head, "HEAD_FILE", tmp_path / "head.json")
    monkeypatch.setattr(db, "_get_client", lambda: object())
    monkeypatch.setattr(db, "_anchor_status", lambda c, ch: {"present": False})
    yield


def _chain(n=4, start=1):
    """n righe firmate e concatenate, come le scrive persist_scan."""
    rows, prev = [], ""
    for i in range(start, start + n):
        r = {"id": i, "description": f"pkg-{i}", "product": f"pkg-{i}",
             "source": "local", "actor_id": 1,
             "hash_ts": f"2026-08-14T10:0{i}:00+00:00"}
        r["prev_hash"] = prev
        r["row_hash"] = db._scan_hash(r, prev)
        prev = r["row_hash"]
        rows.append(r)
    return rows


def _walk(rows):
    """Percorre la catena come verify_audit_chain, poi compone il verdetto."""
    broken, verified, unsigned, prev = [], 0, 0, ""
    for r in rows:
        if not r.get("row_hash"):
            unsigned += 1
            continue
        expect = db._scan_hash(r, r.get("prev_hash") or "")
        if r["row_hash"] == expect and (r.get("prev_hash") or "") == prev:
            verified += 1
        else:
            broken.append(r["id"])
        prev = r["row_hash"]
    return db._chain_verdict("scans", len(rows), verified, broken, unsigned,
                             rows=rows)


def _witness(rows):
    """Registra lo stato corrente come farebbe un append."""
    signed = sum(1 for r in rows if r.get("row_hash"))
    last = rows[-1] if rows else {}
    ledger_head.record("scans", last.get("id"), len(rows), signed,
                       last.get("row_hash"), "2026-08-14T10:10:00+00:00")


# ------------------------------------------------------------------ baseline

def test_an_untouched_chain_with_a_witness_is_intact():
    rows = _chain()
    _witness(rows)
    v = _walk(rows)
    assert v["verdict"] == "intact"
    assert v["ok"] is True


def test_without_a_witness_the_tail_is_not_verifiable():
    """
    Nessun testimone: la catena e' integra per quanto se ne sa, ma cancellare
    le ultime righe non sarebbe rilevabile. Non e' 'intact'.
    """
    v = _walk(_chain())
    assert v["verdict"] == "partial"
    assert v["ok"] is False
    assert v["head"]["present"] is False


# --------------------------------------------------- 265 · troncamento coda

def test_deleting_the_last_entry_is_detected():
    rows = _chain()
    _witness(rows)
    v = _walk(rows[:-1])                      # l'attacco: via l'ultima riga
    assert v["verdict"] == "tampered"
    assert v["ok"] is False
    assert v["tamper_free"] is False
    assert "truncated" in v["tamper_reasons"]
    # Il documento deve poter dire cosa ci si aspettava di trovare.
    assert v["head"]["expected"]["rows"] == 4


def test_deleting_several_entries_is_detected():
    rows = _chain(6)
    _witness(rows)
    assert _walk(rows[:2])["verdict"] == "tampered"


def test_the_witness_never_moves_backwards():
    """
    Il primo verify dopo un troncamento non deve riscrivere il testimone con
    lo stato ridotto: cancellerebbe la prova dell'attacco.
    """
    rows = _chain()
    _witness(rows)
    _witness(rows[:-1])                        # tentativo di arretramento
    assert ledger_head.get("scans")["rows"] == 4
    assert _walk(rows[:-1])["verdict"] == "tampered"


def test_appending_after_the_witness_is_normal_operation():
    rows = _chain()
    _witness(rows)
    grown = rows + _chain(1, start=5)
    v = _walk(grown)
    assert "truncated" not in v["tamper_reasons"]


# ------------------------------------------------ 266 · declassamento legacy

def test_stripping_the_hash_of_the_last_row_is_tampering_not_legacy():
    """
    L'attacco del report: riscrivi la riga piu' recente e azzerane gli hash.
    Prima passava per riga pre-migrazione e la verifica rispondeva ok:true.
    """
    rows = _chain()
    _witness(rows)
    attacked = [dict(r) for r in rows]
    attacked[-1].update({"description": "REWRITTEN", "row_hash": None,
                         "prev_hash": None})
    v = _walk(attacked)
    assert v["verdict"] == "tampered"
    assert "downgraded_rows" in v["tamper_reasons"]
    assert v["downgraded"] == [4]


def test_stripping_every_hash_is_tampering():
    """Seconda variante: azzerare tutti gli hash e riscrivere ogni riga."""
    rows = _chain()
    _witness(rows)
    attacked = [{**r, "row_hash": None, "prev_hash": None,
                 "description": "REWRITTEN"} for r in rows]
    v = _walk(attacked)
    assert v["verdict"] == "tampered"
    assert "downgraded" in v["tamper_reasons"]      # il testimone se ne accorge


def test_an_unsigned_row_after_a_signed_one_is_caught_without_any_witness():
    """
    Difesa che non dipende dal testimone: le righe non firmate sono quelle
    scritte prima che la catena esistesse e stanno tutte all'inizio. Una non
    firmata DOPO una firmata e' una riga a cui e' stato tolto l'hash.
    """
    rows = _chain()
    attacked = [dict(r) for r in rows]
    attacked[-1].update({"row_hash": None, "prev_hash": None})
    v = _walk(attacked)                              # nessun _witness()
    assert v["verdict"] == "tampered"
    assert v["downgraded"] == [4]


def test_genuine_pre_migration_rows_are_not_tampering():
    """
    Le righe davvero antecedenti alla catena stanno in testa: restano
    'unprotected' (copertura parziale), non manomissione.
    """
    rows = [{"id": 1, "description": "old", "row_hash": None, "prev_hash": None},
            {"id": 2, "description": "old", "row_hash": None, "prev_hash": None}]
    rows += _chain(2, start=3)
    # La catena firmata riparte da prev='' come nell'installazione reale.
    v = _walk(rows)
    assert v["downgraded"] == []
    assert v["verdict"] == "partial"
    assert v["unprotected"] == 2


# ------------------------------------------------------- il testimone stesso

def test_rewriting_the_last_row_in_place_is_detected_by_the_head_hash():
    rows = _chain()
    _witness(rows)
    attacked = [dict(r) for r in rows]
    # Riscrittura completa dell'ultima riga, hash incluso e ricalcolato: la
    # catena torna, ma non e' la riga che il testimone aveva visto.
    attacked[-1]["description"] = "REWRITTEN"
    attacked[-1]["row_hash"] = db._scan_hash(attacked[-1],
                                             attacked[-1]["prev_hash"])
    v = _walk(attacked)
    assert v["verdict"] == "tampered"
    assert "head_rewritten" in v["tamper_reasons"]


def test_a_missing_witness_file_is_reported_not_assumed_good(tmp_path,
                                                             monkeypatch):
    monkeypatch.setattr(ledger_head, "HEAD_FILE", tmp_path / "gone.json")
    assert ledger_head.compare("scans", 4, 4, 4, "x") == {
        "present": False, "ok": True, "reasons": [], "expected": None}


def test_the_witness_survives_a_write_failure(tmp_path, monkeypatch):
    """Un file non scrivibile non deve far fallire l'append."""
    monkeypatch.setattr(ledger_head, "HEAD_FILE", tmp_path / "sub" / "head.json")
    assert ledger_head.record("scans", 1, 1, 1, "h", "t") is False
