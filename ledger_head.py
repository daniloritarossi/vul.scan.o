"""
ledger_head.py
--------------
Testimone della TESTA dei registri, tenuto FUORI dal database.

Le catene hash dimostrano che una riga non e' stata modificata, ma non dicono
nulla su una riga che non c'e' piu'. Cancellando le ultime N righe si ottiene
una catena piu' corta e perfettamente valida: percorrendola in avanti da
prev='' ogni collegamento torna, e la verifica rispondeva 'ok'. Stessa cosa
azzerando le colonne hash della coda: quelle righe diventavano indistinguibili
da righe pre-migrazione ("legacy") e venivano saltate.

Il punto e' che una catena, da sola, non sa quanto dovrebbe essere lunga.
Serve qualcosa che abbia visto lo stato precedente e non stia nello stesso
posto che l'attaccante sta riscrivendo. Qui quel qualcosa e' un file locale
sull'host dell'applicazione: dopo ogni append si annota per ciascuna catena
l'ultimo id, il conteggio righe, l'ultimo row_hash e quante righe erano
firmate. La verifica confronta il database con questo file.

  righe in meno / id piu' basso / hash della testa diverso  -> troncamento
  righe firmate diventate non firmate                       -> declassamento

Limite dichiarato, non nascosto: protegge da chi ha accesso al DATABASE, non
da chi ha accesso all'HOST dell'applicazione — quest'ultimo puo' riscrivere
anche il file. Per la stessa ragione il file non e' firmato: la chiave starebbe
sulla stessa macchina, e sarebbe teatro. L'unica difesa reale contro un host
compromesso e' un testimone esterno (notarizzazione, WORM, replica su un altro
sistema), che questo applicativo non ha e non finge di avere.

Il file descrive QUESTA installazione, non il repository: sta accanto agli
altri segreti runtime ed e' git-ignored.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vfa.ledger_head")

HEAD_FILE = Path(os.environ.get(
    "VFA_LEDGER_HEAD", str(Path(__file__).parent / ".vfa_ledger_head.json")))

# Stato per catena: {last_id, rows, signed, last_hash, updated_at}
_EMPTY: dict = {"chains": {}}


def _read() -> dict:
    try:
        data = json.loads(HEAD_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("chains"), dict):
            return data
    except FileNotFoundError:
        return dict(_EMPTY, chains={})
    except Exception as exc:
        # Un file illeggibile non deve bloccare l'applicazione, ma non deve
        # nemmeno passare per "nessun problema": la verifica lo segnalera'
        # come testimone assente.
        logger.warning("head file illeggibile (%s): %s", HEAD_FILE, exc)
    return dict(_EMPTY, chains={})


def _write(state: dict) -> bool:
    try:
        tmp = HEAD_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        # Sostituzione atomica: un crash a meta' scrittura lascerebbe un
        # testimone troncato, cioe' un falso allarme di troncamento.
        os.replace(tmp, HEAD_FILE)
        return True
    except Exception as exc:
        logger.warning("head file non scrivibile (%s): %s", HEAD_FILE, exc)
        return False


def get(chain: str) -> Optional[dict]:
    """Ultimo stato noto della catena. None se non e' mai stato registrato."""
    return _read()["chains"].get(chain)


def record(chain: str, last_id: Optional[int], rows: int, signed: int,
           last_hash: Optional[str], at: str, rewind: bool = False) -> bool:
    """
    Annota lo stato corrente della catena. Avanza SOLO: un aggiornamento che
    farebbe arretrare il testimone (meno righe, id piu' basso) viene rifiutato,
    altrimenti il primo verify dopo un troncamento cancellerebbe la prova.

    'rewind' esiste per l'UNICA cancellazione legittima prevista dal prodotto:
    purge_test_ledger(), che ripulisce le righe marcate '_ftest_' dopo la suite
    di test. Senza, ogni esecuzione dei test lascerebbe l'installazione con un
    troncamento segnalato — e un allarme che si sa essere falso e' il modo piu'
    rapido per smettere di guardare gli allarmi.
    """
    state = _read()
    prev = state["chains"].get(chain) or {}
    if not rewind and ((prev.get("rows") or 0) > rows
                       or (prev.get("last_id") or 0) > (last_id or 0)):
        logger.warning("head: rifiutato arretramento di '%s' (%s righe -> %s)",
                       chain, prev.get("rows"), rows)
        return False
    state["chains"][chain] = {
        "last_id": last_id, "rows": rows, "signed": signed,
        "last_hash": last_hash, "updated_at": at,
    }
    return _write(state)


def compare(chain: str, last_id: Optional[int], rows: int, signed: int,
            last_hash: Optional[str]) -> dict:
    """
    Confronta lo stato osservato con il testimone.

    {present, ok, reasons:[...], expected:{...}} — 'present' False significa che
    non c'e' testimone (installazione appena aggiornata, o file cancellato): in
    quel caso non si afferma che la coda sia integra, si dichiara che non e'
    verificabile.
    """
    prev = get(chain)
    if not prev:
        return {"present": False, "ok": True, "reasons": [], "expected": None}
    reasons = []
    if rows < (prev.get("rows") or 0):
        reasons.append("truncated")
    if (last_id or 0) < (prev.get("last_id") or 0):
        reasons.append("truncated_tail")
    if signed < (prev.get("signed") or 0):
        # Righe che erano firmate ora non lo sono piu': qualcuno ha tolto gli
        # hash per farle passare da 'pre-migrazione'.
        reasons.append("downgraded")
    if (prev.get("last_hash") and last_hash and rows == (prev.get("rows") or 0)
            and last_id == prev.get("last_id") and last_hash != prev.get("last_hash")):
        reasons.append("head_rewritten")
    return {"present": True, "ok": not reasons, "reasons": sorted(set(reasons)),
            "expected": {k: prev.get(k) for k in
                         ("last_id", "rows", "signed", "updated_at")}}
