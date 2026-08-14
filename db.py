"""
db.py
-----
Persistenza dei risultati di scansione su Supabase locale (PostgREST).

Usa il client ufficiale supabase-py, che parla con il gateway in stile Supabase
esposto in ./supabase (http://localhost:8001/rest/v1).

Filosofia "best-effort": come il resto dell'app, se Supabase non e' raggiungibile
la scansione NON si interrompe. Gli errori di persistenza vengono loggati e
ignorati, cosi' l'app resta usabile anche senza DB.

Variabili d'ambiente (con default per il locale):
    SUPABASE_URL          default http://localhost:8001
    SUPABASE_SERVICE_KEY  default chiave service_role demo (vedi supabase/.env)
    SUPABASE_PERSIST      "0" per disabilitare del tutto la scrittura
"""

import datetime
import hashlib
import json
import logging
import os
from typing import Optional

logger = logging.getLogger("vfa.db")

# Campi immutabili di una 'scans' che entrano nella catena hash. version e cve_*
# sono esclusi: update_scan_summary li riscrive a fine scansione (li copre
# _scan_final_hash, sigillato quando i valori definitivi sono noti).
_HASH_FIELDS = ("description", "product", "source", "actor_id", "hash_ts")

# Campi definitivi sigillati a fine scansione, ancorati a row_hash.
_FINAL_HASH_FIELDS = ("version", "cve_count", "cve_ids", "final_ts")


def _canon(payload: dict, fields: tuple) -> str:
    """Serializzazione deterministica dei campi indicati (liste ordinate)."""
    sub = {}
    for k in fields:
        v = payload.get(k)
        sub[k] = sorted(v, key=str) if isinstance(v, list) else v
    return json.dumps(sub, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _scan_hash(payload: dict, prev_hash: str) -> str:
    """sha256 deterministico su (prev_hash | campi immutabili canonicalizzati)."""
    return hashlib.sha256(
        (str(prev_hash or "") + "|" + _canon(payload, _HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _scan_final_hash(payload: dict, row_hash: str) -> str:
    """
    Sigillo di fine scansione: sha256(row_hash | version, cve_count, cve_ids,
    final_ts). Ancorandolo a row_hash, alterare il conteggio CVE a posteriori
    rompe la verifica esattamente come alterare la descrizione.
    """
    return hashlib.sha256(
        (str(row_hash or "") + "|" + _canon(payload, _FINAL_HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _utc_iso() -> str:
    """Timestamp UTC nel formato usato nei calcoli hash (deterministico)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "http://localhost:8001")
# Chiave demo service_role (firmata con il JWT_SECRET demo). Solo per uso locale.
SUPABASE_SERVICE_KEY = os.environ.get(
    "SUPABASE_SERVICE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UtZGVtbyIsImlhdCI6MTY0MTc2OTIwMCwiZXhwIjoxNzk5NTM1NjAwfQ."
    "5z-pJI1qwZg1LE5yavGLqum65WOnnaaI5eZ3V00pLww",
)
PERSIST_ENABLED = os.environ.get("SUPABASE_PERSIST", "1") != "0"

# Client creato una sola volta (lazy).
_client = None
_init_failed = False


def _get_client():
    """Ritorna il client Supabase, creandolo al primo uso. None se non disponibile."""
    global _client, _init_failed
    if _client is not None or _init_failed:
        return _client
    if not PERSIST_ENABLED:
        return None
    try:
        from supabase import create_client
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    except Exception as exc:  # libreria assente o URL non valido
        logger.warning("Supabase non inizializzato (persistenza disattivata): %s", exc)
        _init_failed = True
        _client = None
    return _client


# ---------------------------------------------------------------------------
# ANCORAGGIO DELLE RIGHE NON FIRMATE + VERDETTO DI INTEGRITA'
#
# Le righe scritte prima dell'introduzione delle catene non hanno row_hash. La
# verifica le saltava e rispondeva comunque "ok": su un'installazione reale
# significava dichiarare integro un ledger in cui 104 righe su 108 erano
# riscrivibili senza lasciare traccia — e le run di postura, che reggono i
# conteggi point-in-time, erano non firmate al 100%.
#
# Non si possono firmare a posteriori: nessuno puo' dimostrare che non siano
# gia' state alterate. Si possono pero' ANCORARE — registrarne ORA il digest in
# una riga firmata — cosi' da li' in avanti ogni modifica e' rilevabile. Il
# verdetto distingue i tre casi che prima erano tutti "ok":
#   intact  -> tutto verificato (firmato o ancorato), nessuna rottura
#   partial -> nulla di rotto, ma una parte non e' dimostrabile
#   tampered-> almeno una riga non torna
# ---------------------------------------------------------------------------

# Colonne che entrano nel digest di ancoraggio: tutto cio' che un audit
# leggerebbe come dato probante e che, senza firma, sarebbe riscrivibile.
_ANCHOR_COLUMNS = {
    "scans": ("id", "created_at", "description", "product", "version", "source",
              "actor_id", "actor_name", "cve_count", "cve_ids"),
    "posture_runs": ("id", "created_at", "assets_scanned", "total_packages",
                     "total_vulnerable", "total_vulns", "avg_score",
                     "actor_id", "actor_name"),
    "finding_events": ("id", "event_ts", "fingerprint", "event", "from_status",
                       "to_status", "severity", "actor_id", "actor_name"),
    "audit_events": ("id", "event_ts", "category", "action", "outcome",
                     "actor_id", "actor_name", "target_type", "target_id"),
}

_ANCHOR_HASH_FIELDS = ("chain", "through_id", "row_count", "digest",
                       "actor_id", "event_ts")


def _anchor_hash(payload: dict, prev_hash: str) -> str:
    """sha256(prev_hash | campi dell'ancora): le ancore sono a loro volta
    concatenate, cosi' non se ne puo' sostituire una di nascosto."""
    return hashlib.sha256(
        (str(prev_hash or "") + "|" + _canon(payload, _ANCHOR_HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _anchor_digest(chain: str, rows: list) -> str:
    """Digest deterministico del contenuto delle righe indicate (ordinate per id)."""
    cols = _ANCHOR_COLUMNS.get(chain, ())
    payload = [
        {c: (sorted(r.get(c), key=str) if isinstance(r.get(c), list) else r.get(c))
         for c in cols}
        for r in sorted(rows, key=lambda x: x.get("id") or 0)
    ]
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _fetch_unsigned(client, chain: str, through_id: Optional[int] = None) -> list:
    """Righe della catena prive di row_hash (fino a through_id, se indicato)."""
    cols = _ANCHOR_COLUMNS.get(chain)
    if not cols:
        return []
    try:
        q = client.table(chain).select(",".join(cols) + ",row_hash").is_("row_hash", "null")
        if through_id is not None:
            q = q.lte("id", through_id)
        return (q.order("id").execute().data) or []
    except Exception as exc:
        logger.warning("_fetch_unsigned fallita (%s): %s", chain, exc)
        return []


def fetch_ledger_anchor(chain: str) -> Optional[dict]:
    """Ancora piu' recente della catena indicata. None se assente o DB muto."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("ledger_anchors").select("*")
                .eq("chain", chain).order("id", desc=True).limit(1).execute())
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_ledger_anchor fallita (%s): %s", chain, exc)
        return None


def create_ledger_anchor(chain: str, actor: Optional[dict] = None,
                         note: str = "") -> Optional[dict]:
    """
    Ancora le righe non firmate della catena: ne registra il digest in una riga
    firmata e concatenata alle ancore precedenti.

    Ritorna la riga creata, None se il DB non risponde o se non c'e' nulla da
    ancorare (tutte le righe sono gia' firmate: in quel caso l'ancora sarebbe
    rumore, non protezione).

    Attenzione a cosa significa: l'ancora dichiara "questo era il contenuto al
    momento T", non "queste righe non sono mai state modificate". Nessuno puo'
    dimostrare il secondo enunciato a posteriori, e la verifica continua a
    dichiararlo apertamente.
    """
    client = _get_client()
    if client is None or chain not in _ANCHOR_COLUMNS:
        return None
    rows = _fetch_unsigned(client, chain)
    if not rows:
        return None
    actor = actor or {}
    row = {
        "event_ts": _utc_iso(),
        "chain": chain,
        "through_id": max(r["id"] for r in rows),
        "row_count": len(rows),
        "digest": _anchor_digest(chain, rows),
        "actor_id": actor.get("id"),
        "actor_name": actor.get("name"),
        "note": note or "",
    }
    try:
        prev = (client.table("ledger_anchors").select("row_hash")
                .order("id", desc=True).limit(1).execute())
        prev_hash = (prev.data[0].get("row_hash") or "") if prev.data else ""
    except Exception as exc:
        logger.warning("lettura ultima ancora fallita: %s", exc)
        prev_hash = ""
    row["prev_hash"] = prev_hash
    row["row_hash"] = _anchor_hash(row, prev_hash)
    try:
        resp = client.table("ledger_anchors").insert(row).execute()
        return (resp.data or [row])[0]
    except Exception as exc:
        logger.warning("create_ledger_anchor fallita (%s): %s", chain, exc)
        return None


def _anchor_status(client, chain: str) -> dict:
    """
    Stato dell'ancoraggio della catena:
    {present, at, through_id, row_count, digest_ok, actor}. 'digest_ok' False
    significa che una riga ancorata E' STATA modificata dopo l'ancoraggio: e'
    una manomissione rilevata, non una copertura mancante.
    """
    try:
        resp = (client.table("ledger_anchors").select("*")
                .eq("chain", chain).order("id", desc=True).limit(1).execute())
    except Exception as exc:
        logger.warning("_anchor_status fallita (%s): %s", chain, exc)
        return {"present": False}
    if not resp.data:
        return {"present": False}
    a = resp.data[0]
    rows = _fetch_unsigned(client, chain, through_id=a.get("through_id"))
    return {
        "present": True,
        "at": a.get("event_ts"),
        "through_id": a.get("through_id"),
        "row_count": a.get("row_count") or 0,
        "actor": a.get("actor_name"),
        "digest_ok": _anchor_digest(chain, rows) == a.get("digest"),
        "self_hash_ok": a.get("row_hash") == _anchor_hash(a, a.get("prev_hash") or ""),
    }


def _chain_verdict(chain: str, total: int, verified: int, broken: list,
                   unsigned: int, extra: Optional[dict] = None) -> dict:
    """
    Compone la risposta di verifica con la copertura REALE e un verdetto
    esplicito. Prima si rispondeva {ok: true} quando nessun controllo falliva,
    anche se i controlli coprivano il 2% delle righe: 'ok' voleva dire "niente
    di quello che ho potuto controllare e' rotto", e la risposta non lo diceva
    da nessuna parte.
    """
    client = _get_client()
    anchor = _anchor_status(client, chain) if client is not None else {"present": False}
    # Un'ancora valida copre le righe non firmate fino a through_id: da li' in
    # avanti sono protette. Se il digest non torna, quelle righe sono state
    # modificate dopo l'ancoraggio -> manomissione.
    anchored = 0
    if anchor.get("present") and anchor.get("digest_ok") and anchor.get("self_hash_ok"):
        anchored = min(anchor.get("row_count") or 0, unsigned)
    unprotected = max(unsigned - anchored, 0)

    extra = extra or {}
    finals_broken = extra.get("finals_broken") or []
    unsealed = extra.get("finals_pending") or 0

    tampered = bool(broken) or bool(finals_broken) or (
        anchor.get("present") and not (anchor.get("digest_ok") and anchor.get("self_hash_ok")))
    covered = verified + anchored
    if total == 0:
        verdict = "empty"
    elif tampered:
        verdict = "tampered"
    elif unprotected or unsealed:
        verdict = "partial"
    else:
        verdict = "intact"

    out = {
        "chain": chain,
        "total": total,
        "verified": verified,
        "broken": broken,
        # 'unsigned' = righe senza row_hash; 'anchored' = quante di quelle sono
        # coperte da un'ancora valida; 'unprotected' = quante restano
        # riscrivibili senza lasciare traccia. E' la cifra che conta.
        "unsigned": unsigned,
        "anchored": anchored,
        "unprotected": unprotected,
        "covered": covered,
        "coverage": round(covered / total, 4) if total else None,
        "verdict": verdict,
        # 'ok' ora significa cio' che un lettore assume che significhi: la
        # catena e' integra E la copertura e' completa.
        "ok": verdict in ("intact", "empty"),
        # Manomissione e copertura incompleta sono due fatti diversi e vanno
        # letti separatamente: il primo e' un incidente, il secondo un limite
        # dichiarato.
        "tamper_free": not tampered,
        "anchor": anchor,
    }
    out.update(extra)
    return out


def _last_row_hash(client) -> str:
    """row_hash della scansione piu' recente (per linkare la catena). '' se nessuna."""
    try:
        resp = (client.table("scans").select("row_hash")
                .order("id", desc=True).limit(1).execute())
        if resp.data:
            return resp.data[0].get("row_hash") or ""
    except Exception as exc:
        logger.warning("_last_row_hash fallita: %s", exc)
    return ""


def persist_scan(description: str, target: dict, cve: dict,
                 advisory: Optional[dict] = None,
                 actor: Optional[dict] = None) -> Optional[int]:
    """
    Inserisce la riga 'scans' (target identificato + sintesi CVE + advisory AI).
    Ritorna l'id della scansione, oppure None se la persistenza fallisce.

    'advisory' (opzionale): {affected_version, affected_source}. Tenuto DISTINTO
    dai campi CVE.
    'actor' (opzionale): {id, name} dell'utente autore -> ledger tamper-evident.
    """
    client = _get_client()
    if client is None:
        return None
    advisory = advisory or {}
    actor = actor or {}
    row = {
        "description": description,
        "product": target.get("product"),
        "version": target.get("version"),
        "matched_alias": target.get("matched_alias"),
        "source": target.get("source"),
        "candidates": target.get("candidates") or [],
        "dependencies": target.get("dependencies") or [],
        "cve_count": cve.get("count"),
        "cve_ids": cve.get("ids") or [],
        "cve_summary": cve.get("summary"),
        "cve_error": cve.get("error"),
        "affected_version": advisory.get("affected_version"),
        "affected_source": advisory.get("affected_source"),
        # Attore + catena hash (ledger). hash_ts deterministico lato client cosi'
        # la verifica ricalcola lo stesso digest indipendentemente dal DB.
        "actor_id": actor.get("id"),
        "actor_name": actor.get("name"),
        "hash_ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    prev_hash = _last_row_hash(client)
    row["prev_hash"] = prev_hash
    row["row_hash"] = _scan_hash(row, prev_hash)
    try:
        resp = client.table("scans").insert(row).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("persist_scan fallita: %s", exc)
        return None


def verify_audit_chain() -> Optional[dict]:
    """
    Ricalcola la catena hash del ledger e riporta le rotture.

    Verifica DUE livelli:
      - row_hash   -> campi immutabili + linkatura alla riga precedente
      - final_hash -> version/cve_count/cve_ids sigillati a fine scansione
        (il CONTEGGIO CVE: senza questo controllo il numero sarebbe alterabile
        a posteriori senza rompere nulla)

    Ritorna il verdetto completo (vedi _chain_verdict): total, verified,
    broken, unsigned, anchored, unprotected, coverage, verdict, ok, piu'
    finals_verified/finals_pending/finals_broken. None se il DB non risponde.

    Le righe precedenti alla migrazione (row_hash NULL) non rompono la catena
    ma NON sono verificate: contano come 'unprotected' finche' non vengono
    ancorate, e finche' ce ne sono il verdetto e' 'partial', non 'intact'.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("scans")
                .select("id,description,product,source,actor_id,hash_ts,prev_hash,row_hash,"
                        "version,cve_count,cve_ids,final_ts,final_hash")
                .order("id").execute())
    except Exception as exc:
        logger.warning("verify_audit_chain fallita: %s", exc)
        return None
    rows = resp.data or []
    broken, verified, unsigned = [], 0, 0
    finals_broken, finals_verified, finals_pending = [], 0, 0
    prev = ""                      # row_hash dell'ultima riga hashata
    for r in rows:
        if not r.get("row_hash"):  # riga pre-migrazione, non firmata
            unsigned += 1
            continue
        expect = _scan_hash(r, r.get("prev_hash") or "")
        linked = (r.get("prev_hash") or "") == prev
        if r["row_hash"] == expect and linked:
            verified += 1
        else:
            broken.append(r["id"])
        prev = r["row_hash"]
        if not r.get("final_hash"):
            finals_pending += 1
        elif r["final_hash"] == _scan_final_hash(r, r.get("row_hash") or ""):
            finals_verified += 1
        else:
            finals_broken.append(r["id"])
    return _chain_verdict("scans", len(rows), verified, broken, unsigned,
                          {"finals_verified": finals_verified,
                           "finals_pending": finals_pending,
                           "finals_broken": finals_broken})


def persist_result(scan_id: Optional[int], rd: dict) -> None:
    """
    Inserisce una riga 'scan_results' (esito per singolo asset).
    No-op se scan_id e' None o se la persistenza non e' disponibile.
    """
    client = _get_client()
    if client is None:
        return
    row = {
        "scan_id": scan_id,
        "ip": rd.get("ip"),
        "auth_required": rd.get("auth_required"),
        "method": rd.get("method"),
        "product_found": rd.get("product_found"),
        "detected_version": rd.get("detected_version"),
        "raw_evidence": rd.get("raw_evidence"),
        "vuln_match": rd.get("vuln_match"),
        "cve_count": rd.get("cve_count"),
        "cve_ids": rd.get("cve_ids") or [],
        "cve_error": rd.get("cve_error"),
        "affected_version": rd.get("affected_version"),
        "match_basis": rd.get("match_basis"),
        "os_type": rd.get("os_type"),
        "os_major_version": rd.get("os_major_version"),
    }
    try:
        client.table("scan_results").insert(row).execute()
    except Exception as exc:
        logger.warning("persist_result fallita (ip=%s): %s", rd.get("ip"), exc)


def fetch_audit(limit: int = 2000, date_from: Optional[str] = None,
                date_to: Optional[str] = None):
    """
    Legge lo storico scansioni con i risultati per-asset annidati (embedding
    PostgREST sulla FK scan_results.scan_id -> scans.id), piu' recenti prima.

    'date_from'/'date_to' (ISO date/datetime, opzionali) filtrano su created_at
    lato DB, riducendo il volume prima del filtro RBAC/facet applicato in app.

    Ritorna:
      - lista di scans (ognuna con chiave 'scan_results')  se il DB risponde
      - None                                               se Supabase non e' raggiungibile
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("scans").select("*, scan_results(*)")
        if date_from:
            q = q.gte("created_at", date_from)
        if date_to:
            q = q.lte("created_at", date_to)
        resp = q.order("created_at", desc=True).limit(limit).execute()
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_audit fallita: %s", exc)
        return None


def update_scan_summary(scan_id: Optional[int], cve: dict) -> None:
    """
    Aggiorna la riga 'scans' con la sintesi CVE finale (conteggio + LLM) e
    SIGILLA i valori definitivi in final_hash (ancorato a row_hash).

    Da qui in avanti version/cve_count/cve_ids sono tamper-evident: modificarli
    a DB rompe /api/audit/verify. Il sigillo si applica una sola volta per
    scansione; se la riga ha gia' un final_hash non viene riscritto (un secondo
    aggiornamento resterebbe fuori dalla catena e va trattato come rottura).
    """
    client = _get_client()
    if client is None or scan_id is None:
        return
    row = {
        "version": cve.get("version"),
        "cve_count": cve.get("count"),
        "cve_ids": cve.get("ids") or [],
        "cve_summary": cve.get("summary"),
        "cve_error": cve.get("error"),
    }
    try:
        resp = (client.table("scans").select("row_hash,final_hash")
                .eq("id", scan_id).execute())
        current = (resp.data or [{}])[0]
        if current.get("row_hash") and not current.get("final_hash"):
            row["final_ts"] = _utc_iso()
            row["final_hash"] = _scan_final_hash(row, current["row_hash"])
    except Exception as exc:
        logger.warning("sigillo final_hash non applicato (scan_id=%s): %s", scan_id, exc)
    try:
        client.table("scans").update(row).eq("id", scan_id).execute()
    except Exception as exc:
        logger.warning("update_scan_summary fallita: %s", exc)


# ---------------------------------------------------------------------------
# INVENTARIO ASSET (tabella 'assets', sostituisce assets.txt)
# ---------------------------------------------------------------------------

def fetch_assets():
    """
    Legge l'inventario asset ordinato per id.
    Ritorna la lista di righe (eventualmente vuota) oppure None se il DB
    non e' raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("assets").select("*").order("id").execute()
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_assets fallita: %s", exc)
        return None


def insert_asset(row: dict) -> Optional[int]:
    """Inserisce un asset e ritorna il suo id, None in caso di errore."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("assets").insert(row).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("insert_asset fallita (ip=%s): %s", row.get("ip"), exc)
        return None


def insert_assets(rows: list) -> bool:
    """Inserimento bulk (migrazione da assets.txt). True se riuscito."""
    client = _get_client()
    if client is None or not rows:
        return False
    try:
        client.table("assets").insert(rows).execute()
        return True
    except Exception as exc:
        logger.warning("insert_assets fallita: %s", exc)
        return False


def update_asset(asset_id: int, row: dict) -> bool:
    """Aggiorna l'asset indicato. True se la riga esiste ed e' stata aggiornata."""
    client = _get_client()
    if client is None:
        return False
    try:
        row = {**row, "updated_at": "now()"}
        resp = client.table("assets").update(row).eq("id", asset_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("update_asset fallita (id=%s): %s", asset_id, exc)
        return False


def delete_asset(asset_id: int) -> bool:
    """Elimina l'asset indicato. True se la riga esisteva."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = client.table("assets").delete().eq("id", asset_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("delete_asset fallita (id=%s): %s", asset_id, exc)
        return False


# ---------------------------------------------------------------------------
# FULL POSTURE (SCA)
# ---------------------------------------------------------------------------

# Catena hash delle run di postura. posture_runs regge i CONTEGGI point-in-time
# ed e' quindi evidenza di audit quanto 'scans': stessa costruzione a due
# livelli (creazione firmata + totali sigillati a fine run).
_POSTURE_HASH_FIELDS = ("actor_id", "hash_ts")
_POSTURE_FINAL_FIELDS = ("assets_scanned", "total_packages", "total_vulnerable",
                         "total_vulns", "avg_score", "final_ts")


def _posture_hash(payload: dict, prev_hash: str) -> str:
    """sha256(prev_hash | campi noti alla creazione della run)."""
    return hashlib.sha256(
        (str(prev_hash or "") + "|" + _canon(payload, _POSTURE_HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _posture_final_hash(payload: dict, row_hash: str) -> str:
    """sha256(row_hash | totali della run) — il sigillo di fine scansione."""
    return hashlib.sha256(
        (str(row_hash or "") + "|" + _canon(payload, _POSTURE_FINAL_FIELDS)).encode("utf-8")
    ).hexdigest()


def _last_posture_hash(client) -> str:
    """row_hash dell'ultima run di postura. '' se nessuna."""
    try:
        resp = (client.table("posture_runs").select("row_hash")
                .order("id", desc=True).limit(1).execute())
        if resp.data:
            return resp.data[0].get("row_hash") or ""
    except Exception as exc:
        logger.warning("_last_posture_hash fallita: %s", exc)
    return ""


def create_posture_run(actor: Optional[dict] = None) -> Optional[int]:
    """
    Crea una riga posture_runs (vuota) e ritorna l'id. None se DB assente.
    Registra l'attore e aggancia la run alla catena hash delle run.
    """
    client = _get_client()
    if client is None:
        return None
    actor = actor or {}
    row = {
        "assets_scanned": 0,
        "actor_id": actor.get("id"),
        "actor_name": actor.get("name"),
        "hash_ts": _utc_iso(),
    }
    prev_hash = _last_posture_hash(client)
    row["prev_hash"] = prev_hash
    row["row_hash"] = _posture_hash(row, prev_hash)
    try:
        resp = client.table("posture_runs").insert(row).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("create_posture_run fallita: %s", exc)
        return None


def verify_posture_chain() -> Optional[dict]:
    """
    Verifica la catena hash delle run di postura, sui due livelli: row_hash
    (creazione + linkatura) e final_hash (totali sigillati a fine run).
    Stessa semantica di verify_audit_chain. None se il DB non risponde.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("posture_runs")
                .select("id,actor_id,hash_ts,prev_hash,row_hash,assets_scanned,"
                        "total_packages,total_vulnerable,total_vulns,avg_score,"
                        "final_ts,final_hash")
                .order("id").execute())
    except Exception as exc:
        logger.warning("verify_posture_chain fallita: %s", exc)
        return None
    rows = resp.data or []
    broken, verified, unsigned = [], 0, 0
    finals_broken, finals_verified, finals_pending = [], 0, 0
    prev = ""
    for r in rows:
        if not r.get("row_hash"):          # run precedente alla migrazione
            unsigned += 1
            continue
        expect = _posture_hash(r, r.get("prev_hash") or "")
        linked = (r.get("prev_hash") or "") == prev
        if r["row_hash"] == expect and linked:
            verified += 1
        else:
            broken.append(r["id"])
        prev = r["row_hash"]
        if not r.get("final_hash"):
            finals_pending += 1
        elif r["final_hash"] == _posture_final_hash(r, r.get("row_hash") or ""):
            finals_verified += 1
        else:
            finals_broken.append(r["id"])
    return _chain_verdict("posture_runs", len(rows), verified, broken, unsigned,
                          {"finals_verified": finals_verified,
                           "finals_pending": finals_pending,
                           "finals_broken": finals_broken})


def persist_posture_asset(run_id: Optional[int], report: dict) -> None:
    """Inserisce un asset di postura + i suoi finding per-pacchetto."""
    client = _get_client()
    if client is None or run_id is None:
        return
    try:
        row = {k: report.get(k) for k in (
            "ip", "os_guess", "method", "total_packages", "vulnerable_packages",
            "total_vulns", "score", "sev_critical", "sev_high", "sev_medium",
            "sev_low", "sev_unknown", "os_type", "os_major_version")}
        row["run_id"] = run_id
        resp = client.table("posture_assets").insert(row).execute()
        asset_id = resp.data[0]["id"] if resp.data else None
        findings = report.get("findings") or []
        if asset_id and findings:
            client.table("posture_findings").insert([{
                "asset_id": asset_id,
                "package": f["package"], "version": f["version"],
                "ecosystem": f["ecosystem"], "category": f["category"],
                "vuln_count": f["vuln_count"], "max_severity": f["max_severity"],
                "cve_ids": f["cve_ids"] or [],
            } for f in findings]).execute()
        # Inventario COMPLETO (SBOM): tutti i componenti, non solo i vulnerabili.
        components = report.get("components") or []
        if asset_id and components:
            client.table("posture_components").insert([{
                "asset_id": asset_id,
                "package": c["package"], "version": c["version"],
                "ecosystem": c["ecosystem"], "category": c["category"],
                "purl": c["purl"], "cpe": c["cpe"], "license": c["license"],
                "supplier": c["supplier"], "sha256": c["sha256"],
                "vuln_count": c["vuln_count"], "max_severity": c["max_severity"],
                "cve_ids": c["cve_ids"] or [], "depends_on": c["depends_on"] or [],
            } for c in components]).execute()
    except Exception as exc:
        logger.warning("persist_posture_asset fallita (ip=%s): %s", report.get("ip"), exc)


def finalize_posture_run(run_id: Optional[int], totals: dict) -> None:
    """
    Aggiorna gli aggregati della run a fine scansione e li SIGILLA in
    final_hash (ancorato a row_hash). Da qui i totali della run — i numeri che
    un audit legge come "vulnerabilita' rilevate a questa data" — non sono piu'
    modificabili senza rompere /api/audit/posture-verify. Sigillo write-once:
    una run gia' sigillata non viene riscritta.
    """
    client = _get_client()
    if client is None or run_id is None:
        return
    row = {
        "assets_scanned": totals.get("assets_scanned"),
        "total_packages": totals.get("total_packages"),
        "total_vulnerable": totals.get("total_vulnerable"),
        "total_vulns": totals.get("total_vulns"),
        "avg_score": totals.get("avg_score"),
    }
    try:
        resp = (client.table("posture_runs").select("row_hash,final_hash")
                .eq("id", run_id).execute())
        current = (resp.data or [{}])[0]
        if current.get("row_hash") and not current.get("final_hash"):
            row["final_ts"] = _utc_iso()
            row["final_hash"] = _posture_final_hash(row, current["row_hash"])
    except Exception as exc:
        logger.warning("sigillo posture non applicato (run_id=%s): %s", run_id, exc)
    try:
        client.table("posture_runs").update(row).eq("id", run_id).execute()
    except Exception as exc:
        logger.warning("finalize_posture_run fallita: %s", exc)


def fetch_posture(run_id: Optional[int] = None):
    """
    Ritorna una run di postura con asset + findings annidati.
    run_id None => ultima run. None se DB non raggiungibile, {} se nessuna run.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("posture_runs").select(
            "*, posture_assets(*, posture_findings(*))")
        if run_id is not None:
            q = q.eq("id", run_id)
        else:
            q = q.order("created_at", desc=True).limit(1)
        resp = q.execute()
        return (resp.data[0] if resp.data else {})
    except Exception as exc:
        logger.warning("fetch_posture fallita: %s", exc)
        return None


def fetch_posture_sbom(run_id: Optional[int] = None):
    """
    Ritorna una run con l'inventario COMPLETO per asset (posture_components) —
    sorgente della SBOM. run_id None => ultima run. None se DB non raggiungibile,
    {} se nessuna run.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("posture_runs").select(
            "id, created_at, "
            "posture_assets(ip, os_type, os_guess, os_major_version, posture_components(*))")
        if run_id is not None:
            q = q.eq("id", run_id)
        else:
            q = q.order("created_at", desc=True).limit(1)
        resp = q.execute()
        return (resp.data[0] if resp.data else {})
    except Exception as exc:
        logger.warning("fetch_posture_sbom fallita: %s", exc)
        return None


# ---------------------------------------------------------------------------
# FINDINGS UNIFICATI (ciclo di vita ASPM: dedup + workflow + SLA)
# ---------------------------------------------------------------------------

def fetch_findings(limit: int = 2000):
    """
    Tutti i finding, piu' recenti prima (per last_seen).
    Lista (anche vuota) se il DB risponde, None se non raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("findings").select("*")
                .order("last_seen", desc=True).limit(limit).execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_findings fallita: %s", exc)
        return None


def fetch_findings_by_fps(fps: list):
    """Righe esistenti per i fingerprint indicati. None se DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    if not fps:
        return []
    try:
        rows = []
        # PostgREST limita la lunghezza dell'URL: chunk della lista IN.
        for i in range(0, len(fps), 100):
            resp = (client.table("findings").select("*")
                    .in_("fingerprint", fps[i:i + 100]).execute())
            rows.extend(resp.data or [])
        return rows
    except Exception as exc:
        logger.warning("fetch_findings_by_fps fallita: %s", exc)
        return None


def upsert_findings(rows: list) -> bool:
    """Upsert batch su fingerprint (dedup). True se riuscito."""
    client = _get_client()
    if client is None or not rows:
        return False
    try:
        client.table("findings").upsert(rows, on_conflict="fingerprint").execute()
        return True
    except Exception as exc:
        logger.warning("upsert_findings fallita: %s", exc)
        return False


# ---------------------------------------------------------------------------
# REGISTRO EVENTI DEI FINDING (append-only, tamper-evident)
#
# 'findings' e' aggiornata IN PLACE: lo stato passato viene distrutto, non
# archiviato. Questo registro conserva ogni transizione come riga NUOVA, cosi'
# lo stato a una data qualsiasi e' ricostruibile per replay (vedi
# findings.reconstruct_as_of e l'endpoint /api/findings/as-of).
# ---------------------------------------------------------------------------

# Campi immutabili di un evento che entrano nella catena hash.
_FEVENT_HASH_FIELDS = ("fingerprint", "event", "from_status", "to_status",
                       "severity", "actor_id", "event_ts")


def _fevent_hash(payload: dict, prev_hash: str) -> str:
    """sha256(prev_hash | campi immutabili dell'evento canonicalizzati)."""
    return hashlib.sha256(
        (str(prev_hash or "") + "|" + _canon(payload, _FEVENT_HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _last_fevent_hash(client) -> str:
    """row_hash dell'ultimo evento registrato. '' se il registro e' vuoto."""
    try:
        resp = (client.table("finding_events").select("row_hash")
                .order("id", desc=True).limit(1).execute())
        if resp.data:
            return resp.data[0].get("row_hash") or ""
    except Exception as exc:
        logger.warning("_last_fevent_hash fallita: %s", exc)
    return ""


def log_finding_events(events: list) -> int:
    """
    Appende eventi di ciclo di vita al registro, concatenati in hash.

    'events' e' l'output di findings.lifecycle_events (o una lista costruita a
    mano con le stesse chiavi); l'ordine della lista e' l'ordine di scrittura.
    Best-effort come il resto della persistenza: ritorna il numero di righe
    scritte, 0 se il DB non risponde. Scritture concorrenti possono biforcare
    la catena, esattamente come per il ledger 'scans'.
    """
    client = _get_client()
    if client is None or not events:
        return 0
    prev = _last_fevent_hash(client)
    rows = []
    for e in events:
        actor = e.get("actor") or {}
        row = {
            "event_ts": e.get("event_ts") or _utc_iso(),
            "finding_id": e.get("finding_id"),
            "fingerprint": e.get("fingerprint") or "",
            "event": e.get("event") or "",
            "from_status": e.get("from_status"),
            "to_status": e.get("to_status"),
            "severity": e.get("severity") or None,
            "asset_ip": e.get("asset_ip") or None,
            "source": e.get("source") or None,
            "actor_id": actor.get("id"),
            "actor_name": actor.get("name"),
            "note": e.get("note") or "",
        }
        row["prev_hash"] = prev
        row["row_hash"] = _fevent_hash(row, prev)
        prev = row["row_hash"]
        rows.append(row)
    try:
        client.table("finding_events").insert(rows).execute()
        return len(rows)
    except Exception as exc:
        logger.warning("log_finding_events fallita (%d eventi): %s", len(rows), exc)
        return 0


def fetch_finding_events(until: Optional[str] = None, fp: Optional[str] = None,
                         limit: int = 50000):
    """
    Eventi del registro in ordine di scrittura (id crescente).

    'until' (ISO) taglia lato DB gli eventi successivi: event_ts e' testo in
    formato UTC fisso, quindi il confronto lessicografico coincide con quello
    cronologico. Ritorna la lista, o None se il DB non e' raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("finding_events").select("*")
        if until:
            q = q.lte("event_ts", until)
        if fp:
            q = q.eq("fingerprint", fp)
        resp = q.order("id").limit(limit).execute()
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_finding_events fallita: %s", exc)
        return None


def verify_findings_chain() -> Optional[dict]:
    """
    Ricalcola la catena hash del registro eventi.
    Ritorna {total, verified, broken:[id...], ok}, None se il DB non risponde.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("finding_events")
                .select("id,fingerprint,event,from_status,to_status,severity,"
                        "actor_id,event_ts,prev_hash,row_hash")
                .order("id").execute())
    except Exception as exc:
        logger.warning("verify_findings_chain fallita: %s", exc)
        return None
    rows = resp.data or []
    broken, verified, unsigned, prev = [], 0, 0, ""
    for r in rows:
        if not r.get("row_hash"):
            unsigned += 1
            continue
        expect = _fevent_hash(r, r.get("prev_hash") or "")
        linked = (r.get("prev_hash") or "") == prev
        if r.get("row_hash") == expect and linked:
            verified += 1
        else:
            broken.append(r["id"])
        prev = r.get("row_hash") or ""
    return _chain_verdict("finding_events", len(rows), verified, broken, unsigned)


def set_finding_status(finding_id: int, status: str, note: str = "",
                       actor: Optional[dict] = None) -> bool:
    """
    Transizione manuale di stato dal workflow UI. True se la riga esiste.

    Registra l'evento (from_status -> to_status + attore) PRIMA di perdere lo
    stato precedente: l'UPDATE lo sovrascrive e senza registro non sarebbe piu'
    ricostruibile in audit.
    """
    client = _get_client()
    if client is None:
        return False
    prev = fetch_finding(finding_id)
    if prev is None:
        return False
    try:
        resp = client.table("findings").update({
            "status": status,
            "status_note": note or "",
            "status_changed_at": _utc_iso(),
        }).eq("id", finding_id).execute()
        if not resp.data:
            return False
    except Exception as exc:
        logger.warning("set_finding_status fallita (id=%s): %s", finding_id, exc)
        return False
    log_finding_events([{
        "event": "status_change",
        "finding_id": finding_id,
        "fingerprint": prev.get("fingerprint") or "",
        "from_status": prev.get("status") or "open",
        "to_status": status,
        "severity": prev.get("severity"),
        "asset_ip": prev.get("asset_ip"),
        "source": prev.get("source"),
        "actor": actor or {},
        "note": note or "",
    }])
    return True


def fetch_finding(finding_id: int):
    """Singolo finding per id. None se assente o DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("findings").select("*").eq("id", finding_id).execute()
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_finding fallita (id=%s): %s", finding_id, exc)
        return None


def set_finding_ticket(finding_id: int, ref: str, url: str) -> bool:
    """Salva il riferimento del ticket di remediation creato per il finding."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = client.table("findings").update({
            "ticket_ref": ref, "ticket_url": url,
        }).eq("id", finding_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("set_finding_ticket fallita (id=%s): %s", finding_id, exc)
        return False


def close_stale_posture_findings(asset_ip: str, seen_fps: list,
                                 actor: Optional[dict] = None) -> int:
    """
    Auto-fix: i finding di postura di un asset NON riosservati nell'ultima run
    (fingerprint assente) e ancora open/triaged passano a 'fixed'.
    Ritorna il numero di righe chiuse (0 se DB assente o niente da chiudere).

    Ogni chiusura automatica produce un evento 'auto_fixed' nel registro: e' la
    remediation che un auditor contesta per prima ("chi ha dichiarato risolto,
    e quando?"), e senza traccia sarebbe una riga sovrascritta e basta.
    """
    client = _get_client()
    if client is None or not asset_ip:
        return 0
    note = "Auto-fixed: not detected in latest posture run"
    try:
        resp = (client.table("findings")
                .select("id, fingerprint, status, source, severity")
                .eq("asset_ip", asset_ip).in_("status", ["open", "triaged"])
                .execute())
        seen = set(seen_fps or [])
        stale = [r for r in (resp.data or [])
                 if "posture" in (r.get("source") or "")
                 and r.get("fingerprint") not in seen]
        if not stale:
            return 0
        client.table("findings").update({
            "status": "fixed",
            "status_note": note,
            "status_changed_at": _utc_iso(),
        }).in_("id", [r["id"] for r in stale]).execute()
    except Exception as exc:
        logger.warning("close_stale_posture_findings fallita (ip=%s): %s", asset_ip, exc)
        return 0
    log_finding_events([{
        "event": "auto_fixed",
        "finding_id": r["id"],
        "fingerprint": r.get("fingerprint") or "",
        "from_status": r.get("status") or "open",
        "to_status": "fixed",
        "severity": r.get("severity"),
        "asset_ip": asset_ip,
        "source": r.get("source"),
        "actor": actor or {},
        "note": note,
    } for r in stale])
    return len(stale)


# ---------------------------------------------------------------------------
# REGISTRO ATTIVITA' (audit_events): chi ha fatto cosa, su cosa, quando.
#
# I registri precedenti coprono l'attivita' di SCANSIONE. Questo copre tutto il
# resto — accessi, accessi falliti, cambi ruolo, amministrazione utenti e
# gruppi, assegnazioni, configurazione, export — cioe' le domande che un audit
# pone per prime e a cui prima l'applicativo non sapeva rispondere.
# Stessa costruzione degli altri registri: append-only + catena hash.
# ---------------------------------------------------------------------------

# Campi immutabili di un evento che entrano nella catena hash. 'detail' e'
# incluso: e' li' che vivono i valori dell'azione (ruolo prima/dopo, chiavi di
# configurazione toccate) ed e' esattamente cio' che avrebbe senso ritoccare.
_AEVENT_HASH_FIELDS = ("category", "action", "outcome", "actor_id", "actor_name",
                       "actor_role", "target_type", "target_id", "target_label",
                       "detail", "src_ip", "event_ts")

# Chiavi il cui VALORE non entra mai nel registro. Il registro e' leggibile da
# tutti gli auditor e viaggia negli export: deve dire che una password e' stata
# cambiata o che una chiave API e' stata riscritta, mai con quale valore.
#
# Match ESATTO sul nome della chiave, non "contiene": con la sottostringa,
# 'must_change_password' (un flag booleano) veniva oscurato come se fosse una
# credenziale, e il registro perdeva informazione senza proteggere nulla.
_REDACT_KEYS = frozenset((
    "password", "old_password", "new_password", "password_hash", "token",
    "api_key", "claude_api_key", "serper_api_key", "github_token",
    "jira_api_token", "secret", "activation_link", "reset_link",
))
# Suffissi per le chiavi non previste (integrazioni future): un '<x>_token' o
# un '<x>_api_key' e' sempre una credenziale. '_password' NON e' qui apposta:
# lo prende il match esatto, senza travolgere i flag che finiscono cosi'.
_REDACT_SUFFIXES = ("_token", "_api_key", "_secret")
_REDACTED = "[redacted]"


def _redact(value, key: str = ""):
    """
    Copia di 'value' con i valori sensibili sostituiti da '[redacted]'.
    Ricorsiva: i dettagli di configurazione arrivano annidati per sezione.
    """
    kl = (key or "").lower()
    if kl in _REDACT_KEYS or kl.endswith(_REDACT_SUFFIXES):
        return _REDACTED if value not in (None, "", [], {}) else value
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    return value


def _aevent_hash(payload: dict, prev_hash: str) -> str:
    """sha256(prev_hash | campi immutabili dell'evento canonicalizzati)."""
    return hashlib.sha256(
        (str(prev_hash or "") + "|" + _canon(payload, _AEVENT_HASH_FIELDS)).encode("utf-8")
    ).hexdigest()


def _last_aevent_hash(client) -> str:
    """row_hash dell'ultimo evento di attivita'. '' se il registro e' vuoto."""
    try:
        resp = (client.table("audit_events").select("row_hash")
                .order("id", desc=True).limit(1).execute())
        if resp.data:
            return resp.data[0].get("row_hash") or ""
    except Exception as exc:
        logger.warning("_last_aevent_hash fallita: %s", exc)
    return ""


def log_audit_event(action: str, category: str = "", outcome: str = "success",
                    actor: Optional[dict] = None, target: Optional[dict] = None,
                    detail: Optional[dict] = None,
                    request_meta: Optional[dict] = None) -> bool:
    """
    Appende un evento di attivita' al registro, concatenato in hash.

    action    'auth.login', 'user.role_change', ... (prefisso = categoria se
              'category' non e' passata esplicitamente)
    outcome   success | failure | denied
    actor     {id, name, role} — assente per le azioni pre-autenticazione
              (un login fallito non ha un attore autenticato).
    target    {type, id, label} — l'oggetto dell'azione.
    detail    contesto strutturato; i valori sensibili sono redatti qui dentro.
    request_meta {ip, user_agent}

    Best-effort come il resto della persistenza (True se scritto): un evento
    non registrabile non deve MAI far fallire l'operazione dell'utente. La
    conseguenza — un buco nel registro quando il DB e' giu' — e' dichiarata
    nella pagina di audit invece di essere nascosta.
    """
    client = _get_client()
    if client is None:
        return False
    actor = actor or {}
    target = target or {}
    meta = request_meta or {}
    row = {
        "event_ts": _utc_iso(),
        "category": category or (action.split(".")[0] if "." in action else "other"),
        "action": action,
        "outcome": outcome or "success",
        "actor_id": actor.get("id"),
        "actor_name": actor.get("name"),
        "actor_role": actor.get("role"),
        "target_type": target.get("type"),
        # target_id e' testo: gli id di questo applicativo sono numerici, ma un
        # bersaglio puo' anche essere una sezione di configurazione o un IP.
        "target_id": None if target.get("id") is None else str(target.get("id")),
        "target_label": target.get("label"),
        "detail": _redact(detail or {}),
        "src_ip": meta.get("ip"),
        "user_agent": (meta.get("user_agent") or "")[:300] or None,
    }
    prev = _last_aevent_hash(client)
    row["prev_hash"] = prev
    row["row_hash"] = _aevent_hash(row, prev)
    try:
        client.table("audit_events").insert(row).execute()
        return True
    except Exception as exc:
        logger.warning("log_audit_event fallita (%s): %s", action, exc)
        return False


def fetch_audit_events(limit: int = 5000, date_from: Optional[str] = None,
                       date_to: Optional[str] = None,
                       actor_id: Optional[int] = None):
    """
    Eventi di attivita' dal piu' recente. I filtri di data sono applicati lato
    DB su event_ts (testo UTC a formato fisso: ordine lessicografico =
    cronologico). 'actor_id' limita al singolo attore (usato per i ruoli
    scoped). None se il DB non e' raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        q = client.table("audit_events").select("*")
        if date_from:
            q = q.gte("event_ts", date_from)
        if date_to:
            q = q.lte("event_ts", date_to)
        if actor_id is not None:
            q = q.eq("actor_id", actor_id)
        resp = q.order("id", desc=True).limit(limit).execute()
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_audit_events fallita: %s", exc)
        return None


def verify_events_chain() -> Optional[dict]:
    """
    Ricalcola la catena hash del registro attivita'.
    Ritorna {total, verified, broken:[id...], ok}, None se il DB non risponde.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("audit_events")
                .select("id,category,action,outcome,actor_id,actor_name,actor_role,"
                        "target_type,target_id,target_label,detail,src_ip,event_ts,"
                        "prev_hash,row_hash")
                .order("id").execute())
    except Exception as exc:
        logger.warning("verify_events_chain fallita: %s", exc)
        return None
    rows = resp.data or []
    broken, verified, unsigned, prev = [], 0, 0, ""
    for r in rows:
        if not r.get("row_hash"):
            unsigned += 1
            continue
        expect = _aevent_hash(r, r.get("prev_hash") or "")
        linked = (r.get("prev_hash") or "") == prev
        if r.get("row_hash") == expect and linked:
            verified += 1
        else:
            broken.append(r["id"])
        prev = r.get("row_hash") or ""
    return _chain_verdict("audit_events", len(rows), verified, broken, unsigned)


# ---------------------------------------------------------------------------
# RBAC / CONO DI VISIBILITA' (users, groups, user_groups, asset_assignments)
# ---------------------------------------------------------------------------

def fetch_user_by_username(username: str):
    """Riga utente per username. None se assente o DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("users").select("*").eq("username", username).execute()
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_user_by_username fallita (%s): %s", username, exc)
        return None


def fetch_user(user_id: int):
    """Riga utente per id. None se assente o DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("users").select("*").eq("id", user_id).execute()
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_user fallita (id=%s): %s", user_id, exc)
        return None


def fetch_users():
    """Tutti gli utenti (senza password_hash). None se DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("users")
                .select("id, created_at, username, role, email, "
                        "email_verified_at, is_active, must_change_password")
                .order("id").execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_users fallita: %s", exc)
        return None


def fetch_user_by_email(email: str):
    """Riga utente per email. None se assente o DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("users").select("*").eq("email", email).execute()
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_user_by_email fallita (%s): %s", email, exc)
        return None


def insert_user(row: dict) -> Optional[int]:
    """Crea un utente. Ritorna l'id, None se fallisce (es. username duplicato)."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("users").insert(row).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("insert_user fallita (%s): %s", row.get("username"), exc)
        return None


def update_user(user_id: int, row: dict) -> bool:
    """Aggiorna ruolo e/o password_hash di un utente."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = client.table("users").update(row).eq("id", user_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("update_user fallita (id=%s): %s", user_id, exc)
        return False


def delete_user(user_id: int) -> bool:
    """Elimina un utente (le assegnazioni cascano)."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = client.table("users").delete().eq("id", user_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("delete_user fallita (id=%s): %s", user_id, exc)
        return False


# --- Token one-time (attivazione account / reset password) -----------------

def insert_auth_token(user_id: int, token_hash: str, purpose: str,
                      expires_at: str) -> bool:
    """Salva l'hash di un token one-time. True se riuscito."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.table("auth_tokens").insert({
            "user_id": user_id, "token_hash": token_hash,
            "purpose": purpose, "expires_at": expires_at,
        }).execute()
        return True
    except Exception as exc:
        logger.warning("insert_auth_token fallita (user=%s): %s", user_id, exc)
        return False


def fetch_auth_token(token_hash: str):
    """Riga token per hash. None se assente o DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("auth_tokens").select("*")
                .eq("token_hash", token_hash).execute())
        return resp.data[0] if resp.data else None
    except Exception as exc:
        logger.warning("fetch_auth_token fallita: %s", exc)
        return None


def mark_auth_token_used(token_id: int) -> bool:
    """Brucia il token (one-time). True se la riga esiste."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = (client.table("auth_tokens").update({"used_at": "now()"})
                .eq("id", token_id).execute())
        return bool(resp.data)
    except Exception as exc:
        logger.warning("mark_auth_token_used fallita (id=%s): %s", token_id, exc)
        return False


def invalidate_auth_tokens(user_id: int, purpose: str) -> None:
    """Brucia i token pendenti dell'utente (reinvio invito/reset)."""
    client = _get_client()
    if client is None:
        return
    try:
        (client.table("auth_tokens").update({"used_at": "now()"})
         .eq("user_id", user_id).eq("purpose", purpose)
         .is_("used_at", "null").execute())
    except Exception as exc:
        logger.warning("invalidate_auth_tokens fallita (user=%s): %s", user_id, exc)


def fetch_groups():
    """Tutti i gruppi con i membri annidati. None se DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("groups")
                .select("id, name, user_groups(user_id)").order("id").execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_groups fallita: %s", exc)
        return None


def insert_group(name: str) -> Optional[int]:
    """Crea un gruppo. Ritorna l'id, None se fallisce (es. nome duplicato)."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = client.table("groups").insert({"name": name}).execute()
        return resp.data[0]["id"] if resp.data else None
    except Exception as exc:
        logger.warning("insert_group fallita (%s): %s", name, exc)
        return None


def delete_group(group_id: int) -> bool:
    """Elimina un gruppo (membership e assegnazioni cascano)."""
    client = _get_client()
    if client is None:
        return False
    try:
        resp = client.table("groups").delete().eq("id", group_id).execute()
        return bool(resp.data)
    except Exception as exc:
        logger.warning("delete_group fallita (id=%s): %s", group_id, exc)
        return False


def set_group_members(group_id: int, user_ids: list) -> bool:
    """Sostituisce la membership del gruppo con la lista indicata."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.table("user_groups").delete().eq("group_id", group_id).execute()
        if user_ids:
            client.table("user_groups").insert(
                [{"group_id": group_id, "user_id": int(u)} for u in user_ids]
            ).execute()
        return True
    except Exception as exc:
        logger.warning("set_group_members fallita (id=%s): %s", group_id, exc)
        return False


def fetch_user_group_ids(user_id: int) -> Optional[list]:
    """Lista di group_id a cui l'utente appartiene. None se DB non raggiungibile."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("user_groups").select("group_id")
                .eq("user_id", user_id).execute())
        return [r["group_id"] for r in (resp.data or [])]
    except Exception as exc:
        logger.warning("fetch_user_group_ids fallita (id=%s): %s", user_id, exc)
        return None


def fetch_all_assignments():
    """
    Tutte le assegnazioni asset->utente/gruppo, arricchite con username/nome
    gruppo per la UI. None se DB non raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("asset_assignments")
                .select("id, asset_id, user_id, group_id, users(username), groups(name)")
                .execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_all_assignments fallita: %s", exc)
        return None


def set_asset_assignments(asset_id: int, user_ids: list, group_ids: list) -> bool:
    """Sostituisce le assegnazioni dell'asset con le liste indicate."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.table("asset_assignments").delete().eq("asset_id", asset_id).execute()
        rows = ([{"asset_id": asset_id, "user_id": int(u)} for u in (user_ids or [])]
                + [{"asset_id": asset_id, "group_id": int(g)} for g in (group_ids or [])])
        if rows:
            client.table("asset_assignments").insert(rows).execute()
        return True
    except Exception as exc:
        logger.warning("set_asset_assignments fallita (asset=%s): %s", asset_id, exc)
        return False


def add_asset_assignment(asset_id: int, user_id: Optional[int] = None,
                         group_id: Optional[int] = None) -> bool:
    """Aggiunge una singola assegnazione (usata per l'auto-assign dell'editor)."""
    client = _get_client()
    if client is None:
        return False
    try:
        row = {"asset_id": asset_id}
        if user_id is not None:
            row["user_id"] = int(user_id)
        if group_id is not None:
            row["group_id"] = int(group_id)
        client.table("asset_assignments").insert(row).execute()
        return True
    except Exception as exc:
        logger.warning("add_asset_assignment fallita (asset=%s): %s", asset_id, exc)
        return False


def fetch_assigned_asset_ids(user_id: int, group_ids: list) -> Optional[set]:
    """
    Insieme degli asset id visibili all'utente 'editor': assegnati a lui
    direttamente o a uno dei suoi gruppi. None se DB non raggiungibile.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        ids = set()
        resp = (client.table("asset_assignments").select("asset_id")
                .eq("user_id", user_id).execute())
        ids.update(r["asset_id"] for r in (resp.data or []))
        if group_ids:
            resp = (client.table("asset_assignments").select("asset_id")
                    .in_("group_id", list(group_ids)).execute())
            ids.update(r["asset_id"] for r in (resp.data or []))
        return ids
    except Exception as exc:
        logger.warning("fetch_assigned_asset_ids fallita (user=%s): %s", user_id, exc)
        return None


def fetch_posture_runs(limit: int = 30):
    """Elenco sintetico delle run (per il selettore storico)."""
    client = _get_client()
    if client is None:
        return None
    try:
        resp = (client.table("posture_runs")
                .select("id, created_at, assets_scanned, total_vulns, avg_score")
                .order("created_at", desc=True).limit(limit).execute())
        return resp.data or []
    except Exception as exc:
        logger.warning("fetch_posture_runs fallita: %s", exc)
        return None
