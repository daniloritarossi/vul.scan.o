"""
ratelimit.py
------------
Freno ai tentativi di login falliti (password guessing).

Il registro attivita' sapeva gia' DIRE che qualcuno stava provando password a
raffica; nessuno lo fermava. Qui si contano i fallimenti in una finestra
scorrevole e, superata la soglia, il login viene rifiutato con 429 finche' la
finestra non si svuota.

Due contatori, non uno:
    username  soglia bassa  -> segue l'attaccante che cambia indirizzo
    ip        soglia alta   -> ferma lo spray su molti account dalla stessa
                               origine, senza punire una NAT aziendale

Gli username INESISTENTI vengono contati come gli altri: se solo gli account
reali finissero in blocco, la differenza di risposta direbbe quali esistono, e
si perderebbe la proprieta' che /api/login difende gia' oggi (nessuna
enumerazione).

Stato in memoria: uvicorn gira a processo singolo (start.sh), quindi non serve
un archivio condiviso. Un riavvio pero' azzererebbe i blocchi, percio' la
finestra viene RICOSTRUITA da 'audit_events', dove ogni login fallito e' gia'
registrato: nessuna tabella nuova, e il conteggio resta quello che l'auditor
puo' verificare da solo.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Optional

import db

logger = logging.getLogger("vfa.ratelimit")

# Difese predefinite, sovrascrivibili dalla sezione 'auth' di config.json.
DEFAULTS = {
    "max_attempts": 5,        # fallimenti per username nella finestra
    "ip_max_attempts": 20,    # fallimenti per indirizzo nella finestra
    "window_seconds": 900,    # ampiezza della finestra scorrevole (15 min)
}

# Azioni che azzerano il contatore di un ACCOUNT ALTRUI: nel registro l'attore
# e' l'admin, l'utente interessato sta in 'target_label'.
_CLEARING_TARGETED = ("auth.unlock", "user.password_reset")

# {("user"|"ip", chiave): deque[timestamp]} — solo i fallimenti nella finestra.
_HITS: dict = defaultdict(deque)
# Blocchi gia' annunciati nel registro: evita una riga di audit per ogni
# tentativo respinto (il fatto interessante e' il blocco, non ogni suo effetto).
_ANNOUNCED: dict = {}
_WARMED = False


def _cfg(cfg: Optional[dict] = None) -> dict:
    return {**DEFAULTS, **{k: v for k, v in (cfg or {}).items() if k in DEFAULTS}}


def _key_user(username: str) -> tuple:
    return ("user", (username or "").strip().lower())


def _key_ip(ip: str) -> tuple:
    return ("ip", (ip or "?").strip())


def _prune(dq: deque, window: int, now: float) -> None:
    cutoff = now - window
    while dq and dq[0] < cutoff:
        dq.popleft()


def _warm(window: int) -> None:
    """
    Primo uso dopo l'avvio: ripopola la finestra dai login falliti gia' scritti
    nel registro attivita'. Senza, un riavvio del servizio sarebbe un modo per
    azzerare il contatore.

    Best-effort come tutta la persistenza: se il DB non risponde si parte da
    zero e si conta da adesso, il login non deve fallire per questo.
    """
    global _WARMED
    if _WARMED:
        return
    _WARMED = True                      # anche in caso di errore: un solo tentativo
    try:
        rows = db.fetch_audit_events(limit=500) or []
    except Exception as exc:
        logger.warning("warm-up del rate limit saltato: %s", exc)
        return
    now = time.time()
    restored = 0
    # Gli eventi arrivano dal piu' recente. Il registro contiene sia i
    # fallimenti sia cio' che li ha azzerati (sblocco dell'admin, login
    # riuscito, cambio o reset password): ricostruire solo i primi
    # resusciterebbe blocchi gia' revocati al primo riavvio del servizio.
    freed_at: dict = {}
    for r in rows:
        ts = _epoch(r.get("event_ts"))
        if ts is None or ts < now - window:
            continue
        action, outcome = r.get("action"), r.get("outcome")
        detail = r.get("detail") or {}
        username = (detail.get("username")
                    or (r.get("target_label") if action in _CLEARING_TARGETED else None)
                    or r.get("actor_name") or "")
        key = _key_user(username)
        if (action in _CLEARING_TARGETED
                or (action == "auth.login" and outcome == "success")
                or (action == "auth.password_change" and outcome == "success")):
            freed_at.setdefault(key, ts)      # il piu' recente, essendo ordinati
            continue
        if action != "auth.login" or outcome != "failure":
            continue
        if ts <= freed_at.get(key, 0.0):
            continue                          # fallimento gia' perdonato
        _HITS[key].appendleft(ts)
        _HITS[_key_ip(r.get("src_ip") or "")].appendleft(ts)
        restored += 1
    if restored:
        logger.info("rate limit: %d login falliti recenti ripresi dal registro",
                    restored)


def _epoch(event_ts) -> Optional[float]:
    """'2026-08-22T13:04:25+00:00' -> epoch. None se illeggibile."""
    if not event_ts:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(event_ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def retry_after(username: str, ip: str, cfg: Optional[dict] = None) -> int:
    """
    Secondi che mancano prima di poter riprovare. 0 = tentativo consentito.

    Non registra nulla e non consuma tentativi: puo' essere chiamata anche solo
    per mostrare lo stato di un account nella pagina di amministrazione.
    """
    c = _cfg(cfg)
    window = c["window_seconds"]
    _warm(window)
    now = time.time()
    wait = 0
    for key, limit in ((_key_user(username), c["max_attempts"]),
                       (_key_ip(ip), c["ip_max_attempts"])):
        dq = _HITS.get(key)
        if not dq:
            continue
        _prune(dq, window, now)
        if len(dq) >= limit:
            # Si sblocca quando il piu' vecchio dei fallimenti esce dalla
            # finestra: da quel momento il conteggio torna sotto soglia.
            wait = max(wait, int(dq[0] + window - now) + 1)
    return wait


def user_status(username: str, cfg: Optional[dict] = None) -> dict:
    """
    Stato del solo contatore per username, per la pagina di amministrazione:
    {locked, retry_after, failures, max_attempts}.
    """
    c = _cfg(cfg)
    window = c["window_seconds"]
    _warm(window)
    now = time.time()
    dq = _HITS.get(_key_user(username))
    if dq:
        _prune(dq, window, now)
    failures = len(dq or ())
    locked = failures >= c["max_attempts"]
    wait = int(dq[0] + window - now) + 1 if locked and dq else 0
    return {"locked": locked, "retry_after": max(wait, 0),
            "failures": failures, "max_attempts": c["max_attempts"]}


def record_failure(username: str, ip: str, cfg: Optional[dict] = None) -> None:
    """Registra un login fallito su entrambi i contatori."""
    c = _cfg(cfg)
    _warm(c["window_seconds"])
    now = time.time()
    _HITS[_key_user(username)].append(now)
    _HITS[_key_ip(ip)].append(now)


def should_announce(username: str, ip: str) -> bool:
    """
    True la PRIMA volta che un blocco respinge un tentativo, poi False finche'
    il blocco dura. Serve a scrivere una riga sola nel registro invece di una
    per ogni richiesta respinta.
    """
    key = (_key_user(username), _key_ip(ip))
    now = time.time()
    last = _ANNOUNCED.get(key, 0.0)
    if now - last < 60:
        return False
    _ANNOUNCED[key] = now
    return True


def clear_user(username: str) -> int:
    """
    Azzera il contatore di un account (login riuscito, sblocco dall'admin,
    reset password). Ritorna quanti fallimenti sono stati scartati.

    Il contatore per INDIRIZZO non viene toccato: un successo su un account non
    assolve l'origine che sta provando gli altri.
    """
    dq = _HITS.pop(_key_user(username), None)
    for key in [k for k in _ANNOUNCED if k[0] == _key_user(username)]:
        _ANNOUNCED.pop(key, None)
    return len(dq or ())


def reset_all() -> None:
    """Solo per i test: svuota lo stato in memoria."""
    global _WARMED
    _HITS.clear()
    _ANNOUNCED.clear()
    _WARMED = False
