"""
msrc.py
-------
Fonte MSRC (Microsoft Security Response Center) per i soli prodotti Microsoft.

Perche' non basta NVD: per Windows, Edge, Defender e simili la remediation
reale non e' "aggiorna alla versione X", e' "installa la KB numero Y". MSRC
pubblica entrambi (FixedBuild + numero KB), NVD no. Su un parco Windows e' la
differenza fra un'indicazione azionabile e una generica.

Struttura della sorgente (CVRF v3.0):
    /cvrf/v3.0/updates              -> elenco delle pubblicazioni mensili
    <CvrfUrl> di ogni pubblicazione -> documento con ProductTree + Vulnerability

Il documento non e' interrogabile per prodotto: va indicizzato. Qui si scarica
una finestra delle ultime N pubblicazioni (config 'msrc.releases') e si
costruisce una mappa prodotto -> CVE, tenuta in cache con TTL.

LIMITE DA TENERE PRESENTE, ed e' dichiarato anche in interfaccia: la finestra e'
mensile, quindi l'indice conosce le CVE pubblicate in quel periodo, non l'intera
storia del prodotto. Per la domanda "a quale build devo arrivare" e' corretto
(la build che corregge e' l'ultima pubblicata); per "quante CVE ha in tutto
questo prodotto" e' parziale. Allargare 'releases' allarga la finestra al prezzo
di download piu' pesanti.

Best-effort come il resto dell'app: se MSRC non risponde, il chiamante ricade
su NVD.
"""

import logging
import re
import threading
import time

import requests

from config import load_config

logger = logging.getLogger("vfa.msrc")

SOURCE = "msrc"

_HEADERS = {"Accept": "application/json"}

_LOCK = threading.Lock()
# {"expires": float, "index": {product_lower: [record, ...]}}
_INDEX_CACHE: dict = {}

# Prodotti la cui remediation e' di competenza Microsoft. Il match e' sul nome
# cosi' come lo riporta l'inventario.
_MICROSOFT_HINTS = ("microsoft", "windows", "office", "edge", "defender",
                    "visual c++", "visual studio", ".net", "sharepoint",
                    "exchange server", "sql server", "powershell", "onedrive",
                    "internet explorer", "outlook", "excel", "word", "hyper-v")


def _cfg() -> dict:
    return load_config()["msrc"]


def clear_cache() -> None:
    """Svuota l'indice (test e cambio configurazione)."""
    with _LOCK:
        _INDEX_CACHE.clear()


def is_microsoft(name: str) -> bool:
    """True se il prodotto ricade sotto la responsabilita' di patching Microsoft."""
    low = (name or "").lower()
    return any(hint in low for hint in _MICROSOFT_HINTS)


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9.+]+", " ", (name or "").lower()).strip()


def _fetch_releases(cfg: dict) -> list:
    resp = requests.get(cfg["url"], headers=_HEADERS,
                        timeout=int(cfg.get("timeout", 60)))
    resp.raise_for_status()
    return resp.json().get("value") or []


def _index_document(doc: dict, release_id: str, index: dict) -> None:
    """
    Indicizza un documento CVRF: prodotto -> record CVE.

    Ogni record porta la CVE, la build che corregge e la KB, cioe' i tre dati
    che servono a chiudere il finding su una macchina Windows.
    """
    products = {p.get("ProductID"): (p.get("Value") or "")
                for p in ((doc.get("ProductTree") or {}).get("FullProductName") or [])}
    for vuln in (doc.get("Vulnerability") or []):
        cve_id = vuln.get("CVE")
        if not cve_id:
            continue
        severity = ""
        for threat in (vuln.get("Threats") or []):
            if (threat.get("Type") == 3) and (threat.get("Description") or {}).get("Value"):
                severity = threat["Description"]["Value"]
                break
        # Le remediation portano build e KB, ciascuna riferita a certi ProductID.
        for rem in (vuln.get("Remediations") or []):
            if not rem:
                continue
            kb = (rem.get("Description") or {}).get("Value") or ""
            build = rem.get("FixedBuild") or ""
            if not build and not kb.isdigit():
                continue
            for pid in (rem.get("ProductID") or []):
                label = products.get(pid.split("-")[0])
                if not label:
                    continue
                index.setdefault(_norm(label), []).append({
                    "cve": cve_id,
                    "fixed_build": build,
                    "kb": kb if kb.isdigit() else "",
                    "severity": (severity or "").upper(),
                    "release": release_id,
                    "product": label,
                })


def build_index(force: bool = False) -> tuple:
    """
    Costruisce (o riusa) l'indice prodotto -> CVE sulla finestra configurata.
    Ritorna (index, error). 'error' valorizzato = indice non disponibile.
    """
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {}, "MSRC disabilitato in configurazione"
    with _LOCK:
        cached = _INDEX_CACHE.get("index")
        expires = _INDEX_CACHE.get("expires", 0)
    if cached is not None and not force and time.time() < expires:
        return cached, None

    try:
        releases = _fetch_releases(cfg)
    except Exception as exc:
        logger.warning("MSRC elenco pubblicazioni non raggiungibile: %s", exc)
        return (cached or {}), str(exc)

    wanted = releases[-max(1, int(cfg.get("releases", 3))):]
    index: dict = {}
    failures = []
    for rel in wanted:
        url = rel.get("CvrfUrl")
        if not url:
            continue
        try:
            resp = requests.get(url, headers=_HEADERS,
                                timeout=int(cfg.get("timeout", 60)))
            resp.raise_for_status()
            _index_document(resp.json(), rel.get("ID") or "", index)
        except Exception as exc:                  # una pubblicazione mancante
            failures.append(f"{rel.get('ID')}: {exc}")   # non invalida le altre
    if not index:
        return (cached or {}), "; ".join(failures) or "MSRC index vuoto"
    if failures:
        logger.warning("MSRC: %d pubblicazioni non indicizzate (%s)",
                       len(failures), failures[0])
    with _LOCK:
        _INDEX_CACHE["index"] = index
        _INDEX_CACHE["expires"] = time.time() + \
            float(cfg.get("cache_ttl_hours", 12)) * 3600
    return index, None


def _match_products(index: dict, name: str) -> list:
    """
    Voci dell'indice riferite al prodotto cercato.

    L'inventario dice "Microsoft Edge", MSRC dice "Microsoft Edge
    (Chromium-based)": serve quindi un match per prefisso. NON per semplice
    contenimento, altrimenti "Microsoft Edge" catturerebbe anche "Copilot Chat
    (Microsoft Edge)", che e' un altro prodotto con un altro ciclo di patch.
    """
    key = _norm(name)
    if not key:
        return []
    exact = index.get(key)
    if exact:
        return exact
    out = []
    for label, records in index.items():
        if label.startswith(key) or key.startswith(label):
            out.extend(records)
    return out


def fix_plan(name: str, version: str | None = None) -> dict:
    """
    Fix plan MSRC per un prodotto Microsoft.

    Ritorna la forma comune ai resolver:
      {"cves": [{"id", "fixed", "severity", "kb"}], "fix_version", "unfixed",
       "supported", "error", "detail", "kbs", "window"}.

    'fix_version' e' la build piu' alta fra quelle che correggono; 'kbs' sono
    gli aggiornamenti da installare — su Windows e' quello il gesto concreto.
    """
    out = {"cves": [], "fix_version": None, "unfixed": 0, "supported": True,
           "error": None, "detail": None, "kbs": [], "window": None}
    index, err = build_index()
    if err and not index:
        out["error"] = err
        return out
    records = _match_products(index, name)
    if not records:
        out["supported"] = False
        out["detail"] = "Not listed in the indexed MSRC releases"
        return out

    from cve import _max_ver, _ver_key

    # Contano solo le CVE la cui build correttiva e' successiva a quella
    # installata: le altre sono gia' chiuse su questa macchina e gonfierebbero
    # il conteggio con lavoro gia' fatto.
    installed = _ver_key(version) if version else None

    seen, builds, kbs, releases = {}, [], set(), set()
    for rec in records:
        build = rec["fixed_build"]
        if installed is not None and build and _ver_key(build) <= installed:
            continue
        releases.add(rec["release"])
        prev = seen.get(rec["cve"])
        if prev is None or (build and not prev["fixed"]):
            seen[rec["cve"]] = {"id": rec["cve"], "fixed": build or None,
                                "severity": rec["severity"], "kb": rec["kb"]}
        if build:
            builds.append(build)
        if rec["kb"]:
            kbs.add(rec["kb"])
    cves = sorted(seen.values(), key=lambda c: c["id"])
    out["cves"] = cves
    out["fix_version"] = _max_ver(builds)
    out["unfixed"] = sum(1 for c in cves if not c["fixed"])
    out["kbs"] = sorted(kbs)
    out["window"] = ", ".join(sorted(releases))
    return out
