"""
nvd.py
------
Fonte NVD (NIST National Vulnerability Database) per il software che OSV NON
indicizza: le applicazioni desktop Windows.

OSV ragiona per ecosistemi di pacchetti (Debian, PyPI, npm, Maven...) e non ha
un ecosistema 'Windows': una query per Notepad++ o PuTTY risponde
400 'invalid ecosystem'. NVD ragiona invece per CPE, che copre esattamente
quel software.

Due passaggi, entrambi necessari:

1) RISOLUZIONE CPE (dizionario CPE di NVD)
   Il nome che l'inventario vede ("Notepad++") non e' il CPE. Il vendor reale
   e' 'don_ho', VLC e' 'videolan:vlc_media_player'. Indovinare lo slug dal nome
   produce zero risultati, cioe' un FALSO NEGATIVO: la riga sembrerebbe pulita
   quando non lo e'. Per questo il vendor/prodotto si risolve interrogando il
   dizionario, mai deducendolo.

2) MATCH SUI RANGE DI VERSIONE
   Si usa 'virtualMatchString', non 'cpeName': il primo confronta la versione
   installata con i range delle configurazioni (versionEndExcluding /
   versionEndIncluding), il secondo pretende un CPE gia' esistente a
   dizionario. Dai limiti superiori si ricava la fix version.

Rate limit NVD: 5 richieste/30s senza API key, 50/30s con chiave gratuita
(sezione 'nvd' di config.json). Le risposte sono cache-ate in-process con TTL,
come per il catalogo KEV.

Filosofia best-effort come il resto dell'app: se NVD non risponde, il chiamante
riceve un errore marcato ritentabile e la pagina resta usabile.
"""

import logging
import re
import threading
import time

import requests

from config import load_config

logger = logging.getLogger("vfa.nvd")

SOURCE = "nvd"

# Cache condivise: {chiave: (scadenza, valore)}. Il lock serve perche' la
# scansione di postura interroga in parallelo piu' asset.
_LOCK = threading.Lock()
_CPE_CACHE: dict = {}
_CVE_CACHE: dict = {}


def _cfg() -> dict:
    return load_config()["nvd"]


def _ttl() -> float:
    return float(_cfg().get("cache_ttl_hours", 12)) * 3600


def _cache_get(cache: dict, key):
    with _LOCK:
        hit = cache.get(key)
    if not hit:
        return None
    expires, value = hit
    if time.time() > expires:
        with _LOCK:
            cache.pop(key, None)
        return None
    return value


def _cache_put(cache: dict, key, value) -> None:
    with _LOCK:
        cache[key] = (time.time() + _ttl(), value)


def clear_cache() -> None:
    """Svuota le cache (test e cambio configurazione)."""
    with _LOCK:
        _CPE_CACHE.clear()
        _CVE_CACHE.clear()


def _headers() -> dict:
    key = (_cfg().get("api_key") or "").strip()
    return {"apiKey": key} if key else {}


def _norm(name: str) -> str:
    """Normalizza un nome prodotto per il confronto (case/punteggiatura)."""
    return re.sub(r"[^a-z0-9+]+", " ", (name or "").lower()).strip()


def _cpe_escape(value: str) -> str:
    """
    Nel formato CPE 2.3 i caratteri speciali vanno preceduti da backslash:
    'notepad++' si scrive 'notepad\\+\\+'. Il dizionario NVD restituisce gia'
    la forma sfuggita, quindi si interviene solo se manca.
    """
    return re.sub(r"(?<!\\)([+*?!\"#$%&'()])", r"\\\1", value or "")


def resolve_cpe(name: str, timeout: int | None = None) -> tuple:
    """
    Risolve un nome prodotto nel 'product' del dizionario CPE di NVD.

    Ritorna (product, error). Nessuna corrispondenza -> (None, None): non e'
    un errore, NVD semplicemente non conosce quel prodotto. 'error'
    valorizzato = guasto di rete/servizio (ritentabile).

    Si risolve SOLO il product, non il vendor: lo stesso prodotto convive a
    dizionario sotto vendor diversi (Notepad++ sta sotto 'notepad-plus-plus',
    'don_ho' e 'notepad_plus_plus') e le CVE sono attaccate solo ad alcuni di
    essi — interrogare NVD con 'don_ho' risponde 0 su un prodotto che ne ha 13.
    Un vendor sbagliato darebbe quindi una riga apparentemente pulita, cioe' un
    falso negativo: l'errore peggiore possibile qui. Il vendor resta jolly nella
    query e i vendor davvero corrispondenti si leggono dalla risposta.

    Fra piu' candidati vince il prodotto il cui nome coincide con quello
    cercato: la ricerca per parola chiave restituisce anche plugin e derivati,
    e prendere il primo risultato attribuirebbe a Notepad++ le CVE di un suo
    plugin.
    """
    key = _norm(name)
    if not key:
        return None, None
    cached = _cache_get(_CPE_CACHE, key)
    if cached is not None:
        return cached, None

    cfg = _cfg()
    try:
        resp = requests.get(cfg["cpe_url"],
                            params={"keywordSearch": name, "resultsPerPage": 200},
                            headers=_headers(),
                            timeout=timeout or int(cfg.get("timeout", 30)))
    except Exception as exc:
        return None, str(exc)
    if resp.status_code in (403, 429):
        return None, "NVD rate limit (configura una API key in Settings)"
    if resp.status_code != 200:
        return None, f"NVD HTTP {resp.status_code}"

    try:
        products = resp.json().get("products") or []
    except Exception as exc:
        return None, f"NVD risposta non valida: {exc}"

    counts: dict = {}
    exact = None
    for entry in products:
        parts = (entry.get("cpe") or {}).get("cpeName", "").split(":")
        if len(parts) < 6 or parts[2] != "a":     # solo applicazioni
            continue
        product = parts[4]
        counts[product] = counts.get(product, 0) + 1
        # Il nome a dizionario usa '_' al posto degli spazi ed e' sfuggito.
        if exact is None and _norm(product.replace("_", " ").replace("\\", "")) == key:
            exact = product
    # Senza corrispondenza esatta si prende il prodotto piu' rappresentato:
    # e' quello con piu' versioni a catalogo, non un derivato di nicchia.
    best = exact or (max(counts, key=counts.get) if counts else None)
    _cache_put(_CPE_CACHE, key, best)
    return best, None


def _version_bounds(cve: dict, product: str) -> tuple:
    """
    Limiti superiori di versione dichiarati dalle configurazioni della CVE.

    Ritorna (fixed, last_vulnerable, vendors):
      - fixed           da versionEndExcluding -> la versione corregge
      - last_vulnerable da versionEndIncluding -> l'ultima ancora affetta,
                        la correzione sta OLTRE quel valore
      - vendors         i vendor CPE che hanno prodotto il match (tracciabilita')
    Tenere separati i primi due evita di indicare come sicura una versione che
    e' ancora vulnerabile.
    """
    fixed, last_vuln, vendors = [], [], set()
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            for match in (node.get("cpeMatch") or []):
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 6 or parts[4] != product:
                    continue
                vendors.add(parts[3])
                if match.get("versionEndExcluding"):
                    fixed.append(match["versionEndExcluding"])
                elif match.get("versionEndIncluding"):
                    last_vuln.append(match["versionEndIncluding"])
    return fixed, last_vuln, vendors


def _severity(cve: dict) -> str:
    """Severita' CVSS piu' recente disponibile (v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            return (entries[0].get("cvssData") or {}).get("baseSeverity") or ""
    for entry in (metrics.get("cvssMetricV2") or []):
        return entry.get("baseSeverity") or ""
    return ""


def fix_plan(name: str, version: str | None, timeout: int | None = None) -> dict:
    """
    Fix plan NVD per (nome prodotto, versione installata).

    Ritorna la stessa forma di cve.compute_fix_plan:
      {"cves": [{"id", "fixed", "severity"}], "fix_version", "unfixed",
       "supported", "error", "detail", "cpe"}.

    'supported' False = NVD non conosce il prodotto (nessun CPE): non e' un
    guasto, ritentare non cambia nulla.
    """
    out = {"cves": [], "fix_version": None, "unfixed": 0, "supported": True,
           "error": None, "detail": None, "cpe": None, "vendors": []}
    product, err = resolve_cpe(name, timeout)
    if err:
        out["error"] = err
        return out
    if not product:
        out["supported"] = False
        out["detail"] = "NVD does not list a CPE for this product"
        return out

    # Vendor jolly: vedi resolve_cpe — fissarlo produce falsi negativi.
    cpe = f"cpe:2.3:a:*:{product}:{_cpe_escape(version or '*')}:*:*:*:*:*:*:*"
    out["cpe"] = cpe
    cached = _cache_get(_CVE_CACHE, cpe)
    if cached is not None:
        vulns = cached
    else:
        cfg = _cfg()
        try:
            resp = requests.get(cfg["url"],
                                params={"virtualMatchString": cpe,
                                        "resultsPerPage": 2000},
                                headers=_headers(),
                                timeout=timeout or int(cfg.get("timeout", 30)))
        except Exception as exc:
            out["error"] = str(exc)
            return out
        if resp.status_code in (403, 429):
            out["error"] = "NVD rate limit (configura una API key in Settings)"
            return out
        if resp.status_code == 404:
            out["supported"] = False
            out["detail"] = "NVD does not index this product"
            return out
        if resp.status_code != 200:
            out["error"] = f"NVD HTTP {resp.status_code}"
            return out
        try:
            vulns = resp.json().get("vulnerabilities") or []
        except Exception as exc:
            out["error"] = f"NVD risposta non valida: {exc}"
            return out
        _cache_put(_CVE_CACHE, cpe, vulns)

    from cve import _max_ver          # import locale: evita ciclo cve <-> nvd

    cves, fixes, vendors = [], [], set()
    for item in vulns:
        entry = item.get("cve") or {}
        cid = entry.get("id")
        if not cid:
            continue
        fixed, last_vuln, seen = _version_bounds(entry, product)
        vendors |= seen
        best = _max_ver(fixed)
        if best:
            fixes.append(best)
        cves.append({"id": cid, "fixed": best, "severity": _severity(entry),
                     # Presente solo quando NVD dichiara l'ultima versione
                     # affetta senza indicare quale la corregge.
                     "after": _max_ver(last_vuln) if not best else None})
    from cve import _ver_key

    out["cves"] = cves
    out["fix_version"] = _max_ver(fixes)
    out["unfixed"] = sum(1 for c in cves if not c["fixed"])
    out["vendors"] = sorted(vendors)
    # Alcune CVE dichiarano solo l'ultima versione AFFETTA, non quella che
    # corregge. Se quel limite arriva oltre la fix calcolata, aggiornare a
    # fix_version non basta a coprirle: va detto, non arrotondato.
    after_max = _max_ver([c["after"] for c in cves if c.get("after")])
    if after_max and (not out["fix_version"]
                      or _ver_key(after_max) >= _ver_key(out["fix_version"])):
        out["fix_after"] = after_max
    else:
        out["fix_after"] = None
    return out
