"""
asset_import.py
---------------
Import del perimetro asset da file (CSV / XLSX).

Il file lo legge il BROWSER (SheetJS, gia' presente per gli export): qui non
arriva mai un file, arrivano righe gia' tabellari. Il server resta l'unico a
decidere se una riga e' importabile — il client puo' sbagliare a leggere il
foglio, ma non puo' concedersi una riga che il server rifiuta.

Le colonne sono PREFISSATE (vedi COLUMNS): un import "a colonne libere" e'
un import che indovina, e su un inventario di sicurezza indovinare significa
scansionare l'host sbagliato con le credenziali di un altro.

Tre esiti possibili per riga, e la differenza conta:

  - errore   -> la riga non entra MAI, nemmeno confermando. E' un dato
                malformato (IP assente, SO non riconosciuto, mezza credenziale):
                nessuna conferma dell'utente lo rende valido.
  - scarto   -> duplicato (nel file o gia' in inventario). Non entra: due
                righe con lo stesso IP non sono un import piu' ricco, sono un
                inventario che conta due volte lo stesso host.
  - avviso   -> il dato e' plausibile ma l'AMBIENTE dice altro (host non
                raggiungibile, credenziali rifiutate). Qui la decisione e'
                dell'operatore: puo' essere un host spento oggi o una
                credenziale scritta male. Entra solo se conferma.
"""

import ipaddress
import re

# Colonne del modello, nell'ordine esatto in cui compaiono nel file.
# 'required' = senza questo valore la riga non e' importabile.
COLUMNS = [
    {"name": "ip", "required": True},
    {"name": "username", "required": False},
    {"name": "password", "required": False},
    {"name": "os_type", "required": True, "allowed": ["linux", "windows"]},
    {"name": "os_major_version", "required": False},
    {"name": "enabled", "required": False, "allowed": ["yes", "no"]},
    {"name": "environment", "required": False,
     "allowed": ["production", "staging", "dev", "unknown"]},
    {"name": "internet_facing", "required": False, "allowed": ["yes", "no"]},
    {"name": "criticality", "required": False, "allowed": ["1", "2", "3", "4", "5"]},
]

COLUMN_NAMES = [c["name"] for c in COLUMNS]

# Righe di esempio del modello. Gli IP sono in 192.0.2.0/24 (TEST-NET-1,
# RFC 5737): riservata alla documentazione, non e' instradabile e non puo'
# appartenere a un host reale. Un esempio con un IP plausibile finirebbe
# importato per distrazione e messo in scansione.
TEMPLATE_ROWS = [
    {
        "ip": "192.0.2.10",
        "username": "svc_scanner",
        "password": "ExamplePassw0rd",
        "os_type": "linux",
        "os_major_version": "Ubuntu 22.04",
        "enabled": "yes",
        "environment": "production",
        "internet_facing": "no",
        "criticality": "4",
    },
    {
        "ip": "192.0.2.20",
        "username": "",
        "password": "",
        "os_type": "windows",
        "os_major_version": "Windows 11",
        "enabled": "yes",
        "environment": "staging",
        "internet_facing": "yes",
        "criticality": "2",
    },
]

# Tetto alle righe per richiesta. Non e' un limite di comodo: ogni riga fa
# una sonda TCP e, se ha credenziali, un tentativo di login. Un file da
# 50.000 righe non sarebbe un import, sarebbe una scansione di rete.
MAX_ROWS = 500

_TRUE = ("yes", "y", "true", "1", "si", "sì", "on", "enabled")
_FALSE = ("no", "n", "false", "0", "off", "disabled")

# Hostname secondo RFC 1123 (etichette alfanumeriche separate da punti).
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)

# Stringhe che VOGLIONO essere un indirizzo, non un nome: sole cifre e punti
# (tentativo IPv4) o soli esadecimali e due punti (tentativo IPv6).
_IPV4_SHAPED = re.compile(r"^\d+(\.\d+)*$")
_IPV6_SHAPED = re.compile(r"^[0-9a-f:]+$", re.IGNORECASE)


def parse_bool(raw, default: bool = True) -> bool:
    """Interpreta la colonna booleana del foglio. Vuoto => default."""
    s = str(raw or "").strip().lower()
    if not s:
        return default
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def host_error(raw: str) -> str | None:
    """
    Motivo per cui la stringa non e' un host valido, None se lo e'.

    Distingue due fallimenti che sulla riga si somigliano e non hanno lo stesso
    rimedio: una stringa che non e' ne' indirizzo ne' nome, e una stringa che
    e' chiaramente un indirizzo scritto male. La seconda esiste perche' la sola
    regola sugli hostname non basta: le etichette DNS possono essere numeriche,
    quindi '999.999.999.999' passerebbe come "nome" e verrebbe messo in sonda
    invece che segnalato. La RFC 1123 §2.1 vieta proprio questo, richiedendo
    che l'etichetta piu' a destra di un hostname NON sia tutta numerica —
    esiste per non confondere un nome con un indirizzo.
    """
    s = (raw or "").strip()
    if not s:
        return "ip_missing"
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    # Sembra un indirizzo e non lo e': dirlo come "hostname non valido"
    # manderebbe a cercare l'errore nella parte sbagliata della riga.
    if _IPV4_SHAPED.match(s) or _IPV6_SHAPED.match(s):
        return "ip_malformed_address"
    if not _HOSTNAME.match(s):
        return "ip_invalid"
    if s.rsplit(".", 1)[-1].isdigit():
        return "ip_malformed_address"
    return None


def valid_host(raw: str) -> bool:
    """True se la stringa e' un IP o un hostname sintatticamente valido."""
    return host_error(raw) is None


def normalize(raw: dict) -> tuple[dict, list[str]]:
    """
    Porta una riga del foglio nella forma dell'inventario.

    Ritorna (campi, errori). Se 'errori' non e' vuoto i campi sono comunque
    popolati con quel che si e' capito: servono a mostrare all'operatore QUALE
    riga ha sbagliato, non solo che una riga ha sbagliato.
    """
    def _s(key: str) -> str:
        return str(raw.get(key) or "").strip()

    errors: list[str] = []

    ip = _s("ip")
    bad_ip = host_error(ip)
    if bad_ip:
        errors.append(bad_ip)

    os_type = _s("os_type").lower()
    if not os_type:
        errors.append("os_type_missing")
    elif os_type not in ("linux", "windows"):
        errors.append("os_type_invalid")

    username, password = _s("username"), _s("password")
    # Mezza credenziale non e' una credenziale: l'asset finirebbe in
    # inventario come "autenticazione non richiesta" e la scansione
    # profonda che l'operatore si aspetta non verrebbe mai fatta.
    if bool(username) != bool(password):
        errors.append("credentials_incomplete")

    env = _s("environment").lower() or "unknown"
    if env not in ("production", "staging", "dev", "unknown"):
        errors.append("environment_invalid")
        env = "unknown"

    crit_raw = _s("criticality")
    criticality = 3
    if crit_raw:
        try:
            criticality = int(float(crit_raw))
        except ValueError:
            errors.append("criticality_invalid")
        else:
            if not 1 <= criticality <= 5:
                errors.append("criticality_invalid")
                criticality = max(1, min(5, criticality))

    return {
        "ip": ip,
        "username": username,
        "password": password,
        "os_type": os_type,
        "os_major_version": _s("os_major_version"),
        "enabled": parse_bool(raw.get("enabled"), default=True),
        "environment": env,
        "internet_facing": parse_bool(raw.get("internet_facing"), default=False),
        "criticality": criticality,
    }, errors


def template() -> dict:
    """Contratto del modello: colonne prefissate + due righe di esempio."""
    return {"columns": COLUMNS, "rows": TEMPLATE_ROWS, "max_rows": MAX_ROWS}
