"""
config.py
---------
Lettura e scrittura del file di configurazione config.json.

Tutte le impostazioni hanno un default sicuro embedded: se config.json
manca o e' parziale il sistema resta operativo con i valori di default.
"""

import json
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "config.json"

_DEFAULTS: dict = {
    "search_engine": {
        "provider": "duckduckgo",
        "serper_api_key": "",
        "min_osint_hits": 2,
        "min_osint_query": 4,
    },
    "ai": {
        "provider": "ollama",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:7b",
        "claude_api_key": "",
        "claude_model": "claude-haiku-4-5-20251001",
        "summary_timeout": 60,
        "advisory_timeout": 60,
        "extract_timeout": 30,
        "remediation_timeout": 30,
        "triage_timeout": 60,
        "ai_remediation": False,
    },
    "scanner": {
        "simulate_auth": True,
        "socket_timeout": 4.0,
    },
    "osv": {
        "url": "https://api.osv.dev/v1/query",
        "timeout": 15,
    },
    # NVD: fonte per il software che OSV non indicizza (app desktop Windows).
    # api_key opzionale (gratuita su nvd.nist.gov): alza il rate limit da
    # 5 a 50 richieste per 30s. Senza chiave l'app rallenta, non fallisce.
    "nvd": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "cpe_url": "https://services.nvd.nist.gov/rest/json/cpes/2.0",
        "api_key": "",
        "timeout": 30,
        "cache_ttl_hours": 12,
    },
    # MSRC (Microsoft Security Response Center): fix e numeri KB per i soli
    # prodotti Microsoft. L'indice copre le ultime 'releases' pubblicazioni
    # mensili: finestra piu' larga = piu' CVE storiche ma download piu' pesante.
    "msrc": {
        "url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "enabled": True,
        "releases": 3,
        "timeout": 60,
        "cache_ttl_hours": 12,
    },
    # Ticketing remediation (findings -> GitHub Issues / Jira).
    "ticketing": {
        "provider": "",            # "github" | "jira" | "" (disabilitato)
        "github_token": "",
        "github_repo": "",         # "owner/repo"
        "jira_url": "",            # "https://org.atlassian.net"
        "jira_email": "",
        "jira_api_token": "",
        "jira_project_key": "",
    },
    # SMTP per email di invito/attivazione e reset password.
    "smtp": {
        "host": "",              # vuoto = email disabilitate (invito manuale)
        "port": 587,
        "username": "",
        "password": "",
        "use_tls": True,         # STARTTLS
        "from_addr": "",         # mittente (default = username)
        "base_url": "http://localhost:8000",  # base dei link nelle email
    },
    # Policy di autenticazione.
    "auth": {
        "rotation_days": 0,      # 0 = rotation disattivata (raccomandazione NIST 800-63B)
        "min_password_len": 12,
        "invite_ttl_hours": 48,  # validita' del link di attivazione
        "reset_ttl_hours": 4,    # validita' del link di reset
        # Freno al password guessing (ratelimit.py). Il conteggio e' su una
        # finestra scorrevole: 'max_attempts' fallimenti sullo stesso username
        # (o 'ip_max_attempts' dalla stessa origine) dentro 'window_seconds'
        # bloccano il login finche' la finestra non si svuota.
        "max_attempts": 5,
        "ip_max_attempts": 20,
        "window_seconds": 900,
    },
    # Giorni di SLA remediation per severita' (ciclo di vita findings).
    "sla": {
        "critical": 7,
        "high": 30,
        "medium": 90,
        "low": 180,
        "unknown": 90,
    },
}


def load_config() -> dict:
    """Carica config.json; merge con defaults per chiavi mancanti."""
    if not CONFIG_FILE.exists():
        return {k: dict(v) for k, v in _DEFAULTS.items()}
    try:
        raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {k: dict(v) for k, v in _DEFAULTS.items()}
    result: dict = {}
    for section, defaults in _DEFAULTS.items():
        result[section] = {**defaults, **raw.get(section, {})}
    return result


def save_config(data: dict) -> None:
    """Scrive config.json con indent=2."""
    CONFIG_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def get(section: str, key: str):
    """Shortcut: load_config()[section][key]."""
    return load_config()[section][key]
